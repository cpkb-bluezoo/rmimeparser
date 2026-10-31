//! Push-based MIME writer: ring-native, with every call atomic.

use std::io::{self, Write};
use std::rc::Rc;

use loopbuf::LoopBuf;

use super::content_types::{ContentDisposition, ContentId, ContentType, MimeVersion};
use super::encoders::{Base64Encoder, QuotedPrintableEncoder};
use super::folding::write_folded_header;
use super::utils::is_valid_boundary;
use super::write_error::{WriteError, WriteResult};
use crate::rfc2047::Encoder as Rfc2047Encoder;

/// An error for a call that can never succeed: not valid for the format, or
/// not valid in the writer's state.
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// The error for a body call that could not fit even one byte.
///
/// If the ring is empty it never will, so the call is invalid; otherwise it
/// will once the ring has been drained.
fn no_room(room: usize, capacity: usize) -> io::Error {
    if room >= capacity {
        invalid("the ring is too small for even one byte of this write")
    } else {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "the ring has no room for this write: read from it and try again",
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Headers,
    Body,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CteKind {
    SevenBit,
    EightBit,
    Binary,
    Base64,
    QuotedPrintable,
}

/// An entity being written. Cloning is cheap (no allocation), because a call
/// keeps a copy of the top one to put back if it does not commit.
#[derive(Clone)]
struct EntityFrame {
    /// Boundary passed to `start_entity` (None for root).
    open_boundary: Option<Rc<str>>,
    /// Multipart boundary from Content-Type, if this entity is multipart.
    multipart_boundary: Option<Rc<str>>,
    phase: Phase,
    cte: CteKind,
    base64: Base64Encoder,
    qp: QuotedPrintableEncoder,
    /// True after at least one child part delimiter was written under this multipart.
    emitted_child: bool,
    /// Lone CR seen at end of previous body chunk (7bit/8bit normalization).
    pending_cr: bool,
    /// True if no body octets written yet, or the last emitted body wire ended with CRLF.
    body_at_line_start: bool,
    /// True once any logical body octets have been accepted.
    body_started: bool,
    /// Boundary scanner over logical body bytes.
    boundary_scan: BoundaryScanner,
}

impl EntityFrame {
    fn new(open_boundary: Option<Rc<str>>) -> Self {
        Self {
            open_boundary,
            multipart_boundary: None,
            phase: Phase::Headers,
            cte: CteKind::SevenBit,
            base64: Base64Encoder::new(),
            qp: QuotedPrintableEncoder::new(),
            emitted_child: false,
            pending_cr: false,
            body_at_line_start: true,
            body_started: false,
            boundary_scan: BoundaryScanner::inactive(),
        }
    }
}

/// The two strings a boundary scanner looks for.
struct Needles {
    /// `\r\n--boundary`
    inner: Vec<u8>,
    /// `--boundary`, at the very start of a body.
    start: Vec<u8>,
}

/// Sliding-window scanner for `\r\n--boundary` / leading `--boundary`.
#[derive(Clone)]
struct BoundaryScanner {
    needles: Option<Rc<Needles>>,
    matched: usize,
    start_matched: usize,
    at_body_start: bool,
}

impl BoundaryScanner {
    fn inactive() -> Self {
        Self {
            needles: None,
            matched: 0,
            start_matched: 0,
            at_body_start: true,
        }
    }

    fn for_boundary(boundary: &str) -> Self {
        let mut inner = Vec::with_capacity(4 + boundary.len());
        inner.extend_from_slice(b"\r\n--");
        inner.extend_from_slice(boundary.as_bytes());
        let mut start = Vec::with_capacity(2 + boundary.len());
        start.extend_from_slice(b"--");
        start.extend_from_slice(boundary.as_bytes());
        Self {
            needles: Some(Rc::new(Needles { inner, start })),
            matched: 0,
            start_matched: 0,
            at_body_start: true,
        }
    }

    fn push(&mut self, data: &[u8]) -> io::Result<()> {
        let Some(needles) = self.needles.clone() else {
            return Ok(());
        };
        let mut i = 0usize;
        while i < data.len() {
            if !self.at_body_start && self.matched == 0 {
                // Nothing in progress: jump to the next possible start (CR).
                match data[i..].iter().position(|&b| b == b'\r') {
                    Some(p) => i += p,
                    None => return Ok(()),
                }
            }
            let b = data[i];
            i += 1;
            if self.at_body_start {
                if b == needles.start[self.start_matched] {
                    self.start_matched += 1;
                    if self.start_matched == needles.start.len() {
                        return Err(invalid("body contains multipart boundary delimiter"));
                    }
                } else if b == needles.start[0] {
                    self.start_matched = 1;
                } else {
                    self.start_matched = 0;
                    self.at_body_start = false;
                }
            }

            if b == needles.inner[self.matched] {
                self.matched += 1;
                if self.matched == needles.inner.len() {
                    return Err(invalid("body contains multipart boundary delimiter"));
                }
            } else if b == needles.inner[0] {
                self.matched = 1;
            } else {
                self.matched = 0;
            }
        }
        Ok(())
    }
}

/// Push-based MIME writer over a caller-owned [`LoopBuf`].
///
/// Every call appends its output to the ring in one piece or not at all, and
/// leaves the writer as it was if it does not. Which of the two reasons it
/// failed for decides what to do about it (see [`WriteError`]):
///
/// - [`WriteError::is_would_block`]: the ring has no room right now. Drain it
///   and repeat the same call.
/// - [`std::io::ErrorKind::InvalidInput`]: the call can never succeed. It needs
///   more room than the whole ring has, it is not valid in the writer's state
///   (a body before `end_headers`), or what it was given is not valid MIME (a
///   bare CR in a 7bit body, a body that contains the multipart boundary).
///
/// [`Self::body_content`] and [`Self::raw_body_content`] take as much of their
/// input as fits and return how much; call them again with the rest.
/// Everything else takes its whole input or fails.
pub struct MimeWriter {
    /// One call's output, built here and appended to the ring in one piece.
    out: Vec<u8>,
    stack: Vec<EntityFrame>,
    closed: bool,
    bytes_written: u64,
}

impl Default for MimeWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl MimeWriter {
    pub fn new() -> Self {
        Self {
            out: Vec::new(),
            stack: Vec::new(),
            closed: false,
            bytes_written: 0,
        }
    }

    /// How many bytes this writer has put into rings.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Resets the writer to its initial state, to write another message.
    pub fn reset(&mut self) {
        self.out.clear();
        self.stack.clear();
        self.closed = false;
        self.bytes_written = 0;
    }

    pub fn start_entity(&mut self, buf: &mut LoopBuf, boundary: Option<&str>) -> WriteResult<()> {
        self.run(buf, |w, _, _| w.start_entity_op(boundary))
    }

    fn start_entity_op(&mut self, boundary: Option<&str>) -> io::Result<()> {
        self.ensure_open()?;

        if self.stack.is_empty() {
            if boundary.is_some() {
                return Err(invalid("root entity must use start_entity(None)"));
            }
            self.stack.push(EntityFrame::new(None));
            return Ok(());
        }

        let parent_boundary = {
            let parent = self
                .stack
                .last_mut()
                .ok_or_else(|| invalid("no parent entity"))?;
            if parent.phase != Phase::Body {
                return Err(invalid("cannot start child entity before parent end_headers"));
            }
            let Some(ref mb) = parent.multipart_boundary else {
                return Err(invalid("parent entity is not multipart"));
            };
            let Some(b) = boundary else {
                return Err(invalid("child entity requires start_entity(Some(boundary))"));
            };
            if **mb != *b {
                return Err(invalid(format!(
                    "child boundary {b:?} does not match parent multipart boundary {mb:?}"
                )));
            }
            Rc::clone(mb)
        };

        self.out.extend_from_slice(b"--");
        self.out.extend_from_slice(parent_boundary.as_bytes());
        self.out.extend_from_slice(b"\r\n");
        self.stack.last_mut().unwrap().emitted_child = true;

        let mut frame = EntityFrame::new(Some(Rc::clone(&parent_boundary)));
        frame.boundary_scan = BoundaryScanner::for_boundary(&parent_boundary);
        self.stack.push(frame);
        Ok(())
    }

    pub fn content_type(&mut self, buf: &mut LoopBuf, content_type: &ContentType) -> WriteResult<()> {
        self.run(buf, |w, _, _| w.content_type_op(content_type))
    }

    fn content_type_op(&mut self, content_type: &ContentType) -> io::Result<()> {
        if content_type.is_primary_type("multipart") {
            let boundary = content_type
                .parameter("boundary")
                .ok_or_else(|| invalid("multipart Content-Type requires boundary parameter"))?;
            if !is_valid_boundary(boundary) {
                return Err(invalid(format!("invalid multipart boundary: {boundary}")));
            }
            self.current_mut()?.multipart_boundary = Some(Rc::from(boundary));
        }
        self.write_header("Content-Type", &content_type.to_header_value())
    }

    pub fn content_disposition(
        &mut self,
        buf: &mut LoopBuf,
        disposition: &ContentDisposition,
    ) -> WriteResult<()> {
        self.run(buf, |w, _, _| {
            w.write_header("Content-Disposition", &disposition.to_header_value())
        })
    }

    pub fn content_transfer_encoding(&mut self, buf: &mut LoopBuf, encoding: &str) -> WriteResult<()> {
        self.run(buf, |w, _, _| w.content_transfer_encoding_op(encoding))
    }

    fn content_transfer_encoding_op(&mut self, encoding: &str) -> io::Result<()> {
        let cte = parse_cte(encoding)?;
        let frame = self.current_mut()?;
        if frame.phase != Phase::Headers {
            return Err(invalid("Content-Transfer-Encoding must be set before end_headers"));
        }
        frame.cte = cte;
        self.write_header("Content-Transfer-Encoding", encoding)
    }

    pub fn content_id(&mut self, buf: &mut LoopBuf, content_id: &ContentId) -> WriteResult<()> {
        self.run(buf, |w, _, _| w.write_header("Content-ID", &content_id.to_string()))
    }

    pub fn content_description(&mut self, buf: &mut LoopBuf, description: &str) -> WriteResult<()> {
        self.run(buf, |w, _, _| {
            w.write_header("Content-Description", &encode_unstructured(description))
        })
    }

    pub fn mime_version(&mut self, buf: &mut LoopBuf, version: MimeVersion) -> WriteResult<()> {
        self.run(buf, |w, _, _| w.write_header("MIME-Version", &version.to_string()))
    }

    /// Write an arbitrary header. Non-ASCII / unsafe values are RFC 2047-encoded.
    pub fn header(&mut self, buf: &mut LoopBuf, name: &str, value: &str) -> WriteResult<()> {
        self.run(buf, |w, _, _| w.write_header(name, &encode_unstructured(value)))
    }

    /// Write a header whose value is already encoded (still folded).
    pub fn header_raw_value(&mut self, buf: &mut LoopBuf, name: &str, value: &str) -> WriteResult<()> {
        self.run(buf, |w, _, _| w.write_header(name, value))
    }

    /// Emit already-folded header wire bytes (including terminating CRLF).
    pub fn raw_header(&mut self, buf: &mut LoopBuf, _name: &str, raw_bytes: &[u8]) -> WriteResult<()> {
        self.run(buf, |w, _, _| {
            w.require_headers()?;
            validate_raw_header_bytes(raw_bytes)?;
            w.out.extend_from_slice(raw_bytes);
            Ok(())
        })
    }

    pub fn end_headers(&mut self, buf: &mut LoopBuf) -> WriteResult<()> {
        self.run(buf, |w, _, _| {
            let frame = w.current_mut()?;
            if frame.phase != Phase::Headers {
                return Err(invalid("end_headers called outside header phase"));
            }
            frame.phase = Phase::Body;
            w.out.extend_from_slice(b"\r\n");
            Ok(())
        })
    }

    /// Appends logical body octets, encoded as the entity's
    /// Content-Transfer-Encoding says, and returns how many of `data` it took:
    /// as many as fit in the ring, all of them if the ring has room. Call it
    /// again with the rest, after draining the ring if it returned a
    /// would-block error.
    ///
    /// Nothing is taken if the bytes it would take are not valid (a bare CR, a
    /// NUL, the multipart boundary). Bytes beyond what it takes are not looked
    /// at; the call that reaches an invalid byte reports it.
    pub fn body_content(&mut self, buf: &mut LoopBuf, data: &[u8]) -> WriteResult<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        self.run(buf, |w, room, capacity| {
            w.require_body()?;
            w.take_prefix(data, room, capacity, Self::encode_body)
        })
    }

    /// Emit already-encoded body wire octets (bypasses CTE). Still
    /// boundary-scanned. Takes what fits and returns how much, as
    /// [`Self::body_content`] does.
    pub fn raw_body_content(&mut self, buf: &mut LoopBuf, data: &[u8]) -> WriteResult<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        self.run(buf, |w, room, capacity| {
            w.require_body()?;
            if matches!(w.current_mut()?.cte, CteKind::Base64 | CteKind::QuotedPrintable) {
                return Err(invalid(
                    "raw_body_content cannot mix with base64/quoted-printable CTE encoders",
                ));
            }
            w.take_prefix(data, room, capacity, Self::encode_raw_body)
        })
    }

    pub fn end_entity(&mut self, buf: &mut LoopBuf, boundary: Option<&str>) -> WriteResult<()> {
        self.run(buf, |w, _, _| w.end_entity_op(boundary))
    }

    fn end_entity_op(&mut self, boundary: Option<&str>) -> io::Result<()> {
        self.ensure_open()?;
        let mut frame = self
            .stack
            .pop()
            .ok_or_else(|| invalid("end_entity with empty stack"))?;

        let expected = frame.open_boundary.as_deref();
        match (expected, boundary) {
            (None, None) => {}
            (Some(a), Some(b)) if a == b => {}
            _ => {
                return Err(invalid(format!(
                    "end_entity boundary mismatch: expected {expected:?}, got {boundary:?}"
                )));
            }
        }

        if frame.phase == Phase::Headers {
            return Err(invalid("end_entity before end_headers"));
        }

        if frame.pending_cr {
            return Err(invalid("bare CR at end of body"));
        }

        match frame.cte {
            CteKind::Base64 => frame.base64.finish(&mut self.out)?,
            CteKind::QuotedPrintable => frame.qp.finish(&mut self.out)?,
            _ => {}
        }

        // Ensure the last body line is CRLF-terminated so line-oriented parsers
        // observe it. Base64Encoder::finish already emits a trailing CRLF.
        if frame.multipart_boundary.is_none()
            && frame.body_started
            && matches!(
                frame.cte,
                CteKind::SevenBit | CteKind::EightBit | CteKind::QuotedPrintable
            )
            && !frame.body_at_line_start
        {
            self.out.extend_from_slice(b"\r\n");
        }

        if let Some(ref mb) = frame.multipart_boundary {
            if !frame.emitted_child {
                return Err(invalid("multipart entity closed without any parts"));
            }
            self.out.extend_from_slice(b"--");
            self.out.extend_from_slice(mb.as_bytes());
            self.out.extend_from_slice(b"--\r\n");
        }

        Ok(())
    }

    /// Finish writing. Requires all entities to have been ended. Writes
    /// nothing, so it needs no ring.
    pub fn close(&mut self) -> WriteResult<()> {
        if self.closed {
            return Ok(());
        }
        if !self.stack.is_empty() {
            return Err(WriteError::new(invalid(
                "close() called with open entities; call end_entity first",
            )));
        }
        self.closed = true;
        Ok(())
    }

    /// Runs one call: whatever `op` builds in `self.out` is appended to `buf`
    /// in one piece, or, if `op` or the append fails, the writer is put back as
    /// it was. `op` is given the ring's spare room and its capacity.
    fn run<R>(
        &mut self,
        buf: &mut LoopBuf,
        op: impl FnOnce(&mut Self, usize, usize) -> io::Result<R>,
    ) -> WriteResult<R> {
        let depth = self.stack.len();
        let top = self.stack.last().cloned();
        let closed = self.closed;
        self.out.clear();
        let result = op(self, buf.spare_len(), buf.capacity()).and_then(|value| {
            if !self.out.is_empty() {
                buf.write_all(&self.out)?;
                self.bytes_written += self.out.len() as u64;
            }
            Ok(value)
        });
        if result.is_err() {
            // Whatever the call pushed or popped, the top entity as it was
            self.stack.truncate(depth.saturating_sub(1));
            if let Some(top) = top {
                self.stack.push(top);
            }
            self.closed = closed;
        }
        self.out.clear();
        result.map_err(WriteError::new)
    }

    /// Encodes the longest prefix of `data` that fits in `room` bytes of output,
    /// give or take a few percent, and returns its length. A prefix that is not valid fails the call and takes nothing.
    fn take_prefix(
        &mut self,
        data: &[u8],
        room: usize,
        capacity: usize,
        encode: fn(&mut Self, &[u8]) -> io::Result<()>,
    ) -> io::Result<usize> {
        // Output is about as long as input, apart from base64's four for
        // three and its line breaks: the right first guess
        let guess = match self.current_mut()?.cte {
            CteKind::Base64 => room / 7 * 5,
            _ => room,
        };
        let mut take = data.len().min(guess.max(1));
        loop {
            let frame = self.current_mut()?.clone();
            self.out.clear();
            encode(self, &data[..take])?;
            if self.out.len() <= room {
                return Ok(take);
            }
            let produced = self.out.len();
            *self.current_mut()? = frame;
            if take == 1 {
                return Err(no_room(room, capacity));
            }
            // Shrink in proportion to the overshoot, with a little to spare
            // so the next try fits
            let estimate = (take as u128 * room as u128 / produced as u128) as usize;
            take = (estimate - estimate / 16).clamp(1, take - 1);
        }
    }

    /// Logical body octets: scanned for the boundary, then encoded.
    fn encode_body(&mut self, data: &[u8]) -> io::Result<()> {
        let frame = self.stack.last_mut().expect("an entity");
        frame.boundary_scan.push(data)?;
        frame.body_started = true;
        match frame.cte {
            CteKind::SevenBit => self.write_textual(data, true),
            CteKind::EightBit => self.write_textual(data, false),
            CteKind::Binary => {
                frame.body_at_line_start = data.ends_with(b"\n");
                self.out.extend_from_slice(data);
                Ok(())
            }
            CteKind::Base64 => {
                frame.base64.write(&mut self.out, data)?;
                // Base64 finish always ends with CRLF when there was output.
                frame.body_at_line_start = false;
                Ok(())
            }
            CteKind::QuotedPrintable => {
                frame.qp.write(&mut self.out, data)?;
                frame.body_at_line_start = false;
                Ok(())
            }
        }
    }

    /// Already-encoded body octets: scanned for the boundary and for NUL.
    fn encode_raw_body(&mut self, data: &[u8]) -> io::Result<()> {
        self.stack
            .last_mut()
            .expect("an entity")
            .boundary_scan
            .push(data)?;
        if data.contains(&0) {
            return Err(invalid("NUL byte in body"));
        }
        self.out.extend_from_slice(data);
        Ok(())
    }

    fn write_header(&mut self, name: &str, value: &str) -> io::Result<()> {
        self.require_headers()?;
        write_folded_header(&mut self.out, name, value)
    }

    /// 7bit/8bit body: reject NUL (and high bytes for 7bit); normalize lone LF to CRLF.
    fn write_textual(&mut self, data: &[u8], seven_bit: bool) -> io::Result<()> {
        let frame = self.stack.last_mut().expect("an entity");
        let mut pending_cr = frame.pending_cr;
        let mut at_line_start = frame.body_at_line_start;
        let mut i = 0usize;

        if pending_cr {
            if data.first() == Some(&b'\n') {
                self.out.extend_from_slice(b"\r\n");
                pending_cr = false;
                at_line_start = true;
                i = 1;
            } else {
                return Err(invalid("bare CR in body"));
            }
        }

        while i < data.len() {
            // Ordinary bytes go out as one run.
            let rest = &data[i..];
            let run = rest
                .iter()
                .position(|&b| b == 0 || b == b'\r' || b == b'\n' || (seven_bit && b >= 128))
                .unwrap_or(rest.len());
            if run > 0 {
                self.out.extend_from_slice(&rest[..run]);
                at_line_start = false;
                i += run;
                continue;
            }
            let b = data[i];
            if b == 0 {
                return Err(invalid("NUL byte in body"));
            }
            if seven_bit && b >= 128 {
                return Err(invalid("8-bit byte in 7bit Content-Transfer-Encoding body"));
            }
            if b == b'\r' {
                if i + 1 < data.len() && data[i + 1] == b'\n' {
                    self.out.extend_from_slice(b"\r\n");
                    at_line_start = true;
                    i += 2;
                } else if i + 1 == data.len() {
                    pending_cr = true;
                    i += 1;
                } else {
                    return Err(invalid("bare CR in body"));
                }
                continue;
            }
            // LF
            self.out.extend_from_slice(b"\r\n");
            at_line_start = true;
            i += 1;
        }

        frame.pending_cr = pending_cr;
        frame.body_at_line_start = at_line_start && !pending_cr;
        Ok(())
    }

    fn ensure_open(&self) -> io::Result<()> {
        if self.closed {
            Err(invalid("writer is closed"))
        } else {
            Ok(())
        }
    }

    fn current_mut(&mut self) -> io::Result<&mut EntityFrame> {
        self.ensure_open()?;
        self.stack
            .last_mut()
            .ok_or_else(|| invalid("no current entity"))
    }

    fn require_headers(&mut self) -> io::Result<()> {
        let frame = self.current_mut()?;
        if frame.phase != Phase::Headers {
            return Err(invalid("headers not allowed outside header phase"));
        }
        Ok(())
    }

    fn require_body(&mut self) -> io::Result<()> {
        let frame = self.current_mut()?;
        if frame.phase != Phase::Body {
            return Err(invalid("body_content requires end_headers first"));
        }
        if frame.multipart_boundary.is_some() {
            return Err(invalid(
                "multipart entity body must be written as child parts, not body_content",
            ));
        }
        Ok(())
    }
}

fn encode_unstructured(value: &str) -> String {
    let bytes = value.as_bytes();
    if Rfc2047Encoder::contains_non_ascii(bytes)
        || bytes.iter().any(|&b| b < 0x20 && b != b'\t')
    {
        Rfc2047Encoder::encode_header_value(bytes, "UTF-8")
    } else {
        value.to_string()
    }
}

fn parse_cte(encoding: &str) -> io::Result<CteKind> {
    let t = encoding.trim();
    if t.eq_ignore_ascii_case("7bit") {
        Ok(CteKind::SevenBit)
    } else if t.eq_ignore_ascii_case("8bit") {
        Ok(CteKind::EightBit)
    } else if t.eq_ignore_ascii_case("binary") {
        Ok(CteKind::Binary)
    } else if t.eq_ignore_ascii_case("base64") {
        Ok(CteKind::Base64)
    } else if t.eq_ignore_ascii_case("quoted-printable") {
        Ok(CteKind::QuotedPrintable)
    } else {
        Err(invalid(format!(
            "unsupported Content-Transfer-Encoding: {encoding}"
        )))
    }
}

fn validate_raw_header_bytes(raw: &[u8]) -> io::Result<()> {
    if raw.iter().any(|&b| b == 0) {
        return Err(invalid("NUL in raw_header"));
    }
    let mut line_len = 0usize;
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] == b'\r' {
            if i + 1 < raw.len() && raw[i + 1] == b'\n' {
                if line_len > super::folding::HARD_LINE_LIMIT {
                    return Err(invalid(
                        "raw_header line exceeds 998 octets",
                    ));
                }
                line_len = 0;
                i += 2;
                continue;
            }
            return Err(invalid("bare CR in raw_header"));
        }
        if raw[i] == b'\n' {
            return Err(invalid("bare LF in raw_header"));
        }
        line_len += 1;
        if line_len > super::folding::HARD_LINE_LIMIT {
            return Err(invalid(
                "raw_header line exceeds 998 octets",
            ));
        }
        i += 1;
    }
    Ok(())
}
