//! Push-based MIME writer (constant memory, chunked body).

use std::io::Write;

use super::content_types::{ContentDisposition, ContentId, ContentType, MimeVersion};
use super::encoders::{Base64Encoder, QuotedPrintableEncoder};
use super::folding::write_folded_header;
use super::utils::is_valid_boundary;
use super::write_error::{MimeWriteError, WriteResult};
use crate::rfc2047::Encoder as Rfc2047Encoder;

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

struct EntityFrame {
    /// Boundary passed to `start_entity` (None for root).
    open_boundary: Option<String>,
    /// Multipart boundary from Content-Type, if this entity is multipart.
    multipart_boundary: Option<String>,
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
    fn new(open_boundary: Option<String>) -> Self {
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

/// Sliding-window scanner for `\r\n--boundary` / leading `--boundary`.
struct BoundaryScanner {
    needle: Vec<u8>,
    start_needle: Vec<u8>,
    matched: usize,
    start_matched: usize,
    at_body_start: bool,
    active: bool,
}

impl BoundaryScanner {
    fn inactive() -> Self {
        Self {
            needle: Vec::new(),
            start_needle: Vec::new(),
            matched: 0,
            start_matched: 0,
            at_body_start: true,
            active: false,
        }
    }

    fn for_boundary(boundary: &str) -> Self {
        let mut needle = Vec::with_capacity(4 + boundary.len());
        needle.extend_from_slice(b"\r\n--");
        needle.extend_from_slice(boundary.as_bytes());
        let mut start_needle = Vec::with_capacity(2 + boundary.len());
        start_needle.extend_from_slice(b"--");
        start_needle.extend_from_slice(boundary.as_bytes());
        Self {
            needle,
            start_needle,
            matched: 0,
            start_matched: 0,
            at_body_start: true,
            active: true,
        }
    }

    fn push(&mut self, data: &[u8]) -> WriteResult<()> {
        if !self.active {
            return Ok(());
        }
        for &b in data {
            if self.at_body_start {
                if b == self.start_needle[self.start_matched] {
                    self.start_matched += 1;
                    if self.start_matched == self.start_needle.len() {
                        return Err(MimeWriteError::validation(
                            "body contains multipart boundary delimiter",
                        ));
                    }
                } else if b == self.start_needle[0] {
                    self.start_matched = 1;
                } else {
                    self.start_matched = 0;
                    self.at_body_start = false;
                }
            }

            if b == self.needle[self.matched] {
                self.matched += 1;
                if self.matched == self.needle.len() {
                    return Err(MimeWriteError::validation(
                        "body contains multipart boundary delimiter",
                    ));
                }
            } else if b == self.needle[0] {
                self.matched = 1;
            } else {
                self.matched = 0;
            }
        }
        Ok(())
    }
}

struct CountingWrite<'a, W: Write> {
    inner: &'a mut W,
    count: &'a mut u64,
}

impl<W: Write> Write for CountingWrite<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        *self.count += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Push-based MIME writer. `body_content` may be called repeatedly with chunks.
pub struct MimeWriter<W: Write> {
    out: W,
    stack: Vec<EntityFrame>,
    closed: bool,
    bytes_written: u64,
}

impl<W: Write> MimeWriter<W> {
    pub fn new(out: W) -> Self {
        Self {
            out,
            stack: Vec::new(),
            closed: false,
            bytes_written: 0,
        }
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub fn into_inner(self) -> W {
        self.out
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.out
    }

    pub fn start_entity(&mut self, boundary: Option<&str>) -> WriteResult<()> {
        self.ensure_open()?;

        if self.stack.is_empty() {
            if boundary.is_some() {
                return Err(MimeWriteError::invalid_state(
                    "root entity must use start_entity(None)",
                ));
            }
            self.stack.push(EntityFrame::new(None));
            return Ok(());
        }

        let parent_boundary = {
            let parent = self.stack.last_mut().ok_or_else(|| {
                MimeWriteError::invalid_state("no parent entity")
            })?;
            if parent.phase != Phase::Body {
                return Err(MimeWriteError::invalid_state(
                    "cannot start child entity before parent end_headers",
                ));
            }
            let Some(ref mb) = parent.multipart_boundary else {
                return Err(MimeWriteError::invalid_state(
                    "parent entity is not multipart",
                ));
            };
            let Some(b) = boundary else {
                return Err(MimeWriteError::invalid_state(
                    "child entity requires start_entity(Some(boundary))",
                ));
            };
            if mb != b {
                return Err(MimeWriteError::validation(format!(
                    "child boundary {b:?} does not match parent multipart boundary {mb:?}"
                )));
            }
            mb.clone()
        };

        self.write_raw(b"--")?;
        self.write_raw(parent_boundary.as_bytes())?;
        self.write_raw(b"\r\n")?;
        self.stack.last_mut().unwrap().emitted_child = true;

        let mut frame = EntityFrame::new(Some(parent_boundary.clone()));
        frame.boundary_scan = BoundaryScanner::for_boundary(&parent_boundary);
        self.stack.push(frame);
        Ok(())
    }

    pub fn content_type(&mut self, content_type: &ContentType) -> WriteResult<()> {
        if content_type.is_primary_type("multipart") {
            let boundary = content_type.parameter("boundary").ok_or_else(|| {
                MimeWriteError::validation("multipart Content-Type requires boundary parameter")
            })?;
            if !is_valid_boundary(boundary) {
                return Err(MimeWriteError::validation(format!(
                    "invalid multipart boundary: {boundary}"
                )));
            }
            self.current_mut()?.multipart_boundary = Some(boundary.to_string());
        }
        self.write_header("Content-Type", &content_type.to_header_value())
    }

    pub fn content_disposition(&mut self, disposition: &ContentDisposition) -> WriteResult<()> {
        self.write_header("Content-Disposition", &disposition.to_header_value())
    }

    pub fn content_transfer_encoding(&mut self, encoding: &str) -> WriteResult<()> {
        let cte = parse_cte(encoding)?;
        let frame = self.current_mut()?;
        if frame.phase != Phase::Headers {
            return Err(MimeWriteError::invalid_state(
                "Content-Transfer-Encoding must be set before end_headers",
            ));
        }
        frame.cte = cte;
        self.write_header("Content-Transfer-Encoding", encoding)
    }

    pub fn content_id(&mut self, content_id: &ContentId) -> WriteResult<()> {
        self.write_header("Content-ID", &content_id.to_string())
    }

    pub fn content_description(&mut self, description: &str) -> WriteResult<()> {
        let encoded = encode_unstructured(description);
        self.write_header("Content-Description", &encoded)
    }

    pub fn mime_version(&mut self, version: MimeVersion) -> WriteResult<()> {
        self.write_header("MIME-Version", &version.to_string())
    }

    /// Write an arbitrary header. Non-ASCII / unsafe values are RFC 2047-encoded.
    pub fn header(&mut self, name: &str, value: &str) -> WriteResult<()> {
        let encoded = encode_unstructured(value);
        self.write_header(name, &encoded)
    }

    /// Write a header whose value is already encoded (still folded).
    pub fn header_raw_value(&mut self, name: &str, value: &str) -> WriteResult<()> {
        self.write_header(name, value)
    }

    /// Emit already-folded header wire bytes (including terminating CRLF).
    pub fn raw_header(&mut self, _name: &str, raw_bytes: &[u8]) -> WriteResult<()> {
        self.require_headers()?;
        validate_raw_header_bytes(raw_bytes)?;
        self.write_raw(raw_bytes)
    }

    pub fn end_headers(&mut self) -> WriteResult<()> {
        let frame = self.current_mut()?;
        if frame.phase != Phase::Headers {
            return Err(MimeWriteError::invalid_state(
                "end_headers called outside header phase",
            ));
        }
        frame.phase = Phase::Body;
        self.write_raw(b"\r\n")
    }

    /// Append logical body octets. May be called multiple times (chunked).
    pub fn body_content(&mut self, data: &[u8]) -> WriteResult<()> {
        self.require_body()?;
        if data.is_empty() {
            return Ok(());
        }

        {
            let frame = self.current_mut()?;
            frame.boundary_scan.push(data)?;
            frame.body_started = true;
        }

        let cte = self.current_mut()?.cte;
        match cte {
            CteKind::SevenBit => self.write_textual(data, true),
            CteKind::EightBit => self.write_textual(data, false),
            CteKind::Binary => {
                self.current_mut()?.body_at_line_start = data.ends_with(b"\n");
                self.write_raw(data)
            }
            CteKind::Base64 => {
                self.write_with_base64(data)?;
                // Base64 finish always ends with CRLF when there was output.
                self.current_mut()?.body_at_line_start = false;
                Ok(())
            }
            CteKind::QuotedPrintable => {
                self.write_with_qp(data)?;
                self.current_mut()?.body_at_line_start = false;
                Ok(())
            }
        }
    }

    /// Emit already-encoded body wire octets (bypasses CTE). Still boundary-scanned.
    pub fn raw_body_content(&mut self, data: &[u8]) -> WriteResult<()> {
        self.require_body()?;
        if data.is_empty() {
            return Ok(());
        }
        {
            let frame = self.current_mut()?;
            if matches!(frame.cte, CteKind::Base64 | CteKind::QuotedPrintable) {
                return Err(MimeWriteError::invalid_state(
                    "raw_body_content cannot mix with base64/quoted-printable CTE encoders",
                ));
            }
            frame.boundary_scan.push(data)?;
        }
        if data.iter().any(|&b| b == 0) {
            return Err(MimeWriteError::validation("NUL byte in body"));
        }
        self.write_raw(data)
    }

    pub fn end_entity(&mut self, boundary: Option<&str>) -> WriteResult<()> {
        self.ensure_open()?;
        let frame = self.stack.pop().ok_or_else(|| {
            MimeWriteError::invalid_state("end_entity with empty stack")
        })?;

        let expected = frame.open_boundary.as_deref();
        match (expected, boundary) {
            (None, None) => {}
            (Some(a), Some(b)) if a == b => {}
            _ => {
                return Err(MimeWriteError::invalid_state(format!(
                    "end_entity boundary mismatch: expected {expected:?}, got {boundary:?}"
                )));
            }
        }

        if frame.phase == Phase::Headers {
            return Err(MimeWriteError::invalid_state(
                "end_entity before end_headers",
            ));
        }

        if frame.pending_cr {
            return Err(MimeWriteError::validation("bare CR at end of body"));
        }

        let cte = frame.cte;
        let body_started = frame.body_started;
        let body_at_line_start = frame.body_at_line_start;
        let multipart_boundary = frame.multipart_boundary.clone();
        let emitted_child = frame.emitted_child;

        self.flush_cte(cte, frame.base64, frame.qp)?;

        // Ensure the last body line is CRLF-terminated so line-oriented parsers
        // observe it. Base64Encoder::finish already emits a trailing CRLF.
        if multipart_boundary.is_none()
            && body_started
            && matches!(
                cte,
                CteKind::SevenBit | CteKind::EightBit | CteKind::QuotedPrintable
            )
            && !body_at_line_start
        {
            self.write_raw(b"\r\n")?;
        }

        if let Some(ref mb) = multipart_boundary {
            if !emitted_child {
                return Err(MimeWriteError::invalid_state(
                    "multipart entity closed without any parts",
                ));
            }
            self.write_raw(b"--")?;
            self.write_raw(mb.as_bytes())?;
            self.write_raw(b"--\r\n")?;
        }

        Ok(())
    }

    /// Finish writing. Requires all entities to have been ended.
    pub fn close(&mut self) -> WriteResult<()> {
        if self.closed {
            return Ok(());
        }
        if !self.stack.is_empty() {
            return Err(MimeWriteError::invalid_state(
                "close() called with open entities; call end_entity first",
            ));
        }
        self.closed = true;
        Ok(())
    }

    fn write_header(&mut self, name: &str, value: &str) -> WriteResult<()> {
        self.require_headers()?;
        let mut counter = CountingWrite {
            inner: &mut self.out,
            count: &mut self.bytes_written,
        };
        write_folded_header(&mut counter, name, value)
    }

    fn write_raw(&mut self, data: &[u8]) -> WriteResult<()> {
        self.out.write_all(data)?;
        self.bytes_written += data.len() as u64;
        Ok(())
    }

    fn write_with_base64(&mut self, data: &[u8]) -> WriteResult<()> {
        let mut enc = std::mem::take(&mut self.current_mut()?.base64);
        let mut counter = CountingWrite {
            inner: &mut self.out,
            count: &mut self.bytes_written,
        };
        let result = enc.write(&mut counter, data);
        self.stack.last_mut().unwrap().base64 = enc;
        result
    }

    fn write_with_qp(&mut self, data: &[u8]) -> WriteResult<()> {
        let mut enc = std::mem::take(&mut self.current_mut()?.qp);
        let mut counter = CountingWrite {
            inner: &mut self.out,
            count: &mut self.bytes_written,
        };
        let result = enc.write(&mut counter, data);
        self.stack.last_mut().unwrap().qp = enc;
        result
    }

    fn flush_cte(
        &mut self,
        cte: CteKind,
        mut base64: Base64Encoder,
        mut qp: QuotedPrintableEncoder,
    ) -> WriteResult<()> {
        let mut counter = CountingWrite {
            inner: &mut self.out,
            count: &mut self.bytes_written,
        };
        match cte {
            CteKind::Base64 => base64.finish(&mut counter),
            CteKind::QuotedPrintable => qp.finish(&mut counter),
            _ => Ok(()),
        }
    }

    /// 7bit/8bit body: reject NUL (and high bytes for 7bit); normalize lone LF to CRLF.
    fn write_textual(&mut self, data: &[u8], seven_bit: bool) -> WriteResult<()> {
        let mut pending_cr = self.current_mut()?.pending_cr;
        let mut at_line_start = self.current_mut()?.body_at_line_start;
        let mut i = 0usize;

        if pending_cr {
            if data.first() == Some(&b'\n') {
                self.write_raw(b"\r\n")?;
                pending_cr = false;
                at_line_start = true;
                i = 1;
            } else {
                return Err(MimeWriteError::validation("bare CR in body"));
            }
        }

        while i < data.len() {
            let b = data[i];
            if b == 0 {
                return Err(MimeWriteError::validation("NUL byte in body"));
            }
            if seven_bit && b >= 128 {
                return Err(MimeWriteError::validation(
                    "8-bit byte in 7bit Content-Transfer-Encoding body",
                ));
            }
            if b == b'\r' {
                if i + 1 < data.len() && data[i + 1] == b'\n' {
                    self.write_raw(b"\r\n")?;
                    at_line_start = true;
                    i += 2;
                } else if i + 1 == data.len() {
                    pending_cr = true;
                    i += 1;
                } else {
                    return Err(MimeWriteError::validation("bare CR in body"));
                }
                continue;
            }
            if b == b'\n' {
                self.write_raw(b"\r\n")?;
                at_line_start = true;
                i += 1;
                continue;
            }
            self.write_raw(&[b])?;
            at_line_start = false;
            i += 1;
        }

        let frame = self.current_mut()?;
        frame.pending_cr = pending_cr;
        frame.body_at_line_start = at_line_start && !pending_cr;
        Ok(())
    }

    fn ensure_open(&self) -> WriteResult<()> {
        if self.closed {
            Err(MimeWriteError::invalid_state("writer is closed"))
        } else {
            Ok(())
        }
    }

    fn current_mut(&mut self) -> WriteResult<&mut EntityFrame> {
        self.ensure_open()?;
        self.stack
            .last_mut()
            .ok_or_else(|| MimeWriteError::invalid_state("no current entity"))
    }

    fn require_headers(&mut self) -> WriteResult<()> {
        let frame = self.current_mut()?;
        if frame.phase != Phase::Headers {
            return Err(MimeWriteError::invalid_state(
                "headers not allowed outside header phase",
            ));
        }
        Ok(())
    }

    fn require_body(&mut self) -> WriteResult<()> {
        let frame = self.current_mut()?;
        if frame.phase != Phase::Body {
            return Err(MimeWriteError::invalid_state(
                "body_content requires end_headers first",
            ));
        }
        if frame.multipart_boundary.is_some() {
            return Err(MimeWriteError::invalid_state(
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

fn parse_cte(encoding: &str) -> WriteResult<CteKind> {
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
        Err(MimeWriteError::validation(format!(
            "unsupported Content-Transfer-Encoding: {encoding}"
        )))
    }
}

fn validate_raw_header_bytes(raw: &[u8]) -> WriteResult<()> {
    if raw.iter().any(|&b| b == 0) {
        return Err(MimeWriteError::validation("NUL in raw_header"));
    }
    let mut line_len = 0usize;
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] == b'\r' {
            if i + 1 < raw.len() && raw[i + 1] == b'\n' {
                if line_len > super::folding::HARD_LINE_LIMIT {
                    return Err(MimeWriteError::validation(
                        "raw_header line exceeds 998 octets",
                    ));
                }
                line_len = 0;
                i += 2;
                continue;
            }
            return Err(MimeWriteError::validation("bare CR in raw_header"));
        }
        if raw[i] == b'\n' {
            return Err(MimeWriteError::validation("bare LF in raw_header"));
        }
        line_len += 1;
        if line_len > super::folding::HARD_LINE_LIMIT {
            return Err(MimeWriteError::validation(
                "raw_header line exceeds 998 octets",
            ));
        }
        i += 1;
    }
    Ok(())
}
