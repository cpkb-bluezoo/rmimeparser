//! A push scanner for uuencoded blocks that sit inline in a text body.
//!
//! Plain-text mail and Usenet articles usually carry uuencoded files inline:
//! prose, then a `begin <mode> <name>` line, encoded lines, `end`, then more
//! prose, all under `7bit` or no transfer encoding at all. [`UuScanner`] takes
//! such a body in chunks of any size and tells a [`UuHandler`] which bytes are
//! text and which are the decoded content of a file, holding only the line it
//! is in the middle of, so its memory does not depend on the size of the body
//! or of a block.
//!
//! Writing a block is [`crate::UuencodeEncoder`]'s job: it produces exactly
//! the framing this scanner reads.

use crate::mime::decoders::decode_uu_line;
use crate::mime::error::ParseResult;
use crate::mime::utils::index_of;

/// What a [`UuScanner`] found, as it finds it.
///
/// Every method has an empty default, so a handler takes only what it wants.
pub trait UuHandler {
    /// Text outside any block, in order, exactly as it arrived (line endings
    /// included). Adjacent calls are one run of text: where one ends is not
    /// meaningful.
    fn text(&mut self, _data: &[u8]) -> ParseResult<()> {
        Ok(())
    }

    /// A block begins. `mode` is the octal mode of the `begin` line and `name`
    /// its file name, as bytes because nothing says what encoding it is in.
    fn begin(&mut self, _mode: u32, _name: &[u8]) -> ParseResult<()> {
        Ok(())
    }

    /// Some decoded bytes of the file, as soon as their line is complete.
    fn data(&mut self, _data: &[u8]) -> ParseResult<()> {
        Ok(())
    }

    /// The block is over. `complete` is true when its `end` line was seen and
    /// false when it was cut off: by the end of the input, or by a line that
    /// is not uuencode, which is then delivered as text.
    fn end(&mut self, _complete: bool) -> ParseResult<()> {
        Ok(())
    }
}

impl<T: UuHandler + ?Sized> UuHandler for &mut T {
    fn text(&mut self, data: &[u8]) -> ParseResult<()> {
        (**self).text(data)
    }
    fn begin(&mut self, mode: u32, name: &[u8]) -> ParseResult<()> {
        (**self).begin(mode, name)
    }
    fn data(&mut self, data: &[u8]) -> ParseResult<()> {
        (**self).data(data)
    }
    fn end(&mut self, complete: bool) -> ParseResult<()> {
        (**self).end(complete)
    }
}

/// The bounds of a [`UuScanner`]. Both are about what it holds at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UuScannerLimits {
    /// The longest file name a `begin` line may carry; a longer one makes the
    /// line ordinary text. Default: 255.
    pub max_name_length: usize,
    /// The longest encoded line, line ending included, that is taken as
    /// uuencode. The classic line is 61 characters; this leaves room for the
    /// longer ones some encoders write. Default: 128.
    pub max_line_length: usize,
}

impl Default for UuScannerLimits {
    fn default() -> Self {
        Self {
            max_name_length: 255,
            max_line_length: 128,
        }
    }
}

/// `begin ` is what a block starts with, at the start of a line.
const BEGIN: &[u8] = b"begin ";

/// Room, beyond the name, for the rest of a `begin` line: the keyword, the
/// mode, the separators and trailing whitespace.
const BEGIN_OVERHEAD: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// At the start of a line outside a block; `held` is the part of
    /// `begin ` seen so far.
    TextStart,
    /// In the middle of a line of text.
    TextMid,
    /// In a line that began with `begin `; `held` is the line so far.
    BeginLine,
    /// A `begin` line is waiting in `begin_line` for the line after it to show
    /// that it really starts a block; `held` is that line so far.
    Pending,
    /// In a block; `held` is the line so far.
    Block,
    /// The zero-length line has been seen; only `end` is left.
    AfterZero,
}

/// What a line inside a block is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Line {
    /// Encoded data: the byte count and how much of the line to decode.
    Data(usize, usize),
    /// The zero-length line that ends the data.
    Zero,
    End,
    Invalid,
}

/// Scans a body, pushed in chunks, for inline uuencoded blocks.
///
/// Text is passed through as it arrives. A block is recognised by its `begin
/// <mode> <name>` line at the start of a line (the mode is three or four octal
/// digits), and only once the line after it is uuencode, `end` or the
/// terminating line, so a line of prose that happens to start with `begin ` is
/// text and is delivered as such. Inside a block, a line that is not uuencode
/// ends it as cut off (`end(false)`) and is delivered as text, and that line
/// may itself begin the next block. A line ending in `\r\n` or `\n` is
/// accepted, `` ` `` and space both stand for zero, and trailing whitespace on
/// a line is ignored, so characters trimmed from the end of a line count as
/// zero.
///
/// At most one line is held, plus one `begin` line waiting to be confirmed, so
/// memory is bounded by [`UuScannerLimits`] whatever the input. Call
/// [`Self::finish`] at the end of the input.
pub struct UuScanner<H: UuHandler> {
    handler: H,
    limits: UuScannerLimits,
    cap: usize,
    state: State,
    held: Vec<u8>,
    begin_line: Vec<u8>,
    scratch: Vec<u8>,
}

impl<H: UuHandler> UuScanner<H> {
    pub fn new(handler: H) -> Self {
        Self::with_limits(handler, UuScannerLimits::default())
    }

    pub fn with_limits(handler: H, limits: UuScannerLimits) -> Self {
        let cap = limits
            .max_line_length
            .max(limits.max_name_length.saturating_add(BEGIN_OVERHEAD))
            .max(BEGIN.len());
        Self {
            handler,
            limits,
            cap,
            state: State::TextStart,
            held: Vec::new(),
            begin_line: Vec::new(),
            scratch: Vec::with_capacity(64),
        }
    }

    pub fn limits(&self) -> &UuScannerLimits {
        &self.limits
    }

    pub fn handler(&self) -> &H {
        &self.handler
    }

    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    pub fn into_handler(self) -> H {
        self.handler
    }

    /// Takes the next chunk of the body, of any size. All of it is consumed:
    /// what cannot be judged yet is held until the next chunk.
    pub fn feed(&mut self, data: &[u8]) -> ParseResult<()> {
        let mut pos = 0;
        while pos < data.len() {
            match self.state {
                State::TextMid => {
                    // Text goes through in runs, up to a line that may begin a
                    // block.
                    let mut from = pos;
                    loop {
                        match index_of(&data[from..], b'\n') {
                            Some(i) => {
                                let end = from + i + 1;
                                if end < data.len() && data[end] != BEGIN[0] {
                                    from = end;
                                    continue;
                                }
                                self.handler.text(&data[pos..end])?;
                                pos = end;
                                self.state = State::TextStart;
                            }
                            None => {
                                self.handler.text(&data[pos..])?;
                                pos = data.len();
                            }
                        }
                        break;
                    }
                }
                State::TextStart => {
                    let b = data[pos];
                    if self.held.len() < BEGIN.len() && b == BEGIN[self.held.len()] {
                        self.held.push(b);
                        pos += 1;
                        if self.held.len() == BEGIN.len() {
                            self.state = State::BeginLine;
                        }
                    } else {
                        if !self.held.is_empty() {
                            self.handler.text(&self.held)?;
                            self.held.clear();
                        }
                        self.state = State::TextMid;
                    }
                }
                State::BeginLine | State::Pending | State::Block | State::AfterZero => {
                    let rest = &data[pos..];
                    let newline = index_of(rest, b'\n');
                    let len = newline.unwrap_or(rest.len());
                    if self.held.len() + len > self.cap {
                        self.overflow()?;
                        continue;
                    }
                    self.held.extend_from_slice(&rest[..len]);
                    if newline.is_some() {
                        pos += len + 1;
                        self.line(b"\n")?;
                    } else {
                        pos = data.len();
                    }
                }
            }
        }
        Ok(())
    }

    /// The input has ended: settles what is held, ending a block that is still
    /// open as cut off. The scanner can then be fed a new body.
    pub fn finish(&mut self) -> ParseResult<()> {
        match self.state {
            State::TextStart => {
                if !self.held.is_empty() {
                    self.handler.text(&self.held)?;
                }
            }
            State::TextMid => {}
            State::BeginLine => self.line(b"")?,
            State::Pending | State::Block | State::AfterZero => {
                if !self.held.is_empty() {
                    self.line(b"")?;
                }
                match self.state {
                    State::Pending => {
                        self.handler.text(&self.begin_line)?;
                        self.handler.text(b"\n")?;
                    }
                    State::Block | State::AfterZero => self.handler.end(false)?,
                    _ => {}
                }
            }
        }
        self.state = State::TextStart;
        self.held.clear();
        self.begin_line.clear();
        Ok(())
    }

    /// A line has grown past what can be a line of this kind: it is text, and
    /// the rest of it is text too.
    fn overflow(&mut self) -> ParseResult<()> {
        match self.state {
            State::BeginLine => {}
            State::Pending => {
                self.handler.text(&self.begin_line)?;
                self.handler.text(b"\n")?;
                self.begin_line.clear();
            }
            _ => self.handler.end(false)?,
        }
        self.handler.text(&self.held)?;
        self.held.clear();
        self.state = State::TextMid;
        Ok(())
    }

    /// A line is complete in `held`, ended by `eol` (empty at the end of the
    /// input).
    fn line(&mut self, eol: &[u8]) -> ParseResult<()> {
        if self.state == State::BeginLine {
            if eol.is_empty() || parse_begin(&self.held, &self.limits).is_none() {
                return self.reject(eol);
            }
            std::mem::swap(&mut self.held, &mut self.begin_line);
            self.held.clear();
            self.state = State::Pending;
            return Ok(());
        }

        let kind = classify(&self.held, &self.limits);
        if self.state == State::Pending {
            if kind == Line::Invalid {
                // It was prose after all.
                self.handler.text(&self.begin_line)?;
                self.handler.text(b"\n")?;
                self.begin_line.clear();
                return self.reject(eol);
            }
            if let Some((mode, name)) = parse_begin(&self.begin_line, &self.limits) {
                self.handler.begin(mode, name)?;
            }
            self.begin_line.clear();
            self.state = State::Block;
        }

        match kind {
            Line::Data(n, used) if self.state == State::Block => {
                self.scratch.clear();
                decode_uu_line(&self.held[..used], n, &mut self.scratch);
                self.handler.data(&self.scratch)?;
                self.held.clear();
            }
            Line::Zero if self.state == State::Block => {
                self.state = State::AfterZero;
                self.held.clear();
            }
            Line::End => {
                self.handler.end(true)?;
                self.held.clear();
                self.state = State::TextStart;
            }
            _ => {
                self.handler.end(false)?;
                self.reject(eol)?;
            }
        }
        Ok(())
    }

    /// The line in `held` is not part of a block: it is text, unless it is
    /// the `begin` line of the next one.
    fn reject(&mut self, eol: &[u8]) -> ParseResult<()> {
        if !eol.is_empty() && parse_begin(&self.held, &self.limits).is_some() {
            std::mem::swap(&mut self.held, &mut self.begin_line);
            self.held.clear();
            self.state = State::Pending;
            return Ok(());
        }
        self.handler.text(&self.held)?;
        if !eol.is_empty() {
            self.handler.text(eol)?;
        }
        self.held.clear();
        self.state = State::TextStart;
        Ok(())
    }
}

fn trim_end(mut line: &[u8]) -> &[u8] {
    while let [rest @ .., b' ' | b'\t' | b'\r'] = line {
        line = rest;
    }
    line
}

/// Reads a `begin <mode> <name>` line (its line ending, if any, already
/// taken off): `begin`, spaces, three or four octal digits, spaces and a name
/// that is neither empty, longer than the limit nor made of control
/// characters.
fn parse_begin<'a>(line: &'a [u8], limits: &UuScannerLimits) -> Option<(u32, &'a [u8])> {
    let line = trim_end(line);
    let rest = line.strip_prefix(BEGIN)?;
    let rest = skip_spaces(rest);
    let digits = rest
        .iter()
        .take_while(|b| (b'0'..=b'7').contains(b))
        .count();
    if !(3..=4).contains(&digits) {
        return None;
    }
    let mode = rest[..digits]
        .iter()
        .fold(0u32, |m, d| m * 8 + (d - b'0') as u32);
    let after = &rest[digits..];
    if !after.starts_with(b" ") {
        return None;
    }
    let name = skip_spaces(after);
    if name.is_empty()
        || name.len() > limits.max_name_length
        || name.iter().any(|&b| b < 0x20 || b == 0x7f)
    {
        return None;
    }
    Some((mode, name))
}

fn skip_spaces(mut s: &[u8]) -> &[u8] {
    while let [b' ', rest @ ..] = s {
        s = rest;
    }
    s
}

/// What a line (its `\n` already taken off) is, inside a block.
fn classify(line: &[u8], limits: &UuScannerLimits) -> Line {
    if trim_end(line) == b"end" {
        return Line::End;
    }
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() || line.len() >= limits.max_line_length {
        return Line::Invalid;
    }
    if !(0x20..=0x60).contains(&line[0]) {
        return Line::Invalid;
    }
    let n = ((line[0] - 32) & 63) as usize;
    let body = trim_end(&line[1..]);
    if n == 0 {
        return if body.is_empty() {
            Line::Zero
        } else {
            Line::Invalid
        };
    }
    let expected = n.div_ceil(3) * 4;
    if body.len() > expected || !body.iter().all(|b| (0x20..=0x60).contains(b)) {
        return Line::Invalid;
    }
    Line::Data(n, 1 + body.len())
}
