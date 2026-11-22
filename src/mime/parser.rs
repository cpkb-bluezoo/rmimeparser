//! Push-based MIME entity parser (gumdrop `MIMEParser` port).

use std::io::Read;
use std::rc::Rc;

use loopbuf::LoopBuf;

use crate::buffer::ByteCursor;
use crate::charset::HeaderCharset;
use crate::mime::content_id_parser::ContentIdParser;
use crate::mime::content_types::MimeVersion;
use crate::mime::decoders::{
    decode_base64, decode_quoted_printable, decode_uuencode, is_base64_char,
};
use crate::mime::error::{ParseError, ParseResult};
use crate::mime::handler::{HeaderDelivery, Locator, MimeHandler, SharedLocator};
use crate::mime::limits::ParserLimits;
use crate::mime::messages::{
    format_header_value_too_long, format_multipart_too_deep, format_unclosed_boundary, MIMEMessages,
};
use crate::mime::parameters::{Fed, Kind, ParameterParser, ParameterSink};
use crate::mime::utils::{decode_token_header_value, index_of, is_token, is_valid_boundary};
use crate::mime::wire_sink::{MimeWireSink, NoWire};
use crate::rfc2047::HeaderTextDecoder;

const INITIAL_HEADER_VALUE_CAPACITY: usize = 1024;
const DEFAULT_BUFFER_SIZE: usize = 8192;
const DEFAULT_CHUNK_SIZE: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryMatch {
    pub boundary: String,
    pub is_end_boundary: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Init,
    Header,
    Body,
    FirstBoundary,
    BoundaryOrContent,
    BoundaryOnly,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TransferEncoding {
    Binary,
    Base64,
    QuotedPrintable,
    Uuencode,
}

/// How the value of the header being read is dealt with.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ValueMode {
    /// One of the headers the parser understands: its value is collected
    /// whole (up to `max_element_length`) and parsed when it is complete.
    Buffered,
    /// `Content-Type`, read by the parameter grammar as it arrives.
    ContentType,
    /// `Content-Disposition`, likewise.
    ContentDisposition,
    /// Decoded and handed to the handler as it arrives.
    Unstructured,
    /// Handed to the handler as it arrives, undecoded.
    Raw,
}

/// Picks the `boundary` parameter out of a multipart `Content-Type` as it goes
/// by, for the parser's own use.
#[derive(Default)]
struct BoundaryCollector {
    multipart: bool,
    collecting: bool,
    seen: bool,
    fits: bool,
    value: Vec<u8>,
}

impl BoundaryCollector {
    fn begin(&mut self) {
        *self = Self {
            value: std::mem::take(&mut self.value),
            ..Self::default()
        };
        self.value.clear();
    }

    fn start_parameter(&mut self, name: &str, language: Option<&str>) {
        self.collecting = self.multipart
            && !self.seen
            && language.is_none()
            && name.eq_ignore_ascii_case("boundary");
        if self.collecting {
            self.seen = true;
            self.fits = true;
            self.value.clear();
        }
    }

    fn content(&mut self, text: &str) {
        if self.collecting {
            // no boundary is longer than 70
            if self.value.len() + text.len() > 70 {
                self.fits = false;
            } else {
                self.value.extend_from_slice(text.as_bytes());
            }
        }
    }

    /// The boundary, if the header had a valid one.
    fn boundary(&self) -> Option<&str> {
        let boundary = std::str::from_utf8(&self.value).ok()?;
        (self.seen && self.fits && is_valid_boundary(boundary)).then_some(boundary)
    }
}

/// Delivers the grammar's events to the handler, and to the boundary collector.
struct EventSink<'a, H: MimeHandler> {
    handler: &'a mut H,
    kind: Kind,
    boundary: &'a mut BoundaryCollector,
}

impl<H: MimeHandler> ParameterSink for EventSink<'_, H> {
    fn head(&mut self, first: &str, second: &str) -> ParseResult<()> {
        match self.kind {
            Kind::ContentType => {
                self.boundary.begin();
                self.boundary.multipart = first.eq_ignore_ascii_case("multipart");
                self.handler.start_content_type(first, second)
            }
            Kind::ContentDisposition => self.handler.start_content_disposition(first),
        }
    }

    fn start_parameter(&mut self, name: &str, language: Option<&str>) -> ParseResult<()> {
        self.boundary.start_parameter(name, language);
        self.handler.start_parameter(name, language)
    }

    fn content(&mut self, text: &str) -> ParseResult<()> {
        self.boundary.content(text);
        self.handler.parameter_content(text)
    }

    fn end_parameter(&mut self) -> ParseResult<()> {
        self.boundary.collecting = false;
        self.handler.end_parameter()
    }
}

/// Where the body scanner is within a line (multipart states only).
#[derive(Clone, Copy, PartialEq, Eq)]
enum LineState {
    /// At the start of a line; `held` may hold the previous line's ending.
    Start,
    /// Assembling a line that starts with `-` in `cand`: it may be a boundary.
    Candidate,
    /// Inside an ordinary content line.
    Mid,
}

/// Longest `--boundary--CRLF` line: 2 + boundary (at most 70) + 2 + 2.
const MAX_CANDIDATE_LINE: usize = 76;
/// Longest quoted-printable / uuencode line buffered whole before decoding.
const MAX_ENCODED_LINE: usize = 8192;

/// Event-driven MIME parser.
///
/// The parser reads from a caller-owned [`LoopBuf`] and holds none of the
/// message. [`Self::receive`] consumes what it can use and leaves the rest in
/// the ring, to be presented again once the caller has added to it. A header
/// line is used whole, so a partial one stays in the ring; the ring therefore
/// has to be able to hold the longest header line, which RFC 5322 limits to
/// 998 bytes. Body bytes are consumed as they arrive and delivered as
/// zero-copy runs; the parser only holds back a possible boundary line and the
/// line ending before it.
///
/// A header's value is joined from its folded lines and held until the last
/// has arrived, up to [`ParserLimits::max_element_length`].
///
/// The parser owns its handler. To keep the handler yourself, lend it:
/// `MimeParser::new(&mut handler)` works because `&mut H` is a
/// [`MimeHandler`] whenever `H` is. Use [`Self::handler`], [`Self::handler_mut`]
/// and [`Self::into_handler`] to get at one the parser owns.
pub struct MimeParser<H: MimeHandler, W: MimeWireSink = NoWire> {
    handler: H,
    /// Wire-accurate capture for DKIM; [`NoWire`] unless wrapped by
    /// [`crate::DkimMessageParser`].
    wire: W,
    locator: Rc<SharedLocator>,
    limits: ParserLimits,
    /// Only used to size [`Self::parse`]'s own ring; `receive` reads whatever
    /// ring the caller chose.
    buffer_size: usize,
    /// The most body bytes handed to the handler at a time.
    chunk_size: usize,
    /// A header line that straddles the ring's wrap is joined here.
    line_scratch: Vec<u8>,
    state: State,
    boundaries: Vec<String>,
    boundary_set: bool,
    /// Field name of the header being accumulated; the buffers are reused.
    header_name: String,
    header_active: bool,
    value_mode: ValueMode,
    /// Reads the text of unstructured headers.
    text_decoder: HeaderTextDecoder,
    /// Reads `Content-Type` and `Content-Disposition`.
    params: ParameterParser,
    boundary: BoundaryCollector,
    header_value_sink: Vec<u8>,
    header_raw_name: Option<String>,
    header_raw_sink: Vec<u8>,
    /// The sink wants the raw bytes of the header being read.
    capturing: bool,
    strip_header_whitespace: bool,
    decode_buffer: Vec<u8>,
    transfer_encoding: TransferEncoding,
    /// base64 characters of an incomplete quantum; completed by later input
    /// (lines need not be a multiple of 4 characters).
    b64_carry: [u8; 3],
    b64_carry_len: usize,
    /// Partial quoted-printable / uuencode line awaiting its terminator.
    line_carry: Vec<u8>,
    line_state: LineState,
    /// Line ending withheld until the next line is known not to be a boundary.
    held: [u8; 2],
    held_len: usize,
    /// Candidate boundary line being assembled.
    cand: [u8; MAX_CANDIDATE_LINE],
    cand_len: usize,
    underflow: bool,
    closed: bool,
}

impl<H: MimeHandler> MimeParser<H> {
    /// Creates a parser that owns `handler`, with the default limits.
    pub fn new(handler: H) -> Self {
        Self::build(handler, NoWire, ParserLimits::default())
    }

    /// Creates a parser with the given limits.
    pub fn with_limits(handler: H, limits: ParserLimits) -> Self {
        Self::build(handler, NoWire, limits)
    }
}

impl<H: MimeHandler, W: MimeWireSink> MimeParser<H, W> {
    /// Like [`MimeParser::new`], but also delivers wire-accurate header/body
    /// bytes to `wire`.
    ///
    /// Used by [`crate::DkimMessageParser`]; not part of the everyday handler API.
    pub(crate) fn with_wire(handler: H, wire: W) -> Self {
        Self::build(handler, wire, ParserLimits::default())
    }

    fn build(handler: H, wire: W, limits: ParserLimits) -> Self {
        Self {
            handler,
            wire,
            locator: Rc::new(SharedLocator::new()),
            limits,
            buffer_size: DEFAULT_BUFFER_SIZE,
            chunk_size: DEFAULT_CHUNK_SIZE,
            line_scratch: Vec::new(),
            state: State::Init,
            boundaries: Vec::new(),
            boundary_set: false,
            header_name: String::new(),
            header_active: false,
            value_mode: ValueMode::Buffered,
            text_decoder: HeaderTextDecoder::new(false),
            params: ParameterParser::new(false),
            boundary: BoundaryCollector::default(),
            header_value_sink: Vec::with_capacity(INITIAL_HEADER_VALUE_CAPACITY),
            header_raw_name: None,
            header_raw_sink: Vec::new(),
            capturing: false,
            strip_header_whitespace: true,
            decode_buffer: Vec::new(),
            transfer_encoding: TransferEncoding::Binary,
            b64_carry: [0; 3],
            b64_carry_len: 0,
            line_carry: Vec::new(),
            line_state: LineState::Start,
            held: [0; 2],
            held_len: 0,
            cand: [0; MAX_CANDIDATE_LINE],
            cand_len: 0,
            underflow: false,
            closed: false,
        }
    }

    /// The limits in force.
    pub fn limits(&self) -> &ParserLimits {
        &self.limits
    }

    /// Mutable access to the limits, to change one without restating the rest.
    pub fn limits_mut(&mut self) -> &mut ParserLimits {
        &mut self.limits
    }

    /// Replaces the limits.
    pub fn set_limits(&mut self, limits: ParserLimits) {
        self.limits = limits;
    }

    /// Sets the size of the ring [`Self::parse`] allocates for itself. It has
    /// no effect on [`Self::receive`], which reads whatever ring it is given.
    ///
    /// # Panics
    ///
    /// If `buffer_size` is zero.
    pub fn set_buffer_size(&mut self, buffer_size: usize) {
        assert!(buffer_size > 0, "buffer size must be positive");
        self.buffer_size = buffer_size;
    }

    /// Sets the most body bytes handed to the handler in one call, and the size
    /// of the buffer the transfer decoders fill. Default: 4096.
    ///
    /// # Panics
    ///
    /// If `chunk_size` is zero.
    pub fn set_chunk_size(&mut self, chunk_size: usize) {
        assert!(chunk_size > 0, "chunk size must be positive");
        self.chunk_size = chunk_size;
    }

    /// With `utf8_headers`, raw 8-bit text in an unstructured header's value that
    /// is not valid UTF-8 is read as ISO-8859-1, rather than as windows-1252.
    /// (Valid UTF-8 is read as UTF-8 either way.) Call before parsing.
    pub fn set_utf8_headers(&mut self, utf8_headers: bool) {
        self.text_decoder = HeaderTextDecoder::new(utf8_headers);
        self.params = ParameterParser::new(utf8_headers);
    }

    /// The handler the parser is driving.
    pub fn handler(&self) -> &H {
        &self.handler
    }

    /// Mutable access to the handler between calls to [`Self::receive`].
    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    /// Takes the handler back, dropping the parser.
    pub fn into_handler(self) -> H {
        self.handler
    }

    pub(crate) fn wire(&self) -> &W {
        &self.wire
    }

    pub(crate) fn wire_mut(&mut self) -> &mut W {
        &mut self.wire
    }

    /// Where the parser is in the message. The same locator the handler was
    /// given, and live.
    pub fn locator(&self) -> Rc<dyn Locator> {
        self.locator.clone()
    }

    /// True if the last [`Self::receive`] left an incomplete line in the ring.
    /// More data is needed before parsing can continue.
    pub fn is_underflow(&self) -> bool {
        self.underflow
    }

    pub fn decode_token_header_value(&self, data: &mut &[u8]) -> String {
        decode_token_header_value(data, self.strip_header_whitespace)
    }

    /// Parses as many complete lines of headers and as much body as possible
    /// from `buf`, calling the handler and consuming them from the ring.
    ///
    /// An incomplete header line stays in the ring and
    /// [`Self::is_underflow`] returns true. Add to the ring after it and call
    /// this again.
    ///
    /// # Errors
    ///
    /// A [`ParseError`] if the message is malformed, a limit is exceeded, the
    /// handler returned an error, or `buf` is full of a single header line that
    /// is not yet complete (it can never fit).
    pub fn receive(&mut self, buf: &mut LoopBuf) -> ParseResult<()> {
        if self.closed {
            return Err(ParseError::new(
                "parser is closed: call reset() to parse another message",
            ));
        }
        self.underflow = false;

        if self.state == State::Init {
            self.handler.set_locator(self.locator.clone());
            self.handler.set_limits(&self.limits);
            self.handler.start_entity(None)?;
            self.start_headers();
        }

        while !buf.is_empty() {
            if self.state == State::Header {
                if !self.header_line_from(buf)? {
                    break;
                }
            } else {
                let used = {
                    let (first, second) = buf.readable_spans();
                    self.body_chunk(if first.is_empty() { second } else { first })?
                };
                buf.advance(used);
            }
        }

        self.underflow = !buf.is_empty()
            || (self.state != State::Header
                && self.state != State::Body
                && self.line_state != LineState::Start);
        Ok(())
    }

    /// Takes the header line at the front of `buf`, if it is complete.
    fn header_line_from(&mut self, buf: &mut LoopBuf) -> ParseResult<bool> {
        let newline = {
            let (first, second) = buf.readable_spans();
            index_of(first, b'\n').or_else(|| index_of(second, b'\n').map(|i| first.len() + i))
        };
        let Some(newline) = newline else {
            if let Some(max) = self.limits.max_header_line_length {
                if buf.len() > max + 1 {
                    return Err(ParseError::with_locator(
                        MIMEMessages::HEADER_LINE_TOO_LONG,
                        &*self.locator,
                    ));
                }
            }
            if buf.is_full() {
                return Err(ParseError::with_locator(
                    MIMEMessages::HEADER_LINE_DOES_NOT_FIT,
                    &*self.locator,
                ));
            }
            return Ok(false);
        };
        let len = newline + 1;
        self.take_header_line(buf, len, true)?;
        Ok(true)
    }

    /// Uses the `len` bytes at the front of `buf` as one header line and
    /// consumes them. `ended` is false for a final line with no terminator.
    fn take_header_line(&mut self, buf: &mut LoopBuf, len: usize, ended: bool) -> ParseResult<()> {
        let mut scratch = std::mem::take(&mut self.line_scratch);
        let result = {
            let spans = buf.spans();
            let line: &[u8] = match spans.contiguous(0..len) {
                Some(line) => line,
                None => {
                    scratch.clear();
                    scratch.resize(len, 0);
                    spans.copy_to(0, &mut scratch);
                    &scratch
                }
            };
            self.locator.advance_line(len);
            let result = self.header_line(line);
            if result.is_ok() && ended {
                self.locator.end_line();
            }
            result
        };
        self.line_scratch = scratch;
        buf.advance(len);
        result
    }

    /// Completes parsing and validates state.
    ///
    /// `buf` is the same ring passed to [`Self::receive`] throughout. Anything
    /// still in it is parsed first, and a final line with no terminator is
    /// delivered all the same: as a header, as body content, or as the closing
    /// boundary. Mail stored in files and IMAP literals routinely ends that
    /// way. Fails if a multipart body is left unclosed. After closing, further
    /// calls to [`Self::receive`] return an error; use [`Self::reset`] to parse
    /// another message.
    pub fn close(&mut self, buf: &mut LoopBuf) -> ParseResult<()> {
        if self.closed {
            return Ok(());
        }
        self.receive(buf)?;
        if !buf.is_empty() {
            let len = buf.len();
            self.take_header_line(buf, len, false)?;
        } else if self.cand_len > 0 {
            // An unterminated line that may be a boundary.
            self.candidate_line_complete()?;
        }
        self.underflow = false;
        self.closed = true;

        if self.header_active {
            // Input ended inside the headers: the last one still counts.
            self.flush_raw_header()?;
            self.end_headers()?;
        }

        self.release_held()?;
        self.end_content()?;

        if !self.boundaries.is_empty() {
            let boundary = self.boundaries.last().unwrap().clone();
            return Err(ParseError::with_locator(
                format_unclosed_boundary(&boundary),
                &*self.locator,
            ));
        }

        self.handler.end_entity(None)?;
        Ok(())
    }

    /// Resets the parser to its initial state, to reuse it for a new
    /// independent message. The limits and handler are kept; the ring passed to
    /// [`Self::receive`] is caller-owned and not this parser's concern.
    pub fn reset(&mut self) {
        self.locator = Rc::new(SharedLocator::new());
        self.state = State::Init;
        self.boundaries.clear();
        self.boundary_set = false;
        self.header_name.clear();
        self.header_active = false;
        self.text_decoder.reset();
        self.header_value_sink.clear();
        self.header_raw_name = None;
        self.header_raw_sink.clear();
        self.capturing = false;
        self.decode_buffer.clear();
        self.clear_body_state();
        self.transfer_encoding = TransferEncoding::Binary;
        self.underflow = false;
        self.closed = false;
    }

    /// Parses a message from a [`Read`] source.
    ///
    /// The parser is automatically reset before parsing. Allocates one ring
    /// (sized by [`Self::set_buffer_size`]) and never grows it: reads from
    /// `reader` into its spare capacity and calls [`Self::receive`] until EOF,
    /// then [`Self::close`]. The reader is not closed.
    pub fn parse<R: Read>(&mut self, mut reader: R) -> ParseResult<()> {
        self.reset();

        let mut buf = LoopBuf::with_capacity(self.buffer_size);
        loop {
            let (spare, _) = buf.spare_capacity_mut();
            if spare.is_empty() {
                // `receive` reports a ring full of one unfinished header line,
                // so this is not reached; it is here so a bug cannot loop forever
                return Err(ParseError::new("receive buffer too small"));
            }
            let bytes_read = reader
                .read(spare)
                .map_err(|e| ParseError::new(format!("I/O error reading stream: {e}")))?;
            if bytes_read == 0 {
                break;
            }
            buf.commit_write(bytes_read);
            self.receive(&mut buf)?;
        }

        self.close(&mut buf)
    }

    fn clear_body_state(&mut self) {
        self.b64_carry_len = 0;
        self.line_carry.clear();
        self.line_state = LineState::Start;
        self.held_len = 0;
        self.cand_len = 0;
    }

    fn start_headers(&mut self) {
        self.state = State::Header;
        self.boundary_set = false;
        self.transfer_encoding = TransferEncoding::Binary;
        self.clear_body_state();
    }

    fn end_headers(&mut self) -> ParseResult<()> {
        self.flush_header()?;
        self.wire.mark_headers_complete()?;
        self.handler.end_headers()?;
        self.clear_body_state();
        if self.boundary_set {
            self.state = State::FirstBoundary;
        } else if !self.boundaries.is_empty() {
            self.state = State::BoundaryOrContent;
        } else {
            self.state = State::Body;
        }
        Ok(())
    }

    fn header_line(&mut self, line: &[u8]) -> ParseResult<()> {
        let (start, end) = strip_line_ending(line);
        if start >= end {
            self.flush_raw_header()?;
            return self.end_headers();
        }

        let length = end - start;
        if self
            .limits
            .max_header_line_length
            .is_some_and(|max| length > max)
        {
            return Err(ParseError::with_locator(
                MIMEMessages::HEADER_LINE_TOO_LONG,
                &*self.locator,
            ));
        }

        // Raw bytes are only kept for a DKIM wire sink.
        let capture = W::CAPTURES;

        let first = line[start];
        if first == b' ' || first == b'\t' {
            if !self.header_active {
                return Err(ParseError::with_locator(
                    MIMEMessages::NO_FIELD_NAME,
                    &*self.locator,
                ));
            }
            if self.capturing {
                self.check_captured_size(self.header_raw_sink.len(), line.len())?;
                self.header_raw_sink.extend_from_slice(line);
            }
            return self.feed_value(&line[start..start + length]);
        }

        if capture {
            self.flush_raw_header()?;
        }
        self.flush_header()?;

        let colon_pos = index_of(&line[start..end], b':').map(|i| start + i);
        let Some(colon_pos) = colon_pos else {
            return Err(ParseError::with_locator(
                MIMEMessages::NO_COLON_IN_HEADER,
                &*self.locator,
            ));
        };

        let mut name_end = colon_pos;
        while name_end > start && is_header_whitespace(line[name_end - 1]) {
            name_end -= 1;
        }
        if name_end <= start {
            return Err(ParseError::with_locator(
                MIMEMessages::FIELD_NAME_EMPTY,
                &*self.locator,
            ));
        }

        if let Some(&c) = line[start..name_end]
            .iter()
            .find(|c| !(33..=126).contains(*c))
        {
            return Err(ParseError::with_locator(
                format!("{}: {}", MIMEMessages::ILLEGAL_FIELD_NAME_CHAR, c),
                &*self.locator,
            ));
        }

        if self
            .limits
            .max_header_name_length
            .is_some_and(|max| name_end - start > max)
        {
            return Err(ParseError::with_locator(
                MIMEMessages::HEADER_NAME_TOO_LONG,
                &*self.locator,
            ));
        }

        // Validated above as printable ASCII, so this is plain UTF-8.
        self.header_name.clear();
        self.header_name
            .extend(line[start..name_end].iter().map(|&b| b as char));
        self.header_active = true;

        // The sink says, from the name, whether it wants the header's bytes
        self.capturing = capture && self.wire.wants_header(&self.header_name);
        if self.capturing {
            self.header_raw_name = Some(self.header_name.clone());
            self.check_captured_size(self.header_raw_sink.len(), line.len())?;
            self.header_raw_sink.extend_from_slice(line);
        }

        self.start_value()?;

        self.feed_value(&line[colon_pos + 1..end])
    }

    /// Decides how the value of the header just named is dealt with, and tells
    /// the handler it is starting if it is for the handler.
    fn start_value(&mut self) -> ParseResult<()> {
        let max_token = self.limits.max_token_length.unwrap_or(usize::MAX);
        if self.header_name.eq_ignore_ascii_case("content-type") {
            self.value_mode = ValueMode::ContentType;
            self.params.start(Kind::ContentType, max_token);
            return Ok(());
        }
        if self.header_name.eq_ignore_ascii_case("content-disposition") {
            self.value_mode = ValueMode::ContentDisposition;
            self.params.start(Kind::ContentDisposition, max_token);
            return Ok(());
        }
        if is_understood_header(&self.header_name) {
            self.value_mode = ValueMode::Buffered;
            return Ok(());
        }
        self.value_mode = match self.handler.header_delivery(&self.header_name) {
            HeaderDelivery::Unstructured => {
                self.text_decoder.reset();
                ValueMode::Unstructured
            }
            HeaderDelivery::Raw => ValueMode::Raw,
        };
        self.handler.start_header(&self.header_name)
    }

    /// Some of the current header's value, with its folds taken out.
    fn feed_value(&mut self, bytes: &[u8]) -> ParseResult<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        match self.value_mode {
            ValueMode::Buffered => {
                self.check_element_size(self.header_value_sink.len(), bytes.len())?;
                self.header_value_sink.extend_from_slice(bytes);
            }
            ValueMode::ContentType | ValueMode::ContentDisposition => {
                let kind = self.params_kind();
                let mut sink = EventSink {
                    handler: &mut self.handler,
                    kind,
                    boundary: &mut self.boundary,
                };
                if let Fed::Malformed { reason, rest } = self.params.feed(bytes, &mut sink)? {
                    self.malformed(reason, &bytes[rest..])?;
                }
            }
            ValueMode::Unstructured => {
                let handler = &mut self.handler;
                self.text_decoder
                    .feed(bytes, &mut |text| handler.header_content(text))?;
            }
            ValueMode::Raw => self.handler.raw_header_content(bytes)?,
        }
        Ok(())
    }

    fn params_kind(&self) -> Kind {
        if self.value_mode == ValueMode::ContentType {
            Kind::ContentType
        } else {
            Kind::ContentDisposition
        }
    }

    /// The value of a `Content-Type` or `Content-Disposition` is complete.
    /// False if it turned out not to be valid, in which case the handler has
    /// been told and the rest is unstructured text.
    fn finish_structured(&mut self) -> ParseResult<bool> {
        let kind = self.params_kind();
        let mut sink = EventSink {
            handler: &mut self.handler,
            kind,
            boundary: &mut self.boundary,
        };
        if let Fed::Malformed { reason, rest: _ } = self.params.finish(&mut sink)? {
            self.malformed(reason, &[])?;
            return Ok(false);
        }
        match kind {
            Kind::ContentType => {
                self.handler.end_content_type()?;
                if let Some(boundary) = self.boundary.boundary() {
                    let boundary = boundary.to_string();
                    if self.boundary_set {
                        self.boundaries.pop();
                    }
                    if let Some(max) = self.limits.max_multipart_depth {
                        if self.boundaries.len() >= max {
                            return Err(ParseError::with_locator(
                                format_multipart_too_deep(max),
                                &*self.locator,
                            ));
                        }
                    }
                    self.boundaries.push(boundary);
                    self.boundary_set = true;
                }
            }
            Kind::ContentDisposition => self.handler.end_content_disposition()?,
        }
        Ok(true)
    }

    /// The head of the `Content-Type` or `Content-Disposition` is not valid:
    /// the handler is told, and the value so far and `rest` are delivered as
    /// unstructured text.
    fn malformed(&mut self, reason: &str, rest: &[u8]) -> ParseResult<()> {
        self.handler.malformed_header(&self.header_name, reason)?;
        self.value_mode = ValueMode::Unstructured;
        self.text_decoder.reset();
        let handler = &mut self.handler;
        self.text_decoder
            .feed(self.params.head(), &mut |text| handler.header_content(text))?;
        self.text_decoder
            .feed(rest, &mut |text| handler.header_content(text))
    }

    /// Hands the accumulated header to the handler, keeping its buffers.
    fn flush_header(&mut self) -> ParseResult<()> {
        if !self.header_active {
            return Ok(());
        }
        self.header_active = false;
        let mut mode = self.value_mode;
        if matches!(mode, ValueMode::ContentType | ValueMode::ContentDisposition) {
            if self.finish_structured()? {
                return Ok(());
            }
            // it was not valid, and is now unstructured text to be finished
            mode = ValueMode::Unstructured;
        }
        match mode {
            ValueMode::ContentType | ValueMode::ContentDisposition => unreachable!(),
            ValueMode::Buffered => {
                let name = std::mem::take(&mut self.header_name);
                let value = std::mem::take(&mut self.header_value_sink);
                let result = match self.header(&name, &value) {
                    Ok(None) => Ok(()),
                    Ok(Some(reason)) => self.malformed_value(&name, reason, &value),
                    Err(e) => Err(e),
                };
                self.header_name = name;
                self.header_name.clear();
                self.header_value_sink = value;
                self.header_value_sink.clear();
                result
            }
            ValueMode::Unstructured => {
                let handler = &mut self.handler;
                self.text_decoder
                    .finish(&mut |text| handler.header_content(text))?;
                self.handler.end_header()
            }
            ValueMode::Raw => self.handler.end_header(),
        }
    }

    /// Parses one of the headers the parser holds whole. `Some` is the reason
    /// it is not valid.
    fn header(&mut self, name: &str, value: &[u8]) -> ParseResult<Option<&'static str>> {
        let is = |wanted: &str| name.eq_ignore_ascii_case(wanted);
        if is("content-transfer-encoding") {
            self.handle_content_transfer_encoding_header(value)
        } else if is("content-id") {
            self.handle_content_id_header(value)
        } else if is("mime-version") {
            self.handle_mime_version_header(value)
        } else {
            Ok(None)
        }
    }

    /// Reports a held header that is not valid, and delivers its value as
    /// unstructured text.
    fn malformed_value(&mut self, name: &str, reason: &str, value: &[u8]) -> ParseResult<()> {
        self.handler.malformed_header(name, reason)?;
        self.text_decoder.reset();
        let handler = &mut self.handler;
        self.text_decoder
            .feed(value, &mut |text| handler.header_content(text))?;
        self.text_decoder
            .finish(&mut |text| handler.header_content(text))?;
        self.handler.end_header()
    }

    fn handle_content_transfer_encoding_header(
        &mut self,
        value: &[u8],
    ) -> ParseResult<Option<&'static str>> {
        let mut slice = value;
        let value_str = decode_token_header_value(&mut slice, self.strip_header_whitespace);
        let encoding = match value_str.to_ascii_lowercase().as_str() {
            "base64" => Some(TransferEncoding::Base64),
            "quoted-printable" => Some(TransferEncoding::QuotedPrintable),
            "x-uuencode" | "x-uue" | "uuencode" | "uue" => Some(TransferEncoding::Uuencode),
            "7bit" | "8bit" | "binary" => None,
            _ if value_str.starts_with("x-") && is_token(&value_str) => None,
            _ => return Ok(Some("not a known Content-Transfer-Encoding")),
        };
        if let Some(encoding) = encoding {
            self.transfer_encoding = encoding;
        }
        self.handler.content_transfer_encoding(&value_str)?;
        Ok(None)
    }

    fn handle_content_id_header(&mut self, value: &[u8]) -> ParseResult<Option<&'static str>> {
        let mut cursor = ByteCursor::new(value);
        match ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591) {
            Some(id) => {
                self.handler.content_id(id.local_part(), id.domain())?;
                Ok(None)
            }
            None => Ok(Some("a Content-ID is one <local@domain> message-id")),
        }
    }

    fn handle_mime_version_header(&mut self, value: &[u8]) -> ParseResult<Option<&'static str>> {
        let mut slice = value;
        let value_str = decode_token_header_value(&mut slice, self.strip_header_whitespace);
        // comments are allowed in the value: `1.0 (Generated by X)`
        let uncommented = crate::mime::utils::strip_comments(&value_str);
        let parsed = uncommented.ok().and_then(|v| MimeVersion::parse(v.trim()));
        match parsed {
            Some(version) => {
                self.handler
                    .mime_version(version.major(), version.minor())?;
                Ok(None)
            }
            None => Ok(Some("not a MIME version")),
        }
    }

    /// Consumes body bytes from the front of `data` and returns how many.
    /// Stops early, after a boundary line, when a new entity's headers begin.
    fn body_chunk(&mut self, data: &[u8]) -> ParseResult<usize> {
        let used = if self.state == State::Body {
            self.emit_content(data)?;
            data.len()
        } else {
            self.scan_multipart(data)?
        };
        let consumed = &data[..used];
        self.locator.advance(consumed);
        self.wire.raw_body_content(consumed)?;
        Ok(used)
    }

    /// True for preamble and epilogue text, which is not part of any part.
    fn is_unexpected(&self) -> bool {
        matches!(self.state, State::FirstBoundary | State::BoundaryOnly)
    }

    fn boundary_line_limit(&self) -> usize {
        match self.boundaries.last() {
            Some(b) => (b.len() + 6).min(MAX_CANDIDATE_LINE),
            None => 0,
        }
    }

    /// Scans multipart body bytes. Runs of ordinary lines go to the content
    /// pipeline straight from `data`; a line starting with `-` is assembled
    /// to see whether it is a boundary; the line ending before a line is
    /// withheld until that line is known not to be a boundary (the ending
    /// belongs to the boundary then).
    fn scan_multipart(&mut self, data: &[u8]) -> ParseResult<usize> {
        let len = data.len();
        let mut i = 0usize;
        while i < len {
            match self.line_state {
                LineState::Start => {
                    if data[i] == b'-' && !self.boundaries.is_empty() {
                        self.cand_len = 0;
                        self.line_state = LineState::Candidate;
                    } else {
                        self.release_held()?;
                        self.line_state = LineState::Mid;
                    }
                }
                LineState::Candidate => {
                    let rest = &data[i..];
                    let nl = index_of(rest, b'\n');
                    let take = nl.map_or(rest.len(), |p| p + 1);
                    if self.cand_len + take > self.boundary_line_limit() {
                        // Too long to be a boundary line: ordinary content.
                        self.release_held()?;
                        let cand = self.cand;
                        let mut n = self.cand_len;
                        self.cand_len = 0;
                        self.line_state = LineState::Mid;
                        // A trailing CR may be half a line ending: withhold it
                        // as the `Mid` state does.
                        let cr = n > 0 && cand[n - 1] == b'\r';
                        if cr {
                            n -= 1;
                        }
                        self.emit_content(&cand[..n])?;
                        if cr {
                            self.held[0] = b'\r';
                            self.held_len = 1;
                        }
                        continue;
                    }
                    self.cand[self.cand_len..self.cand_len + take].copy_from_slice(&rest[..take]);
                    self.cand_len += take;
                    i += take;
                    if nl.is_some() && self.candidate_line_complete()? {
                        return Ok(i);
                    }
                }
                LineState::Mid => {
                    if self.held_len == 1 {
                        // A withheld CR: it ends the line if LF follows.
                        if data[i] == b'\n' {
                            self.held[1] = b'\n';
                            self.held_len = 2;
                            self.line_state = LineState::Start;
                            i += 1;
                            continue;
                        }
                        self.release_held()?;
                    }
                    let rest = &data[i..];
                    // The run ends at the first line ending that is followed
                    // by `-` (a possible boundary) or by the end of the input.
                    let mut from = 0usize;
                    loop {
                        match index_of(&rest[from..], b'\n') {
                            Some(q) => {
                                let nl = from + q;
                                if nl + 1 < rest.len() && rest[nl + 1] != b'-' {
                                    from = nl + 1;
                                    continue;
                                }
                                let cr = nl > 0 && rest[nl - 1] == b'\r';
                                let end = if cr { nl - 1 } else { nl };
                                self.emit_content(&rest[..end])?;
                                self.held_len = if cr { 2 } else { 1 };
                                self.held[0] = if cr { b'\r' } else { b'\n' };
                                self.held[1] = b'\n';
                                self.line_state = LineState::Start;
                                i += nl + 1;
                            }
                            None => {
                                let cr = rest[rest.len() - 1] == b'\r';
                                let end = if cr { rest.len() - 1 } else { rest.len() };
                                self.emit_content(&rest[..end])?;
                                if cr {
                                    self.held[0] = b'\r';
                                    self.held_len = 1;
                                }
                                i = len;
                            }
                        }
                        break;
                    }
                }
            }
        }
        Ok(i)
    }

    /// A line that started with `-` is complete in `cand` (or the input
    /// ended). Returns true when it starts a new entity's headers.
    fn candidate_line_complete(&mut self) -> ParseResult<bool> {
        let line = self.cand;
        let n = self.cand_len;
        self.cand_len = 0;
        self.line_state = LineState::Start;
        let line = &line[..n];

        let found = match self.boundaries.last() {
            Some(boundary) => check_boundary(line, boundary),
            None => None,
        };
        let Some(m) = found else {
            self.release_held()?;
            let (content, eol) = split_line_ending(line);
            self.emit_content(content)?;
            self.held_len = eol.len();
            self.held[..eol.len()].copy_from_slice(eol);
            if eol.is_empty() {
                self.line_state = LineState::Mid;
            }
            return Ok(false);
        };

        // The line ending before a boundary belongs to the boundary.
        self.held_len = 0;
        self.end_content()?;
        match self.state {
            State::FirstBoundary | State::BoundaryOnly => {
                if m.is_end_boundary {
                    self.handler.end_entity(Some(&m.boundary))?;
                    self.transfer_encoding = TransferEncoding::Binary;
                    self.boundaries.pop();
                    self.state = State::BoundaryOnly;
                    return Ok(false);
                }
                self.handler.start_entity(Some(&m.boundary))?;
            }
            _ => {
                if m.is_end_boundary {
                    self.handler.end_entity(Some(&m.boundary))?;
                    self.transfer_encoding = TransferEncoding::Binary;
                    self.boundaries.pop();
                    if let Some(parent) = self.boundaries.last() {
                        let parent = parent.clone();
                        self.handler.end_entity(Some(&parent))?;
                    }
                    self.state = State::BoundaryOnly;
                    return Ok(false);
                }
                self.handler.end_entity(Some(&m.boundary))?;
                self.handler.start_entity(Some(&m.boundary))?;
            }
        }
        self.transfer_encoding = TransferEncoding::Binary;
        self.start_headers();
        Ok(true)
    }

    /// Emits the withheld line ending as content.
    fn release_held(&mut self) -> ParseResult<()> {
        if self.held_len > 0 {
            let held = self.held;
            let n = self.held_len;
            self.held_len = 0;
            self.emit_content(&held[..n])?;
        }
        Ok(())
    }

    /// Sends body bytes through the Content-Transfer-Encoding decoder (if
    /// any) to the handler.
    fn emit_content(&mut self, data: &[u8]) -> ParseResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        match self.transfer_encoding {
            TransferEncoding::Binary => {
                for chunk in data.chunks(self.chunk_size) {
                    self.route(chunk)?;
                }
                Ok(())
            }
            TransferEncoding::Base64 => self.decode_base64_stream(data),
            TransferEncoding::QuotedPrintable | TransferEncoding::Uuencode => {
                self.decode_line_stream(data)
            }
        }
    }

    fn route(&mut self, chunk: &[u8]) -> ParseResult<()> {
        if self.is_unexpected() {
            self.handler.unexpected_content(chunk)
        } else {
            self.handler.body_content(chunk)
        }
    }

    fn ensure_decode_buffer(&mut self) {
        if self.decode_buffer.capacity() < self.chunk_size {
            self.decode_buffer
                .reserve(self.chunk_size - self.decode_buffer.len());
        }
    }

    /// Hands `decode_buffer` to the handler; the buffer is kept for reuse.
    fn deliver_decoded(&mut self) -> ParseResult<()> {
        if self.decode_buffer.is_empty() {
            return Ok(());
        }
        let out = std::mem::take(&mut self.decode_buffer);
        let result = self.route(&out);
        self.decode_buffer = out;
        self.decode_buffer.clear();
        result
    }

    fn decode_base64_stream(&mut self, data: &[u8]) -> ParseResult<()> {
        self.ensure_decode_buffer();
        let max = self.chunk_size.max(3);
        let mut src = data;

        if self.b64_carry_len > 0 {
            self.decode_buffer.clear();
            self.complete_b64_quantum(&mut src);
            self.deliver_decoded()?;
        }
        while !src.is_empty() {
            self.decode_buffer.clear();
            // A partial quantum stays in the carry; padding ends one itself.
            let consumed = decode_base64(&mut src, &mut self.decode_buffer, max, false, false);
            self.deliver_decoded()?;
            if consumed == 0 {
                break;
            }
        }
        if !src.is_empty() {
            self.save_b64_carry(src);
        }
        Ok(())
    }

    /// Completes the carried partial quantum with characters from the front
    /// of `src`, decoding it into `decode_buffer`. If `src` runs out first
    /// the characters join the carry.
    fn complete_b64_quantum(&mut self, src: &mut &[u8]) {
        let mut group = [0u8; 4];
        let mut n = self.b64_carry_len;
        group[..n].copy_from_slice(&self.b64_carry[..n]);
        let mut padded = false;
        let data = *src;
        let mut i = 0;
        while n < 4 && i < data.len() {
            let b = data[i];
            i += 1;
            if is_base64_char(b) {
                group[n] = b;
                n += 1;
            } else if b == b'=' {
                group[n] = b;
                n += 1;
                padded = true;
                break;
            }
        }
        *src = &data[i..];
        if n == 4 || padded {
            self.b64_carry_len = 0;
            let mut g: &[u8] = &group[..n];
            decode_base64(&mut g, &mut self.decode_buffer, 4, padded, false);
        } else {
            self.b64_carry[..n].copy_from_slice(&group[..n]);
            self.b64_carry_len = n;
        }
    }

    /// Keeps the base64 characters of an incomplete quantum left in `rest`.
    fn save_b64_carry(&mut self, rest: &[u8]) {
        let mut n = 0;
        for &b in rest {
            if is_base64_char(b) && n < 3 {
                self.b64_carry[n] = b;
                n += 1;
            }
        }
        self.b64_carry_len = n;
    }

    /// Quoted-printable and uuencode decode whole lines: complete lines are
    /// decoded straight from `data`, a partial one waits in `line_carry`.
    fn decode_line_stream(&mut self, data: &[u8]) -> ParseResult<()> {
        let mut src = data;
        if !self.line_carry.is_empty() {
            match index_of(src, b'\n') {
                Some(nl) => {
                    self.line_carry.extend_from_slice(&src[..=nl]);
                    src = &src[nl + 1..];
                    let line = std::mem::take(&mut self.line_carry);
                    let result = self.decode_lines(&line, false);
                    self.line_carry = line;
                    self.line_carry.clear();
                    result?;
                }
                None => {
                    self.line_carry.extend_from_slice(src);
                    return self.limit_line_carry();
                }
            }
        }
        if let Some(last) = src.iter().rposition(|&b| b == b'\n') {
            self.decode_lines(&src[..=last], false)?;
            src = &src[last + 1..];
        }
        self.line_carry.extend_from_slice(src);
        self.limit_line_carry()
    }

    /// An endless line cannot wait forever: decode what is held.
    fn limit_line_carry(&mut self) -> ParseResult<()> {
        if self.line_carry.len() > MAX_ENCODED_LINE {
            let line = std::mem::take(&mut self.line_carry);
            let result = self.decode_lines(&line, true);
            self.line_carry = line;
            self.line_carry.clear();
            result?;
        }
        Ok(())
    }

    fn decode_lines(&mut self, lines: &[u8], end_of_stream: bool) -> ParseResult<()> {
        self.ensure_decode_buffer();
        let max = self.chunk_size.max(3);
        let mut src = lines;
        while !src.is_empty() {
            self.decode_buffer.clear();
            let consumed = if self.transfer_encoding == TransferEncoding::QuotedPrintable {
                decode_quoted_printable(&mut src, &mut self.decode_buffer, max, end_of_stream)
            } else {
                decode_uuencode(&mut src, &mut self.decode_buffer, max, end_of_stream)
            };
            self.deliver_decoded()?;
            if consumed == 0 {
                break;
            }
        }
        Ok(())
    }

    /// End of an entity's body: flush what the decoders still hold.
    fn end_content(&mut self) -> ParseResult<()> {
        match self.transfer_encoding {
            TransferEncoding::Binary => {}
            TransferEncoding::Base64 => {
                if self.b64_carry_len > 0 {
                    let mut group = [0u8; 3];
                    let n = self.b64_carry_len;
                    group[..n].copy_from_slice(&self.b64_carry[..n]);
                    self.b64_carry_len = 0;
                    self.ensure_decode_buffer();
                    self.decode_buffer.clear();
                    let mut g: &[u8] = &group[..n];
                    decode_base64(&mut g, &mut self.decode_buffer, 4, true, false);
                    self.deliver_decoded()?;
                }
            }
            TransferEncoding::QuotedPrintable | TransferEncoding::Uuencode => {
                if self.transfer_encoding == TransferEncoding::QuotedPrintable
                    && self.line_carry.last() == Some(&b'=')
                {
                    // A soft line break whose line ending was withheld.
                    self.line_carry.pop();
                }
                if !self.line_carry.is_empty() {
                    let line = std::mem::take(&mut self.line_carry);
                    let result = self.decode_lines(&line, true);
                    self.line_carry = line;
                    self.line_carry.clear();
                    result?;
                }
            }
        }
        Ok(())
    }

    fn check_element_size(&self, current: usize, required: usize) -> ParseResult<()> {
        self.check_size(self.limits.max_element_length, current, required)
    }

    fn check_captured_size(&self, current: usize, required: usize) -> ParseResult<()> {
        self.check_size(self.limits.max_captured_header_size, current, required)
    }

    fn check_size(&self, max: Option<usize>, current: usize, required: usize) -> ParseResult<()> {
        if let Some(max) = max.filter(|&max| current + required > max) {
            return Err(ParseError::with_locator(
                format_header_value_too_long(max),
                &*self.locator,
            ));
        }
        Ok(())
    }

    fn flush_raw_header(&mut self) -> ParseResult<()> {
        if let Some(name) = self.header_raw_name.take() {
            if !self.header_raw_sink.is_empty() {
                self.wire.raw_header(&name, &self.header_raw_sink)?;
            }
            self.header_raw_sink.clear();
        }
        Ok(())
    }
}

pub fn check_boundary(line: &[u8], boundary: &str) -> Option<BoundaryMatch> {
    let (start, end) = (0usize, line.len());
    if end - start < 2 {
        return None;
    }

    let bytes = line;
    let mut pos = start;

    if bytes[pos] != b'-' || bytes[pos + 1] != b'-' {
        return None;
    }
    pos += 2;

    for ch in boundary.bytes() {
        if pos >= end || bytes[pos] != ch {
            return None;
        }
        pos += 1;
    }

    let remaining = end - pos;
    match remaining {
        0 => Some(BoundaryMatch {
            boundary: boundary.to_string(),
            is_end_boundary: false,
        }),
        1 => {
            let c = bytes[pos];
            if c == b'\n' || c == b'\r' {
                Some(BoundaryMatch {
                    boundary: boundary.to_string(),
                    is_end_boundary: false,
                })
            } else {
                None
            }
        }
        2 => {
            let c1 = bytes[pos];
            let c2 = bytes[pos + 1];
            if c1 == b'\r' && c2 == b'\n' {
                Some(BoundaryMatch {
                    boundary: boundary.to_string(),
                    is_end_boundary: false,
                })
            } else if c1 == b'-' && c2 == b'-' {
                Some(BoundaryMatch {
                    boundary: boundary.to_string(),
                    is_end_boundary: true,
                })
            } else {
                None
            }
        }
        _ => {
            if bytes[pos] == b'-' && bytes[pos + 1] == b'-' {
                pos += 2;
                let trailing = end - pos;
                match trailing {
                    0 => Some(BoundaryMatch {
                        boundary: boundary.to_string(),
                        is_end_boundary: true,
                    }),
                    1 => {
                        let c = bytes[pos];
                        if c == b'\n' || c == b'\r' {
                            Some(BoundaryMatch {
                                boundary: boundary.to_string(),
                                is_end_boundary: true,
                            })
                        } else {
                            None
                        }
                    }
                    2 => {
                        if bytes[pos] == b'\r' && bytes[pos + 1] == b'\n' {
                            Some(BoundaryMatch {
                                boundary: boundary.to_string(),
                                is_end_boundary: true,
                            })
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            } else {
                None
            }
        }
    }
}

/// The headers the parser understands itself; every other header is delivered
/// to the handler.
fn is_understood_header(name: &str) -> bool {
    ["content-transfer-encoding", "content-id", "mime-version"]
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known))
}

fn is_header_whitespace(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn strip_line_ending(line: &[u8]) -> (usize, usize) {
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
        if end > 0 && line[end - 1] == b'\r' {
            end -= 1;
        }
    }
    (0, end)
}

/// Splits a line into its content and its line ending (possibly empty).
fn split_line_ending(line: &[u8]) -> (&[u8], &[u8]) {
    let (_, end) = strip_line_ending(line);
    line.split_at(end)
}
