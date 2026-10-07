//! Push-based MIME entity parser (gumdrop `MIMEParser` port).

use crate::buffer::ByteCursor;
use crate::charset::HeaderCharset;
use crate::mime::content_type_parser::{ContentDispositionParser, ContentTypeParser};
use crate::mime::content_types::MimeVersion;
use crate::mime::content_id_parser::ContentIdParser;
use crate::mime::decoders::{
    decode_base64, decode_quoted_printable, decode_uuencode, is_base64_char,
};
use crate::mime::error::{
    HeaderLineTooLongError, HeaderValueTooLongError, MimeParseError, ParseResult,
};
use crate::mime::handler::{MimeHandler, MimeLocator};
use crate::mime::messages::{
    format_header_value_too_long, format_unclosed_boundary,
    MIMEMessages,
};
use crate::mime::utils::{decode_token_header_value, index_of, is_token,
                         is_valid_boundary};
use crate::mime::wire_sink::MimeWireSink;

const MAX_HEADER_LINE_LENGTH: usize = 998;
const INITIAL_HEADER_VALUE_CAPACITY: usize = 1024;
const DEFAULT_MAX_HEADER_VALUE_SIZE: usize = 32 * 1024;

#[derive(Debug, Default, Clone)]
pub struct MessageHeaderState {
    pub smtp_utf8: bool,
    pub used_obsolete_syntax: bool,
}

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

/// Event-driven MIME parser with rprotobuf-style `receive(&mut &[u8])` contract.
///
/// Header lines are parsed whole: a partial header line stays in the
/// caller's slice. Body bytes are consumed as they arrive and delivered as
/// zero-copy runs; the parser only holds back a possible boundary line and
/// the line ending before it.
pub struct MimeParser<'a, H: MimeHandler + ?Sized> {
    handler: &'a mut H,
    /// Optional wire sink for DKIM-style raw capture (not exposed on [`MimeHandler`]).
    wire: Option<&'a mut dyn MimeWireSink>,
    locator: MimeLocator,
    state: State,
    boundaries: Vec<String>,
    boundary_set: bool,
    /// Field name of the header being accumulated; the buffers are reused.
    header_name: String,
    header_active: bool,
    header_value_sink: Vec<u8>,
    header_raw_name: Option<String>,
    header_raw_sink: Vec<u8>,
    strip_header_whitespace: bool,
    max_buffer_size: usize,
    max_header_value_size: usize,
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
}

impl<'a, H: MimeHandler + ?Sized> MimeParser<'a, H> {
    pub fn new(handler: &'a mut H) -> Self {
        Self::build(handler, None)
    }

    /// Like [`Self::new`], but also delivers wire-accurate header/body bytes to `wire`.
    ///
    /// Used by [`crate::DkimMessageParser`]; not part of the everyday handler API.
    pub(crate) fn with_wire(handler: &'a mut H, wire: &'a mut dyn MimeWireSink) -> Self {
        Self::build(handler, Some(wire))
    }

    fn build(handler: &'a mut H, wire: Option<&'a mut dyn MimeWireSink>) -> Self {
        Self {
            handler,
            wire,
            locator: MimeLocator::default(),
            state: State::Init,
            boundaries: Vec::new(),
            boundary_set: false,
            header_name: String::new(),
            header_active: false,
            header_value_sink: Vec::with_capacity(INITIAL_HEADER_VALUE_CAPACITY),
            header_raw_name: None,
            header_raw_sink: Vec::new(),
            strip_header_whitespace: true,
            max_buffer_size: 4096,
            max_header_value_size: DEFAULT_MAX_HEADER_VALUE_SIZE,
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
        }
    }

    pub fn locator(&self) -> &MimeLocator {
        &self.locator
    }

    pub fn is_underflow(&self) -> bool {
        self.underflow
    }

    pub fn decode_token_header_value(&self, data: &mut &[u8]) -> String {
        decode_token_header_value(data, self.strip_header_whitespace)
    }

    pub fn set_max_buffer_size(&mut self, max_buffer_size: usize) -> ParseResult<()> {
        if max_buffer_size == 0 {
            return Err(MimeParseError::new(
                MIMEMessages::MAX_BUFFER_SIZE_NOT_POSITIVE,
            ));
        }
        self.max_buffer_size = max_buffer_size;
        Ok(())
    }

    pub fn set_max_header_value_size(&mut self, max_header_value_size: usize) -> ParseResult<()> {
        if max_header_value_size == 0 {
            return Err(MimeParseError::new(
                MIMEMessages::MAX_HEADER_VALUE_SIZE_NOT_POSITIVE,
            ));
        }
        self.max_header_value_size = max_header_value_size;
        Ok(())
    }

    pub fn receive(&mut self, data: &mut &[u8]) -> ParseResult<()> {
        self.underflow = false;

        if self.state == State::Init {
            self.locator.reset();
            self.handler.set_locator(&self.locator)?;
            self.handler.start_entity(None)?;
            self.start_headers();
        }

        let bytes = *data;
        let mut pos = 0usize;
        while pos < bytes.len() {
            if self.state == State::Header {
                let rest = &bytes[pos..];
                match index_of(rest, b'\n') {
                    Some(nl) => {
                        let line = &rest[..=nl];
                        pos += nl + 1;
                        self.locator.offset += line.len() as i64;
                        self.locator.column_number += line.len() as i64;
                        self.header_line(line)?;
                        self.locator.line_number += 1;
                        self.locator.column_number = 0;
                    }
                    None => {
                        if rest.len() > MAX_HEADER_LINE_LENGTH + 1 {
                            return Err(HeaderLineTooLongError::new(
                                MIMEMessages::HEADER_LINE_TOO_LONG,
                                &self.locator,
                            )
                            .into());
                        }
                        break;
                    }
                }
            } else {
                pos += self.body_chunk(&bytes[pos..])?;
            }
        }

        *data = &bytes[pos..];
        self.underflow = !data.is_empty()
            || (self.state != State::Header
                && self.state != State::Body
                && self.line_state != LineState::Start);
        Ok(())
    }

    /// Feed the last of the input and close. Unlike [`Self::receive`]
    /// followed by [`Self::close`], a final line that has no terminator is
    /// still delivered: as body content, or as the closing boundary. Mail
    /// stored in files and IMAP literals routinely end that way.
    pub fn finish(&mut self, data: &mut &[u8]) -> ParseResult<()> {
        self.receive(data)?;
        if !data.is_empty() {
            let line = *data;
            *data = &[];
            self.locator.offset += line.len() as i64;
            self.locator.column_number += line.len() as i64;
            self.header_line(line)?;
        } else if self.cand_len > 0 {
            // An unterminated line that may be a boundary.
            self.candidate_line_complete()?;
        }
        self.underflow = false;
        self.close()
    }

    pub fn close(&mut self) -> ParseResult<()> {
        if self.underflow {
            match self.state {
                State::Init | State::Header => {
                    return Err(MimeParseError::with_locator(
                        MIMEMessages::INCOMPLETE_HEADER,
                        &self.locator,
                    ));
                }
                State::FirstBoundary | State::BoundaryOrContent | State::BoundaryOnly => {
                    return Err(MimeParseError::with_locator(
                        MIMEMessages::INCOMPLETE_MULTIPART,
                        &self.locator,
                    ));
                }
                State::Body => {}
            }
        }

        if self.header_active {
            self.end_headers()?;
        }

        self.release_held()?;
        self.end_content()?;

        if !self.boundaries.is_empty() {
            let boundary = self.boundaries.last().unwrap().clone();
            return Err(MimeParseError::with_locator(
                format_unclosed_boundary(&boundary),
                &self.locator,
            ));
        }

        self.handler.end_entity(None)?;
        Ok(())
    }

    pub fn reset(&mut self) {
        self.locator.reset();
        self.state = State::Init;
        self.boundaries.clear();
        self.boundary_set = false;
        self.header_name.clear();
        self.header_active = false;
        self.header_value_sink.clear();
        self.header_raw_name = None;
        self.header_raw_sink.clear();
        self.decode_buffer.clear();
        self.clear_body_state();
        self.transfer_encoding = TransferEncoding::Binary;
        self.underflow = false;
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
        if let Some(wire) = self.wire.as_mut() {
            wire.mark_headers_complete()?;
        }
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
        if length > MAX_HEADER_LINE_LENGTH {
            return Err(HeaderLineTooLongError::new(
                MIMEMessages::HEADER_LINE_TOO_LONG,
                &self.locator,
            )
            .into());
        }

        // Raw bytes are only kept for a DKIM wire sink.
        let capture = self.wire.is_some();

        let first = line[start];
        if first == b' ' || first == b'\t' {
            if !self.header_active {
                return Err(MimeParseError::with_locator(
                    MIMEMessages::NO_FIELD_NAME,
                    &self.locator,
                ));
            }
            if capture {
                self.check_header_size(self.header_raw_sink.len(), line.len())?;
                self.header_raw_sink.extend_from_slice(line);
            }
            if length > 0 {
                self.check_header_size(self.header_value_sink.len(), length)?;
                self.header_value_sink
                    .extend_from_slice(&line[start..start + length]);
            }
            return Ok(());
        }

        if capture {
            self.flush_raw_header()?;
        }
        self.flush_header()?;

        if capture {
            self.header_raw_name = extract_raw_header_name(line, start, end);
            self.check_header_size(self.header_raw_sink.len(), line.len())?;
            self.header_raw_sink.extend_from_slice(line);
        }

        let colon_pos = index_of(&line[start..end], b':').map(|i| start + i);
        let Some(colon_pos) = colon_pos else {
            return Err(MimeParseError::with_locator(
                MIMEMessages::NO_COLON_IN_HEADER,
                &self.locator,
            ));
        };

        let mut name_end = colon_pos;
        while name_end > start && is_header_whitespace(line[name_end - 1]) {
            name_end -= 1;
        }
        if name_end <= start {
            return Err(MimeParseError::with_locator(
                MIMEMessages::FIELD_NAME_EMPTY,
                &self.locator,
            ));
        }

        for i in start..name_end {
            let c = line[i];
            if c < 33 || c > 126 {
                return Err(MimeParseError::with_locator(
                    format!("{}: {}", MIMEMessages::ILLEGAL_FIELD_NAME_CHAR, c),
                    &self.locator,
                ));
            }
        }

        // Validated above as printable ASCII, so this is plain UTF-8.
        self.header_name.clear();
        self.header_name
            .extend(line[start..name_end].iter().map(|&b| b as char));
        self.header_active = true;

        let value_length = end.saturating_sub(colon_pos + 1);
        if value_length > 0 {
            self.check_header_size(self.header_value_sink.len(), value_length)?;
            self.header_value_sink
                .extend_from_slice(&line[colon_pos + 1..end]);
        }

        Ok(())
    }

    /// Hands the accumulated header to the handler, keeping its buffers.
    fn flush_header(&mut self) -> ParseResult<()> {
        if !self.header_active {
            return Ok(());
        }
        self.header_active = false;
        let name = std::mem::take(&mut self.header_name);
        let value = std::mem::take(&mut self.header_value_sink);
        let result = self.dispatch_header(&name, &value);
        self.header_name = name;
        self.header_name.clear();
        self.header_value_sink = value;
        self.header_value_sink.clear();
        result
    }

    fn dispatch_header(&mut self, name: &str, value: &[u8]) -> ParseResult<()> {
        if self.handler.pre_mime_header(name, value)? {
            return Ok(());
        }
        self.header(name, value)
    }

    fn header(&mut self, name: &str, value: &[u8]) -> ParseResult<()> {
        let is = |wanted: &str| name.eq_ignore_ascii_case(wanted);
        if is("content-type") {
            self.handle_content_type_header(value)
        } else if is("content-disposition") {
            self.handle_content_disposition_header(value)
        } else if is("content-transfer-encoding") {
            self.handle_content_transfer_encoding_header(value)
        } else if is("content-id") {
            self.handle_content_id_header(value)
        } else if is("content-description") {
            self.handle_content_description_header(value)
        } else if is("mime-version") {
            self.handle_mime_version_header(value)
        } else {
            Ok(())
        }
    }

    fn handle_content_type_header(&mut self, value: &[u8]) -> ParseResult<()> {
        let mut cursor = ByteCursor::new(value);
        if let Some(content_type) =
            ContentTypeParser::parse(&mut cursor, HeaderCharset::Iso88591)
        {
            if content_type.is_primary_type("multipart") {
                if let Some(boundary) = content_type.parameter("boundary") {
                    if is_valid_boundary(boundary) {
                        if self.boundary_set {
                            self.boundaries.pop();
                        }
                        self.boundaries.push(boundary.to_string());
                        self.boundary_set = true;
                    }
                }
            }
            self.handler.content_type(&content_type)?;
        }
        Ok(())
    }

    fn handle_content_disposition_header(&mut self, value: &[u8]) -> ParseResult<()> {
        let mut cursor = ByteCursor::new(value);
        if let Some(disposition) =
            ContentDispositionParser::parse(&mut cursor, HeaderCharset::Iso88591)
        {
            self.handler.content_disposition(&disposition)?;
        }
        Ok(())
    }

    fn handle_content_transfer_encoding_header(&mut self, value: &[u8]) -> ParseResult<()> {
        let mut slice = value;
        let value_str = decode_token_header_value(&mut slice, self.strip_header_whitespace);
        match value_str.to_ascii_lowercase().as_str() {
            "base64" => {
                self.transfer_encoding = TransferEncoding::Base64;
                self.handler.content_transfer_encoding(&value_str)?;
            }
            "quoted-printable" => {
                self.transfer_encoding = TransferEncoding::QuotedPrintable;
                self.handler.content_transfer_encoding(&value_str)?;
            }
            "x-uuencode" | "x-uue" | "uuencode" | "uue" => {
                self.transfer_encoding = TransferEncoding::Uuencode;
                self.handler.content_transfer_encoding(&value_str)?;
            }
            "7bit" | "8bit" | "binary" => {
                self.handler.content_transfer_encoding(&value_str)?;
            }
            _ if value_str.starts_with("x-") && is_token(&value_str) => {
                self.handler.content_transfer_encoding(&value_str)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_content_id_header(&mut self, value: &[u8]) -> ParseResult<()> {
        let mut cursor = ByteCursor::new(value);
        if let Some(id) = ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591) {
            self.handler.content_id(&id)?;
        }
        Ok(())
    }

    fn handle_content_description_header(&mut self, value: &[u8]) -> ParseResult<()> {
        let mut slice = value;
        let value_str = decode_token_header_value(&mut slice, self.strip_header_whitespace);
        self.handler.content_description(&value_str)?;
        Ok(())
    }

    fn handle_mime_version_header(&mut self, value: &[u8]) -> ParseResult<()> {
        let mut slice = value;
        let value_str = decode_token_header_value(&mut slice, self.strip_header_whitespace);
        if let Some(version) = MimeVersion::parse(&value_str) {
            self.handler.mime_version(version)?;
        }
        Ok(())
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
        self.advance_locator(consumed);
        if let Some(wire) = self.wire.as_mut() {
            wire.raw_body_content(consumed)?;
        }
        Ok(used)
    }

    fn advance_locator(&mut self, bytes: &[u8]) {
        self.locator.offset += bytes.len() as i64;
        match bytes.iter().rposition(|&b| b == b'\n') {
            None => self.locator.column_number += bytes.len() as i64,
            Some(last) => {
                self.locator.line_number += bytes.iter().filter(|&&b| b == b'\n').count() as i64;
                self.locator.column_number = (bytes.len() - 1 - last) as i64;
            }
        }
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
                for chunk in data.chunks(self.max_buffer_size) {
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
        if self.decode_buffer.capacity() < self.max_buffer_size {
            self.decode_buffer
                .reserve(self.max_buffer_size - self.decode_buffer.len());
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
        let max = self.max_buffer_size.max(3);
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
        let max = self.max_buffer_size.max(3);
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

    fn check_header_size(&self, current: usize, required: usize) -> ParseResult<()> {
        if current + required > self.max_header_value_size {
            return Err(HeaderValueTooLongError::new(
                format_header_value_too_long(self.max_header_value_size),
                &self.locator,
            )
            .into());
        }
        Ok(())
    }

    fn flush_raw_header(&mut self) -> ParseResult<()> {
        if let Some(name) = self.header_raw_name.take() {
            if !self.header_raw_sink.is_empty() {
                if let Some(wire) = self.wire.as_mut() {
                    wire.raw_header(&name, &self.header_raw_sink)?;
                }
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

fn is_header_whitespace(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn extract_raw_header_name(line: &[u8], start: usize, end: usize) -> Option<String> {
    let slice = &line[start..end];
    let colon = slice.iter().position(|&b| b == b':')?;
    let name = trim_ascii_ws_bytes(&slice[..colon]);
    if name.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(name).into_owned())
}

fn trim_ascii_ws_bytes(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| *b != b' ' && *b != b'\t')
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| *b != b' ' && *b != b'\t')
        .map(|i| i + 1)
        .unwrap_or(start);
    &bytes[start..end]
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
