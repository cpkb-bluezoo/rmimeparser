//! Push-based MIME entity parser (gumdrop `MIMEParser` port).

use crate::buffer::ByteCursor;
use crate::charset::HeaderCharset;
use crate::mime::content_type_parser::{ContentDispositionParser, ContentTypeParser};
use crate::mime::content_types::MimeVersion;
use crate::mime::content_id_parser::ContentIdParser;
use crate::mime::decoders::{decode_base64, decode_quoted_printable};
use crate::mime::error::{
    HeaderLineTooLongError, HeaderValueTooLongError, MimeParseError, ParseResult,
};
use crate::mime::handler::{MimeHandler, MimeLocator};
use crate::mime::messages::{
    format_header_value_too_long, format_unclosed_boundary, format_unexpected_parser_state,
    MIMEMessages,
};
use crate::mime::utils::{decode_header_bytes, decode_token_header_value, index_of, is_token,
                         is_valid_boundary};

const MAX_HEADER_LINE_LENGTH: usize = 998;
const INITIAL_HEADER_VALUE_CAPACITY: usize = 1024;
const INITIAL_PENDING_BODY_CAPACITY: usize = 4096;
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
}

/// Event-driven MIME parser with rprotobuf-style `receive(&mut &[u8])` contract.
pub struct MimeParser<'a, H: MimeHandler + ?Sized> {
    handler: &'a mut H,
    locator: MimeLocator,
    state: State,
    boundaries: Vec<String>,
    boundary_set: bool,
    header_name: Option<String>,
    header_value_sink: Vec<u8>,
    header_raw_name: Option<String>,
    header_raw_sink: Vec<u8>,
    strip_header_whitespace: bool,
    allow_cr_line_end: bool,
    max_buffer_size: usize,
    max_header_value_size: usize,
    decode_buffer: Vec<u8>,
    content_flushed: bool,
    pending_body_content: Vec<u8>,
    pending_body_content_unexpected: bool,
    transfer_encoding: TransferEncoding,
    last: u8,
    underflow: bool,
}

impl<'a, H: MimeHandler + ?Sized> MimeParser<'a, H> {
    pub fn new(handler: &'a mut H) -> Self {
        Self {
            handler,
            locator: MimeLocator::default(),
            state: State::Init,
            boundaries: Vec::new(),
            boundary_set: false,
            header_name: None,
            header_value_sink: Vec::with_capacity(INITIAL_HEADER_VALUE_CAPACITY),
            header_raw_name: None,
            header_raw_sink: Vec::with_capacity(INITIAL_HEADER_VALUE_CAPACITY),
            strip_header_whitespace: true,
            allow_cr_line_end: false,
            max_buffer_size: 4096,
            max_header_value_size: DEFAULT_MAX_HEADER_VALUE_SIZE,
            decode_buffer: Vec::new(),
            content_flushed: false,
            pending_body_content: Vec::new(),
            pending_body_content_unexpected: false,
            transfer_encoding: TransferEncoding::Binary,
            last: 0,
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
        let mut start = 0usize;
        let len = bytes.len();

        for pos in 0..len {
            let c = bytes[pos];
            self.locator.offset += 1;
            self.locator.column_number += 1;

            let mut eol = None;
            if c == b'\n' {
                eol = Some(pos + 1);
            } else if self.allow_cr_line_end && self.last == b'\r' {
                eol = Some(pos);
            }
            self.last = c;

            if let Some(end) = eol {
                let line = &bytes[start..end];
                match self.state {
                    State::Header => self.header_line(line)?,
                    _ => self.body_line(line)?,
                }
                start = end;
                self.locator.line_number += 1;
                self.locator.column_number = 0;
            }
        }

        *data = &bytes[start..];
        self.underflow = !data.is_empty();
        Ok(())
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

        if self.header_name.is_some() {
            self.end_headers()?;
        }

        self.flush_pending_body_content(false)?;

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
        self.header_name = None;
        self.header_value_sink.clear();
        self.header_raw_name = None;
        self.header_raw_sink.clear();
        self.decode_buffer.clear();
        self.content_flushed = false;
        self.clear_pending_body_content();
        self.transfer_encoding = TransferEncoding::Binary;
        self.last = 0;
        self.underflow = false;
    }

    fn start_headers(&mut self) {
        self.state = State::Header;
        self.boundary_set = false;
        self.content_flushed = false;
        self.transfer_encoding = TransferEncoding::Binary;
        self.clear_pending_body_content();
    }

    fn end_headers(&mut self) -> ParseResult<()> {
        if let Some(name) = self.header_name.take() {
            let value = std::mem::take(&mut self.header_value_sink);
            self.dispatch_header(&name, &value)?;
        }
        self.handler.end_headers()?;
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
        let (start, end) = strip_line_ending(line, self.allow_cr_line_end);
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

        let first = line[start];
        if first == b' ' || first == b'\t' {
            if self.header_name.is_none() {
                return Err(MimeParseError::with_locator(
                    MIMEMessages::NO_FIELD_NAME,
                    &self.locator,
                ));
            }
            self.ensure_header_raw_sink_capacity(line.len())?;
            self.header_raw_sink.extend_from_slice(line);
            if length > 0 {
                self.ensure_header_value_sink_capacity(length)?;
                self.header_value_sink
                    .extend_from_slice(&line[start..start + length]);
            }
            return Ok(());
        }

        self.flush_raw_header()?;
        if let Some(name) = self.header_name.take() {
            let value = std::mem::take(&mut self.header_value_sink);
            self.dispatch_header(&name, &value)?;
        }

        self.header_raw_name = extract_raw_header_name(line, start, end);
        self.ensure_header_raw_sink_capacity(line.len())?;
        self.header_raw_sink.extend_from_slice(line);

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

        self.header_name = Some(decode_header_bytes(
            &line[start..name_end],
            true,
            self.strip_header_whitespace,
        ));

        let value_length = end.saturating_sub(colon_pos + 1);
        if value_length > 0 {
            self.ensure_header_value_sink_capacity(value_length)?;
            self.header_value_sink
                .extend_from_slice(&line[colon_pos + 1..end]);
        }

        Ok(())
    }

    fn dispatch_header(&mut self, name: &str, value: &[u8]) -> ParseResult<()> {
        if self.handler.pre_mime_header(name, value)? {
            return Ok(());
        }
        self.header(name, value)
    }

    fn header(&mut self, name: &str, value: &[u8]) -> ParseResult<()> {
        match name.to_ascii_lowercase().as_str() {
            "content-type" => self.handle_content_type_header(value)?,
            "content-disposition" => self.handle_content_disposition_header(value)?,
            "content-transfer-encoding" => self.handle_content_transfer_encoding_header(value)?,
            "content-id" => self.handle_content_id_header(value)?,
            "content-description" => self.handle_content_description_header(value)?,
            "mime-version" => self.handle_mime_version_header(value)?,
            _ => {}
        }
        Ok(())
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

    fn body_line(&mut self, line: &[u8]) -> ParseResult<()> {
        if matches!(
            self.state,
            State::Body | State::FirstBoundary | State::BoundaryOrContent | State::BoundaryOnly
        ) {
            self.handler.raw_body_content(line)?;
        }

        self.content_flushed = false;
        match self.state {
            State::FirstBoundary | State::BoundaryOnly => {
                if !self.content_flushed && !self.boundaries.is_empty() {
                    if let Some(m) = self.detect_boundary(line) {
                        self.flush_pending_body_content(true)?;
                        if m.is_end_boundary {
                            self.handler.end_entity(Some(&m.boundary))?;
                            self.transfer_encoding = TransferEncoding::Binary;
                            self.boundaries.pop();
                            self.state = State::BoundaryOnly;
                            return Ok(());
                        }
                        self.handler.start_entity(Some(&m.boundary))?;
                        self.transfer_encoding = TransferEncoding::Binary;
                        self.start_headers();
                        return Ok(());
                    }
                }
                self.flush_pending_body_content(false)?;
                self.buffer_body_content(line, true);
            }
            State::BoundaryOrContent => {
                if !self.content_flushed && !self.boundaries.is_empty() {
                    if let Some(m) = self.detect_boundary(line) {
                        self.flush_pending_body_content(true)?;
                        if m.is_end_boundary {
                            self.handler.end_entity(Some(&m.boundary))?;
                            self.transfer_encoding = TransferEncoding::Binary;
                            self.boundaries.pop();
                            if let Some(parent) = self.boundaries.last() {
                                let parent = parent.clone();
                                self.handler.end_entity(Some(&parent))?;
                            }
                            self.state = State::BoundaryOnly;
                            return Ok(());
                        }
                        self.handler.end_entity(Some(&m.boundary))?;
                        self.handler.start_entity(Some(&m.boundary))?;
                        self.transfer_encoding = TransferEncoding::Binary;
                        self.start_headers();
                        return Ok(());
                    }
                }
                self.flush_pending_body_content(false)?;
                self.buffer_body_content(line, false);
            }
            State::Body => {
                self.flush_body_content(line, false, false, false)?;
            }
            State::Init | State::Header => {
                return Err(MimeParseError::with_locator(
                    format_unexpected_parser_state(&format!("{:?}", self.state)),
                    &self.locator,
                ));
            }
        }
        Ok(())
    }

    fn flush_body_content(
        &mut self,
        line: &[u8],
        unexpected: bool,
        is_before_boundary: bool,
        end_of_stream: bool,
    ) -> ParseResult<()> {
        match self.transfer_encoding {
            TransferEncoding::Base64 | TransferEncoding::QuotedPrintable => {
                self.flush_body_content_with_decoding(
                    line,
                    unexpected,
                    is_before_boundary,
                    end_of_stream,
                )
            }
            TransferEncoding::Binary => {
                self.flush_body_content_binary(line, unexpected, is_before_boundary)
            }
        }
    }

    fn flush_body_content_with_decoding(
        &mut self,
        source: &[u8],
        unexpected: bool,
        is_before_boundary: bool,
        end_of_stream: bool,
    ) -> ParseResult<()> {
        if self.decode_buffer.capacity() < self.max_buffer_size {
            self.decode_buffer
                .reserve(self.max_buffer_size.saturating_sub(self.decode_buffer.capacity()));
        }

        let mut src = source;
        let mut has_processed_content = false;

        while !src.is_empty() {
            self.decode_buffer.clear();
            let is_last_chunk = src.len() <= self.max_buffer_size;
            let flush_remaining = is_last_chunk && (is_before_boundary || end_of_stream);

            let consumed = match self.transfer_encoding {
                TransferEncoding::Base64 => decode_base64(
                    &mut src,
                    &mut self.decode_buffer,
                    self.max_buffer_size,
                    flush_remaining,
                    true,
                ),
                TransferEncoding::QuotedPrintable => decode_quoted_printable(
                    &mut src,
                    &mut self.decode_buffer,
                    self.max_buffer_size,
                    flush_remaining,
                ),
                TransferEncoding::Binary => 0,
            };

            if !self.decode_buffer.is_empty() {
                let mut out = self.decode_buffer.clone();
                if is_last_chunk && is_before_boundary {
                    strip_trailing_line_ending(&mut out, self.allow_cr_line_end);
                }
                if !out.is_empty() {
                    if unexpected {
                        self.handler.unexpected_content(&out)?;
                    } else {
                        self.handler.body_content(&out)?;
                    }
                }
                has_processed_content = true;
            }

            if consumed == 0 {
                break;
            }
        }

        self.content_flushed = has_processed_content;
        Ok(())
    }

    fn flush_body_content_binary(
        &mut self,
        source: &[u8],
        unexpected: bool,
        is_before_boundary: bool,
    ) -> ParseResult<()> {
        let mut pos = 0usize;
        let mut has_processed_content = false;

        while pos < source.len() {
            let chunk_end = (pos + self.max_buffer_size).min(source.len());
            let mut chunk = source[pos..chunk_end].to_vec();
            let is_last_chunk = chunk_end >= source.len();
            if is_last_chunk && is_before_boundary {
                strip_trailing_line_ending(&mut chunk, self.allow_cr_line_end);
            }
            if !chunk.is_empty() {
                if unexpected {
                    self.handler.unexpected_content(&chunk)?;
                } else {
                    self.handler.body_content(&chunk)?;
                }
            }
            has_processed_content = true;
            pos = chunk_end;
        }

        self.content_flushed = has_processed_content;
        Ok(())
    }

    fn buffer_body_content(&mut self, line: &[u8], unexpected: bool) {
        self.ensure_pending_body_content_capacity(line.len());
        self.pending_body_content.extend_from_slice(line);
        self.pending_body_content_unexpected = unexpected;
    }

    fn ensure_pending_body_content_capacity(&mut self, required: usize) {
        if self.pending_body_content.len() + required <= self.pending_body_content.capacity() {
            return;
        }
        let new_cap = (self.pending_body_content.len() + required)
            .max(self.pending_body_content.capacity() * 2)
            .max(INITIAL_PENDING_BODY_CAPACITY);
        self.pending_body_content.reserve(new_cap - self.pending_body_content.capacity());
    }

    fn flush_pending_body_content(&mut self, is_before_boundary: bool) -> ParseResult<()> {
        if self.pending_body_content.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.pending_body_content);
        let unexpected = self.pending_body_content_unexpected;
        self.flush_body_content(&pending, unexpected, is_before_boundary, false)?;
        Ok(())
    }

    fn clear_pending_body_content(&mut self) {
        self.pending_body_content.clear();
        self.pending_body_content_unexpected = false;
    }

    fn ensure_header_value_sink_capacity(&mut self, required: usize) -> ParseResult<()> {
        let current = self.header_value_sink.len();
        if current + required > self.max_header_value_size {
            return Err(HeaderValueTooLongError::new(
                format_header_value_too_long(self.max_header_value_size),
                &self.locator,
            )
            .into());
        }
        if self.header_value_sink.len() + required > self.header_value_sink.capacity() {
            let new_cap = (current + required)
                .max(self.header_value_sink.capacity() * 2)
                .max(INITIAL_HEADER_VALUE_CAPACITY);
            self.header_value_sink.reserve(new_cap - self.header_value_sink.capacity());
        }
        Ok(())
    }

    fn ensure_header_raw_sink_capacity(&mut self, required: usize) -> ParseResult<()> {
        let current = self.header_raw_sink.len();
        if current + required > self.max_header_value_size {
            return Err(HeaderValueTooLongError::new(
                format_header_value_too_long(self.max_header_value_size),
                &self.locator,
            )
            .into());
        }
        if self.header_raw_sink.len() + required > self.header_raw_sink.capacity() {
            let new_cap = (current + required)
                .max(self.header_raw_sink.capacity() * 2)
                .max(INITIAL_HEADER_VALUE_CAPACITY);
            self.header_raw_sink.reserve(new_cap - self.header_raw_sink.capacity());
        }
        Ok(())
    }

    fn flush_raw_header(&mut self) -> ParseResult<()> {
        if let Some(name) = self.header_raw_name.take() {
            if !self.header_raw_sink.is_empty() {
                self.handler.raw_header(&name, &self.header_raw_sink)?;
            }
            self.header_raw_sink.clear();
        }
        Ok(())
    }

    fn detect_boundary(&self, line: &[u8]) -> Option<BoundaryMatch> {
        if self.boundaries.is_empty() {
            return None;
        }
        let boundary = self.boundaries.last()?.clone();
        check_boundary(line, &boundary)
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

fn strip_line_ending(line: &[u8], allow_cr_line_end: bool) -> (usize, usize) {
    let mut end = line.len();
    if end == 0 {
        return (0, 0);
    }
    if line[end - 1] == b'\n' {
        end -= 1;
        if end > 0 && line[end - 1] == b'\r' {
            end -= 1;
        }
    } else if allow_cr_line_end && line[end - 1] == b'\r' {
        end -= 1;
    }
    (0, end)
}

fn strip_trailing_line_ending(data: &mut Vec<u8>, allow_cr_line_end: bool) {
    let len = data.len();
    if len >= 2 && data[len - 2] == b'\r' && data[len - 1] == b'\n' {
        data.truncate(len - 2);
    } else if len >= 1 {
        let last = data[len - 1];
        if last == b'\n' || (allow_cr_line_end && last == b'\r') {
            data.truncate(len - 1);
        }
    }
}
