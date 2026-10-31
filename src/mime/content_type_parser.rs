//! `Content-Type` and `Content-Disposition` parsers for a value held whole.
//!
//! These run the same grammar the parser streams with,
//! and collect its events into a [`ContentType`] or [`ContentDisposition`].

use crate::buffer::ByteCursor;
use crate::charset::HeaderCharset;

use super::collectors::{ContentDispositionCollector, ContentTypeCollector};
use super::content_types::ContentDisposition;
use super::content_types::ContentType;
use super::error::ParseResult;
use super::parameters::{Fed, Kind, ParameterParser, ParameterSink};

/// Collects the grammar's events.
#[derive(Default)]
struct Collect {
    content_type: ContentTypeCollector,
    disposition: ContentDispositionCollector,
    kind: Option<Kind>,
}

impl ParameterSink for Collect {
    fn head(&mut self, first: &str, second: &str) -> ParseResult<()> {
        match self.kind {
            Some(Kind::ContentDisposition) => self.disposition.start(first),
            _ => self.content_type.start(first, second),
        }
        Ok(())
    }

    fn start_parameter(&mut self, name: &str, language: Option<&str>) -> ParseResult<()> {
        match self.kind {
            Some(Kind::ContentDisposition) => self.disposition.start_parameter(name, language),
            _ => self.content_type.start_parameter(name, language),
        }
        Ok(())
    }

    fn content(&mut self, text: &str) -> ParseResult<()> {
        match self.kind {
            Some(Kind::ContentDisposition) => self.disposition.parameter_content(text),
            _ => self.content_type.parameter_content(text),
        }
        Ok(())
    }

    fn end_parameter(&mut self) -> ParseResult<()> {
        match self.kind {
            Some(Kind::ContentDisposition) => self.disposition.end_parameter(),
            _ => self.content_type.end_parameter(),
        }
        Ok(())
    }
}

/// Runs the grammar over `bytes`. False if the head is not valid.
fn run(kind: Kind, bytes: &[u8], charset: HeaderCharset, sink: &mut Collect) -> bool {
    sink.kind = Some(kind);
    let mut parser = ParameterParser::new(charset == HeaderCharset::Utf8);
    parser.start(kind, 256);
    match parser.feed(bytes, sink) {
        Ok(Fed::Continue) => {}
        _ => return false,
    }
    matches!(parser.finish(sink), Ok(Fed::Continue))
}

pub struct ContentTypeParser;

impl ContentTypeParser {
    /// The content type in `value`, which is consumed. `None` if it is not
    /// `type/subtype`.
    pub fn parse(value: &mut ByteCursor<'_>, charset: HeaderCharset) -> Option<ContentType> {
        let mut collect = Collect::default();
        let valid = run(Kind::ContentType, value.slice(), charset, &mut collect);
        value.consume_to_limit();
        valid.then(|| collect.content_type.finish())
    }

    pub fn parse_str(value: &str) -> Option<ContentType> {
        if value.trim().is_empty() {
            return None;
        }
        let mut cursor = ByteCursor::new(value.as_bytes());
        Self::parse(&mut cursor, HeaderCharset::Iso88591)
    }
}

pub struct ContentDispositionParser;

impl ContentDispositionParser {
    /// The disposition in `value`, which is consumed. `None` if its type is not
    /// a token.
    pub fn parse(value: &mut ByteCursor<'_>, charset: HeaderCharset) -> Option<ContentDisposition> {
        let mut collect = Collect::default();
        let valid = run(
            Kind::ContentDisposition,
            value.slice(),
            charset,
            &mut collect,
        );
        value.consume_to_limit();
        valid.then(|| collect.disposition.finish())
    }

    pub fn parse_str(value: &str) -> Option<ContentDisposition> {
        if value.trim().is_empty() {
            return None;
        }
        let mut cursor = ByteCursor::new(value.as_bytes());
        Self::parse(&mut cursor, HeaderCharset::Iso88591)
    }
}
