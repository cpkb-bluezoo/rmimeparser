use crate::mime::content_types::{ContentDisposition, ContentId, ContentType, MimeVersion};
use crate::mime::error::ParseResult;

/// Position within the MIME entity for error reporting.
#[derive(Debug, Clone, Copy, Default)]
pub struct MimeLocator {
    pub offset: i64,
    pub line_number: i64,
    pub column_number: i64,
}

impl MimeLocator {
    pub fn reset(&mut self) {
        self.offset = 0;
        self.line_number = 1;
        self.column_number = 0;
    }
}

/// rprotobuf-style locator trait.
pub trait Locator {
    fn offset(&self) -> u64;
    fn line_number(&self) -> u64;
    fn column_number(&self) -> u64;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ParserLocator {
    pub offset: u64,
    pub line_number: u64,
    pub column_number: u64,
}

impl Locator for ParserLocator {
    fn offset(&self) -> u64 {
        self.offset
    }
    fn line_number(&self) -> u64 {
        self.line_number
    }
    fn column_number(&self) -> u64 {
        self.column_number
    }
}

impl Locator for MimeLocator {
    fn offset(&self) -> u64 {
        self.offset as u64
    }
    fn line_number(&self) -> u64 {
        self.line_number as u64
    }
    fn column_number(&self) -> u64 {
        self.column_number as u64
    }
}

/// Callback interface for push-based MIME parsing events.
pub trait MimeHandler {
    fn set_locator(&mut self, _locator: &MimeLocator) -> ParseResult<()> {
        Ok(())
    }

    /// Return `true` if this header was handled and default MIME dispatch should be skipped.
    fn pre_mime_header(&mut self, _name: &str, _value: &[u8]) -> ParseResult<bool> {
        Ok(false)
    }

    fn start_entity(&mut self, _boundary: Option<&str>) -> ParseResult<()> {
        Ok(())
    }

    fn content_type(&mut self, _content_type: &ContentType) -> ParseResult<()> {
        Ok(())
    }

    fn content_disposition(&mut self, _disposition: &ContentDisposition) -> ParseResult<()> {
        Ok(())
    }

    fn content_transfer_encoding(&mut self, _encoding: &str) -> ParseResult<()> {
        Ok(())
    }

    fn content_id(&mut self, _content_id: &ContentId) -> ParseResult<()> {
        Ok(())
    }

    fn content_description(&mut self, _description: &str) -> ParseResult<()> {
        Ok(())
    }

    fn mime_version(&mut self, _version: MimeVersion) -> ParseResult<()> {
        Ok(())
    }

    fn end_headers(&mut self) -> ParseResult<()> {
        Ok(())
    }

    fn body_content(&mut self, _content: &[u8]) -> ParseResult<()> {
        Ok(())
    }

    fn unexpected_content(&mut self, _content: &[u8]) -> ParseResult<()> {
        Ok(())
    }

    fn end_entity(&mut self, _boundary: Option<&str>) -> ParseResult<()> {
        Ok(())
    }
}

/// rprotobuf-style handler trait alias.
pub trait Handler: MimeHandler {}

impl<T: MimeHandler> Handler for T {}

pub struct DefaultHandler;

impl MimeHandler for DefaultHandler {}
