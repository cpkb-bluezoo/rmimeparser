//! Bridges [`MessageHandler`] to [`MimeHandler`] while capturing raw DKIM bytes.

use crate::mime::content_types::{ContentDisposition, ContentId, ContentType, MimeVersion};
use crate::mime::error::ParseResult;
use crate::mime::handler::{MimeHandler, MimeLocator};
use crate::mime::parser::MessageHeaderState;
use crate::rfc5322::headers;
use crate::MessageHandler;

use super::raw_capture::RawCapture;

/// Forwards RFC 5322 events to a [`MessageHandler`] and records raw header/body bytes.
pub struct CaptureBridge<'a, H: MessageHandler + ?Sized> {
    pub(crate) capture: RawCapture,
    pub(crate) inner: &'a mut H,
    pub(crate) state: MessageHeaderState,
    strip_header_whitespace: bool,
}

impl<'a, H: MessageHandler + ?Sized> CaptureBridge<'a, H> {
    pub fn new(handler: &'a mut H) -> Self {
        Self {
            capture: RawCapture::default(),
            inner: handler,
            state: MessageHeaderState::default(),
            strip_header_whitespace: true,
        }
    }
}

impl<H: MessageHandler + ?Sized> MimeHandler for CaptureBridge<'_, H> {
    fn set_locator(&mut self, locator: &MimeLocator) -> ParseResult<()> {
        self.inner.set_locator(locator)
    }

    fn pre_mime_header(&mut self, name: &str, value: &[u8]) -> ParseResult<bool> {
        let mut value_vec = value.to_vec();
        headers::dispatch_rfc5322_header(
            self.strip_header_whitespace,
            &mut self.state,
            self.inner,
            name,
            &mut value_vec,
        )
    }

    fn start_entity(&mut self, boundary: Option<&str>) -> ParseResult<()> {
        self.inner.start_entity(boundary)
    }

    fn content_type(&mut self, content_type: &ContentType) -> ParseResult<()> {
        self.inner.content_type(content_type)
    }

    fn content_disposition(&mut self, disposition: &ContentDisposition) -> ParseResult<()> {
        self.inner.content_disposition(disposition)
    }

    fn content_transfer_encoding(&mut self, encoding: &str) -> ParseResult<()> {
        self.inner.content_transfer_encoding(encoding)
    }

    fn content_id(&mut self, content_id: &ContentId) -> ParseResult<()> {
        self.inner.content_id(content_id)
    }

    fn content_description(&mut self, description: &str) -> ParseResult<()> {
        self.inner.content_description(description)
    }

    fn mime_version(&mut self, version: MimeVersion) -> ParseResult<()> {
        self.inner.mime_version(version)
    }

    fn end_headers(&mut self) -> ParseResult<()> {
        self.capture.mark_headers_complete();
        self.inner.end_headers()
    }

    fn raw_header(&mut self, name: &str, raw_bytes: &[u8]) -> ParseResult<()> {
        self.capture.add_raw_header(name, raw_bytes);
        Ok(())
    }

    fn raw_body_content(&mut self, content: &[u8]) -> ParseResult<()> {
        self.capture.append_raw_body(content);
        Ok(())
    }

    fn body_content(&mut self, data: &[u8]) -> ParseResult<()> {
        self.inner.body_content(data)
    }

    fn unexpected_content(&mut self, data: &[u8]) -> ParseResult<()> {
        self.inner.unexpected_content(data)
    }

    fn end_entity(&mut self, boundary: Option<&str>) -> ParseResult<()> {
        self.inner.end_entity(boundary)
    }
}
