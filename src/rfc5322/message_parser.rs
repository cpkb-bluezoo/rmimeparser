//! RFC 5322 message parser (wraps MIME parser).

use std::io::Read;
use std::rc::Rc;

use loopbuf::LoopBuf;

use crate::mime::content_types::{ContentDisposition, ContentId, ContentType, MimeVersion};
use crate::mime::error::ParseResult;
use crate::mime::handler::{Locator, MimeHandler};
use crate::mime::limits::ParserLimits;
use crate::mime::parser::{MessageHeaderState, MimeParser};
use crate::rfc5322::headers;
use crate::rfc5322::message_handler::MessageHandler;

/// Bridges [`MessageHandler`] to [`MimeHandler`] and dispatches RFC 5322 headers.
pub(crate) struct MessageBridge<H: MessageHandler> {
    pub(crate) inner: H,
    pub(crate) state: MessageHeaderState,
    strip_header_whitespace: bool,
}

impl<H: MessageHandler> MessageBridge<H> {
    pub fn new(handler: H) -> Self {
        Self {
            inner: handler,
            state: MessageHeaderState::default(),
            strip_header_whitespace: true,
        }
    }
}

impl<H: MessageHandler> MimeHandler for MessageBridge<H> {
    fn set_locator(&mut self, locator: Rc<dyn Locator>) {
        self.inner.set_locator(locator)
    }

    fn pre_mime_header(&mut self, name: &str, value: &[u8]) -> ParseResult<bool> {
        headers::dispatch_rfc5322_header(
            self.strip_header_whitespace,
            &mut self.state,
            &mut self.inner,
            name,
            value,
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
        self.inner.end_headers()
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

/// RFC 5322 message parser using composition over [`MimeParser`].
///
/// Reads from a caller-owned [`LoopBuf`] and owns its handler, as
/// [`MimeParser`] does.
pub struct MessageParser<H: MessageHandler> {
    mime: MimeParser<MessageBridge<H>>,
}

impl<H: MessageHandler> MessageParser<H> {
    pub fn new(handler: H) -> Self {
        Self {
            mime: MimeParser::new(MessageBridge::new(handler)),
        }
    }

    /// Creates a parser with the given limits.
    pub fn with_limits(handler: H, limits: ParserLimits) -> Self {
        Self {
            mime: MimeParser::with_limits(MessageBridge::new(handler), limits),
        }
    }

    pub fn set_smtp_utf8(&mut self, smtp_utf8: bool) {
        self.mime.handler_mut().state.smtp_utf8 = smtp_utf8;
    }

    pub fn is_smtp_utf8(&self) -> bool {
        self.mime.handler().state.smtp_utf8
    }

    pub fn limits(&self) -> &ParserLimits {
        self.mime.limits()
    }

    pub fn limits_mut(&mut self) -> &mut ParserLimits {
        self.mime.limits_mut()
    }

    pub fn set_limits(&mut self, limits: ParserLimits) {
        self.mime.set_limits(limits)
    }

    pub fn set_buffer_size(&mut self, buffer_size: usize) {
        self.mime.set_buffer_size(buffer_size)
    }

    pub fn set_chunk_size(&mut self, chunk_size: usize) {
        self.mime.set_chunk_size(chunk_size)
    }

    /// The handler the parser is driving.
    pub fn handler(&self) -> &H {
        &self.mime.handler().inner
    }

    /// Mutable access to the handler between calls to [`Self::receive`].
    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.mime.handler_mut().inner
    }

    /// Takes the handler back, dropping the parser.
    pub fn into_handler(self) -> H {
        self.mime.into_handler().inner
    }

    pub fn locator(&self) -> Rc<dyn Locator> {
        self.mime.locator()
    }

    /// See [`MimeParser::receive`].
    pub fn receive(&mut self, buf: &mut LoopBuf) -> ParseResult<()> {
        self.mime.receive(buf)
    }

    /// See [`MimeParser::close`].
    pub fn close(&mut self, buf: &mut LoopBuf) -> ParseResult<()> {
        self.mime.close(buf)
    }

    /// See [`MimeParser::parse`].
    pub fn parse<R: Read>(&mut self, reader: R) -> ParseResult<()> {
        self.mime.parse(reader)
    }

    pub fn reset(&mut self) {
        self.mime.reset();
        self.mime.handler_mut().state = MessageHeaderState::default();
    }

    pub fn is_underflow(&self) -> bool {
        self.mime.is_underflow()
    }
}
