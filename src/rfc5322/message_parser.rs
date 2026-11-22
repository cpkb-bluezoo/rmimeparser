//! RFC 5322 message parser (wraps MIME parser).

use std::io::Read;
use std::rc::Rc;

use loopbuf::LoopBuf;

use crate::mime::error::ParseResult;
use crate::mime::handler::{HeaderDelivery, Locator, MimeHandler};
use crate::mime::limits::ParserLimits;
use crate::mime::parser::MimeParser;
use crate::rfc5322::headers;
use crate::rfc5322::message_handler::MessageHandler;
use crate::rfc5322::stream::HeaderStream;

#[derive(Debug, Default, Clone)]
pub(crate) struct MessageHeaderState {
    pub smtp_utf8: bool,
}

/// Bridges [`MessageHandler`] to [`MimeHandler`] and reads the RFC 5322 headers.
pub(crate) struct MessageBridge<H: MessageHandler> {
    pub(crate) inner: H,
    pub(crate) state: MessageHeaderState,
    /// Set by `header_delivery` for a header this layer takes, until the
    /// `start_header` that follows it.
    claimed: Option<headers::RawKind>,
    /// Reads the headers this layer takes.
    stream: HeaderStream,
    max_element: usize,
}

impl<H: MessageHandler> MessageBridge<H> {
    pub fn new(handler: H) -> Self {
        Self {
            inner: handler,
            state: MessageHeaderState::default(),
            claimed: None,
            stream: HeaderStream::new(),
            max_element: usize::MAX,
        }
    }

    /// Readies the bridge for another message.
    pub(crate) fn reset(&mut self) {
        self.state = MessageHeaderState::default();
        self.claimed = None;
        self.stream = HeaderStream::new();
    }
}

impl<H: MessageHandler> MimeHandler for MessageBridge<H> {
    fn set_locator(&mut self, locator: Rc<dyn Locator>) {
        self.inner.set_locator(locator)
    }

    fn header_delivery(&mut self, name: &str) -> HeaderDelivery {
        self.claimed = headers::classify(name);
        if self.claimed.is_some() {
            HeaderDelivery::Raw
        } else {
            self.inner.header_delivery(name)
        }
    }

    fn set_limits(&mut self, limits: &ParserLimits) {
        self.max_element = limits.max_element_length.unwrap_or(usize::MAX);
        self.inner.set_limits(limits)
    }

    fn start_header(&mut self, name: &str) -> ParseResult<()> {
        match self.claimed.take() {
            Some(kind) => self.stream.start(
                &mut self.inner,
                kind,
                name,
                self.state.smtp_utf8,
                self.max_element,
            ),
            None => self.inner.start_header(name),
        }
    }

    fn header_content(&mut self, text: &str) -> ParseResult<()> {
        self.inner.header_content(text)
    }

    fn raw_header_content(&mut self, bytes: &[u8]) -> ParseResult<()> {
        if self.stream.active() {
            self.stream.feed(&mut self.inner, bytes)
        } else {
            self.inner.raw_header_content(bytes)
        }
    }

    fn end_header(&mut self) -> ParseResult<()> {
        if self.stream.active() {
            self.stream.finish(&mut self.inner)
        } else {
            self.inner.end_header()
        }
    }

    fn start_entity(&mut self, boundary: Option<&str>) -> ParseResult<()> {
        self.inner.start_entity(boundary)
    }

    fn start_content_type(&mut self, primary: &str, sub: &str) -> ParseResult<()> {
        self.inner.start_content_type(primary, sub)
    }

    fn end_content_type(&mut self) -> ParseResult<()> {
        self.inner.end_content_type()
    }

    fn start_content_disposition(&mut self, kind: &str) -> ParseResult<()> {
        self.inner.start_content_disposition(kind)
    }

    fn end_content_disposition(&mut self) -> ParseResult<()> {
        self.inner.end_content_disposition()
    }

    fn start_parameter(&mut self, name: &str, language: Option<&str>) -> ParseResult<()> {
        self.inner.start_parameter(name, language)
    }

    fn parameter_content(&mut self, text: &str) -> ParseResult<()> {
        self.inner.parameter_content(text)
    }

    fn end_parameter(&mut self) -> ParseResult<()> {
        self.inner.end_parameter()
    }

    fn malformed_header(&mut self, name: &str, reason: &str) -> ParseResult<()> {
        self.inner.malformed_header(name, reason)
    }

    fn content_transfer_encoding(&mut self, encoding: &str) -> ParseResult<()> {
        self.inner.content_transfer_encoding(encoding)
    }

    fn content_id(&mut self, local_part: &str, domain: &str) -> ParseResult<()> {
        self.inner.content_id(local_part, domain)
    }

    fn mime_version(&mut self, major: u32, minor: u32) -> ParseResult<()> {
        self.inner.mime_version(major, minor)
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
        self.mime.set_utf8_headers(smtp_utf8);
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
        self.mime.handler_mut().reset();
    }

    pub fn is_underflow(&self) -> bool {
        self.mime.is_underflow()
    }
}
