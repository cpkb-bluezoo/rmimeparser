//! RFC 5322 message parser (wraps MIME parser).

use std::mem::MaybeUninit;

use crate::mime::content_types::{ContentDisposition, ContentId, ContentType, MimeVersion};
use crate::mime::error::ParseResult;
use crate::mime::handler::{MimeHandler, MimeLocator};
use crate::mime::parser::{MessageHeaderState, MimeParser};
use crate::rfc5322::headers;
use crate::rfc5322::message_handler::MessageHandler;

/// Bridges [`MessageHandler`] to [`MimeHandler`] and dispatches RFC 5322 headers.
pub struct MessageBridge<'a, H: MessageHandler + ?Sized> {
    pub(crate) inner: &'a mut H,
    pub(crate) state: MessageHeaderState,
    strip_header_whitespace: bool,
}

impl<'a, H: MessageHandler + ?Sized> MessageBridge<'a, H> {
    pub fn new(handler: &'a mut H) -> Self {
        Self {
            inner: handler,
            state: MessageHeaderState::default(),
            strip_header_whitespace: true,
        }
    }
}

impl<H: MessageHandler + ?Sized> MimeHandler for MessageBridge<'_, H> {
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

struct MessageParserInner<'a, H: MessageHandler + ?Sized> {
    bridge: MessageBridge<'a, H>,
    mime: MaybeUninit<MimeParser<'a, MessageBridge<'a, H>>>,
}

/// RFC 5322 message parser using composition over [`MimeParser`].
pub struct MessageParser<'a, H: MessageHandler + ?Sized> {
    inner: Box<MessageParserInner<'a, H>>,
}

impl<'a, H: MessageHandler + ?Sized> MessageParser<'a, H> {
    pub fn new(handler: &'a mut H) -> Self {
        let inner = Box::new(MessageParserInner {
            bridge: MessageBridge::new(handler),
            mime: MaybeUninit::uninit(),
        });
        let ptr = Box::into_raw(inner);
        unsafe {
            let bridge_ref = &mut (*ptr).bridge;
            (*ptr).mime.write(MimeParser::new(bridge_ref));
            Self {
                inner: Box::from_raw(ptr),
            }
        }
    }

    pub fn set_smtp_utf8(&mut self, smtp_utf8: bool) {
        self.inner.bridge.state.smtp_utf8 = smtp_utf8;
    }

    pub fn is_smtp_utf8(&self) -> bool {
        self.inner.bridge.state.smtp_utf8
    }

    pub fn receive(&mut self, data: &mut &[u8]) -> ParseResult<()> {
        let mime = unsafe { self.inner.mime.assume_init_mut() };
        mime.receive(data)
    }

    pub fn close(&mut self) -> ParseResult<()> {
        let mime = unsafe { self.inner.mime.assume_init_mut() };
        mime.close()
    }

    pub fn reset(&mut self) {
        let mime = unsafe { self.inner.mime.assume_init_mut() };
        mime.reset();
        self.inner.bridge.state = MessageHeaderState::default();
    }

    pub fn is_underflow(&self) -> bool {
        let mime = unsafe { self.inner.mime.assume_init_ref() };
        mime.is_underflow()
    }
}
