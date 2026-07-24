//! DKIM-oriented message parser (gumdrop `DKIMMessageParser` port).

use std::mem::MaybeUninit;

use crate::mime::error::ParseResult;
use crate::mime::parser::MimeParser;
use crate::rfc5322::message_parser::MessageBridge;
use crate::MessageHandler;

use super::raw_capture::RawCapture;
use super::raw_header::RawHeader;

struct DkimParserInner<'a, H: MessageHandler + ?Sized> {
    capture: RawCapture,
    bridge: MessageBridge<'a, H>,
    mime: MaybeUninit<MimeParser<'a, MessageBridge<'a, H>>>,
}

/// RFC 5322 message parser that captures raw header and body bytes for DKIM.
///
/// Use the same [`MessageHandler`] callbacks as [`crate::MessageParser`] for decoded
/// headers and body. After parsing, read wire bytes from this parser via
/// [`Self::raw_headers`] / [`Self::raw_body`] — do not implement raw callbacks on the
/// handler (those are not part of the public handler API).
pub struct DkimMessageParser<'a, H: MessageHandler + ?Sized> {
    inner: Box<DkimParserInner<'a, H>>,
}

impl<'a, H: MessageHandler + ?Sized> DkimMessageParser<'a, H> {
    pub fn new(handler: &'a mut H) -> Self {
        let inner = Box::new(DkimParserInner {
            capture: RawCapture::default(),
            bridge: MessageBridge::new(handler),
            mime: MaybeUninit::uninit(),
        });
        let ptr = Box::into_raw(inner);
        unsafe {
            let bridge_ref = &mut (*ptr).bridge;
            let capture_ref = &mut (*ptr).capture;
            (*ptr)
                .mime
                .write(MimeParser::with_wire(bridge_ref, capture_ref));
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
        self.inner.bridge.state = crate::mime::parser::MessageHeaderState::default();
        self.inner.capture.clear();
    }

    pub fn is_underflow(&self) -> bool {
        let mime = unsafe { self.inner.mime.assume_init_ref() };
        mime.is_underflow()
    }

    pub fn raw_headers(&self) -> &[RawHeader] {
        self.inner.capture.raw_headers()
    }

    pub fn raw_header(&self, name: &str) -> Option<&RawHeader> {
        self.inner.capture.raw_header(name)
    }

    pub fn all_raw_headers(&self, name: &str) -> Vec<&RawHeader> {
        self.inner.capture.all_raw_headers(name)
    }

    pub fn header_bytes(&self, name: &str) -> Option<&[u8]> {
        self.inner.capture.header_bytes(name)
    }

    pub fn all_header_bytes(&self, name: &str) -> Vec<&[u8]> {
        self.inner.capture.all_header_bytes(name)
    }

    pub fn raw_body(&self) -> &[u8] {
        self.inner.capture.raw_body()
    }

    pub fn is_headers_complete(&self) -> bool {
        self.inner.capture.is_headers_complete()
    }
}
