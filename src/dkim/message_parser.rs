//! DKIM-oriented message parser (gumdrop `DKIMMessageParser` port).

use std::mem::MaybeUninit;

use crate::mime::error::ParseResult;
use crate::mime::parser::MimeParser;
use crate::MessageHandler;

use super::capture_bridge::CaptureBridge;
use super::raw_header::RawHeader;

struct DkimParserInner<'a, H: MessageHandler + ?Sized> {
    bridge: CaptureBridge<'a, H>,
    mime: MaybeUninit<MimeParser<'a, CaptureBridge<'a, H>>>,
}

/// RFC 5322 message parser that captures raw header and body bytes for DKIM.
///
/// Mirrors gumdrop's `DKIMMessageParser`: raw headers are stored in order of
/// appearance (including fold CRLFs), and the raw undecoded body is accumulated
/// line-by-line before transfer-decoding.
pub struct DkimMessageParser<'a, H: MessageHandler + ?Sized> {
    inner: Box<DkimParserInner<'a, H>>,
}

impl<'a, H: MessageHandler + ?Sized> DkimMessageParser<'a, H> {
    pub fn new(handler: &'a mut H) -> Self {
        let inner = Box::new(DkimParserInner {
            bridge: CaptureBridge::new(handler),
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
        self.inner.bridge.state = crate::mime::parser::MessageHeaderState::default();
        self.inner.bridge.capture.clear();
    }

    pub fn is_underflow(&self) -> bool {
        let mime = unsafe { self.inner.mime.assume_init_ref() };
        mime.is_underflow()
    }

    pub fn raw_headers(&self) -> &[RawHeader] {
        self.inner.bridge.capture.raw_headers()
    }

    pub fn raw_header(&self, name: &str) -> Option<&RawHeader> {
        self.inner.bridge.capture.raw_header(name)
    }

    pub fn all_raw_headers(&self, name: &str) -> Vec<&RawHeader> {
        self.inner.bridge.capture.all_raw_headers(name)
    }

    pub fn header_bytes(&self, name: &str) -> Option<&[u8]> {
        self.inner.bridge.capture.header_bytes(name)
    }

    pub fn all_header_bytes(&self, name: &str) -> Vec<&[u8]> {
        self.inner.bridge.capture.all_header_bytes(name)
    }

    pub fn raw_body(&self) -> &[u8] {
        self.inner.bridge.capture.raw_body()
    }

    pub fn is_headers_complete(&self) -> bool {
        self.inner.bridge.capture.is_headers_complete()
    }
}
