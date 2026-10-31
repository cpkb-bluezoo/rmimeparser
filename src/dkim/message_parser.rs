//! DKIM-oriented message parser (gumdrop `DKIMMessageParser` port).

use std::io::Read;
use std::rc::Rc;

use loopbuf::LoopBuf;

use crate::mime::error::ParseResult;
use crate::mime::handler::Locator;
use crate::mime::limits::ParserLimits;
use crate::mime::parser::{MessageHeaderState, MimeParser};
use crate::rfc5322::message_parser::MessageBridge;
use crate::MessageHandler;

use super::raw_capture::RawCapture;
use super::raw_header::RawHeader;

/// RFC 5322 message parser that captures raw header and body bytes for DKIM.
///
/// Use the same [`MessageHandler`] callbacks as [`crate::MessageParser`] for decoded
/// headers and body. After parsing, read wire bytes from this parser via
/// [`Self::raw_headers`] / [`Self::raw_body`] — do not implement raw callbacks on the
/// handler (those are not part of the public handler API).
///
/// By default raw body bytes are retained in full (like raw headers) so
/// [`Self::raw_body`] works after parsing — the same shape as before
/// [`Self::set_body_sink`] existed. For large messages where retaining a
/// second full copy of the body is undesirable (e.g. streaming DKIM
/// verification/signing that only needs to feed a running digest), call
/// [`Self::set_body_sink`] to divert body bytes to a caller-supplied
/// callback instead.
///
/// Reads from a caller-owned [`LoopBuf`] and owns its handler, as
/// [`crate::MimeParser`] does.
pub struct DkimMessageParser<H: MessageHandler> {
    mime: MimeParser<MessageBridge<H>, RawCapture>,
}

impl<H: MessageHandler> DkimMessageParser<H> {
    pub fn new(handler: H) -> Self {
        Self {
            mime: MimeParser::with_wire(MessageBridge::new(handler), RawCapture::default()),
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

    /// See [`crate::MimeParser::receive`].
    pub fn receive(&mut self, buf: &mut LoopBuf) -> ParseResult<()> {
        self.mime.receive(buf)
    }

    /// See [`crate::MimeParser::close`].
    pub fn close(&mut self, buf: &mut LoopBuf) -> ParseResult<()> {
        self.mime.close(buf)
    }

    /// See [`crate::MimeParser::parse`].
    pub fn parse<R: Read>(&mut self, reader: R) -> ParseResult<()> {
        self.mime.reset();
        self.mime.wire_mut().clear();
        self.mime.parse(reader)
    }

    pub fn reset(&mut self) {
        self.mime.reset();
        self.mime.handler_mut().state = MessageHeaderState::default();
        self.mime.wire_mut().clear();
    }

    pub fn is_underflow(&self) -> bool {
        self.mime.is_underflow()
    }

    pub fn raw_headers(&self) -> &[RawHeader] {
        self.mime.wire().raw_headers()
    }

    pub fn raw_header(&self, name: &str) -> Option<&RawHeader> {
        self.mime.wire().raw_header(name)
    }

    pub fn all_raw_headers(&self, name: &str) -> Vec<&RawHeader> {
        self.mime.wire().all_raw_headers(name)
    }

    pub fn header_bytes(&self, name: &str) -> Option<&[u8]> {
        self.mime.wire().header_bytes(name)
    }

    pub fn all_header_bytes(&self, name: &str) -> Vec<&[u8]> {
        self.mime.wire().all_header_bytes(name)
    }

    pub fn raw_body(&self) -> &[u8] {
        self.mime.wire().raw_body()
    }

    /// Divert raw body bytes to `sink`, called once per body chunk in wire
    /// order, instead of retaining them — see the type-level docs. Raw
    /// headers are unaffected and still available via [`Self::raw_headers`]
    /// after parsing (DKIM's `h=` header selection needs random access
    /// across the whole ordered header set, which — unlike the body — stays
    /// small for essentially all real messages).
    ///
    /// The parser owns the sink, so it cannot borrow from the caller's stack:
    /// share state with it through an `Rc<RefCell<_>>` (the parser is used from
    /// one thread) or a channel.
    ///
    /// Call this before feeding any body bytes to [`Self::receive`]
    /// (typically right after construction). [`Self::reset`] drops the
    /// sink along with everything else it clears; install a fresh one
    /// before reusing the parser for another message.
    pub fn set_body_sink(&mut self, sink: impl FnMut(&[u8]) + 'static) {
        self.mime.wire_mut().set_body_sink(Box::new(sink));
    }

    pub fn is_headers_complete(&self) -> bool {
        self.mime.wire().is_headers_complete()
    }
}
