//! Sink for wire-accurate MIME bytes (DKIM capture).

use crate::mime::error::ParseResult;

/// Receives raw header and body octets exactly as they appear on the wire.
///
/// Not part of the everyday handler API: [`crate::DkimMessageParser`] attaches
/// one to the parser it wraps. Ordinary [`crate::MimeParser`] and
/// [`crate::MessageParser`] users never see these events, and the default sink
/// ([`NoWire`]) costs nothing.
#[doc(hidden)]
pub trait MimeWireSink {
    /// Whether this sink wants anything. The parser keeps the raw bytes of a
    /// header only when it does.
    const CAPTURES: bool = true;

    fn raw_header(&mut self, name: &str, raw_bytes: &[u8]) -> ParseResult<()>;

    fn raw_body_content(&mut self, content: &[u8]) -> ParseResult<()>;

    /// Called when the blank line after headers is seen (before body processing).
    fn mark_headers_complete(&mut self) -> ParseResult<()> {
        Ok(())
    }
}

/// The sink of a parser that captures nothing.
#[doc(hidden)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NoWire;

impl MimeWireSink for NoWire {
    const CAPTURES: bool = false;

    fn raw_header(&mut self, _name: &str, _raw_bytes: &[u8]) -> ParseResult<()> {
        Ok(())
    }

    fn raw_body_content(&mut self, _content: &[u8]) -> ParseResult<()> {
        Ok(())
    }
}
