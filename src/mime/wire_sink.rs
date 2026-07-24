//! Crate-internal sink for wire-accurate MIME bytes (DKIM capture).

use crate::mime::error::ParseResult;

/// Receives raw header and body octets exactly as they appear on the wire.
///
/// Not part of the public handler API. [`crate::DkimMessageParser`] attaches a
/// sink via [`crate::mime::parser::MimeParser::with_wire`]; ordinary
/// [`crate::MimeParser`] / [`crate::MessageParser`] users never see these events.
pub(crate) trait MimeWireSink {
    fn raw_header(&mut self, name: &str, raw_bytes: &[u8]) -> ParseResult<()>;

    fn raw_body_content(&mut self, content: &[u8]) -> ParseResult<()>;

    /// Called when the blank line after headers is seen (before body processing).
    fn mark_headers_complete(&mut self) -> ParseResult<()> {
        Ok(())
    }
}
