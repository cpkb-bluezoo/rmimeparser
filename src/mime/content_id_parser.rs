//! MIME Content-ID parser.

use super::message_id_parser::MessageIdParser;
use crate::buffer::ByteCursor;
use crate::charset::HeaderCharset;

use super::content_types::ContentId;

/// Content-ID / Message-ID parser.
pub struct ContentIdParser;

impl ContentIdParser {
    pub fn parse(value: &mut ByteCursor<'_>, charset: HeaderCharset) -> Option<ContentId> {
        if !value.has_remaining() {
            return None;
        }
        let mut dup = value.duplicate();
        let list = MessageIdParser::parse_message_id_list(&mut dup, charset)?;
        if list.len() != 1 {
            return None;
        }
        value.set_position(dup.position());
        Some(list.into_iter().next().unwrap())
    }

    pub fn parse_list(
        value: &mut ByteCursor<'_>,
        charset: HeaderCharset,
    ) -> Option<Vec<ContentId>> {
        MessageIdParser::parse_message_id_list(value, charset)
    }

    pub fn parse_str(value: &str) -> Option<ContentId> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        let mut cursor = ByteCursor::new(trimmed.as_bytes());
        Self::parse(&mut cursor, HeaderCharset::Iso88591)
    }
}
