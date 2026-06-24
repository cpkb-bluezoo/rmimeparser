//! RFC 2231 extended parameter value decoder.

use crate::buffer::ByteCursor;
use crate::charset::{self, HeaderCharset};

/// RFC 2231 parameter decoder.
pub struct Decoder;

impl Decoder {
    pub fn decode_parameter_value(
        value: &mut ByteCursor<'_>,
        _fallback: HeaderCharset,
    ) -> Option<String> {
        if !value.has_remaining() {
            return None;
        }
        let limit = value.limit();
        if value.get(value.position()) == b'"' {
            value.advance(1);
        }
        if !value.has_remaining() {
            return None;
        }
        let charset = consume_ascii_until(value, b'\'')?;
        if charset.is_empty() {
            return None;
        }
        if value.position() >= limit || value.get(value.position()) != b'\'' {
            return None;
        }
        value.advance(1);
        if consume_ascii_until(value, b'\'').is_none() {
            return None;
        }
        if value.position() >= limit || value.get(value.position()) != b'\'' {
            return None;
        }
        value.advance(1);
        let encoded_start = value.position();
        let mut encoded_end = limit;
        if encoded_end > encoded_start && value.get(encoded_end - 1) == b'"' {
            encoded_end -= 1;
        }
        if encoded_start >= encoded_end {
            value.set_position(limit);
            return Some(String::new());
        }
        let decoded_bytes = charset::percent_decode(&value.bytes()[encoded_start..encoded_end]);
        let name = charset::normalize_charset_name(&charset);
        let result = if name.eq_ignore_ascii_case("UTF-8") {
            charset::decode_bytes(&decoded_bytes, HeaderCharset::Utf8)
        } else if name.eq_ignore_ascii_case("ISO-8859-1") {
            charset::decode_bytes(&decoded_bytes, HeaderCharset::Iso88591)
        } else {
            charset::decode_bytes_named(&decoded_bytes, &charset)
        };
        value.set_position(limit);
        Some(result)
    }
}

fn consume_ascii_until(value: &mut ByteCursor<'_>, delimiter: u8) -> Option<String> {
    let limit = value.limit();
    let mut sb = String::new();
    while value.position() < limit {
        let b = value.get(value.position());
        if b == delimiter {
            return Some(sb.trim().to_string());
        }
        if b < 0x20 || b > 0x7E {
            return None;
        }
        sb.push(b as char);
        value.advance(1);
    }
    None
}
