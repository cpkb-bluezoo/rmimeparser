//! RFC 5322 Message-ID list parser.

use crate::buffer::ByteCursor;
use crate::charset::{decode_slice, HeaderCharset};
use crate::mime::ContentId;

/// Message-ID parser.
pub struct MessageIdParser;

impl MessageIdParser {
    pub fn parse_message_id_list(
        value: &mut ByteCursor<'_>,
        charset: HeaderCharset,
    ) -> Option<Vec<ContentId>> {
        if !value.has_remaining() {
            return Some(Vec::new());
        }
        let mut message_ids = Vec::new();
        let limit = value.limit();
        let smtp_utf8 = charset == HeaderCharset::Utf8;
        while value.position() < limit {
            skip_cfws(value);
            if value.position() >= limit {
                break;
            }
            if value.get(value.position()) != b'<' {
                break;
            }
            value.advance(1);
            let start_local = value.position();
            if !advance_until_at(value) {
                break;
            }
            let at_index = value.position();
            let mut local_cursor =
                ByteCursor::from_slice(value.bytes(), start_local, at_index);
            let local_part = decode_slice(&mut local_cursor, charset);
            value.advance(1);
            let start_domain = value.position();
            if !advance_until_gt(value) {
                break;
            }
            let gt_index = value.position();
            let mut domain_cursor =
                ByteCursor::from_slice(value.bytes(), start_domain, gt_index);
            let domain = decode_slice(&mut domain_cursor, charset);
            value.advance(1);
            if !is_valid_id_left(&local_part, smtp_utf8) || !is_valid_id_right(&domain, smtp_utf8) {
                break;
            }
            message_ids.push(ContentId::new(local_part, domain));
        }
        Some(message_ids)
    }
}

fn advance_until_at(value: &mut ByteCursor<'_>) -> bool {
    let limit = value.limit();
    while value.position() < limit {
        if value.get(value.position()) == b'@' {
            return true;
        }
        value.advance(1);
    }
    false
}

fn advance_until_gt(value: &mut ByteCursor<'_>) -> bool {
    let limit = value.limit();
    while value.position() < limit {
        let b = value.get(value.position());
        if b == b'[' {
            value.advance(1);
            while value.position() < limit {
                let c = value.get(value.position());
                if c == b'\\' && value.position() + 1 < limit {
                    value.advance(2);
                    continue;
                }
                if c == b']' {
                    value.advance(1);
                    break;
                }
                value.advance(1);
            }
            continue;
        }
        if b == b'>' {
            return true;
        }
        value.advance(1);
    }
    false
}

fn is_valid_id_left(s: &str, smtp_utf8: bool) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut need_atext = true;
    for c in s.chars() {
        if c == '.' {
            if need_atext {
                return false;
            }
            need_atext = true;
        } else if is_atext(c, smtp_utf8) {
            need_atext = false;
        } else {
            return false;
        }
    }
    !need_atext
}

fn is_valid_id_right(s: &str, smtp_utf8: bool) -> bool {
    if s.is_empty() {
        return true;
    }
    if s.starts_with('[') {
        if s.len() < 2 || !s.ends_with(']') {
            return false;
        }
        let inner = &s[1..s.len() - 1];
        let chars: Vec<char> = inner.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '\\' && i + 1 < chars.len() {
                i += 2;
                continue;
            }
            if !is_dtext(chars[i], smtp_utf8) {
                return false;
            }
            i += 1;
        }
        return true;
    }
    is_valid_id_left(s, smtp_utf8)
}

fn is_atext(c: char, smtp_utf8: bool) -> bool {
    if smtp_utf8 && c > '\u{007F}' {
        return true;
    }
    c > ' ' && c < '\u{007F}'
        && !matches!(c, '(' | ')' | '<' | '>' | '[' | ']' | ':' | ';' | '@' | '\\' | ',' | '"')
}

fn is_dtext(c: char, smtp_utf8: bool) -> bool {
    if smtp_utf8 && c > '\u{007F}' {
        return true;
    }
    c > ' ' && c < '\u{007F}' && !matches!(c, '[' | ']' | '\\')
}

fn skip_cfws(value: &mut ByteCursor<'_>) {
    let limit = value.limit();
    while value.position() < limit {
        let b = value.get(value.position());
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b',') {
            value.advance(1);
        } else if b == b'(' {
            skip_comment(value);
        } else {
            break;
        }
    }
}

fn skip_comment(value: &mut ByteCursor<'_>) {
    let limit = value.limit();
    if value.position() >= limit || value.get(value.position()) != b'(' {
        return;
    }
    value.advance(1);
    let mut depth = 1;
    while value.position() < limit && depth > 0 {
        let pos = value.position();
        let b = value.get(pos);
        if b == b'\\' && pos + 1 < limit {
            value.set_position(pos + 2);
            continue;
        }
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
        }
        value.set_position(pos + 1);
    }
}
