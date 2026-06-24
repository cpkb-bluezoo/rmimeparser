//! RFC 5322 email address parser.

use crate::buffer::ByteCursor;
use crate::charset::{decode_slice, HeaderCharset};
use crate::rfc2047::Decoder as Rfc2047Decoder;

use super::email_address::EmailAddress;
use super::group_email_address::{Address, GroupEmailAddress};

/// RFC 5322 address parser.
pub struct EmailAddressParser;

impl EmailAddressParser {
    pub fn parse_email_address_list(value: &str) -> Option<Vec<Address>> {
        Self::parse_email_address_list_smtp_utf8(value, false)
    }

    pub fn parse_email_address_list_smtp_utf8(
        value: &str,
        smtp_utf8: bool,
    ) -> Option<Vec<Address>> {
        let value = value.trim();
        if value.is_empty() {
            return Some(Vec::new());
        }
        let mut addresses = Vec::new();
        let chars: Vec<char> = value.chars().collect();
        let len = chars.len();
        let mut pos = 0usize;
        let mut token = String::with_capacity(256);
        skip_ws_comments(&chars, len, &mut pos);
        while pos < len {
            let address = parse_address(&chars, len, &mut pos, &mut token, smtp_utf8)?;
            addresses.push(address);
            skip_ws_comments(&chars, len, &mut pos);
            if pos < len && chars[pos] == ',' {
                pos += 1;
                skip_ws_comments(&chars, len, &mut pos);
            } else if pos < len {
                return None;
            }
        }
        Some(addresses)
    }

    pub fn parse_email_address_list_bytes(
        value: &mut ByteCursor<'_>,
        charset: HeaderCharset,
    ) -> Option<Vec<Address>> {
        if !value.has_remaining() {
            return Some(Vec::new());
        }
        let mut addresses = Vec::new();
        let limit = value.limit();
        while value.position() < limit {
            skip_cfws(value);
            if value.position() >= limit {
                break;
            }
            let b = value.get(value.position());
            if b == b':' || b == b';' {
                skip_group(value);
                continue;
            }
            let mut display_name: Option<String> = None;
            if b != b'<' {
                let stop = [b'<', b':', b',', b';'];
                let name = Rfc2047Decoder::decode_display_name(value, charset, &stop);
                if value.position() >= limit {
                    if let Some(trimmed) = try_bare_addr_spec(&name) {
                        addresses.push(Address::Mailbox(trimmed));
                    }
                    break;
                }
                let b = value.get(value.position());
                if b != b'<' {
                    if let Some(addr) = try_bare_addr_spec(&name) {
                        addresses.push(Address::Mailbox(addr));
                        continue;
                    }
                    break;
                }
                display_name = Some(name);
            }
            let b = value.get(value.position());
            if b != b'<' {
                break;
            }
            value.advance(1);
            let local_range = parse_local_part_range(value)?;
            let mut local_cursor =
                ByteCursor::from_slice(value.bytes(), local_range.0, local_range.1);
            let local_part = decode_slice(&mut local_cursor, charset);
            if value.position() >= limit || value.get(value.position()) != b'@' {
                break;
            }
            value.advance(1);
            let domain_range = parse_domain_range(value)?;
            let mut domain_cursor =
                ByteCursor::from_slice(value.bytes(), domain_range.0, domain_range.1);
            let domain = decode_slice(&mut domain_cursor, charset);
            if value.position() >= limit || value.get(value.position()) != b'>' {
                break;
            }
            value.advance(1);
            addresses.push(Address::Mailbox(EmailAddress::new(
                display_name,
                local_part,
                domain,
                false,
            )));
        }
        Some(addresses)
    }

    pub fn parse_email_address(value: &str) -> Option<EmailAddress> {
        let list = Self::parse_email_address_list(value)?;
        match list.first()? {
            Address::Mailbox(m) => Some(m.clone()),
            Address::Group(_) => None,
        }
    }

    pub fn parse_envelope_address(value: &str) -> Option<EmailAddress> {
        Self::parse_envelope_address_smtp_utf8(value, false)
    }

    pub fn parse_envelope_address_smtp_utf8(
        value: &str,
        smtp_utf8: bool,
    ) -> Option<EmailAddress> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        let mut at_pos = None;
        let mut in_quote = false;
        let chars: Vec<char> = value.chars().collect();
        for (i, &c) in chars.iter().enumerate() {
            if c == '"' && (i == 0 || chars[i - 1] != '\\') {
                in_quote = !in_quote;
            } else if c == '@' && !in_quote {
                if at_pos.is_some() {
                    return None;
                }
                at_pos = Some(i);
            }
        }
        let at = at_pos?;
        if at == 0 || at + 1 >= chars.len() {
            return None;
        }
        let local_part: String = chars[..at].iter().collect();
        let domain: String = chars[at + 1..].iter().collect();
        if !is_valid_local_part(&local_part, smtp_utf8) || !is_valid_domain(&domain, smtp_utf8) {
            return None;
        }
        Some(EmailAddress::new(None, local_part, domain, true))
    }
}

fn try_bare_addr_spec(text: &str) -> Option<EmailAddress> {
    let trimmed = text.trim();
    let at = trimmed.rfind('@')?;
    if at == 0 || at + 1 >= trimmed.len() {
        return None;
    }
    let local = &trimmed[..at];
    let domain = &trimmed[at + 1..];
    if trimmed.contains('<') || trimmed.contains('>') {
        return None;
    }
    Some(EmailAddress::new(None, local, domain, true))
}

fn parse_address(
    input: &[char],
    len: usize,
    pos: &mut usize,
    token: &mut String,
    smtp_utf8: bool,
) -> Option<Address> {
    skip_ws_comments(input, len, pos);
    if *pos >= len {
        return None;
    }
    let colon = find_next_unquoted(input, len, ':', *pos);
    let angle = find_next_unquoted(input, len, '<', *pos);
    if colon.is_some() && (angle.is_none() || colon? < angle?) {
        let group = parse_group(input, len, pos, token, smtp_utf8)?;
        Some(Address::Group(group))
    } else {
        let mailbox = parse_individual_address(input, len, pos, token, smtp_utf8)?;
        Some(Address::Mailbox(mailbox))
    }
}

fn parse_group(
    input: &[char],
    len: usize,
    pos: &mut usize,
    token: &mut String,
    smtp_utf8: bool,
) -> Option<GroupEmailAddress> {
    let group_name = parse_display_name(input, len, pos, token, smtp_utf8)?;
    if *pos >= len || input[*pos] != ':' {
        return None;
    }
    *pos += 1;
    skip_ws_comments(input, len, pos);
    let mut members = Vec::new();
    while *pos < len && input[*pos] != ';' {
        if let Some(m) = parse_individual_address(input, len, pos, token, smtp_utf8) {
            members.push(m);
        }
        skip_ws_comments(input, len, pos);
        if *pos < len && input[*pos] == ',' {
            *pos += 1;
            skip_ws_comments(input, len, pos);
        } else if *pos < len && input[*pos] != ';' {
            return None;
        }
    }
    if *pos >= len || input[*pos] != ';' {
        return None;
    }
    *pos += 1;
    skip_ws_comments(input, len, pos);
    Some(GroupEmailAddress::new(group_name, members, None))
}

fn parse_individual_address(
    input: &[char],
    len: usize,
    pos: &mut usize,
    token: &mut String,
    smtp_utf8: bool,
) -> Option<EmailAddress> {
    skip_ws_comments(input, len, pos);
    if *pos >= len {
        return None;
    }
    let mut display_name = None;
    let angle_pos = find_next_unquoted(input, len, '<', *pos);
    let (local_part, domain, simple);
    if let Some(angle) = angle_pos {
        if angle > *pos {
            display_name = Some(parse_display_name(input, len, pos, token, smtp_utf8)?);
            skip_ws_comments(input, len, pos);
        }
        if *pos >= len || input[*pos] != '<' {
            return None;
        }
        *pos += 1;
        let parts = parse_addr_spec(input, len, pos, token, smtp_utf8)?;
        local_part = parts.0;
        domain = parts.1;
        simple = false;
        if *pos >= len || input[*pos] != '>' {
            return None;
        }
        *pos += 1;
    } else {
        let parts = parse_addr_spec(input, len, pos, token, smtp_utf8)?;
        local_part = parts.0;
        domain = parts.1;
        simple = true;
    }
    Some(EmailAddress::new(display_name, local_part, domain, simple))
}

fn parse_display_name(
    input: &[char],
    len: usize,
    pos: &mut usize,
    token: &mut String,
    smtp_utf8: bool,
) -> Option<String> {
    token.clear();
    skip_ws_comments(input, len, pos);
    while *pos < len {
        let c = input[*pos];
        if matches!(c, '<' | ':' | ',' | ';') {
            break;
        } else if c == '"' {
            parse_quoted_string(input, len, pos, token)?;
        } else if c == '(' {
            skip_comment(input, len, pos);
        } else if is_whitespace(c) {
            if !token.ends_with(' ') {
                token.push(' ');
            }
            *pos += 1;
        } else if is_atom(c, smtp_utf8) {
            token.push(c);
            *pos += 1;
        } else {
            break;
        }
    }
    let mut result = token.trim().to_string();
    if result.len() >= 2 && result.starts_with('"') && result.ends_with('"') {
        result = result[1..result.len() - 1].to_string();
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

fn parse_addr_spec(
    input: &[char],
    len: usize,
    pos: &mut usize,
    token: &mut String,
    smtp_utf8: bool,
) -> Option<(String, String)> {
    token.clear();
    parse_local_part(input, len, pos, token, smtp_utf8)?;
    let local = token.clone();
    if *pos >= len || input[*pos] != '@' {
        return None;
    }
    *pos += 1;
    token.clear();
    parse_domain(input, len, pos, token, smtp_utf8)?;
    Some((local, token.clone()))
}

fn parse_local_part(
    input: &[char],
    len: usize,
    pos: &mut usize,
    token: &mut String,
    smtp_utf8: bool,
) -> Option<()> {
    if *pos >= len {
        return None;
    }
    if input[*pos] == '"' {
        parse_quoted_string(input, len, pos, token)
    } else {
        parse_atom(input, len, pos, token, smtp_utf8)?;
        while *pos < len && input[*pos] == '.' {
            token.push('.');
            *pos += 1;
            parse_atom(input, len, pos, token, smtp_utf8)?;
        }
        Some(())
    }
}

fn parse_domain(
    input: &[char],
    len: usize,
    pos: &mut usize,
    token: &mut String,
    smtp_utf8: bool,
) -> Option<()> {
    if *pos >= len {
        return None;
    }
    if input[*pos] == '[' {
        token.push('[');
        *pos += 1;
        while *pos < len && input[*pos] != ']' {
            let c = input[*pos];
            if c == '\\' && *pos + 1 < len {
                token.push(c);
                token.push(input[*pos + 1]);
                *pos += 2;
            } else if is_dtext(c) {
                token.push(c);
                *pos += 1;
            } else {
                return None;
            }
        }
        if *pos >= len {
            return None;
        }
        token.push(']');
        *pos += 1;
        Some(())
    } else {
        parse_atom(input, len, pos, token, smtp_utf8)?;
        while *pos < len && input[*pos] == '.' {
            token.push('.');
            *pos += 1;
            parse_atom(input, len, pos, token, smtp_utf8)?;
        }
        Some(())
    }
}

fn parse_atom(
    input: &[char],
    len: usize,
    pos: &mut usize,
    token: &mut String,
    smtp_utf8: bool,
) -> Option<()> {
    let start = token.len();
    while *pos < len && is_atom(input[*pos], smtp_utf8) {
        token.push(input[*pos]);
        *pos += 1;
    }
    if token.len() == start {
        None
    } else {
        Some(())
    }
}

fn parse_quoted_string(
    input: &[char],
    len: usize,
    pos: &mut usize,
    token: &mut String,
) -> Option<()> {
    if *pos >= len || input[*pos] != '"' {
        return None;
    }
    token.push('"');
    *pos += 1;
    while *pos < len && input[*pos] != '"' {
        let c = input[*pos];
        if c == '\\' && *pos + 1 < len {
            token.push(c);
            token.push(input[*pos + 1]);
            *pos += 2;
        } else {
            token.push(c);
            *pos += 1;
        }
    }
    if *pos >= len {
        return None;
    }
    token.push('"');
    *pos += 1;
    Some(())
}

fn skip_comment(input: &[char], len: usize, pos: &mut usize) {
    if *pos >= len || input[*pos] != '(' {
        return;
    }
    *pos += 1;
    let mut depth = 1;
    while *pos < len && depth > 0 {
        let c = input[*pos];
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
        } else if c == '\\' && *pos + 1 < len {
            *pos += 1;
        }
        *pos += 1;
    }
}

fn skip_ws_comments(input: &[char], len: usize, pos: &mut usize) {
    while *pos < len {
        let c = input[*pos];
        if is_whitespace(c) {
            *pos += 1;
        } else if c == '(' {
            skip_comment(input, len, pos);
        } else {
            break;
        }
    }
}

fn find_next_unquoted(input: &[char], len: usize, target: char, start: usize) -> Option<usize> {
    let mut in_quotes = false;
    let mut depth = 0;
    for i in start..len {
        let c = input[i];
        if c == '"' && depth == 0 {
            if i == 0 || input[i - 1] != '\\' {
                in_quotes = !in_quotes;
            }
        } else if c == '(' && !in_quotes {
            depth += 1;
        } else if c == ')' && !in_quotes {
            depth -= 1;
        } else if c == target && !in_quotes && depth == 0 {
            return Some(i);
        }
    }
    None
}

fn is_whitespace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

fn is_atom(c: char, smtp_utf8: bool) -> bool {
    if smtp_utf8 && c > '\u{007F}' {
        return true;
    }
    c > ' ' && c < '\u{007F}'
        && !matches!(c, '(' | ')' | '<' | '>' | '[' | ']' | ':' | ';' | '@' | '\\' | ',' | '.' | '"')
}

fn is_dtext(c: char) -> bool {
    c >= '!' && c <= '~' && !matches!(c, '[' | ']' | '\\')
}

fn is_valid_local_part(local_part: &str, smtp_utf8: bool) -> bool {
    let len = local_part.len();
    if len == 0 || len > 64 {
        return false;
    }
    if local_part.starts_with('"') {
        if len < 2 || !local_part.ends_with('"') {
            return false;
        }
        let inner = &local_part[1..len - 1];
        let chars: Vec<char> = inner.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '\\' && i + 1 < chars.len() {
                i += 2;
            } else if c < ' ' || c == '\u{007F}' {
                if !smtp_utf8 || c < '\u{0080}' {
                    return false;
                }
                i += 1;
            } else {
                i += 1;
            }
        }
        return true;
    }
    if local_part.starts_with('.') || local_part.ends_with('.') {
        return false;
    }
    let mut prev_dot = false;
    for c in local_part.chars() {
        if c == '.' {
            if prev_dot {
                return false;
            }
            prev_dot = true;
        } else {
            prev_dot = false;
            if !is_atom_char(c, smtp_utf8) {
                return false;
            }
        }
    }
    true
}

fn is_valid_domain(domain: &str, smtp_utf8: bool) -> bool {
    let len = domain.len();
    if len == 0 || len > 255 {
        return false;
    }
    if domain.starts_with('[') {
        if !domain.ends_with(']') {
            return false;
        }
        return domain[1..domain.len() - 1].chars().all(|c| {
            (c >= '!' && c <= '~') && !matches!(c, '[' | ']' | '\\')
        });
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    let mut prev_dot = false;
    for c in domain.chars() {
        if c == '.' {
            if prev_dot {
                return false;
            }
            prev_dot = true;
        } else {
            prev_dot = false;
            if c.is_ascii_alphanumeric() || c == '-' {
                continue;
            }
            if smtp_utf8 && c > '\u{007F}' {
                continue;
            }
            return false;
        }
    }
    true
}

fn is_atom_char(c: char, smtp_utf8: bool) -> bool {
    if c.is_ascii_alphanumeric() {
        return true;
    }
    if matches!(
        c,
        '!' | '#'
            | '$'
            | '%'
            | '&'
            | '\''
            | '*'
            | '+'
            | '-'
            | '/'
            | '='
            | '?'
            | '^'
            | '_'
            | '`'
            | '{'
            | '|'
            | '}'
            | '~'
    ) {
        return true;
    }
    smtp_utf8 && c > '\u{007F}'
}

fn skip_cfws(value: &mut ByteCursor<'_>) {
    let limit = value.limit();
    while value.position() < limit {
        let b = value.get(value.position());
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b',') {
            value.advance(1);
        } else if b == b'(' {
            skip_comment_bytes(value);
        } else {
            break;
        }
    }
}

fn skip_comment_bytes(value: &mut ByteCursor<'_>) {
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

fn skip_group(value: &mut ByteCursor<'_>) {
    let limit = value.limit();
    while value.position() < limit && value.get(value.position()) != b';' {
        value.advance(1);
    }
    if value.position() < limit {
        value.advance(1);
    }
}

fn is_atext(b: u8) -> bool {
    b > 32 && b < 127
        && !matches!(b, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b':' | b';' | b'@' | b'\\' | b',' | b'"')
}

fn parse_local_part_range(value: &ByteCursor<'_>) -> Option<(usize, usize)> {
    let limit = value.limit();
    let mut pos = value.position();
    if pos >= limit {
        return None;
    }
    let start = pos;
    if value.get(pos) == b'"' {
        pos += 1;
        while pos < limit {
            let b = value.get(pos);
            if b == b'\\' && pos + 1 < limit {
                pos += 2;
                continue;
            }
            if b == b'"' {
                pos += 1;
                return Some((start + 1, pos - 1));
            }
            pos += 1;
        }
        return None;
    }
    while pos < limit && (is_atext(value.get(pos)) || value.get(pos) == b'.') {
        pos += 1;
    }
    if pos == start {
        None
    } else {
        Some((start, pos))
    }
}

fn parse_domain_range(value: &ByteCursor<'_>) -> Option<(usize, usize)> {
    let limit = value.limit();
    let mut pos = value.position();
    if pos >= limit {
        return None;
    }
    let start = pos;
    if value.get(pos) == b'[' {
        pos += 1;
        while pos < limit && value.get(pos) != b']' {
            if value.get(pos) == b'\\' && pos + 1 < limit {
                pos += 2;
                continue;
            }
            pos += 1;
        }
        if pos >= limit {
            return None;
        }
        pos += 1;
        return Some((start, pos));
    }
    while pos < limit && (is_atext(value.get(pos)) || value.get(pos) == b'.') {
        pos += 1;
    }
    Some((start, pos))
}
