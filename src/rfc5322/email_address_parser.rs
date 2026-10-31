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
        let mailboxes = Self::parse_mailbox_list_bytes(value, charset)?;
        Some(mailboxes.into_iter().map(Address::Mailbox).collect())
    }

    /// Like [`Self::parse_email_address_list_bytes`], but yields the mailboxes
    /// directly (this parser never produces groups): header dispatch needs no
    /// intermediate list.
    pub(crate) fn parse_mailbox_list_bytes(
        value: &mut ByteCursor<'_>,
        charset: HeaderCharset,
    ) -> Option<Vec<EmailAddress>> {
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
                    if let Some(trimmed) = try_bare_addr_spec_owned(name) {
                        addresses.push(trimmed);
                    }
                    break;
                }
                let b = value.get(value.position());
                if b != b'<' {
                    if let Some(addr) = try_bare_addr_spec_owned(name) {
                        addresses.push(addr);
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
            value.set_position(local_range.1);
            if value.position() < limit && value.get(value.position()) == b'"' {
                value.advance(1);
            }
            if value.position() >= limit || value.get(value.position()) != b'@' {
                break;
            }
            value.advance(1);
            let domain_range = parse_domain_range(value)?;
            let mut domain_cursor =
                ByteCursor::from_slice(value.bytes(), domain_range.0, domain_range.1);
            let domain = decode_slice(&mut domain_cursor, charset);
            value.set_position(domain_range.1);
            if value.position() >= limit || value.get(value.position()) != b'>' {
                break;
            }
            value.advance(1);
            addresses.push(EmailAddress::new(
                display_name,
                local_part,
                domain,
                false,
            ));
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

/// Where the list element starting at `from` ends: the next unquoted,
/// uncommented `,` or `;`, or `len`. One pass that stops at the first
/// delimiter, so scanning a list stays linear.
fn address_end(input: &[char], len: usize, from: usize) -> usize {
    let mut in_quotes = false;
    let mut depth = 0;
    for i in from..len {
        let c = input[i];
        if c == '"' && depth == 0 {
            if i == 0 || input[i - 1] != '\\' {
                in_quotes = !in_quotes;
            }
        } else if c == '(' && !in_quotes {
            depth += 1;
        } else if c == ')' && !in_quotes {
            depth -= 1;
        } else if (c == ',' || c == ';') && !in_quotes && depth == 0 {
            return i;
        }
    }
    len
}

/// [`try_bare_addr_spec`] for an owned string: the local part reuses its
/// allocation.
fn try_bare_addr_spec_owned(mut text: String) -> Option<EmailAddress> {
    let trimmed = text.trim();
    let at = trimmed.rfind('@')?;
    if at == 0 || at + 1 >= trimmed.len() || trimmed.contains('<') || trimmed.contains('>') {
        return None;
    }
    let lead = trimmed.as_ptr() as usize - text.as_ptr() as usize;
    let domain = trimmed[at + 1..].to_string();
    text.truncate(lead + at);
    text.drain(..lead);
    Some(EmailAddress::new(None, text, domain, true))
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
    // Only this address: a `<` or `:` in a later list element must not
    // decide how this one is read.
    let end = address_end(input, len, *pos);
    let colon = find_next_unquoted(input, end, ':', *pos);
    let angle = find_next_unquoted(input, end, '<', *pos);
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
    let angle_pos = find_next_unquoted(input, address_end(input, len, *pos), '<', *pos);
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
    ('!'..='~').contains(&c) && !matches!(c, '[' | ']' | '\\')
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
            ('!'..='~').contains(&c) && !matches!(c, '[' | ']' | '\\')
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


/// Buffers the element parsers reuse from one element to the next.
#[derive(Default)]
pub(crate) struct MailboxScratch {
    chars: Vec<char>,
    token: String,
}

/// A mailbox read from one element of an address list.
pub(crate) struct Mailbox {
    pub(crate) display_name: Option<String>,
    pub(crate) local_part: String,
    pub(crate) domain: String,
    /// Written in obsolete syntax.
    pub(crate) obsolete: bool,
}

/// Reads one mailbox from `text`, the text of one element of an address list:
/// `[display-name] <local@domain>` or `local@domain`, with comments allowed.
/// Falls back to the obsolete syntaxes (a source route, a display name with
/// dots). The local part and domain have to be valid whichever way it is read.
/// `None` if it is not a mailbox.
pub(crate) fn parse_mailbox_element(
    text: &str,
    smtp_utf8: bool,
    scratch: &mut MailboxScratch,
) -> Option<Mailbox> {
    let text = text.trim();
    parse_mailbox_fast(text, smtp_utf8)
        .or_else(|| parse_mailbox_general(text, smtp_utf8, scratch))
}

/// The two shapes nearly every address has, read directly: `local@domain` and
/// `Plain Name <local@domain>`, in plain ASCII with no quotes or comments. It
/// accepts only what the general parser would accept with the same result,
/// and returns `None`, not an error, for anything else; the general parser
/// then decides.
fn parse_mailbox_fast(text: &str, smtp_utf8: bool) -> Option<Mailbox> {
    let bytes = text.as_bytes();
    let plain = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'/' | b'=' | b'?' | b'^' | b'_' | b'`' | b'{' | b'|' | b'}' | b'~');
    // The address itself: plain characters and dots, one at sign
    let address = |s: &str| -> Option<(String, String)> {
        let (local, domain) = s.split_once('@')?;
        if !s.bytes().all(|b| plain(b) || b == b'.' || b == b'@')
            || !valid_parts(local, domain, smtp_utf8)
        {
            return None;
        }
        Some((local.to_string(), domain.to_string()))
    };
    if bytes.is_empty() || !bytes.is_ascii() {
        return None;
    }
    let (display_name, local_part, domain) = match bytes.iter().position(|&b| b == b'<') {
        None => {
            let (local, domain) = address(text)?;
            (None, local, domain)
        }
        Some(open) => {
            if bytes[bytes.len() - 1] != b'>' {
                return None;
            }
            let (local, domain) = address(&text[open + 1..text.len() - 1])?;
            let name = &text[..open];
            // a phrase: plain words, white space between them
            if !name.bytes().all(|b| plain(b) || b == b' ' || b == b'\t') {
                return None;
            }
            let mut words = name.split_ascii_whitespace();
            let display = match words.next() {
                None => None,
                Some(first) => {
                    let mut joined = String::with_capacity(name.len());
                    joined.push_str(first);
                    for word in words {
                        joined.push(' ');
                        joined.push_str(word);
                    }
                    Some(Rfc2047Decoder::decode_encoded_words_owned(joined))
                }
            };
            (display, local, domain)
        }
    };
    Some(Mailbox {
        display_name,
        local_part,
        domain,
        obsolete: false,
    })
}

fn parse_mailbox_general(
    text: &str,
    smtp_utf8: bool,
    scratch: &mut MailboxScratch,
) -> Option<Mailbox> {
    if text.is_empty() {
        return None;
    }
    let MailboxScratch { chars, token } = scratch;
    chars.clear();
    chars.extend(text.chars());
    let len = chars.len();
    let mut pos = 0usize;
    if let Some(address) = parse_individual_address(chars, len, &mut pos, token, smtp_utf8) {
        skip_ws_comments(chars, len, &mut pos);
        if pos == len && valid_parts(address.local_part(), address.domain(), smtp_utf8) {
            let (display_name, local_part, domain) = address.into_parts();
            return Some(Mailbox {
                display_name: display_name.map(Rfc2047Decoder::decode_encoded_words_owned),
                local_part,
                domain,
                obsolete: false,
            });
        }
    }
    parse_obsolete_mailbox(text, smtp_utf8)
}

/// The name of a group, from the text before its colon.
pub(crate) fn parse_group_name(
    text: &str,
    smtp_utf8: bool,
    scratch: &mut MailboxScratch,
) -> Option<String> {
    let MailboxScratch { chars, token } = scratch;
    chars.clear();
    chars.extend(text.trim().chars());
    let len = chars.len();
    let mut pos = 0usize;
    let name = parse_display_name(chars, len, &mut pos, token, smtp_utf8)?;
    skip_ws_comments(chars, len, &mut pos);
    (pos == len).then(|| Rfc2047Decoder::decode_encoded_words_owned(name))
}

fn valid_parts(local: &str, domain: &str, smtp_utf8: bool) -> bool {
    is_valid_local_part(local, smtp_utf8) && is_valid_domain(domain, smtp_utf8)
}

fn decode_words(name: &str) -> String {
    Rfc2047Decoder::decode_encoded_words_owned(name.to_string())
}

/// The obsolete forms: a display name with characters a phrase does not allow
/// (`John Q. Public <jqp@example.org>`), and a source route
/// (`<@a.example,@b.example:user@c.example>`).
fn parse_obsolete_mailbox(text: &str, smtp_utf8: bool) -> Option<Mailbox> {
    let uncommented = crate::mime::utils::strip_comments(text).ok()?;
    let text = uncommented.trim();
    let (display, inner) = match (text.find('<'), text.rfind('>')) {
        (Some(open), Some(close)) if open < close && text[close + 1..].trim().is_empty() => {
            (text[..open].trim(), text[open + 1..close].trim())
        }
        (None, None) => ("", text),
        _ => return None,
    };
    let inner = match inner.strip_prefix('@') {
        // a route: skip to the colon that ends it
        Some(_) => inner[inner.rfind(':')? + 1..].trim(),
        None => inner,
    };
    if inner.chars().any(char::is_whitespace) {
        return None;
    }
    let at = inner.rfind('@')?;
    let (local, domain) = (&inner[..at], &inner[at + 1..]);
    if !valid_parts(local, domain, smtp_utf8) {
        return None;
    }
    // a bare address is only obsolete if it is a route
    if display.is_empty() && !text.starts_with('@') && !text.starts_with('<') {
        return None;
    }
    let display = clean_name(display);
    Some(Mailbox {
        display_name: (!display.is_empty()).then(|| decode_words(&display)),
        local_part: local.to_string(),
        domain: domain.to_string(),
        obsolete: true,
    })
}

/// A display name without its quotes and quoted-pairs.
fn clean_name(name: &str) -> String {
    let name = name.trim();
    let name = if name.len() >= 2 && name.starts_with('"') && name.ends_with('"') {
        &name[1..name.len() - 1]
    } else {
        name
    };
    name.replace("\\\"", "\"").replace("\\\\", "\\").trim().to_string()
}

#[cfg(test)]
mod fast_path_tests {
    use super::*;

    /// A small deterministic generator.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// Wherever the fast path reads an address, the general parser reads the
    /// same one.
    #[test]
    fn the_fast_path_never_disagrees_with_the_general_parser() {
        let alphabet: Vec<&str> = vec![
            "a", "B", "7", "x", " ", " ", ".", "@", "@", "<", ">", "-", "_", "+", "\"", "(", ")",
            ",", ":", ";", "\\", "[", "]", "=?utf-8?q?a?=", "\t", "\u{e9}", "john", "example",
            ".org", "<a@b.org>", "'",
        ];
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut scratch = MailboxScratch::default();
        let (mut accepted, mut total) = (0usize, 0usize);
        for _ in 0..300_000 {
            let n = 1 + (rng.next() % 9) as usize;
            let text: String = (0..n)
                .map(|_| alphabet[(rng.next() % alphabet.len() as u64) as usize])
                .collect();
            let text = text.trim();
            if text.is_empty() {
                continue;
            }
            total += 1;
            for smtp_utf8 in [false, true] {
                let Some(fast) = parse_mailbox_fast(text, smtp_utf8) else {
                    continue;
                };
                accepted += 1;
                let general = parse_mailbox_general(text, smtp_utf8, &mut scratch)
                    .unwrap_or_else(|| panic!("fast read {text:?}, general did not"));
                assert_eq!(fast.display_name, general.display_name, "{text:?}");
                assert_eq!(fast.local_part, general.local_part, "{text:?}");
                assert_eq!(fast.domain, general.domain, "{text:?}");
                assert_eq!(fast.obsolete, general.obsolete, "{text:?}");
            }
        }
        assert!(total > 200_000 && accepted > 1_000, "{accepted} of {total}");
    }
}
