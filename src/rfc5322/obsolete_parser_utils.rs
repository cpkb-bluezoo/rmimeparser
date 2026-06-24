//! Obsolete RFC 5322 syntax recovery helpers.

use crate::buffer::{index_of, ByteCursor};
use crate::charset::{decode_slice, HeaderCharset};
use crate::mime::ContentId;
use crate::rfc2047::Decoder as Rfc2047Decoder;
use crate::rfc5322::email_address::EmailAddress;
use crate::rfc5322::email_address_parser::EmailAddressParser;

/// Obsolete syntax parsers.
pub struct ObsoleteParserUtils;

impl ObsoleteParserUtils {
    pub fn parse_obsolete_address_list(
        value: &mut ByteCursor<'_>,
        charset: HeaderCharset,
    ) -> Option<Vec<EmailAddress>> {
        if !value.has_remaining() {
            return None;
        }
        let mut addresses = Vec::new();
        let limit = value.limit();
        while value.position() < limit {
            let comma = index_of(value, b',');
            let end = comma.unwrap_or(limit);
            if end > value.position() {
                let mut segment = value.duplicate();
                segment.set_limit(end);
                let part =
                    Rfc2047Decoder::decode_unstructured_header_value(&mut segment, charset, true);
                if !part.trim().is_empty() {
                    if let Some(addr) = parse_obsolete_address(&part) {
                        addresses.push(addr);
                    }
                }
            }
            value.set_position(if let Some(c) = comma { c + 1 } else { limit });
        }
        if addresses.is_empty() {
            None
        } else {
            Some(addresses)
        }
    }

    pub fn parse_obsolete_message_id_list(
        value: &mut ByteCursor<'_>,
        charset: HeaderCharset,
    ) -> Option<Vec<ContentId>> {
        if !value.has_remaining() {
            return None;
        }
        let mut message_ids = Vec::new();
        let limit = value.limit();
        let mut segment_start = value.position();
        let mut pos = segment_start;
        while pos <= limit {
            let b = if pos < limit {
                value.get(pos)
            } else {
                b' '
            };
            let is_sep = matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b',');
            if is_sep || pos == limit {
                if pos > segment_start {
                    let mut segment =
                        ByteCursor::from_slice(value.bytes(), segment_start, pos);
                    let part = decode_slice(&mut segment, charset);
                    if !part.trim().is_empty() {
                        if let Some(id) = parse_obsolete_message_id(&part) {
                            message_ids.push(id);
                        }
                    }
                }
                segment_start = pos + 1;
            }
            pos += 1;
        }
        value.set_position(limit);
        if message_ids.is_empty() {
            None
        } else {
            Some(message_ids)
        }
    }
}

fn parse_obsolete_address(address_text: &str) -> Option<EmailAddress> {
    let address_text = address_text.trim();
    if address_text.contains(':') && address_text.starts_with('@') {
        return parse_source_routed_address(address_text);
    }
    parse_basic_obsolete_address(address_text)
}

fn parse_source_routed_address(address_text: &str) -> Option<EmailAddress> {
    let colon = address_text.rfind(':')?;
    if colon + 1 >= address_text.len() {
        return None;
    }
    let destination = address_text[colon + 1..].trim();
    if destination.contains('@') && !destination.contains(' ') {
        return parse_basic_email_address(destination);
    }
    None
}

fn parse_basic_obsolete_address(address_text: &str) -> Option<EmailAddress> {
    if address_text.contains('<') && address_text.contains('>') {
        return parse_display_name_address(address_text);
    }
    if address_text.contains('@') {
        return parse_basic_email_address(address_text);
    }
    None
}

fn parse_display_name_address(address_text: &str) -> Option<EmailAddress> {
    let open = address_text.find('<')?;
    let close = address_text.rfind('>')?;
    if close <= open {
        return None;
    }
    let display_name = clean_display_name(address_text[..open].trim());
    let email = address_text[open + 1..close].trim();
    if !email.contains('@') {
        return None;
    }
    let at = email.rfind('@')?;
    if at == 0 || at + 1 >= email.len() {
        return None;
    }
    Some(EmailAddress::new(
        if display_name.is_empty() {
            None
        } else {
            Some(display_name)
        },
        &email[..at],
        &email[at + 1..],
        false,
    ))
}

fn parse_basic_email_address(email_address: &str) -> Option<EmailAddress> {
    let email_address = remove_comments(email_address.trim());
    let at = email_address.rfind('@')?;
    if at == 0 || at + 1 >= email_address.len() {
        return None;
    }
    Some(EmailAddress::new(
        None,
        &email_address[..at],
        &email_address[at + 1..],
        false,
    ))
}

fn clean_display_name(display_name: &str) -> String {
    let mut display_name = display_name.trim().to_string();
    if display_name.len() >= 2
        && display_name.starts_with('"')
        && display_name.ends_with('"')
    {
        display_name = display_name[1..display_name.len() - 1].to_string();
    }
    display_name
        .replace("\\\"", "\"")
        .replace("\\\\", "\\")
        .trim()
        .to_string()
}

fn parse_obsolete_message_id(id_text: &str) -> Option<ContentId> {
    let id_text = remove_comments(id_text.trim());
    if id_text.starts_with('<') && id_text.ends_with('>') {
        return parse_basic_message_id(&id_text[1..id_text.len() - 1]);
    }
    parse_basic_message_id(&id_text)
}

fn remove_comments(text: &str) -> String {
    let mut result = String::new();
    let mut depth = 0;
    for c in text.chars() {
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
        } else if depth == 0 {
            result.push(c);
        }
    }
    result.trim().to_string()
}

fn parse_basic_message_id(message_id: &str) -> Option<ContentId> {
    let message_id = message_id.trim();
    let at = message_id.rfind('@')?;
    if at == 0 || at + 1 >= message_id.len() {
        return None;
    }
    let local_part = &message_id[..at];
    let domain_part = &message_id[at + 1..];
    if local_part.is_empty() || !is_valid_local_part(local_part) {
        return None;
    }
    if domain_part.is_empty() || !is_valid_domain_part(domain_part) {
        return None;
    }
    Some(ContentId::new(local_part, domain_part))
}

fn is_valid_local_part(local_part: &str) -> bool {
    local_part.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '.' | '-' | '_' | '+' | '=' | '#' | '$' | '%')
    })
}

fn is_valid_domain_part(domain_part: &str) -> bool {
    if !domain_part.contains('.') {
        return false;
    }
    if domain_part.starts_with('.')
        || domain_part.ends_with('.')
        || domain_part.starts_with('-')
        || domain_part.ends_with('-')
    {
        return false;
    }
    domain_part
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

// Keep compiler happy for unused import in future extensions.
#[allow(dead_code)]
fn _envelope_fallback(s: &str) -> Option<EmailAddress> {
    EmailAddressParser::parse_envelope_address(s)
}
