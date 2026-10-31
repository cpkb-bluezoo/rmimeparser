//! RFC 5322 structured header dispatch (used by MIME parser).

use crate::buffer::ByteCursor;
use crate::charset::HeaderCharset;
use crate::mime::error::ParseResult;
use crate::rfc5322::message_parser::MessageHeaderState;
use crate::mime::utils::{decode_header_bytes, decode_token_header_value};
use crate::rfc2047::Decoder as Rfc2047Decoder;
use crate::rfc5322::email_address_parser::EmailAddressParser;
use crate::rfc5322::message_date_time::MessageDateTimeFormatter;
use crate::rfc5322::message_handler::MessageHandler;
use crate::mime::MessageIdParser;
use crate::rfc5322::obsolete_parser_utils::ObsoleteParserUtils;
use crate::rfc5322::obsolete_structure_type::ObsoleteStructureType;

/// The RFC 5322 headers this layer parses itself, so asks the MIME parser to
/// hand it raw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawKind {
    Date,
    Address,
    MessageId,
}

/// Which kind, if any, of header `name` is (case-insensitively). Every other
/// header, known or not, is unstructured.
pub(crate) fn classify(name: &str) -> Option<RawKind> {
    let mut buf = [0u8; LOWER_NAME_MAX];
    match lowercase_name(name, &mut buf) {
        "date" | "resent-date" => Some(RawKind::Date),
        "from"
        | "sender"
        | "to"
        | "cc"
        | "bcc"
        | "reply-to"
        | "resent-from"
        | "return-path"
        | "resent-sender"
        | "resent-to"
        | "resent-cc"
        | "resent-bcc"
        | "resent-reply-to"
        | "envelope-to"
        | "delivered-to"
        | "x-original-to"
        | "errors-to"
        | "apparently-to" => Some(RawKind::Address),
        "message-id" | "in-reply-to" | "references" | "resent-message-id" => {
            Some(RawKind::MessageId)
        }
        _ => None,
    }
}

/// Parses a header of `kind` whose whole raw value is `value`.
pub(crate) fn dispatch_raw<H: MessageHandler + ?Sized>(
    kind: RawKind,
    strip_header_whitespace: bool,
    state: &mut MessageHeaderState,
    handler: &mut H,
    name: &str,
    value: &[u8],
) -> ParseResult<()> {
    match kind {
        RawKind::Date => handle_date_header(state, handler, name, value),
        RawKind::Address => {
            handle_address_header(strip_header_whitespace, state, handler, name, value)
        }
        RawKind::MessageId => {
            handle_message_id_header(strip_header_whitespace, state, handler, name, value)
        }
    }
}

fn handle_date_header<H: MessageHandler + ?Sized>(
    state: &mut MessageHeaderState,
    handler: &mut H,
    name: &str,
    value: &[u8],
) -> ParseResult<()> {
    let value_str = {
        let mut slice = value;
        decode_token_header_value(&mut slice, true)
    };
    state.used_obsolete_syntax = false;
    if let Ok(dt) = MessageDateTimeFormatter::parse(&value_str) {
        handler.date_header(name, dt)?;
    } else if let Some(dt) = MessageDateTimeFormatter::parse_obsolete(&value_str) {
        state.used_obsolete_syntax = true;
        handler.obsolete_structure(ObsoleteStructureType::ObsoleteDateTimeSyntax)?;
        handler.date_header(name, dt)?;
    } else {
        handler.unexpected_header(name, &value_str)?;
    }
    Ok(())
}

fn handle_address_header<H: MessageHandler + ?Sized>(
    strip_header_whitespace: bool,
    state: &MessageHeaderState,
    handler: &mut H,
    name: &str,
    value: &[u8],
) -> ParseResult<()> {
    let charset = header_charset(state);
    let mut cursor = ByteCursor::new(value);
    if let Some(mailboxes) = EmailAddressParser::parse_mailbox_list_bytes(&mut cursor, charset) {
        if !mailboxes.is_empty() {
            handler.address_header(name, &mailboxes)?;
            return Ok(());
        }
    }
    let mut cursor = ByteCursor::new(value);
    if let Some(list) = ObsoleteParserUtils::parse_obsolete_address_list(&mut cursor, charset) {
        handler.obsolete_structure(ObsoleteStructureType::ObsoleteAddressSyntax)?;
        handler.address_header(name, &list)?;
        return Ok(());
    }
    let value_str = decode_header_value_with_rfc2047(strip_header_whitespace, state, value);
    handler.unexpected_header(name, &value_str)?;
    Ok(())
}

fn handle_message_id_header<H: MessageHandler + ?Sized>(
    _strip_header_whitespace: bool,
    state: &MessageHeaderState,
    handler: &mut H,
    name: &str,
    value: &[u8],
) -> ParseResult<()> {
    let charset = header_charset(state);
    let mut cursor = ByteCursor::new(value);
    if let Some(ids) = MessageIdParser::parse_message_id_list(&mut cursor, charset) {
        if !ids.is_empty() {
            handler.message_id_header(name, &ids)?;
            return Ok(());
        }
    }
    let mut cursor = ByteCursor::new(value);
    if let Some(ids) = ObsoleteParserUtils::parse_obsolete_message_id_list(&mut cursor, charset) {
        handler.obsolete_structure(ObsoleteStructureType::ObsoleteMessageIdSyntax)?;
        handler.message_id_header(name, &ids)?;
        return Ok(());
    }
    let value_str = decode_header_bytes(value, true, true);
    handler.unexpected_header(name, &value_str)?;
    Ok(())
}

fn decode_header_value_with_rfc2047(
    strip_header_whitespace: bool,
    state: &MessageHeaderState,
    value: &[u8],
) -> String {
    let s = Rfc2047Decoder::decode_header_value_smtp_utf8(value, state.smtp_utf8);
    if strip_header_whitespace {
        crate::charset::trim_owned(s)
    } else {
        s
    }
}

fn header_charset(state: &MessageHeaderState) -> HeaderCharset {
    if state.smtp_utf8 {
        HeaderCharset::Utf8
    } else {
        HeaderCharset::Iso88591
    }
}

/// Longest header name [`classify`] matches.
const LOWER_NAME_MAX: usize = 32;

/// Lowercases `name` into `buf` without allocating. A name too long to be
/// any known header is reduced to the empty string, which matches none.
fn lowercase_name<'b>(name: &str, buf: &'b mut [u8; LOWER_NAME_MAX]) -> &'b str {
    let bytes = name.as_bytes();
    if bytes.len() > LOWER_NAME_MAX {
        return "";
    }
    let n = bytes.len();
    for i in 0..n {
        buf[i] = bytes[i].to_ascii_lowercase();
    }
    // Names are printable ASCII (validated by the parser); anything else
    // simply matches nothing.
    std::str::from_utf8(&buf[..n]).unwrap_or("")
}
