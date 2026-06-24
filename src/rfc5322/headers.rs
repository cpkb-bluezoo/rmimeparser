//! RFC 5322 structured header dispatch (used by MIME parser).

use crate::buffer::ByteCursor;
use crate::charset::HeaderCharset;
use crate::mime::error::ParseResult;
use crate::mime::parser::MessageHeaderState;
use crate::mime::utils::{decode_header_bytes, decode_token_header_value};
use crate::rfc2047::Decoder as Rfc2047Decoder;
use crate::rfc5322::email_address::EmailAddress;
use crate::rfc5322::email_address_parser::EmailAddressParser;
use crate::rfc5322::group_email_address::Address;
use crate::rfc5322::message_date_time::MessageDateTimeFormatter;
use crate::rfc5322::message_handler::MessageHandler;
use crate::rfc5322::message_id_parser::MessageIdParser;
use crate::rfc5322::obsolete_parser_utils::ObsoleteParserUtils;
use crate::rfc5322::obsolete_structure_type::ObsoleteStructureType;

pub fn dispatch_rfc5322_header<H: MessageHandler + ?Sized>(
    strip_header_whitespace: bool,
    state: &mut MessageHeaderState,
    handler: &mut H,
    name: &str,
    value: &mut Vec<u8>,
) -> ParseResult<bool> {
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "content-type"
        | "content-disposition"
        | "content-transfer-encoding"
        | "content-id"
        | "content-description"
        | "mime-version" => Ok(false),
        "date" | "resent-date" => {
            handle_date_header(state, handler, name, value)?;
            Ok(true)
        }
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
        |         "apparently-to" => {
            handle_address_header(strip_header_whitespace, state, handler, name, value)?;
            Ok(true)
        }
        "message-id" | "in-reply-to" | "references" | "resent-message-id" => {
            handle_message_id_header(strip_header_whitespace, state, handler, name, value)?;
            Ok(true)
        }
        "received" => {
            let value_str = decode_header_value_with_rfc2047(strip_header_whitespace, state, value);
            handler.header(name, &value_str)?;
            Ok(true)
        }
        _ if is_unstructured_header(&lower) => {
            let value_str = decode_header_value_with_rfc2047(strip_header_whitespace, state, value);
            handler.header(name, &value_str)?;
            Ok(true)
        }
        _ => Ok(false),
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
    if let Some(list) = EmailAddressParser::parse_email_address_list_bytes(&mut cursor, charset) {
        let mailboxes = flatten_addresses(list);
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
        s.trim().to_string()
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

fn is_unstructured_header(lower_name: &str) -> bool {
    matches!(lower_name, "subject" | "comments" | "keywords" | "received")
        || lower_name.starts_with("x-")
}

fn flatten_addresses(list: Vec<Address>) -> Vec<EmailAddress> {
    let mut out = Vec::new();
    for addr in list {
        match addr {
            Address::Mailbox(m) => out.push(m),
            Address::Group(g) => out.extend(g.members().iter().cloned()),
        }
    }
    out
}
