//! MIME Content-Type parser.

use std::collections::{BTreeMap, HashMap};

use crate::buffer::{index_of, ByteCursor};
use crate::charset::{decode_slice, HeaderCharset};
use crate::rfc2047::Decoder as Rfc2047Decoder;
use crate::rfc2231::Decoder as Rfc2231Decoder;

use super::content_types::ContentType;
use super::parameter::Parameter;
use super::utils::is_token;

pub struct ContentTypeParser;

impl ContentTypeParser {
    pub fn parse(value: &mut ByteCursor<'_>, charset: HeaderCharset) -> Option<ContentType> {
        if value.remaining() < 3 {
            return None;
        }
        let start = value.position();
        let end = value.limit();
        let semicolon = index_of(value, b';');
        let type_end = semicolon.unwrap_or(end);
        let slash = {
            let mut cursor = value.duplicate();
            cursor.set_position(start);
            index_of(&cursor, b'/')
        }?;
        if slash >= type_end {
            return None;
        }
        let mut primary_cursor = ByteCursor::from_slice(value.bytes(), start, slash);
        let primary = decode_slice(&mut primary_cursor, charset);
        let mut sub_cursor = ByteCursor::from_slice(value.bytes(), slash + 1, type_end);
        let sub = decode_slice(&mut sub_cursor, charset);
        if !is_token(&primary) || !is_token(&sub) {
            return None;
        }
        let params_start = semicolon.map(|s| s + 1).unwrap_or(end);
        let mut params_cursor = ByteCursor::from_slice(value.bytes(), params_start, end);
        let parameters = parse_parameter_list(&mut params_cursor, charset);
        value.set_position(end);
        Some(ContentType::new(primary, sub, parameters))
    }

    pub fn parse_str(value: &str) -> Option<ContentType> {
        if value.trim().is_empty() {
            return None;
        }
        let mut cursor = ByteCursor::new(value.as_bytes());
        Self::parse(&mut cursor, HeaderCharset::Iso88591)
    }
}

pub struct ContentDispositionParser;

impl ContentDispositionParser {
    pub fn parse(value: &mut ByteCursor<'_>, charset: HeaderCharset) -> Option<super::content_types::ContentDisposition> {
        if value.remaining() < 1 {
            return None;
        }
        let start = value.position();
        let end = value.limit();
        let semicolon = index_of(value, b';');
        let type_end = semicolon.unwrap_or(end);
        let mut type_cursor = ByteCursor::from_slice(value.bytes(), start, type_end);
        let disposition_type = decode_slice(&mut type_cursor, charset);
        if !is_token(&disposition_type) {
            return None;
        }
        let params_start = semicolon.map(|s| s + 1).unwrap_or(end);
        let mut params_cursor = ByteCursor::from_slice(value.bytes(), params_start, end);
        let parameters = parse_parameter_list(&mut params_cursor, charset);
        value.set_position(end);
        Some(super::content_types::ContentDisposition::new(
            disposition_type,
            parameters,
        ))
    }

    pub fn parse_str(value: &str) -> Option<super::content_types::ContentDisposition> {
        if value.trim().is_empty() {
            return None;
        }
        let mut cursor = ByteCursor::new(value.as_bytes());
        Self::parse(&mut cursor, HeaderCharset::Iso88591)
    }
}

struct RawParamSlice {
    name: String,
    value_start: usize,
    value_end: usize,
    quoted: bool,
}

pub(crate) fn parse_parameter_list(
    value: &mut ByteCursor<'_>,
    charset: HeaderCharset,
) -> Option<Vec<Parameter>> {
    let params_end = value.limit();
    if !value.has_remaining() {
        return None;
    }
    let bytes = value.bytes();
    let mut raw_params = Vec::new();

    while value.position() < params_end {
        skip_ows(value, params_end);
        if value.position() >= params_end {
            break;
        }
        let pos = value.position();
        let Some(equals_index) = index_of(value, b'=') else {
            break;
        };
        if equals_index < pos + 1 {
            let next_semi = index_of(value, b';').unwrap_or(params_end);
            value.set_position(if next_semi >= params_end {
                params_end
            } else {
                next_semi
            });
            continue;
        }
        let mut name_cursor = ByteCursor::from_slice(bytes, pos, equals_index);
        let name = decode_slice(&mut name_cursor, charset);
        value.set_position(equals_index + 1);
        if !is_token(&name) {
            let next_semi = index_of(value, b';').unwrap_or(params_end);
            value.set_position(if next_semi >= params_end {
                params_end
            } else {
                next_semi
            });
            continue;
        }

        let value_start = value.position();
        let (value_end, quoted) = if value_start < params_end && bytes[value_start] == b'"' {
            let Some(quote_end) = find_quoted_value_end(bytes, value_start, params_end) else {
                break;
            };
            value.set_position(quote_end);
            (quote_end, true)
        } else {
            let semicolon_idx = index_of(value, b';').unwrap_or(params_end);
            value.set_position(semicolon_idx);
            let trimmed_start = skip_ows_forward(bytes, value_start, semicolon_idx);
            let trimmed_end = skip_ows_backward(bytes, trimmed_start, semicolon_idx);
            (trimmed_end.max(trimmed_start), false)
        };

        raw_params.push(RawParamSlice {
            name,
            value_start: if quoted {
                value_start + 1
            } else {
                skip_ows_forward(bytes, value_start, value_end)
            },
            value_end: if quoted && value_end > value_start + 1 {
                value_end - 1
            } else {
                value_end
            },
            quoted,
        });
    }

    value.set_position(params_end);
    process_raw_params(bytes, raw_params, charset)
}

fn process_raw_params(
    buf: &[u8],
    raw_params: Vec<RawParamSlice>,
    charset: HeaderCharset,
) -> Option<Vec<Parameter>> {
    if raw_params.is_empty() {
        return None;
    }

    let mut rfc2231_decoded: HashMap<String, String> = HashMap::new();
    let mut continuation_ranges: HashMap<String, BTreeMap<usize, (usize, usize)>> =
        HashMap::new();

    for r in &raw_params {
        let name = &r.name;
        if let Some(star_idx) = name.find('*') {
            let after = &name[star_idx + 1..];
            if !after.is_empty() && after.chars().all(|c| c.is_ascii_digit()) {
                let base_name = name[..star_idx].to_string();
                let index: usize = after.parse().unwrap_or(0);
                continuation_ranges
                    .entry(base_name)
                    .or_default()
                    .insert(index, (r.value_start, r.value_end));
                continue;
            }
        }
        if name.ends_with('*') && name.len() > 1 {
            let base_name = name[..name.len() - 1].to_string();
            let mut slice = ByteCursor::from_slice(buf, r.value_start, r.value_end);
            if let Some(decoded) = Rfc2231Decoder::decode_parameter_value(&mut slice, charset) {
                rfc2231_decoded.insert(base_name, decoded);
            }
        }
    }

    for (base_name, parts) in &continuation_ranges {
        if rfc2231_decoded.contains_key(base_name) {
            continue;
        }
        let mut combined = Vec::new();
        for (_, (start, end)) in parts {
            combined.extend_from_slice(&buf[*start..*end]);
        }
        let mut combined_buf = ByteCursor::new(&combined);
        if let Some(decoded) = Rfc2231Decoder::decode_parameter_value(&mut combined_buf, charset)
        {
            rfc2231_decoded.insert(base_name.clone(), decoded);
        }
    }

    let mut parameters = Vec::new();
    let mut seen: HashMap<String, ()> = HashMap::new();

    for r in &raw_params {
        let base_name = get_base_param_name(&r.name);
        if seen.contains_key(&base_name) {
            continue;
        }
        let final_value = if let Some(v) = rfc2231_decoded.get(&base_name) {
            v.clone()
        } else if r.quoted {
            let unescaped = unescape_quoted_value(buf, r.value_start, r.value_end);
            let mut slice = ByteCursor::new(&unescaped);
            let raw = decode_slice(&mut slice, charset);
            Rfc2047Decoder::decode_encoded_words(&raw)
        } else {
            let mut slice = ByteCursor::from_slice(buf, r.value_start, r.value_end);
            Rfc2047Decoder::decode_parameter_value(&mut slice, charset)
        };
        seen.insert(base_name.clone(), ());
        parameters.push(Parameter::new(base_name, final_value));
    }

    if parameters.is_empty() {
        None
    } else {
        Some(parameters)
    }
}

fn get_base_param_name(name: &str) -> String {
    if name.ends_with('*') && name.len() > 1 {
        let star_idx = name.find('*').unwrap_or(name.len());
        if star_idx == name.len() - 1 {
            return name[..name.len() - 1].to_string();
        }
    }
    if let Some(star_idx) = name.find('*') {
        let after = &name[star_idx + 1..];
        if !after.is_empty() && after.chars().all(|c| c.is_ascii_digit()) {
            return name[..star_idx].to_string();
        }
    }
    name.to_string()
}

fn unescape_quoted_value(buf: &[u8], start: usize, end: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(end - start);
    let mut i = start;
    while i < end {
        if buf[i] == b'\\' && i + 1 < end {
            out.push(buf[i + 1]);
            i += 2;
        } else {
            out.push(buf[i]);
            i += 1;
        }
    }
    out
}

fn find_quoted_value_end(buf: &[u8], start: usize, end: usize) -> Option<usize> {
    let mut p = start + 1;
    while p < end {
        let b = buf[p];
        if b == b'\\' && p + 1 < end {
            p += 2;
            continue;
        }
        if b == b'"' {
            return Some(p + 1);
        }
        p += 1;
    }
    None
}

fn skip_ows(value: &mut ByteCursor<'_>, end: usize) {
    while value.position() < end {
        let b = value.get(value.position());
        if b != b';' && !b.is_ascii_whitespace() {
            break;
        }
        value.advance(1);
    }
}

fn skip_ows_forward(buf: &[u8], start: usize, end: usize) -> usize {
    let mut pos = start;
    while pos < end && matches!(buf[pos], b' ' | b'\t') {
        pos += 1;
    }
    pos
}

fn skip_ows_backward(buf: &[u8], start: usize, end: usize) -> usize {
    let mut pos = end;
    while pos > start && matches!(buf[pos - 1], b' ' | b'\t') {
        pos -= 1;
    }
    pos
}
