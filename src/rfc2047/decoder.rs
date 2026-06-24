//! RFC 2047 encoded-word decoder.

use crate::buffer::ByteCursor;
use crate::charset::{self, HeaderCharset, base64};

/// RFC 2047 encoded-word decoder.
pub struct Decoder;

impl Decoder {
    pub fn decode_header_value(bytes: &[u8]) -> String {
        Self::decode_header_value_smtp_utf8(bytes, false)
    }

    pub fn decode_header_value_smtp_utf8(bytes: &[u8], smtp_utf8: bool) -> String {
        if bytes.is_empty() {
            return String::new();
        }
        if smtp_utf8 {
            if let Ok(as_utf8) = std::str::from_utf8(bytes) {
                if !contains_replacement_char(as_utf8) {
                    let decoded = Self::decode_encoded_words(as_utf8);
                    return handle_raw_8bit_data(&decoded, true);
                }
            }
        }
        let raw = charset::decode_bytes(bytes, HeaderCharset::Iso88591);
        let decoded = Self::decode_encoded_words(&raw);
        handle_raw_8bit_data(&decoded, smtp_utf8)
    }

    pub fn decode_header_value_str(header_value: &str) -> String {
        Self::decode_header_value_str_smtp_utf8(header_value, false)
    }

    pub fn decode_header_value_str_smtp_utf8(header_value: &str, smtp_utf8: bool) -> String {
        if header_value.is_empty() {
            return header_value.to_string();
        }
        let decoded = Self::decode_encoded_words(header_value);
        handle_raw_8bit_data(&decoded, smtp_utf8)
    }

    pub fn decode_encoded_words(input: &str) -> String {
        if input.is_empty() {
            return input.to_string();
        }

        let mut result = String::new();
        let mut adjacent_words: Vec<EncodedWord<'_>> = Vec::new();
        let mut pos = 0usize;
        let mut last_end = 0usize;
        let mut parser = EncodedWordParser::default();

        while parser.find_next(input, pos) {
            if parser.start > last_end {
                let before = &input[last_end..parser.start];
                if !adjacent_words.is_empty() {
                    result.push_str(&decode_adjacent_encoded_words(&adjacent_words));
                    adjacent_words.clear();
                    if !is_whitespace_only(before) {
                        result.push_str(before);
                    }
                } else {
                    result.push_str(before);
                }
            }

            let word = EncodedWord {
                charset: &input[parser.charset_start..parser.charset_end],
                encoding: parser.encoding,
                encoded_text: &input[parser.text_start..parser.text_end],
                start: parser.start,
                end: parser.end,
            };

            if adjacent_words.is_empty()
                || is_adjacent(input, adjacent_words.last().unwrap(), &word)
            {
                adjacent_words.push(word);
            } else {
                result.push_str(&decode_adjacent_encoded_words(&adjacent_words));
                adjacent_words.clear();
                adjacent_words.push(word);
            }

            last_end = parser.end;
            pos = parser.end;
        }

        if !adjacent_words.is_empty() {
            result.push_str(&decode_adjacent_encoded_words(&adjacent_words));
        }
        if last_end < input.len() {
            result.push_str(&input[last_end..]);
        }
        result
    }

    pub fn decode_unstructured_header_value(
        value: &mut ByteCursor<'_>,
        charset: HeaderCharset,
        strip: bool,
    ) -> String {
        if !value.has_remaining() {
            value.consume_to_limit();
            return String::new();
        }
        let stop = value.limit();
        let mut pos = value.position();
        let mut out = String::new();
        while pos < stop {
            let fold = find_next_fold(value.bytes(), pos, stop);
            let segment_end = fold.unwrap_or(stop);
            if segment_end > pos {
                let segment = decode_buffer_segment(value.bytes(), pos, segment_end, charset);
                if !segment.is_empty() {
                    if !out.is_empty() {
                        out.push(' ');
                    }
                    out.push_str(&segment);
                }
            }
            if fold.is_none() {
                break;
            }
            pos = skip_fold(value.bytes(), fold.unwrap(), stop);
        }
        let mut decoded = Self::decode_encoded_words(&out);
        if strip {
            decoded = decoded.trim().to_string();
        }
        value.consume_to_limit();
        decoded
    }

    pub fn decode_display_name(
        input: &mut ByteCursor<'_>,
        charset: HeaderCharset,
        stop_bytes: &[u8],
    ) -> String {
        if !input.has_remaining() {
            return String::new();
        }
        let start = input.position();
        let end = find_phrase_end(input.bytes(), start, input.limit(), stop_bytes);
        if end <= start {
            return String::new();
        }
        let raw = decode_buffer_segment(input.bytes(), start, end, charset);
        let mut decoded = Self::decode_encoded_words(&raw);
        if decoded.len() >= 2
            && decoded.starts_with('"')
            && decoded.ends_with('"')
        {
            decoded = decoded[1..decoded.len() - 1].to_string();
        }
        input.set_position(end);
        decoded.trim().to_string()
    }

    pub fn decode_parameter_value(input: &mut ByteCursor<'_>, charset: HeaderCharset) -> String {
        if !input.has_remaining() {
            return String::new();
        }
        let start = input.position();
        let limit = input.limit();
        let end = if input.get(start) == b'"' {
            let mut pos = start + 1;
            while pos < limit {
                let b = input.get(pos);
                if b == b'\\' && pos + 1 < limit {
                    pos += 2;
                    continue;
                }
                if b == b'"' {
                    pos += 1;
                    break;
                }
                pos += 1;
            }
            pos
        } else {
            let mut pos = start;
            while pos < limit {
                let b = input.get(pos);
                if matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b';' | b'"') {
                    break;
                }
                pos += 1;
            }
            pos
        };
        let quoted = input.get(start) == b'"';
        let value_start = if quoted { start + 1 } else { start };
        let value_end = if quoted && end > start { end - 1 } else { end };
        let raw = decode_buffer_segment(input.bytes(), value_start, value_end, charset);
        let decoded = Self::decode_encoded_words(&raw);
        input.set_position(end);
        decoded.trim().to_string()
    }

    pub fn decode_rfc2231_parameter(param_value: &str) -> Option<String> {
        if param_value.is_empty() {
            return Some(param_value.to_string());
        }
        let parsed = parse_rfc2231_parameter(param_value)?;
        let raw = charset::percent_decode(parsed.encoded.as_bytes());
        Some(charset::decode_bytes_named(&raw, &parsed.charset))
    }
}

#[derive(Default)]
struct EncodedWordParser {
    start: usize,
    end: usize,
    charset_start: usize,
    charset_end: usize,
    encoding: char,
    text_start: usize,
    text_end: usize,
}

impl EncodedWordParser {
    fn find_next(&mut self, input: &str, start_pos: usize) -> bool {
        let bytes = input.as_bytes();
        let mut pos = start_pos;
        while pos + 1 < bytes.len() {
            if bytes[pos] == b'=' && bytes[pos + 1] == b'?' {
                break;
            }
            pos += 1;
        }
        if pos + 1 >= bytes.len() {
            return false;
        }
        self.start = pos;
        pos += 2;
        let charset_start = pos;
        while pos < bytes.len() && bytes[pos] != b'?' {
            pos += 1;
        }
        if pos >= bytes.len() {
            return false;
        }
        self.charset_start = charset_start;
        self.charset_end = pos;
        pos += 1;
        if pos >= bytes.len() {
            return false;
        }
        let enc = bytes[pos] as char;
        if !matches!(enc, 'B' | 'b' | 'Q' | 'q') {
            return false;
        }
        self.encoding = enc.to_ascii_uppercase();
        pos += 1;
        if pos >= bytes.len() || bytes[pos] != b'?' {
            return false;
        }
        pos += 1;
        let text_start = pos;
        while pos + 1 < bytes.len() {
            if bytes[pos] == b'?' && bytes[pos + 1] == b'=' {
                break;
            }
            pos += 1;
        }
        if pos + 1 >= bytes.len() {
            return false;
        }
        self.text_start = text_start;
        self.text_end = pos;
        self.end = pos + 2;
        true
    }
}

struct EncodedWord<'a> {
    charset: &'a str,
    encoding: char,
    encoded_text: &'a str,
    start: usize,
    end: usize,
}

fn decode_adjacent_encoded_words(words: &[EncodedWord<'_>]) -> String {
    let mut result = String::new();
    for word in words {
        match decode_single_encoded_word(word.charset, word.encoding, word.encoded_text) {
            Ok(decoded) => result.push_str(&decoded),
            Err(_) => {
                result.push_str("=?");
                result.push_str(word.charset);
                result.push('?');
                result.push(word.encoding);
                result.push('?');
                result.push_str(word.encoded_text);
                result.push_str("?=");
            }
        }
    }
    result
}

fn decode_single_encoded_word(
    charset: &str,
    encoding: char,
    encoded_text: &str,
) -> Result<String, ()> {
    let decoded_bytes = if encoding == 'B' {
        if !base64::is_valid(encoded_text) {
            return Err(());
        }
        base64::decode(encoded_text)?
    } else if encoding == 'Q' {
        decode_q_encoding(encoded_text)?
    } else {
        return Err(());
    };
    Ok(charset::decode_bytes_named(
        &decoded_bytes,
        charset,
    ))
}

fn decode_q_encoding(encoded: &str) -> Result<Vec<u8>, ()> {
    let mut result = Vec::with_capacity(encoded.len());
    let chars: Vec<char> = encoded.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '_' {
            result.push(b' ');
            i += 1;
        } else if c == '=' && i + 2 < chars.len() {
            let h1 = chars[i + 1];
            let h2 = chars[i + 2];
            if let Some(value) = fast_hex_decode(h1, h2) {
                result.push(value);
                i += 3;
            } else {
                result.push(c as u8);
                i += 1;
            }
        } else {
            result.push(c as u8);
            i += 1;
        }
    }
    Ok(result)
}

fn fast_hex_decode(h1: char, h2: char) -> Option<u8> {
    let v1 = charset::hex_value(h1 as u8)?;
    let v2 = charset::hex_value(h2 as u8)?;
    Some((v1 << 4) | v2)
}

fn is_adjacent(input: &str, prev: &EncodedWord<'_>, current: &EncodedWord<'_>) -> bool {
    if prev.end >= current.start {
        return false;
    }
    input[prev.end..current.start]
        .chars()
        .all(is_whitespace)
}

fn is_whitespace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

fn is_whitespace_only(text: &str) -> bool {
    text.chars().all(is_whitespace)
}

fn handle_raw_8bit_data(input: &str, smtp_utf8: bool) -> String {
    if !has_non_ascii_data(input) {
        return input.to_string();
    }
    if input.chars().any(|c| c > '\u{00FF}') {
        return input.to_string();
    }
    let bytes: Vec<u8> = input.chars().map(|c| c as u8).collect();
    if smtp_utf8 {
        if let Ok(utf8) = std::str::from_utf8(&bytes) {
            if !contains_replacement_char(utf8) {
                return utf8.to_string();
            }
        }
        return charset::decode_bytes(&bytes, HeaderCharset::Iso88591);
    }
    if let Ok(utf8) = std::str::from_utf8(&bytes) {
        if !contains_replacement_char(utf8) {
            return utf8.to_string();
        }
    }
    charset::decode_bytes_named(&bytes, "windows-1252")
}

fn has_non_ascii_data(input: &str) -> bool {
    input.chars().any(|c| c == '\0' || c > '\u{007F}')
}

fn contains_replacement_char(s: &str) -> bool {
    s.contains('\u{FFFD}')
}

fn find_next_fold(bytes: &[u8], from: usize, stop: usize) -> Option<usize> {
    let mut pos = from;
    while pos < stop {
        let b = bytes[pos];
        if b == b'\r'
            && pos + 2 <= stop
            && bytes[pos + 1] == b'\n'
            && pos + 2 < stop
            && matches!(bytes[pos + 2], b' ' | b'\t')
        {
            return Some(pos);
        }
        if b == b'\n' && pos + 1 < stop && matches!(bytes[pos + 1], b' ' | b'\t') {
            return Some(pos);
        }
        pos += 1;
    }
    None
}

fn skip_fold(bytes: &[u8], fold_start: usize, limit: usize) -> usize {
    if fold_start + 2 <= limit
        && bytes[fold_start] == b'\r'
        && bytes[fold_start + 1] == b'\n'
    {
        return fold_start + 2;
    }
    if fold_start + 1 < limit && bytes[fold_start] == b'\n' {
        return fold_start + 1;
    }
    fold_start + 1
}

fn decode_buffer_segment(bytes: &[u8], start: usize, end: usize, charset: HeaderCharset) -> String {
    if start >= end {
        return String::new();
    }
    charset::decode_bytes(&bytes[start..end], charset).trim().to_string()
}

fn find_phrase_end(bytes: &[u8], from: usize, limit: usize, stop_bytes: &[u8]) -> usize {
    let mut pos = from;
    while pos < limit {
        let b = bytes[pos];
        if b == b'"' {
            pos += 1;
            while pos < limit {
                let q = bytes[pos];
                if q == b'\\' && pos + 1 < limit {
                    pos += 2;
                    continue;
                }
                if q == b'"' {
                    pos += 1;
                    break;
                }
                pos += 1;
            }
            continue;
        }
        if stop_bytes.contains(&b) {
            return pos;
        }
        pos += 1;
    }
    pos
}

struct Rfc2231ParseResult {
    charset: String,
    encoded: String,
}

fn parse_rfc2231_parameter(param_value: &str) -> Option<Rfc2231ParseResult> {
    let star_eq = param_value.find("*=")?;
    if star_eq == 0 {
        return None;
    }
    let mut pos = star_eq + 2;
    let charset_start = pos;
    while pos < param_value.len() && param_value.as_bytes()[pos] != b'\'' {
        pos += 1;
    }
    if pos >= param_value.len() {
        return None;
    }
    let charset = param_value[charset_start..pos].to_string();
    pos += 1;
    while pos < param_value.len() && param_value.as_bytes()[pos] != b'\'' {
        pos += 1;
    }
    if pos >= param_value.len() {
        return None;
    }
    pos += 1;
    let encoded = param_value[pos..].to_string();
    Some(Rfc2231ParseResult { charset, encoded })
}
