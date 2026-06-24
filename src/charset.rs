//! Charset decoding helpers (std-only).

use crate::buffer::ByteCursor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderCharset {
    Iso88591,
    Utf8,
}

impl HeaderCharset {
    pub fn from_name(name: &str) -> Self {
        let normalized = normalize_charset_name(name);
        if normalized.eq_ignore_ascii_case("UTF-8") {
            Self::Utf8
        } else {
            Self::Iso88591
        }
    }
}

pub fn normalize_charset_name(charset: &str) -> String {
    let trimmed = charset.trim();
    match trimmed.to_ascii_uppercase().as_str() {
        "UTF8" | "UTF-8" => "UTF-8".to_string(),
        "WIN1252" | "WINDOWS1252" => "windows-1252".to_string(),
        "LATIN1" | "ISO88591" | "ISO-88591" | "ISO-8859-1" => "ISO-8859-1".to_string(),
        "ISO885915" | "ISO-885915" | "ISO-8859-15" => "ISO-8859-15".to_string(),
        "KOI8R" | "KOI8-R" => "KOI8-R".to_string(),
        "KOI8U" | "KOI8-U" => "KOI8-U".to_string(),
        _ => trimmed.to_string(),
    }
}

/// Decode `[position, limit)` and advance position to limit.
pub fn decode_slice(cursor: &mut ByteCursor<'_>, charset: HeaderCharset) -> String {
    let bytes = cursor.slice().to_vec();
    cursor.consume_to_limit();
    decode_bytes(&bytes, charset).trim().to_string()
}

pub fn decode_bytes(bytes: &[u8], charset: HeaderCharset) -> String {
    match charset {
        HeaderCharset::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        HeaderCharset::Iso88591 => bytes_to_iso88591(bytes),
    }
}

pub fn decode_bytes_named(bytes: &[u8], charset_name: &str) -> String {
    let name = normalize_charset_name(charset_name);
    if name.eq_ignore_ascii_case("UTF-8") {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    if name.eq_ignore_ascii_case("windows-1252") {
        return bytes_to_windows1252(bytes);
    }
    if name.eq_ignore_ascii_case("ISO-8859-1") {
        return bytes_to_iso88591(bytes);
    }
    // Fallback chain matching gumdrop behaviour.
    if let Ok(s) = std::str::from_utf8(bytes) {
        if !s.contains('\u{FFFD}') {
            return s.to_string();
        }
    }
    bytes_to_iso88591(bytes)
}

fn bytes_to_iso88591(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

fn bytes_to_windows1252(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| WINDOWS_1252[b as usize])
        .collect()
}

const WINDOWS_1252: [char; 256] = {
    let mut table = [0u8 as char; 256];
    let mut i = 0usize;
    while i < 256 {
        table[i] = if i < 0x80 || i >= 0xA0 {
            i as u8 as char
        } else {
            match i {
                0x80 => '\u{20AC}',
                0x82 => '\u{201A}',
                0x83 => '\u{0192}',
                0x84 => '\u{201E}',
                0x85 => '\u{2026}',
                0x86 => '\u{2020}',
                0x87 => '\u{2021}',
                0x88 => '\u{02C6}',
                0x89 => '\u{2030}',
                0x8A => '\u{0160}',
                0x8B => '\u{2039}',
                0x8C => '\u{0152}',
                0x8E => '\u{017D}',
                0x91 => '\u{2018}',
                0x92 => '\u{2019}',
                0x93 => '\u{201C}',
                0x94 => '\u{201D}',
                0x95 => '\u{2022}',
                0x96 => '\u{2013}',
                0x97 => '\u{2014}',
                0x98 => '\u{02DC}',
                0x99 => '\u{2122}',
                0x9A => '\u{0161}',
                0x9B => '\u{203A}',
                0x9C => '\u{0153}',
                0x9E => '\u{017E}',
                0x9F => '\u{0178}',
                _ => i as u8 as char,
            }
        };
        i += 1;
    }
    table
};

pub fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

pub fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

pub mod base64 {
    pub fn decode(input: &str) -> Result<Vec<u8>, ()> {
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0u32;
        for &b in input.as_bytes() {
            if b == b'=' {
                break;
            }
            let val = decode_char(b).ok_or(())?;
            buf = (buf << 6) | val as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
        Ok(out)
    }

    pub fn encode(data: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        let mut i = 0;
        while i < data.len() {
            let b0 = data[i] as u32;
            let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
            let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
            out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
            if i + 1 < data.len() {
                out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
            if i + 2 < data.len() {
                out.push(TABLE[(triple & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
            i += 3;
        }
        out
    }

    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    pub fn is_valid(input: &str) -> bool {
        if input.is_empty() {
            return true;
        }
        if input.len() % 4 != 0 {
            return false;
        }
        let mut padding = 0usize;
        for (i, &c) in input.as_bytes().iter().enumerate() {
            if c == b'=' {
                padding += 1;
                if i < input.len() - 2 || padding > 2 {
                    return false;
                }
            } else if !is_base64_char(c) {
                return false;
            } else if padding > 0 {
                return false;
            }
        }
        true
    }

    fn is_base64_char(c: u8) -> bool {
        matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/')
    }
}
