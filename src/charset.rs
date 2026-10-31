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
    let decoded = decode_bytes(cursor.slice(), charset);
    cursor.consume_to_limit();
    trim_owned(decoded)
}

/// `s.trim()` as an owned string, reusing `s`'s allocation.
pub(crate) fn trim_owned(mut s: String) -> String {
    let trimmed = s.trim();
    if trimmed.len() == s.len() {
        return s;
    }
    let end = trimmed.as_ptr() as usize - s.as_ptr() as usize + trimmed.len();
    let start = end - trimmed.len();
    s.truncate(end);
    s.drain(..start);
    s
}

pub fn decode_bytes(bytes: &[u8], charset: HeaderCharset) -> String {
    match charset {
        HeaderCharset::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        HeaderCharset::Iso88591 => bytes_to_iso88591(bytes),
    }
}

enum NamedCharset {
    Utf8,
    Windows1252,
    Latin1,
    Other,
}

/// The charsets [`normalize_charset_name`] folds together, recognised
/// without building the normalised name.
fn named_charset(name: &str) -> NamedCharset {
    let name = name.trim();
    let is = |candidates: &[&str]| candidates.iter().any(|c| name.eq_ignore_ascii_case(c));
    if is(&["utf8", "utf-8"]) {
        NamedCharset::Utf8
    } else if is(&["win1252", "windows1252", "windows-1252"]) {
        NamedCharset::Windows1252
    } else if is(&["latin1", "iso88591", "iso-88591", "iso-8859-1"]) {
        NamedCharset::Latin1
    } else {
        NamedCharset::Other
    }
}

pub fn decode_bytes_named(bytes: &[u8], charset_name: &str) -> String {
    match named_charset(charset_name) {
        NamedCharset::Utf8 => return String::from_utf8_lossy(bytes).into_owned(),
        NamedCharset::Windows1252 => return bytes_to_windows1252(bytes),
        NamedCharset::Latin1 => return bytes_to_iso88591(bytes),
        NamedCharset::Other => {}
    }
    // Fallback chain matching gumdrop behaviour.
    if let Ok(s) = std::str::from_utf8(bytes) {
        if !s.contains('\u{FFFD}') {
            return s.to_string();
        }
    }
    bytes_to_iso88591(bytes)
}

pub(crate) fn bytes_to_iso88591(bytes: &[u8]) -> String {
    if bytes.is_ascii() {
        // ASCII is already valid UTF-8: one copy.
        if let Ok(s) = std::str::from_utf8(bytes) {
            return s.to_owned();
        }
    }
    let mut out = String::with_capacity(bytes.len() + bytes.len() / 4);
    out.extend(bytes.iter().map(|&b| b as char));
    out
}

fn bytes_to_windows1252(bytes: &[u8]) -> String {
    if bytes.is_ascii() {
        if let Ok(s) = std::str::from_utf8(bytes) {
            return s.to_owned();
        }
    }
    let mut out = String::with_capacity(bytes.len() + bytes.len() / 4);
    out.extend(bytes.iter().map(|&b| WINDOWS_1252[b as usize]));
    out
}

pub(crate) const WINDOWS_1252: [char; 256] = {
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
    use std::fmt;

    /// The text is not valid base64.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Base64Error;

    impl fmt::Display for Base64Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("invalid base64")
        }
    }

    impl std::error::Error for Base64Error {}

    pub fn decode(input: &str) -> Result<Vec<u8>, Base64Error> {
        let mut out = Vec::with_capacity(input.len() / 4 * 3 + 3);
        let mut buf = 0u32;
        let mut bits = 0u32;
        for &b in input.as_bytes() {
            if b == b'=' {
                break;
            }
            let val = decode_char(b).ok_or(Base64Error)?;
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
        let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
        encode_into(data, &mut out);
        out
    }

    /// Appends the padded base64 of `data` to `out`.
    pub fn encode_into(data: &[u8], out: &mut String) {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < data.len() {
            let b0 = data[i] as u32;
            let b1 = if i + 1 < data.len() {
                data[i + 1] as u32
            } else {
                0
            };
            let b2 = if i + 2 < data.len() {
                data[i + 2] as u32
            } else {
                0
            };
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
            } else if !is_base64_char(c) || padding > 0 {
                return false;
            }
        }
        true
    }

    fn is_base64_char(c: u8) -> bool {
        matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pre-optimisation behaviour: normalise the name, then compare.
    fn reference_decode_named(bytes: &[u8], charset_name: &str) -> String {
        let name = normalize_charset_name(charset_name);
        if name.eq_ignore_ascii_case("UTF-8") {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        if name.eq_ignore_ascii_case("windows-1252") {
            return bytes_to_windows1252(bytes);
        }
        if name.eq_ignore_ascii_case("ISO-8859-1") {
            return bytes.iter().map(|&b| b as char).collect();
        }
        if let Ok(s) = std::str::from_utf8(bytes) {
            if !s.contains('\u{FFFD}') {
                return s.to_string();
            }
        }
        bytes.iter().map(|&b| b as char).collect()
    }

    #[test]
    fn charset_names_resolve_as_before() {
        let samples: [&[u8]; 4] = [b"plain", b"caf\xc3\xa9", b"caf\xe9 \x93q\x94", b""];
        let names = [
            "UTF8",
            "utf-8",
            "Utf-8",
            " utf-8 ",
            "WIN1252",
            "windows1252",
            "Windows-1252",
            "windows-1252",
            "LATIN1",
            "latin1",
            "ISO88591",
            "iso-88591",
            "ISO-8859-1",
            "iso-8859-1",
            "ISO-8859-15",
            "KOI8-R",
            "us-ascii",
            "",
            "shift_jis",
        ];
        for name in names {
            for bytes in samples {
                assert_eq!(
                    decode_bytes_named(bytes, name),
                    reference_decode_named(bytes, name),
                    "{name:?} {bytes:?}"
                );
            }
        }
    }

    #[test]
    fn trim_owned_matches_str_trim() {
        let pieces = ["", " ", "a", "\u{a0}", "\u{85}", "\t", "\r\n", "é", " x y "];
        for a in pieces {
            for b in pieces {
                for c in pieces {
                    let s = format!("{a}{b}{c}");
                    assert_eq!(trim_owned(s.clone()), s.trim(), "{s:?}");
                }
            }
        }
    }

    #[test]
    fn latin1_decoding_matches_char_mapping() {
        let all: Vec<u8> = (0..=255u8).collect();
        let reference: String = all.iter().map(|&b| b as char).collect();
        assert_eq!(bytes_to_iso88591(&all), reference);
        assert_eq!(bytes_to_iso88591(b"ascii only"), "ascii only");
    }
}

/// How [`ByteDecoder`] reads the bytes of a named charset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ByteCharset {
    /// UTF-8, an invalid sequence becoming U+FFFD.
    Utf8,
    Windows1252,
    Latin1,
    /// Raw 8-bit header text: UTF-8 where it is valid, windows-1252 where it
    /// is not.
    Utf8OrWindows1252,
    /// Any other charset: UTF-8 where it is valid, ISO-8859-1 where it is not,
    /// as [`decode_bytes_named`] does for the charsets it does not know.
    Utf8OrLatin1,
}

impl ByteCharset {
    pub(crate) fn from_name(name: &str) -> Self {
        match named_charset(name) {
            NamedCharset::Utf8 => Self::Utf8,
            NamedCharset::Windows1252 => Self::Windows1252,
            NamedCharset::Latin1 => Self::Latin1,
            NamedCharset::Other => Self::Utf8OrLatin1,
        }
    }
}

/// Decodes bytes to text in any chunking, holding at most the start of a UTF-8
/// sequence between calls.
#[derive(Debug, Clone)]
pub(crate) struct ByteDecoder {
    charset: ByteCharset,
    carry: [u8; 4],
    carry_len: usize,
    carry_need: usize,
}

impl ByteDecoder {
    pub(crate) fn new(charset: ByteCharset) -> Self {
        Self {
            charset,
            carry: [0; 4],
            carry_len: 0,
            carry_need: 0,
        }
    }

    pub(crate) fn feed(&mut self, bytes: &[u8], out: &mut String) {
        match self.charset {
            ByteCharset::Latin1 => out.extend(bytes.iter().map(|&b| b as char)),
            ByteCharset::Windows1252 => out.extend(bytes.iter().map(|&b| WINDOWS_1252[b as usize])),
            ByteCharset::Utf8 | ByteCharset::Utf8OrLatin1 | ByteCharset::Utf8OrWindows1252 => {
                for &b in bytes {
                    self.utf8_byte(b, out);
                }
            }
        }
    }

    /// Ends the text: an unfinished sequence is invalid.
    pub(crate) fn finish(&mut self, out: &mut String) {
        self.flush_carry(out);
    }

    fn utf8_byte(&mut self, b: u8, out: &mut String) {
        if b < 0x80 {
            self.flush_carry(out);
            out.push(b as char);
            return;
        }
        if self.carry_len == 0 {
            let need = match b {
                0xC2..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF4 => 4,
                _ => {
                    self.invalid(b, out);
                    return;
                }
            };
            self.carry[0] = b;
            self.carry_len = 1;
            self.carry_need = need;
            return;
        }
        if b & 0xC0 != 0x80 {
            self.flush_carry(out);
            self.utf8_byte(b, out);
            return;
        }
        self.carry[self.carry_len] = b;
        self.carry_len += 1;
        if self.carry_len == self.carry_need {
            let bytes = self.carry;
            let n = self.carry_len;
            match std::str::from_utf8(&bytes[..n]) {
                Ok(s) => {
                    self.carry_len = 0;
                    out.push_str(s);
                }
                Err(_) => self.flush_carry(out),
            }
        }
    }

    /// A byte that is not UTF-8: U+FFFD or, for other charsets, ISO-8859-1.
    fn invalid(&self, b: u8, out: &mut String) {
        out.push(match self.charset {
            ByteCharset::Utf8 => '\u{FFFD}',
            ByteCharset::Utf8OrWindows1252 => WINDOWS_1252[b as usize],
            _ => b as char,
        });
    }

    fn flush_carry(&mut self, out: &mut String) {
        let bytes = self.carry;
        let n = self.carry_len;
        self.carry_len = 0;
        for &b in &bytes[..n] {
            self.invalid(b, out);
        }
    }
}

/// The text of a header element read whole: raw 8-bit bytes are UTF-8 where they
/// are valid and otherwise windows-1252, or ISO-8859-1 with `utf8_headers`.
/// ASCII, which is nearly all of it, is borrowed.
pub(crate) fn decode_header_element(bytes: &[u8], utf8_headers: bool) -> std::borrow::Cow<'_, str> {
    if bytes.is_ascii() {
        if let Ok(s) = std::str::from_utf8(bytes) {
            return std::borrow::Cow::Borrowed(s);
        }
    }
    let mut out = String::with_capacity(bytes.len() + 8);
    let mut decoder = ByteDecoder::new(if utf8_headers {
        ByteCharset::Utf8OrLatin1
    } else {
        ByteCharset::Utf8OrWindows1252
    });
    decoder.feed(bytes, &mut out);
    decoder.finish(&mut out);
    std::borrow::Cow::Owned(out)
}
