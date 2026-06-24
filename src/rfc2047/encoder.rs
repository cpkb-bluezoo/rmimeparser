//! RFC 2047 encoded-word encoder.

use crate::charset::{self, base64, HeaderCharset};
use crate::rfc2047::decoder::Decoder;

/// RFC 2047 §2 — an encoded-word MUST NOT be more than 75 characters long.
pub const MAX_ENCODED_WORD_LENGTH: usize = 75;

/// RFC 2047 encoded-word encoder.
pub struct Encoder;

impl Encoder {
    pub fn contains_non_ascii(header: &[u8]) -> bool {
        Self::contains_non_ascii_range(header, 0, header.len())
    }

    pub fn contains_non_ascii_range(header: &[u8], start: usize, end: usize) -> bool {
        header[start..end].iter().any(|&b| b > 127)
    }

    pub fn encoding_for_data(data: &[u8]) -> char {
        Self::encoding_for_data_range(data, 0, data.len())
    }

    pub fn encoding_for_data_range(data: &[u8], start: usize, end: usize) -> char {
        let total = end - start;
        if total == 0 {
            return 'B';
        }
        let mut bytes_needing_encoding = 0usize;
        for &b in &data[start..end] {
            let b = b as u32;
            if b > 127 || b < 32 || b == b'?' as u32 || b == b'=' as u32 || b == b'_' as u32 {
                bytes_needing_encoding += 1;
            }
        }
        if bytes_needing_encoding * 6 < total {
            'Q'
        } else {
            'B'
        }
    }

    pub fn encode_header_value(header_value: &[u8], charset: &str) -> String {
        let encoding = Self::encoding_for_data(header_value);
        Self::encode_with_charset(header_value, charset, encoding)
    }

    fn encode_with_charset(header: &[u8], charset: &str, encoding: char) -> String {
        if encoding == 'Q' {
            Self::encode_q(header, charset)
        } else {
            Self::encode_b(header, charset)
        }
    }

    pub fn encode_b(header: &[u8], charset: &str) -> String {
        Self::encode_b_range(header, 0, header.len(), charset)
    }

    pub fn encode_b_range(header: &[u8], start: usize, end: usize, charset: &str) -> String {
        let overhead = 2 + charset.len() + 3 + 2;
        let max_base64_chars = MAX_ENCODED_WORD_LENGTH.saturating_sub(overhead);
        let mut max_raw_bytes = (max_base64_chars / 4) * 3;
        if max_raw_bytes == 0 {
            max_raw_bytes = 1;
        }

        let mut result = String::new();
        let mut i = start;
        while i < end {
            let mut segment_start = i;
            while segment_start < end && header[segment_start] <= 127 {
                segment_start += 1;
            }
            if segment_start > i {
                result.push_str(&charset::decode_bytes(
                    &header[i..segment_start],
                    HeaderCharset::Iso88591,
                ));
                i = segment_start;
            }
            if i >= end {
                break;
            }
            let mut segment_end = i;
            while segment_end < end {
                if header[segment_end] > 127 {
                    segment_end += 1;
                } else {
                    let ascii = header[segment_end] as char;
                    if ascii == '<' || ascii == '>' {
                        break;
                    } else if ascii == '"' && segment_end == i {
                        break;
                    } else {
                        segment_end += 1;
                    }
                }
            }
            if segment_end > i {
                let segment = &header[i..segment_end];
                let mut offset = 0usize;
                while offset < segment.len() {
                    let mut chunk_size = max_raw_bytes.min(segment.len() - offset);
                    while chunk_size > 0 && offset + chunk_size < segment.len() {
                        let b = segment[offset + chunk_size];
                        if (b & 0x80) == 0 || (b & 0xC0) == 0xC0 {
                            break;
                        }
                        chunk_size -= 1;
                    }
                    if chunk_size == 0 {
                        chunk_size = 1;
                    }
                    let chunk = &segment[offset..offset + chunk_size];
                    let encoded = base64::encode(chunk);
                    result.push_str(&format!("=?{charset}?B?{encoded}?="));
                    offset += chunk_size;
                }
                i = segment_end;
            }
        }
        result
    }

    pub fn encode_q(header: &[u8], charset: &str) -> String {
        let overhead = 2 + charset.len() + 3 + 2;
        let max_encoded_chars = MAX_ENCODED_WORD_LENGTH.saturating_sub(overhead);
        let mut result = String::new();
        let mut i = 0usize;
        while i < header.len() {
            let mut segment_start = i;
            while segment_start < header.len() && header[segment_start] <= 127 {
                segment_start += 1;
            }
            if segment_start > i {
                result.push_str(&charset::decode_bytes(
                    &header[i..segment_start],
                    HeaderCharset::Iso88591,
                ));
                i = segment_start;
            }
            if i >= header.len() {
                break;
            }
            let mut segment_end = i;
            while segment_end < header.len() && header[segment_end] > 127 {
                segment_end += 1;
            }
            if segment_end > i {
                let mut j = i;
                while j < segment_end {
                    result.push_str(&format!("=?{charset}?Q?"));
                    let word_start = result.len();
                    let mut chars_used = 0usize;
                    while j < segment_end && chars_used + 3 <= max_encoded_chars {
                        result.push_str(&format!("={:02X}", header[j]));
                        chars_used += 3;
                        j += 1;
                    }
                    let _ = word_start;
                    result.push_str("?=");
                }
                i = segment_end;
            }
        }
        result
    }
}

// Re-export decoder round-trip helper for tests.
impl Encoder {
    pub fn round_trip_check(original: &str) -> bool {
        let bytes = original.as_bytes();
        let encoded = Self::encode_header_value(bytes, "UTF-8");
        Decoder::decode_encoded_words(&encoded) == original
    }
}
