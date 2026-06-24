use std::sync::OnceLock;

const WHITESPACE: i8 = -2;

fn decode_table() -> &'static [i8; 256] {
    static TABLE: OnceLock<[i8; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [-1i8; 256];
        t[b' ' as usize] = WHITESPACE;
        t[b'\t' as usize] = WHITESPACE;
        t[b'\r' as usize] = WHITESPACE;
        t[b'\n' as usize] = WHITESPACE;
        for i in 0..26u8 {
            t[(b'A' + i) as usize] = i as i8;
            t[(b'a' + i) as usize] = (26 + i) as i8;
        }
        for i in 0..10u8 {
            t[(b'0' + i) as usize] = (52 + i) as i8;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    })
}

fn hex_decode_table() -> &'static [i8; 256] {
    static TABLE: OnceLock<[i8; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [-1i8; 256];
        for i in 0..10u8 {
            t[(b'0' + i) as usize] = i as i8;
        }
        for i in 0..6u8 {
            t[(b'A' + i) as usize] = (10 + i) as i8;
            t[(b'a' + i) as usize] = (10 + i) as i8;
        }
        t
    })
}

/// RFC 2045 §6.8 — maximum encoded line length.
pub const BASE64_MAX_LINE_LENGTH: usize = 76;

pub struct Base64Decoder;

impl Base64Decoder {
    pub fn estimate_decoded_size(encoded_size: usize) -> usize {
        estimate_base64_decoded_size(encoded_size)
    }

    pub fn decode(src: &mut &[u8], dst: &mut Vec<u8>, max: usize) -> usize {
        decode_base64(src, dst, max, false, false)
    }

    pub fn decode_eos(
        src: &mut &[u8],
        dst: &mut Vec<u8>,
        max: usize,
        end_of_stream: bool,
    ) -> usize {
        decode_base64(src, dst, max, end_of_stream, false)
    }

    pub fn decode_full(
        src: &mut &[u8],
        dst: &mut Vec<u8>,
        max: usize,
        end_of_stream: bool,
        strict_line_length: bool,
    ) -> usize {
        decode_base64(src, dst, max, end_of_stream, strict_line_length)
    }
}

pub struct QuotedPrintableDecoder;

impl QuotedPrintableDecoder {
    pub fn estimate_decoded_size(encoded_size: usize) -> usize {
        estimate_qp_decoded_size(encoded_size)
    }

    pub fn decode(src: &mut &[u8], dst: &mut Vec<u8>, max: usize) -> usize {
        decode_quoted_printable(src, dst, max, false)
    }

    pub fn decode_eos(
        src: &mut &[u8],
        dst: &mut Vec<u8>,
        max: usize,
        end_of_stream: bool,
    ) -> usize {
        decode_quoted_printable(src, dst, max, end_of_stream)
    }
}

/// Estimates the maximum decoded size for BASE64 input.
pub fn estimate_base64_decoded_size(encoded_size: usize) -> usize {
    (encoded_size * 3) / 4 + 4
}

/// Estimates the maximum decoded size for quoted-printable input.
pub fn estimate_qp_decoded_size(encoded_size: usize) -> usize {
    encoded_size
}

/// Decodes BASE64 from the front of `src` into `dst`, consuming at most `max` output bytes.
/// Returns the number of input bytes consumed.
pub fn decode_base64(
    src: &mut &[u8],
    dst: &mut Vec<u8>,
    max: usize,
    end_of_stream: bool,
    strict_line_length: bool,
) -> usize {
    if strict_line_length {
        validate_base64_line_length(src);
    }

    let start_len = src.len();
    let dst_start = dst.len();
    let dst_limit = dst_start + max;

    let mut src_pos = 0usize;
    let mut last_valid_src_pos = 0usize;
    let mut quantum: u32 = 0;
    let mut quantum_bits: u32 = 0;
    let mut saw_padding = false;

    while src_pos < start_len {
        let b = src[src_pos];
        let val = decode_table()[b as usize];

        if val >= 0 {
            quantum = (quantum << 6) | val as u32;
            quantum_bits += 6;
            src_pos += 1;

            if quantum_bits >= 24 {
                if dst.len() + 3 <= dst_limit {
                    dst.push((quantum >> 16) as u8);
                    dst.push((quantum >> 8) as u8);
                    dst.push(quantum as u8);
                    last_valid_src_pos = src_pos;
                    quantum = 0;
                    quantum_bits = 0;
                } else {
                    src_pos = last_valid_src_pos;
                    break;
                }
            }
        } else if val == WHITESPACE {
            src_pos += 1;
        } else if b == b'=' {
            saw_padding = true;
            src_pos += 1;
            break;
        } else {
            src_pos += 1;
        }
    }

    if (saw_padding || end_of_stream) && quantum_bits >= 8 && dst.len() < dst_limit {
        dst.push((quantum >> (quantum_bits - 8)) as u8);
        if quantum_bits >= 16 && dst.len() < dst_limit {
            dst.push((quantum >> (quantum_bits - 16)) as u8);
        }
        last_valid_src_pos = src_pos;
    }

    *src = &src[last_valid_src_pos..];
    last_valid_src_pos
}

fn validate_base64_line_length(src: &[u8]) {
    let mut line_len = 0usize;
    for &b in src {
        if b == b'\r' || b == b'\n' {
            line_len = 0;
        } else {
            line_len += 1;
            if line_len > BASE64_MAX_LINE_LENGTH {
                panic!("RFC 2045 §6.8: Base64 line exceeds {BASE64_MAX_LINE_LENGTH} characters");
            }
        }
    }
}

/// Decodes quoted-printable from the front of `src` into `dst`, consuming at most `max` output bytes.
/// Returns the number of input bytes consumed.
pub fn decode_quoted_printable(
    src: &mut &[u8],
    dst: &mut Vec<u8>,
    max: usize,
    end_of_stream: bool,
) -> usize {
    let start_len = src.len();
    let dst_limit = dst.len() + max;
    let mut src_pos = 0usize;

    while src_pos < start_len && dst.len() < dst_limit {
        let b = src[src_pos];

        if b != b'=' {
            dst.push(b);
            src_pos += 1;
            continue;
        }

        let remaining = start_len - src_pos - 1;

        if remaining >= 2 {
            let hex1 = src[src_pos + 1];
            let hex2 = src[src_pos + 2];
            let val1 = hex_decode_table()[hex1 as usize];
            let val2 = hex_decode_table()[hex2 as usize];

            if val1 >= 0 && val2 >= 0 {
                dst.push(((val1 as u8) << 4) | val2 as u8);
                src_pos += 3;
                continue;
            }

            if hex1 == b'\r' && hex2 == b'\n' {
                src_pos += 3;
                continue;
            }
            if hex1 == b'\n' {
                src_pos += 2;
                continue;
            }

            dst.push(b);
            src_pos += 1;
        } else if remaining == 1 {
            let next = src[src_pos + 1];
            if next == b'\n' {
                src_pos += 2;
            } else if next == b'\r' {
                if end_of_stream {
                    dst.push(b);
                    src_pos += 1;
                } else {
                    break;
                }
            } else if end_of_stream {
                dst.push(b);
                src_pos += 1;
            } else {
                break;
            }
        } else if end_of_stream {
            dst.push(b);
            src_pos += 1;
        } else {
            break;
        }
    }

    let consumed = src_pos;
    *src = &src[consumed..];
    consumed
}
