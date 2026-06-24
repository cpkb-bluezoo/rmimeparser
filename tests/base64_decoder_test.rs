use rmimeparser::{
    decode_base64, estimate_base64_decoded_size, Base64Decoder, BASE64_MAX_LINE_LENGTH,
};

fn b64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if i + 1 < data.len() {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if i + 2 < data.len() {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
        i += 3;
    }
    out
}

fn decode(encoded: &str) -> String {
    let mut src = encoded.as_bytes();
    let cap = estimate_base64_decoded_size(encoded.len());
    let mut dst = Vec::with_capacity(cap);
    decode_base64(&mut src, &mut dst, cap, false, false);
    String::from_utf8(dst).unwrap()
}

fn decode_with_end_of_stream(encoded: &str) -> String {
    let mut src = encoded.as_bytes();
    let cap = estimate_base64_decoded_size(encoded.len());
    let mut dst = Vec::with_capacity(cap);
    decode_base64(&mut src, &mut dst, cap, true, false);
    String::from_utf8(dst).unwrap()
}

fn decode_bytes(encoded: &str) -> Vec<u8> {
    let mut src = encoded.as_bytes();
    let cap = estimate_base64_decoded_size(encoded.len());
    let mut dst = Vec::with_capacity(cap);
    decode_base64(&mut src, &mut dst, cap, false, false);
    dst
}

#[test]
fn test_decode_simple() {
    assert_eq!(decode("SGVsbG8="), "Hello");
}

#[test]
fn test_decode_world() {
    assert_eq!(decode("V29ybGQ="), "World");
}

#[test]
fn test_decode_no_padding() {
    assert_eq!(decode("TWFu"), "Man");
}

#[test]
fn test_decode_one_padding() {
    assert_eq!(decode("TWE="), "Ma");
}

#[test]
fn test_decode_two_padding() {
    assert_eq!(decode("TQ=="), "M");
}

#[test]
fn test_decode_with_whitespace() {
    assert_eq!(decode("SGVs\r\nbG8="), "Hello");
}

#[test]
fn test_decode_with_spaces() {
    assert_eq!(decode("SGVs bG8="), "Hello");
}

#[test]
fn test_decode_longer_string() {
    let original = "The quick brown fox jumps over the lazy dog";
    let encoded = b64_encode(original.as_bytes());
    assert_eq!(decode(&encoded), original);
}

#[test]
fn test_decode_binary_data() {
    let original: Vec<u8> = (0..=255).map(|i| i as u8).collect();
    let encoded = b64_encode(&original);
    assert_eq!(decode_bytes(&encoded), original);
}

#[test]
fn test_decode_empty_input() {
    let mut src = &[][..];
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_base64(&mut src, &mut dst, 100, false, false);
    assert_eq!(dst.len(), 0);
    assert_eq!(consumed, 0);
}

#[test]
fn test_decode_limited_output() {
    let encoded = "SGVsbG8gV29ybGQ=";
    let mut src = encoded.as_bytes();
    let mut dst = Vec::with_capacity(3);
    decode_base64(&mut src, &mut dst, 3, false, false);
    assert!(dst.len() <= 3);
}

#[test]
fn test_estimate_decoded_size() {
    assert!(Base64Decoder::estimate_decoded_size(4) >= 3);
    assert!(Base64Decoder::estimate_decoded_size(100) >= 75);
    assert!(Base64Decoder::estimate_decoded_size(0) >= 0);
}

#[test]
fn test_decode_special_chars() {
    let original = vec![0xFB, 0xEF, 0xBE];
    let encoded = b64_encode(&original);
    assert_eq!(decode_bytes(&encoded), original);
}

#[test]
fn test_decode_multiple_quantums() {
    let original = "ABCDEFGHIJKL";
    let encoded = b64_encode(original.as_bytes());
    assert_eq!(decode(&encoded), original);
}

#[test]
fn test_incomplete_quantum1_char() {
    let mut src: &[u8] = b"S";
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_base64(&mut src, &mut dst, 100, false, false);
    assert_eq!(dst.len(), 0, "1 char incomplete: should decode 0 bytes");
    assert_eq!(consumed, 0, "1 char incomplete: should consume 0 bytes");
    assert_eq!(src.len(), 1, "Source should be at start");
}

#[test]
fn test_incomplete_quantum2_chars() {
    let mut src: &[u8] = b"SG";
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_base64(&mut src, &mut dst, 100, false, false);
    assert_eq!(dst.len(), 0);
    assert_eq!(consumed, 0);
}

#[test]
fn test_incomplete_quantum3_chars() {
    let mut src: &[u8] = b"SGV";
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_base64(&mut src, &mut dst, 100, false, false);
    assert_eq!(dst.len(), 0);
    assert_eq!(consumed, 0);
}

#[test]
fn test_incomplete_quantum2_chars_with_end_of_stream() {
    let mut src: &[u8] = b"SG";
    let mut dst = Vec::with_capacity(100);
    decode_base64(&mut src, &mut dst, 100, true, false);
    assert_eq!(dst.len(), 1, "2 chars EOS: should decode 1 byte");
    assert_eq!(dst[0], b'H');
}

#[test]
fn test_incomplete_quantum3_chars_with_end_of_stream() {
    let mut src: &[u8] = b"SGV";
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_base64(&mut src, &mut dst, 100, true, false);
    assert_eq!(dst.len(), 2, "3 chars EOS: should decode 2 bytes");
    assert_eq!(consumed, 3, "3 chars EOS: should consume 3 bytes");
    assert_eq!(&dst[..], b"He");
}

#[test]
fn test_streaming_decode_in_chunks() {
    let mut dst = Vec::with_capacity(100);
    let mut src1: &[u8] = b"SGVs";
    let consumed = decode_base64(&mut src1, &mut dst, 100, false, false);
    assert_eq!(dst.len(), 3, "First chunk: should decode 3 bytes");
    assert_eq!(consumed, 4, "First chunk: should consume 4 bytes");

    let mut src2: &[u8] = b"bG8=";
    decode_base64(&mut src2, &mut dst, 100, false, false);
    assert_eq!(dst.len(), 5, "Second chunk: should decode 2 bytes");
}

#[test]
fn test_streaming_with_incomplete_carry_over() {
    let mut buf = b"SGVsb".to_vec();
    let mut dst = Vec::with_capacity(100);
    let mut src = buf.as_slice();
    let consumed = decode_base64(&mut src, &mut dst, 100, false, false);
    assert_eq!(dst.len(), 3);
    assert_eq!(consumed, 4);
    assert_eq!(src, b"b");

    buf = src.to_vec();
    buf.extend_from_slice(b"G8=");
    src = buf.as_slice();
    let consumed = decode_base64(&mut src, &mut dst, 100, false, false);
    assert_eq!(dst.len(), 5);
    assert_eq!(consumed, 4);
    assert_eq!(String::from_utf8(dst).unwrap(), "Hello");
}

#[test]
fn test_streaming_large_data_in_small_chunks() {
    let original = "The quick brown fox jumps over the lazy dog";
    let encoded = b64_encode(original.as_bytes());
    let encoded_bytes = encoded.as_bytes();

    let mut src_buf = Vec::with_capacity(16);
    let mut dst = Vec::with_capacity(200);
    let mut offset = 0usize;

    while offset < encoded_bytes.len() {
        let to_read = (16 - src_buf.len()).min(encoded_bytes.len() - offset);
        src_buf.extend_from_slice(&encoded_bytes[offset..offset + to_read]);
        offset += to_read;
        let mut src = src_buf.as_slice();
        let is_last = offset >= encoded_bytes.len();
        decode_base64(&mut src, &mut dst, 200, is_last, false);
        src_buf = src.to_vec();
    }

    assert_eq!(String::from_utf8(dst).unwrap(), original);
}

#[test]
fn test_source_position_after_complete_quantum() {
    let mut src: &[u8] = b"TWFu";
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_base64(&mut src, &mut dst, 100, false, false);
    assert_eq!(dst.len(), 3);
    assert_eq!(consumed, 4);
    assert!(src.is_empty());
}

#[test]
fn test_source_position_after_incomplete_quantum() {
    let mut src: &[u8] = b"TWFuT";
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_base64(&mut src, &mut dst, 100, false, false);
    assert_eq!(dst.len(), 3);
    assert_eq!(consumed, 4);
    assert_eq!(src, b"T");
}

#[test]
fn test_destination_buffer_full() {
    let mut src: &[u8] = b"SGVsbG8gV29ybGQ=";
    let mut dst = Vec::with_capacity(3);
    let consumed = decode_base64(&mut src, &mut dst, 3, false, false);
    assert_eq!(dst.len(), 3);
    assert_eq!(consumed, 4);
    assert!(!src.is_empty());
}

#[test]
fn test_max_parameter_respected() {
    let mut src: &[u8] = b"SGVsbG8gV29ybGQ=";
    let mut dst = Vec::with_capacity(100);
    decode_base64(&mut src, &mut dst, 3, false, false);
    assert!(dst.len() <= 3);
}

#[test]
fn test_decode_with_invalid_chars() {
    assert_eq!(decode("SG!V@s#b$G%8^="), "Hello");
}

#[test]
fn test_decode_all_whitespace() {
    let mut src: &[u8] = b"   \r\n\t  ";
    let mut dst = Vec::with_capacity(100);
    decode_base64(&mut src, &mut dst, 100, true, false);
    assert_eq!(dst.len(), 0);
}

#[test]
fn test_decode_with_leading_whitespace() {
    assert_eq!(decode("   SGVsbG8="), "Hello");
}

#[test]
fn test_decode_with_trailing_whitespace() {
    assert_eq!(decode("SGVsbG8=   "), "Hello");
}

#[test]
fn test_decode_no_padding_no_end_of_stream() {
    let mut src: &[u8] = b"TWFu";
    let mut dst = Vec::with_capacity(100);
    decode_base64(&mut src, &mut dst, 100, false, false);
    assert_eq!(dst.len(), 3);
    assert_eq!(String::from_utf8(dst).unwrap(), "Man");
}

#[test]
fn test_multiple_complete_quantums_no_end_of_stream() {
    let mut src: &[u8] = b"TWFuTWFu";
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_base64(&mut src, &mut dst, 100, false, false);
    assert_eq!(dst.len(), 6);
    assert_eq!(consumed, 8);
}

#[test]
fn test_round_trip_with_end_of_stream() {
    for original in ["A", "AB", "ABC", "ABCD", "ABCDE", "ABCDEF"] {
        let encoded = b64_encode(original.as_bytes());
        assert_eq!(
            decode_with_end_of_stream(&encoded),
            original,
            "Round trip failed for: {original}"
        );
    }
}

#[test]
fn test_streaming_with_whitespace_breaks() {
    let original = "The quick brown fox jumps over the lazy dog";
    let encoded = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==";
    let mut src = encoded.as_bytes();
    let mut dst = Vec::with_capacity(200);
    decode_base64(&mut src, &mut dst, 200, true, false);
    assert_eq!(String::from_utf8(dst).unwrap(), original);
}

#[test]
fn test_single_byte_incomplete_at_end_of_stream() {
    let mut src: &[u8] = b"T";
    let mut dst = Vec::with_capacity(100);
    decode_base64(&mut src, &mut dst, 100, true, false);
    assert_eq!(dst.len(), 0);
}

#[test]
fn test_compact_and_continue() {
    let encoded = "SGVsbG8gV29ybGQh";
    let encoded_bytes = encoded.as_bytes();
    let mut receive = Vec::with_capacity(8);
    let mut output = Vec::with_capacity(100);
    let mut offset = 0usize;

    while offset < encoded_bytes.len() {
        let to_read = (8 - receive.len()).min(encoded_bytes.len() - offset);
        receive.extend_from_slice(&encoded_bytes[offset..offset + to_read]);
        offset += to_read;
        let mut src = receive.as_slice();
        let is_last = offset >= encoded_bytes.len();
        decode_base64(&mut src, &mut output, 100, is_last, false);
        receive = src.to_vec();
    }

    assert_eq!(String::from_utf8(output).unwrap(), "Hello World!");
}

#[test]
fn test_strict_mode_accepts_valid_line_length() {
    let base64_data = b64_encode(
        b"This is some test data that should encode to a reasonable length.",
    );
    let line = if base64_data.len() > 76 {
        &base64_data[..76]
    } else {
        &base64_data
    };
    let mut src = line.as_bytes();
    let mut dst = Vec::with_capacity(200);
    decode_base64(&mut src, &mut dst, 200, true, true);
    assert!(!dst.is_empty());
}

#[test]
#[should_panic(expected = "RFC 2045 §6.8")]
fn test_strict_mode_rejects_long_line() {
    let data = "A".repeat(77);
    let mut src = data.as_bytes();
    let mut dst = Vec::with_capacity(200);
    decode_base64(&mut src, &mut dst, 200, true, true);
}

#[test]
fn test_strict_mode_accepts_multiple_short_lines() {
    let data = "QUFBQUFBQUFBQUFBQUFB\r\nQkJCQkJCQkJCQkJCQkJC\r\n";
    let mut src = data.as_bytes();
    let mut dst = Vec::with_capacity(200);
    decode_base64(&mut src, &mut dst, 200, true, true);
    assert!(!dst.is_empty());
}

#[test]
#[should_panic(expected = "RFC 2045 §6.8")]
fn test_strict_mode_rejects_second_long_line() {
    let mut data = String::from("QUFBQUFBQUFBQUFBQUFB\r\n");
    data.push_str(&"B".repeat(77));
    let mut src = data.as_bytes();
    let mut dst = Vec::with_capacity(200);
    decode_base64(&mut src, &mut dst, 200, true, true);
}

#[test]
fn test_lenient_mode_allows_long_line() {
    let data = "A".repeat(100);
    let mut src = data.as_bytes();
    let mut dst = Vec::with_capacity(200);
    decode_base64(&mut src, &mut dst, 200, true, false);
    assert!(!dst.is_empty());
}

#[test]
fn test_strict_mode_exactly76_chars() {
    let data = "Q".repeat(76);
    let mut src = data.as_bytes();
    let mut dst = Vec::with_capacity(200);
    decode_base64(&mut src, &mut dst, 200, true, true);
    assert!(!dst.is_empty());
}

#[test]
fn test_max_line_length_constant() {
    assert_eq!(BASE64_MAX_LINE_LENGTH, 76);
}
