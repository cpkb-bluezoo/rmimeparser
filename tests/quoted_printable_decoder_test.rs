use rmimeparser::{
    decode_quoted_printable, estimate_qp_decoded_size, QuotedPrintableDecoder,
};

fn decode(encoded: &str) -> String {
    let mut src = encoded.as_bytes();
    let cap = estimate_qp_decoded_size(encoded.len());
    let mut dst = Vec::with_capacity(cap);
    decode_quoted_printable(&mut src, &mut dst, cap, false);
    String::from_utf8(dst).unwrap()
}

fn decode_with_end_of_stream(encoded: &str) -> String {
    let mut src = encoded.as_bytes();
    let cap = estimate_qp_decoded_size(encoded.len());
    let mut dst = Vec::with_capacity(cap);
    decode_quoted_printable(&mut src, &mut dst, cap, true);
    String::from_utf8(dst).unwrap()
}

fn decode_iso(encoded: &str) -> String {
    let mut src = encoded.as_bytes();
    let cap = estimate_qp_decoded_size(encoded.len());
    let mut dst = Vec::with_capacity(cap);
    decode_quoted_printable(&mut src, &mut dst, cap, false);
    dst.iter().map(|&b| b as char).collect()
}

fn decode_iso_with_end_of_stream(encoded: &str) -> String {
    let mut src = encoded.as_bytes();
    let cap = estimate_qp_decoded_size(encoded.len());
    let mut dst = Vec::with_capacity(cap);
    decode_quoted_printable(&mut src, &mut dst, cap, true);
    dst.iter().map(|&b| b as char).collect()
}

#[test]
fn test_decode_simple() {
    assert_eq!(decode("Hello World"), "Hello World");
}

#[test]
fn test_decode_hex_escape() {
    assert_eq!(decode("Hello=20World"), "Hello World");
}

#[test]
fn test_decode_multiple_hex_escapes() {
    assert_eq!(decode("=48=65=6C=6C=6F"), "Hello");
}

#[test]
fn test_decode_lowercase_hex() {
    assert_eq!(decode("=48=65=6c=6c=6f"), "Hello");
}

#[test]
fn test_decode_soft_line_break_crlf() {
    assert_eq!(decode("Hello=\r\nWorld"), "HelloWorld");
}

#[test]
fn test_decode_soft_line_break_lf() {
    assert_eq!(decode("Hello=\nWorld"), "HelloWorld");
}

#[test]
fn test_decode_high_bytes() {
    assert_eq!(decode("=C3=A9"), "é");
}

#[test]
fn test_decode_equals() {
    assert_eq!(decode("1+1=3D2"), "1+1=2");
}

#[test]
fn test_decode_empty_input() {
    let mut src = &[][..];
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_quoted_printable(&mut src, &mut dst, 100, false);
    assert_eq!(dst.len(), 0);
    assert_eq!(consumed, 0);
}

#[test]
fn test_decode_mixed_content() {
    assert_eq!(decode("Caf=C3=A9 au lait"), "Café au lait");
}

#[test]
fn test_decode_limited_output() {
    let mut src: &[u8] = b"Hello World";
    let mut dst = Vec::with_capacity(5);
    decode_quoted_printable(&mut src, &mut dst, 5, false);
    assert_eq!(dst.len(), 5);
}

#[test]
fn test_estimate_decoded_size() {
    assert_eq!(QuotedPrintableDecoder::estimate_decoded_size(100), 100);
    assert_eq!(QuotedPrintableDecoder::estimate_decoded_size(0), 0);
}

#[test]
fn test_decode_invalid_hex_treated_as_literal() {
    assert_eq!(decode_iso_with_end_of_stream("=GG"), "=GG");
}

#[test]
fn test_decode_tab_and_newline() {
    assert_eq!(decode("Hello\tWorld\nTest"), "Hello\tWorld\nTest");
}

#[test]
fn test_decode_japanese_utf8() {
    assert_eq!(decode("=E6=97=A5=E6=9C=AC"), "日本");
}

#[test]
fn test_incomplete_equals_at_end() {
    let mut src: &[u8] = b"Hello=";
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_quoted_printable(&mut src, &mut dst, 100, false);
    assert_eq!(dst.len(), 5);
    assert_eq!(consumed, 5);
    assert_eq!(src, b"=");
}

#[test]
fn test_incomplete_equals_at_end_with_end_of_stream() {
    let mut src: &[u8] = b"Hello=";
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_quoted_printable(&mut src, &mut dst, 100, true);
    assert_eq!(dst.len(), 6);
    assert_eq!(consumed, 6);
    assert_eq!(String::from_utf8(dst).unwrap(), "Hello=");
}

#[test]
fn test_incomplete_escape_one_hex_char() {
    let mut src: &[u8] = b"Hello=4";
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_quoted_printable(&mut src, &mut dst, 100, false);
    assert_eq!(dst.len(), 5);
    assert_eq!(consumed, 5);
}

#[test]
fn test_incomplete_escape_one_hex_char_with_end_of_stream() {
    let mut src: &[u8] = b"Hello=4";
    let mut dst = Vec::with_capacity(100);
    decode_quoted_printable(&mut src, &mut dst, 100, true);
    assert_eq!(String::from_utf8(dst).unwrap(), "Hello=4");
}

#[test]
fn test_incomplete_soft_break_cr() {
    let mut src: &[u8] = b"Hello=\r";
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_quoted_printable(&mut src, &mut dst, 100, false);
    assert_eq!(dst.len(), 5);
    assert_eq!(consumed, 5);
}

#[test]
fn test_incomplete_soft_break_cr_with_end_of_stream() {
    let mut src: &[u8] = b"Hello=\r";
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_quoted_printable(&mut src, &mut dst, 100, true);
    assert_eq!(dst.len(), 7);
    assert_eq!(consumed, 7);
}

#[test]
fn test_streaming_decode_simple() {
    let mut dst = Vec::with_capacity(100);
    let mut src1: &[u8] = b"Hello";
    decode_quoted_printable(&mut src1, &mut dst, 100, false);
    assert_eq!(dst.len(), 5);
    let mut src2: &[u8] = b" World";
    decode_quoted_printable(&mut src2, &mut dst, 100, true);
    assert_eq!(String::from_utf8(dst).unwrap(), "Hello World");
}

#[test]
fn test_streaming_with_split_escape() {
    let mut dst = Vec::with_capacity(100);
    let mut buf = b"Hello=".to_vec();
    let mut src = buf.as_slice();
    let consumed = decode_quoted_printable(&mut src, &mut dst, 100, false);
    assert_eq!(dst.len(), 5);
    assert_eq!(consumed, 5);

    buf = src.to_vec();
    buf.extend_from_slice(b"20World");
    src = buf.as_slice();
    decode_quoted_printable(&mut src, &mut dst, 100, true);
    assert_eq!(String::from_utf8(dst).unwrap(), "Hello World");
}

#[test]
fn test_streaming_with_split_escape_middle() {
    let mut dst = Vec::with_capacity(100);
    let mut buf = b"Hello=2".to_vec();
    let mut src = buf.as_slice();
    let consumed = decode_quoted_printable(&mut src, &mut dst, 100, false);
    assert_eq!(consumed, 5);

    buf = src.to_vec();
    buf.extend_from_slice(b"0World");
    src = buf.as_slice();
    decode_quoted_printable(&mut src, &mut dst, 100, true);
    assert_eq!(String::from_utf8(dst).unwrap(), "Hello World");
}

#[test]
fn test_streaming_with_split_soft_break() {
    let mut dst = Vec::with_capacity(100);
    let mut buf = b"Hello=\r".to_vec();
    let mut src = buf.as_slice();
    let consumed = decode_quoted_printable(&mut src, &mut dst, 100, false);
    assert_eq!(consumed, 5);

    buf = src.to_vec();
    buf.extend_from_slice(b"\nWorld");
    src = buf.as_slice();
    decode_quoted_printable(&mut src, &mut dst, 100, true);
    assert_eq!(String::from_utf8(dst).unwrap(), "HelloWorld");
}

#[test]
fn test_streaming_large_data_in_small_chunks() {
    let original = "The quick brown fox = jumps over the lazy dog";
    let encoded = "The quick brown fox =3D jumps over the lazy dog";
    let mut dst = Vec::with_capacity(200);
    let mut src_buf = Vec::new();
    let chunk_sizes = [5usize, 7, 3, 11, 8, 100];
    let encoded_bytes = encoded.as_bytes();
    let mut offset = 0usize;
    let mut chunk_idx = 0usize;

    while offset < encoded_bytes.len() && chunk_idx < chunk_sizes.len() {
        let end = (offset + chunk_sizes[chunk_idx]).min(encoded_bytes.len());
        src_buf.extend_from_slice(&encoded_bytes[offset..end]);
        offset = end;
        chunk_idx += 1;
        let mut src = src_buf.as_slice();
        let is_last = offset >= encoded_bytes.len();
        decode_quoted_printable(&mut src, &mut dst, 200, is_last);
        src_buf = src.to_vec();
    }

    assert_eq!(String::from_utf8(dst).unwrap(), original);
}

#[test]
fn test_source_position_after_complete() {
    let mut src: &[u8] = b"Hello";
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_quoted_printable(&mut src, &mut dst, 100, false);
    assert_eq!(dst.len(), 5);
    assert_eq!(consumed, 5);
    assert!(src.is_empty());
}

#[test]
fn test_source_position_after_incomplete() {
    let mut src: &[u8] = b"Hello=";
    let mut dst = Vec::with_capacity(100);
    let consumed = decode_quoted_printable(&mut src, &mut dst, 100, false);
    assert_eq!(dst.len(), 5);
    assert_eq!(consumed, 5);
    assert_eq!(src, b"=");
}

#[test]
fn test_destination_buffer_full() {
    let mut src: &[u8] = b"Hello World!";
    let mut dst = Vec::with_capacity(5);
    let consumed = decode_quoted_printable(&mut src, &mut dst, 5, false);
    assert_eq!(dst.len(), 5);
    assert_eq!(consumed, 5);
    assert!(!src.is_empty());
}

#[test]
fn test_max_parameter_respected() {
    let mut src: &[u8] = b"Hello World!";
    let mut dst = Vec::with_capacity(100);
    decode_quoted_printable(&mut src, &mut dst, 5, false);
    assert_eq!(dst.len(), 5);
}

#[test]
fn test_decode_all_escapes() {
    assert_eq!(decode_with_end_of_stream("=41=42=43"), "ABC");
}

#[test]
fn test_decode_consecutive_soft_breaks() {
    assert_eq!(decode("Hel=\r\n=\r\nlo"), "Hello");
}

#[test]
fn test_decode_mixed_line_breaks() {
    assert_eq!(decode("Hello=\r\n\nWorld"), "Hello\nWorld");
}

#[test]
fn test_decode_invalid_hex_first_char() {
    assert_eq!(decode_iso_with_end_of_stream("=GX"), "=GX");
}

#[test]
fn test_decode_invalid_hex_second_char() {
    assert_eq!(decode_iso_with_end_of_stream("=4G"), "=4G");
}

#[test]
fn test_decode_all_bytes() {
    let encoded: String = (0..256)
        .map(|i| format!("={i:02X}"))
        .collect();
    let mut src = encoded.as_bytes();
    let mut dst = Vec::with_capacity(256);
    decode_quoted_printable(&mut src, &mut dst, 256, true);
    assert_eq!(dst.len(), 256);
    for (i, &b) in dst.iter().enumerate() {
        assert_eq!(b, i as u8, "Byte {i} mismatch");
    }
}

#[test]
fn test_compact_and_continue() {
    let encoded = "Hello=20World=21";
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
        decode_quoted_printable(&mut src, &mut output, 100, is_last);
        receive = src.to_vec();
    }

    assert_eq!(String::from_utf8(output).unwrap(), "Hello World!");
}

#[test]
fn test_split_escape_at_buffer_boundary() {
    let mut dst = Vec::with_capacity(100);
    let mut buf = b"Test=".to_vec();
    let mut src = buf.as_slice();
    decode_quoted_printable(&mut src, &mut dst, 100, false);

    buf = src.to_vec();
    buf.extend_from_slice(b"20More");
    src = buf.as_slice();
    decode_quoted_printable(&mut src, &mut dst, 100, true);

    assert_eq!(String::from_utf8(dst).unwrap(), "Test More");
}

#[test]
fn test_multiple_incomplete_then_complete() {
    let mut dst = Vec::with_capacity(100);
    let mut buf = Vec::with_capacity(10);

    buf.push(b'=');
    let mut src = buf.as_slice();
    let consumed = decode_quoted_printable(&mut src, &mut dst, 100, false);
    assert_eq!(consumed, 0);
    buf = src.to_vec();

    buf.push(b'4');
    let mut src = buf.as_slice();
    let consumed = decode_quoted_printable(&mut src, &mut dst, 100, false);
    assert_eq!(consumed, 0);
    buf = src.to_vec();

    buf.push(b'1');
    let mut src = buf.as_slice();
    let consumed = decode_quoted_printable(&mut src, &mut dst, 100, true);
    assert_eq!(consumed, 3);
    assert_eq!(dst.len(), 1);
    assert_eq!(dst[0], b'A');
}
