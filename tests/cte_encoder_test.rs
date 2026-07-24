use rmimeparser::{
    decode_base64, decode_quoted_printable, encode_base64, encode_quoted_printable,
    Base64Encoder, QuotedPrintableEncoder, BASE64_MAX_LINE_LENGTH,
};

fn round_trip_base64(data: &[u8]) {
    let mut encoded = Vec::new();
    encode_base64(&mut encoded, data).unwrap();

    // Lines (except possibly last) must be ≤ 76.
    let text = String::from_utf8_lossy(&encoded);
    for line in text.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        assert!(
            line.len() <= BASE64_MAX_LINE_LENGTH,
            "line too long: {} ({line})",
            line.len()
        );
    }

    let mut src = &encoded[..];
    let mut decoded = Vec::new();
    decode_base64(&mut src, &mut decoded, data.len() + 16, true, false);
    assert_eq!(decoded, data);
}

fn round_trip_qp(data: &[u8]) {
    let mut encoded = Vec::new();
    encode_quoted_printable(&mut encoded, data).unwrap();
    let mut src = &encoded[..];
    let mut decoded = Vec::new();
    decode_quoted_printable(&mut src, &mut decoded, data.len() + 64, true);
    assert_eq!(decoded, data);
}

#[test]
fn base64_empty() {
    round_trip_base64(b"");
}

#[test]
fn base64_short() {
    round_trip_base64(b"Hello");
    round_trip_base64(b"Hi");
    round_trip_base64(b"A");
}

#[test]
fn base64_long_wraps() {
    let data = vec![b'x'; 200];
    round_trip_base64(&data);
}

#[test]
fn base64_chunked_matches_oneshot() {
    let data: Vec<u8> = (0..100u8).cycle().take(250).collect();

    let mut oneshot = Vec::new();
    encode_base64(&mut oneshot, &data).unwrap();

    let mut chunked = Vec::new();
    let mut enc = Base64Encoder::new();
    for chunk in data.chunks(7) {
        enc.write(&mut chunked, chunk).unwrap();
    }
    enc.finish(&mut chunked).unwrap();

    assert_eq!(chunked, oneshot);

    let mut src = &chunked[..];
    let mut decoded = Vec::new();
    decode_base64(&mut src, &mut decoded, data.len() + 8, true, false);
    assert_eq!(decoded, data);
}

#[test]
fn qp_simple() {
    round_trip_qp(b"Hello world");
}

#[test]
fn qp_equals_and_high_bytes() {
    round_trip_qp(b"a=b\xc3\xa9");
}

#[test]
fn qp_trailing_space_encoded() {
    let mut encoded = Vec::new();
    encode_quoted_printable(&mut encoded, b"hello ").unwrap();
    let s = String::from_utf8(encoded).unwrap();
    assert!(s.contains("=20"), "expected trailing space encoded: {s}");
}

#[test]
fn qp_chunked_matches_oneshot() {
    let data = b"Line one with = signs\r\nLine two \r\nSoft?";
    let mut oneshot = Vec::new();
    encode_quoted_printable(&mut oneshot, data).unwrap();

    let mut chunked = Vec::new();
    let mut enc = QuotedPrintableEncoder::new();
    for chunk in data.chunks(5) {
        enc.write(&mut chunked, chunk).unwrap();
    }
    enc.finish(&mut chunked).unwrap();

    assert_eq!(chunked, oneshot);
    round_trip_qp(data);
}

#[test]
fn qp_long_line_soft_breaks() {
    let data = vec![b'A'; 100];
    let mut encoded = Vec::new();
    encode_quoted_printable(&mut encoded, &data).unwrap();
    let text = String::from_utf8_lossy(&encoded);
    assert!(text.contains("=\r\n"));
    round_trip_qp(&data);
}
