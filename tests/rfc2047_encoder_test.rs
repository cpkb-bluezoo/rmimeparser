use rmimeparser::{Rfc2047Decoder, Rfc2047Encoder};

#[test]
fn test_contains_non_ascii_true() {
    let data = "Café".as_bytes();
    assert!(Rfc2047Encoder::contains_non_ascii(data));
}

#[test]
fn test_contains_non_ascii_false() {
    let data = b"Hello World";
    assert!(!Rfc2047Encoder::contains_non_ascii(data));
}

#[test]
fn test_contains_non_ascii_empty() {
    assert!(!Rfc2047Encoder::contains_non_ascii(b""));
}

#[test]
fn test_contains_non_ascii_range() {
    let data = "Hello Café World".as_bytes();
    assert!(!Rfc2047Encoder::contains_non_ascii_range(data, 0, 6));
    assert!(Rfc2047Encoder::contains_non_ascii_range(data, 6, data.len()));
}

#[test]
fn test_encoding_for_ascii() {
    let data = b"Hello World";
    assert_eq!(Rfc2047Encoder::encoding_for_data(data), 'Q');
}

#[test]
fn test_encoding_for_mostly_non_ascii() {
    let data = "日本語テスト".as_bytes();
    assert_eq!(Rfc2047Encoder::encoding_for_data(data), 'B');
}

#[test]
fn test_encoding_for_empty() {
    assert_eq!(Rfc2047Encoder::encoding_for_data(b""), 'B');
}

#[test]
fn test_encode_b_simple() {
    let data = b"Hello";
    assert_eq!(Rfc2047Encoder::encode_b(data, "UTF-8"), "Hello");
}

#[test]
fn test_encode_b_with_non_ascii() {
    let data = "Café".as_bytes();
    let encoded = Rfc2047Encoder::encode_b(data, "UTF-8");
    assert!(encoded.contains("=?UTF-8?B?"));
    assert!(encoded.contains("?="));
    assert_eq!(Rfc2047Decoder::decode_encoded_words(&encoded), "Café");
}

#[test]
fn test_encode_b_japanese() {
    let data = "日本語".as_bytes();
    let encoded = Rfc2047Encoder::encode_b(data, "UTF-8");
    assert!(encoded.contains("=?UTF-8?B?"));
    assert_eq!(Rfc2047Decoder::decode_encoded_words(&encoded), "日本語");
}

#[test]
fn test_encode_q_with_non_ascii() {
    let data = "Café".as_bytes();
    let encoded = Rfc2047Encoder::encode_q(data, "UTF-8");
    assert!(encoded.contains("=?UTF-8?Q?"));
    assert_eq!(Rfc2047Decoder::decode_encoded_words(&encoded), "Café");
}

#[test]
fn test_round_trip_check() {
    assert!(Rfc2047Encoder::round_trip_check("Hello World"));
    assert!(Rfc2047Encoder::round_trip_check("Café résumé"));
}
