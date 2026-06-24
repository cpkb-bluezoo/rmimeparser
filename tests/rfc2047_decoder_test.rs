use rmimeparser::{ByteCursor, HeaderCharset, Rfc2047Decoder};

#[test]
fn test_decode_simple_base64() {
    let encoded = "=?UTF-8?B?SGVsbG8=?=";
    assert_eq!(Rfc2047Decoder::decode_encoded_words(encoded), "Hello");
}

#[test]
fn test_decode_simple_quoted_printable() {
    let encoded = "=?UTF-8?Q?Hello?=";
    assert_eq!(Rfc2047Decoder::decode_encoded_words(encoded), "Hello");
}

#[test]
fn test_decode_q_encoding_with_underscore() {
    let encoded = "=?UTF-8?Q?Hello_World?=";
    assert_eq!(Rfc2047Decoder::decode_encoded_words(encoded), "Hello World");
}

#[test]
fn test_decode_q_encoding_with_hex() {
    let encoded = "=?UTF-8?Q?Caf=C3=A9?=";
    assert_eq!(Rfc2047Decoder::decode_encoded_words(encoded), "Café");
}

#[test]
fn test_decode_lowercase_encoding() {
    assert_eq!(
        Rfc2047Decoder::decode_encoded_words("=?UTF-8?b?SGVsbG8=?="),
        "Hello"
    );
    assert_eq!(
        Rfc2047Decoder::decode_encoded_words("=?UTF-8?q?Hello?="),
        "Hello"
    );
}

#[test]
fn test_decode_mixed_plain_and_encoded() {
    let encoded = "Subject: =?UTF-8?B?SGVsbG8=?= World";
    assert_eq!(
        Rfc2047Decoder::decode_encoded_words(encoded),
        "Subject: Hello World"
    );
}

#[test]
fn test_decode_adjacent_encoded_words() {
    let encoded = "=?UTF-8?B?SGVs?= =?UTF-8?B?bG8=?=";
    assert_eq!(Rfc2047Decoder::decode_encoded_words(encoded), "Hello");
}

#[test]
fn test_decode_iso88591() {
    let encoded = "=?ISO-8859-1?Q?Caf=E9?=";
    assert_eq!(Rfc2047Decoder::decode_encoded_words(encoded), "Café");
}

#[test]
fn test_decode_windows1252() {
    let encoded = "=?windows-1252?Q?=93Hello=94?=";
    let decoded = Rfc2047Decoder::decode_encoded_words(encoded);
    assert!(decoded.contains("Hello"));
}

#[test]
fn test_decode_japanese() {
    let encoded = "=?UTF-8?B?5pel5pys6Kqe?=";
    assert_eq!(Rfc2047Decoder::decode_encoded_words(encoded), "日本語");
}

#[test]
fn test_decode_empty_string() {
    assert_eq!(Rfc2047Decoder::decode_encoded_words(""), "");
}

#[test]
fn test_decode_plain_ascii() {
    assert_eq!(
        Rfc2047Decoder::decode_encoded_words("Hello World"),
        "Hello World"
    );
}

#[test]
fn test_decode_invalid_encoded_word() {
    let invalid = "=?UTF-8?X?Invalid?=";
    assert_eq!(Rfc2047Decoder::decode_encoded_words(invalid), invalid);
}

#[test]
fn test_decode_incomplete_encoded_word() {
    let incomplete = "=?UTF-8?B?SGVsbG8";
    assert_eq!(Rfc2047Decoder::decode_encoded_words(incomplete), incomplete);
}

#[test]
fn test_decode_header_value_simple() {
    let header = b"Hello World";
    assert_eq!(Rfc2047Decoder::decode_header_value(header), "Hello World");
}

#[test]
fn test_decode_header_value_with_encoded_word() {
    let header = b"=?UTF-8?B?SGVsbG8=?= World";
    assert_eq!(Rfc2047Decoder::decode_header_value(header), "Hello World");
}

#[test]
fn test_decode_header_value_empty() {
    assert_eq!(Rfc2047Decoder::decode_header_value(b""), "");
}

#[test]
fn test_decode_rfc2231_simple() {
    let param = "filename*=UTF-8''Hello%20World";
    assert_eq!(
        Rfc2047Decoder::decode_rfc2231_parameter(param).as_deref(),
        Some("Hello World")
    );
}

#[test]
fn test_decode_rfc2231_japanese() {
    let param = "filename*=UTF-8''%E6%97%A5%E6%9C%AC%E8%AA%9E.txt";
    assert_eq!(
        Rfc2047Decoder::decode_rfc2231_parameter(param).as_deref(),
        Some("日本語.txt")
    );
}

#[test]
fn test_decode_multiple_encoded_words_in_subject() {
    let encoded = "=?UTF-8?Q?This_is_a?= =?UTF-8?Q?_long_subject?=";
    assert_eq!(
        Rfc2047Decoder::decode_encoded_words(encoded),
        "This is a long subject"
    );
}

#[test]
fn test_decode_charset_normalization() {
    assert_eq!(
        Rfc2047Decoder::decode_encoded_words("=?utf8?B?SGVsbG8=?="),
        "Hello"
    );
    assert_eq!(
        Rfc2047Decoder::decode_encoded_words("=?UTF8?B?SGVsbG8=?="),
        "Hello"
    );
}

#[test]
fn test_decode_unstructured_header_value_simple() {
    let mut cursor = ByteCursor::new(b"Hello");
    let out = Rfc2047Decoder::decode_unstructured_header_value(
        &mut cursor,
        HeaderCharset::Iso88591,
        true,
    );
    assert_eq!(out, "Hello");
    assert!(!cursor.has_remaining());
}

#[test]
fn test_decode_unstructured_header_value_with_folding() {
    let mut cursor = ByteCursor::new(b"Hello\r\n world");
    let out = Rfc2047Decoder::decode_unstructured_header_value(
        &mut cursor,
        HeaderCharset::Iso88591,
        true,
    );
    assert_eq!(out, "Hello world");
    assert!(!cursor.has_remaining());
}

#[test]
fn test_decode_display_name_stops_at_angle() {
    let mut cursor = ByteCursor::new(b"John Doe <j@x.org>");
    let stop = [b'<'];
    let out = Rfc2047Decoder::decode_display_name(&mut cursor, HeaderCharset::Iso88591, &stop);
    assert_eq!(out.trim(), "John Doe");
    assert_eq!(cursor.get(cursor.position()), b'<');
}

#[test]
fn test_decode_parameter_value_token() {
    let mut cursor = ByteCursor::new(b"utf-8");
    let out = Rfc2047Decoder::decode_parameter_value(&mut cursor, HeaderCharset::Iso88591);
    assert_eq!(out, "utf-8");
    assert!(!cursor.has_remaining());
}
