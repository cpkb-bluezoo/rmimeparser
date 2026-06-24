use rmimeparser::{ByteCursor, HeaderCharset, Rfc2231Decoder};

#[test]
fn test_decode_utf8_percent_encoded() {
    let mut cursor = ByteCursor::new(b"UTF-8''na%C3%AFve");
    let out = Rfc2231Decoder::decode_parameter_value(&mut cursor, HeaderCharset::Iso88591);
    assert_eq!(out.as_deref(), Some("naïve"));
    assert!(!cursor.has_remaining());
}

#[test]
fn test_decode_charset_lang_value() {
    let mut cursor = ByteCursor::new(b"iso-8859-1'en'Hello%20World");
    let out = Rfc2231Decoder::decode_parameter_value(&mut cursor, HeaderCharset::Iso88591);
    assert_eq!(out.as_deref(), Some("Hello World"));
    assert!(!cursor.has_remaining());
}

#[test]
fn test_decode_with_quotes() {
    let mut cursor = ByteCursor::new(b"\"UTF-8''%C3%A9\"");
    let out = Rfc2231Decoder::decode_parameter_value(&mut cursor, HeaderCharset::Iso88591);
    assert_eq!(out.as_deref(), Some("é"));
    assert!(!cursor.has_remaining());
}

#[test]
fn test_not_rfc2231_format_returns_none() {
    let mut cursor = ByteCursor::new(b"plain");
    let out = Rfc2231Decoder::decode_parameter_value(&mut cursor, HeaderCharset::Iso88591);
    assert!(out.is_none());
}

#[test]
fn test_empty_value() {
    let mut cursor = ByteCursor::new(b"UTF-8''");
    let out = Rfc2231Decoder::decode_parameter_value(&mut cursor, HeaderCharset::Iso88591);
    assert_eq!(out.as_deref(), Some(""));
    assert!(!cursor.has_remaining());
}
