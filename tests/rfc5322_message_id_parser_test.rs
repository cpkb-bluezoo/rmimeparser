use rmimeparser::{ByteCursor, HeaderCharset, MessageIdParser};

#[test]
fn test_parse_empty() {
    let mut cursor = ByteCursor::new(b"");
    let list = MessageIdParser::parse_message_id_list(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert!(list.is_empty());
}

#[test]
fn test_parse_single() {
    let mut cursor = ByteCursor::new(b"<unique123@example.com>");
    let list = MessageIdParser::parse_message_id_list(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].to_string(), "<unique123@example.com>");
    assert!(!cursor.has_remaining());
}

#[test]
fn test_parse_multiple() {
    let mut cursor = ByteCursor::new(b"<a@x.com> <b@y.org>");
    let list = MessageIdParser::parse_message_id_list(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].to_string(), "<a@x.com>");
    assert_eq!(list[1].to_string(), "<b@y.org>");
}
