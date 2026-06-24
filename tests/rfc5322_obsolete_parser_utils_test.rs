use rmimeparser::{ByteCursor, HeaderCharset, ObsoleteParserUtils};

#[test]
fn test_parse_obsolete_address_list_simple() {
    let mut cursor = ByteCursor::new(b"user@example.com (comment)");
    let list =
        ObsoleteParserUtils::parse_obsolete_address_list(&mut cursor, HeaderCharset::Iso88591);
    assert!(list.is_some());
    let list = list.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].local_part(), "user");
    assert_eq!(list[0].domain(), "example.com");
}

#[test]
fn test_parse_obsolete_message_id_list() {
    let mut cursor = ByteCursor::new(b"<id@example.com> (foo)");
    let ids =
        ObsoleteParserUtils::parse_obsolete_message_id_list(&mut cursor, HeaderCharset::Iso88591);
    assert!(ids.is_some());
    let ids = ids.unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].to_string(), "<id@example.com>");
}
