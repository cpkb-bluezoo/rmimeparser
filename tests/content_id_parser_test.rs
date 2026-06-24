use rmimeparser::{ByteCursor, ContentIdParser, HeaderCharset};

#[test]
fn test_parse_null() {
    let mut cursor = ByteCursor::new(&[] as &[u8]);
    assert!(ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591).is_none());
}

#[test]
fn test_parse_empty() {
    let mut cursor = ByteCursor::new(b"");
    assert!(ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591).is_none());
}

#[test]
fn test_parse_whitespace_only() {
    let mut cursor = ByteCursor::new(b"   ");
    assert!(ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591).is_none());
}

#[test]
fn test_parse_with_angle_brackets() {
    let mut cursor = ByteCursor::new(b"<abc123@example.com>");
    let cid = ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert_eq!(cid.local_part(), "abc123");
    assert_eq!(cid.domain(), "example.com");
}

#[test]
fn test_parse_with_leading_trailing_whitespace() {
    let mut cursor = ByteCursor::new(b"  <msg@host.com>  ");
    let cid = ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert_eq!(cid.local_part(), "msg");
    assert_eq!(cid.domain(), "host.com");
}

#[test]
fn test_parse_no_at() {
    let mut cursor = ByteCursor::new(b"<localpart.example.com>");
    assert!(ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591).is_none());
}

#[test]
fn test_parse_at_at_start() {
    let mut cursor = ByteCursor::new(b"<@example.com>");
    assert!(ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591).is_none());
}

#[test]
fn test_parse_at_at_end() {
    let mut cursor = ByteCursor::new(b"<localpart@>");
    let cid = ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert_eq!(cid.local_part(), "localpart");
    assert_eq!(cid.domain(), "");
}

#[test]
fn test_parse_angle_brackets_only() {
    let mut cursor = ByteCursor::new(b"<>");
    assert!(ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591).is_none());
}

#[test]
fn test_parse_single_angle_bracket() {
    let mut cursor = ByteCursor::new(b"<");
    assert!(ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591).is_none());
    let mut cursor = ByteCursor::new(b">");
    assert!(ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591).is_none());
}

#[test]
fn test_parse_dot_in_local_part() {
    let mut cursor = ByteCursor::new(b"<part1.E72C5B26@example.com>");
    let cid = ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert_eq!(cid.local_part(), "part1.E72C5B26");
    assert_eq!(cid.domain(), "example.com");
}

#[test]
fn test_parse_domain_literal() {
    let mut cursor = ByteCursor::new(b"<user@[192.168.1.1]>");
    let cid = ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert_eq!(cid.local_part(), "user");
    assert_eq!(cid.domain(), "[192.168.1.1]");
}

#[test]
fn test_parse_multiple_ids_returns_null() {
    let mut cursor = ByteCursor::new(b"<a@x.com> <b@y.com>");
    assert!(ContentIdParser::parse(&mut cursor, HeaderCharset::Iso88591).is_none());
}

#[test]
fn test_parse_list_null() {
    let mut cursor = ByteCursor::new(&[] as &[u8]);
    let list = ContentIdParser::parse_list(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert!(list.is_empty());
}

#[test]
fn test_parse_list_empty() {
    let mut cursor = ByteCursor::new(b"");
    let list = ContentIdParser::parse_list(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert!(list.is_empty());
}

#[test]
fn test_parse_list_single() {
    let mut cursor = ByteCursor::new(b"<one@example.com>");
    let list = ContentIdParser::parse_list(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].local_part(), "one");
    assert_eq!(list[0].domain(), "example.com");
}

#[test]
fn test_parse_list_multiple_with_spaces() {
    let mut cursor = ByteCursor::new(b"<a@x.com> <b@y.com> <c@z.com>");
    let list = ContentIdParser::parse_list(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].local_part(), "a");
    assert_eq!(list[1].local_part(), "b");
    assert_eq!(list[2].local_part(), "c");
}

#[test]
fn test_parse_list_multiple_with_commas() {
    let mut cursor = ByteCursor::new(b"<a@x.com>,<b@y.com>,<c@z.com>");
    let list = ContentIdParser::parse_list(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert_eq!(list.len(), 3);
}

#[test]
fn test_parse_list_with_comments() {
    let mut cursor = ByteCursor::new(b"(comment) <id@host.com> (another)");
    let list = ContentIdParser::parse_list(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].local_part(), "id");
    assert_eq!(list[0].domain(), "host.com");
}

#[test]
fn test_parse_list_malformed_unclosed_angle() {
    let mut cursor = ByteCursor::new(b"<a@b.com> <unclosed@domain");
    let list = ContentIdParser::parse_list(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].local_part(), "a");
}

#[test]
fn test_parse_list_stops_at_non_angle() {
    let mut cursor = ByteCursor::new(b"<valid@x.com> garbage <also@y.com>");
    let list = ContentIdParser::parse_list(&mut cursor, HeaderCharset::Iso88591).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].local_part(), "valid");
}
