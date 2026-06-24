use rmimeparser::{Address, ByteCursor, EmailAddressParser, HeaderCharset};

#[test]
fn test_parse_envelope_address_simple() {
    let addr = EmailAddressParser::parse_envelope_address("user@example.com").unwrap();
    assert_eq!(addr.local_part(), "user");
    assert_eq!(addr.domain(), "example.com");
    assert_eq!(addr.display_name(), None);
}

#[test]
fn test_parse_envelope_address_no_at() {
    assert!(EmailAddressParser::parse_envelope_address("userexample.com").is_none());
}

#[test]
fn test_parse_envelope_address_utf8_local_part() {
    assert!(
        EmailAddressParser::parse_envelope_address_smtp_utf8("用户@example.com", false).is_none()
    );
    let addr =
        EmailAddressParser::parse_envelope_address_smtp_utf8("用户@example.com", true).unwrap();
    assert_eq!(addr.local_part(), "用户");
    assert_eq!(addr.domain(), "example.com");
}

#[test]
fn test_parse_email_address_with_display_name() {
    let addr = EmailAddressParser::parse_email_address("John Doe <john@example.com>").unwrap();
    assert_eq!(addr.display_name(), Some("John Doe"));
    assert_eq!(addr.local_part(), "john");
    assert_eq!(addr.domain(), "example.com");
}

#[test]
fn test_parse_email_address_list_empty() {
    let addrs = EmailAddressParser::parse_email_address_list("").unwrap();
    assert!(addrs.is_empty());
}

#[test]
fn test_parse_email_address_list_multiple() {
    let addrs = EmailAddressParser::parse_email_address_list(
        "user1@example.com, user2@example.com, user3@example.com",
    )
    .unwrap();
    assert_eq!(addrs.len(), 3);
    assert_eq!(addrs[0].as_mailbox().unwrap().local_part(), "user1");
    assert_eq!(addrs[1].as_mailbox().unwrap().local_part(), "user2");
    assert_eq!(addrs[2].as_mailbox().unwrap().local_part(), "user3");
}

#[test]
fn test_parse_group_address() {
    let addrs = EmailAddressParser::parse_email_address_list(
        "Team: user1@example.com, user2@example.com;",
    )
    .unwrap();
    assert_eq!(addrs.len(), 1);
    match &addrs[0] {
        Address::Group(group) => {
            assert_eq!(group.group_name(), "Team");
            assert_eq!(group.members().len(), 2);
        }
        Address::Mailbox(_) => panic!("expected group"),
    }
}

#[test]
fn test_parse_group_address_empty() {
    let addrs = EmailAddressParser::parse_email_address_list("EmptyGroup:;").unwrap();
    assert_eq!(addrs.len(), 1);
    match &addrs[0] {
        Address::Group(group) => {
            assert_eq!(group.group_name(), "EmptyGroup");
            assert!(group.members().is_empty());
        }
        Address::Mailbox(_) => panic!("expected group"),
    }
}

#[test]
fn test_parse_email_address_list_byte_buffer_quoted_display_name() {
    let value = b"\"Smith, Alice\" <alice@example.com>";
    let mut cursor = ByteCursor::new(value);
    let addrs =
        EmailAddressParser::parse_email_address_list_bytes(&mut cursor, HeaderCharset::Iso88591)
            .unwrap();
    assert_eq!(
        addrs[0].as_mailbox().unwrap().display_name(),
        Some("Smith, Alice")
    );
}

#[test]
fn test_parse_email_address_list_byte_buffer_bare_addr_spec() {
    let value = b" user0@example.com,\tuser1@example.com,\tuser2@example.com";
    let mut cursor = ByteCursor::new(value);
    let addrs =
        EmailAddressParser::parse_email_address_list_bytes(&mut cursor, HeaderCharset::Iso88591)
            .unwrap();
    assert_eq!(addrs.len(), 3);
    assert_eq!(addrs[0].as_mailbox().unwrap().local_part(), "user0");
    assert_eq!(addrs[1].as_mailbox().unwrap().local_part(), "user1");
    assert_eq!(addrs[2].as_mailbox().unwrap().local_part(), "user2");
}
