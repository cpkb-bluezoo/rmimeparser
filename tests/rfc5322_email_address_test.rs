use rmimeparser::EmailAddress;

#[test]
fn test_simple_address() {
    let addr = EmailAddress::new(None, "user", "example.com", true);
    assert_eq!(addr.display_name(), None);
    assert_eq!(addr.local_part(), "user");
    assert_eq!(addr.domain(), "example.com");
    assert_eq!(addr.address(), "user@example.com");
    assert_eq!(addr.comments(), None);
}

#[test]
fn test_address_with_display_name() {
    let addr = EmailAddress::new(Some("John Doe".into()), "john", "example.com", false);
    assert_eq!(addr.display_name(), Some("John Doe"));
    assert_eq!(addr.address(), "john@example.com");
}

#[test]
fn test_address_with_comments() {
    let addr = EmailAddress::with_comments(
        Some("Jane Smith".into()),
        "jane",
        "example.com",
        vec!["Work".into(), "Primary".into()],
    );
    assert_eq!(addr.display_name(), Some("Jane Smith"));
    assert_eq!(addr.address(), "jane@example.com");
    let comments = addr.comments().unwrap();
    assert_eq!(comments.len(), 2);
    assert!(comments.contains(&"Work".to_string()));
    assert!(comments.contains(&"Primary".to_string()));
}

#[test]
fn test_simple_address_flag() {
    let simple = EmailAddress::new(None, "user", "example.com", true);
    assert!(simple.is_simple_address());
    let not_simple = EmailAddress::new(None, "user", "example.com", false);
    assert!(!not_simple.is_simple_address());
}

#[test]
fn test_to_string_with_display_name() {
    let addr = EmailAddress::new(Some("John Doe".into()), "john", "example.com", false);
    let s = addr.to_string();
    assert!(s.contains("John Doe"));
    assert!(s.contains("john@example.com"));
}

#[test]
fn test_equals_case_insensitive_domain() {
    let addr1 = EmailAddress::new(Some("John".into()), "john", "example.com", false);
    let addr2 = EmailAddress::new(Some("John".into()), "john", "EXAMPLE.COM", false);
    assert_eq!(addr1, addr2);
}

#[test]
fn test_not_equals_local_part_case_sensitive() {
    let addr1 = EmailAddress::new(None, "john", "example.com", true);
    let addr2 = EmailAddress::new(None, "John", "example.com", true);
    assert_ne!(addr1, addr2);
}
