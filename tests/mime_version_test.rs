use rmimeparser::MimeVersion;

#[test]
fn test_version10() {
    let version = MimeVersion::VERSION_1_0;
    assert_eq!(version.to_string(), "1.0");
}

#[test]
fn test_parse10() {
    let version = MimeVersion::parse("1.0").unwrap();
    assert_eq!(version, MimeVersion::VERSION_1_0);
}

#[test]
fn test_parse_with_whitespace() {
    let version = MimeVersion::parse("  1.0  ").unwrap();
    assert_eq!(version, MimeVersion::VERSION_1_0);
}

#[test]
fn test_parse_unknown() {
    assert!(MimeVersion::parse("2.0").is_none());
}

#[test]
fn test_parse_null() {
    assert!(MimeVersion::parse("").is_none());
}

#[test]
fn test_parse_empty() {
    assert!(MimeVersion::parse("").is_none());
}

#[test]
fn test_parse_invalid() {
    assert!(MimeVersion::parse("not a version").is_none());
}

#[test]
fn test_parse_with_comment() {
    assert!(MimeVersion::parse("1.0 (produced by Outlook)").is_none());
}
