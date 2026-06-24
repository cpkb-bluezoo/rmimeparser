use rmimeparser::ContentId;

#[test]
fn test_constructor() {
    let cid = ContentId::new("abc123", "example.com");
    assert_eq!(cid.local_part(), "abc123");
    assert_eq!(cid.domain(), "example.com");
}

#[test]
fn test_to_string() {
    let cid = ContentId::new("image001", "mail.example.com");
    assert_eq!(cid.to_string(), "<image001@mail.example.com>");
}

#[test]
fn test_equals() {
    let cid1 = ContentId::new("abc123", "example.com");
    let cid2 = ContentId::new("abc123", "example.com");
    assert_eq!(cid1, cid2);
}

#[test]
fn test_not_equals_different_local_part() {
    let cid1 = ContentId::new("abc123", "example.com");
    let cid2 = ContentId::new("xyz789", "example.com");
    assert_ne!(cid1, cid2);
}

#[test]
fn test_not_equals_different_domain() {
    let cid1 = ContentId::new("abc123", "example.com");
    let cid2 = ContentId::new("abc123", "other.com");
    assert_ne!(cid1, cid2);
}

#[test]
fn test_hash_code() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let cid1 = ContentId::new("abc123", "example.com");
    let cid2 = ContentId::new("abc123", "example.com");
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    cid1.hash(&mut h1);
    cid2.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn test_typical_message_id() {
    let cid = ContentId::new("CAKzMBDA8yFFaKE+abc123@mail.gmail.com", "mail.gmail.com");
    assert_eq!(cid.local_part(), "CAKzMBDA8yFFaKE+abc123@mail.gmail.com");
    assert_eq!(cid.domain(), "mail.gmail.com");
}

#[test]
fn test_content_id_with_numbers() {
    let cid = ContentId::new("part1.E72C5B26.B8F21A30", "example.com");
    assert_eq!(cid.local_part(), "part1.E72C5B26.B8F21A30");
    assert_eq!(cid.domain(), "example.com");
}

#[test]
fn test_local_part_with_special_chars() {
    let cid = ContentId::new("user+tag.name", "example.com");
    assert_eq!(cid.local_part(), "user+tag.name");
}
