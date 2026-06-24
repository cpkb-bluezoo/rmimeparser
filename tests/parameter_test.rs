use rmimeparser::Parameter;

#[test]
fn test_constructor() {
    let p = Parameter::new("charset", "utf-8");
    assert_eq!(p.name(), "charset");
    assert_eq!(p.value(), "utf-8");
}

#[test]
fn test_equals() {
    let p1 = Parameter::new("charset", "utf-8");
    let p2 = Parameter::new("charset", "utf-8");
    assert_eq!(p1, p2);
}

#[test]
fn test_equals_name_case_insensitive() {
    let p1 = Parameter::new("charset", "utf-8");
    let p2 = Parameter::new("CHARSET", "utf-8");
    assert_eq!(p1, p2);
}

#[test]
fn test_not_equals_different_name() {
    let p1 = Parameter::new("charset", "utf-8");
    let p2 = Parameter::new("boundary", "utf-8");
    assert_ne!(p1, p2);
}

#[test]
fn test_not_equals_different_value() {
    let p1 = Parameter::new("charset", "utf-8");
    let p2 = Parameter::new("charset", "iso-8859-1");
    assert_ne!(p1, p2);
}

#[test]
fn test_hash_code() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let p1 = Parameter::new("charset", "utf-8");
    let p2 = Parameter::new("charset", "utf-8");
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    p1.hash(&mut h1);
    p2.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn test_hash_code_case_insensitive_name() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let p1 = Parameter::new("charset", "utf-8");
    let p2 = Parameter::new("CHARSET", "utf-8");
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    p1.hash(&mut h1);
    p2.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn test_to_string() {
    let p = Parameter::new("charset", "utf-8");
    let s = p.to_string();
    assert!(s.contains("charset"));
    assert!(s.contains("utf-8"));
}

#[test]
fn test_to_string_with_special_chars() {
    let p = Parameter::new("boundary", "----=_Part_123");
    let s = p.to_string();
    assert!(s.contains("boundary"));
}

#[test]
#[should_panic(expected = "value must not be null")]
fn test_null_value_throws() {
    Parameter::maybe_new(Some("name"), None::<String>);
}

#[test]
#[should_panic(expected = "name must not be null")]
fn test_null_name_throws() {
    Parameter::maybe_new(None::<String>, Some("value"));
}

#[test]
fn test_empty_value() {
    let p = Parameter::new("name", "");
    assert_eq!(p.name(), "name");
    assert_eq!(p.value(), "");
}
