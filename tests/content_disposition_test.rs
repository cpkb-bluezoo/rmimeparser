use rmimeparser::{ContentDisposition, Parameter};

#[test]
fn test_simple_disposition() {
    let cd = ContentDisposition::new("attachment", None);
    assert_eq!(cd.disposition_type(), "attachment");
    assert!(cd.parameters().is_none());
}

#[test]
fn test_disposition_with_filename() {
    let cd = ContentDisposition::new(
        "attachment",
        Some(vec![Parameter::new("filename", "document.pdf")]),
    );
    assert_eq!(cd.disposition_type(), "attachment");
    assert_eq!(cd.get_parameter("filename"), Some("document.pdf"));
}

#[test]
fn test_form_data_disposition() {
    let cd = ContentDisposition::new(
        "form-data",
        Some(vec![
            Parameter::new("name", "field1"),
            Parameter::new("filename", "upload.txt"),
        ]),
    );
    assert_eq!(cd.disposition_type(), "form-data");
    assert_eq!(cd.get_parameter("name"), Some("field1"));
    assert_eq!(cd.get_parameter("filename"), Some("upload.txt"));
}

#[test]
fn test_is_disposition_type() {
    let cd = ContentDisposition::new("attachment", None);
    assert!(cd.is_disposition_type("attachment"));
    assert!(cd.is_disposition_type("ATTACHMENT"));
    assert!(cd.is_disposition_type("Attachment"));
    assert!(!cd.is_disposition_type("inline"));
}

#[test]
fn test_inline_disposition() {
    let cd = ContentDisposition::new("inline", None);
    assert!(cd.is_disposition_type("inline"));
    assert!(!cd.is_disposition_type("attachment"));
}

#[test]
fn test_parameter_case_insensitive() {
    let cd = ContentDisposition::new(
        "attachment",
        Some(vec![Parameter::new("FileName", "test.txt")]),
    );
    assert_eq!(cd.get_parameter("filename"), Some("test.txt"));
    assert_eq!(cd.get_parameter("FILENAME"), Some("test.txt"));
    assert_eq!(cd.get_parameter("FileName"), Some("test.txt"));
}

#[test]
fn test_has_parameter() {
    let cd = ContentDisposition::new(
        "attachment",
        Some(vec![Parameter::new("filename", "test.txt")]),
    );
    assert!(cd.has_parameter("filename"));
    assert!(cd.has_parameter("FILENAME"));
    assert!(!cd.has_parameter("name"));
}

#[test]
fn test_get_missing_parameter() {
    let cd = ContentDisposition::new("attachment", None);
    assert!(cd.get_parameter("filename").is_none());
}

#[test]
fn test_multiple_parameters() {
    let cd = ContentDisposition::new(
        "attachment",
        Some(vec![
            Parameter::new("filename", "report.pdf"),
            Parameter::new("creation-date", "\"Wed, 12 Feb 1997 16:29:51 -0500\""),
            Parameter::new("size", "12345"),
        ]),
    );
    assert_eq!(cd.get_parameter("filename"), Some("report.pdf"));
    assert!(cd.get_parameter("creation-date").is_some());
    assert_eq!(cd.get_parameter("size"), Some("12345"));
}

#[test]
fn test_to_string() {
    let cd = ContentDisposition::new("attachment", None);
    assert_eq!(cd.to_string(), "attachment");
}

#[test]
fn test_to_string_with_filename() {
    let cd = ContentDisposition::new(
        "attachment",
        Some(vec![Parameter::new("filename", "test.txt")]),
    );
    let s = cd.to_string();
    assert!(s.starts_with("attachment"));
    assert!(s.contains("filename"));
}

#[test]
fn test_equals() {
    let cd1 = ContentDisposition::new("attachment", None);
    let cd2 = ContentDisposition::new("attachment", None);
    let cd3 = ContentDisposition::new("ATTACHMENT", None);
    assert_eq!(cd1, cd2);
    assert_eq!(cd1, cd3);
}

#[test]
fn test_not_equals() {
    let cd1 = ContentDisposition::new("attachment", None);
    let cd2 = ContentDisposition::new("inline", None);
    assert_ne!(cd1, cd2);
}

#[test]
fn test_hash_code() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let cd1 = ContentDisposition::new("attachment", None);
    let cd2 = ContentDisposition::new("attachment", None);
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    cd1.hash(&mut h1);
    cd2.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn test_get_parameters_returns_unmodifiable_list() {
    let cd = ContentDisposition::new(
        "attachment",
        Some(vec![Parameter::new("filename", "test.txt")]),
    );
    let params = cd.parameters().unwrap();
    assert_eq!(params.len(), 1);
}
