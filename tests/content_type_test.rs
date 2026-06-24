use rmimeparser::{ContentType, Parameter};

#[test]
fn test_simple_content_type() {
    let ct = ContentType::new("text", "plain", None);
    assert_eq!(ct.primary_type(), "text");
    assert_eq!(ct.sub_type(), "plain");
    assert!(ct.parameters().is_none());
}

#[test]
fn test_content_type_with_charset() {
    let ct = ContentType::new(
        "text",
        "plain",
        Some(vec![Parameter::new("charset", "utf-8")]),
    );
    assert_eq!(ct.primary_type(), "text");
    assert_eq!(ct.sub_type(), "plain");
    assert_eq!(ct.get_parameter("charset"), Some("utf-8"));
}

#[test]
fn test_is_primary_type() {
    let ct = ContentType::new("text", "html", None);
    assert!(ct.is_primary_type("text"));
    assert!(ct.is_primary_type("TEXT"));
    assert!(ct.is_primary_type("Text"));
    assert!(!ct.is_primary_type("image"));
}

#[test]
fn test_is_sub_type() {
    let ct = ContentType::new("text", "html", None);
    assert!(ct.is_sub_type("html"));
    assert!(ct.is_sub_type("HTML"));
    assert!(ct.is_sub_type("Html"));
    assert!(!ct.is_sub_type("plain"));
}

#[test]
fn test_is_mime_type_two_args() {
    let ct = ContentType::new("application", "json", None);
    assert!(ct.is_mime_type("application", "json"));
    assert!(ct.is_mime_type("APPLICATION", "JSON"));
    assert!(!ct.is_mime_type("application", "xml"));
    assert!(!ct.is_mime_type("text", "json"));
}

#[test]
fn test_is_mime_type_one_arg() {
    let ct = ContentType::new("multipart", "form-data", None);
    assert!(ct.is_mime_type_str("multipart/form-data"));
    assert!(ct.is_mime_type_str("MULTIPART/FORM-DATA"));
    assert!(ct.is_mime_type_str("Multipart/Form-Data"));
    assert!(!ct.is_mime_type_str("multipart/mixed"));
    assert!(!ct.is_mime_type_str("text/plain"));
}

#[test]
fn test_is_mime_type_invalid_format() {
    let ct = ContentType::new("text", "plain", None);
    assert!(!ct.is_mime_type_str("textplain"));
    assert!(!ct.is_mime_type_str("text/"));
    assert!(!ct.is_mime_type_str("/plain"));
}

#[test]
fn test_multiple_parameters() {
    let ct = ContentType::new(
        "multipart",
        "mixed",
        Some(vec![
            Parameter::new("charset", "utf-8"),
            Parameter::new("boundary", "----=_Part_123"),
            Parameter::new("format", "flowed"),
        ]),
    );
    assert_eq!(ct.get_parameter("charset"), Some("utf-8"));
    assert_eq!(ct.get_parameter("boundary"), Some("----=_Part_123"));
    assert_eq!(ct.get_parameter("format"), Some("flowed"));
}

#[test]
fn test_parameter_case_insensitive() {
    let ct = ContentType::new(
        "text",
        "plain",
        Some(vec![Parameter::new("CharSet", "utf-8")]),
    );
    assert_eq!(ct.get_parameter("charset"), Some("utf-8"));
    assert_eq!(ct.get_parameter("CHARSET"), Some("utf-8"));
    assert_eq!(ct.get_parameter("CharSet"), Some("utf-8"));
}

#[test]
fn test_has_parameter() {
    let ct = ContentType::new(
        "text",
        "plain",
        Some(vec![Parameter::new("charset", "utf-8")]),
    );
    assert!(ct.has_parameter("charset"));
    assert!(ct.has_parameter("CHARSET"));
    assert!(!ct.has_parameter("boundary"));
}

#[test]
fn test_get_missing_parameter() {
    let ct = ContentType::new("text", "plain", None);
    assert!(ct.get_parameter("charset").is_none());
}

#[test]
fn test_to_string() {
    let ct = ContentType::new("text", "plain", None);
    assert_eq!(ct.to_string(), "text/plain");
}

#[test]
fn test_to_string_with_parameters() {
    let ct = ContentType::new(
        "text",
        "plain",
        Some(vec![
            Parameter::new("charset", "utf-8"),
            Parameter::new("format", "flowed"),
        ]),
    );
    let s = ct.to_string();
    assert!(s.starts_with("text/plain"));
    assert!(s.contains("charset=utf-8"));
}

#[test]
fn test_equals() {
    let ct1 = ContentType::new("text", "plain", None);
    let ct2 = ContentType::new("text", "plain", None);
    let ct3 = ContentType::new("TEXT", "PLAIN", None);
    assert_eq!(ct1, ct2);
    assert_eq!(ct1, ct3);
}

#[test]
fn test_not_equals() {
    let ct1 = ContentType::new("text", "plain", None);
    let ct2 = ContentType::new("text", "html", None);
    let ct3 = ContentType::new("image", "plain", None);
    assert_ne!(ct1, ct2);
    assert_ne!(ct1, ct3);
}

#[test]
fn test_equals_with_parameters() {
    let ct1 = ContentType::new(
        "text",
        "plain",
        Some(vec![Parameter::new("charset", "utf-8")]),
    );
    let ct2 = ContentType::new(
        "text",
        "plain",
        Some(vec![Parameter::new("charset", "utf-8")]),
    );
    assert_eq!(ct1, ct2);
}

#[test]
fn test_hash_code() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let ct1 = ContentType::new("text", "plain", None);
    let ct2 = ContentType::new("text", "plain", None);
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    ct1.hash(&mut h1);
    ct2.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn test_common_types() {
    let text_plain = ContentType::new("text", "plain", None);
    assert!(text_plain.is_mime_type("text", "plain"));

    let text_html = ContentType::new("text", "html", None);
    assert!(text_html.is_primary_type("text"));

    let app_json = ContentType::new("application", "json", None);
    assert!(app_json.is_primary_type("application"));

    let multipart = ContentType::new("multipart", "mixed", None);
    assert!(multipart.is_primary_type("multipart"));

    let image_png = ContentType::new("image", "png", None);
    assert!(image_png.is_primary_type("image"));
}

#[test]
fn test_duplicate_parameters() {
    let ct = ContentType::new(
        "text",
        "plain",
        Some(vec![
            Parameter::new("charset", "utf-8"),
            Parameter::new("charset", "iso-8859-1"),
        ]),
    );
    assert_eq!(ct.get_parameter("charset"), Some("utf-8"));
}

#[test]
fn test_get_parameters_returns_unmodifiable_list() {
    let ct = ContentType::new(
        "text",
        "plain",
        Some(vec![Parameter::new("charset", "utf-8")]),
    );
    let params = ct.parameters().unwrap();
    assert_eq!(params.len(), 1);
}
