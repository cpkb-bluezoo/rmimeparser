use rmimeparser::ContentTypeParser;

#[test]
fn test_parse_simple() {
    let ct = ContentTypeParser::parse_str("text/plain").unwrap();
    assert_eq!(ct.primary_type(), "text");
    assert_eq!(ct.sub_type(), "plain");
    assert!(ct.parameters().is_none());
}

#[test]
fn test_parse_with_charset() {
    let ct = ContentTypeParser::parse_str("text/html; charset=utf-8").unwrap();
    assert_eq!(ct.primary_type(), "text");
    assert_eq!(ct.sub_type(), "html");
    assert_eq!(ct.get_parameter("charset"), Some("utf-8"));
}

#[test]
fn test_parse_with_quoted_parameter() {
    let ct =
        ContentTypeParser::parse_str("multipart/form-data; boundary=\"----=_Part_123\"").unwrap();
    assert_eq!(ct.primary_type(), "multipart");
    assert_eq!(ct.sub_type(), "form-data");
    assert_eq!(ct.get_parameter("boundary"), Some("----=_Part_123"));
}

#[test]
fn test_parse_multiple_parameters() {
    let ct = ContentTypeParser::parse_str(
        "text/plain; charset=utf-8; format=flowed; delsp=yes",
    )
    .unwrap();
    assert_eq!(ct.get_parameter("charset"), Some("utf-8"));
    assert_eq!(ct.get_parameter("format"), Some("flowed"));
    assert_eq!(ct.get_parameter("delsp"), Some("yes"));
}

#[test]
fn test_parse_with_whitespace() {
    let ct = ContentTypeParser::parse_str("  text/plain  ;  charset = utf-8  ").unwrap();
    assert_eq!(ct.primary_type(), "text");
    assert_eq!(ct.sub_type(), "plain");
    assert_eq!(ct.get_parameter("charset"), Some("utf-8"));
}

#[test]
fn test_parse_quoted_parameter_with_escapes() {
    let ct =
        ContentTypeParser::parse_str("text/plain; filename=\"test\\\"file\\\\.txt\"").unwrap();
    assert_eq!(ct.get_parameter("filename"), Some("test\"file\\.txt"));
}

#[test]
fn test_parse_null_returns_null() {
    assert!(ContentTypeParser::parse_str("").is_none());
}

#[test]
fn test_parse_empty_returns_null() {
    assert!(ContentTypeParser::parse_str("").is_none());
}

#[test]
fn test_parse_missing_subtype() {
    assert!(ContentTypeParser::parse_str("text").is_none());
}

#[test]
fn test_parse_missing_slash() {
    assert!(ContentTypeParser::parse_str("textplain").is_none());
}

#[test]
fn test_parse_case_preservation() {
    let ct = ContentTypeParser::parse_str("Text/HTML; Charset=UTF-8").unwrap();
    assert!(ct.is_mime_type("text", "html"));
    assert_eq!(ct.get_parameter("Charset"), Some("UTF-8"));
}

#[test]
fn test_parse_multipart_mixed() {
    let ct = ContentTypeParser::parse_str(
        "multipart/mixed; boundary=\"----=_NextPart_000_0000_01D12345.6789ABCD\"",
    )
    .unwrap();
    assert!(ct.is_mime_type("multipart", "mixed"));
    assert_eq!(
        ct.get_parameter("boundary"),
        Some("----=_NextPart_000_0000_01D12345.6789ABCD")
    );
}

#[test]
fn test_parse_application_json() {
    let ct = ContentTypeParser::parse_str("application/json; charset=utf-8").unwrap();
    assert!(ct.is_mime_type("application", "json"));
    assert_eq!(ct.get_parameter("charset"), Some("utf-8"));
}

#[test]
fn test_parse_image_with_metadata() {
    let ct = ContentTypeParser::parse_str("image/jpeg; name=\"photo.jpg\"").unwrap();
    assert!(ct.is_mime_type("image", "jpeg"));
    assert_eq!(ct.get_parameter("name"), Some("photo.jpg"));
}

#[test]
fn test_parse_subtype_with_plus() {
    let ct = ContentTypeParser::parse_str("application/vnd.api+json").unwrap();
    assert_eq!(ct.primary_type(), "application");
    assert_eq!(ct.sub_type(), "vnd.api+json");
}

#[test]
fn test_parse_subtype_with_dot() {
    let ct = ContentTypeParser::parse_str("application/vnd.ms-excel").unwrap();
    assert_eq!(ct.primary_type(), "application");
    assert_eq!(ct.sub_type(), "vnd.ms-excel");
}

#[test]
fn test_parse_rfc2047_encoded_parameter() {
    let ct = ContentTypeParser::parse_str("text/plain; name=\"=?UTF-8?B?dGVzdC50eHQ=?=\"").unwrap();
    assert_eq!(ct.get_parameter("name"), Some("test.txt"));
}

#[test]
fn test_parse_unquoted_boundary() {
    let ct = ContentTypeParser::parse_str("multipart/form-data; boundary=simpleboundary").unwrap();
    assert_eq!(ct.get_parameter("boundary"), Some("simpleboundary"));
}
