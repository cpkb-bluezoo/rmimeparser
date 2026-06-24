use rmimeparser::ContentDispositionParser;

#[test]
fn test_parse_simple_attachment() {
    let cd = ContentDispositionParser::parse_str("attachment").unwrap();
    assert!(cd.is_disposition_type("attachment"));
    assert!(cd.parameters().is_none());
}

#[test]
fn test_parse_simple_inline() {
    let cd = ContentDispositionParser::parse_str("inline").unwrap();
    assert!(cd.is_disposition_type("inline"));
}

#[test]
fn test_parse_form_data() {
    let cd = ContentDispositionParser::parse_str("form-data; name=\"field1\"").unwrap();
    assert!(cd.is_disposition_type("form-data"));
    assert_eq!(cd.get_parameter("name"), Some("field1"));
}

#[test]
fn test_parse_with_filename() {
    let cd = ContentDispositionParser::parse_str("attachment; filename=\"document.pdf\"").unwrap();
    assert!(cd.is_disposition_type("attachment"));
    assert_eq!(cd.get_parameter("filename"), Some("document.pdf"));
}

#[test]
fn test_parse_with_unquoted_filename() {
    let cd = ContentDispositionParser::parse_str("attachment; filename=document.pdf").unwrap();
    assert_eq!(cd.get_parameter("filename"), Some("document.pdf"));
}

#[test]
fn test_parse_form_data_with_filename() {
    let cd =
        ContentDispositionParser::parse_str("form-data; name=\"upload\"; filename=\"test.txt\"")
            .unwrap();
    assert!(cd.is_disposition_type("form-data"));
    assert_eq!(cd.get_parameter("name"), Some("upload"));
    assert_eq!(cd.get_parameter("filename"), Some("test.txt"));
}

#[test]
fn test_parse_with_whitespace() {
    let cd =
        ContentDispositionParser::parse_str("  attachment  ;  filename=\"test.txt\"  ").unwrap();
    assert!(cd.is_disposition_type("attachment"));
    assert_eq!(cd.get_parameter("filename"), Some("test.txt"));
}

#[test]
fn test_parse_quoted_filename_with_spaces() {
    let cd =
        ContentDispositionParser::parse_str("attachment; filename=\"my document.pdf\"").unwrap();
    assert_eq!(cd.get_parameter("filename"), Some("my document.pdf"));
}

#[test]
fn test_parse_quoted_filename_with_escapes() {
    let cd =
        ContentDispositionParser::parse_str("attachment; filename=\"test\\\"file.txt\"").unwrap();
    assert_eq!(cd.get_parameter("filename"), Some("test\"file.txt"));
}

#[test]
fn test_parse_null_returns_null() {
    assert!(ContentDispositionParser::parse_str("").is_none());
}

#[test]
fn test_parse_empty_returns_null() {
    assert!(ContentDispositionParser::parse_str("").is_none());
}

#[test]
fn test_parse_multiple_parameters() {
    let cd = ContentDispositionParser::parse_str(
        "attachment; filename=\"report.pdf\"; creation-date=\"Wed, 12 Feb 1997 16:29:51 -0500\"; size=12345",
    )
    .unwrap();
    assert_eq!(cd.get_parameter("filename"), Some("report.pdf"));
    assert!(cd.get_parameter("creation-date").is_some());
    assert_eq!(cd.get_parameter("size"), Some("12345"));
}

#[test]
fn test_parse_rfc2047_encoded_filename() {
    let cd =
        ContentDispositionParser::parse_str("attachment; filename=\"=?UTF-8?B?dGVzdC50eHQ=?=\"").unwrap();
    assert_eq!(cd.get_parameter("filename"), Some("test.txt"));
}

#[test]
fn test_parse_case_preservation() {
    let cd = ContentDispositionParser::parse_str("Attachment; FileName=\"Test.TXT\"").unwrap();
    assert!(cd.is_disposition_type("attachment"));
    assert_eq!(cd.get_parameter("filename"), Some("Test.TXT"));
}

#[test]
fn test_parse_filename_with_path() {
    let cd = ContentDispositionParser::parse_str(
        "attachment; filename=\"C:\\\\Users\\\\test\\\\document.pdf\"",
    )
    .unwrap();
    assert_eq!(cd.get_parameter("filename"), Some("C:\\Users\\test\\document.pdf"));
}

#[test]
fn test_parse_international_filename() {
    let cd = ContentDispositionParser::parse_str(
        "attachment; filename*=UTF-8''%E6%97%A5%E6%9C%AC%E8%AA%9E.txt",
    )
    .unwrap();
    assert_eq!(cd.get_parameter("filename"), Some("日本語.txt"));
}
