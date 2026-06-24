use rmimeparser::{
    decode_slice, index_of, ContentDisposition, ContentType, HeaderLineTooLongError,
    HeaderValueTooLongError, MimeHandler, MimeParseError, MimeParser, MimeVersion, ParseResult,
};

struct TestHandler {
    events: Vec<String>,
    content_type: Option<ContentType>,
    content_disposition: Option<ContentDisposition>,
    content_transfer_encoding: Option<String>,
    mime_version: Option<MimeVersion>,
    body: Vec<u8>,
    entity_count: usize,
}

impl TestHandler {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            content_type: None,
            content_disposition: None,
            content_transfer_encoding: None,
            mime_version: None,
            body: Vec::new(),
            entity_count: 0,
        }
    }
}

impl MimeHandler for TestHandler {
    fn set_locator(&mut self, _locator: &rmimeparser::MimeLocator) -> ParseResult<()> {
        self.events.push("setLocator".to_string());
        Ok(())
    }

    fn start_entity(&mut self, boundary: Option<&str>) -> ParseResult<()> {
        self.events
            .push(format!("startEntity:{}", boundary.unwrap_or("null")));
        self.entity_count += 1;
        Ok(())
    }

    fn content_type(&mut self, content_type: &ContentType) -> ParseResult<()> {
        self.events.push(format!("contentType:{content_type}"));
        self.content_type = Some(content_type.clone());
        Ok(())
    }

    fn content_disposition(&mut self, disposition: &ContentDisposition) -> ParseResult<()> {
        self.events
            .push(format!("contentDisposition:{disposition}"));
        self.content_disposition = Some(disposition.clone());
        Ok(())
    }

    fn content_transfer_encoding(&mut self, encoding: &str) -> ParseResult<()> {
        self.events
            .push(format!("contentTransferEncoding:{encoding}"));
        self.content_transfer_encoding = Some(encoding.to_string());
        Ok(())
    }

    fn mime_version(&mut self, version: MimeVersion) -> ParseResult<()> {
        self.events.push(format!("mimeVersion:{version}"));
        self.mime_version = Some(version);
        Ok(())
    }

    fn end_headers(&mut self) -> ParseResult<()> {
        self.events.push("endHeaders".to_string());
        Ok(())
    }

    fn body_content(&mut self, data: &[u8]) -> ParseResult<()> {
        self.body.extend_from_slice(data);
        self.events.push("bodyContent".to_string());
        Ok(())
    }

    fn unexpected_content(&mut self, _data: &[u8]) -> ParseResult<()> {
        self.events.push("unexpectedContent".to_string());
        Ok(())
    }

    fn end_entity(&mut self, boundary: Option<&str>) -> ParseResult<()> {
        self.events
            .push(format!("endEntity:{}", boundary.unwrap_or("null")));
        Ok(())
    }
}

fn parse(parser: &mut MimeParser<'_, TestHandler>, content: &str) -> ParseResult<()> {
    let mut input = content.as_bytes();
    parser.receive(&mut input)?;
    parser.close()
}

fn parse_with_compact(parser: &mut MimeParser<'_, TestHandler>, chunks: &[&[u8]]) -> ParseResult<()> {
    let mut buffer = Vec::with_capacity(256);
    for chunk in chunks {
        buffer.extend_from_slice(chunk);
        let mut slice = buffer.as_slice();
        parser.receive(&mut slice)?;
        buffer = slice.to_vec();
    }
    assert!(
        !parser.is_underflow(),
        "Parser has unconsumed data at EOF"
    );
    parser.close()
}

fn split_at(content: &str, positions: &[usize]) -> Vec<Vec<u8>> {
    let bytes = content.as_bytes();
    let mut result = Vec::with_capacity(positions.len() + 1);
    let mut prev = 0usize;
    for &pos in positions {
        result.push(bytes[prev..pos].to_vec());
        prev = pos;
    }
    result.push(bytes[prev..].to_vec());
    result
}

fn body_string(handler: &TestHandler) -> String {
    String::from_utf8_lossy(&handler.body).into_owned()
}

#[test]
fn test_simple_entity() {
    let content = "Content-Type: text/plain\r\n\r\nHello, World!\r\n";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parse(&mut parser, content).unwrap();

    assert!(handler.events.iter().any(|e| e == "startEntity:null"));
    assert!(handler
        .events
        .iter()
        .any(|e| e.starts_with("contentType:text/plain")));
    assert!(handler.events.iter().any(|e| e == "endHeaders"));
    assert!(handler.events.iter().any(|e| e == "bodyContent"));
    assert!(handler.events.iter().any(|e| e == "endEntity:null"));
    assert_eq!(body_string(&handler), "Hello, World!\r\n");
}

#[test]
fn test_content_type_with_charset() {
    let content = "Content-Type: text/html; charset=utf-8\r\n\r\n<html>Test</html>";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parse(&mut parser, content).unwrap();

    let ct = handler.content_type.as_ref().unwrap();
    assert!(ct.is_mime_type("text", "html"));
    assert_eq!(ct.parameter("charset"), Some("utf-8"));
}

#[test]
fn test_content_disposition() {
    let content = "Content-Disposition: attachment; filename=\"report.pdf\"\r\n\r\nPDF content";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parse(&mut parser, content).unwrap();

    let cd = handler.content_disposition.as_ref().unwrap();
    assert!(cd.is_disposition_type("attachment"));
    assert_eq!(cd.parameter("filename"), Some("report.pdf"));
}

#[test]
fn test_content_transfer_encoding() {
    let content = "Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8=";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parse(&mut parser, content).unwrap();

    assert_eq!(
        handler.content_transfer_encoding.as_deref(),
        Some("base64")
    );
}

#[test]
fn test_decode_token_header_value_simple() {
    let mut handler = TestHandler::new();
    let parser = MimeParser::new(&mut handler);
    let mut buf = b"base64".as_slice();
    assert_eq!(parser.decode_token_header_value(&mut buf), "base64");
    assert!(buf.is_empty());
}

#[test]
fn test_decode_token_header_value_with_folding() {
    let mut handler = TestHandler::new();
    let parser = MimeParser::new(&mut handler);
    let mut buf = b"quoted-printable\r\n\t".as_slice();
    assert_eq!(
        parser.decode_token_header_value(&mut buf),
        "quoted-printable"
    );
}

#[test]
fn test_decode_token_header_value_multiple_folds() {
    let mut handler = TestHandler::new();
    let parser = MimeParser::new(&mut handler);
    let mut buf = b"1.0\r\n \r\n ".as_slice();
    assert_eq!(parser.decode_token_header_value(&mut buf), "1.0");
}

#[test]
fn test_decode_slice() {
    let buf = b"text/plain";
    let mut slice1 = &buf[0..4];
    assert_eq!(decode_slice(&mut slice1), "text");
    let mut slice2 = &buf[5..10];
    assert_eq!(decode_slice(&mut slice2), "plain");
    let mut empty = &buf[0..0];
    assert_eq!(decode_slice(&mut empty), "");
}

#[test]
fn test_mime_version() {
    let content = "MIME-Version: 1.0\r\n\r\nBody";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parse(&mut parser, content).unwrap();

    assert_eq!(handler.mime_version, Some(MimeVersion::V1_0));
}

#[test]
fn test_multipart_basic() {
    let content = "Content-Type: multipart/mixed; boundary=boundary123\r\n\r\n\
        --boundary123\r\n\r\nPart 1\r\n--boundary123\r\n\r\n<p>Part 2</p>\r\n--boundary123--\r\n";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parse(&mut parser, content).unwrap();

    assert_eq!(handler.entity_count, 3);
}

#[test]
fn test_empty_body() {
    let content = "Content-Type: text/plain\r\n\r\n";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parse(&mut parser, content).unwrap();

    assert!(handler.events.iter().any(|e| e == "endHeaders"));
    assert_eq!(body_string(&handler), "");
}

#[test]
fn test_no_content_type() {
    let content = "Subject: Test\r\n\r\nPlain text body\r\n";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parse(&mut parser, content).unwrap();

    assert!(handler.events.iter().any(|e| e == "startEntity:null"));
    assert!(handler.events.iter().any(|e| e == "endHeaders"));
    assert!(body_string(&handler).contains("Plain text body"));
}

#[test]
fn test_folded_header() {
    let content = "Content-Type: text/plain;\r\n  charset=utf-8\r\n\r\nBody";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parse(&mut parser, content).unwrap();

    assert_eq!(
        handler.content_type.as_ref().unwrap().parameter("charset"),
        Some("utf-8")
    );
}

#[test]
fn test_header_line_too_long() {
    let mut sb = String::from("X: ");
    while sb.len() < 999 {
        sb.push('a');
    }
    sb.push_str("\r\n\r\n");

    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let err = parse(&mut parser, &sb).unwrap_err();
    assert!(matches!(err, MimeParseError { .. }));
    let _ = HeaderLineTooLongError::new("header line too long", parser.locator());
}

#[test]
fn test_header_value_too_long() {
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parser.set_max_header_value_size(50).unwrap();

    let mut sb = String::from("X: ");
    for _ in 0..49 {
        sb.push('a');
    }
    sb.push_str("\r\n aaaaa\r\n\r\n");

    let err = parse(&mut parser, &sb).unwrap_err();
    let _ = HeaderValueTooLongError::new("too long", parser.locator());
    assert!(err.message().contains("maximum"));
}

#[test]
fn test_reset() {
    let mut handler = TestHandler::new();
    {
        let mut parser = MimeParser::new(&mut handler);
        parse(&mut parser, "Content-Type: text/plain\r\n\r\nFirst").unwrap();
        parser.reset();
    }
    assert_eq!(handler.entity_count, 1);

    handler.entity_count = 0;
    handler.events.clear();
    handler.body.clear();

    let mut parser = MimeParser::new(&mut handler);
    parse(&mut parser, "Content-Type: text/html\r\n\r\n<p>Second</p>").unwrap();
    assert_eq!(handler.entity_count, 1);
    assert!(handler.content_type.as_ref().unwrap().is_mime_type("text", "html"));
}

#[test]
fn test_incremental_parsing() {
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);

    let chunks: Vec<&[u8]> = vec![
        b"Content-Type",
        b": text/plain\r\n",
        b"\r\n",
        b"Hello",
        b", World!\r\n",
    ];
    parse_with_compact(&mut parser, &chunks).unwrap();

    assert!(handler.content_type.is_some());
    assert_eq!(body_string(&handler), "Hello, World!\r\n");
}

#[test]
fn test_split_crlf() {
    let content = "Content-Type: text/plain\r\n\r\nBody\r\n";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[25]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert!(handler.content_type.is_some());
    assert_eq!(
        handler.content_type.as_ref().unwrap().to_string(),
        "text/plain"
    );
    assert_eq!(body_string(&handler), "Body\r\n");
}

#[test]
fn test_split_empty_line_crlf() {
    let content = "Content-Type: text/plain\r\n\r\nBody text\r\n";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[27]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert!(handler.events.iter().any(|e| e == "endHeaders"));
    assert_eq!(body_string(&handler), "Body text\r\n");
}

#[test]
fn test_split_header_name() {
    let content = "Content-Type: text/plain\r\n\r\nBody\r\n";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[4]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert!(handler.content_type.is_some());
}

#[test]
fn test_split_header_value() {
    let content = "Content-Type: text/plain\r\n\r\nBody\r\n";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[19]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert!(handler.content_type.is_some());
}

#[test]
fn test_split_folded_header() {
    let content = "Content-Type: text/plain;\r\n charset=utf-8\r\n\r\nBody\r\n";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[27]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert_eq!(
        handler.content_type.as_ref().unwrap().parameter("charset"),
        Some("utf-8")
    );
}

#[test]
fn test_split_folded_header_mid_continuation() {
    let content = "Content-Type: text/plain;\r\n charset=utf-8\r\n\r\nBody\r\n";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[35]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert_eq!(
        handler.content_type.as_ref().unwrap().parameter("charset"),
        Some("utf-8")
    );
}

#[test]
fn test_split_boundary_dashes() {
    let content = "Content-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\n\r\nPart1\r\n--abc--\r\n";
    let boundary_start = content.find("--abc").unwrap();
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[boundary_start + 1]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert_eq!(handler.entity_count, 2);
}

#[test]
fn test_split_boundary_text() {
    let content = "Content-Type: multipart/mixed; boundary=boundary123\r\n\r\n\
        --boundary123\r\n\r\nPart1\r\n--boundary123--\r\n";
    let boundary_start = content.find("--boundary123").unwrap();
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[boundary_start + 7]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert_eq!(handler.entity_count, 2);
}

#[test]
fn test_split_end_boundary_marker() {
    let content = "Content-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\n\r\nPart\r\n--abc--\r\n";
    let end_boundary = content.rfind("--abc--").unwrap();
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[end_boundary + 6]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert_eq!(handler.entity_count, 2);
    assert!(handler
        .events
        .iter()
        .any(|e| e.contains("endEntity:abc")));
}

#[test]
fn test_split_boundary_crlf() {
    let content = "Content-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\n\r\nPart1\r\n--abc--\r\n";
    let after_boundary = content.find("--abc").unwrap() + 5;
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[after_boundary + 1]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert_eq!(handler.entity_count, 2);
}

#[test]
fn test_split_base64_character() {
    let content = "Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[40]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert_eq!(body_string(&handler).trim(), "Hello");
}

#[test]
fn test_split_base64_padding() {
    let content = "Content-Transfer-Encoding: base64\r\n\r\nSGk=\r\n";
    let padding_pos = content.find('=').unwrap();
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[padding_pos]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert_eq!(body_string(&handler).trim(), "Hi");
}

#[test]
fn test_split_base64_multi_line() {
    let content = "Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8sIFdv\r\ncmxkIQ==\r\n";
    let crlf_pos = content[37..].find("\r\n").unwrap() + 37;
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[crlf_pos + 1]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert_eq!(body_string(&handler).trim(), "Hello, World!");
}

#[test]
fn test_split_quoted_printable_encoded() {
    let content = "Content-Transfer-Encoding: quoted-printable\r\n\r\na=3Db\r\n";
    let encoded_pos = content.find("=3D").unwrap();
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[encoded_pos + 1]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert_eq!(body_string(&handler).trim(), "a=b");
}

#[test]
fn test_split_quoted_printable_hex_digits() {
    let content = "Content-Transfer-Encoding: quoted-printable\r\n\r\na=3Db\r\n";
    let encoded_pos = content.find("=3D").unwrap();
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[encoded_pos + 2]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert_eq!(body_string(&handler).trim(), "a=b");
}

#[test]
fn test_split_quoted_printable_soft_line_break() {
    let content = "Content-Transfer-Encoding: quoted-printable\r\n\r\nHello=\r\nWorld\r\n";
    let soft_break = content.find("=\r\n").unwrap();
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[soft_break + 1]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    let body = body_string(&handler);
    assert!(body.contains("Hello") && body.contains("World"));
}

#[test]
fn test_multiple_split_points() {
    let content = "Content-Type: text/plain\r\n\r\nHello, World!\r\n";
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[10, 20, 28, 35]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert!(handler.content_type.is_some());
    assert_eq!(body_string(&handler), "Hello, World!\r\n");
}

#[test]
fn test_byte_by_byte_parsing() {
    let content = "Content-Type: text/plain\r\n\r\nHi\r\n";
    let bytes = content.as_bytes();
    let chunks: Vec<Vec<u8>> = bytes.iter().map(|&b| vec![b]).collect();
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();

    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert!(handler.content_type.is_some());
    assert_eq!(body_string(&handler), "Hi\r\n");
}

#[test]
fn test_multipart_byte_by_byte() {
    let content = "Content-Type: multipart/mixed; boundary=X\r\n\r\n--X\r\n\r\nA\r\n--X--\r\n";
    let bytes = content.as_bytes();
    let chunks: Vec<Vec<u8>> = bytes.iter().map(|&b| vec![b]).collect();
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();

    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert_eq!(handler.entity_count, 2);
}

#[test]
fn test_split_at_every_position() {
    let content = "Content-Type: text/plain\r\n\r\nBody\r\n";
    let bytes = content.as_bytes();

    for split_pos in 1..bytes.len() {
        let mut handler = TestHandler::new();
        let mut parser = MimeParser::new(&mut handler);
        let chunks = split_at(content, &[split_pos]);
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        parse_with_compact(&mut parser, &chunk_refs)
            .unwrap_or_else(|e| panic!("Split at {split_pos} failed: {e}"));
        assert!(
            handler.content_type.is_some(),
            "Split at {split_pos} failed"
        );
        assert_eq!(
            body_string(&handler),
            "Body\r\n",
            "Split at {split_pos} wrong body"
        );
    }
}

#[test]
fn test_split_long_boundary() {
    let boundary = "----=_Part_0_1234567890.1234567890";
    let content = format!(
        "Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n\
         --{boundary}\r\n\r\nContent\r\n--{boundary}--\r\n"
    );
    let boundary_start = content.find(&format!("--{boundary}")).unwrap();
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(&content, &[boundary_start + 20]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert_eq!(handler.entity_count, 2);
}

#[test]
fn test_index_of_helper() {
    assert_eq!(index_of(b"text/plain", b'/'), Some(4));
    assert_eq!(index_of(b"no slash", b'/'), None);
}
