use std::rc::Rc;

use loopbuf::LoopBuf;
use rmimeparser::{
    decode_slice, index_of, ContentDisposition, ContentDispositionCollector, ContentType,
    ContentTypeCollector, HeaderDelivery, Locator, MimeHandler, MimeParser, ParseResult,
};

struct TestHandler {
    events: Vec<String>,
    content_type: Option<ContentType>,
    content_disposition: Option<ContentDisposition>,
    content_transfer_encoding: Option<String>,
    mime_version: Option<(u32, u32)>,
    body: Vec<u8>,
    entity_count: usize,
    /// Unstructured headers, as (name, value).
    headers: Vec<(String, String)>,
    content_type_collector: ContentTypeCollector,
    disposition_collector: ContentDispositionCollector,
    /// (header name, reason, the text delivered after it)
    malformed: Vec<(String, String, String)>,
    in_malformed: bool,
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
            headers: Vec::new(),
            content_type_collector: Default::default(),
            disposition_collector: Default::default(),
            malformed: Vec::new(),
            in_malformed: false,
        }
    }
}

impl MimeHandler for TestHandler {
    fn set_locator(&mut self, _locator: Rc<dyn Locator>) {
        self.events.push("setLocator".to_string());
    }

    fn start_entity(&mut self, boundary: Option<&str>) -> ParseResult<()> {
        self.events
            .push(format!("startEntity:{}", boundary.unwrap_or("null")));
        self.entity_count += 1;
        Ok(())
    }

    fn start_content_type(&mut self, primary: &str, sub: &str) -> ParseResult<()> {
        self.content_type_collector.start(primary, sub);
        Ok(())
    }

    fn end_content_type(&mut self) -> ParseResult<()> {
        let content_type = self.content_type_collector.finish();
        self.events.push(format!("contentType:{content_type}"));
        self.content_type = Some(content_type);
        Ok(())
    }

    fn start_content_disposition(&mut self, kind: &str) -> ParseResult<()> {
        self.disposition_collector.start(kind);
        Ok(())
    }

    fn end_content_disposition(&mut self) -> ParseResult<()> {
        let disposition = self.disposition_collector.finish();
        self.events
            .push(format!("contentDisposition:{disposition}"));
        self.content_disposition = Some(disposition);
        Ok(())
    }

    // The parameters of whichever of the two is open
    fn start_parameter(&mut self, name: &str, language: Option<&str>) -> ParseResult<()> {
        self.content_type_collector.start_parameter(name, language);
        self.disposition_collector.start_parameter(name, language);
        Ok(())
    }

    fn parameter_content(&mut self, text: &str) -> ParseResult<()> {
        self.content_type_collector.parameter_content(text);
        self.disposition_collector.parameter_content(text);
        Ok(())
    }

    fn end_parameter(&mut self) -> ParseResult<()> {
        self.content_type_collector.end_parameter();
        self.disposition_collector.end_parameter();
        Ok(())
    }

    fn malformed_header(&mut self, name: &str, reason: &str) -> ParseResult<()> {
        self.malformed
            .push((name.to_string(), reason.to_string(), String::new()));
        self.in_malformed = true;
        Ok(())
    }

    fn content_transfer_encoding(&mut self, encoding: &str) -> ParseResult<()> {
        self.events
            .push(format!("contentTransferEncoding:{encoding}"));
        self.content_transfer_encoding = Some(encoding.to_string());
        Ok(())
    }

    fn mime_version(&mut self, major: u32, minor: u32) -> ParseResult<()> {
        let version = format!("{major}.{minor}");
        self.events.push(format!("mimeVersion:{version}"));
        self.mime_version = Some((major, minor));
        Ok(())
    }

    fn end_header(&mut self) -> ParseResult<()> {
        self.in_malformed = false;
        Ok(())
    }

    fn start_header(&mut self, name: &str) -> ParseResult<()> {
        self.headers.push((name.to_string(), String::new()));
        Ok(())
    }

    fn header_content(&mut self, text: &str) -> ParseResult<()> {
        if self.in_malformed {
            self.malformed.last_mut().unwrap().2.push_str(text);
        } else {
            self.headers.last_mut().unwrap().1.push_str(text);
        }
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

type Parser<'a> = MimeParser<&'a mut TestHandler>;

fn parse(parser: &mut Parser<'_>, content: &str) -> ParseResult<()> {
    let mut ring = LoopBuf::with_capacity(content.len() + 2048);
    ring.extend_from_slice(content.as_bytes());
    parser.receive(&mut ring)?;
    parser.close(&mut ring)
}

fn parse_with_compact(parser: &mut Parser<'_>, chunks: &[&[u8]]) -> ParseResult<()> {
    let mut ring = LoopBuf::with_capacity(4096);
    for chunk in chunks {
        ring.extend_from_slice(chunk);
        parser.receive(&mut ring)?;
    }
    assert!(!parser.is_underflow(), "Parser has unconsumed data at EOF");
    parser.close(&mut ring)
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

    assert_eq!(handler.content_transfer_encoding.as_deref(), Some("base64"));
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

    assert_eq!(handler.mime_version, Some((1, 0)));
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
    assert!(err.message().contains("998"), "{err}");
}

#[test]
fn test_header_value_too_long() {
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parser.limits_mut().max_element_length = Some(50);

    // Content-Transfer-Encoding is one of the headers the parser holds whole to parse
    let mut sb = String::from("Content-Transfer-Encoding: ");
    for _ in 0..49 {
        sb.push('a');
    }
    sb.push_str("\r\n aaaaa\r\n\r\n");

    let err = parse(&mut parser, &sb).unwrap_err();
    assert!(err.message().contains("maximum"));
}

#[test]
fn test_unstructured_header_is_streamed_not_held_so_the_value_limit_does_not_apply() {
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parser.limits_mut().max_element_length = Some(50);
    // Far past the limit, in many folded lines
    let mut sb = String::from("X-Long: start\r\n");
    for _ in 0..200 {
        sb.push_str(" more text on a folded line\r\n");
    }
    sb.push_str("\r\n");
    parse(&mut parser, &sb).unwrap();
    let text = &handler.headers[0].1;
    assert!(text.starts_with("start more text"));
    assert!(text.len() > 5000);
    assert!(!text.contains('\r') && !text.contains('\n'));
    assert_eq!(handler.headers[0].0, "X-Long");
}

#[test]
fn test_header_name_too_long() {
    // The line limit is 998, so it comes first unless it is relaxed
    let relaxed = |parser: &mut MimeParser<&mut TestHandler>| {
        parser.limits_mut().max_header_line_length = None;
    };
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    relaxed(&mut parser);
    let sb = format!("{}: v\r\n\r\n", "N".repeat(1025));
    let err = parse(&mut parser, &sb).unwrap_err();
    assert!(err.message().contains("name"), "{err}");

    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    relaxed(&mut parser);
    parse(&mut parser, &format!("{}: v\r\n\r\n", "N".repeat(1024))).unwrap();
}

#[test]
fn test_every_unknown_header_is_delivered_unstructured_and_the_mime_ones_are_not() {
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parse(
        &mut parser,
        "Subject: =?UTF-8?Q?caf=C3=A9?= au\r\n lait\r\nContent-Type: text/plain\r\nContent-Description: a\r\n picture\r\nWeird-Header:    padded  \r\n\r\nbody",
    )
    .unwrap();
    assert_eq!(
        handler.headers,
        vec![
            ("Subject".to_string(), "caf\u{e9} au lait".to_string()),
            ("Content-Description".to_string(), "a picture".to_string()),
            ("Weird-Header".to_string(), "padded".to_string()),
        ]
    );
    assert!(handler.content_type.is_some());
}

#[test]
fn test_unstructured_header_arrives_the_same_whatever_the_chunking() {
    let msg =
        "Subject: =?UTF-8?B?Y2Fmw6k=?= =?UTF-8?Q?_au_lait?=\r\n and more\r\n text\r\n\r\nbody";
    let mut expected = None;
    for step in [1usize, 2, 3, 5, 11, 1000] {
        let mut handler = TestHandler::new();
        let mut parser = MimeParser::new(&mut handler);
        let mut ring = LoopBuf::with_capacity(4096);
        for chunk in msg.as_bytes().chunks(step) {
            ring.extend_from_slice(chunk);
            parser.receive(&mut ring).unwrap();
        }
        parser.close(&mut ring).unwrap();
        let got = handler.headers.clone();
        assert_eq!(got[0].1, "caf\u{e9} au lait and more text", "step {step}");
        match &expected {
            None => expected = Some(got),
            Some(e) => assert_eq!(&got, e, "step {step}"),
        }
    }
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
    assert!(handler
        .content_type
        .as_ref()
        .unwrap()
        .is_mime_type("text", "html"));
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
    let content =
        "Content-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\n\r\nPart1\r\n--abc--\r\n";
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
    let content =
        "Content-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\n\r\nPart\r\n--abc--\r\n";
    let end_boundary = content.rfind("--abc--").unwrap();
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    let chunks = split_at(content, &[end_boundary + 6]);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    parse_with_compact(&mut parser, &chunk_refs).unwrap();

    assert_eq!(handler.entity_count, 2);
    assert!(handler.events.iter().any(|e| e.contains("endEntity:abc")));
}

#[test]
fn test_split_boundary_crlf() {
    let content =
        "Content-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\n\r\nPart1\r\n--abc--\r\n";
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

/// A layer on top of MIME takes the headers it parses itself raw.
struct RawTaker {
    raw: Vec<(String, Vec<u8>)>,
    unstructured: Vec<String>,
}

impl MimeHandler for RawTaker {
    fn header_delivery(&mut self, name: &str) -> HeaderDelivery {
        if name.eq_ignore_ascii_case("x-raw") {
            HeaderDelivery::Raw
        } else {
            HeaderDelivery::Unstructured
        }
    }
    fn start_header(&mut self, name: &str) -> ParseResult<()> {
        if name.eq_ignore_ascii_case("x-raw") {
            self.raw.push((name.to_string(), Vec::new()));
        } else {
            self.unstructured.push(name.to_string());
        }
        Ok(())
    }
    fn raw_header_content(&mut self, bytes: &[u8]) -> ParseResult<()> {
        self.raw.last_mut().unwrap().1.extend_from_slice(bytes);
        Ok(())
    }
}

#[test]
fn test_a_header_asked_for_raw_arrives_undecoded_and_unfolded() {
    let mut taker = RawTaker {
        raw: Vec::new(),
        unstructured: Vec::new(),
    };
    let mut parser = MimeParser::new(&mut taker);
    let msg = "Other: x\r\nX-Raw: =?UTF-8?Q?a?=,  b\r\n\t\"c, d\"\r\n\r\nbody";
    let mut ring = LoopBuf::with_capacity(msg.len() + 64);
    ring.extend_from_slice(msg.as_bytes());
    parser.receive(&mut ring).unwrap();
    parser.close(&mut ring).unwrap();
    assert_eq!(taker.unstructured, vec!["Other".to_string()]);
    assert_eq!(taker.raw.len(), 1);
    // nothing decoded, the fold's line ending gone and the white space after it kept
    assert_eq!(taker.raw[0].1, b" =?UTF-8?Q?a?=,  b\t\"c, d\"".to_vec());
}

#[test]
fn test_a_header_taken_raw_is_not_limited_by_the_parser_whoever_takes_it_bounds_it() {
    let mut taker = RawTaker {
        raw: Vec::new(),
        unstructured: Vec::new(),
    };
    let mut parser = MimeParser::new(&mut taker);
    parser.limits_mut().max_element_length = Some(20);
    let msg = format!("X-Raw: {}\r\n\r\n", "a".repeat(40));
    let mut ring = LoopBuf::with_capacity(msg.len() + 64);
    ring.extend_from_slice(msg.as_bytes());
    parser.receive(&mut ring).unwrap();
    assert_eq!(taker.raw[0].1.len(), 41);
}

// ---- Content-Type and Content-Disposition stream ----

fn parse_chunked(msg: &str, step: usize) -> TestHandler {
    let mut handler = TestHandler::new();
    {
        let mut parser = MimeParser::new(&mut handler);
        let mut ring = LoopBuf::with_capacity(8192);
        for chunk in msg.as_bytes().chunks(step) {
            ring.extend_from_slice(chunk);
            parser.receive(&mut ring).unwrap();
        }
        parser.close(&mut ring).unwrap();
    }
    handler
}

#[test]
fn test_a_huge_parameter_value_is_streamed_not_held() {
    let mut handler = TestHandler::new();
    let mut parser = MimeParser::new(&mut handler);
    parser.limits_mut().max_element_length = Some(50);
    let mut msg = String::from("Content-Disposition: attachment; filename=\"");
    for _ in 0..300 {
        msg.push_str("a long file name part\r\n ");
    }
    msg.push_str("\"\r\n\r\nbody");
    parse(&mut parser, &msg).unwrap();
    let cd = handler.content_disposition.unwrap();
    assert!(cd.is_disposition_type("attachment"));
    assert!(cd.get_parameter("filename").unwrap().len() > 6000);
}

#[test]
fn test_content_type_arrives_the_same_whatever_the_chunking() {
    let msg = "Content-Type: multipart/mixed;\r\n boundary=\"b-1\"; charset=\"utf-8\";\r\n title*0*=UTF-8''caf%C3;\r\n title*1*=%A9%20au; title*2=\" lait\"\r\n\r\npreamble\r\n--b-1\r\n\r\nx\r\n--b-1--\r\n";
    let whole = parse_chunked(msg, 1000);
    let ct = whole.content_type.clone().unwrap();
    assert!(ct.is_mime_type("multipart", "mixed"));
    assert_eq!(ct.get_parameter("boundary"), Some("b-1"));
    assert_eq!(ct.get_parameter("title"), Some("caf\u{e9} au lait"));
    for step in [1usize, 2, 3, 5, 7, 11, 13] {
        let got = parse_chunked(msg, step);
        assert_eq!(got.content_type, whole.content_type, "step {step}");
        // how many calls the body takes depends on the chunking; what it says does not
        let mut a = got.events.clone();
        let mut b = whole.events.clone();
        a.dedup();
        b.dedup();
        assert_eq!(a, b, "step {step}");
    }
}

#[test]
fn test_the_multipart_boundary_comes_from_the_streamed_parameter() {
    // the boundary is read while the parameter streams past, whatever the
    // chunking, folded onto its own line, and quoted
    let msg = "Content-Type: multipart/mixed;\r\n boundary=\"split-here\"\r\n\r\n--split-here\r\n\r\npart\r\n--split-here--\r\n";
    for step in [1usize, 4, 1000] {
        let h = parse_chunked(msg, step);
        assert!(
            h.events.iter().any(|e| e == "startEntity:split-here"),
            "step {step}: {:?}",
            h.events
        );
    }
    // not multipart: a boundary parameter means nothing
    let h = parse_chunked(
        "Content-Type: text/plain; boundary=x\r\n\r\n--x\r\nbody",
        1000,
    );
    assert!(!h.events.iter().any(|e| e.starts_with("startEntity:x")));
    // an invalid boundary (too long) is not used
    let long = "b".repeat(71);
    let h = parse_chunked(
        &format!("Content-Type: multipart/mixed; boundary={long}\r\n\r\n--{long}\r\nx"),
        1000,
    );
    assert!(!h.events.iter().any(|e| e.starts_with("startEntity:b")));
}

#[test]
fn test_a_content_type_that_is_not_valid_is_reported_with_its_text() {
    for step in [1usize, 3, 1000] {
        let h = parse_chunked("Content-Type: text plain; charset=x\r\n\r\nbody", step);
        assert!(h.content_type.is_none(), "step {step}");
        assert_eq!(h.malformed.len(), 1, "step {step}");
        let (name, reason, text) = &h.malformed[0];
        assert_eq!(name, "Content-Type");
        assert!(
            reason.contains("subtype") || reason.contains("type"),
            "{reason}"
        );
        // the whole value, as unstructured text
        assert_eq!(text, "text plain; charset=x", "step {step}");
    }
    // a value that ends before the head is complete
    let h = parse_chunked("Content-Type: text\r\n\r\nbody", 1000);
    assert_eq!(h.malformed[0].2, "text");
    // and one too long to be a head, over folded lines
    let folded = "ddddddddd\r\n ".repeat(200);
    let h = parse_chunked(&format!("Content-Disposition: {folded}\r\n\r\nx"), 1000);
    assert_eq!(h.malformed.len(), 1);
    assert_eq!(h.malformed[0].2.replace(' ', "").len(), 1800);
}

#[test]
fn test_the_extended_parameter_says_it_is_extended() {
    #[derive(Default)]
    struct Seen(Vec<(String, Option<String>)>);
    impl MimeHandler for Seen {
        fn start_parameter(&mut self, name: &str, language: Option<&str>) -> ParseResult<()> {
            self.0
                .push((name.to_string(), language.map(str::to_string)));
            Ok(())
        }
    }
    let mut seen = Seen::default();
    let mut parser = MimeParser::new(&mut seen);
    let msg = "Content-Disposition: attachment; a=1; b*=UTF-8'en'x; c*=UTF-8''y; d*0=\"z\"\r\n\r\n";
    let mut ring = LoopBuf::with_capacity(4096);
    ring.extend_from_slice(msg.as_bytes());
    parser.receive(&mut ring).unwrap();
    parser.close(&mut ring).unwrap();
    assert_eq!(
        seen.0,
        vec![
            ("a".to_string(), None),
            ("b".to_string(), Some("en".to_string())),
            ("c".to_string(), Some(String::new())),
            ("d".to_string(), None),
        ]
    );
}
