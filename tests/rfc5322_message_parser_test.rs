use std::collections::HashMap;

use rmimeparser::{
    ContentId, ContentType, EmailAddress, MessageHandler, MessageParser, MimeHandler, MimeLocator,
    MimeVersion, OffsetDateTime, ParseResult,
};

/// Records parser events for verification (gumdrop `MessageParserTest.TestMessageHandler`).
struct TestMessageHandler {
    date_headers: HashMap<String, OffsetDateTime>,
    address_headers: HashMap<String, Vec<EmailAddress>>,
    message_id_headers: HashMap<String, Vec<ContentId>>,
    unstructured_headers: HashMap<String, String>,
    unexpected_headers: HashMap<String, String>,
    content_type: Option<ContentType>,
    mime_version: Option<MimeVersion>,
    body: Vec<u8>,
    entity_count: usize,
}

impl TestMessageHandler {
    fn new() -> Self {
        Self {
            date_headers: HashMap::new(),
            address_headers: HashMap::new(),
            message_id_headers: HashMap::new(),
            unstructured_headers: HashMap::new(),
            unexpected_headers: HashMap::new(),
            content_type: None,
            mime_version: None,
            body: Vec::new(),
            entity_count: 0,
        }
    }

    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    fn clear_address_headers(&mut self) {
        self.address_headers.clear();
    }

    fn clear_body(&mut self) {
        self.body.clear();
    }
}

impl MimeHandler for TestMessageHandler {
    fn set_locator(&mut self, _locator: &MimeLocator) -> ParseResult<()> {
        Ok(())
    }

    fn start_entity(&mut self, _boundary: Option<&str>) -> ParseResult<()> {
        self.entity_count += 1;
        Ok(())
    }

    fn content_type(&mut self, content_type: &ContentType) -> ParseResult<()> {
        self.content_type = Some(content_type.clone());
        Ok(())
    }

    fn mime_version(&mut self, version: MimeVersion) -> ParseResult<()> {
        self.mime_version = Some(version);
        Ok(())
    }

    fn end_headers(&mut self) -> ParseResult<()> {
        Ok(())
    }

    fn body_content(&mut self, data: &[u8]) -> ParseResult<()> {
        self.body.extend_from_slice(data);
        Ok(())
    }
}

impl MessageHandler for TestMessageHandler {
    fn header(&mut self, name: &str, value: &str) -> ParseResult<()> {
        self.unstructured_headers
            .insert(name.to_string(), value.to_string());
        Ok(())
    }

    fn unexpected_header(&mut self, name: &str, value: &str) -> ParseResult<()> {
        self.unexpected_headers
            .insert(name.to_string(), value.to_string());
        Ok(())
    }

    fn date_header(&mut self, name: &str, date: OffsetDateTime) -> ParseResult<()> {
        self.date_headers.insert(name.to_string(), date);
        Ok(())
    }

    fn address_header(&mut self, name: &str, addresses: &[EmailAddress]) -> ParseResult<()> {
        self.address_headers
            .insert(name.to_string(), addresses.to_vec());
        Ok(())
    }

    fn message_id_header(&mut self, name: &str, content_ids: &[ContentId]) -> ParseResult<()> {
        self.message_id_headers
            .insert(name.to_string(), content_ids.to_vec());
        Ok(())
    }
}

fn parse(content: &str, handler: &mut TestMessageHandler) {
    let mut parser = MessageParser::new(handler);
    let mut data = content.as_bytes();
    parser.receive(&mut data).unwrap();
    parser.close().unwrap();
}

// --- Date header tests ---

#[test]
fn test_date_header() {
    let content = "Date: Sat, 7 Dec 2024 14:30:00 +0000\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    let date = handler.date_headers.get("Date").expect("Date header");
    assert_eq!(date.year, 2024);
    assert_eq!(date.month, 12);
    assert_eq!(date.day, 7);
    assert_eq!(date.hour, 14);
    assert_eq!(date.minute, 30);
    assert_eq!(date.offset_seconds, 0);
}

#[test]
fn test_date_header_with_timezone() {
    let content = "Date: Fri, 6 Dec 2024 09:15:30 -0500\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    let date = handler.date_headers.get("Date").expect("Date header");
    assert_eq!(date.offset_hours(), -5);
}

#[test]
fn test_resent_date_header() {
    let content = "Resent-Date: Mon, 9 Dec 2024 10:00:00 +0100\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.date_headers.contains_key("Resent-Date"));
}

// --- Address header tests ---

#[test]
fn test_from_header() {
    let content = "From: alice@example.com\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    let addresses = handler.address_headers.get("From").expect("From");
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0].address(), "alice@example.com");
}

#[test]
fn test_from_header_with_display_name() {
    let content = "From: Alice Smith <alice@example.com>\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    let addresses = handler.address_headers.get("From").expect("From");
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0].address(), "alice@example.com");
    assert_eq!(addresses[0].display_name(), Some("Alice Smith"));
}

#[test]
fn test_to_header_multiple_recipients() {
    let content = "To: alice@example.com, bob@example.com\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    let addresses = handler.address_headers.get("To").expect("To");
    assert_eq!(addresses.len(), 2);
    assert_eq!(addresses[0].address(), "alice@example.com");
    assert_eq!(addresses[1].address(), "bob@example.com");
}

#[test]
fn test_cc_header() {
    let content = "Cc: manager@example.com\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.address_headers.contains_key("Cc"));
}

#[test]
fn test_bcc_header() {
    let content = "Bcc: secret@example.com\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.address_headers.contains_key("Bcc"));
}

#[test]
fn test_reply_to_header() {
    let content = "Reply-To: replies@example.com\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.address_headers.contains_key("Reply-To"));
}

#[test]
fn test_sender_header() {
    let content = "Sender: secretary@example.com\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.address_headers.contains_key("Sender"));
}

// --- Message-ID header tests ---

#[test]
fn test_message_id_header() {
    let content = "Message-ID: <unique123@example.com>\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    let ids = handler
        .message_id_headers
        .get("Message-ID")
        .expect("Message-ID");
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].local_part(), "unique123");
    assert_eq!(ids[0].domain(), "example.com");
}

#[test]
fn test_in_reply_to_header() {
    let content = "In-Reply-To: <original123@example.com>\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.message_id_headers.contains_key("In-Reply-To"));
}

#[test]
fn test_references_header_multiple() {
    let content =
        "References: <msg1@example.com> <msg2@example.com> <msg3@example.com>\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    let ids = handler.message_id_headers.get("References").expect("References");
    assert_eq!(ids.len(), 3);
}

// --- Unstructured header tests ---

#[test]
fn test_subject_header() {
    let content = "Subject: Test email subject\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.unstructured_headers.contains_key("Subject"));
    assert_eq!(
        handler.unstructured_headers.get("Subject").map(String::as_str),
        Some("Test email subject")
    );
}

#[test]
fn test_comments_header() {
    let content = "Comments: This is a comment\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.unstructured_headers.contains_key("Comments"));
}

#[test]
fn test_received_header() {
    let content =
        "Received: from mail.example.com by mx.example.org; Sat, 7 Dec 2024 12:00:00 +0000\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.unstructured_headers.contains_key("Received"));
}

#[test]
fn test_custom_x_header() {
    let content = "X-Custom-Header: custom value\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.unstructured_headers.contains_key("X-Custom-Header"));
    assert_eq!(
        handler
            .unstructured_headers
            .get("X-Custom-Header")
            .map(String::as_str),
        Some("custom value")
    );
}

// --- MIME headers (delegated to parent) ---

#[test]
fn test_content_type_header() {
    let content = "Content-Type: text/plain; charset=utf-8\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    let ct = handler.content_type.as_ref().expect("content type");
    assert!(ct.is_mime_type("text", "plain"));
    assert_eq!(ct.get_parameter("charset"), Some("utf-8"));
}

#[test]
fn test_mime_version_header() {
    let content = "MIME-Version: 1.0\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert_eq!(handler.mime_version, Some(MimeVersion::V1_0));
}

// --- Complete message tests ---

#[test]
fn test_complete_email_message() {
    let content = "\
Date: Sat, 7 Dec 2024 14:30:00 +0000\r\n\
From: sender@example.com\r\n\
To: recipient@example.com\r\n\
Subject: Test message\r\n\
Message-ID: <unique-id@example.com>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain\r\n\
\r\n\
This is the message body.\r\n";

    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.date_headers.contains_key("Date"));
    assert!(handler.address_headers.contains_key("From"));
    assert!(handler.address_headers.contains_key("To"));
    assert!(handler.unstructured_headers.contains_key("Subject"));
    assert!(handler.message_id_headers.contains_key("Message-ID"));
    assert!(handler.mime_version.is_some());
    assert!(handler.content_type.is_some());
    assert_eq!(
        handler.body_text().trim(),
        "This is the message body."
    );
}

#[test]
fn test_multipart_email() {
    let content = "\
Date: Sat, 7 Dec 2024 14:30:00 +0000\r\n\
From: sender@example.com\r\n\
To: recipient@example.com\r\n\
Subject: Multipart test\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=boundary123\r\n\
\r\n\
--boundary123\r\n\
Content-Type: text/plain\r\n\
\r\n\
Plain text part\r\n\
--boundary123\r\n\
Content-Type: text/html\r\n\
\r\n\
<p>HTML part</p>\r\n\
--boundary123--\r\n";

    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert_eq!(handler.entity_count, 3);
    assert!(handler.date_headers.contains_key("Date"));
    assert!(handler.address_headers.contains_key("From"));
}

#[test]
fn test_parse_simple_message() {
    let content = "\
From: user@example.com\r\n\
To: recipient@example.com\r\n\
Subject: Test\r\n\
Date: Fri, 21 Nov 1997 09:55:06 -0600\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain\r\n\
\r\n\
Hello\r\n";

    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert_eq!(handler.date_headers.len(), 1);
    assert_eq!(handler.address_headers.len(), 2);
    assert_eq!(
        handler.unstructured_headers.get("Subject").map(String::as_str),
        Some("Test")
    );
    assert!(handler.body_text().contains("Hello"));
}

// --- Invalid header tests ---

#[test]
fn test_invalid_date_header() {
    let content = "Date: not a valid date\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.unexpected_headers.contains_key("Date"));
    assert!(!handler.date_headers.contains_key("Date"));
}

#[test]
fn test_invalid_address_header() {
    let content = "From: not a valid email address\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.unexpected_headers.contains_key("From"));
    assert!(!handler.address_headers.contains_key("From"));
}

#[test]
fn test_invalid_message_id_header() {
    let content = "Message-ID: not-a-valid-id\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.unexpected_headers.contains_key("Message-ID"));
    assert!(!handler.message_id_headers.contains_key("Message-ID"));
}

// --- Parser configuration tests ---

#[test]
fn test_set_handler_with_message_handler() {
    let content = "Subject: Test\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.unstructured_headers.contains_key("Subject"));
}

#[test]
fn test_reset() {
    let mut handler = TestMessageHandler::new();

    {
        let mut parser = MessageParser::new(&mut handler);
        let mut data = b"From: alice@example.com\r\n\r\nFirst".as_slice();
        parser.receive(&mut data).unwrap();
        parser.close().unwrap();
    }
    assert!(handler.address_headers.contains_key("From"));

    {
        let mut parser = MessageParser::new(&mut handler);
        parser.reset();
    }
    handler.clear_address_headers();
    handler.clear_body();

    {
        let mut parser = MessageParser::new(&mut handler);
        let mut data = b"From: bob@example.com\r\n\r\nSecond".as_slice();
        parser.receive(&mut data).unwrap();
        parser.close().unwrap();
    }

    let addresses = handler.address_headers.get("From").expect("From");
    assert_eq!(addresses[0].address(), "bob@example.com");
}

// --- Header case insensitivity tests ---

#[test]
fn test_header_case_insensitivity() {
    let content = "\
DATE: Sat, 7 Dec 2024 14:30:00 +0000\r\n\
from: sender@example.com\r\n\
MESSAGE-id: <test@example.com>\r\n\
subject: Test\r\n\
\r\n\
Body";

    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    assert!(handler.date_headers.contains_key("DATE"));
    assert!(handler.address_headers.contains_key("from"));
    assert!(handler.message_id_headers.contains_key("MESSAGE-id"));
    assert!(handler.unstructured_headers.contains_key("subject"));
}

// --- Address with angle brackets ---

#[test]
fn test_address_angle_bracket_only() {
    let content = "From: <alice@example.com>\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    let addresses = handler.address_headers.get("From").expect("From");
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0].address(), "alice@example.com");
}

#[test]
fn test_address_quoted_display_name() {
    let content = "From: \"Smith, Alice\" <alice@example.com>\r\n\r\nBody";
    let mut handler = TestMessageHandler::new();
    parse(content, &mut handler);

    let addresses = handler.address_headers.get("From").expect("From");
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0].address(), "alice@example.com");
    assert_eq!(addresses[0].display_name(), Some("Smith, Alice"));
}
