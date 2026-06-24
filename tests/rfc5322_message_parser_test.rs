use rmimeparser::{
    ContentType, EmailAddress, MessageHandler, MessageParser, MimeHandler, MimeLocator, MimeVersion,
    OffsetDateTime, ParseResult,
};

struct TestMessageHandler {
    date_headers: Vec<(String, OffsetDateTime)>,
    address_headers: Vec<(String, Vec<EmailAddress>)>,
    subject: Option<String>,
    end_headers: bool,
    body: Vec<u8>,
}

impl MimeHandler for TestMessageHandler {
    fn set_locator(&mut self, _locator: &MimeLocator) -> ParseResult<()> {
        Ok(())
    }

    fn content_type(&mut self, content_type: &ContentType) -> ParseResult<()> {
        let _ = content_type;
        Ok(())
    }

    fn mime_version(&mut self, version: MimeVersion) -> ParseResult<()> {
        assert!(matches!(version, MimeVersion::V1_0));
        Ok(())
    }

    fn end_headers(&mut self) -> ParseResult<()> {
        self.end_headers = true;
        Ok(())
    }

    fn body_content(&mut self, data: &[u8]) -> ParseResult<()> {
        self.body.extend_from_slice(data);
        Ok(())
    }
}

impl MessageHandler for TestMessageHandler {
    fn date_header(&mut self, name: &str, date: OffsetDateTime) -> ParseResult<()> {
        self.date_headers.push((name.to_string(), date));
        Ok(())
    }

    fn address_header(&mut self, name: &str, addresses: &[EmailAddress]) -> ParseResult<()> {
        self.address_headers
            .push((name.to_string(), addresses.to_vec()));
        Ok(())
    }

    fn header(&mut self, _name: &str, value: &str) -> ParseResult<()> {
        self.subject = Some(value.to_string());
        Ok(())
    }
}

#[test]
fn test_parse_simple_message() {
    let raw = b"From: user@example.com\r\n\
To: recipient@example.com\r\n\
Subject: Test\r\n\
Date: Fri, 21 Nov 1997 09:55:06 -0600\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain\r\n\
\r\n\
Hello\r\n";

    let mut handler = TestMessageHandler {
        date_headers: Vec::new(),
        address_headers: Vec::new(),
        subject: None,
        end_headers: false,
        body: Vec::new(),
    };
    let mut parser = MessageParser::new(&mut handler);
    let mut data = &raw[..];
    parser.receive(&mut data).unwrap();
    parser.close().unwrap();

    assert!(handler.end_headers);
    assert_eq!(handler.date_headers.len(), 1);
    assert_eq!(handler.date_headers[0].0, "Date");
    assert_eq!(handler.address_headers.len(), 2);
    assert_eq!(handler.subject.as_deref(), Some("Test"));
    let body = String::from_utf8_lossy(&handler.body);
    assert!(body.contains("Hello"), "body was: {body:?}");
}
