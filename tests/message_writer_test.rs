use loopbuf::LoopBuf;
use rmimeparser::{
    ContentType, EmailAddress, MessageHandler, MessageParser, MessageWriter, MimeHandler,
    OffsetDateTime, ParseResult,
};

#[derive(Default)]
struct Capture {
    subject: Option<String>,
    header: (String, String),
    from: Vec<EmailAddress>,
    date: Option<OffsetDateTime>,
    body: Vec<u8>,
}

impl MimeHandler for Capture {
    fn start_header(&mut self, name: &str) -> ParseResult<()> {
        self.header = (name.to_string(), String::new());
        Ok(())
    }

    fn header_content(&mut self, text: &str) -> ParseResult<()> {
        self.header.1.push_str(text);
        Ok(())
    }

    fn end_header(&mut self) -> ParseResult<()> {
        if self.header.0.eq_ignore_ascii_case("subject") {
            self.subject = Some(std::mem::take(&mut self.header.1));
        }
        Ok(())
    }

    fn body_content(&mut self, data: &[u8]) -> ParseResult<()> {
        self.body.extend_from_slice(data);
        Ok(())
    }
}

impl MessageHandler for Capture {
    fn address_header(&mut self, name: &str, addresses: &[EmailAddress]) -> ParseResult<()> {
        if name.eq_ignore_ascii_case("from") {
            self.from = addresses.to_vec();
        }
        Ok(())
    }

    fn date_header(&mut self, name: &str, date: OffsetDateTime) -> ParseResult<()> {
        if name.eq_ignore_ascii_case("date") {
            self.date = Some(date);
        }
        Ok(())
    }
}

#[test]
fn write_message_with_subject_and_date() {
    let mut ring = LoopBuf::with_capacity(1 << 16);
    {
        let mut w = MessageWriter::new();
        w.start_entity(&mut ring, None).unwrap();
        w.header(&mut ring, "Subject", "Café résumé").unwrap();
        w.date_header(&mut ring, 
            "Date",
            OffsetDateTime::new(2024, 6, 15, 12, 30, 0, 0),
        )
        .unwrap();
        w.address_header(&mut ring, 
            "From",
            &[EmailAddress::new(
                Some("José".into()),
                "jose",
                "example.com",
                false,
            )],
        )
        .unwrap();
        w.content_type(&mut ring, &ContentType::new("text", "plain", None))
            .unwrap();
        w.content_transfer_encoding(&mut ring, "quoted-printable").unwrap();
        w.end_headers(&mut ring).unwrap();
        w.body_content(&mut ring, "Hello café".as_bytes()).unwrap();
        w.end_entity(&mut ring, None).unwrap();
        w.close().unwrap();
    }
    let out = ring.spans().to_vec();

    let wire = String::from_utf8_lossy(&out);
    assert!(wire.contains("Subject:"));
    assert!(wire.contains("=?") || wire.contains("Café") || wire.contains("UTF-8"));
    assert!(wire.contains("Date:"));
    assert!(wire.contains("From:"));

    let mut capture = Capture::default();
    {
        let mut parser = MessageParser::new(&mut capture);
        let mut input = LoopBuf::with_capacity(out.len() + 2048);
        input.extend_from_slice(&out);
        parser.receive(&mut input).unwrap();
        parser.close(&mut input).unwrap();
    }

    assert_eq!(capture.subject.as_deref(), Some("Café résumé"));
    // Parser delivers QP line endings as part of decoded body.
    assert_eq!(
        String::from_utf8_lossy(&capture.body).trim(),
        "Hello café"
    );
    assert!(capture.date.is_some());
    assert_eq!(capture.from.len(), 1);
    assert_eq!(capture.from[0].address(), "jose@example.com");
}
