use rmimeparser::{
    ContentType, EmailAddress, MessageHandler, MessageParser, MessageWriter, MimeHandler,
    OffsetDateTime, ParseResult,
};

#[derive(Default)]
struct Capture {
    subject: Option<String>,
    from: Vec<EmailAddress>,
    date: Option<OffsetDateTime>,
    body: Vec<u8>,
}

impl MimeHandler for Capture {
    fn body_content(&mut self, data: &[u8]) -> ParseResult<()> {
        self.body.extend_from_slice(data);
        Ok(())
    }
}

impl MessageHandler for Capture {
    fn header(&mut self, name: &str, value: &str) -> ParseResult<()> {
        if name.eq_ignore_ascii_case("subject") {
            self.subject = Some(value.to_string());
        }
        Ok(())
    }

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
    let mut out = Vec::new();
    {
        let mut w = MessageWriter::new(&mut out);
        w.start_entity(None).unwrap();
        w.header("Subject", "Café résumé").unwrap();
        w.date_header(
            "Date",
            OffsetDateTime::new(2024, 6, 15, 12, 30, 0, 0),
        )
        .unwrap();
        w.address_header(
            "From",
            &[EmailAddress::new(
                Some("José".into()),
                "jose",
                "example.com",
                false,
            )],
        )
        .unwrap();
        w.content_type(&ContentType::new("text", "plain", None))
            .unwrap();
        w.content_transfer_encoding("quoted-printable").unwrap();
        w.end_headers().unwrap();
        w.body_content("Hello café".as_bytes()).unwrap();
        w.end_entity(None).unwrap();
        w.close().unwrap();
    }

    let wire = String::from_utf8_lossy(&out);
    assert!(wire.contains("Subject:"));
    assert!(wire.contains("=?") || wire.contains("Café") || wire.contains("UTF-8"));
    assert!(wire.contains("Date:"));
    assert!(wire.contains("From:"));

    let mut capture = Capture::default();
    {
        let mut parser = MessageParser::new(&mut capture);
        let mut input = out.as_slice();
        parser.receive(&mut input).unwrap();
        parser.close().unwrap();
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
