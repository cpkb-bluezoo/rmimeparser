use rmimeparser::{
    ContentType, ContentTypeParser, MimeHandler, MimeParser, MimeVersion, MimeWriter, Parameter,
    ParseResult,
};

struct CollectBody {
    bodies: Vec<Vec<u8>>,
    current: Vec<u8>,
    events: Vec<String>,
}

impl CollectBody {
    fn new() -> Self {
        Self {
            bodies: Vec::new(),
            current: Vec::new(),
            events: Vec::new(),
        }
    }
}

impl MimeHandler for CollectBody {
    fn start_entity(&mut self, boundary: Option<&str>) -> ParseResult<()> {
        self.events
            .push(format!("start:{}", boundary.unwrap_or("-")));
        Ok(())
    }

    fn end_headers(&mut self) -> ParseResult<()> {
        self.current.clear();
        Ok(())
    }

    fn body_content(&mut self, data: &[u8]) -> ParseResult<()> {
        self.current.extend_from_slice(data);
        Ok(())
    }

    fn end_entity(&mut self, boundary: Option<&str>) -> ParseResult<()> {
        if !self.current.is_empty() || self.bodies.is_empty() {
            // Only push when we had a leaf body phase; multipart parents may be empty.
        }
        if !self.current.is_empty() {
            self.bodies.push(std::mem::take(&mut self.current));
        }
        self.events
            .push(format!("end:{}", boundary.unwrap_or("-")));
        Ok(())
    }
}

fn parse_all(raw: &[u8]) -> CollectBody {
    let mut handler = CollectBody::new();
    {
        let mut parser = MimeParser::new(&mut handler);
        let mut input = raw;
        parser.receive(&mut input).unwrap();
        parser.close().unwrap();
    }
    handler
}

#[test]
fn write_simple_text_7bit() {
    let mut out = Vec::new();
    {
        let mut w = MimeWriter::new(&mut out);
        w.start_entity(None).unwrap();
        let ct = ContentTypeParser::parse_str("text/plain; charset=us-ascii").unwrap();
        w.content_type(&ct).unwrap();
        w.end_headers().unwrap();
        w.body_content(b"Hello").unwrap();
        w.body_content(b" world").unwrap();
        w.end_entity(None).unwrap();
        w.close().unwrap();
    }

    let s = String::from_utf8(out.clone()).unwrap();
    assert!(s.contains("Content-Type: text/plain"));
    assert!(s.ends_with("Hello world") || s.contains("Hello world"));

    let parsed = parse_all(&out);
    assert_eq!(parsed.bodies.len(), 1);
    assert_eq!(
        String::from_utf8_lossy(&parsed.bodies[0]).trim(),
        "Hello world"
    );
}

#[test]
fn write_base64_chunked_round_trip() {
    let payload: Vec<u8> = (0..180u8).collect();
    let mut out = Vec::new();
    {
        let mut w = MimeWriter::new(&mut out);
        w.start_entity(None).unwrap();
        w.content_type(&ContentType::new("application", "octet-stream", None))
            .unwrap();
        w.content_transfer_encoding("base64").unwrap();
        w.end_headers().unwrap();
        for chunk in payload.chunks(13) {
            w.body_content(chunk).unwrap();
        }
        w.end_entity(None).unwrap();
        w.close().unwrap();
    }

    let parsed = parse_all(&out);
    assert_eq!(parsed.bodies.len(), 1);
    assert_eq!(parsed.bodies[0], payload);
}

#[test]
fn write_multipart_mixed() {
    let mut out = Vec::new();
    {
        let mut w = MimeWriter::new(&mut out);
        w.start_entity(None).unwrap();
        w.mime_version(MimeVersion::V1_0).unwrap();
        let ct = ContentType::new(
            "multipart",
            "mixed",
            Some(vec![Parameter::new("boundary", "bound123")]),
        );
        w.content_type(&ct).unwrap();
        w.end_headers().unwrap();

        w.start_entity(Some("bound123")).unwrap();
        w.content_type(&ContentType::new("text", "plain", None))
            .unwrap();
        w.end_headers().unwrap();
        w.body_content(b"Part one").unwrap();
        w.end_entity(Some("bound123")).unwrap();

        w.start_entity(Some("bound123")).unwrap();
        w.content_type(&ContentType::new("text", "plain", None))
            .unwrap();
        w.end_headers().unwrap();
        w.body_content(b"Part two").unwrap();
        w.end_entity(Some("bound123")).unwrap();

        w.end_entity(None).unwrap();
        w.close().unwrap();
    }

    let s = String::from_utf8(out.clone()).unwrap();
    assert!(s.contains("--bound123\r\n"));
    assert!(s.contains("--bound123--\r\n"));

    let parsed = parse_all(&out);
    assert_eq!(parsed.bodies.len(), 2);
    assert_eq!(
        String::from_utf8_lossy(&parsed.bodies[0]).trim(),
        "Part one"
    );
    assert_eq!(
        String::from_utf8_lossy(&parsed.bodies[1]).trim(),
        "Part two"
    );
}

#[test]
fn rejects_body_before_end_headers() {
    let mut out = Vec::new();
    let mut w = MimeWriter::new(&mut out);
    w.start_entity(None).unwrap();
    assert!(w.body_content(b"x").is_err());
}

#[test]
fn rejects_boundary_in_body() {
    let mut out = Vec::new();
    let mut w = MimeWriter::new(&mut out);
    w.start_entity(None).unwrap();
    let ct = ContentType::new(
        "multipart",
        "mixed",
        Some(vec![Parameter::new("boundary", "abc")]),
    );
    w.content_type(&ct).unwrap();
    w.end_headers().unwrap();

    w.start_entity(Some("abc")).unwrap();
    w.content_type(&ContentType::new("text", "plain", None))
        .unwrap();
    w.end_headers().unwrap();
    assert!(w.body_content(b"hello\r\n--abc\r\nnope").is_err());
}

#[test]
fn rejects_7bit_high_byte() {
    let mut out = Vec::new();
    let mut w = MimeWriter::new(&mut out);
    w.start_entity(None).unwrap();
    w.content_type(&ContentType::new("text", "plain", None))
        .unwrap();
    w.end_headers().unwrap();
    assert!(w.body_content(b"caf\xe9").is_err());
}

#[test]
fn header_after_body_fails() {
    let mut out = Vec::new();
    let mut w = MimeWriter::new(&mut out);
    w.start_entity(None).unwrap();
    w.content_type(&ContentType::new("text", "plain", None))
        .unwrap();
    w.end_headers().unwrap();
    w.body_content(b"x").unwrap();
    assert!(w.header("X-Extra", "nope").is_err());
}
