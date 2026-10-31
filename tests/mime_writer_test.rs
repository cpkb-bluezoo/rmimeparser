use loopbuf::LoopBuf;
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
        self.events.push(format!("end:{}", boundary.unwrap_or("-")));
        Ok(())
    }
}

/// A ring holding `bytes`, with room to spare.
fn ring(bytes: &[u8]) -> LoopBuf {
    let mut buf = LoopBuf::with_capacity(bytes.len() + 2048);
    buf.extend_from_slice(bytes);
    buf
}

fn parse_all(raw: &[u8]) -> CollectBody {
    let mut handler = CollectBody::new();
    {
        let mut parser = MimeParser::new(&mut handler);
        let mut input = ring(raw);
        parser.receive(&mut input).unwrap();
        parser.close(&mut input).unwrap();
    }
    handler
}

#[test]
fn write_simple_text_7bit() {
    let mut ring = LoopBuf::with_capacity(1 << 16);
    {
        let mut w = MimeWriter::new();
        w.start_entity(&mut ring, None).unwrap();
        let ct = ContentTypeParser::parse_str("text/plain; charset=us-ascii").unwrap();
        w.content_type(&mut ring, &ct).unwrap();
        w.end_headers(&mut ring).unwrap();
        w.body_content(&mut ring, b"Hello").unwrap();
        w.body_content(&mut ring, b" world").unwrap();
        w.end_entity(&mut ring, None).unwrap();
        w.close().unwrap();
    }
    let out = ring.spans().to_vec();

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
    let mut ring = LoopBuf::with_capacity(1 << 16);
    {
        let mut w = MimeWriter::new();
        w.start_entity(&mut ring, None).unwrap();
        w.content_type(
            &mut ring,
            &ContentType::new("application", "octet-stream", None),
        )
        .unwrap();
        w.content_transfer_encoding(&mut ring, "base64").unwrap();
        w.end_headers(&mut ring).unwrap();
        for chunk in payload.chunks(13) {
            w.body_content(&mut ring, chunk).unwrap();
        }
        w.end_entity(&mut ring, None).unwrap();
        w.close().unwrap();
    }
    let out = ring.spans().to_vec();

    let parsed = parse_all(&out);
    assert_eq!(parsed.bodies.len(), 1);
    assert_eq!(parsed.bodies[0], payload);
}

#[test]
fn write_multipart_mixed() {
    let mut ring = LoopBuf::with_capacity(1 << 16);
    {
        let mut w = MimeWriter::new();
        w.start_entity(&mut ring, None).unwrap();
        w.mime_version(&mut ring, MimeVersion::V1_0).unwrap();
        let ct = ContentType::new(
            "multipart",
            "mixed",
            Some(vec![Parameter::new("boundary", "bound123")]),
        );
        w.content_type(&mut ring, &ct).unwrap();
        w.end_headers(&mut ring).unwrap();

        w.start_entity(&mut ring, Some("bound123")).unwrap();
        w.content_type(&mut ring, &ContentType::new("text", "plain", None))
            .unwrap();
        w.end_headers(&mut ring).unwrap();
        w.body_content(&mut ring, b"Part one").unwrap();
        w.end_entity(&mut ring, Some("bound123")).unwrap();

        w.start_entity(&mut ring, Some("bound123")).unwrap();
        w.content_type(&mut ring, &ContentType::new("text", "plain", None))
            .unwrap();
        w.end_headers(&mut ring).unwrap();
        w.body_content(&mut ring, b"Part two").unwrap();
        w.end_entity(&mut ring, Some("bound123")).unwrap();

        w.end_entity(&mut ring, None).unwrap();
        w.close().unwrap();
    }
    let out = ring.spans().to_vec();

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
    let mut ring = LoopBuf::with_capacity(1 << 16);
    let mut w = MimeWriter::new();
    w.start_entity(&mut ring, None).unwrap();
    assert!(w.body_content(&mut ring, b"x").is_err());
}

#[test]
fn rejects_boundary_in_body() {
    let mut ring = LoopBuf::with_capacity(1 << 16);
    let mut w = MimeWriter::new();
    w.start_entity(&mut ring, None).unwrap();
    let ct = ContentType::new(
        "multipart",
        "mixed",
        Some(vec![Parameter::new("boundary", "abc")]),
    );
    w.content_type(&mut ring, &ct).unwrap();
    w.end_headers(&mut ring).unwrap();

    w.start_entity(&mut ring, Some("abc")).unwrap();
    w.content_type(&mut ring, &ContentType::new("text", "plain", None))
        .unwrap();
    w.end_headers(&mut ring).unwrap();
    assert!(w
        .body_content(&mut ring, b"hello\r\n--abc\r\nnope")
        .is_err());
}

#[test]
fn rejects_7bit_high_byte() {
    let mut ring = LoopBuf::with_capacity(1 << 16);
    let mut w = MimeWriter::new();
    w.start_entity(&mut ring, None).unwrap();
    w.content_type(&mut ring, &ContentType::new("text", "plain", None))
        .unwrap();
    w.end_headers(&mut ring).unwrap();
    assert!(w.body_content(&mut ring, b"caf\xe9").is_err());
}

#[test]
fn header_after_body_fails() {
    let mut ring = LoopBuf::with_capacity(1 << 16);
    let mut w = MimeWriter::new();
    w.start_entity(&mut ring, None).unwrap();
    w.content_type(&mut ring, &ContentType::new("text", "plain", None))
        .unwrap();
    w.end_headers(&mut ring).unwrap();
    w.body_content(&mut ring, b"x").unwrap();
    assert!(w.header(&mut ring, "X-Extra", "nope").is_err());
}
