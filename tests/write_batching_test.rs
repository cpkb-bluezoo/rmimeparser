//! Writers must not issue one `write` per byte or per word: callers often
//! pass an unbuffered `File` or socket.

use rmimeparser::{
    encode_base64, encode_quoted_printable, encode_uuencode, write_folded_header, ContentType,
    MimeWriter, Parameter,
};
use std::io::Write;

/// Counts `write` calls and keeps the bytes.
#[derive(Default)]
struct Spy {
    calls: usize,
    bytes: Vec<u8>,
}

impl Write for Spy {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.calls += 1;
        self.bytes.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + i / 7) % 251) as u8).collect()
}

#[test]
fn base64_encoder_writes_in_large_blocks() {
    let mut spy = Spy::default();
    encode_base64(&mut spy, &payload(300_000)).unwrap();
    assert!(spy.calls < 400, "{} write calls", spy.calls);
}

#[test]
fn quoted_printable_encoder_writes_in_large_blocks() {
    let mut spy = Spy::default();
    encode_quoted_printable(&mut spy, &payload(100_000)).unwrap();
    assert!(spy.calls < 400, "{} write calls", spy.calls);
}

#[test]
fn uuencode_encoder_writes_in_large_blocks() {
    let mut spy = Spy::default();
    encode_uuencode(&mut spy, "f", 0o644, &payload(100_000)).unwrap();
    assert!(spy.calls < 400, "{} write calls", spy.calls);
}

#[test]
fn folded_header_is_one_write() {
    let mut spy = Spy::default();
    let value = "word ".repeat(60);
    write_folded_header(&mut spy, "Subject", value.trim_end()).unwrap();
    assert_eq!(spy.calls, 1);
    let text = String::from_utf8(spy.bytes).unwrap();
    assert!(text.starts_with("Subject: word word"));
    assert!(text.contains("\r\n "), "folded: {text:?}");
    assert!(text.ends_with("word\r\n"));
}

#[test]
fn text_body_is_written_in_runs() {
    let mut spy = Spy::default();
    {
        let mut w = MimeWriter::new(&mut spy);
        w.start_entity(None).unwrap();
        w.content_transfer_encoding("8bit").unwrap();
        w.end_headers().unwrap();
        let line = "plain text line without anything special\n".repeat(2000);
        w.body_content(line.as_bytes()).unwrap();
        w.end_entity(None).unwrap();
        w.close().unwrap();
    }
    // Headers plus one write per line (the LF becomes CRLF), not per byte.
    assert!(spy.calls < 2 * 2000 + 20, "{} write calls", spy.calls);
    let text = String::from_utf8(spy.bytes).unwrap();
    assert!(text.contains("plain text line without anything special\r\nplain text"));
    assert!(!text.contains("\n\n") && !text.replace("\r\n", "").contains('\n'));
}

#[test]
fn text_body_validation_still_applies_inside_runs() {
    for (cte, body, expect_ok) in [
        ("7bit", b"ok text\r\nmore".as_slice(), true),
        ("7bit", b"caf\xc3\xa9".as_slice(), false),
        ("8bit", b"caf\xc3\xa9".as_slice(), true),
        ("8bit", b"nul\0byte".as_slice(), false),
        ("8bit", b"bare\rcr".as_slice(), false),
    ] {
        let mut out = Vec::new();
        let mut w = MimeWriter::new(&mut out);
        w.start_entity(None).unwrap();
        w.content_transfer_encoding(cte).unwrap();
        w.end_headers().unwrap();
        assert_eq!(w.body_content(body).is_ok(), expect_ok, "{cte} {body:?}");
    }
}

#[test]
fn boundary_in_body_is_still_rejected_across_chunks() {
    let mut out = Vec::new();
    let mut w = MimeWriter::new(&mut out);
    w.start_entity(None).unwrap();
    w.content_type(&ContentType::new(
        "multipart",
        "mixed",
        Some(vec![Parameter::new("boundary", "BND")]),
    ))
    .unwrap();
    w.end_headers().unwrap();
    w.start_entity(Some("BND")).unwrap();
    w.end_headers().unwrap();
    w.body_content(b"some text\r").unwrap();
    assert!(w.body_content(b"\n--BN").is_ok());
    assert!(w.body_content(b"D tail").is_err(), "split delimiter must still be found");
}

#[test]
fn boundary_lookalikes_are_not_rejected() {
    let mut out = Vec::new();
    let mut w = MimeWriter::new(&mut out);
    w.start_entity(None).unwrap();
    w.content_type(&ContentType::new(
        "multipart",
        "mixed",
        Some(vec![Parameter::new("boundary", "BND")]),
    ))
    .unwrap();
    w.end_headers().unwrap();
    w.start_entity(Some("BND")).unwrap();
    w.end_headers().unwrap();
    // Carriage returns, dashes and a near miss, in awkward chunks.
    for chunk in [&b"a\r"[..], b"\n-", b"-BN x\r", b"\n\r\n--B", b"NX"] {
        w.body_content(chunk).unwrap();
    }
}
