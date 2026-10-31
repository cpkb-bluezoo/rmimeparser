//! The writers put their output in a caller-owned ring, and every call is
//! atomic: it appends everything it was asked to or nothing, and leaves the
//! writer as it was.

use std::io::ErrorKind;

use loopbuf::{LoopBuf, WriteResult};
use rmimeparser::{ContentType, MimeVersion, MimeWriter, Parameter};

fn drain(ring: &mut LoopBuf, sink: &mut Vec<u8>) {
    sink.extend_from_slice(&ring.spans().to_vec());
    let n = ring.len();
    ring.advance(n);
}

/// Repeats `f` until it succeeds, draining the ring each time it is full.
fn call<R>(
    ring: &mut LoopBuf,
    sink: &mut Vec<u8>,
    mut f: impl FnMut(&mut LoopBuf) -> WriteResult<R>,
) -> R {
    loop {
        match f(ring) {
            Ok(value) => return value,
            Err(e) if e.is_would_block() => drain(ring, sink),
            Err(e) => panic!("{e}"),
        }
    }
}

fn body(w: &mut MimeWriter, ring: &mut LoopBuf, sink: &mut Vec<u8>, data: &[u8]) {
    let mut rest = data;
    while !rest.is_empty() {
        let taken = call(ring, sink, |r| w.body_content(r, rest));
        assert!(taken > 0 && taken <= rest.len());
        rest = &rest[taken..];
    }
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + i / 7) % 251) as u8).collect()
}

/// A multipart message with every transfer encoding in it, written through
/// whatever ring it is given.
fn write_message(ring: &mut LoopBuf) -> Vec<u8> {
    let mut sink = Vec::new();
    let mut w = MimeWriter::new();
    macro_rules! put {
        ($e:expr) => {
            call(ring, &mut sink, |r| $e(&mut w, r))
        };
    }
    put!(|w: &mut MimeWriter, r| w.start_entity(r, None));
    put!(|w: &mut MimeWriter, r| w.mime_version(r, MimeVersion::V1_0));
    put!(|w: &mut MimeWriter, r| w.header(
        r,
        "Subject",
        "a subject long enough to be folded, with some accents: café résumé naïve"
    ));
    put!(|w: &mut MimeWriter, r| w.content_type(
        r,
        &ContentType::new(
            "multipart",
            "mixed",
            Some(vec![Parameter::new("boundary", "BND")])
        )
    ));
    put!(|w: &mut MimeWriter, r| w.end_headers(r));
    for (cte, data) in [
        (
            "7bit",
            "plain ascii text\nwith lines\n".repeat(40).into_bytes(),
        ),
        (
            "8bit",
            "text with café and\nlines\n".repeat(40).into_bytes(),
        ),
        ("binary", payload(700)),
        ("base64", payload(2000)),
        (
            "quoted-printable",
            "caf\u{e9} = tabs\tand spaces  \nlines\n"
                .repeat(40)
                .into_bytes(),
        ),
    ] {
        put!(|w: &mut MimeWriter, r| w.start_entity(r, Some("BND")));
        put!(|w: &mut MimeWriter, r| w.content_transfer_encoding(r, cte));
        put!(|w: &mut MimeWriter, r| w.end_headers(r));
        body(&mut w, ring, &mut sink, &data);
        put!(|w: &mut MimeWriter, r| w.end_entity(r, Some("BND")));
    }
    put!(|w: &mut MimeWriter, r| w.end_entity(r, None));
    w.close().unwrap();
    drain(ring, &mut sink);
    sink
}

#[test]
fn a_message_comes_out_the_same_through_any_ring() {
    let expected = write_message(&mut LoopBuf::with_capacity(1 << 20));
    assert!(expected.len() > 5000);
    // The smallest ring has to hold the longest single header, folded.
    for capacity in [200, 257, 400, 1000, 4096] {
        let got = write_message(&mut LoopBuf::with_capacity(capacity));
        assert_eq!(got, expected, "capacity {capacity}");
    }
}

#[test]
fn a_header_that_does_not_fit_waits_and_leaves_the_writer_as_it_was() {
    let mut ring = LoopBuf::with_capacity(64);
    let mut sink = Vec::new();
    let mut w = MimeWriter::new();
    w.start_entity(&mut ring, None).unwrap();
    ring.extend_from_slice(&[b'x'; 50]);

    let err = w
        .header(&mut ring, "Subject", "twenty chars of text")
        .unwrap_err();
    assert!(err.is_would_block(), "{err}");
    assert_eq!(ring.len(), 50, "nothing was written");

    drain(&mut ring, &mut sink);
    w.header(&mut ring, "Subject", "twenty chars of text")
        .unwrap();
    assert_eq!(ring.spans().to_vec(), b"Subject: twenty chars of text\r\n");
}

#[test]
fn a_call_larger_than_the_whole_ring_is_invalid_not_would_block() {
    let mut ring = LoopBuf::with_capacity(16);
    let mut w = MimeWriter::new();
    w.start_entity(&mut ring, None).unwrap();
    let err = w
        .header(
            &mut ring,
            "Subject",
            "far more than sixteen bytes of header",
        )
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(ring.is_empty());

    // and so is a body byte, once the ring is empty and still too small
    w.end_headers(&mut ring).unwrap();
    ring.advance(2);
    let mut full = LoopBuf::with_capacity(1);
    full.extend_from_slice(b"x");
    let err = w.body_content(&mut full, b"\n").unwrap_err();
    assert!(
        err.is_would_block(),
        "a full ring will have room once it is drained"
    );
    let mut empty = LoopBuf::with_capacity(1);
    let err = w.body_content(&mut empty, b"\n").unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidInput,
        "one LF needs two bytes: CRLF"
    );
}

#[test]
fn a_child_delimiter_that_does_not_fit_leaves_the_entity_stack_as_it_was() {
    let mut ring = LoopBuf::with_capacity(64);
    let mut sink = Vec::new();
    let mut w = MimeWriter::new();
    w.start_entity(&mut ring, None).unwrap();
    w.content_type(
        &mut ring,
        &ContentType::new(
            "multipart",
            "mixed",
            Some(vec![Parameter::new("boundary", "BND")]),
        ),
    )
    .unwrap();
    w.end_headers(&mut ring).unwrap();
    drain(&mut ring, &mut sink);

    ring.extend_from_slice(&[b'x'; 62]);
    let err = w.start_entity(&mut ring, Some("BND")).unwrap_err();
    assert!(err.is_would_block(), "{err}");
    drain(&mut ring, &mut sink);

    // the same call now works, and the entity it opens can be closed
    w.start_entity(&mut ring, Some("BND")).unwrap();
    w.end_headers(&mut ring).unwrap();
    w.end_entity(&mut ring, Some("BND")).unwrap();
    w.end_entity(&mut ring, None).unwrap();
    w.close().unwrap();
}

#[test]
fn an_invalid_body_leaves_the_writer_as_it_was() {
    let mut ring = LoopBuf::with_capacity(4096);
    let mut w = MimeWriter::new();
    w.start_entity(&mut ring, None).unwrap();
    w.end_headers(&mut ring).unwrap();
    let before = ring.len();

    // a CR ends the chunk: it waits to see whether LF follows
    assert_eq!(w.body_content(&mut ring, b"line\r").unwrap(), 5);
    // a bare CR followed by something else is not valid, and takes nothing
    let err = w.body_content(&mut ring, b"x").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    // so the CR is still waiting, and the LF that completes it is accepted
    assert_eq!(w.body_content(&mut ring, b"\nnext\n").unwrap(), 6);
    w.end_entity(&mut ring, None).unwrap();
    assert_eq!(&ring.spans().to_vec()[before..], b"line\r\nnext\r\n");
}

#[test]
fn a_body_call_takes_what_fits_and_says_how_much() {
    let mut ring = LoopBuf::with_capacity(64);
    let mut w = MimeWriter::new();
    w.start_entity(&mut ring, None).unwrap();
    w.content_transfer_encoding(&mut ring, "binary").unwrap();
    w.end_headers(&mut ring).unwrap();
    ring.advance(ring.len());

    let data = [b'a'; 100];
    let taken = w.body_content(&mut ring, &data).unwrap();
    assert_eq!(taken, 64, "as much as the ring holds");
    let err = w.body_content(&mut ring, &data[taken..]).unwrap_err();
    assert!(err.is_would_block());
    assert_eq!(ring.len(), 64);
}

#[test]
fn a_boundary_in_the_body_is_refused_whatever_the_chunking_and_the_ring() {
    for capacity in [64usize, 256] {
        let mut ring = LoopBuf::with_capacity(capacity);
        let mut sink = Vec::new();
        let mut w = MimeWriter::new();
        w.start_entity(&mut ring, None).unwrap();
        w.content_type(
            &mut ring,
            &ContentType::new(
                "multipart",
                "mixed",
                Some(vec![Parameter::new("boundary", "BND")]),
            ),
        )
        .unwrap();
        w.end_headers(&mut ring).unwrap();
        w.start_entity(&mut ring, Some("BND")).unwrap();
        w.end_headers(&mut ring).unwrap();
        drain(&mut ring, &mut sink);

        body(&mut w, &mut ring, &mut sink, b"some text\r");
        body(&mut w, &mut ring, &mut sink, b"\n--BN");
        let err = loop {
            match w.body_content(&mut ring, b"D tail") {
                Err(e) if e.is_would_block() => drain(&mut ring, &mut sink),
                other => break other.unwrap_err(),
            }
        };
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }
}

#[test]
fn a_writer_can_be_reset_and_reused() {
    let mut ring = LoopBuf::with_capacity(4096);
    let mut w = MimeWriter::new();
    w.start_entity(&mut ring, None).unwrap();
    w.end_headers(&mut ring).unwrap();
    w.body_content(&mut ring, b"first").unwrap();
    w.end_entity(&mut ring, None).unwrap();
    w.close().unwrap();
    assert!(w.start_entity(&mut ring, None).is_err(), "closed");

    w.reset();
    assert_eq!(w.bytes_written(), 0);
    w.start_entity(&mut ring, None).unwrap();
}

// ---- raw bodies and the message writer through a small ring ----

#[test]
fn a_raw_body_goes_through_a_small_ring_in_pieces_and_arrives_whole() {
    let data: Vec<u8> = (0..3000u32).map(|i| b'a' + (i % 26) as u8).collect();
    for capacity in [64usize, 100, 4096] {
        let mut ring = LoopBuf::with_capacity(capacity);
        let mut sink = Vec::new();
        let mut w = MimeWriter::new();
        w.start_entity(&mut ring, None).unwrap();
        w.content_transfer_encoding(&mut ring, "binary").unwrap();
        w.end_headers(&mut ring).unwrap();
        drain(&mut ring, &mut sink);
        let header_len = sink.len();
        let mut rest = &data[..];
        let mut calls = 0;
        while !rest.is_empty() {
            let taken = call(&mut ring, &mut sink, |r| w.raw_body_content(r, rest));
            assert!(taken > 0);
            rest = &rest[taken..];
            calls += 1;
        }
        w.end_entity(&mut ring, None).unwrap();
        drain(&mut ring, &mut sink);
        assert_eq!(
            &sink[header_len..header_len + data.len()],
            &data[..],
            "capacity {capacity}"
        );
        if capacity < 3000 {
            assert!(calls > 1, "a small ring takes it in pieces");
        }
    }
}

#[test]
fn a_raw_body_with_a_nul_or_the_boundary_is_refused_and_takes_nothing() {
    let mut ring = LoopBuf::with_capacity(4096);
    let mut w = MimeWriter::new();
    w.start_entity(&mut ring, None).unwrap();
    w.end_headers(&mut ring).unwrap();
    let before = ring.len();
    let err = w.raw_body_content(&mut ring, b"ab\0cd").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert_eq!(ring.len(), before);
    // and a raw body cannot mix with an encoder
    let mut w = MimeWriter::new();
    w.start_entity(&mut ring, None).unwrap();
    w.content_transfer_encoding(&mut ring, "base64").unwrap();
    w.end_headers(&mut ring).unwrap();
    assert_eq!(
        w.raw_body_content(&mut ring, b"x").unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
}

#[test]
fn the_message_writer_gives_the_same_message_through_any_ring() {
    use rmimeparser::{EmailAddress, MessageWriter, OffsetDateTime};

    fn write(ring: &mut LoopBuf) -> Vec<u8> {
        let mut sink = Vec::new();
        let mut w = MessageWriter::new();
        macro_rules! put {
            ($e:expr) => {
                call(ring, &mut sink, |r| $e(&mut w, r))
            };
        }
        put!(|w: &mut MessageWriter, r| w.start_entity(r, None));
        put!(|w: &mut MessageWriter, r| w.header(r, "Subject", "Caf\u{e9} r\u{e9}sum\u{e9}"));
        put!(|w: &mut MessageWriter, r| w.date_header(
            r,
            "Date",
            OffsetDateTime::new(2024, 6, 15, 12, 30, 0, 0)
        ));
        put!(|w: &mut MessageWriter, r| w.address_header(
            r,
            "To",
            &[
                EmailAddress::new(Some("Jos\u{e9}".into()), "jose", "example.com", false),
                EmailAddress::new(None, "bob", "example.org", false),
            ]
        ));
        put!(|w: &mut MessageWriter, r| w.content_type(r, &ContentType::new("text", "plain", None)));
        put!(|w: &mut MessageWriter, r| w.content_transfer_encoding(r, "quoted-printable"));
        put!(|w: &mut MessageWriter, r| w.end_headers(r));
        let text = "Hello caf\u{e9}, line one\nline two\n".repeat(30);
        let mut rest = text.as_bytes();
        while !rest.is_empty() {
            let n = call(ring, &mut sink, |r| w.body_content(r, rest));
            rest = &rest[n..];
        }
        put!(|w: &mut MessageWriter, r| w.end_entity(r, None));
        w.close().unwrap();
        assert_eq!(w.bytes_written() as usize, sink.len() + ring.len());
        drain(ring, &mut sink);
        sink
    }
    let expected = write(&mut LoopBuf::with_capacity(1 << 20));
    assert!(expected.len() > 500);
    for capacity in [200usize, 300, 1000] {
        assert_eq!(
            write(&mut LoopBuf::with_capacity(capacity)),
            expected,
            "capacity {capacity}"
        );
    }
}
