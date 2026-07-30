use rmimeparser::{DkimMessageParser, MessageHandler, MimeHandler, RawHeader};

struct CaptureHandler;

impl MimeHandler for CaptureHandler {}

impl MessageHandler for CaptureHandler {}

fn parse_message(raw: &[u8]) -> (Vec<RawHeader>, Vec<u8>) {
    let mut handler = CaptureHandler;
    let mut parser = DkimMessageParser::new(&mut handler);
    let mut input: &[u8] = raw;
    parser.receive(&mut input).unwrap();
    parser.close().unwrap();
    (
        parser.raw_headers().to_vec(),
        parser.raw_body().to_vec(),
    )
}

#[test]
fn test_raw_header_preserves_fold_crlf() {
    let raw = b"Subject: hello\r\n world\r\n\r\nBody\r\n";
    let (headers, _) = parse_message(raw);

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name(), "Subject");
    assert_eq!(headers[0].bytes(), b"Subject: hello\r\n world\r\n");
    assert_eq!(headers[0].bytes_unfolded(), b"Subject: hello world\r\n");
}

#[test]
fn test_raw_header_bare_lf_fold() {
    let raw = b"Subject: hello\n world\n\nBody\n";
    let (headers, _) = parse_message(raw);

    assert_eq!(headers[0].bytes_unfolded(), b"Subject: hello world\n");
}

#[test]
fn test_multiple_same_named_headers_in_order() {
    let raw = b"Received: first\r\nReceived: second\r\n\r\n";
    let (headers, _) = parse_message(raw);

    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].bytes(), b"Received: first\r\n");
    assert_eq!(headers[1].bytes(), b"Received: second\r\n");
}

#[test]
fn test_raw_body_before_transfer_decoding() {
    let raw = b"Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n";
    let (_, body) = parse_message(raw);

    assert_eq!(body, b"SGVsbG8=\r\n");
}

#[test]
fn test_round_trip_raw_headers_and_body() {
    let mut raw = Vec::new();
    raw.extend_from_slice(b"From: sender@example.com\r\n");
    raw.extend_from_slice(b"Subject: folded\r\n");
    raw.extend_from_slice(b" line\r\n");
    raw.extend_from_slice(b"To: recipient@example.com\r\n");
    raw.extend_from_slice(b"Content-Transfer-Encoding: quoted-printable\r\n");
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(b"Hello=20World\r\n");
    let raw = raw.as_slice();

    let (headers, body) = parse_message(raw);

    let mut reconstructed = Vec::new();
    for header in &headers {
        reconstructed.extend_from_slice(header.bytes());
    }
    reconstructed.extend_from_slice(b"\r\n");
    reconstructed.extend_from_slice(&body);

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap();

    assert_eq!(&reconstructed[..header_end], &raw[..header_end]);
    assert_eq!(&reconstructed[header_end..], &raw[header_end..]);
}

#[test]
fn test_dkim_message_parser_lookup_api() {
    let raw = b"From: a@example.com\r\nDKIM-Signature: v=1; a=rsa-sha256\r\n\r\nx\r\n";
    let mut handler = CaptureHandler;
    let mut parser = DkimMessageParser::new(&mut handler);
    let mut input: &[u8] = raw;
    parser.receive(&mut input).unwrap();
    parser.close().unwrap();

    assert!(parser.is_headers_complete());
    assert!(parser.raw_header("from").is_some());
    assert_eq!(parser.header_bytes("from").unwrap(), b"From: a@example.com\r\n");
    assert_eq!(parser.all_raw_headers("dkim-signature").len(), 1);
    assert_eq!(parser.raw_body(), b"x\r\n");
}

#[test]
fn test_raw_header_as_string() {
    let header = RawHeader::new("Subject", b"Subject: test\r\n".to_vec());
    assert_eq!(header.as_string(), "Subject: test\r\n");
    assert_eq!(header.as_string_unfolded(), "Subject: test\r\n");
}

/// [`DkimMessageParser::set_body_sink`] delivers every body chunk to the
/// callback, in wire order, matching what whole-buffer `raw_body()` would
/// have produced — and once installed, `raw_body()` itself stays empty
/// (the whole point: no second full copy retained).
#[test]
fn test_body_sink_receives_chunks_matching_whole_buffer_and_raw_body_stays_empty() {
    use std::cell::RefCell;
    use std::rc::Rc;

    let raw = b"Subject: hi\r\n\r\nHello\r\nWorld\r\n";
    let mut handler = CaptureHandler;
    let mut parser = DkimMessageParser::new(&mut handler);

    let sunk = Rc::new(RefCell::new(Vec::new()));
    let sunk2 = Rc::clone(&sunk);
    parser.set_body_sink(move |chunk: &[u8]| sunk2.borrow_mut().extend_from_slice(chunk));

    let mut input: &[u8] = raw;
    parser.receive(&mut input).unwrap();
    parser.close().unwrap();

    assert_eq!(*sunk.borrow(), b"Hello\r\nWorld\r\n".to_vec());
    assert!(
        parser.raw_body().is_empty(),
        "raw_body() must not retain a second copy once a sink is installed"
    );
    // Headers are unaffected — still fully available.
    assert_eq!(parser.raw_headers().len(), 1);
}

/// Feeding the message in many tiny wire chunks (1-byte reads, the worst
/// case) — carrying any unconsumed suffix forward per `receive`'s NIO
/// compact-cursor contract, same as every other incremental consumer in
/// this codebase — must still deliver every body byte to the sink exactly
/// once, with no reordering or loss: the property a streaming DKIM hasher
/// depends on.
#[test]
fn test_body_sink_receives_all_bytes_regardless_of_wire_chunking() {
    use std::cell::RefCell;
    use std::rc::Rc;

    let raw = b"X: y\r\n\r\nThe quick brown fox jumps over the lazy dog.\r\n";
    let mut handler = CaptureHandler;
    let mut parser = DkimMessageParser::new(&mut handler);

    let sunk = Rc::new(RefCell::new(Vec::new()));
    let sunk2 = Rc::clone(&sunk);
    parser.set_body_sink(move |chunk: &[u8]| sunk2.borrow_mut().extend_from_slice(chunk));

    let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let mut carry: Vec<u8> = Vec::new();
    let mut offset = 0;
    while offset < raw.len() {
        carry.extend_from_slice(&raw[offset..offset + 1]);
        offset += 1;
        let mut slice: &[u8] = carry.as_slice();
        parser.receive(&mut slice).unwrap();
        carry = slice.to_vec();
    }
    parser.close().unwrap();

    assert_eq!(*sunk.borrow(), raw[header_end..].to_vec());
}

/// `DkimMessageParser::reset` drops a previously installed sink — reusing
/// the parser for a second message without re-installing one falls back to
/// whole-buffer retention rather than silently feeding the stale (likely
/// already-finalized) callback.
#[test]
fn test_reset_drops_the_body_sink() {
    use std::cell::RefCell;
    use std::rc::Rc;

    let mut handler = CaptureHandler;
    let mut parser = DkimMessageParser::new(&mut handler);

    let sunk = Rc::new(RefCell::new(Vec::new()));
    let sunk2 = Rc::clone(&sunk);
    parser.set_body_sink(move |chunk: &[u8]| sunk2.borrow_mut().extend_from_slice(chunk));
    let mut input: &[u8] = b"A: b\r\n\r\nfirst\r\n";
    parser.receive(&mut input).unwrap();
    parser.close().unwrap();
    assert_eq!(*sunk.borrow(), b"first\r\n".to_vec());

    parser.reset();
    let mut input: &[u8] = b"A: b\r\n\r\nsecond\r\n";
    parser.receive(&mut input).unwrap();
    parser.close().unwrap();

    // Sink was dropped by reset(), so no further calls happened...
    assert_eq!(*sunk.borrow(), b"first\r\n".to_vec());
    // ...and the second message's body was retained normally instead.
    assert_eq!(parser.raw_body(), b"second\r\n");
}
