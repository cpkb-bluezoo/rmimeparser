use loopbuf::LoopBuf;
use rmimeparser::{DkimMessageParser, MessageHandler, MimeHandler, RawHeader};

struct CaptureHandler;

impl MimeHandler for CaptureHandler {}

impl MessageHandler for CaptureHandler {}

/// A ring holding `bytes`, with room to spare.
fn ring(bytes: &[u8]) -> LoopBuf {
    let mut buf = LoopBuf::with_capacity(bytes.len() + 2048);
    buf.extend_from_slice(bytes);
    buf
}

fn parse_message(raw: &[u8]) -> (Vec<RawHeader>, Vec<u8>) {
    let mut handler = CaptureHandler;
    let mut parser = DkimMessageParser::new(&mut handler);
    let mut input = ring(raw);
    parser.receive(&mut input).unwrap();
    parser.close(&mut input).unwrap();
    (parser.raw_headers().to_vec(), parser.raw_body().to_vec())
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
    let mut input = ring(raw);
    parser.receive(&mut input).unwrap();
    parser.close(&mut input).unwrap();

    assert!(parser.is_headers_complete());
    assert!(parser.raw_header("from").is_some());
    assert_eq!(
        parser.header_bytes("from").unwrap(),
        b"From: a@example.com\r\n"
    );
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

    let mut input = ring(raw);
    parser.receive(&mut input).unwrap();
    parser.close(&mut input).unwrap();

    assert_eq!(*sunk.borrow(), b"Hello\r\nWorld\r\n".to_vec());
    assert!(
        parser.raw_body().is_empty(),
        "raw_body() must not retain a second copy once a sink is installed"
    );
    // Headers are unaffected — still fully available.
    assert_eq!(parser.raw_headers().len(), 1);
}

/// Feeding the message in many tiny wire chunks (1-byte reads, the worst
/// case), the ring keeping whatever the parser has not consumed — must still deliver every body byte to the sink exactly
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
    let mut ring = LoopBuf::with_capacity(2048);
    for byte in raw {
        ring.extend_from_slice(&[*byte]);
        parser.receive(&mut ring).unwrap();
    }
    parser.close(&mut ring).unwrap();

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
    let mut input = ring(b"A: b\r\n\r\nfirst\r\n");
    parser.receive(&mut input).unwrap();
    parser.close(&mut input).unwrap();
    assert_eq!(*sunk.borrow(), b"first\r\n".to_vec());

    parser.reset();
    let mut input = ring(b"A: b\r\n\r\nsecond\r\n");
    parser.receive(&mut input).unwrap();
    parser.close(&mut input).unwrap();

    // Sink was dropped by reset(), so no further calls happened...
    assert_eq!(*sunk.borrow(), b"first\r\n".to_vec());
    // ...and the second message's body was retained normally instead.
    assert_eq!(parser.raw_body(), b"second\r\n");
}

/// Stored mail often ends without a final line terminator; `close` accepts
/// an unterminated closing boundary, whatever the chunking.
#[test]
fn test_close_accepts_unterminated_closing_boundary() {
    let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nbody\r\n--b--";

    for step in [1usize, 7, raw.len()] {
        let mut handler = CaptureHandler;
        let mut parser = DkimMessageParser::new(&mut handler);
        let mut ring = LoopBuf::with_capacity(2048);
        for chunk in raw.chunks(step) {
            ring.extend_from_slice(chunk);
            parser.receive(&mut ring).unwrap();
        }
        parser.close(&mut ring).unwrap();
        assert_eq!(parser.raw_body(), b"--b\r\nbody\r\n--b--", "step {step}");
        assert_eq!(parser.raw_headers().len(), 1);
    }
}

#[test]
fn test_close_keeps_final_header_line_without_terminator() {
    let raw = b"Subject: hello\r\nX-Last: no terminator";
    let mut handler = CaptureHandler;
    let mut parser = DkimMessageParser::new(&mut handler);
    let mut input = ring(raw);
    parser.close(&mut input).unwrap();
    assert_eq!(parser.raw_headers().len(), 2);
    assert_eq!(parser.raw_headers()[1].bytes(), b"X-Last: no terminator");
}

// ---- capturing only the headers a signature covers ----

fn big_message() -> Vec<u8> {
    let mut m =
        b"DKIM-Signature: v=1; a=rsa-sha256; h=from:Subject; d=example.org;\r\n b=abc\r\n".to_vec();
    m.extend_from_slice(b"Received: from a.example\r\n by b.example\r\n");
    m.extend_from_slice(b"FROM: alice@example.org\r\n");
    m.extend_from_slice(b"X-Big: ");
    m.extend_from_slice(&[b'x'; 500]);
    m.extend_from_slice(b"\r\n");
    m.extend_from_slice(b"Subject: hello\r\n world\r\n");
    m.extend_from_slice(b"\r\nBody\r\n");
    m
}

fn feed(parser: &mut DkimMessageParser<&mut CaptureHandler>, message: &[u8], step: usize) {
    let mut ring = LoopBuf::with_capacity(4096);
    for chunk in message.chunks(step) {
        ring.extend_from_slice(chunk);
        parser.receive(&mut ring).unwrap();
    }
    parser.close(&mut ring).unwrap();
}

#[test]
fn capture_only_keeps_just_the_named_headers_and_nothing_else_is_held() {
    let message = big_message();
    for step in [1usize, 7, 4000] {
        let mut handler = CaptureHandler;
        let mut parser = DkimMessageParser::new(&mut handler);
        parser.capture_only(["from", "dkim-signature"]);
        feed(&mut parser, &message, step);
        let names: Vec<&str> = parser.raw_headers().iter().map(|h| h.name()).collect();
        assert_eq!(names, ["DKIM-Signature", "FROM"], "step {step}");
        assert_eq!(
            parser.header_bytes("from").unwrap(),
            b"FROM: alice@example.org\r\n"
        );
        // the folded signature keeps its fold
        assert!(parser
            .header_bytes("dkim-signature")
            .unwrap()
            .ends_with(b"\r\n b=abc\r\n"));
        // and the body is untouched
        assert_eq!(parser.raw_body(), b"Body\r\n");
    }
}

#[test]
fn a_header_that_is_not_captured_does_not_count_against_the_capture_limit() {
    let message = big_message();
    // X-Big is over 500 bytes: with a limit of 200, capturing it is an error
    let mut handler = CaptureHandler;
    let mut parser = DkimMessageParser::new(&mut handler);
    parser.limits_mut().max_captured_header_size = Some(200);
    let mut ring = LoopBuf::with_capacity(4096);
    ring.extend_from_slice(&message);
    let err = parser.receive(&mut ring).unwrap_err();
    assert!(err.message().contains("maximum"), "{err}");

    // but when it is not wanted, it is never accumulated
    let mut handler = CaptureHandler;
    let mut parser = DkimMessageParser::new(&mut handler);
    parser.limits_mut().max_captured_header_size = Some(200);
    parser.capture_only(["from", "subject"]);
    feed(&mut parser, &message, 100);
    assert_eq!(parser.raw_headers().len(), 2);
}

/// A verifier learns what to capture from the signature, which sits above the
/// headers it covers.
#[test]
fn a_signature_can_widen_what_is_captured_before_the_headers_it_covers_arrive() {
    use std::cell::RefCell;
    use std::rc::Rc;

    let message = big_message();
    // the whole message in one go is the hard case: every header is read in
    // one call to receive, so there is no chance to widen between calls
    for step in [1usize, 5, 4000] {
        let wanted = Rc::new(RefCell::new(vec!["dkim-signature".to_string()]));
        let mut handler = CaptureHandler;
        let mut parser = DkimMessageParser::new(&mut handler);
        let for_filter = Rc::clone(&wanted);
        parser.set_header_filter(move |name| {
            for_filter
                .borrow()
                .iter()
                .any(|w| name.eq_ignore_ascii_case(w))
        });
        let for_callback = Rc::clone(&wanted);
        parser.set_header_callback(move |header| {
            if header.name().eq_ignore_ascii_case("dkim-signature") {
                let text = String::from_utf8_lossy(&header.bytes_unfolded()).to_string();
                let h = text
                    .split(';')
                    .find_map(|tag| tag.trim().strip_prefix("h="))
                    .unwrap_or("");
                for name in h.split(':') {
                    for_callback
                        .borrow_mut()
                        .push(name.trim().to_ascii_lowercase());
                }
            }
        });
        feed(&mut parser, &message, step);
        let names: Vec<&str> = parser.raw_headers().iter().map(|h| h.name()).collect();
        assert_eq!(names, ["DKIM-Signature", "FROM", "Subject"], "step {step}");
    }
}

#[test]
fn without_a_filter_every_header_is_captured_and_reset_drops_the_filter() {
    let message = big_message();
    let mut handler = CaptureHandler;
    let mut parser = DkimMessageParser::new(&mut handler);
    parser.capture_only(["from"]);
    feed(&mut parser, &message, 4000);
    assert_eq!(parser.raw_headers().len(), 1);

    parser.reset();
    feed(&mut parser, &message, 4000);
    assert_eq!(parser.raw_headers().len(), 5, "every header again");
}
