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
