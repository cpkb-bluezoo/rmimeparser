use rmimeparser::{
    decode_uuencode, encode_uuencode, estimate_uuencode_decoded_size, MimeHandler, MimeParser,
    ParseResult, UuencodeDecoder, UuencodeEncoder, UUENCODE_LINE_BYTES,
};

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 7919 + i / 3) % 256) as u8).collect()
}

fn encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_uuencode(&mut out, "file.bin", 0o644, data).unwrap();
    out
}

fn decode_all(encoded: &[u8]) -> Vec<u8> {
    let mut src = encoded;
    let mut dst = Vec::new();
    decode_uuencode(&mut src, &mut dst, estimate_uuencode_decoded_size(encoded.len()), true);
    assert!(src.is_empty(), "everything consumed at end of stream");
    dst
}

/// The classic example from the uuencode manual page.
#[test]
fn cat_is_the_textbook_line() {
    let encoded = encode(b"Cat");
    assert_eq!(encoded, b"begin 644 file.bin\r\n#0V%T\r\n`\r\nend\r\n");
    assert_eq!(decode_all(&encoded), b"Cat");
}

#[test]
fn round_trips_every_length_around_the_line_size() {
    for len in [0usize, 1, 2, 3, 4, 44, 45, 46, 89, 90, 91, 100, 1000] {
        let data = sample(len);
        let encoded = encode(&data);
        assert_eq!(decode_all(&encoded), data, "len {len}");
        let text = String::from_utf8(encoded.clone()).unwrap();
        for line in text.lines().filter(|l| !l.starts_with("begin") && *l != "end" && *l != "`") {
            assert!(line.len() <= 1 + (UUENCODE_LINE_BYTES + 2) / 3 * 4, "{line}");
            assert!(!line.ends_with(' '), "no trailing whitespace: {line:?}");
        }
    }
}

#[test]
fn streaming_encoder_matches_one_shot_whatever_the_write_sizes() {
    let data = sample(500);
    let whole = encode(&data);
    for step in [1usize, 2, 3, 7, 44, 45, 46, 128] {
        let mut enc = UuencodeEncoder::new("file.bin", 0o644);
        let mut out = Vec::new();
        for chunk in data.chunks(step) {
            enc.write(&mut out, chunk).unwrap();
        }
        enc.finish(&mut out).unwrap();
        assert_eq!(out, whole, "step {step}");
    }
}

/// Feeding the decoder arbitrary chunks with the parser's leftover
/// convention gives the same bytes as one shot, at every split size.
#[test]
fn decoder_resumes_at_any_chunk_boundary() {
    let data = sample(300);
    let encoded = encode(&data);
    for step in 1..=encoded.len() {
        let mut pending: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        let mut offset = 0;
        while offset < encoded.len() {
            let end = (offset + step).min(encoded.len());
            pending.extend_from_slice(&encoded[offset..end]);
            offset = end;
            let mut src = pending.as_slice();
            decode_uuencode(&mut src, &mut out, usize::MAX, offset == encoded.len());
            let left = src.len();
            let consumed = pending.len() - left;
            pending.drain(..consumed);
        }
        assert!(pending.is_empty(), "step {step}");
        assert_eq!(out, data, "step {step}");
    }
}

#[test]
fn framing_blank_and_lf_only_lines_are_tolerated() {
    let encoded = b"begin 644 x\n\n#0V%T\n`\nend\n";
    assert_eq!(decode_all(encoded), b"Cat");
    // Lines may be padded with spaces by other encoders.
    let padded = b"begin 644 x\r\n#0V%T  \r\n`\r\nend\r\n";
    assert_eq!(decode_all(padded), b"Cat");
    // A final line without its terminator is only taken at end of stream.
    let mut src: &[u8] = b"#0V%T";
    let mut dst = Vec::new();
    assert_eq!(decode_uuencode(&mut src, &mut dst, 64, false), 0);
    assert!(dst.is_empty());
    assert_eq!(UuencodeDecoder::decode_eos(&mut src, &mut dst, 64, true), 5);
    assert_eq!(dst, b"Cat");
}

#[test]
fn output_cap_stops_at_a_line_boundary_and_leaves_the_rest() {
    let data = sample(90);
    let encoded = encode(&data);
    let mut src = encoded.as_slice();
    let mut dst = Vec::new();
    // Room for one 45-byte line only.
    let consumed = UuencodeDecoder::decode(&mut src, &mut dst, 50);
    assert_eq!(dst, &data[..45]);
    assert_eq!(consumed, encoded.len() - src.len());
    assert!(src.starts_with(b"M"), "second line left intact");
    let mut rest = Vec::new();
    decode_uuencode(&mut src, &mut rest, 1000, true);
    assert_eq!(rest, &data[45..]);
}

#[derive(Default)]
struct BodyCollector {
    cte: Option<String>,
    body: Vec<u8>,
}

impl MimeHandler for BodyCollector {
    fn content_transfer_encoding(&mut self, encoding: &str) -> ParseResult<()> {
        self.cte = Some(encoding.to_string());
        Ok(())
    }
    fn body_content(&mut self, content: &[u8]) -> ParseResult<()> {
        self.body.extend_from_slice(content);
        Ok(())
    }
}

/// A `Content-Transfer-Encoding: x-uuencode` body reaches the handler
/// decoded, however the message is split.
#[test]
fn parser_decodes_an_x_uuencode_body() {
    let data = sample(200);
    let mut message = b"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\n".to_vec();
    message.extend_from_slice(&encode(&data));
    for step in [1usize, 5, 64, message.len()] {
        let mut handler = BodyCollector::default();
        {
            let mut parser = MimeParser::new(&mut handler);
            let mut pending: Vec<u8> = Vec::new();
            for chunk in message.chunks(step) {
                pending.extend_from_slice(chunk);
                let mut slice = pending.as_slice();
                parser.receive(&mut slice).unwrap();
                let left = slice.len();
                let consumed = pending.len() - left;
                pending.drain(..consumed);
            }
            parser.close().unwrap();
        }
        assert_eq!(handler.cte.as_deref(), Some("x-uuencode"), "step {step}");
        assert_eq!(handler.body, data, "step {step}");
    }
}
