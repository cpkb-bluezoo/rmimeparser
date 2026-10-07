use rmimeparser::{
    decode_base64, decode_quoted_printable, encode_base64, encode_quoted_printable,
    Base64Encoder, QuotedPrintableEncoder, BASE64_MAX_LINE_LENGTH,
};

fn round_trip_base64(data: &[u8]) {
    let mut encoded = Vec::new();
    encode_base64(&mut encoded, data).unwrap();

    // Lines (except possibly last) must be ≤ 76.
    let text = String::from_utf8_lossy(&encoded);
    for line in text.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        assert!(
            line.len() <= BASE64_MAX_LINE_LENGTH,
            "line too long: {} ({line})",
            line.len()
        );
    }

    let mut src = &encoded[..];
    let mut decoded = Vec::new();
    decode_base64(&mut src, &mut decoded, data.len() + 16, true, false);
    assert_eq!(decoded, data);
}

fn round_trip_qp(data: &[u8]) {
    let mut encoded = Vec::new();
    encode_quoted_printable(&mut encoded, data).unwrap();
    let mut src = &encoded[..];
    let mut decoded = Vec::new();
    decode_quoted_printable(&mut src, &mut decoded, data.len() + 64, true);
    assert_eq!(decoded, data);
}

#[test]
fn base64_empty() {
    round_trip_base64(b"");
}

#[test]
fn base64_short() {
    round_trip_base64(b"Hello");
    round_trip_base64(b"Hi");
    round_trip_base64(b"A");
}

#[test]
fn base64_long_wraps() {
    let data = vec![b'x'; 200];
    round_trip_base64(&data);
}

#[test]
fn base64_chunked_matches_oneshot() {
    let data: Vec<u8> = (0..100u8).cycle().take(250).collect();

    let mut oneshot = Vec::new();
    encode_base64(&mut oneshot, &data).unwrap();

    let mut chunked = Vec::new();
    let mut enc = Base64Encoder::new();
    for chunk in data.chunks(7) {
        enc.write(&mut chunked, chunk).unwrap();
    }
    enc.finish(&mut chunked).unwrap();

    assert_eq!(chunked, oneshot);

    let mut src = &chunked[..];
    let mut decoded = Vec::new();
    decode_base64(&mut src, &mut decoded, data.len() + 8, true, false);
    assert_eq!(decoded, data);
}

#[test]
fn qp_simple() {
    round_trip_qp(b"Hello world");
}

#[test]
fn qp_equals_and_high_bytes() {
    round_trip_qp(b"a=b\xc3\xa9");
}

#[test]
fn qp_trailing_space_encoded() {
    let mut encoded = Vec::new();
    encode_quoted_printable(&mut encoded, b"hello ").unwrap();
    let s = String::from_utf8(encoded).unwrap();
    assert!(s.contains("=20"), "expected trailing space encoded: {s}");
}

#[test]
fn qp_chunked_matches_oneshot() {
    let data = b"Line one with = signs\r\nLine two \r\nSoft?";
    let mut oneshot = Vec::new();
    encode_quoted_printable(&mut oneshot, data).unwrap();

    let mut chunked = Vec::new();
    let mut enc = QuotedPrintableEncoder::new();
    for chunk in data.chunks(5) {
        enc.write(&mut chunked, chunk).unwrap();
    }
    enc.finish(&mut chunked).unwrap();

    assert_eq!(chunked, oneshot);
    round_trip_qp(data);
}

#[test]
fn qp_long_line_soft_breaks() {
    let data = vec![b'A'; 100];
    let mut encoded = Vec::new();
    encode_quoted_printable(&mut encoded, &data).unwrap();
    let text = String::from_utf8_lossy(&encoded);
    assert!(text.contains("=\r\n"));
    round_trip_qp(&data);
}

/// The byte-at-a-time quoted-printable algorithm the bulk fast path replaced.
fn reference_qp(data: &[u8]) -> Vec<u8> {
    const LIMIT: usize = 76;
    let hex = b"0123456789ABCDEF";
    let mut out = Vec::new();
    let mut line_len = 0usize;
    let mut pending: Option<u8> = None;
    fn emit(out: &mut Vec<u8>, line_len: &mut usize, b: u8, encode: bool, hex: &[u8; 16]) {
        let n = if encode { 3 } else { 1 };
        if *line_len + n > LIMIT - 1 && *line_len > 0 {
            out.extend_from_slice(b"=\r\n");
            *line_len = 0;
        }
        if encode {
            out.extend_from_slice(&[b'=', hex[(b >> 4) as usize], hex[(b & 15) as usize]]);
            *line_len += 3;
        } else {
            out.push(b);
            *line_len += 1;
        }
    }
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if b == b'\r' && i + 1 < data.len() && data[i + 1] == b'\n' {
            if let Some(w) = pending.take() {
                emit(&mut out, &mut line_len, w, true, hex);
            }
            out.extend_from_slice(b"\r\n");
            line_len = 0;
            i += 2;
        } else if b == b'\n' {
            if let Some(w) = pending.take() {
                emit(&mut out, &mut line_len, w, true, hex);
            }
            out.extend_from_slice(b"\r\n");
            line_len = 0;
            i += 1;
        } else if b == b' ' || b == b'\t' {
            if let Some(w) = pending.take() {
                emit(&mut out, &mut line_len, w, false, hex);
            }
            pending = Some(b);
            i += 1;
        } else {
            if let Some(w) = pending.take() {
                emit(&mut out, &mut line_len, w, false, hex);
            }
            let enc = b == b'\r' || b > 126 || b < 32 || b == b'=';
            emit(&mut out, &mut line_len, b, enc, hex);
            i += 1;
        }
    }
    if let Some(w) = pending.take() {
        emit(&mut out, &mut line_len, w, true, hex);
    }
    out
}

#[test]
fn quoted_printable_encoder_matches_byte_at_a_time_reference() {
    // Deterministic pseudo-random inputs biased towards the interesting bytes.
    let alphabet: &[u8] = b"abcXYZ019 \t\r\n=.-~\x00\x1f\x7f\x80\xff";
    let mut state = 0x2545F491u32;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };
    for round in 0..300 {
        let len = (next() % 400) as usize + (round % 5) * 100;
        let data: Vec<u8> = (0..len)
            .map(|_| {
                if next() % 4 == 0 {
                    alphabet[(next() as usize) % alphabet.len()]
                } else {
                    b'a' + (next() % 26) as u8
                }
            })
            .collect();
        let mut got = Vec::new();
        encode_quoted_printable(&mut got, &data).unwrap();
        assert_eq!(got, reference_qp(&data), "round {round} len {len}");

        // Any chunking gives the same output.
        let mut enc = QuotedPrintableEncoder::new();
        let mut chunked = Vec::new();
        let mut rest = data.as_slice();
        while !rest.is_empty() {
            let n = ((next() % 9) as usize + 1).min(rest.len());
            enc.write(&mut chunked, &rest[..n]).unwrap();
            rest = &rest[n..];
        }
        enc.finish(&mut chunked).unwrap();
        assert_eq!(chunked, got, "chunked, round {round}");
    }
}
