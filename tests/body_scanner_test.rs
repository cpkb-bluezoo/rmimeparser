//! The multipart body scanner consumes bytes as they arrive. Whatever the
//! chunking, the events must be the same, and hand-checked tricky inputs
//! must come out exactly.

use rmimeparser::{MimeHandler, MimeParser, ParseResult};

/// Normalised event log: adjacent content callbacks are merged.
#[derive(Default)]
struct Log {
    events: Vec<String>,
    body: Vec<u8>,
    unexpected: Vec<u8>,
}

impl Log {
    fn flush(&mut self) {
        if !self.body.is_empty() {
            let b = std::mem::take(&mut self.body);
            self.events.push(format!("body {:?}", String::from_utf8_lossy(&b)));
        }
        if !self.unexpected.is_empty() {
            let b = std::mem::take(&mut self.unexpected);
            self.events.push(format!("unexpected {:?}", String::from_utf8_lossy(&b)));
        }
    }
}

impl MimeHandler for Log {
    fn start_entity(&mut self, b: Option<&str>) -> ParseResult<()> {
        self.flush();
        self.events.push(format!("start {b:?}"));
        Ok(())
    }
    fn end_entity(&mut self, b: Option<&str>) -> ParseResult<()> {
        self.flush();
        self.events.push(format!("end {b:?}"));
        Ok(())
    }
    fn end_headers(&mut self) -> ParseResult<()> {
        self.flush();
        self.events.push("headers".to_string());
        Ok(())
    }
    fn body_content(&mut self, d: &[u8]) -> ParseResult<()> {
        if !self.unexpected.is_empty() {
            self.flush();
        }
        self.body.extend_from_slice(d);
        Ok(())
    }
    fn unexpected_content(&mut self, d: &[u8]) -> ParseResult<()> {
        if !self.body.is_empty() {
            self.flush();
        }
        self.unexpected.extend_from_slice(d);
        Ok(())
    }
}

/// Feeds `chunks` in order, re-presenting any unconsumed tail, then `finish`.
fn run(chunks: &[&[u8]]) -> Vec<String> {
    let mut h = Log::default();
    {
        let mut p = MimeParser::new(&mut h);
        let mut pending: Vec<u8> = Vec::new();
        for (n, chunk) in chunks.iter().enumerate() {
            pending.extend_from_slice(chunk);
            let mut slice = pending.as_slice();
            if n + 1 == chunks.len() {
                p.finish(&mut slice).unwrap();
            } else {
                p.receive(&mut slice).unwrap();
            }
            let consumed = pending.len() - slice.len();
            pending.drain(..consumed);
        }
    }
    h.flush();
    h.events
}

fn whole(raw: &[u8]) -> Vec<String> {
    run(&[raw])
}

/// Same events for every two-chunk split, every three-chunk split of a
/// sample of positions, and one-byte chunks.
fn assert_chunk_invariant(raw: &[u8]) -> Vec<String> {
    let expected = whole(raw);
    for cut in 1..raw.len() {
        assert_eq!(run(&[&raw[..cut], &raw[cut..]]), expected, "split at {cut}");
    }
    let ones: Vec<&[u8]> = raw.chunks(1).collect();
    assert_eq!(run(&ones), expected, "one byte at a time");
    for step in [2usize, 3, 5, 7, 16] {
        let parts: Vec<&[u8]> = raw.chunks(step).collect();
        assert_eq!(run(&parts), expected, "chunks of {step}");
    }
    expected
}

fn bodies(events: &[String]) -> Vec<String> {
    events.iter().filter(|e| e.starts_with("body")).cloned().collect()
}

const MP: &str = "Content-Type: multipart/mixed; boundary=\"XX\"\r\n\r\n";

#[test]
fn simple_parts_with_preamble_and_epilogue() {
    let raw = format!("{MP}preamble\r\n--XX\r\nContent-Type: text/plain\r\n\r\none\r\ntwo\r\n--XX\r\n\r\nthree\r\n--XX--\r\nepilogue\r\n");
    let ev = assert_chunk_invariant(raw.as_bytes());
    assert_eq!(bodies(&ev), vec!["body \"one\\r\\ntwo\"", "body \"three\""]);
    assert!(ev.contains(&"unexpected \"preamble\"".to_string()), "{ev:?}");
    assert!(ev.iter().any(|e| e.starts_with("unexpected") && e.contains("epilogue")), "{ev:?}");
}

#[test]
fn dash_lines_that_are_not_boundaries_stay_content() {
    let raw = format!(
        "{MP}--XX\r\n\r\n-- \r\n---\r\n--XXY not a boundary\r\n--X\r\n----------------------------------------------------------------------------------------------------\r\n-\r\n--XX--\r\n"
    );
    let ev = assert_chunk_invariant(raw.as_bytes());
    let long = "-".repeat(100);
    let expect = format!("-- \r\n---\r\n--XXY not a boundary\r\n--X\r\n{long}\r\n-");
    assert_eq!(bodies(&ev), vec![format!("body {:?}", expect)]);
}

#[test]
fn blank_lines_before_a_boundary_are_content_except_the_last_ending() {
    let raw = format!("{MP}--XX\r\n\r\ntext\r\n\r\n\r\n--XX--\r\n");
    let ev = assert_chunk_invariant(raw.as_bytes());
    assert_eq!(bodies(&ev), vec!["body \"text\\r\\n\\r\\n\""]);
}

#[test]
fn bare_lf_line_endings() {
    let raw = "Content-Type: multipart/mixed; boundary=XX\n\n--XX\n\nalpha\nbeta\n--XX--\n";
    let ev = assert_chunk_invariant(raw.as_bytes());
    assert_eq!(bodies(&ev), vec!["body \"alpha\\nbeta\""]);
}

#[test]
fn empty_part_and_back_to_back_boundaries() {
    let raw = format!("{MP}--XX\r\n\r\n--XX\r\n\r\nx\r\n--XX--\r\n");
    let ev = assert_chunk_invariant(raw.as_bytes());
    assert_eq!(bodies(&ev), vec!["body \"x\""]);
    assert_eq!(ev.iter().filter(|e| e.starts_with("start")).count(), 3);
}

#[test]
fn nested_multipart() {
    let raw = "Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n--inner\r\n\r\nplain\r\n--inner\r\n\r\nhtml\r\n--inner--\r\n--outer\r\n\r\nlast\r\n--outer--\r\n";
    let ev = assert_chunk_invariant(raw.as_bytes());
    assert_eq!(bodies(&ev), vec!["body \"plain\"", "body \"html\"", "body \"last\""]);
}

#[test]
fn quoted_printable_part_with_soft_breaks() {
    let raw = format!(
        "{MP}--XX\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nsoft=\r\nbreak =3D ok=\r\n--XX\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nline one\r\nline two\r\n--XX--\r\n"
    );
    let ev = assert_chunk_invariant(raw.as_bytes());
    assert_eq!(bodies(&ev), vec!["body \"softbreak = ok\"", "body \"line one\\r\\nline two\""]);
}

#[test]
fn quoted_printable_hard_line_break_encoded_at_the_end_is_data() {
    let raw = format!("{MP}--XX\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nend=0D=0A\r\n--XX--\r\n");
    let ev = assert_chunk_invariant(raw.as_bytes());
    assert_eq!(bodies(&ev), vec!["body \"end\\r\\n\""]);
}

#[test]
fn uuencoded_part() {
    // "Cat" uuencoded
    let raw = format!(
        "{MP}--XX\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nbegin 644 f\r\n#0V%T\r\n`\r\nend\r\n--XX--\r\n"
    );
    let ev = assert_chunk_invariant(raw.as_bytes());
    assert_eq!(bodies(&ev), vec!["body \"Cat\""]);
}

#[test]
fn base64_parts_with_odd_line_lengths_and_binary_tail() {
    let raw = format!(
        "{MP}--XX\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\nREVG\r\nR0g=\r\n--XX\r\nContent-Transfer-Encoding: base64\r\n\r\nQU\r\nJD\r\n--XX--\r\n"
    );
    let ev = assert_chunk_invariant(raw.as_bytes());
    assert_eq!(bodies(&ev), vec!["body \"ABCDEFGH\"", "body \"ABC\""]);
}

#[test]
fn non_multipart_bodies_in_any_chunking() {
    let raw = "Content-Type: text/plain\r\n\r\nline one\r\n--not a boundary\r\n\r\nlast line without ending";
    let ev = assert_chunk_invariant(raw.as_bytes());
    assert_eq!(bodies(&ev), vec!["body \"line one\\r\\n--not a boundary\\r\\n\\r\\nlast line without ending\""]);
}

#[test]
fn long_unterminated_header_line_is_rejected_early() {
    let mut h = Log::default();
    let mut p = MimeParser::new(&mut h);
    let long = vec![b'a'; 5000];
    let mut slice = long.as_slice();
    assert!(p.receive(&mut slice).is_err(), "no need to wait for a newline");
}

#[test]
fn body_without_newlines_is_consumed_not_buffered() {
    let mut h = Log::default();
    let mut p = MimeParser::new(&mut h);
    let mut head: &[u8] = b"Content-Type: text/plain\r\n\r\n";
    p.receive(&mut head).unwrap();
    let blob = vec![b'x'; 1_000_000];
    let mut slice = blob.as_slice();
    p.receive(&mut slice).unwrap();
    assert!(slice.is_empty(), "the parser consumed the whole run");
    p.close().unwrap();
    h.flush();
    assert_eq!(bodies(&h.events).len(), 1);
}

/// Like `run`, but a parse error is a result rather than a panic.
fn run_result(chunks: &[&[u8]]) -> (Vec<String>, bool) {
    let mut h = Log::default();
    let mut failed = false;
    {
        let mut p = MimeParser::new(&mut h);
        let mut pending: Vec<u8> = Vec::new();
        'feed: for (n, chunk) in chunks.iter().enumerate() {
            pending.extend_from_slice(chunk);
            let mut slice = pending.as_slice();
            let r = if n + 1 == chunks.len() { p.finish(&mut slice) } else { p.receive(&mut slice) };
            if r.is_err() {
                failed = true;
                break 'feed;
            }
            let consumed = pending.len() - slice.len();
            pending.drain(..consumed);
        }
    }
    h.flush();
    (h.events, failed)
}

/// Random multipart messages made of boundary-like fragments, line endings
/// and encoded text: never a panic, and the chunking never changes the result.
#[test]
fn random_multipart_bodies_are_chunk_invariant() {
    let frags: [&str; 22] = [
        "--XX", "--XX--", "--X", "-", "--", "---", "\r\n", "\n", "\r", "text", " ", "=\r\n",
        "=3D", "QUJD", "REVG", "=", "\r\n--XX\r\n", "\r\n--XX--\r\n", "Content-Type: text/plain\r\n\r\n",
        "Content-Transfer-Encoding: base64\r\n\r\n", "Content-Transfer-Encoding: quoted-printable\r\n\r\n",
        "begin 644 f\r\n#0V%T\r\n`\r\nend\r\n",
    ];
    let mut state = 0x9E3779B9u32;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };
    for round in 0..400 {
        let mut raw = format!("{MP}").into_bytes();
        // Usually start a part so headers parse; sometimes go straight to the body.
        if next() % 4 != 0 {
            raw.extend_from_slice(b"--XX\r\n");
            if next() % 2 == 0 {
                raw.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
            } else {
                raw.extend_from_slice(b"\r\n");
            }
        }
        for _ in 0..(next() % 40) {
            raw.extend_from_slice(frags[(next() as usize) % frags.len()].as_bytes());
        }
        let expected = run_result(&[&raw]);
        for cut in 1..raw.len() {
            let got = run_result(&[&raw[..cut], &raw[cut..]]);
            assert_eq!(got, expected, "round {round} cut {cut}: {:?}", String::from_utf8_lossy(&raw));
        }
        let ones: Vec<&[u8]> = raw.chunks(1).collect();
        assert_eq!(run_result(&ones), expected, "round {round} one byte at a time");
    }
}
