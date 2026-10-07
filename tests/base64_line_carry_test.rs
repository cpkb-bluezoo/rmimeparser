//! base64 bodies whose lines are not a multiple of four characters: the
//! partial quantum at the end of a line continues on the next line.

use rmimeparser::{MimeHandler, MimeParser, ParseResult};

#[derive(Default)]
struct Collect {
    bodies: Vec<Vec<u8>>,
    current: Vec<u8>,
}

impl MimeHandler for Collect {
    fn start_entity(&mut self, _b: Option<&str>) -> ParseResult<()> {
        self.current.clear();
        Ok(())
    }
    fn body_content(&mut self, data: &[u8]) -> ParseResult<()> {
        self.current.extend_from_slice(data);
        Ok(())
    }
    fn end_entity(&mut self, _b: Option<&str>) -> ParseResult<()> {
        if !self.current.is_empty() {
            self.bodies.push(std::mem::take(&mut self.current));
        }
        Ok(())
    }
}

fn parse_in_chunks(raw: &[u8], step: usize) -> Vec<Vec<u8>> {
    let mut h = Collect::default();
    {
        let mut p = MimeParser::new(&mut h);
        let mut pending: Vec<u8> = Vec::new();
        let mut offset = 0;
        while offset < raw.len() {
            let end = (offset + step).min(raw.len());
            pending.extend_from_slice(&raw[offset..end]);
            offset = end;
            let mut slice = pending.as_slice();
            if offset == raw.len() {
                p.finish(&mut slice).unwrap();
            } else {
                p.receive(&mut slice).unwrap();
            }
            let consumed = pending.len() - slice.len();
            pending.drain(..consumed);
        }
    }
    h.bodies
}

const HEAD: &str = "Content-Transfer-Encoding: base64\r\n\r\n";

#[test]
fn lines_of_six_characters() {
    // "ABCDEFGHI" = QUJDREVGR0hJ
    let raw = format!("{HEAD}QUJDRE\r\nVGR0hJ\r\n");
    for step in [1usize, 3, raw.len()] {
        assert_eq!(parse_in_chunks(raw.as_bytes(), step), vec![b"ABCDEFGHI".to_vec()], "step {step}");
    }
}

#[test]
fn lines_of_one_and_two_characters_with_padding() {
    // "ABCDEFGH" = QUJDREVGR0g=
    let raw = format!("{HEAD}Q\r\nU\r\nJD\r\nREVG\r\nR\r\n0g=\r\n");
    for step in [1usize, 2, raw.len()] {
        assert_eq!(parse_in_chunks(raw.as_bytes(), step), vec![b"ABCDEFGH".to_vec()], "step {step}");
    }
}

#[test]
fn unaligned_lines_without_padding_end_cleanly() {
    // "ABCDE" = QUJDREU= ; the producer left the padding off.
    let raw = format!("{HEAD}QUJ\r\nDREU\r\n");
    assert_eq!(parse_in_chunks(raw.as_bytes(), 4), vec![b"ABCDE".to_vec()]);
}

#[test]
fn unaligned_lines_inside_multipart() {
    let raw = format!(
        "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n{HEAD}QUJDRE\r\nVGR0hJ\r\n--b\r\n{HEAD}QUJ\r\nDREU=\r\n--b--\r\n"
    );
    for step in [1usize, 5, raw.len()] {
        assert_eq!(
            parse_in_chunks(raw.as_bytes(), step),
            vec![b"ABCDEFGHI".to_vec(), b"ABCDE".to_vec()],
            "step {step}"
        );
    }
}

/// A decoded attachment that happens to end in a line break keeps it: the
/// line ending stripped before a boundary is the encoded text's, not the
/// decoded data's.
#[test]
fn decoded_data_ending_in_newline_survives_before_boundary() {
    // "hello\r\n" = aGVsbG8NCg== ; "hello\n" = aGVsbG8K
    let raw = format!(
        "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n{HEAD}aGVsbG8NCg==\r\n--b\r\n{HEAD}aGVsbG8K\r\n--b--\r\n"
    );
    for step in [1usize, 7, raw.len()] {
        assert_eq!(
            parse_in_chunks(raw.as_bytes(), step),
            vec![b"hello\r\n".to_vec(), b"hello\n".to_vec()],
            "step {step}"
        );
    }
}

/// Overlong base64 lines (some producers ignore the 76 column limit) are
/// decoded, never a panic.
#[test]
fn base64_line_longer_than_76_columns_decodes() {
    let data: Vec<u8> = (0..90u8).collect();
    let mut encoded = Vec::new();
    rmimeparser::encode_base64(&mut encoded, &data).unwrap();
    let one_line: String = String::from_utf8(encoded).unwrap().replace("\r\n", "");
    assert!(one_line.len() > 76);
    let raw = format!("{HEAD}{one_line}\r\n");
    for step in [1usize, 50, raw.len()] {
        assert_eq!(parse_in_chunks(raw.as_bytes(), step), vec![data.clone()], "step {step}");
    }
}
