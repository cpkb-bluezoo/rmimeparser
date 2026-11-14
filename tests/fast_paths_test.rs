//! Parity of the word-at-a-time and grouped fast paths with plain
//! byte-at-a-time references.

use loopbuf::LoopBuf;
use rmimeparser::{decode_base64, encode_base64, index_of, Locator, MimeHandler, MimeParser};
use std::cell::Cell;
use std::rc::Rc;

#[test]
fn index_of_matches_position_at_every_offset_and_length() {
    for len in 0..40usize {
        for target in [b'\n', 0u8, 0x80, 0xFF, b'a'] {
            let base: Vec<u8> = (0..len).map(|i| b'b' + (i % 5) as u8).collect();
            assert_eq!(
                index_of(&base, target),
                base.iter().position(|&b| b == target)
            );
            for at in 0..len {
                let mut d = base.clone();
                d[at] = target;
                assert_eq!(index_of(&d, target), Some(at), "len {len} at {at}");
                // a later duplicate must not win
                if at + 1 < len {
                    d[len - 1] = target;
                    assert_eq!(index_of(&d, target), Some(at));
                }
            }
        }
    }
}

#[test]
fn index_of_ignores_bytes_that_look_like_the_target() {
    // 0x0A neighbours and high-bit bytes must not trigger false hits
    let d = [
        0x0Bu8,
        0x09,
        0x8A,
        0x0A ^ 0x80,
        0x00,
        0x01,
        0x0B,
        0x09,
        b'\n',
    ];
    assert_eq!(index_of(&d, b'\n'), Some(8));
}

fn decode_all(enc: &[u8], max: usize) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut src = enc;
    let mut used = 0;
    loop {
        let n = decode_base64(&mut src, &mut out, max, true, false);
        used += n;
        if n == 0 {
            break;
        }
    }
    (out, used)
}

#[test]
fn base64_decodes_across_line_breaks_padding_and_small_limits() {
    for len in 0..60usize {
        let raw: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
        let mut enc = Vec::new();
        encode_base64(&mut enc, &raw).unwrap();
        // wrapped as the encoder writes it, and with extra whitespace inserted
        let spaced: Vec<u8> = enc
            .iter()
            .enumerate()
            .flat_map(|(i, &b)| {
                if i % 7 == 6 {
                    vec![b, b' ', b'\r', b'\n']
                } else {
                    vec![b]
                }
            })
            .collect();
        for max in [3usize, 6, 9, 100] {
            assert_eq!(decode_all(&enc, max).0, raw, "len {len} max {max}");
            assert_eq!(
                decode_all(&spaced, max).0,
                raw,
                "spaced len {len} max {max}"
            );
        }
    }
}

#[test]
fn base64_limit_leaves_whole_quanta_unconsumed() {
    let enc = b"QUJDREVGR0hJ"; // ABCDEFGHI
    let mut src: &[u8] = enc;
    let mut out = Vec::new();
    let n = decode_base64(&mut src, &mut out, 6, false, false);
    assert_eq!((out.as_slice(), n, src), (&b"ABCDEF"[..], 8, &b"R0hJ"[..]));
}

#[test]
fn base64_invalid_character_inside_a_group_is_skipped() {
    let mut out = Vec::new();
    let mut src: &[u8] = b"QU!JD";
    decode_base64(&mut src, &mut out, 100, true, false);
    assert_eq!(out, b"ABC");
}

struct Lines(Rc<Cell<(u64, u64, u64)>>, Option<Rc<dyn Locator>>);
impl MimeHandler for Lines {
    fn set_locator(&mut self, l: Rc<dyn Locator>) {
        self.1 = Some(l);
    }
    fn end_entity(&mut self, _: Option<&str>) -> rmimeparser::ParseResult<()> {
        let l = self.1.as_ref().unwrap();
        self.0.set((l.offset(), l.line_number(), l.column_number()));
        Ok(())
    }
}

#[test]
fn locator_counts_lines_and_columns_of_a_large_body() {
    let mut msg = b"Content-Type: text/plain\r\n\r\n".to_vec();
    let line = b"0123456789abcdef\r\n";
    for _ in 0..1000 {
        msg.extend_from_slice(line);
    }
    msg.extend_from_slice(b"tail");
    let seen = Rc::new(Cell::new((0, 0, 0)));
    let mut p = MimeParser::new(Lines(seen.clone(), None));
    let mut ring = LoopBuf::with_capacity(1 << 16);
    ring.extend_from_slice(&msg);
    p.receive(&mut ring).unwrap();
    p.close(&mut ring).unwrap();
    let (offset, lines, col) = seen.get();
    assert_eq!(offset, msg.len() as u64);
    assert_eq!(lines, 1003); // numbering starts at 1
    assert_eq!(col, 4);
}
