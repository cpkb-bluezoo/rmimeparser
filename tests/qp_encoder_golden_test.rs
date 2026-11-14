//! The quoted-printable encoder's output over a fixed corpus is pinned by a
//! hash, so a faster encoder is known to write the same bytes; whatever the
//! chunking of the input, the output is the same, and decodes back.

use rmimeparser::{decode_quoted_printable, QuotedPrintableEncoder};

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }
}

/// Inputs that exercise words, runs of white space, long lines, bare CR and
/// LF, `=`, and bytes needing escapes, in varying mixes.
fn corpus() -> Vec<Vec<u8>> {
    let alphabets: [&[u8]; 6] = [
        b"abcdefghij  \t\r\n",
        b"abcdefghijklmnopqrstuvwxyz ",
        b"ab= \t\r\n\x01\x7f\xe9\xff",
        b"abcdefghijklmnopqrstuvwxyz0123456789.,;:!? ",
        b"\r\n \t",
        b"x",
    ];
    let mut rng = Lcg(12345);
    let mut out = Vec::new();
    for round in 0..600 {
        let alphabet = alphabets[round % alphabets.len()];
        let len = (rng.next() % 400) as usize + if round % 7 == 0 { 300 } else { 0 };
        let mut v: Vec<u8> = (0..len)
            .map(|_| alphabet[rng.next() as usize % alphabet.len()])
            .collect();
        if round % 5 == 0 {
            // fully random bytes
            v.iter_mut().for_each(|b| *b = rng.next() as u8);
        }
        out.push(v);
    }
    out.push(Vec::new());
    out.push(b"trailing space ".to_vec());
    out.push(b"trailing tab\t\r\nnext".to_vec());
    out.push(b"ends with cr\r".to_vec());
    out.push("A line that is plain text and long enough to need a soft break somewhere after column seventy-five, ok?\r\n".as_bytes().to_vec());
    out
}

fn encode(data: &[u8], chunk: usize) -> Vec<u8> {
    let mut enc = QuotedPrintableEncoder::new();
    let mut out = Vec::new();
    for c in data.chunks(chunk.max(1)) {
        enc.write(&mut out, c).unwrap();
    }
    enc.finish(&mut out).unwrap();
    out
}

fn fnv(h: &mut u64, bytes: &[u8]) {
    for &b in bytes {
        *h = (*h ^ b as u64).wrapping_mul(0x100000001b3);
    }
}

#[test]
fn output_is_stable_and_independent_of_chunking() {
    let mut hash = 0xcbf29ce484222325u64;
    for data in corpus() {
        let whole = encode(&data, usize::MAX);
        fnv(&mut hash, &whole);
        fnv(&mut hash, &[0xff]);
        for chunk in [1usize, 2, 3, 7, 64, 77] {
            assert_eq!(encode(&data, chunk), whole, "chunk {chunk}");
        }
        for line in whole.split(|&b| b == b'\n') {
            assert!(line.len() <= 77, "line of {} bytes", line.len());
        }
    }
    assert_eq!(
        hash, GOLDEN,
        "encoder output changed: hash is now {hash:#x}"
    );
}

#[test]
fn output_decodes_to_the_input_with_line_breaks_normalised() {
    for data in corpus() {
        let enc = encode(&data, usize::MAX);
        let mut src = enc.as_slice();
        let mut dst = Vec::new();
        decode_quoted_printable(&mut src, &mut dst, usize::MAX / 2, true);
        // bare LF is written as CRLF; trailing white space before a break is escaped, not lost
        let mut expect = Vec::new();
        let mut i = 0;
        while i < data.len() {
            if data[i] == b'\n' && (i == 0 || data[i - 1] != b'\r') {
                expect.extend_from_slice(b"\r\n");
            } else {
                expect.push(data[i]);
            }
            i += 1;
        }
        assert_eq!(dst, expect);
    }
}

const GOLDEN: u64 = 0xcfa227cb1dee7cc7;
