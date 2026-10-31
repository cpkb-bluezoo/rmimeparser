//! Randomized input for the streaming header machines.
//!
//! The recorded tables prove the grammars on the cases someone thought of.
//! These generate thousands of nasty headers from a vocabulary of the pieces
//! that matter (quotes, comments, encoded words, partial UTF-8, percent
//! sequences, continuations), and check what must hold of any input:
//!
//! * the parser never panics and never fails on a header that is merely odd:
//!   something it cannot read is reported through `malformed_header`;
//! * the events are the same however the input is cut into pieces.
//!
//! The generator is deterministic, so a failure reproduces.

use loopbuf::LoopBuf;
use rmimeparser::{
    ContentDispositionParser, ContentTypeParser, HeaderTextDecoder, MessageHandler, MessageParser,
    MimeHandler, ObsoleteStructureType, ParseResult,
};

/// The seed and the number of rounds, from `FUZZ_SEED` and `FUZZ_ROUNDS` when
/// set, so that more of the input space can be searched than the fixed run
/// covers: `FUZZ_SEED=7 FUZZ_ROUNDS=50000 cargo test --test header_fuzz_test`.
fn seed(default: u64) -> u64 {
    std::env::var("FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map_or(default, |s| {
            default ^ s.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1
        })
}

fn rounds(default: usize) -> usize {
    std::env::var("FUZZ_ROUNDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Every event, with runs of text joined (a piece has no particular size).
#[derive(Default)]
struct Events {
    out: Vec<String>,
    text: String,
}

impl Events {
    fn flush(&mut self) {
        if !self.text.is_empty() {
            let t = std::mem::take(&mut self.text);
            self.out.push(format!("text {t:?}"));
        }
    }
    fn push(&mut self, event: String) {
        self.flush();
        self.out.push(event);
    }
}

impl MimeHandler for Events {
    fn start_header(&mut self, n: &str) -> ParseResult<()> {
        self.push(format!("header {n}"));
        Ok(())
    }
    fn header_content(&mut self, t: &str) -> ParseResult<()> {
        self.text.push_str(t);
        Ok(())
    }
    fn end_header(&mut self) -> ParseResult<()> {
        self.push("end header".into());
        Ok(())
    }
    fn start_content_type(&mut self, p: &str, s: &str) -> ParseResult<()> {
        self.push(format!("ct {p}/{s}"));
        Ok(())
    }
    fn end_content_type(&mut self) -> ParseResult<()> {
        self.push("end ct".into());
        Ok(())
    }
    fn start_content_disposition(&mut self, k: &str) -> ParseResult<()> {
        self.push(format!("cd {k}"));
        Ok(())
    }
    fn end_content_disposition(&mut self) -> ParseResult<()> {
        self.push("end cd".into());
        Ok(())
    }
    fn start_parameter(&mut self, n: &str, l: Option<&str>) -> ParseResult<()> {
        self.push(format!("param {n} {l:?}"));
        Ok(())
    }
    fn parameter_content(&mut self, t: &str) -> ParseResult<()> {
        self.text.push_str(t);
        Ok(())
    }
    fn end_parameter(&mut self) -> ParseResult<()> {
        self.push("end param".into());
        Ok(())
    }
    fn malformed_header(&mut self, n: &str, r: &str) -> ParseResult<()> {
        self.push(format!("malformed {n}: {r}"));
        Ok(())
    }
    fn content_transfer_encoding(&mut self, e: &str) -> ParseResult<()> {
        self.push(format!("cte {e}"));
        Ok(())
    }
    fn content_id(&mut self, id: &rmimeparser::ContentId) -> ParseResult<()> {
        self.push(format!("cid {id}"));
        Ok(())
    }
    fn mime_version(&mut self, v: rmimeparser::MimeVersion) -> ParseResult<()> {
        self.push(format!("mv {v}"));
        Ok(())
    }
}

impl MessageHandler for Events {
    fn start_address_header(&mut self, n: &str) -> ParseResult<()> {
        self.push(format!("addresses {n}"));
        Ok(())
    }
    fn mailbox(&mut self, d: Option<&str>, l: &str, dom: &str) -> ParseResult<()> {
        self.push(format!("mailbox {d:?} {l} {dom}"));
        Ok(())
    }
    fn start_group(&mut self, n: &str) -> ParseResult<()> {
        self.push(format!("group {n}"));
        Ok(())
    }
    fn end_group(&mut self) -> ParseResult<()> {
        self.push("end group".into());
        Ok(())
    }
    fn end_address_header(&mut self) -> ParseResult<()> {
        self.push("end addresses".into());
        Ok(())
    }
    fn start_message_id_header(&mut self, n: &str) -> ParseResult<()> {
        self.push(format!("ids {n}"));
        Ok(())
    }
    fn message_id(&mut self, l: &str, d: &str) -> ParseResult<()> {
        self.push(format!("id {l}@{d}"));
        Ok(())
    }
    fn end_message_id_header(&mut self) -> ParseResult<()> {
        self.push("end ids".into());
        Ok(())
    }
    fn date_header(&mut self, n: &str, d: rmimeparser::OffsetDateTime) -> ParseResult<()> {
        self.push(format!("date {n} {d}"));
        Ok(())
    }
    fn obsolete_structure(&mut self, k: ObsoleteStructureType) -> ParseResult<()> {
        self.push(format!("obsolete {k:?}"));
        Ok(())
    }
}

/// Parses `message` fed in pieces of the given lengths (the rest in a last
/// piece), and returns the events. A parse error is a failure of the test: no
/// header here is malformed beyond what `malformed_header` reports.
fn events(message: &[u8], cuts: &[usize]) -> Vec<String> {
    let mut handler = Events::default();
    {
        let mut parser = MessageParser::new(&mut handler);
        let mut ring = LoopBuf::with_capacity(message.len() + 64);
        let mut at = 0;
        for &n in cuts {
            let n = n.min(message.len() - at);
            ring.extend_from_slice(&message[at..at + n]);
            at += n;
            parser
                .receive(&mut ring)
                .unwrap_or_else(|e| fail(message, cuts, &e.to_string()));
        }
        ring.extend_from_slice(&message[at..]);
        parser
            .receive(&mut ring)
            .unwrap_or_else(|e| fail(message, cuts, &e.to_string()));
        parser
            .close(&mut ring)
            .unwrap_or_else(|e| fail(message, cuts, &e.to_string()));
    }
    handler.flush();
    handler.out
}

fn fail(message: &[u8], cuts: &[usize], why: &str) -> ! {
    panic!(
        "{why}: {:?} cuts {cuts:?}",
        String::from_utf8_lossy(message)
    );
}

/// Pieces of header values worth combining.
const PIECES: &[&str] = &[
    "a",
    "b1",
    "Z",
    "x-y",
    "7",
    " ",
    " ",
    "\t",
    ";",
    "=",
    "=",
    "\"",
    "\\",
    "(",
    ")",
    "<",
    ">",
    ",",
    ":",
    "@",
    ".",
    "*",
    "%",
    "'",
    "0",
    "1",
    "2",
    "*0",
    "*1*",
    "=?utf-8?q?",
    "?=",
    "?",
    "=?utf-8?b?QQ==?=",
    "=?iso-8859-1?q?caf=E9?=",
    "\u{e9}",
    "\u{65e5}",
    "\u{1f600}",
    "text/plain",
    "multipart/mixed",
    "charset",
    "boundary",
    "filename",
    "name*0=",
    "name*1*=",
    "filename*=utf-8''",
    "utf-8'en'",
    "%C3",
    "%A9",
    "%zz",
    "<a@b.org>",
    "a@b.org",
    "Name <n@d.org>",
    "grp:",
    "g@h.org;",
    "Tue, 6 Oct 2026 10:00:00 +0000",
    "1.0",
    "base64",
    "7bit",
    "\r\n ",
];

fn random_value(rng: &mut Rng) -> Vec<u8> {
    let n = 1 + rng.below(14);
    let mut value = Vec::new();
    for _ in 0..n {
        value.extend_from_slice(PIECES[rng.below(PIECES.len())].as_bytes());
    }
    // raw bytes that are not UTF-8, and a UTF-8 sequence cut short
    match rng.below(12) {
        0 => value.push(0xE9),
        1 => value.extend_from_slice(&[0xC3]),
        2 => value.extend_from_slice(&[0xE6, 0x97]),
        _ => {}
    }
    value
}

const HEADERS: &[&str] = &[
    "Subject",
    "X-Anything",
    "Content-Type",
    "Content-Disposition",
    "To",
    "Reply-To",
    "References",
    "Message-ID",
    "Date",
    "Content-Transfer-Encoding",
    "Content-ID",
    "MIME-Version",
];

#[test]
fn no_header_breaks_the_parser_and_the_cutting_never_changes_the_events() {
    let mut rng = Rng(seed(0x2545_F491_4F6C_DD1D));
    let mut cases = 0usize;
    let rounds = rounds(4000);
    for round in 0..rounds {
        for name in HEADERS {
            let mut value = random_value(&mut rng);
            // the generator can fold a line, but no line may reach 998 bytes
            value.truncate(300);
            let mut message = format!("{name}: ").into_bytes();
            message.extend_from_slice(&value);
            message.extend_from_slice(b"\r\n\r\nbody");
            // a folded line is a line of its own
            let whole = events(&message, &[]);

            let mut cuts = Vec::new();
            for _ in 0..(1 + rng.below(4)) {
                cuts.push(1 + rng.below(message.len()));
            }
            assert_eq!(
                events(&message, &cuts),
                whole,
                "round {round}: {:?} cuts {cuts:?}",
                String::from_utf8_lossy(&message)
            );
            if rng.below(10) == 0 {
                let ones = vec![1usize; message.len()];
                assert_eq!(
                    events(&message, &ones),
                    whole,
                    "round {round}: {:?} byte by byte",
                    String::from_utf8_lossy(&message)
                );
            }
            cases += 1;
        }
    }
    assert!(cases >= rounds * HEADERS.len());
}

#[test]
fn the_text_decoder_gives_the_same_text_however_random_bytes_are_cut() {
    let alphabet: &[&[u8]] = &[
        b"a",
        b"Z",
        b" ",
        b"\t",
        b"=",
        b"?",
        b"=?",
        b"?=",
        b"=?utf-8?q?",
        b"=?utf-8?b?QQ==?=",
        b"=?x?q?=C3=A9?=",
        b"=C3",
        b"\xc3",
        b"\xa9",
        b"\xe9",
        b"\xe6\x97",
        b"\xe6\x97\xa5",
        b"\xf0\x9f",
        b"\xf0\x9f\x98\x80",
        b"\x80",
        b"_",
    ];
    let decode = |chunks: &[&[u8]], utf8: bool| {
        let mut decoder = HeaderTextDecoder::new(utf8);
        let mut out = String::new();
        let mut emit = |s: &str| -> Result<(), ()> {
            out.push_str(s);
            Ok(())
        };
        for chunk in chunks {
            decoder.feed(chunk, &mut emit).unwrap();
        }
        decoder.finish(&mut emit).unwrap();
        out
    };
    let mut rng = Rng(seed(0x9E37_79B9_7F4A_7C15));
    for _ in 0..rounds(40_000) * 10 {
        let n = 1 + rng.below(20);
        let mut input = Vec::new();
        for _ in 0..n {
            input.extend_from_slice(alphabet[rng.below(alphabet.len())]);
        }
        // also a long run of white space, past what is held
        if rng.below(20) == 0 {
            input.extend(std::iter::repeat(b' ').take(300));
            input.extend_from_slice(b"=?utf-8?q?a?=");
        }
        for utf8 in [false, true] {
            let whole = decode(&[&input], utf8);
            let cut = rng.below(input.len() + 1);
            assert_eq!(
                decode(&[&input[..cut], &input[cut..]], utf8),
                whole,
                "{input:?} at {cut}"
            );
            let ones: Vec<&[u8]> = input.chunks(1).collect();
            assert_eq!(decode(&ones, utf8), whole, "{input:?} byte by byte");
        }
    }
}

// ---- parameter edge cases ----

fn ct(value: &str) -> Vec<(String, String)> {
    ContentTypeParser::parse_str(value)
        .expect("a valid head")
        .parameters()
        .unwrap_or(&[])
        .iter()
        .map(|p| (p.name().to_string(), p.value().to_string()))
        .collect()
}

fn one(name: &str, value: &str) -> Vec<(String, String)> {
    vec![(name.to_string(), value.to_string())]
}

#[test]
fn malformed_percent_sequences_in_an_extended_value_are_kept_as_text() {
    assert_eq!(ct("text/plain; n*=utf-8''%zz"), one("n", "%zz"));
    assert_eq!(ct("text/plain; n*=utf-8''ab%"), one("n", "ab%"));
    assert_eq!(ct("text/plain; n*=utf-8''ab%4"), one("n", "ab%4"));
    assert_eq!(ct("text/plain; n*=utf-8''ab%4z"), one("n", "ab%4z"));
    assert_eq!(ct("text/plain; n*=utf-8''%41%42"), one("n", "AB"));
}

#[test]
fn a_prefix_that_is_not_charset_language_is_plain_text() {
    // fewer than two apostrophes, an empty charset, a space, or too long
    assert_eq!(ct("text/plain; n*=utf-8'x"), one("n", "utf-8'x"));
    assert_eq!(ct("text/plain; n*=''abc"), one("n", "''abc"));
    assert_eq!(ct("text/plain; n*=utf 8''x"), one("n", "utf 8''x"));
    let long = "x".repeat(200);
    assert_eq!(
        ct(&format!("text/plain; n*={long}'en'abc")),
        one("n", &format!("{long}'en'abc"))
    );
}

#[test]
fn continuation_indices_are_read_strictly() {
    // leading zeros are the same index
    assert_eq!(ct("text/plain; n*00=a; n*01=b"), one("n", "ab"));
    // a number too big to be an index makes it an ordinary parameter name
    assert_eq!(ct("text/plain; n*9999999999=x"), one("n*9999999999", "x"));
    // a restart starts a new parameter, of which the first wins
    assert_eq!(ct("text/plain; n*0=a; n*0=b"), one("n", "a"));
    // a gap ends it
    assert_eq!(ct("text/plain; n*0=a; n*2=c; n*1=b"), one("n", "ab"));
    // a continuation that never began is dropped
    assert_eq!(ct("text/plain; n*3=x; k=v"), one("k", "v"));
}

#[test]
fn a_name_past_the_token_limit_is_skipped_and_the_next_parameter_read() {
    let long = "a".repeat(300);
    assert_eq!(ct(&format!("text/plain; {long}=x; k=v")), one("k", "v"));
}

#[test]
fn an_extended_continuation_followed_by_a_plain_segment_is_one_value() {
    // the plain segment is taken as it is, without percent-decoding
    assert_eq!(
        ct("text/plain; n*0*=utf-8''a%20b; n*1=\"%41\""),
        one("n", "a b%41")
    );
}

#[test]
fn a_percent_sequence_cut_by_the_end_of_a_segment_is_text_not_lost() {
    assert_eq!(
        ct("text/plain; n*0*=utf-8''%C; n*1*=3%41"),
        one("n", "%C3A")
    );
}

#[test]
fn dispositions_have_the_same_grammar() {
    let cd = ContentDispositionParser::parse_str(
        "attachment; filename*0*=utf-8''a%C3; filename*1*=%A9.txt",
    )
    .unwrap();
    assert_eq!(cd.get_parameter("filename"), Some("a\u{e9}.txt"));
}
