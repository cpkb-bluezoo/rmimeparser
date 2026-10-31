//! The streaming header-text decoder gives the same text as the buffered
//! RFC 2047 decoder, whatever the chunking of its input.

use rmimeparser::{HeaderTextDecoder, Rfc2047Decoder};

fn stream(chunks: &[&[u8]], smtp_utf8: bool) -> String {
    let mut decoder = HeaderTextDecoder::new(smtp_utf8);
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
}

fn buffered(bytes: &[u8], smtp_utf8: bool) -> String {
    Rfc2047Decoder::decode_header_value_smtp_utf8(bytes, smtp_utf8)
        .trim()
        .to_string()
}

const SAMPLES: &[&[u8]] = &[
    b"Hello world",
    b"  padded   text  ",
    b"=?UTF-8?Q?caf=C3=A9?= au lait",
    b"=?utf-8?b?Y2Fmw6k=?= =?utf-8?q?_au_lait?=",
    b"a =?utf-8?q?b?= c",
    b"=?utf-8?q?a?= =?utf-8?q?b?=",
    b"=?utf-8?q?a?=   \t  =?utf-8?q?b?= tail",
    b"=?ISO-8859-1?Q?caf=E9?=",
    b"=?x?Q?unterminated",
    b"==?utf-8?q?x?=",
    b"no encoded = word? here",
    b"a=b c=d",
    b"=?utf-8?q?bad=ZZ?= after",
    b"=?utf-8?x?nope?= text",
    b"=? ? ?=",
    b"caf\xc3\xa9 raw utf8",
    b"caf\xe9 raw latin1",
    b"and =?utf-8?q?=C3=A9?= then =?utf-8?q?=3D?=",
    b"",
    b"   ",
    b"=?utf-8?q??=",
    b"tab\tseparated\tvalues",
];

/// Where the buffered decoder gives up at the first failed candidate, this one
/// goes on and finds the encoded word that follows a stray `=?`.
#[test]
fn an_encoded_word_after_a_stray_start_is_found() {
    assert_eq!(stream(&[b"=?=?utf-8?q?x?="], false), "=?x");
    let ones: Vec<&[u8]> = b"=?=?utf-8?q?x?=".chunks(1).collect();
    assert_eq!(stream(&ones, false), "=?x");
    assert_eq!(stream(&[b"=?=?=?utf-8?q?x?= end"], false), "=?=?x end");
}

/// The buffered decoder reads raw UTF-8 next to an encoded word as Latin-1
/// and gives mojibake; the stream reads each as what it is.
#[test]
fn raw_utf8_next_to_an_encoded_word_is_read_as_utf8() {
    assert_eq!(
        stream(&[b"mixed \xc3\xa9 and =?utf-8?q?=C3=A9?="], false),
        "mixed \u{e9} and \u{e9}"
    );
    assert_eq!(
        stream(&[b"mixed \xe9 and =?utf-8?q?=C3=A9?="], false),
        "mixed \u{e9} and \u{e9}"
    );
}

#[test]
fn matches_the_buffered_decoder() {
    for sample in SAMPLES {
        for smtp_utf8 in [false, true] {
            assert_eq!(
                stream(&[sample], smtp_utf8),
                buffered(sample, smtp_utf8),
                "{:?} smtp_utf8={smtp_utf8}",
                String::from_utf8_lossy(sample)
            );
        }
    }
}

#[test]
fn the_chunking_does_not_matter() {
    for sample in SAMPLES {
        for smtp_utf8 in [false, true] {
            let whole = stream(&[sample], smtp_utf8);
            for cut in 0..=sample.len() {
                assert_eq!(
                    stream(&[&sample[..cut], &sample[cut..]], smtp_utf8),
                    whole,
                    "{:?} cut at {cut}",
                    String::from_utf8_lossy(sample)
                );
            }
            let ones: Vec<&[u8]> = sample.chunks(1).collect();
            assert_eq!(
                stream(&ones, smtp_utf8),
                whole,
                "{:?} byte by byte",
                String::from_utf8_lossy(sample)
            );
        }
    }
}

#[test]
fn a_decoder_can_be_reused() {
    let mut decoder = HeaderTextDecoder::new(false);
    for _ in 0..2 {
        let mut out = String::new();
        let mut emit = |s: &str| -> Result<(), ()> {
            out.push_str(s);
            Ok(())
        };
        decoder.feed(b"  =?utf-8?q?a?= b  ", &mut emit).unwrap();
        decoder.finish(&mut emit).unwrap();
        decoder.reset();
        assert_eq!(out, "a b");
    }
}

#[test]
fn long_text_is_handed_on_in_chunks_not_held() {
    let text = "word ".repeat(10_000);
    let mut decoder = HeaderTextDecoder::new(false);
    let mut chunks = 0;
    let mut longest = 0;
    let mut emit = |s: &str| -> Result<(), ()> {
        chunks += 1;
        longest = longest.max(s.len());
        Ok(())
    };
    for piece in text.as_bytes().chunks(500) {
        decoder.feed(piece, &mut emit).unwrap();
    }
    decoder.finish(&mut emit).unwrap();
    assert!(chunks >= 100, "{chunks} chunks");
    assert!(longest <= 2048, "longest chunk {longest}");
}

#[test]
fn an_error_from_the_handler_stops_the_decoding() {
    let mut decoder = HeaderTextDecoder::new(false);
    let mut emit = |_: &str| -> Result<(), &'static str> { Err("stop") };
    assert_eq!(decoder.feed(b"some text", &mut emit), Err("stop"));
}
