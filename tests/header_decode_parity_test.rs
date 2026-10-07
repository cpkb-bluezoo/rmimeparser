//! The header decoders have an ASCII fast path; it must agree with the
//! general path on every input.

use rmimeparser::{decode_header_bytes, Rfc2047Decoder};

#[test]
fn decode_header_bytes_trims_like_str_trim_on_latin1_text() {
    // 0x85 and 0xA0 decode to NEL and NBSP, which `str::trim` removes.
    let edges: [&[u8]; 6] = [b"", b" ", b"\t", b"\xa0", b"\x85", b"\xa0 \x85\t"];
    let cores: [&[u8]; 3] = [b"x", b"a b", b"caf\xe9"];
    for l in edges {
        for c in cores {
            for r in edges {
                let mut data = l.to_vec();
                data.extend_from_slice(c);
                data.extend_from_slice(r);
                let reference: String = data.iter().map(|&b| b as char).collect();
                assert_eq!(decode_header_bytes(&data, true, true), reference.trim(), "{data:?}");
                assert_eq!(decode_header_bytes(&data, true, false), reference, "{data:?}");
            }
        }
    }
}

#[test]
fn plain_ascii_header_values_decode_to_themselves() {
    for v in [
        "Hello, world", "  padded  ", "a=b", "x?=y", "100% sure", "with\0nul", "=", "?",
        "from mail.example.com (mail.example.com [192.0.2.1]) by mx; Tue, 6 Oct 2026",
    ] {
        for smtp_utf8 in [false, true] {
            assert_eq!(
                Rfc2047Decoder::decode_header_value_smtp_utf8(v.as_bytes(), smtp_utf8),
                v,
                "{v:?} smtp_utf8={smtp_utf8}"
            );
        }
    }
}

#[test]
fn encoded_words_still_decode_inside_ascii_values() {
    let v = b"Re: =?UTF-8?Q?caf=C3=A9_au_lait?= and =?ISO-8859-1?B?Y2Fm6Q==?=";
    for smtp_utf8 in [false, true] {
        assert_eq!(
            Rfc2047Decoder::decode_header_value_smtp_utf8(v, smtp_utf8),
            "Re: café au lait and café"
        );
    }
}

#[test]
fn q_encoding_of_ascii_text() {
    for (word, expected) in [
        ("=?UTF-8?Q?a_b=20c=3Dd?=", "a b c=d"),
        ("=?UTF-8?Q?x=4?=", "x=4"),
        ("=?UTF-8?Q?=ZZ_ok?=", "=ZZ ok"),
        ("=?UTF-8?Q?end=?=", "end="),
        ("=?UTF-8?Q?=C3=A9?=", "é"),
    ] {
        assert_eq!(Rfc2047Decoder::decode_encoded_words(word), expected, "{word}");
    }
}
