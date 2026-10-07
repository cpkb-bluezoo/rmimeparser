use rmimeparser::{Rfc2047Decoder, Rfc2047Encoder};

#[test]
fn test_contains_non_ascii_true() {
    let data = "Café".as_bytes();
    assert!(Rfc2047Encoder::contains_non_ascii(data));
}

#[test]
fn test_contains_non_ascii_false() {
    let data = b"Hello World";
    assert!(!Rfc2047Encoder::contains_non_ascii(data));
}

#[test]
fn test_contains_non_ascii_empty() {
    assert!(!Rfc2047Encoder::contains_non_ascii(b""));
}

#[test]
fn test_contains_non_ascii_range() {
    let data = "Hello Café World".as_bytes();
    assert!(!Rfc2047Encoder::contains_non_ascii_range(data, 0, 6));
    assert!(Rfc2047Encoder::contains_non_ascii_range(data, 6, data.len()));
}

#[test]
fn test_encoding_for_ascii() {
    let data = b"Hello World";
    assert_eq!(Rfc2047Encoder::encoding_for_data(data), 'Q');
}

#[test]
fn test_encoding_for_mostly_non_ascii() {
    let data = "日本語テスト".as_bytes();
    assert_eq!(Rfc2047Encoder::encoding_for_data(data), 'B');
}

#[test]
fn test_encoding_for_empty() {
    assert_eq!(Rfc2047Encoder::encoding_for_data(b""), 'B');
}

#[test]
fn test_encode_b_simple() {
    let data = b"Hello";
    assert_eq!(Rfc2047Encoder::encode_b(data, "UTF-8"), "Hello");
}

#[test]
fn test_encode_b_with_non_ascii() {
    let data = "Café".as_bytes();
    let encoded = Rfc2047Encoder::encode_b(data, "UTF-8");
    assert!(encoded.contains("=?UTF-8?B?"));
    assert!(encoded.contains("?="));
    assert_eq!(Rfc2047Decoder::decode_encoded_words(&encoded), "Café");
}

#[test]
fn test_encode_b_japanese() {
    let data = "日本語".as_bytes();
    let encoded = Rfc2047Encoder::encode_b(data, "UTF-8");
    assert!(encoded.contains("=?UTF-8?B?"));
    assert_eq!(Rfc2047Decoder::decode_encoded_words(&encoded), "日本語");
}

#[test]
fn test_encode_q_with_non_ascii() {
    let data = "Café".as_bytes();
    let encoded = Rfc2047Encoder::encode_q(data, "UTF-8");
    assert!(encoded.contains("=?UTF-8?Q?"));
    assert_eq!(Rfc2047Decoder::decode_encoded_words(&encoded), "Café");
}

#[test]
fn test_round_trip_check() {
    assert!(Rfc2047Encoder::round_trip_check("Hello World"));
    assert!(Rfc2047Encoder::round_trip_check("Café résumé"));
}

/// Exact output, captured from the encoder before it stopped allocating a
/// string per escaped byte and per word.
#[test]
fn test_exact_output_is_stable() {
    let accent = "café au lait".as_bytes();
    assert_eq!(
        Rfc2047Encoder::encode_header_value(accent, "UTF-8"),
        "caf=?UTF-8?Q?=C3=A9?= au lait"
    );
    assert_eq!(
        Rfc2047Encoder::encode_b(accent, "UTF-8"),
        "caf=?UTF-8?B?w6kgYXUgbGFpdA==?="
    );
    assert_eq!(
        Rfc2047Encoder::encode_b(accent, "ISO-8859-1"),
        "caf=?ISO-8859-1?B?w6kgYXUgbGFpdA==?="
    );

    let mixed = "Ünïcödé Sübjéct with <angle@example.org> and \"quoted\" bits".as_bytes();
    assert_eq!(
        Rfc2047Encoder::encode_q(mixed, "UTF-8"),
        "=?UTF-8?Q?=C3=9C?=n=?UTF-8?Q?=C3=AF?=c=?UTF-8?Q?=C3=B6?=d=?UTF-8?Q?=C3=A9?= S=?UTF-8?Q?=C3=BC?=bj=?UTF-8?Q?=C3=A9?=ct with <angle@example.org> and \"quoted\" bits"
    );
    assert_eq!(
        Rfc2047Encoder::encode_b(mixed, "UTF-8"),
        "=?UTF-8?B?w5xuw69jw7Zkw6kgU8O8YmrDqWN0IHdpdGgg?=<angle@example.org> and \"quoted\" bits"
    );

    // Long text splits into words of at most 75 characters.
    let long = "日本語のテキストです。これは長い件名で、複数の符号化語に分割されるはずです。".as_bytes();
    let q = Rfc2047Encoder::encode_q(long, "UTF-8");
    assert_eq!(
        q,
        "=?UTF-8?Q?=E6=97=A5=E6=9C=AC=E8=AA=9E=E3=81=AE=E3=83=86=E3=82=AD=E3=82=B9?==?UTF-8?Q?=E3=83=88=E3=81=A7=E3=81=99=E3=80=82=E3=81=93=E3=82=8C=E3=81=AF?==?UTF-8?Q?=E9=95=B7=E3=81=84=E4=BB=B6=E5=90=8D=E3=81=A7=E3=80=81=E8=A4=87?==?UTF-8?Q?=E6=95=B0=E3=81=AE=E7=AC=A6=E5=8F=B7=E5=8C=96=E8=AA=9E=E3=81=AB?==?UTF-8?Q?=E5=88=86=E5=89=B2=E3=81=95=E3=82=8C=E3=82=8B=E3=81=AF=E3=81=9A?==?UTF-8?Q?=E3=81=A7=E3=81=99=E3=80=82?="
    );
    for word in q.split("?==?") {
        assert!(word.len() <= 75, "{word}");
    }
    assert_eq!(
        Rfc2047Encoder::encode_b(long, "UTF-8"),
        "=?UTF-8?B?5pel5pys6Kqe44Gu44OG44Kt44K544OI44Gn44GZ44CC44GT44KM44Gv6ZW3?==?UTF-8?B?44GE5Lu25ZCN44Gn44CB6KSH5pWw44Gu56ym5Y+35YyW6Kqe44Gr5YiG5Ymy?==?UTF-8?B?44GV44KM44KL44Gv44Ga44Gn44GZ44CC?="
    );
}
