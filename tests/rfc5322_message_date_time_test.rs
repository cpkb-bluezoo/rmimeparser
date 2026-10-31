use rmimeparser::{MessageDateTimeFormatter, OffsetDateTime};

#[test]
fn test_format_canonical() {
    let dt = OffsetDateTime::new(1997, 11, 21, 9, 55, 6, -6 * 3600);
    assert_eq!(
        MessageDateTimeFormatter::format(&dt),
        "Fri, 21 Nov 1997 09:55:06 -0600"
    );
}

#[test]
fn test_format_single_digit_day() {
    let dt = OffsetDateTime::new(2003, 7, 1, 10, 52, 37, 2 * 3600);
    assert_eq!(
        MessageDateTimeFormatter::format(&dt),
        "Tue, 1 Jul 2003 10:52:37 +0200"
    );
}

#[test]
fn test_parse_canonical() {
    let dt = MessageDateTimeFormatter::parse("Fri, 21 Nov 1997 09:55:06 -0600").unwrap();
    assert_eq!(dt.year, 1997);
    assert_eq!(dt.month, 11);
    assert_eq!(dt.day, 21);
    assert_eq!(dt.hour, 9);
    assert_eq!(dt.minute, 55);
    assert_eq!(dt.second, 6);
    assert_eq!(dt.offset_seconds, -6 * 3600);
}

#[test]
fn test_round_trip() {
    let original = "Wed, 15 Jan 2020 14:30:45 -0800";
    let dt = MessageDateTimeFormatter::parse(original).unwrap();
    assert_eq!(MessageDateTimeFormatter::format(&dt), original);
}

#[test]
fn test_parse_obsolete_two_digit_year() {
    let dt = MessageDateTimeFormatter::parse_obsolete("21 Nov 97 09:55:06 -0600");
    assert!(dt.is_some());
    let dt = dt.unwrap();
    assert_eq!(dt.year, 1997);
}

fn expected() -> OffsetDateTime {
    OffsetDateTime::new(1997, 11, 21, 9, 55, 6, -6 * 3600)
}

#[test]
fn test_parse_trailing_comment() {
    let dt =
        MessageDateTimeFormatter::parse("Fri, 21 Nov 1997 09:55:06 -0600 (via relay)").unwrap();
    assert_eq!(dt, expected());
}

#[test]
fn test_parse_leading_and_nested_comments() {
    let dt = MessageDateTimeFormatter::parse(
        "(first) Fri, 21 Nov 1997 (mid) 09:55:06 -0600 (a (nested) \\) one)",
    )
    .unwrap();
    assert_eq!(dt, expected());
}

#[test]
fn test_parse_unterminated_comment_rejected() {
    assert!(MessageDateTimeFormatter::parse("Fri, 21 Nov 1997 09:55:06 -0600 (oops").is_err());
}

#[test]
fn test_parse_obsolete_trailing_comment() {
    let dt =
        MessageDateTimeFormatter::parse_obsolete("Fri, 21 Nov 1997 09:55:06 CST (EST)").unwrap();
    assert_eq!(dt, expected());
}

/// Non-ASCII text in a date must never be able to panic the parser: the
/// obsolete-syntax recovery used to slice a string in the middle of a character.
#[test]
fn non_ascii_text_in_an_obsolete_date_is_not_a_panic() {
    for text in [
        "Tue, 6 Oct 2026 10:00:00 \u{e9}",
        "\u{e9}UTC",
        "6 Oct 2026 10:00 \u{65e5}\u{672c}GMT",
        "GMT\u{1f600}",
        "Tue, 6 Oct 2026 10:00:00 EST\u{e9}",
        "caf\u{e9} EST",
    ] {
        assert!(
            MessageDateTimeFormatter::parse_obsolete(text).is_none(),
            "{text:?}"
        );
    }
    // and a good obsolete date with non-ASCII in a comment still reads
    let date = MessageDateTimeFormatter::parse_obsolete("6 Oct 2026 10:00:00 EST (\u{e9}t\u{e9})")
        .unwrap();
    assert_eq!(date.hour, 10);
    assert_eq!(date.offset_seconds, -5 * 3600);
}
