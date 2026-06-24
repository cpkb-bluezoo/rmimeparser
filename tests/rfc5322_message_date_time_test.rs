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
