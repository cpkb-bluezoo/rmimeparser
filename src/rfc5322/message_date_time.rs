//! RFC 5322 date-time parsing and formatting (std-only).

use std::fmt;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/// Date-time with fixed offset (RFC 5322).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetDateTime {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub offset_seconds: i32,
}

impl OffsetDateTime {
    pub fn new(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        offset_seconds: i32,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            offset_seconds,
        }
    }

    pub fn offset_hours(&self) -> i32 {
        self.offset_seconds / 3600
    }
}

impl fmt::Display for OffsetDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", MessageDateTimeFormatter::format(self))
    }
}

/// RFC 5322 date-time formatter/parser.
pub struct MessageDateTimeFormatter;

impl MessageDateTimeFormatter {
    pub fn format(dt: &OffsetDateTime) -> String {
        let dow = weekday(dt.year, dt.month, dt.day);
        let month = MONTHS[(dt.month.saturating_sub(1)) as usize];
        let sign = if dt.offset_seconds >= 0 { '+' } else { '-' };
        let abs = dt.offset_seconds.unsigned_abs();
        let off_h = (abs / 3600) as u32;
        let off_m = ((abs % 3600) / 60) as u32;
        format!(
            "{}, {} {} {:04} {:02}:{:02}:{:02} {sign}{:02}{:02}",
            WEEKDAYS[dow],
            dt.day,
            month,
            dt.year,
            dt.hour,
            dt.minute,
            dt.second,
            off_h,
            off_m
        )
    }

    pub fn parse(date_string: &str) -> Result<OffsetDateTime, ()> {
        parse_date_time(date_string.trim(), false)
    }

    pub fn parse_obsolete(date_string: &str) -> Option<OffsetDateTime> {
        let mut s = date_string.trim().to_string();
        s = convert_two_digit_year(&s);
        s = convert_obsolete_timezones(&s);
        parse_date_time(&s, true).ok()
    }
}

fn parse_date_time(input: &str, obsolete: bool) -> Result<OffsetDateTime, ()> {
    let bytes = input.as_bytes();
    let mut pos = 0usize;
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    if pos + 3 < bytes.len() && bytes[pos + 3] == b',' {
        pos += 4;
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
    }
    while pos < bytes.len() && bytes[pos] == b' ' {
        pos += 1;
    }
    let day = read_number(bytes, &mut pos, 1, 2)?;
    skip_ws(bytes, &mut pos);
    let month = parse_month(bytes, &mut pos)?;
    skip_ws(bytes, &mut pos);
    let year_len = if obsolete { 4 } else { 4 };
    let mut year = read_number(bytes, &mut pos, 2, year_len)?;
    if year < 100 {
        year = if year < 50 { 2000 + year } else { 1900 + year };
    }
    skip_ws(bytes, &mut pos);
    let hour = read_number(bytes, &mut pos, 2, 2)?;
    expect(bytes, &mut pos, b':')?;
    let minute = read_number(bytes, &mut pos, 2, 2)?;
    let second = if pos < bytes.len() && bytes[pos] == b':' {
        pos += 1;
        read_number(bytes, &mut pos, 2, 2)?
    } else if obsolete {
        0
    } else {
        return Err(());
    };
    skip_ws(bytes, &mut pos);
    let offset_seconds = if pos < bytes.len()
        && (bytes[pos] == b'+' || bytes[pos] == b'-')
    {
        parse_offset(bytes, &mut pos)?
    } else if obsolete {
        0
    } else {
        return Err(());
    };
    skip_ws(bytes, &mut pos);
    if pos != bytes.len() {
        return Err(());
    }
    Ok(OffsetDateTime::new(
        year,
        month as u8,
        day as u8,
        hour as u8,
        minute as u8,
        second as u8,
        offset_seconds,
    ))
}

fn read_number(bytes: &[u8], pos: &mut usize, min: usize, max: usize) -> Result<i32, ()> {
    let start = *pos;
    let mut value = 0i32;
    while *pos < bytes.len() && bytes[*pos].is_ascii_digit() && *pos - start < max {
        value = value * 10 + (bytes[*pos] - b'0') as i32;
        *pos += 1;
    }
    let len = *pos - start;
    if len < min || len > max {
        return Err(());
    }
    Ok(value)
}

fn expect(bytes: &[u8], pos: &mut usize, ch: u8) -> Result<(), ()> {
    if *pos < bytes.len() && bytes[*pos] == ch {
        *pos += 1;
        Ok(())
    } else {
        Err(())
    }
}

fn skip_ws(bytes: &[u8], pos: &mut usize) {
    while *pos < bytes.len() && bytes[*pos].is_ascii_whitespace() {
        *pos += 1;
    }
}

fn parse_month(bytes: &[u8], pos: &mut usize) -> Result<u8, ()> {
    if *pos + 3 > bytes.len() {
        return Err(());
    }
    let name = std::str::from_utf8(&bytes[*pos..*pos + 3]).map_err(|_| ())?;
    let month = MONTHS
        .iter()
        .position(|m| m.eq_ignore_ascii_case(name))
        .ok_or(())? as u8
        + 1;
    *pos += 3;
    Ok(month)
}

fn parse_offset(bytes: &[u8], pos: &mut usize) -> Result<i32, ()> {
    let sign = if bytes[*pos] == b'-' { -1 } else { 1 };
    *pos += 1;
    let hours = read_number(bytes, pos, 2, 2)?;
    let minutes = if *pos + 2 <= bytes.len() && bytes[*pos..*pos + 2].iter().all(|b| b.is_ascii_digit())
    {
        read_number(bytes, pos, 2, 2)?
    } else {
        0
    };
    Ok(sign * (hours * 3600 + minutes * 60))
}

fn weekday(year: i32, month: u8, day: u8) -> usize {
    // Sakamoto's algorithm
    let t = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    let mut y = year;
    if month < 3 {
        y -= 1;
    }
    let w = (y + y / 4 - y / 100 + y / 400 + t[(month - 1) as usize] as i32 + day as i32) % 7;
    // Sakamoto: 0=Sunday..6=Saturday; RFC 5322 uses Mon..Sun.
    ((w + 6).rem_euclid(7)) as usize
}

fn convert_two_digit_year(input: &str) -> String {
    let mut out = input.to_string();
    for prefix in ["19", "20"] {
        let _ = prefix;
    }
    // Simplified: replace standalone 2-digit years before time.
    let parts: Vec<&str> = out.split_whitespace().collect();
    let mut rebuilt = String::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            rebuilt.push(' ');
        }
        if part.len() == 2
            && part.chars().all(|c| c.is_ascii_digit())
            && i + 1 < parts.len()
            && parts[i + 1].contains(':')
        {
            let yr: i32 = part.parse().unwrap_or(0);
            rebuilt.push_str(&if yr < 50 {
                format!("20{part}")
            } else {
                format!("19{part}")
            });
        } else {
            rebuilt.push_str(part);
        }
    }
    out = rebuilt;
    out
}

fn convert_obsolete_timezones(input: &str) -> String {
    let replacements = [
        (" GMT", " +0000"),
        (" UT", " +0000"),
        (" UTC", " +0000"),
        (" EST", " -0500"),
        (" EDT", " -0400"),
        (" CST", " -0600"),
        (" CDT", " -0500"),
        (" MST", " -0700"),
        (" MDT", " -0600"),
        (" PST", " -0800"),
        (" PDT", " -0700"),
    ];
    let mut out = input.to_string();
    for (from, to) in replacements {
        if out.ends_with(from.trim()) || out.contains(from) {
            out = out.replace(from.trim(), to.trim());
        }
    }
    // Word-boundary style replacements
    for (name, offset) in [
        ("GMT", "+0000"),
        ("UT", "+0000"),
        ("UTC", "+0000"),
        ("EST", "-0500"),
        ("EDT", "-0400"),
        ("CST", "-0600"),
        ("CDT", "-0500"),
        ("MST", "-0700"),
        ("MDT", "-0600"),
        ("PST", "-0800"),
        ("PDT", "-0700"),
    ] {
        out = replace_word(&out, name, offset);
    }
    out
}

fn replace_word(input: &str, word: &str, replacement: &str) -> String {
    let mut out = String::new();
    let mut i = 0;
    let bytes = input.as_bytes();
    while i < bytes.len() {
        if input[i..].starts_with(word)
            && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
            && (i + word.len() == bytes.len() || !bytes[i + word.len()].is_ascii_alphanumeric())
        {
            out.push_str(replacement);
            i += word.len();
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}
