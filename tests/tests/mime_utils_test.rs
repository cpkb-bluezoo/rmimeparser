use rmimeparser::MIMEUtils;

#[test]
fn test_is_token_valid() {
    assert!(MIMEUtils::is_token("text"));
    assert!(MIMEUtils::is_token("plain"));
    assert!(MIMEUtils::is_token("utf-8"));
    assert!(MIMEUtils::is_token("7bit"));
    assert!(MIMEUtils::is_token("base64"));
    assert!(MIMEUtils::is_token("x-custom"));
}

#[test]
fn test_is_token_with_numbers() {
    assert!(MIMEUtils::is_token("iso-8859-1"));
    assert!(MIMEUtils::is_token("UTF8"));
    assert!(MIMEUtils::is_token("8bit"));
}

#[test]
fn test_is_token_with_special_chars() {
    assert!(MIMEUtils::is_token("vnd.ms-excel"));
    assert!(MIMEUtils::is_token("application+json"));
}

#[test]
fn test_is_token_empty() {
    assert!(!MIMEUtils::is_token(""));
}

#[test]
fn test_is_token_with_space() {
    assert!(!MIMEUtils::is_token("text plain"));
}

#[test]
fn test_is_token_with_specials() {
    assert!(!MIMEUtils::is_token("text/plain"));
    assert!(!MIMEUtils::is_token("name=value"));
    assert!(!MIMEUtils::is_token("name;value"));
    assert!(!MIMEUtils::is_token("name\"value"));
}

#[test]
fn test_is_token_char_alpha() {
    assert!(MIMEUtils::is_token_char('a'));
    assert!(MIMEUtils::is_token_char('z'));
    assert!(MIMEUtils::is_token_char('A'));
    assert!(MIMEUtils::is_token_char('Z'));
}

#[test]
fn test_is_token_char_digit() {
    assert!(MIMEUtils::is_token_char('0'));
    assert!(MIMEUtils::is_token_char('9'));
}

#[test]
fn test_is_token_char_special() {
    assert!(MIMEUtils::is_token_char('-'));
    assert!(MIMEUtils::is_token_char('.'));
    assert!(MIMEUtils::is_token_char('!'));
    assert!(MIMEUtils::is_token_char('#'));
    assert!(MIMEUtils::is_token_char('$'));
    assert!(MIMEUtils::is_token_char('%'));
    assert!(MIMEUtils::is_token_char('&'));
    assert!(MIMEUtils::is_token_char('\''));
    assert!(MIMEUtils::is_token_char('*'));
    assert!(MIMEUtils::is_token_char('+'));
    assert!(MIMEUtils::is_token_char('^'));
    assert!(MIMEUtils::is_token_char('_'));
    assert!(MIMEUtils::is_token_char('`'));
    assert!(MIMEUtils::is_token_char('|'));
    assert!(MIMEUtils::is_token_char('~'));
}

#[test]
fn test_is_token_char_not_allowed() {
    assert!(!MIMEUtils::is_token_char(' '));
    assert!(!MIMEUtils::is_token_char('\t'));
    assert!(!MIMEUtils::is_token_char('('));
    assert!(!MIMEUtils::is_token_char(')'));
    assert!(!MIMEUtils::is_token_char('<'));
    assert!(!MIMEUtils::is_token_char('>'));
    assert!(!MIMEUtils::is_token_char('@'));
    assert!(!MIMEUtils::is_token_char(','));
    assert!(!MIMEUtils::is_token_char(';'));
    assert!(!MIMEUtils::is_token_char(':'));
    assert!(!MIMEUtils::is_token_char('\\'));
    assert!(!MIMEUtils::is_token_char('"'));
    assert!(!MIMEUtils::is_token_char('/'));
    assert!(!MIMEUtils::is_token_char('['));
    assert!(!MIMEUtils::is_token_char(']'));
    assert!(!MIMEUtils::is_token_char('?'));
    assert!(!MIMEUtils::is_token_char('='));
}

#[test]
fn test_is_special() {
    assert!(MIMEUtils::is_special('('));
    assert!(MIMEUtils::is_special(')'));
    assert!(MIMEUtils::is_special('<'));
    assert!(MIMEUtils::is_special('>'));
    assert!(MIMEUtils::is_special('@'));
    assert!(MIMEUtils::is_special(','));
    assert!(MIMEUtils::is_special(';'));
    assert!(MIMEUtils::is_special(':'));
    assert!(MIMEUtils::is_special('\\'));
    assert!(MIMEUtils::is_special('"'));
    assert!(MIMEUtils::is_special('/'));
    assert!(MIMEUtils::is_special('['));
    assert!(MIMEUtils::is_special(']'));
    assert!(MIMEUtils::is_special('?'));
    assert!(MIMEUtils::is_special('='));
}

#[test]
fn test_is_not_special() {
    assert!(!MIMEUtils::is_special('a'));
    assert!(!MIMEUtils::is_special('0'));
    assert!(!MIMEUtils::is_special('-'));
    assert!(!MIMEUtils::is_special('.'));
}

#[test]
fn test_is_valid_boundary_simple() {
    assert!(MIMEUtils::is_valid_boundary("simpleboundary"));
    assert!(MIMEUtils::is_valid_boundary("boundary123"));
}

#[test]
fn test_is_valid_boundary_with_special_chars() {
    assert!(MIMEUtils::is_valid_boundary("----=_Part_123"));
    assert!(MIMEUtils::is_valid_boundary("----WebKitFormBoundary7MA4YWxkTrZu0gW"));
}

#[test]
fn test_is_valid_boundary_max_length() {
    let boundary70 = "a".repeat(70);
    assert!(MIMEUtils::is_valid_boundary(&boundary70));
}

#[test]
fn test_is_valid_boundary_too_long() {
    let boundary71 = "a".repeat(71);
    assert!(!MIMEUtils::is_valid_boundary(&boundary71));
}

#[test]
fn test_is_valid_boundary_empty() {
    assert!(!MIMEUtils::is_valid_boundary(""));
}

#[test]
fn test_is_valid_boundary_with_space() {
    assert!(!MIMEUtils::is_valid_boundary("boundary with space"));
}

#[test]
fn test_is_valid_boundary_ending_with_space() {
    assert!(!MIMEUtils::is_valid_boundary("boundary "));
}

#[test]
fn test_is_boundary_char_alphanumeric() {
    assert!(MIMEUtils::is_boundary_char('a'));
    assert!(MIMEUtils::is_boundary_char('Z'));
    assert!(MIMEUtils::is_boundary_char('0'));
    assert!(MIMEUtils::is_boundary_char('9'));
}

#[test]
fn test_is_boundary_char_special() {
    assert!(MIMEUtils::is_boundary_char('\''));
    assert!(MIMEUtils::is_boundary_char('('));
    assert!(MIMEUtils::is_boundary_char(')'));
    assert!(MIMEUtils::is_boundary_char('+'));
    assert!(MIMEUtils::is_boundary_char('_'));
    assert!(MIMEUtils::is_boundary_char(','));
    assert!(MIMEUtils::is_boundary_char('-'));
    assert!(MIMEUtils::is_boundary_char('.'));
    assert!(MIMEUtils::is_boundary_char('/'));
    assert!(MIMEUtils::is_boundary_char(':'));
    assert!(MIMEUtils::is_boundary_char('='));
    assert!(MIMEUtils::is_boundary_char('?'));
}

#[test]
fn test_is_boundary_char_space() {
    assert!(!MIMEUtils::is_boundary_char(' '));
}
