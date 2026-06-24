use std::fmt;
use std::hash::{Hash, Hasher};

use super::utils::MIMEUtils;

const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

#[derive(Debug, Clone)]
pub struct Parameter {
    name: String,
    value: String,
}

impl Parameter {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Like Java `Parameter(String, String)` — panics if either argument is `None`.
    pub fn maybe_new(
        name: Option<impl Into<String>>,
        value: Option<impl Into<String>>,
    ) -> Self {
        Self::new(
            name.expect("name must not be null"),
            value.expect("value must not be null"),
        )
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn to_header_value(&self) -> String {
        if self.value.chars().all(|c| c <= '\u{007f}') {
            if MIMEUtils::is_token(&self.value) {
                format!("{}={}", self.name, self.value)
            } else {
                format!(
                    "{}=\"{}\"",
                    self.name,
                    escape_quoted_string(&self.value)
                )
            }
        } else {
            format!("{}*=UTF-8''{}", self.name, percent_encode(&self.value))
        }
    }
}

impl PartialEq for Parameter {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq_ignore_ascii_case(&other.name) && self.value == other.value
    }
}

impl Eq for Parameter {}

impl Hash for Parameter {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.to_ascii_lowercase().hash(state);
        self.value.hash(state);
    }
}

impl fmt::Display for Parameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.value)
    }
}

fn escape_quoted_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for &b in s.as_bytes() {
        if is_attr_char(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX_DIGITS[((b >> 4) & 0x0f) as usize] as char);
            out.push(HEX_DIGITS[(b & 0x0f) as usize] as char);
        }
    }
    out
}

fn is_attr_char(b: u8) -> bool {
    matches!(b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
        | b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~'
    )
}
