//! RFC 2045 token and RFC 2046 boundary validation helpers.

/// Utility methods for MIME parsing and validation.
pub struct MIMEUtils;

impl MIMEUtils {
    pub fn is_token(s: &str) -> bool {
        is_token(s)
    }

    pub fn is_token_char(c: char) -> bool {
        is_token_char(c)
    }

    pub fn is_special(c: char) -> bool {
        is_special(c)
    }

    pub fn is_valid_boundary(boundary: &str) -> bool {
        is_valid_boundary(boundary)
    }

    pub fn is_boundary_char(c: char) -> bool {
        is_boundary_char(c)
    }
}

pub fn is_token(s: &str) -> bool {
    !s.is_empty() && s.chars().all(is_token_char)
}

pub fn is_token_char(c: char) -> bool {
    matches!(c,
        '0'..='9' | 'A'..='Z' | 'a'..='z'
        | '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.'
        | '^' | '_' | '`' | '{' | '|' | '}' | '~'
    )
}

/// RFC 2045 tspecial — must be quoted in parameter values.
pub fn is_special(c: char) -> bool {
    matches!(c,
        '(' | ')' | '<' | '>' | '@' | ',' | ';' | ':' | '\\' | '"' |
        '/' | '[' | ']' | '?' | '='
    )
}

pub fn is_valid_boundary(boundary: &str) -> bool {
    !boundary.is_empty()
        && boundary.len() <= 70
        && boundary.chars().all(is_boundary_char)
}

pub fn is_boundary_char(c: char) -> bool {
    matches!(c,
        '0'..='9' | 'A'..='Z' | 'a'..='z'
        | '\'' | '(' | ')' | '+' | '_' | ',' | '-' | '.' | '/' | ':' | '=' | '?'
    )
}

/// Finds the first occurrence of `target` in `data`.
pub fn index_of(data: &[u8], target: u8) -> Option<usize> {
    data.iter().position(|&b| b == target)
}

/// Decodes ISO-8859-1 header bytes, optionally trimming whitespace.
pub fn decode_header_bytes(data: &[u8], trim: bool, strip_header_whitespace: bool) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut s = String::with_capacity(data.len());
    for &b in data {
        s.push(b as char);
    }
    if trim && strip_header_whitespace {
        s = s.trim().to_string();
    }
    s
}

/// Decodes the front of `data` as ISO-8859-1 and advances past the consumed segment.
pub fn decode_slice(data: &mut &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let end = data.len();
    let s = decode_header_bytes(data, true, true);
    *data = &data[end..];
    s
}

fn find_next_fold(value: &[u8], from: usize, stop: usize) -> Option<usize> {
    let mut pos = from;
    while pos < stop {
        let b = value[pos];
        if b == b'\r'
            && pos + 2 <= stop
            && value[pos + 1] == b'\n'
            && pos + 2 < stop
            && (value[pos + 2] == b' ' || value[pos + 2] == b'\t')
        {
            return Some(pos);
        }
        if b == b'\n' && pos + 1 < stop && (value[pos + 1] == b' ' || value[pos + 1] == b'\t') {
            return Some(pos);
        }
        pos += 1;
    }
    None
}

fn skip_fold(value: &[u8], fold_start: usize, limit: usize) -> usize {
    if fold_start + 2 <= limit && value[fold_start] == b'\r' && value[fold_start + 1] == b'\n' {
        return fold_start + 2;
    }
    if fold_start + 1 < limit && value[fold_start] == b'\n' {
        return fold_start + 1;
    }
    fold_start + 1
}

/// Decodes a token-only header value with inline folding (CRLF+LWSP → space).
pub fn decode_token_header_value(data: &mut &[u8], strip_header_whitespace: bool) -> String {
    let stop = data.len();
    if stop == 0 {
        return String::new();
    }

    let mut out = String::new();
    while !data.is_empty() {
        let remaining = *data;
        let fold = find_next_fold(remaining, 0, remaining.len());
        let segment_end = fold.unwrap_or(remaining.len());
        if segment_end > 0 {
            let mut segment_slice = &remaining[..segment_end];
            let segment = decode_slice(&mut segment_slice);
            if !segment.is_empty() {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(&segment);
            }
        }
        if fold.is_none() {
            *data = &data[remaining.len()..];
            break;
        }
        let next = skip_fold(remaining, segment_end, remaining.len());
        *data = &data[next..];
    }

    if strip_header_whitespace {
        out.trim().to_string()
    } else {
        out
    }
}
