//! RFC 5322 header line folding.

use std::io::Write;

use super::write_error::{MimeWriteError, WriteResult};

/// Recommended maximum length of a header line (RFC 5322 §2.1.1).
pub const SOFT_LINE_LIMIT: usize = 78;

/// Absolute maximum length of a header line (RFC 5322 §2.1.1).
pub const HARD_LINE_LIMIT: usize = 998;

/// Write a single header field as folded `Name: value\r\n` lines.
///
/// Soft-wraps near [`SOFT_LINE_LIMIT`], preferring breaks at WSP. Never breaks
/// inside an RFC 2047 encoded-word. Never emits a physical line longer than
/// [`HARD_LINE_LIMIT`].
pub fn write_folded_header<W: Write>(out: &mut W, name: &str, value: &str) -> WriteResult<()> {
    validate_header_name(name)?;

    let name_prefix = format!("{name}: ");
    if name_prefix.len() > HARD_LINE_LIMIT {
        return Err(MimeWriteError::validation(format!(
            "header name too long: {name}"
        )));
    }

    let value_bytes = value.as_bytes();
    let mut line_len = name_prefix.len();
    out.write_all(name_prefix.as_bytes())?;

    if value_bytes.is_empty() {
        out.write_all(b"\r\n")?;
        return Ok(());
    }

    let mut i = 0usize;
    while i < value_bytes.len() {
        let remaining = &value_bytes[i..];
        let token_end = next_atom_end(remaining);
        let atom = &remaining[..token_end];

        if atom.is_empty() {
            // Leading/trailing WSP or lone WSP: write as-is if it fits, else fold.
            let b = remaining[0];
            if line_len + 1 > SOFT_LINE_LIMIT && line_len > name_prefix.len().min(1) {
                fold_newline(out, &mut line_len)?;
            }
            if line_len + 1 > HARD_LINE_LIMIT {
                return Err(MimeWriteError::validation(
                    "header line exceeds 998 octets",
                ));
            }
            out.write_all(&[b])?;
            line_len += 1;
            i += 1;
            continue;
        }

        // Prefer folding before this atom if it would exceed the soft limit.
        if line_len > 0
            && line_len + atom.len() > SOFT_LINE_LIMIT
            && line_len >= 2
        {
            // Only fold if we are not at the very start of the field value on first line
            // with nothing written yet beyond "Name: ".
            if line_len > name_prefix.len() || i > 0 {
                fold_newline(out, &mut line_len)?;
            }
        }

        if line_len + atom.len() > HARD_LINE_LIMIT {
            // Atom itself is too long for one line — hard-break (except encoded-words,
            // which must not be broken).
            if is_encoded_word(atom) {
                return Err(MimeWriteError::validation(
                    "encoded-word exceeds maximum header line length",
                ));
            }
            let mut offset = 0usize;
            while offset < atom.len() {
                let space = HARD_LINE_LIMIT.saturating_sub(line_len);
                if space == 0 {
                    fold_newline(out, &mut line_len)?;
                    continue;
                }
                let take = space.min(atom.len() - offset);
                out.write_all(&atom[offset..offset + take])?;
                line_len += take;
                offset += take;
                if offset < atom.len() {
                    fold_newline(out, &mut line_len)?;
                }
            }
        } else {
            out.write_all(atom)?;
            line_len += atom.len();
        }
        i += token_end;
    }

    out.write_all(b"\r\n")?;
    Ok(())
}

fn fold_newline<W: Write>(out: &mut W, line_len: &mut usize) -> WriteResult<()> {
    out.write_all(b"\r\n ")?;
    *line_len = 1; // continuation WSP
    Ok(())
}

fn validate_header_name(name: &str) -> WriteResult<()> {
    if name.is_empty() {
        return Err(MimeWriteError::validation("empty header name"));
    }
    for &b in name.as_bytes() {
        if b == b':' || b == b'\r' || b == b'\n' || b < 0x21 || b > 0x7e {
            return Err(MimeWriteError::validation(format!(
                "invalid header name: {name}"
            )));
        }
    }
    Ok(())
}

/// Returns the end offset of the next atom: an encoded-word, a non-WSP run, or 1 WSP.
fn next_atom_end(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    if bytes[0] == b' ' || bytes[0] == b'\t' {
        return 1;
    }
    if bytes.starts_with(b"=?") {
        if let Some(end) = find_encoded_word_end(bytes) {
            return end;
        }
    }
    let mut i = 0usize;
    while i < bytes.len() && bytes[i] != b' ' && bytes[i] != b'\t' {
        // If we encounter a new encoded-word start mid-run, stop before it so it
        // can be kept intact on the next iteration.
        if i > 0 && bytes[i..].starts_with(b"=?") {
            if find_encoded_word_end(&bytes[i..]).is_some() {
                break;
            }
        }
        i += 1;
    }
    i
}

fn find_encoded_word_end(bytes: &[u8]) -> Option<usize> {
    // =?charset?X?text?=
    if !bytes.starts_with(b"=?") {
        return None;
    }
    let mut q = 0usize;
    let mut i = 2usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b'?' {
            q += 1;
            if q == 3 && bytes[i + 1] == b'=' {
                return Some(i + 2);
            }
        }
        i += 1;
    }
    None
}

fn is_encoded_word(atom: &[u8]) -> bool {
    find_encoded_word_end(atom) == Some(atom.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_header_no_fold() {
        let mut out = Vec::new();
        write_folded_header(&mut out, "Subject", "Hello").unwrap();
        assert_eq!(out, b"Subject: Hello\r\n");
    }

    #[test]
    fn folds_long_value_at_spaces() {
        let mut out = Vec::new();
        let value = "a ".repeat(50);
        write_folded_header(&mut out, "X-Long", value.trim_end()).unwrap();
        let s = String::from_utf8(out).unwrap();
        for line in s.split("\r\n").filter(|l| !l.is_empty()) {
            assert!(line.len() <= HARD_LINE_LIMIT);
        }
        assert!(s.contains("\r\n "));
    }

    #[test]
    fn rejects_bad_name() {
        let mut out = Vec::new();
        assert!(write_folded_header(&mut out, "Bad:Name", "x").is_err());
    }
}
