//! Which headers the RFC 5322 layer parses itself.

/// The RFC 5322 headers this layer parses itself, so asks the MIME parser to
/// hand it raw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawKind {
    Date,
    Address,
    MessageId,
}

/// Which kind, if any, of header `name` is (case-insensitively). Every other
/// header, known or not, is unstructured.
pub(crate) fn classify(name: &str) -> Option<RawKind> {
    let mut buf = [0u8; LOWER_NAME_MAX];
    match lowercase_name(name, &mut buf) {
        "date" | "resent-date" => Some(RawKind::Date),
        "from" | "sender" | "to" | "cc" | "bcc" | "reply-to" | "resent-from" | "return-path"
        | "resent-sender" | "resent-to" | "resent-cc" | "resent-bcc" | "resent-reply-to"
        | "envelope-to" | "delivered-to" | "x-original-to" | "errors-to" | "apparently-to" => {
            Some(RawKind::Address)
        }
        "message-id" | "in-reply-to" | "references" | "resent-message-id" => {
            Some(RawKind::MessageId)
        }
        _ => None,
    }
}

/// Longest header name [`classify`] matches.
const LOWER_NAME_MAX: usize = 32;

/// Lowercases `name` into `buf` without allocating. A name too long to be
/// any known header is reduced to the empty string, which matches none.
fn lowercase_name<'b>(name: &str, buf: &'b mut [u8; LOWER_NAME_MAX]) -> &'b str {
    let bytes = name.as_bytes();
    if bytes.len() > LOWER_NAME_MAX {
        return "";
    }
    let n = bytes.len();
    for i in 0..n {
        buf[i] = bytes[i].to_ascii_lowercase();
    }
    // Names are printable ASCII (validated by the parser); anything else
    // simply matches nothing.
    std::str::from_utf8(&buf[..n]).unwrap_or("")
}
