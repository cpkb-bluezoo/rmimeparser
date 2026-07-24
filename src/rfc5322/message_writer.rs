//! Push-based RFC 5322 message writer.

use std::io::Write;

use crate::mime::content_types::ContentId;
use crate::mime::writer::MimeWriter;
use crate::mime::write_error::WriteResult;
use crate::rfc2047::Encoder as Rfc2047Encoder;
use crate::rfc5322::email_address::EmailAddress;
use crate::rfc5322::message_date_time::{MessageDateTimeFormatter, OffsetDateTime};

/// RFC 5322 message writer composed over [`MimeWriter`].
///
/// Adds typed header helpers; MIME entity / body methods are forwarded.
pub struct MessageWriter<W: Write> {
    inner: MimeWriter<W>,
}

impl<W: Write> MessageWriter<W> {
    pub fn new(out: W) -> Self {
        Self {
            inner: MimeWriter::new(out),
        }
    }

    pub fn into_inner(self) -> MimeWriter<W> {
        self.inner
    }

    pub fn into_write(self) -> W {
        self.inner.into_inner()
    }

    pub fn mime_writer(&mut self) -> &mut MimeWriter<W> {
        &mut self.inner
    }

    pub fn bytes_written(&self) -> u64 {
        self.inner.bytes_written()
    }

    pub fn start_entity(&mut self, boundary: Option<&str>) -> WriteResult<()> {
        self.inner.start_entity(boundary)
    }

    pub fn end_entity(&mut self, boundary: Option<&str>) -> WriteResult<()> {
        self.inner.end_entity(boundary)
    }

    pub fn end_headers(&mut self) -> WriteResult<()> {
        self.inner.end_headers()
    }

    pub fn body_content(&mut self, data: &[u8]) -> WriteResult<()> {
        self.inner.body_content(data)
    }

    pub fn raw_body_content(&mut self, data: &[u8]) -> WriteResult<()> {
        self.inner.raw_body_content(data)
    }

    pub fn close(&mut self) -> WriteResult<()> {
        self.inner.close()
    }

    pub fn content_type(
        &mut self,
        content_type: &crate::mime::ContentType,
    ) -> WriteResult<()> {
        self.inner.content_type(content_type)
    }

    pub fn content_disposition(
        &mut self,
        disposition: &crate::mime::ContentDisposition,
    ) -> WriteResult<()> {
        self.inner.content_disposition(disposition)
    }

    pub fn content_transfer_encoding(&mut self, encoding: &str) -> WriteResult<()> {
        self.inner.content_transfer_encoding(encoding)
    }

    pub fn content_id(&mut self, content_id: &ContentId) -> WriteResult<()> {
        self.inner.content_id(content_id)
    }

    pub fn content_description(&mut self, description: &str) -> WriteResult<()> {
        self.inner.content_description(description)
    }

    pub fn mime_version(&mut self, version: crate::mime::MimeVersion) -> WriteResult<()> {
        self.inner.mime_version(version)
    }

    pub fn raw_header(&mut self, name: &str, raw_bytes: &[u8]) -> WriteResult<()> {
        self.inner.raw_header(name, raw_bytes)
    }

    /// Unstructured header; applies RFC 2047 when needed.
    pub fn header(&mut self, name: &str, value: &str) -> WriteResult<()> {
        self.inner.header(name, value)
    }

    pub fn date_header(&mut self, name: &str, date: OffsetDateTime) -> WriteResult<()> {
        let value = MessageDateTimeFormatter::format(&date);
        self.inner.header_raw_value(name, &value)
    }

    pub fn address_header(&mut self, name: &str, addresses: &[EmailAddress]) -> WriteResult<()> {
        let value = format_address_list(addresses);
        // Display names may already contain encoded-words; fold only.
        self.inner.header_raw_value(name, &value)
    }

    pub fn message_id_header(
        &mut self,
        name: &str,
        content_ids: &[ContentId],
    ) -> WriteResult<()> {
        let mut value = String::new();
        for (i, id) in content_ids.iter().enumerate() {
            if i > 0 {
                value.push(' ');
            }
            value.push_str(&id.to_string());
        }
        self.inner.header_raw_value(name, &value)
    }
}

fn format_address_list(addresses: &[EmailAddress]) -> String {
    let mut out = String::new();
    for (i, addr) in addresses.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&format_address(addr));
    }
    out
}

fn format_address(addr: &EmailAddress) -> String {
    let angle = format!("<{}>", addr.address());
    if let Some(name) = addr.display_name() {
        if name.is_empty() {
            return angle;
        }
        let encoded = if Rfc2047Encoder::contains_non_ascii(name.as_bytes())
            || name.as_bytes().iter().any(|&b| {
                b < 0x20 || b == b'"' || b == b'\\' || b == b'\r' || b == b'\n'
            }) {
            Rfc2047Encoder::encode_header_value(name.as_bytes(), "UTF-8")
        } else if needs_quoting(name) {
            format!("\"{}\"", escape_quoted(name))
        } else {
            name.to_string()
        };
        format!("{encoded} {angle}")
    } else {
        angle
    }
}

fn needs_quoting(name: &str) -> bool {
    name.split_whitespace().nth(1).is_some()
        || name.bytes().any(|b| {
            matches!(
                b,
                b'(' | b')' | b'<' | b'>' | b'@' | b',' | b';' | b':' | b'\\' | b'"' | b'[' | b']'
            )
        })
}

fn escape_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
