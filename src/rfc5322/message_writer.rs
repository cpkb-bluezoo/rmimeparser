//! Push-based RFC 5322 message writer.

use loopbuf::LoopBuf;

use crate::mime::content_types::ContentId;
use crate::mime::write_error::WriteResult;
use crate::mime::writer::MimeWriter;
use crate::rfc2047::Encoder as Rfc2047Encoder;
use crate::rfc5322::email_address::EmailAddress;
use crate::rfc5322::message_date_time::{MessageDateTimeFormatter, OffsetDateTime};

/// RFC 5322 message writer composed over [`MimeWriter`].
///
/// Adds typed header helpers; MIME entity / body methods are forwarded. Every
/// call is atomic and writes into a caller-owned ring, as [`MimeWriter`]'s do.
#[derive(Default)]
pub struct MessageWriter {
    inner: MimeWriter,
}

impl MessageWriter {
    pub fn new() -> Self {
        Self {
            inner: MimeWriter::new(),
        }
    }

    pub fn into_inner(self) -> MimeWriter {
        self.inner
    }

    pub fn mime_writer(&mut self) -> &mut MimeWriter {
        &mut self.inner
    }

    pub fn bytes_written(&self) -> u64 {
        self.inner.bytes_written()
    }

    pub fn reset(&mut self) {
        self.inner.reset()
    }

    pub fn start_entity(&mut self, buf: &mut LoopBuf, boundary: Option<&str>) -> WriteResult<()> {
        self.inner.start_entity(buf, boundary)
    }

    pub fn end_entity(&mut self, buf: &mut LoopBuf, boundary: Option<&str>) -> WriteResult<()> {
        self.inner.end_entity(buf, boundary)
    }

    pub fn end_headers(&mut self, buf: &mut LoopBuf) -> WriteResult<()> {
        self.inner.end_headers(buf)
    }

    /// See [`MimeWriter::body_content`]: takes what fits and returns how much.
    pub fn body_content(&mut self, buf: &mut LoopBuf, data: &[u8]) -> WriteResult<usize> {
        self.inner.body_content(buf, data)
    }

    /// See [`MimeWriter::raw_body_content`].
    pub fn raw_body_content(&mut self, buf: &mut LoopBuf, data: &[u8]) -> WriteResult<usize> {
        self.inner.raw_body_content(buf, data)
    }

    pub fn close(&mut self) -> WriteResult<()> {
        self.inner.close()
    }

    pub fn content_type(
        &mut self,
        buf: &mut LoopBuf,
        content_type: &crate::mime::ContentType,
    ) -> WriteResult<()> {
        self.inner.content_type(buf, content_type)
    }

    pub fn content_disposition(
        &mut self,
        buf: &mut LoopBuf,
        disposition: &crate::mime::ContentDisposition,
    ) -> WriteResult<()> {
        self.inner.content_disposition(buf, disposition)
    }

    pub fn content_transfer_encoding(
        &mut self,
        buf: &mut LoopBuf,
        encoding: &str,
    ) -> WriteResult<()> {
        self.inner.content_transfer_encoding(buf, encoding)
    }

    pub fn content_id(&mut self, buf: &mut LoopBuf, content_id: &ContentId) -> WriteResult<()> {
        self.inner.content_id(buf, content_id)
    }

    pub fn content_description(&mut self, buf: &mut LoopBuf, description: &str) -> WriteResult<()> {
        self.inner.content_description(buf, description)
    }

    pub fn mime_version(
        &mut self,
        buf: &mut LoopBuf,
        version: crate::mime::MimeVersion,
    ) -> WriteResult<()> {
        self.inner.mime_version(buf, version)
    }

    pub fn raw_header(
        &mut self,
        buf: &mut LoopBuf,
        name: &str,
        raw_bytes: &[u8],
    ) -> WriteResult<()> {
        self.inner.raw_header(buf, name, raw_bytes)
    }

    /// Unstructured header; applies RFC 2047 when needed.
    pub fn header(&mut self, buf: &mut LoopBuf, name: &str, value: &str) -> WriteResult<()> {
        self.inner.header(buf, name, value)
    }

    pub fn date_header(
        &mut self,
        buf: &mut LoopBuf,
        name: &str,
        date: OffsetDateTime,
    ) -> WriteResult<()> {
        let value = MessageDateTimeFormatter::format(&date);
        self.inner.header_raw_value(buf, name, &value)
    }

    pub fn address_header(
        &mut self,
        buf: &mut LoopBuf,
        name: &str,
        addresses: &[EmailAddress],
    ) -> WriteResult<()> {
        let value = format_address_list(addresses);
        // Display names may already contain encoded-words; fold only.
        self.inner.header_raw_value(buf, name, &value)
    }

    pub fn message_id_header(
        &mut self,
        buf: &mut LoopBuf,
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
        self.inner.header_raw_value(buf, name, &value)
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
            || name
                .as_bytes()
                .iter()
                .any(|&b| b < 0x20 || b == b'"' || b == b'\\' || b == b'\r' || b == b'\n')
        {
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
