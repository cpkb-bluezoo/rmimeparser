//! Streaming Content-Transfer-Encoding encoders (constant memory).

use std::io::Write;

use super::decoders::BASE64_MAX_LINE_LENGTH;
use super::write_error::WriteResult;

const BASE64_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Streaming BASE64 encoder with RFC 2045 76-column wrapping.
///
/// Retains at most 2 pending input bytes and the current line length.
pub struct Base64Encoder {
    pending: [u8; 3],
    pending_len: usize,
    line_len: usize,
}

impl Default for Base64Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Base64Encoder {
    pub fn new() -> Self {
        Self {
            pending: [0; 3],
            pending_len: 0,
            line_len: 0,
        }
    }

    pub fn write<W: Write>(&mut self, out: &mut W, mut data: &[u8]) -> WriteResult<()> {
        if self.pending_len > 0 {
            while self.pending_len < 3 && !data.is_empty() {
                self.pending[self.pending_len] = data[0];
                self.pending_len += 1;
                data = &data[1..];
            }
            if self.pending_len == 3 {
                let chunk = [self.pending[0], self.pending[1], self.pending[2]];
                self.pending_len = 0;
                self.encode_quantum(out, &chunk, 3)?;
            }
        }

        while data.len() >= 3 {
            self.encode_quantum(out, &data[..3], 3)?;
            data = &data[3..];
        }

        if !data.is_empty() {
            self.pending[..data.len()].copy_from_slice(data);
            self.pending_len = data.len();
        }
        Ok(())
    }

    /// Flush padding and a final CRLF if the last line was non-empty.
    pub fn finish<W: Write>(&mut self, out: &mut W) -> WriteResult<()> {
        if self.pending_len > 0 {
            let mut chunk = [0u8; 3];
            chunk[..self.pending_len].copy_from_slice(&self.pending[..self.pending_len]);
            let n = self.pending_len;
            self.pending_len = 0;
            self.encode_quantum(out, &chunk, n)?;
        }
        if self.line_len > 0 {
            out.write_all(b"\r\n")?;
            self.line_len = 0;
        }
        Ok(())
    }

    fn encode_quantum<W: Write>(
        &mut self,
        out: &mut W,
        data: &[u8],
        len: usize,
    ) -> WriteResult<()> {
        let b0 = data[0] as u32;
        let b1 = if len > 1 { data[1] as u32 } else { 0 };
        let b2 = if len > 2 { data[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        let mut encoded = [0u8; 4];
        encoded[0] = BASE64_TABLE[((triple >> 18) & 0x3f) as usize];
        encoded[1] = BASE64_TABLE[((triple >> 12) & 0x3f) as usize];
        encoded[2] = if len > 1 {
            BASE64_TABLE[((triple >> 6) & 0x3f) as usize]
        } else {
            b'='
        };
        encoded[3] = if len > 2 {
            BASE64_TABLE[(triple & 0x3f) as usize]
        } else {
            b'='
        };

        for &c in &encoded {
            if self.line_len >= BASE64_MAX_LINE_LENGTH {
                out.write_all(b"\r\n")?;
                self.line_len = 0;
            }
            out.write_all(&[c])?;
            self.line_len += 1;
        }
        Ok(())
    }
}

/// Streaming quoted-printable encoder with 76-column soft line breaks.
///
/// Holds at most one pending SPACE/TAB so trailing whitespace before CRLF/EOS
/// can be encoded without buffering the body.
pub struct QuotedPrintableEncoder {
    line_len: usize,
    pending_ws: Option<u8>,
}

impl Default for QuotedPrintableEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl QuotedPrintableEncoder {
    pub fn new() -> Self {
        Self {
            line_len: 0,
            pending_ws: None,
        }
    }

    pub fn write<W: Write>(&mut self, out: &mut W, data: &[u8]) -> WriteResult<()> {
        let mut i = 0usize;
        while i < data.len() {
            let b = data[i];

            if b == b'\r' {
                if i + 1 < data.len() && data[i + 1] == b'\n' {
                    self.flush_pending_ws(out, true)?;
                    out.write_all(b"\r\n")?;
                    self.line_len = 0;
                    i += 2;
                    continue;
                }
                self.flush_pending_ws(out, false)?;
                self.emit_byte(out, b, true)?;
                i += 1;
                continue;
            }
            if b == b'\n' {
                self.flush_pending_ws(out, true)?;
                out.write_all(b"\r\n")?;
                self.line_len = 0;
                i += 1;
                continue;
            }

            if b == b' ' || b == b'\t' {
                self.flush_pending_ws(out, false)?;
                self.pending_ws = Some(b);
                i += 1;
                continue;
            }

            self.flush_pending_ws(out, false)?;
            let needs_encode = b > 126 || b < 32 || b == b'=';
            self.emit_byte(out, b, needs_encode)?;
            i += 1;
        }
        Ok(())
    }

    pub fn finish<W: Write>(&mut self, out: &mut W) -> WriteResult<()> {
        self.flush_pending_ws(out, true)?;
        self.line_len = 0;
        Ok(())
    }

    fn flush_pending_ws<W: Write>(&mut self, out: &mut W, encode: bool) -> WriteResult<()> {
        if let Some(b) = self.pending_ws.take() {
            self.emit_byte(out, b, encode)?;
        }
        Ok(())
    }

    fn emit_byte<W: Write>(&mut self, out: &mut W, b: u8, encode: bool) -> WriteResult<()> {
        let encoded_len = if encode { 3 } else { 1 };
        if self.line_len + encoded_len > BASE64_MAX_LINE_LENGTH - 1 && self.line_len > 0 {
            out.write_all(b"=\r\n")?;
            self.line_len = 0;
        }
        if encode {
            let buf = [b'=', HEX[(b >> 4) as usize], HEX[(b & 0x0f) as usize]];
            out.write_all(&buf)?;
            self.line_len += 3;
        } else {
            out.write_all(&[b])?;
            self.line_len += 1;
        }
        Ok(())
    }
}

/// Encode the entire buffer as BASE64 (O(1) auxiliary memory).
pub fn encode_base64<W: Write>(out: &mut W, data: &[u8]) -> WriteResult<()> {
    let mut enc = Base64Encoder::new();
    enc.write(out, data)?;
    enc.finish(out)
}

/// Encode the entire buffer as quoted-printable.
pub fn encode_quoted_printable<W: Write>(out: &mut W, data: &[u8]) -> WriteResult<()> {
    let mut enc = QuotedPrintableEncoder::new();
    enc.write(out, data)?;
    enc.finish(out)
}
