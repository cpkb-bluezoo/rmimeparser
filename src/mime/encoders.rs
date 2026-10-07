//! Streaming Content-Transfer-Encoding encoders (constant memory).

use std::io::Write;

use super::decoders::BASE64_MAX_LINE_LENGTH;
use super::write_error::WriteResult;

const BASE64_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Collects small writes in a stack buffer so a caller's unbuffered `Write`
/// (a file, a socket) sees one call per few hundred bytes, not one per byte.
pub(crate) struct Batch<'w, W: Write, const N: usize = 4096> {
    out: &'w mut W,
    buf: [u8; N],
    len: usize,
}

impl<'w, W: Write, const N: usize> Batch<'w, W, N> {
    pub(crate) fn new(out: &'w mut W) -> Self {
        Self {
            out,
            buf: [0; N],
            len: 0,
        }
    }

    /// A fixed-size put compiles to plain stores, unlike a variable-length
    /// copy; the encoders emit 1 to 4 bytes at a time.
    #[inline(always)]
    fn put_n<const K: usize>(&mut self, bytes: [u8; K]) -> WriteResult<()> {
        if self.len + K > self.buf.len() {
            self.flush()?;
        }
        self.buf[self.len..self.len + K].copy_from_slice(&bytes);
        self.len += K;
        Ok(())
    }

    #[inline]
    pub(crate) fn put(&mut self, bytes: &[u8]) -> WriteResult<()> {
        if bytes.len() > self.buf.len() {
            // Larger than the buffer: no point copying it.
            self.flush()?;
            self.out.write_all(bytes)?;
            return Ok(());
        }
        if self.len + bytes.len() > self.buf.len() {
            self.flush()?;
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }

    pub(crate) fn flush(&mut self) -> WriteResult<()> {
        if self.len > 0 {
            let n = self.len;
            self.len = 0;
            self.out.write_all(&self.buf[..n])?;
        }
        Ok(())
    }
}

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
        let mut batch = Batch::new(out);
        if self.pending_len > 0 {
            while self.pending_len < 3 && !data.is_empty() {
                self.pending[self.pending_len] = data[0];
                self.pending_len += 1;
                data = &data[1..];
            }
            if self.pending_len == 3 {
                let chunk = [self.pending[0], self.pending[1], self.pending[2]];
                self.pending_len = 0;
                self.encode_quantum(&mut batch, &chunk, 3)?;
            }
        }

        while data.len() >= 3 {
            self.encode_quantum(&mut batch, &data[..3], 3)?;
            data = &data[3..];
        }

        if !data.is_empty() {
            self.pending[..data.len()].copy_from_slice(data);
            self.pending_len = data.len();
        }
        batch.flush()
    }

    /// Flush padding and a final CRLF if the last line was non-empty.
    pub fn finish<W: Write>(&mut self, out: &mut W) -> WriteResult<()> {
        let mut batch = Batch::new(out);
        if self.pending_len > 0 {
            let mut chunk = [0u8; 3];
            chunk[..self.pending_len].copy_from_slice(&self.pending[..self.pending_len]);
            let n = self.pending_len;
            self.pending_len = 0;
            self.encode_quantum(&mut batch, &chunk, n)?;
        }
        if self.line_len > 0 {
            batch.put_n(*b"\r\n")?;
            self.line_len = 0;
        }
        batch.flush()
    }

    /// Encodes up to three bytes as four characters. The line limit is a
    /// multiple of four, so a line break never splits a quantum.
    fn encode_quantum<W: Write>(
        &mut self,
        batch: &mut Batch<'_, W>,
        data: &[u8],
        len: usize,
    ) -> WriteResult<()> {
        let b0 = data[0] as u32;
        let b1 = if len > 1 { data[1] as u32 } else { 0 };
        let b2 = if len > 2 { data[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        let encoded = [
            BASE64_TABLE[((triple >> 18) & 0x3f) as usize],
            BASE64_TABLE[((triple >> 12) & 0x3f) as usize],
            if len > 1 {
                BASE64_TABLE[((triple >> 6) & 0x3f) as usize]
            } else {
                b'='
            },
            if len > 2 {
                BASE64_TABLE[(triple & 0x3f) as usize]
            } else {
                b'='
            },
        ];

        if self.line_len >= BASE64_MAX_LINE_LENGTH {
            batch.put_n(*b"\r\n")?;
            self.line_len = 0;
        }
        batch.put_n(encoded)?;
        self.line_len += 4;
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
    /// A CR that ended the last chunk: a line break if the next byte is LF.
    pending_cr: bool,
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
            pending_cr: false,
        }
    }

    pub fn write<W: Write>(&mut self, out: &mut W, data: &[u8]) -> WriteResult<()> {
        let mut batch = Batch::new(out);
        let mut i = 0usize;
        if self.pending_cr {
            if data.is_empty() {
                return Ok(());
            }
            self.pending_cr = false;
            if data[0] == b'\n' {
                self.flush_pending_ws(&mut batch, true)?;
                batch.put_n(*b"\r\n")?;
                self.line_len = 0;
                i = 1;
            } else {
                self.flush_pending_ws(&mut batch, false)?;
                self.emit_byte(&mut batch, b'\r', true)?;
            }
        }
        while i < data.len() {
            let b = data[i];
            match QP_CLASS[b as usize] {
                QP_PLAIN => {
                    self.flush_pending_ws(&mut batch, false)?;
                    // A run of printable ASCII: copied in bulk, split only
                    // at the soft line break column.
                    let mut j = i + 1;
                    while j < data.len() && QP_CLASS[data[j] as usize] == QP_PLAIN {
                        j += 1;
                    }
                    let mut run = &data[i..j];
                    while !run.is_empty() {
                        if self.line_len >= BASE64_MAX_LINE_LENGTH - 1 {
                            batch.put_n(*b"=\r\n")?;
                            self.line_len = 0;
                        }
                        let take = (BASE64_MAX_LINE_LENGTH - 1 - self.line_len).min(run.len());
                        batch.put(&run[..take])?;
                        self.line_len += take;
                        run = &run[take..];
                    }
                    i = j;
                }
                QP_ENCODE => {
                    self.flush_pending_ws(&mut batch, false)?;
                    self.emit_byte(&mut batch, b, true)?;
                    i += 1;
                }
                QP_SPACE => {
                    self.flush_pending_ws(&mut batch, false)?;
                    self.pending_ws = Some(b);
                    i += 1;
                }
                QP_CR => {
                    if i + 1 == data.len() {
                        // Whether this CR is a line break depends on the next chunk.
                        self.pending_cr = true;
                        i += 1;
                    } else if data[i + 1] == b'\n' {
                        self.flush_pending_ws(&mut batch, true)?;
                        batch.put_n(*b"\r\n")?;
                        self.line_len = 0;
                        i += 2;
                    } else {
                        self.flush_pending_ws(&mut batch, false)?;
                        self.emit_byte(&mut batch, b, true)?;
                        i += 1;
                    }
                }
                _ => {
                    // LF
                    self.flush_pending_ws(&mut batch, true)?;
                    batch.put_n(*b"\r\n")?;
                    self.line_len = 0;
                    i += 1;
                }
            }
        }
        batch.flush()
    }

    pub fn finish<W: Write>(&mut self, out: &mut W) -> WriteResult<()> {
        let mut batch = Batch::new(out);
        if self.pending_cr {
            // A CR at the very end is data, not a line break.
            self.pending_cr = false;
            self.flush_pending_ws(&mut batch, false)?;
            self.emit_byte(&mut batch, b'\r', true)?;
        }
        self.flush_pending_ws(&mut batch, true)?;
        self.line_len = 0;
        batch.flush()
    }

    #[inline(always)]
    fn flush_pending_ws<W: Write>(
        &mut self,
        batch: &mut Batch<'_, W>,
        encode: bool,
    ) -> WriteResult<()> {
        if let Some(b) = self.pending_ws.take() {
            self.emit_byte(batch, b, encode)?;
        }
        Ok(())
    }

    #[inline(always)]
    fn emit_byte<W: Write>(
        &mut self,
        batch: &mut Batch<'_, W>,
        b: u8,
        encode: bool,
    ) -> WriteResult<()> {
        let encoded_len = if encode { 3 } else { 1 };
        if self.line_len + encoded_len > BASE64_MAX_LINE_LENGTH - 1 && self.line_len > 0 {
            batch.put_n(*b"=\r\n")?;
            self.line_len = 0;
        }
        if encode {
            batch.put_n([b'=', HEX[(b >> 4) as usize], HEX[(b & 0x0f) as usize]])?;
            self.line_len += 3;
        } else {
            batch.put_n([b])?;
            self.line_len += 1;
        }
        Ok(())
    }
}

const QP_PLAIN: u8 = 0;
const QP_ENCODE: u8 = 1;
const QP_SPACE: u8 = 2;
const QP_CR: u8 = 3;
const QP_LF: u8 = 4;

/// How the quoted-printable encoder treats each byte: printable ASCII other
/// than `=` is copied as is, space and tab wait for what follows, CR and LF
/// are line breaks, everything else is escaped.
const QP_CLASS: [u8; 256] = {
    let mut t = [QP_ENCODE; 256];
    let mut b = 33;
    while b < 127 {
        t[b] = QP_PLAIN;
        b += 1;
    }
    t[b'=' as usize] = QP_ENCODE;
    t[b' ' as usize] = QP_SPACE;
    t[b'\t' as usize] = QP_SPACE;
    t[b'\r' as usize] = QP_CR;
    t[b'\n' as usize] = QP_LF;
    t
};

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

/// Streaming uuencode encoder: `begin <mode> <name>` on the first write,
/// 45-byte lines, then "`" and `end` on [`Self::finish`]. Retains at most
/// one partial line of input.
pub struct UuencodeEncoder {
    begin: Option<String>,
    pending: [u8; super::decoders::UUENCODE_LINE_BYTES],
    pending_len: usize,
}

impl UuencodeEncoder {
    /// `mode` is the Unix permission bits written in octal (`0o644` is the
    /// usual choice); line breaks in `filename` are replaced.
    pub fn new(filename: &str, mode: u32) -> Self {
        let name: String = filename
            .chars()
            .map(|c| if c == '\r' || c == '\n' { '_' } else { c })
            .collect();
        Self {
            begin: Some(format!("begin {:o} {}\r\n", mode & 0o7777, name)),
            pending: [0; super::decoders::UUENCODE_LINE_BYTES],
            pending_len: 0,
        }
    }

    fn write_begin<W: Write>(&mut self, out: &mut W) -> WriteResult<()> {
        if let Some(b) = self.begin.take() {
            out.write_all(b.as_bytes())?;
        }
        Ok(())
    }

    pub fn write<W: Write>(&mut self, out: &mut W, mut data: &[u8]) -> WriteResult<()> {
        self.write_begin(out)?;
        let mut batch = Batch::new(out);
        let line = super::decoders::UUENCODE_LINE_BYTES;
        while !data.is_empty() {
            let take = (line - self.pending_len).min(data.len());
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&data[..take]);
            self.pending_len += take;
            data = &data[take..];
            if self.pending_len == line {
                let full = self.pending;
                self.pending_len = 0;
                encode_uu_line(&mut batch, &full)?;
            }
        }
        batch.flush()
    }

    /// Flush the last partial line and write the "`" and `end` lines.
    pub fn finish<W: Write>(&mut self, out: &mut W) -> WriteResult<()> {
        self.write_begin(out)?;
        let mut batch = Batch::new(out);
        if self.pending_len > 0 {
            let n = self.pending_len;
            let last = self.pending;
            self.pending_len = 0;
            encode_uu_line(&mut batch, &last[..n])?;
        }
        batch.put(b"`\r\nend\r\n")?;
        batch.flush()
    }
}

fn uu_encode_char(v: u32) -> u8 {
    // 0 is written as "`" rather than a space, the conventional choice so
    // lines never end in whitespace that transports might trim.
    if v == 0 {
        b'`'
    } else {
        (v as u8) + 32
    }
}

/// One encoded line for up to 45 bytes: length character, groups of four,
/// CRLF.
fn encode_uu_line<W: Write>(batch: &mut Batch<'_, W>, bytes: &[u8]) -> WriteResult<()> {
    // 1 length character + 15 groups of 4 + CRLF
    let mut line = [0u8; 64];
    let mut n = 0;
    line[n] = (bytes.len() as u8) + 32;
    n += 1;
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let g = (b0 << 16) | (b1 << 8) | b2;
        line[n] = uu_encode_char((g >> 18) & 63);
        line[n + 1] = uu_encode_char((g >> 12) & 63);
        line[n + 2] = uu_encode_char((g >> 6) & 63);
        line[n + 3] = uu_encode_char(g & 63);
        n += 4;
    }
    line[n] = b'\r';
    line[n + 1] = b'\n';
    batch.put(&line[..n + 2])
}

/// Encode `data` as one complete uuencode section (`begin` … `end`).
pub fn encode_uuencode<W: Write>(out: &mut W, filename: &str, mode: u32, data: &[u8]) -> WriteResult<()> {
    let mut enc = UuencodeEncoder::new(filename, mode);
    enc.write(out, data)?;
    enc.finish(out)
}
