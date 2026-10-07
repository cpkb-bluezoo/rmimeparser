//! Throughput and allocation benchmark (std only).
//!
//! ```bash
//! cargo run --release --example perf
//! ```
//!
//! Prints MB/s for the main paths and, via a counting global allocator, the
//! number of allocations and bytes allocated per scenario.

use rmimeparser::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

struct Counting;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(l.size(), Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(n, Relaxed);
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn snapshot() -> (usize, usize) {
    (ALLOCS.load(Relaxed), BYTES.load(Relaxed))
}

/// Counts body bytes and callbacks; keeps nothing.
#[derive(Default)]
struct Tally {
    bytes: usize,
    calls: usize,
}

impl MimeHandler for Tally {
    fn body_content(&mut self, d: &[u8]) -> ParseResult<()> {
        self.bytes += d.len();
        self.calls += 1;
        Ok(())
    }
}
impl MessageHandler for Tally {}

fn parse_mime(msg: &[u8]) -> Tally {
    let mut h = Tally::default();
    {
        let mut p = MimeParser::new(&mut h);
        let mut s = msg;
        p.receive(&mut s).unwrap();
        p.finish(&mut s).ok();
    }
    h
}

fn parse_message(msg: &[u8]) -> Tally {
    let mut h = Tally::default();
    {
        let mut p = MessageParser::new(&mut h);
        let mut s = msg;
        p.receive(&mut s).unwrap();
        p.finish(&mut s).ok();
    }
    h
}

fn throughput<F: FnMut()>(name: &str, bytes: usize, iters: usize, mut f: F) {
    f();
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let s = t.elapsed().as_secs_f64();
    println!(
        "{name:<46} {:>8.1} MB/s  ({:.2} ms/iter)",
        (bytes * iters) as f64 / s / 1e6,
        s * 1000.0 / iters as f64
    );
}

fn allocations<F: FnOnce() -> usize>(name: &str, f: F) {
    let a = snapshot();
    let calls = f();
    let b = snapshot();
    println!(
        "{name:<46} {:>7} allocs {:>10} bytes {:>7} callbacks",
        b.0 - a.0,
        b.1 - a.1,
        calls
    );
}

struct CountWrites(usize);
impl std::io::Write for CountWrites {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0 += 1;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn main() {
    let payload: Vec<u8> = (0..8_000_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let mut b64 = Vec::new();
    encode_base64(&mut b64, &payload).unwrap();
    let text = "The quick brown fox jumps over the lazy dog, again and again.\r\n".repeat(150_000);

    let mut b64_msg =
        b"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n".to_vec();
    b64_msg.extend_from_slice(&b64);
    let text_msg = format!("Content-Type: text/plain\r\n\r\n{text}").into_bytes();
    let multipart_text = format!(
        "Content-Type: multipart/mixed; boundary=\"XX\"\r\n\r\n--XX\r\nContent-Type: text/plain\r\n\r\n{text}\r\n--XX--\r\n"
    )
    .into_bytes();
    let mut multipart_b64 = b"Content-Type: multipart/mixed; boundary=\"XX\"\r\n\r\n--XX\r\nContent-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n".to_vec();
    multipart_b64.extend_from_slice(&b64);
    multipart_b64.extend_from_slice(b"\r\n--XX--\r\n");
    let headers = b"Received: from mail.example.com (mail.example.com [192.0.2.1]) by mx.example.net with ESMTPS id abc123 for <bob@example.net>; Tue, 6 Oct 2026 10:00:00 +0000\r\nFrom: Alice Example <alice@example.com>\r\nTo: Bob <bob@example.net>, Carol <carol@example.org>\r\nSubject: Hello there, this is a plain subject\r\nDate: Tue, 6 Oct 2026 10:00:00 +0000 (UTC)\r\nMessage-ID: <abc123@example.com>\r\nX-Mailer: bench 1.0\r\nX-Spam-Status: No, score=-1.2\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhello\r\n";

    println!("-- throughput");
    throughput("mime: base64 body", b64_msg.len(), 5, || {
        parse_mime(&b64_msg);
    });
    throughput("mime: plain text body", text_msg.len(), 10, || {
        parse_mime(&text_msg);
    });
    throughput("mime: plain text in multipart", multipart_text.len(), 10, || {
        parse_mime(&multipart_text);
    });
    throughput("mime: base64 attachment in multipart", multipart_b64.len(), 5, || {
        parse_mime(&multipart_b64);
    });
    let n = 20_000;
    throughput("message: 10-header small messages", headers.len() * n, 1, || {
        for _ in 0..n {
            parse_message(headers);
        }
    });
    throughput("encode_base64 to Vec", payload.len(), 5, || {
        let mut o = Vec::with_capacity(11_000_000);
        encode_base64(&mut o, &payload).unwrap();
    });
    throughput("encode_quoted_printable to Vec", payload.len(), 5, || {
        let mut o = Vec::with_capacity(30_000_000);
        encode_quoted_printable(&mut o, &payload).unwrap();
    });
    throughput("encode_quoted_printable, ASCII text", text.len(), 10, || {
        let mut o = Vec::with_capacity(text.len() + text.len() / 4);
        encode_quoted_printable(&mut o, text.as_bytes()).unwrap();
    });
    let mut qp = Vec::new();
    encode_quoted_printable(&mut qp, text.as_bytes()).unwrap();
    throughput("decode_quoted_printable (mostly ASCII)", qp.len(), 10, || {
        let mut dst = Vec::with_capacity(qp.len() + 16);
        let mut s = qp.as_slice();
        decode_quoted_printable(&mut s, &mut dst, usize::MAX / 2, true);
    });
    let list: String = (0..5000).map(|i| format!("User {i} <user{i}@example.org>")).collect::<Vec<_>>().join(", ");
    throughput("address list (str API), 5000 addresses", list.len(), 20, || {
        EmailAddressParser::parse_email_address_list(&list).unwrap();
    });

    println!("\n-- allocations");
    allocations("MessageParser, 10 headers", || parse_message(headers).calls);
    allocations("MimeParser, same 10 headers", || parse_mime(headers).calls);
    for lines in [1000usize, 2000] {
        let t = "The quick brown fox jumps over the lazy dog, again and again.\r\n".repeat(lines);
        let mp = format!("Content-Type: multipart/mixed; boundary=\"XX\"\r\n\r\n--XX\r\nContent-Type: text/plain\r\n\r\n{t}\r\n--XX--\r\n");
        let single = format!("Content-Type: text/plain\r\n\r\n{t}");
        allocations(&format!("multipart text, {lines} lines"), || parse_mime(mp.as_bytes()).calls);
        allocations(&format!("single-entity text, {lines} lines"), || parse_mime(single.as_bytes()).calls);
    }
    let raw: Vec<u8> = (0..57_000u32).map(|i| i as u8).collect();
    let mut enc = Vec::new();
    encode_base64(&mut enc, &raw).unwrap();
    let mut m = b"Content-Transfer-Encoding: base64\r\n\r\n".to_vec();
    m.extend_from_slice(&enc);
    allocations("base64 body, 1000 lines", || parse_mime(&m).calls);
    let mut w = CountWrites(0);
    encode_base64(&mut w, &payload[..1_000_000]).unwrap();
    println!("{:<46} {:>7} write() calls", "encode_base64, 1 MB", w.0);
}
