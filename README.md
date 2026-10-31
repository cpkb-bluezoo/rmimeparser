# rmimeparser

Push-based MIME and RFC 5322 message parser and writer for Rust.

**rmimeparser** ports the [gumdrop](https://github.com/cpkb-bluezoo/gumdrop) `org.bluezoo.gumdrop.mime` package tree to Rust, using the same design as [rprotobuf](https://github.com/cpkb-bluezoo/rprotobuf) and [jsonparser](https://github.com/cpkb-bluezoo/jsonparser):

- Incremental `receive(&mut LoopBuf)` parsing over a caller-owned ring — the parser holds none of the body, streaming over a fixed read buffer
- Handler callbacks instead of materialised message domain objects
- Push `MimeWriter` / `MessageWriter` — constant memory, chunked `body_content`, no builder/DOM
- MIME core with RFC 5322 as an extension (`MessageParser` / `MessageWriter` compose MIME)
- Content-Transfer-Encoding codecs for base64, quoted-printable and uuencode (`x-uuencode`): the parser decodes bodies as they stream, and each codec is available on its own as a push decoder and a streaming encoder
- One dependency, [loopbuf](https://github.com/cpkb-bluezoo/loopbuf), the fixed-capacity ring shared by the other parsers

Header encoding helpers (`RFC2047Encoder`, `MessageDateTimeFormatter`, `to_header_value()` on value types) are shared by the writers.

## MIME parser

```rust
use loopbuf::LoopBuf;
use rmimeparser::{MimeHandler, MimeParser, ParseResult};

struct TeeHandler {
    bytes: usize,
}

impl MimeHandler for TeeHandler {
    fn body_content(&mut self, data: &[u8]) -> ParseResult<()> {
        self.bytes += data.len();
        Ok(())
    }
}

let raw = b"Content-Type: text/plain\r\n\r\nHello\r\n";
let mut parser = MimeParser::new(TeeHandler { bytes: 0 });
let mut ring = LoopBuf::with_capacity(8192);
ring.extend_from_slice(raw);
parser.receive(&mut ring)?;
parser.close(&mut ring)?;
assert_eq!(parser.handler().bytes, 7);
```

The parser owns its handler; `handler()`, `handler_mut()` and `into_handler()` get at it. To keep the handler yourself, lend it: `MimeParser::new(&mut handler)` works because `&mut H` is a `MimeHandler` whenever `H` is, and so is a `Box<dyn MimeHandler>`.

`MimeParser::parse(reader)` does the ring for you: it reads any `std::io::Read` through one ring of `set_buffer_size` bytes (default 8192) and calls `close`.

## MIME writer

```rust
use rmimeparser::{ContentType, MimeWriter};

let mut out = Vec::new();
let mut w = MimeWriter::new(&mut out);
w.start_entity(None)?;
w.content_type(&ContentType::new("text", "plain", None))?;
w.content_transfer_encoding("base64")?;
w.end_headers()?;
w.body_content(b"Hello")?;
w.body_content(b" world")?; // chunked; constant memory
w.end_entity(None)?;
w.close()?;
```

## RFC 5322 message parser

```rust
use loopbuf::LoopBuf;
use rmimeparser::{MessageHandler, MessageParser, ParseResult};

struct Headers;

impl MessageHandler for Headers {
    fn header(&mut self, name: &str, value: &str) -> ParseResult<()> {
        if name.eq_ignore_ascii_case("subject") {
            // ...
        }
        Ok(())
    }
}

let raw = b"From: sender@example.com\r\nSubject: test\r\n\r\nBody\r\n";
let mut parser = MessageParser::new(Headers);
let mut ring = LoopBuf::with_capacity(8192);
ring.extend_from_slice(raw);
parser.receive(&mut ring)?;
parser.close(&mut ring)?;
```

### Streaming

```rust
loop {
    // read from the socket into the ring's spare capacity, then
    parser.receive(&mut ring)?;
    // what the parser could not use yet is still in the ring
}
parser.close(&mut ring)?;
```

The ring belongs to the caller and the parser never grows it. A header line is used whole, so a partial one stays in the ring, to be completed by the next read; the ring therefore has to hold the longest header line (RFC 5322 limits it to 998 bytes), and a ring full of one unfinished line makes `receive` return an error rather than wait for data that cannot fit. A header line longer than `ParserLimits::max_header_line_length` (default 998) is rejected without waiting for its terminator. Body bytes are consumed as they arrive and handed to the handler as zero-copy runs (at most `set_chunk_size` bytes each, default 4096; a run that crosses the ring's wrap arrives as two), so a body never needs to be buffered or re-presented, whatever its line lengths. The parser keeps only what it cannot yet decide: a line that might be a multipart boundary (at most about 76 bytes), the line ending before it, and the partial unit of a transfer-encoding decoder. `parser.is_underflow()` is true while an incomplete line is left in the ring.

`close(&mut ring)` parses what the ring still holds first, so a final line without its terminator is delivered as a header, as body content or as the closing boundary, which files and IMAP literals often need. It fails if a multipart body is left unclosed. After closing, `receive` returns an error until `reset()`.

A header's value is joined from its folded lines and held until the last has arrived, up to `ParserLimits::max_header_value_size` (default 32768). The limits are one struct, `ParserLimits`, whose fields are `None` for no limit; set them with `with_limits`, `limits_mut` or `set_limits`.

`MimeHandler::set_locator` hands the handler an `Rc<dyn Locator>` that stays live: keep it and read the offset, line and column from inside any later callback. A parser and its handler are used from one thread, so none of this is `Send` or `Sync`.

## Package layout

| Rust module | Gumdrop Java |
|-------------|--------------|
| `mime` | `org.bluezoo.gumdrop.mime` — `MIMEParser`, handlers, CTE codecs, content types, `MimeWriter` |
| `rfc2047` | `mime.rfc2047` — encoded-word decode/encode |
| `rfc2231` | `mime.rfc2231` — extended parameter decode |
| `rfc5322` | `mime.rfc5322` — `MessageParser` / `MessageWriter`, addresses, dates, Message-ID |

## Relationship to other bluezoo libraries

| Library | Format | Pattern |
|---------|--------|---------|
| [jsonparser](https://github.com/cpkb-bluezoo/jsonparser) | JSON | `JSONContentHandler` + `receive` |
| [rprotobuf](https://github.com/cpkb-bluezoo/rprotobuf) | Protobuf | `Handler` + `receive` / `Writer` |
| **rmimeparser** | MIME / RFC 5322 | `MimeHandler` / `MessageHandler` + `receive`; `MimeWriter` / `MessageWriter` |
| [gumdrop](https://github.com/cpkb-bluezoo/gumdrop) | Protobuf (Java) | `ProtobufHandler` + `receive` |

## License

GNU Lesser General Public License version 3 or later (see [LICENSE](LICENSE), which
incorporates the GNU General Public License version 3 in [LICENSE-GPL](LICENSE-GPL)).

## Development

```bash
cargo test
cargo doc --open
```

The test suite ports gumdrop's MIME JUnit tests and covers the writer (CTE encoders, folding, write-then-parse round trips).

### Benchmark

`cargo run --release --example perf` prints throughput for the main parse and encode paths and, through a counting global allocator, the allocations and callbacks per scenario. It uses only the standard library.

### Rspamd email corpus

An opt-in harness clones the external [rspamd-test-corpus](https://github.com/rspamd/rspamd-test-corpus) (not vendored here) and parses every `.eml` with a plain `main` (no test-harness dependencies), listing skipped and failed files by path:

- **passed** — parse succeeds
- **skipped** — non-mail, or parse `Err` that is justified (e.g. truncated multipart with no `--boundary--` line); the reason shows the error
- **failed** — panic, or parse `Err` on a message that does not appear malformed (parser bug); the run exits non-zero

Optional overrides live in [`tests/corpus/expected_errors`](tests/corpus/expected_errors).

```bash
cargo test --features rspamd-corpus --test rspamd_corpus
```

By default the corpus is checked out under `target/rspamd-test-corpus`. Set `RSPAMD_TEST_CORPUS` to reuse an existing checkout.

## Publishing

```bash
cargo publish   # crates.io, when ready
```

Or depend via git until the first release:

```toml
rmimeparser = { git = "https://github.com/cpkb-bluezoo/rmimeparser", tag = "v0.5.0" }
```
