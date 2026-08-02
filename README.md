# rmimeparser

Push-based MIME and RFC 5322 message parser and writer for Rust.

**rmimeparser** ports the [gumdrop](https://github.com/cpkb-bluezoo/gumdrop) `org.bluezoo.gumdrop.mime` package tree to Rust, using the same design as [rprotobuf](https://github.com/cpkb-bluezoo/rprotobuf) and [jsonparser](https://github.com/cpkb-bluezoo/jsonparser):

- Incremental `receive()` parsing — constant memory, streaming over fixed read buffers
- Handler callbacks instead of materialised message domain objects
- Push `MimeWriter` / `MessageWriter` — constant memory, chunked `body_content`, no builder/DOM
- MIME core with RFC 5322 as an extension (`MessageParser` / `MessageWriter` compose MIME)
- Zero dependencies beyond the Rust standard library

Header encoding helpers (`RFC2047Encoder`, `MessageDateTimeFormatter`, `to_header_value()` on value types) are shared by the writers.

## MIME parser

```rust
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
let mut handler = TeeHandler { bytes: 0 };
let mut parser = MimeParser::new(&mut handler);
let mut input = &raw[..];
parser.receive(&mut input)?;
parser.close()?;
assert_eq!(handler.bytes, 7);
```

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
let mut handler = Headers;
let mut parser = MessageParser::new(&mut handler);
let mut input = &raw[..];
parser.receive(&mut input)?;
parser.close()?;
```

### Streaming (NIO-style buffer contract)

```rust
loop {
    // read more bytes into `buf`...
    let mut slice = &buf[..filled];
    parser.receive(&mut slice)?;
    // `slice` advanced; compact `buf` and read again
}
```

On underflow, `parser.is_underflow()` is true and `close()` may fail until more data arrives (except non-multipart body EOF).

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

LGPL-2.1-or-later (see [LICENSE](LICENSE)).

## Development

```bash
cargo test
cargo doc --open
```

The test suite ports gumdrop's MIME JUnit tests and covers the writer (CTE encoders, folding, write-then-parse round trips).

### Rspamd email corpus

An opt-in harness clones the external [rspamd-test-corpus](https://github.com/rspamd/rspamd-test-corpus) (not vendored here) and checks that `MessageParser` does not panic on those messages:

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
rmimeparser = { git = "https://github.com/cpkb-bluezoo/rmimeparser", tag = "v0.2.0" }
```
