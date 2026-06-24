# rmimeparser

Push-based MIME and RFC 5322 message parser for Rust.

**rmimeparser** ports the [gumdrop](https://github.com/cpkb-bluezoo/gumdrop) `org.bluezoo.gumdrop.mime` package tree to Rust, using the same design as [rprotobuf](https://github.com/cpkb-bluezoo/rprotobuf) and [jsonparser](https://github.com/cpkb-bluezoo/jsonparser):

- Incremental `receive()` parsing — constant memory, streaming over fixed read buffers
- Handler callbacks instead of materialised message domain objects
- MIME core with RFC 5322 as an extension (`MessageParser` composes `MimeParser`)
- Zero dependencies beyond the Rust standard library

This is **not** a port of Java SAM (`MessageParser` in `com.mimecast:sam`). It follows gumdrop’s MIME-first design; SAM’s message-centred API and legacy RFC handling are out of scope.

A unified MIME writer/handler will be added later. Gumdrop’s generation pieces (`RFC2047Encoder`, `MessageDateTimeFormatter`, `to_header_value()` on value types) are included for header encoding.

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
| `mime` | `org.bluezoo.gumdrop.mime` — `MIMEParser`, handlers, CTE decoders, content types |
| `rfc2047` | `mime.rfc2047` — encoded-word decode/encode |
| `rfc2231` | `mime.rfc2231` — extended parameter decode |
| `rfc5322` | `mime.rfc5322` — `MessageParser`, addresses, dates, Message-ID |

## Relationship to other bluezoo libraries

| Library | Format | Pattern |
|---------|--------|---------|
| [jsonparser](https://github.com/cpkb-bluezoo/jsonparser) | JSON | `JSONContentHandler` + `receive` |
| [rprotobuf](https://github.com/cpkb-bluezoo/rprotobuf) | Protobuf | `Handler` + `receive` |
| **rmimeparser** | MIME / RFC 5322 | `MimeHandler` / `MessageHandler` + `receive` |
| [gumdrop](https://github.com/cpkb-bluezoo/gumdrop) | Protobuf (Java) | `ProtobufHandler` + `receive` |

## License

LGPL-2.1-or-later (see [LICENSE](LICENSE)).

## Development

```bash
cargo test
cargo doc --open
```

The test suite ports gumdrop's MIME JUnit tests (368 integration tests across parser, decoders, content types, RFC 2047/2231, and RFC 5322).

## Publishing

```bash
cargo publish   # crates.io, when ready
```

Or depend via git until the first release:

```toml
rmimeparser = { git = "https://github.com/cpkb-bluezoo/rmimeparser", tag = "v0.1.0" }
```
