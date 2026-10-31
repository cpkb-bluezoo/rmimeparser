# rmimeparser

Push-based MIME and RFC 5322 message parser and writer for Rust.

**rmimeparser** ports the [gumdrop](https://github.com/cpkb-bluezoo/gumdrop) `org.bluezoo.gumdrop.mime` package tree to Rust, using the same design as [rprotobuf](https://github.com/cpkb-bluezoo/rprotobuf) and [jsonparser](https://github.com/cpkb-bluezoo/jsonparser):

- Incremental `receive(&mut LoopBuf)` parsing over a caller-owned ring — the parser holds none of the body, streaming over a fixed read buffer
- Handler callbacks instead of materialised message domain objects
- Push `MimeWriter` / `MessageWriter` writing into a caller-owned ring, each call atomic — chunked `body_content`, no builder/DOM
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
use loopbuf::LoopBuf;
use rmimeparser::{ContentType, MimeWriter};

let mut ring = LoopBuf::with_capacity(8192);
let mut w = MimeWriter::new();
w.start_entity(&mut ring, None)?;
w.content_type(&mut ring, &ContentType::new("text", "plain", None))?;
w.content_transfer_encoding(&mut ring, "base64")?;
w.end_headers(&mut ring)?;
let taken = w.body_content(&mut ring, b"Hello world")?; // as many bytes as fit
assert_eq!(taken, 11);
w.end_entity(&mut ring, None)?;
w.close()?;
```

The writers put their output in a caller-owned ring and hold none of it. Every call is atomic: it appends everything it was asked to or nothing, and leaves the writer as it was. The error is `loopbuf::WriteError`, shared with the other writers: `is_would_block()` means the ring has no room right now, so drain it and repeat the same call; `ErrorKind::InvalidInput` means the call can never succeed (it needs more room than the whole ring has, it is not valid in the writer's state, or what it was given is not valid MIME).

`body_content` and `raw_body_content` take as much of their input as fits and return how much, so a body of any size passes through a ring of any size; call them again with the rest. Everything else takes its whole input or fails.

## RFC 5322 message parser

```rust
use loopbuf::LoopBuf;
use rmimeparser::{MessageHandler, MessageParser, MimeHandler, ParseResult};

#[derive(Default)]
struct Headers {
    subject: String,
    in_subject: bool,
}

// A header the parser does not parse arrives as unstructured text in pieces
impl MimeHandler for Headers {
    fn start_header(&mut self, name: &str) -> ParseResult<()> {
        self.in_subject = name.eq_ignore_ascii_case("subject");
        Ok(())
    }
    fn header_content(&mut self, text: &str) -> ParseResult<()> {
        if self.in_subject {
            self.subject.push_str(text);
        }
        Ok(())
    }
}

impl MessageHandler for Headers {}

let raw = b"From: sender@example.com\r\nSubject: test\r\n\r\nBody\r\n";
let mut parser = MessageParser::new(Headers::default());
let mut ring = LoopBuf::with_capacity(8192);
ring.extend_from_slice(raw);
parser.receive(&mut ring)?;
parser.close(&mut ring)?;
```

### Headers

The two layers are separate. `MimeParser` and `MimeHandler` know nothing of RFC 5322, so something that only needs MIME (HTTP's `multipart/form-data`) can use them alone. `MessageParser` and `MessageHandler` extend them for mail: addresses, dates and message-ids.

`MimeParser` parses five headers itself: `Content-Type`, `Content-Disposition`, `Content-Transfer-Encoding`, `Content-ID` and `MIME-Version`. **Every other header is unstructured**, known or not, and arrives as `start_header(name)`, any number of `header_content(&str)` pieces and `end_header()`. The pieces are unfolded, trimmed, RFC 2047 encoded words decoded, and raw 8-bit text read as UTF-8 where it is valid and as windows-1252 where it is not (ISO-8859-1 with `set_utf8_headers(true)`). The parser holds none of the value, so a header of any size passes through; a bounded amount (an encoded word, some white space, a UTF-8 sequence) is held across pieces, and a piece has no particular size. `HeaderTextDecoder` is the same decoder on its own.

A layer that parses some headers itself says so with `MimeHandler::header_delivery(name)`, asked once for each header the parser does not understand. Answering `HeaderDelivery::Raw` has the value arrive as `raw_header_content(&[u8])` instead: undecoded, with only the folds removed. That is how `MessageParser` takes dates, address lists and message-ids, which it has to read as tokens: decoding an encoded word first could put a `<` or a `,` into the structure. A header taken raw is held by whoever takes it, so `ParserLimits::max_header_value_size` applies to it, as it does to the three of those five that the parser holds whole (`Content-Transfer-Encoding`, `Content-ID`, `MIME-Version`); it does not apply to unstructured headers, `Content-Type` or `Content-Disposition`. The header name has to arrive whole and is limited to `max_header_name_length` (1024).

### Content-Type and Content-Disposition

These two stream too, as events, so a parameter value of any size passes through and nothing is held but the head:

```text
start_content_type(primary, sub)      start_content_disposition(kind)
  start_parameter(name, language)       ...
    parameter_content(text)*
  end_parameter()
end_content_type()                    end_content_disposition()
```

A parameter value arrives decoded: quoted-pairs resolved, RFC 2047 encoded words decoded, and an RFC 2231 extended value (`name*=UTF-8''%C3%A9`) percent-decoded and read in its charset. RFC 2231 continuations (`name*0*=...; name*1*=...`) are joined into one parameter, named without the `*0`; segments have to arrive in order from 0, and one that does not is dropped. `language` is `Some` for an extended value, so a handler can prefer `filename*` to `filename` (the same name can come twice; which to keep is the handler's policy). A parameter the grammar cannot use is skipped and the next is read.

If the head is not `type/subtype` (or the disposition type is not a token), `malformed_header(name, reason)` stands in for `start_header` and the whole value follows as unstructured text, so a handler that wants the value as a string can have it.

The parser picks the `boundary` out of a multipart `Content-Type` itself as it goes by. A handler that wants a `ContentType` or `ContentDisposition` object puts the events through `ContentTypeCollector` or `ContentDispositionCollector` (first parameter of a name wins; an extended value replaces a plain one), and `ContentTypeParser::parse` / `ContentDispositionParser::parse` give one for a value held whole, by running the same grammar.

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
