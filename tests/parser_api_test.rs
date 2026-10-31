//! The parser's API around the parsing: `parse(Read)`, buffer and chunk sizes,
//! closing and reuse, and the locator.

use std::cell::RefCell;
use std::io::Read;
use std::rc::Rc;

use loopbuf::LoopBuf;
use rmimeparser::{
    DkimMessageParser, Locator, MessageHandler, MessageParser, MimeHandler, MimeParser, ParseResult,
};

/// Records the events that carry content, and where the locator said the
/// parser was at each header.
#[derive(Default)]
struct Rec {
    locator: Option<Rc<dyn Locator>>,
    /// (offset, line, column) at each start_header
    at_headers: Vec<(u64, u64, u64)>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    body_calls: Vec<usize>,
}

impl MimeHandler for Rec {
    fn set_locator(&mut self, locator: Rc<dyn Locator>) {
        self.locator = Some(locator);
    }
    fn start_header(&mut self, name: &str) -> ParseResult<()> {
        let l = self.locator.as_ref().unwrap();
        self.at_headers
            .push((l.offset(), l.line_number(), l.column_number()));
        self.headers.push((name.to_string(), String::new()));
        Ok(())
    }
    fn header_content(&mut self, text: &str) -> ParseResult<()> {
        self.headers.last_mut().unwrap().1.push_str(text);
        Ok(())
    }
    fn body_content(&mut self, data: &[u8]) -> ParseResult<()> {
        self.body.extend_from_slice(data);
        self.body_calls.push(data.len());
        Ok(())
    }
}

impl MessageHandler for Rec {}

/// A reader that gives one byte at a time.
struct OneByte<'a>(&'a [u8]);

impl Read for OneByte<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.split_first() {
            Some((&b, rest)) if !buf.is_empty() => {
                buf[0] = b;
                self.0 = rest;
                Ok(1)
            }
            _ => Ok(0),
        }
    }
}

const MESSAGE: &[u8] = b"A: b\r\nC: d\r\n\r\nbody";

#[test]
fn parse_reads_a_reader_to_the_end() {
    for (buffer_size, reader_is_slow) in [(8192, false), (1100, true), (1000, true)] {
        let mut rec = Rec::default();
        let mut parser = MimeParser::new(&mut rec);
        parser.set_buffer_size(buffer_size);
        if reader_is_slow {
            parser.parse(OneByte(MESSAGE)).unwrap();
        } else {
            parser.parse(MESSAGE).unwrap();
        }
        drop(parser);
        assert_eq!(
            rec.headers,
            vec![("A".into(), "b".into()), ("C".into(), "d".into())]
        );
        assert_eq!(rec.body, b"body");
    }
}

#[test]
fn parse_works_for_the_message_and_dkim_parsers_too() {
    let mut rec = Rec::default();
    MessageParser::new(&mut rec)
        .parse(OneByte(MESSAGE))
        .unwrap();
    assert_eq!(rec.headers.len(), 2);
    assert_eq!(rec.body, b"body");

    let mut rec = Rec::default();
    let mut dkim = DkimMessageParser::new(&mut rec);
    dkim.parse(OneByte(MESSAGE)).unwrap();
    assert_eq!(dkim.raw_headers().len(), 2);
    assert_eq!(dkim.raw_body(), b"body");
    // parse resets first: a second message does not add to the first
    dkim.parse(MESSAGE).unwrap();
    assert_eq!(dkim.raw_headers().len(), 2);
    assert_eq!(dkim.raw_body(), b"body");
}

#[test]
fn parse_reports_a_header_line_the_buffer_cannot_hold() {
    let message = format!("X: {}\r\n\r\nbody", "a".repeat(500));
    let mut rec = Rec::default();
    let mut parser = MimeParser::new(&mut rec);
    parser.set_buffer_size(64);
    let err = parser.parse(message.as_bytes()).unwrap_err();
    assert!(err.message().contains("does not fit"), "{err}");
}

#[test]
fn a_ring_full_of_one_unfinished_header_line_is_an_error_not_a_wait() {
    let mut rec = Rec::default();
    let mut parser = MimeParser::new(&mut rec);
    let mut ring = LoopBuf::with_capacity(32);
    ring.extend_from_slice(&[b'x'; 32]);
    let err = parser.receive(&mut ring).unwrap_err();
    assert!(err.message().contains("does not fit"), "{err}");
}

#[test]
fn the_header_line_limit_is_exactly_998_bytes() {
    let parse = |len: usize, limit_off: bool| {
        let line = format!("X: {}", "a".repeat(len - 3));
        assert_eq!(line.len(), len);
        let message = format!("{line}\r\n\r\n");
        let mut rec = Rec::default();
        let mut parser = MimeParser::new(&mut rec);
        if limit_off {
            parser.limits_mut().max_header_line_length = None;
        }
        let mut ring = LoopBuf::with_capacity(4096);
        ring.extend_from_slice(message.as_bytes());
        parser.receive(&mut ring)
    };
    assert!(parse(998, false).is_ok());
    assert!(parse(999, false).is_err());
    assert!(
        parse(3000, true).is_ok(),
        "no limit, and the ring is large enough"
    );
}

#[test]
fn a_closed_parser_refuses_more_until_it_is_reset_and_then_parses_again() {
    let run = |parser: &mut MimeParser<&mut Rec>| {
        let mut ring = LoopBuf::with_capacity(256);
        ring.extend_from_slice(MESSAGE);
        parser.receive(&mut ring).unwrap();
        parser.close(&mut ring).unwrap();
        ring
    };
    let mut rec = Rec::default();
    let mut parser = MimeParser::new(&mut rec);
    let mut ring = run(&mut parser);
    ring.extend_from_slice(b"more");
    assert!(parser
        .receive(&mut ring)
        .unwrap_err()
        .message()
        .contains("closed"));
    // closing twice is not an error
    parser.close(&mut ring).unwrap();

    parser.reset();
    run(&mut parser);
    drop(parser);
    assert_eq!(rec.headers.len(), 4, "two messages, two headers each");
    assert_eq!(rec.body, b"bodybody");
}

#[test]
fn the_chunk_size_bounds_what_the_handler_is_given_at_a_time() {
    let mut message = b"Content-Type: text/plain\r\n\r\n".to_vec();
    message.extend_from_slice(&[b'z'; 100]);
    let mut rec = Rec::default();
    let mut parser = MimeParser::new(&mut rec);
    parser.set_chunk_size(7);
    let mut ring = LoopBuf::with_capacity(512);
    ring.extend_from_slice(&message);
    parser.receive(&mut ring).unwrap();
    parser.close(&mut ring).unwrap();
    drop(parser);
    assert_eq!(rec.body.len(), 100);
    assert!(
        rec.body_calls.iter().all(|&n| n <= 7),
        "{:?}",
        rec.body_calls
    );
    assert!(rec.body_calls.len() >= 100 / 7);
}

#[test]
#[should_panic(expected = "chunk size")]
fn a_zero_chunk_size_is_refused() {
    let mut rec = Rec::default();
    MimeParser::new(&mut rec).set_chunk_size(0);
}

#[test]
#[should_panic(expected = "buffer size")]
fn a_zero_buffer_size_is_refused() {
    let mut rec = Rec::default();
    MimeParser::new(&mut rec).set_buffer_size(0);
}

#[test]
fn is_underflow_says_when_a_line_is_left_in_the_ring() {
    let mut rec = Rec::default();
    let mut parser = MimeParser::new(&mut rec);
    let mut ring = LoopBuf::with_capacity(256);
    ring.extend_from_slice(b"A: b\r\nC: ");
    parser.receive(&mut ring).unwrap();
    assert!(parser.is_underflow());
    assert_eq!(ring.len(), 3, "the unfinished line stays in the ring");
    ring.extend_from_slice(b"d\r\n\r\n");
    parser.receive(&mut ring).unwrap();
    assert!(!parser.is_underflow());
    assert!(ring.is_empty());
}

// ---- the locator ----

#[test]
fn the_locator_is_live_and_says_where_each_header_ends() {
    let mut rec = Rec::default();
    let mut parser = MimeParser::new(&mut rec);
    let mut ring = LoopBuf::with_capacity(256);
    ring.extend_from_slice(MESSAGE);
    parser.receive(&mut ring).unwrap();
    parser.close(&mut ring).unwrap();
    drop(parser);
    // (offset, line, column) as each header line has been consumed
    assert_eq!(rec.at_headers, vec![(6, 1, 6), (12, 2, 6)]);
    // the same locator, kept by the handler, is live after the parse
    let l = rec.locator.unwrap();
    assert_eq!((l.offset(), l.line_number(), l.column_number()), (18, 4, 4));
}

#[test]
fn the_locator_reads_the_same_wherever_the_ring_wraps() {
    let mut message = b"A: b\r\nC: d\r\n\r\n".to_vec();
    message.extend_from_slice(b"line one\r\nline two\r\nlast");
    let reference = {
        let mut rec = Rec::default();
        let mut parser = MimeParser::new(&mut rec);
        let mut ring = LoopBuf::with_capacity(512);
        ring.extend_from_slice(&message);
        parser.receive(&mut ring).unwrap();
        parser.close(&mut ring).unwrap();
        drop(parser);
        let l = rec.locator.unwrap();
        (
            rec.at_headers.clone(),
            (l.offset(), l.line_number(), l.column_number()),
        )
    };
    assert_eq!(reference.1, (message.len() as u64, 6, 4));
    for (capacity, step) in [(40, 1), (40, 3), (64, 7), (100, 100)] {
        let mut rec = Rec::default();
        let mut parser = MimeParser::new(&mut rec);
        let mut ring = LoopBuf::with_capacity(capacity);
        for chunk in message.chunks(step) {
            ring.extend_from_slice(chunk);
            parser.receive(&mut ring).unwrap();
        }
        parser.close(&mut ring).unwrap();
        drop(parser);
        let l = rec.locator.unwrap();
        assert_eq!(
            rec.at_headers, reference.0,
            "capacity {capacity} step {step}"
        );
        assert_eq!(
            (l.offset(), l.line_number(), l.column_number()),
            reference.1,
            "capacity {capacity} step {step}"
        );
    }
}

#[test]
fn an_error_says_where_it_happened() {
    let mut rec = Rec::default();
    let mut parser = MimeParser::new(&mut rec);
    let mut ring = LoopBuf::with_capacity(256);
    ring.extend_from_slice(b"A: b\r\nno colon here\r\n\r\n");
    let err = parser.receive(&mut ring).unwrap_err();
    assert!(err.message().contains("line 2"), "{err}");
    assert!(err.message().contains("offset 21"), "{err}");
}

#[test]
fn reset_gives_the_next_message_a_fresh_locator_and_leaves_the_old_one_alone() {
    let mut rec = Rec::default();
    let mut parser = MimeParser::new(&mut rec);
    let mut ring = LoopBuf::with_capacity(256);
    ring.extend_from_slice(MESSAGE);
    parser.receive(&mut ring).unwrap();
    parser.close(&mut ring).unwrap();
    parser.reset();
    ring.extend_from_slice(b"X: y\r\n\r\n");
    parser.receive(&mut ring).unwrap();
    parser.close(&mut ring).unwrap();
    drop(parser);
    // the second message started again at the top
    assert_eq!(rec.at_headers.last(), Some(&(6, 1, 6)));
}

/// A handler that keeps the locator it was given can read it from inside a
/// later callback; here, at the end of the headers, which is the blank line
/// (line 3) just consumed.
#[test]
fn a_kept_locator_can_be_read_inside_a_callback() {
    struct AtBody(Option<Rc<dyn Locator>>, Rc<RefCell<Vec<(u64, u64)>>>);
    impl MimeHandler for AtBody {
        fn set_locator(&mut self, l: Rc<dyn Locator>) {
            self.0 = Some(l);
        }
        fn end_headers(&mut self) -> ParseResult<()> {
            let l = self.0.as_ref().unwrap();
            self.1.borrow_mut().push((l.offset(), l.line_number()));
            Ok(())
        }
    }
    let seen = Rc::new(RefCell::new(Vec::new()));
    let mut parser = MimeParser::new(AtBody(None, Rc::clone(&seen)));
    parser.parse(MESSAGE).unwrap();
    assert_eq!(*seen.borrow(), vec![(14, 3)]);
}
