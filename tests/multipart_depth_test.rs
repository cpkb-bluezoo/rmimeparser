//! `ParserLimits::max_multipart_depth`: the nesting of multipart entities is
//! bounded, and the bound holds memory down whatever the input does.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::Read;

use loopbuf::LoopBuf;
use rmimeparser::{MimeHandler, MimeParser, ParseResult, ParserLimits};

// Allocations are counted per thread: the test harness allocates on its own
// threads while a test runs, and a process-wide count would take that in.
thread_local! {
    static CURRENT: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn grow(by: usize) {
    CURRENT.with(|c| {
        let now = c.get() + by as isize;
        c.set(now);
        PEAK.with(|p| p.set(p.get().max(now)));
    });
}

fn shrink(by: usize) {
    CURRENT.with(|c| c.set(c.get() - by as isize));
}

/// Starts a measurement, returning the baseline to subtract from [`peak`].
fn start_measuring() -> isize {
    let base = CURRENT.with(|c| c.get());
    PEAK.with(|p| p.set(base));
    base
}

fn peak(base: isize) -> usize {
    (PEAK.with(|p| p.get()) - base) as usize
}

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        shrink(layout.size());
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            if new_size >= layout.size() {
                grow(new_size - layout.size());
            } else {
                shrink(layout.size() - new_size);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

#[derive(Default)]
struct Sink {
    entities: usize,
    body_bytes: usize,
}

impl MimeHandler for Sink {
    fn start_entity(&mut self, _boundary: Option<&str>) -> ParseResult<()> {
        self.entities += 1;
        Ok(())
    }
    fn body_content(&mut self, data: &[u8]) -> ParseResult<()> {
        self.body_bytes += data.len();
        Ok(())
    }
}

/// A message `depth` multiparts deep with `body_lines` lines of text at the
/// bottom, generated as it is read so that nothing of it is held.
struct Nest {
    depth: usize,
    body_lines: usize,
    level: usize,
    lines_done: usize,
    closed: usize,
    pending: Vec<u8>,
    pos: usize,
}

impl Nest {
    fn new(depth: usize, body_lines: usize) -> Self {
        Self {
            depth,
            body_lines,
            level: 0,
            lines_done: 0,
            closed: 0,
            pending: Vec::new(),
            pos: 0,
        }
    }

    fn refill(&mut self) -> bool {
        self.pending.clear();
        self.pos = 0;
        if self.level < self.depth {
            let b = format!("b{}", self.level);
            self.pending.extend_from_slice(
                format!("Content-Type: multipart/mixed; boundary={b}\r\n\r\n--{b}\r\n").as_bytes(),
            );
            self.level += 1;
        } else if self.level == self.depth && self.lines_done == 0 {
            self.pending
                .extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
            self.lines_done = 1;
        } else if self.lines_done <= self.body_lines {
            self.pending
                .extend_from_slice(b"some body text on a line\r\n");
            self.lines_done += 1;
        } else if self.closed < self.depth {
            let b = format!("b{}", self.depth - 1 - self.closed);
            self.pending
                .extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
            self.closed += 1;
        } else {
            return false;
        }
        true
    }
}

impl Read for Nest {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos == self.pending.len() && !self.refill() {
            return Ok(0);
        }
        let n = buf.len().min(self.pending.len() - self.pos);
        buf[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn parse_nest(limits: ParserLimits, depth: usize, body_lines: usize) -> (ParseResult<()>, Sink) {
    let mut sink = Sink::default();
    let result = {
        let mut parser = MimeParser::with_limits(&mut sink, limits);
        parser.parse(Nest::new(depth, body_lines))
    };
    (result, sink)
}

fn nested(depth: usize) -> Vec<u8> {
    let mut out = Vec::new();
    Nest::new(depth, 1).read_to_end(&mut out).unwrap();
    out
}

#[test]
fn the_default_limit_is_32_and_unlimited_has_none() {
    assert_eq!(ParserLimits::default().max_multipart_depth, Some(32));
    assert_eq!(ParserLimits::unlimited().max_multipart_depth, None);
}

#[test]
fn a_message_32_deep_parses_and_33_deep_fails_naming_the_limit() {
    let (ok, sink) = parse_nest(ParserLimits::default(), 32, 1);
    ok.unwrap();
    assert!(sink.entities >= 32);

    let (err, _) = parse_nest(ParserLimits::default(), 33, 1);
    let err = err.unwrap_err();
    assert!(err.message().contains("depth"), "{err}");
    assert!(err.message().contains("32"), "{err}");
}

#[test]
fn unlimited_parses_both() {
    parse_nest(ParserLimits::unlimited(), 32, 1).0.unwrap();
    parse_nest(ParserLimits::unlimited(), 33, 1).0.unwrap();
    parse_nest(ParserLimits::unlimited(), 500, 1).0.unwrap();
}

#[test]
fn the_outcome_is_the_same_for_every_chunk_size() {
    for depth in [32usize, 33] {
        let data = nested(depth);
        let mut expected: Option<bool> = None;
        for chunk in 1..=200usize {
            let mut sink = Sink::default();
            let mut parser = MimeParser::new(&mut sink);
            let mut ring = LoopBuf::with_capacity(4096);
            let mut result = Ok(());
            for piece in data.chunks(chunk) {
                ring.extend_from_slice(piece);
                result = parser.receive(&mut ring);
                if result.is_err() {
                    break;
                }
            }
            if result.is_ok() {
                result = parser.close(&mut ring);
            }
            let ok = result.is_ok();
            assert_eq!(ok, depth == 32, "depth {depth}, chunk {chunk}");
            if let Err(e) = &result {
                assert!(e.message().contains("depth"), "{e}");
            }
            assert_eq!(*expected.get_or_insert(ok), ok);
        }
    }
}

#[test]
fn memory_at_the_limit_does_not_grow_with_the_body() {
    let peak_for = |lines: usize| {
        let base = start_measuring();
        let (r, sink) = parse_nest(ParserLimits::default(), 32, lines);
        r.unwrap();
        assert!(sink.body_bytes >= lines * 20);
        peak(base)
    };
    let small = peak_for(1_000);
    // About 25 MiB of body text
    let large = peak_for(1_000_000);
    assert!(
        large < small + 64 * 1024,
        "peak grew with the body: {small} -> {large}"
    );
    assert!(large < 2 * 1024 * 1024, "peak {large}");
}

#[test]
fn a_pathological_nest_fails_fast_with_memory_bounded_by_the_limit() {
    let base = start_measuring();
    let mut sink = Sink::default();
    let err = {
        let mut parser = MimeParser::new(&mut sink);
        parser.parse(Nest::new(100_000, 1)).unwrap_err()
    };
    assert!(err.message().contains("depth"), "{err}");
    assert!(sink.entities <= 33, "went on to {} entities", sink.entities);
    let peak = peak(base);
    assert!(peak < 2 * 1024 * 1024, "peak {peak}");
}
