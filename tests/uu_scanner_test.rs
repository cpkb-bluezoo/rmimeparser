//! `UuScanner`: inline uuencoded blocks in a text body.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use rmimeparser::{encode_uuencode, ParseResult, UuHandler, UuScanner, UuScannerLimits};

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

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ev {
    Text(Vec<u8>),
    Begin(u32, Vec<u8>),
    Data(Vec<u8>),
    End(bool),
}

/// Records the events, merging adjacent text and adjacent data, which the
/// scanner may split anywhere.
#[derive(Default)]
struct Rec {
    events: Vec<Ev>,
}

impl UuHandler for Rec {
    fn text(&mut self, data: &[u8]) -> ParseResult<()> {
        match self.events.last_mut() {
            Some(Ev::Text(t)) => t.extend_from_slice(data),
            _ => self.events.push(Ev::Text(data.to_vec())),
        }
        Ok(())
    }
    fn begin(&mut self, mode: u32, name: &[u8]) -> ParseResult<()> {
        self.events.push(Ev::Begin(mode, name.to_vec()));
        Ok(())
    }
    fn data(&mut self, data: &[u8]) -> ParseResult<()> {
        match self.events.last_mut() {
            Some(Ev::Data(d)) => d.extend_from_slice(data),
            _ => self.events.push(Ev::Data(data.to_vec())),
        }
        Ok(())
    }
    fn end(&mut self, complete: bool) -> ParseResult<()> {
        self.events.push(Ev::End(complete));
        Ok(())
    }
}

fn scan_chunked(input: &[u8], chunk: usize) -> Vec<Ev> {
    let mut scanner = UuScanner::new(Rec::default());
    for piece in input.chunks(chunk) {
        scanner.feed(piece).unwrap();
    }
    scanner.finish().unwrap();
    scanner.into_handler().events
}

/// The events are the same however the input is cut.
fn scan(input: &[u8]) -> Vec<Ev> {
    let whole = scan_chunked(input, input.len().max(1));
    for chunk in 1..=input.len().max(1) {
        assert_eq!(
            scan_chunked(input, chunk),
            whole,
            "chunks of {chunk} bytes: {:?}",
            String::from_utf8_lossy(input)
        );
    }
    whole
}

fn text(s: &str) -> Ev {
    Ev::Text(s.as_bytes().to_vec())
}

fn data(d: &[u8]) -> Ev {
    Ev::Data(d.to_vec())
}

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 7919 + i / 3) % 256) as u8).collect()
}

fn block(name: &str, mode: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_uuencode(&mut out, name, mode, payload).unwrap();
    out
}

#[test]
fn round_trip_with_two_blocks_in_chunks_of_every_size() {
    let first = sample(200);
    let second = sample(46);
    let mut input = b"Hello,\r\nhere is a file:\r\n".to_vec();
    input.extend(block("one.bin", 0o644, &first));
    input.extend_from_slice(b"and another:\r\nbegin is not a block\r\n");
    input.extend(block("two file.dat", 0o755, &second));
    input.extend_from_slice(b"Bye.\r\nno final newline");

    let events = scan(&input);
    assert_eq!(
        events,
        vec![
            text("Hello,\r\nhere is a file:\r\n"),
            Ev::Begin(0o644, b"one.bin".to_vec()),
            data(&first),
            Ev::End(true),
            text("and another:\r\nbegin is not a block\r\n"),
            Ev::Begin(0o755, b"two file.dat".to_vec()),
            data(&second),
            Ev::End(true),
            text("Bye.\r\nno final newline"),
        ]
    );
}

#[test]
fn a_block_with_no_end_is_cut_off_with_what_was_decoded() {
    let payload = sample(100);
    let mut input = b"before\n".to_vec();
    let full = block("f", 0o600, &payload);
    // Drop the zero line and `end`
    let text_len = full.len() - b"`\r\nend\r\n".len();
    input.extend_from_slice(&full[..text_len]);

    let events = scan(&input);
    assert_eq!(
        events,
        vec![
            text("before\n"),
            Ev::Begin(0o600, b"f".to_vec()),
            data(&payload),
            Ev::End(false),
        ]
    );
}

#[test]
fn a_block_missing_only_its_end_line_is_cut_off() {
    let payload = sample(10);
    let full = block("f", 0o644, &payload);
    let input = &full[..full.len() - b"end\r\n".len()];
    assert_eq!(
        scan(input),
        vec![
            Ev::Begin(0o644, b"f".to_vec()),
            data(&payload),
            Ev::End(false)
        ]
    );
}

#[test]
fn prose_beginning_with_begin_is_text() {
    for prose in [
        "begin the meeting now\r\n",
        "begin 12 things\r\n",
        "begin 644\r\n",
        "begin 999 file\r\n",
        "begin 6444444 file\r\n",
        "begin 644 \r\n",
        "begin-base64 644 file\r\n",
        "begin\r\n",
        "beginning of the end\r\n",
        " begin 644 file\r\n",
    ] {
        assert_eq!(scan(prose.as_bytes()), vec![text(prose)], "{prose:?}");
    }
}

#[test]
fn a_begin_line_that_nothing_confirms_is_text_not_swallowed() {
    // It looks like a `begin` line, but the line after it is prose
    let input = "begin 644 proposals\r\nwe should discuss this\r\n";
    assert_eq!(scan(input.as_bytes()), vec![text(input)]);

    // and at the end of the input
    let input = "intro\nbegin 644 proposals\n";
    assert_eq!(scan(input.as_bytes()), vec![text(input)]);
}

#[test]
fn a_prose_line_inside_a_block_ends_it_and_is_text() {
    let payload = sample(45);
    let mut input = b"begin 644 f\r\n".to_vec();
    let full = block("f", 0o644, &payload);
    let lines_start = b"begin 644 f\r\n".len();
    input.extend_from_slice(&full[lines_start..lines_start + 63]); // the one M line
    input.extend_from_slice(b"begin the next part of the plan\r\nmore\r\n");
    let events = scan(&input);
    assert_eq!(
        events,
        vec![
            Ev::Begin(0o644, b"f".to_vec()),
            data(&payload),
            Ev::End(false),
            text("begin the next part of the plan\r\nmore\r\n"),
        ]
    );
}

#[test]
fn a_cut_off_block_can_be_followed_directly_by_the_next() {
    let a = sample(45);
    let b = sample(5);
    let full_a = block("a", 0o644, &a);
    let mut input = full_a[..full_a.len() - b"`\r\nend\r\n".len()].to_vec();
    input.extend(block("b", 0o600, &b));
    assert_eq!(
        scan(&input),
        vec![
            Ev::Begin(0o644, b"a".to_vec()),
            data(&a),
            Ev::End(false),
            Ev::Begin(0o600, b"b".to_vec()),
            data(&b),
            Ev::End(true),
        ]
    );
}

#[test]
fn unix_line_endings_and_a_space_for_zero_are_accepted() {
    // "Cat": the zero line and the group using a space for the zero characters
    let input = b"begin 644 cat.txt\n#0V%T\n \nend\n";
    assert_eq!(
        scan(input),
        vec![
            Ev::Begin(0o644, b"cat.txt".to_vec()),
            data(b"Cat"),
            Ev::End(true)
        ]
    );
    let input = b"begin 644 cat.txt\r\n#0V%T\r\n`\r\nend\r\n";
    assert_eq!(
        scan(input),
        vec![
            Ev::Begin(0o644, b"cat.txt".to_vec()),
            data(b"Cat"),
            Ev::End(true)
        ]
    );
}

#[test]
fn zero_characters_that_were_trimmed_or_written_as_spaces_decode_as_zero() {
    // "\0\0\0" is the group "````"; a transport may trim it to nothing, and an
    // older encoder wrote spaces
    for line in ["#````", "#    ", "#  ", "#", "#`` "] {
        let input = format!("begin 644 z\n{line}\n`\nend\n");
        assert_eq!(
            scan(input.as_bytes()),
            vec![
                Ev::Begin(0o644, b"z".to_vec()),
                data(&[0, 0, 0]),
                Ev::End(true)
            ],
            "{line:?}"
        );
    }
}

#[test]
fn trailing_whitespace_is_tolerated_on_every_kind_of_line() {
    let input = b"begin 644 cat.txt  \r\n#0V%T \t\r\n` \r\nend  \r\nafter";
    assert_eq!(
        scan(input),
        vec![
            Ev::Begin(0o644, b"cat.txt".to_vec()),
            data(b"Cat"),
            Ev::End(true),
            text("after"),
        ]
    );
}

#[test]
fn end_without_the_zero_line_is_complete() {
    let input = b"begin 644 cat.txt\n#0V%T\nend\n";
    assert_eq!(
        scan(input),
        vec![
            Ev::Begin(0o644, b"cat.txt".to_vec()),
            data(b"Cat"),
            Ev::End(true)
        ]
    );
}

#[test]
fn an_empty_block_is_a_block() {
    assert_eq!(
        scan(b"begin 644 e\r\nend\r\n"),
        vec![Ev::Begin(0o644, b"e".to_vec()), Ev::End(true)]
    );
}

#[test]
fn data_after_the_zero_line_ends_the_block_as_cut_off() {
    let input = "begin 644 f\n#0V%T\n`\n#0V%T\nend\n";
    assert_eq!(
        scan(input.as_bytes()),
        vec![
            Ev::Begin(0o644, b"f".to_vec()),
            data(b"Cat"),
            Ev::End(false),
            text("#0V%T\nend\n"),
        ]
    );
}

#[test]
fn the_name_is_bounded() {
    let ok = format!("begin 644 {}\nend\n", "n".repeat(255));
    assert_eq!(
        scan(ok.as_bytes()),
        vec![Ev::Begin(0o644, vec![b'n'; 255]), Ev::End(true)]
    );
    let long = format!("begin 644 {}\nend\n", "n".repeat(256));
    assert_eq!(scan(long.as_bytes()), vec![text(&long)]);

    let mut scanner = UuScanner::with_limits(
        Rec::default(),
        UuScannerLimits {
            max_name_length: 4,
            ..Default::default()
        },
    );
    scanner
        .feed(b"begin 644 abcd\nend\nbegin 644 abcde\nend\n")
        .unwrap();
    scanner.finish().unwrap();
    assert_eq!(
        scanner.into_handler().events,
        vec![
            Ev::Begin(0o644, b"abcd".to_vec()),
            Ev::End(true),
            text("begin 644 abcde\nend\n"),
        ]
    );
}

#[test]
fn a_line_longer_than_the_limit_is_text_however_long() {
    let long = format!("{}\n", "M".repeat(5000));
    let input = format!("begin 644 f\n{long}after\n");
    assert_eq!(
        scan(input.as_bytes()),
        vec![text(&format!("begin 644 f\n{long}after\n"))]
    );
    let input = format!("begin 644 f\n#0V%T\n{long}after\n");
    assert_eq!(
        scan(input.as_bytes()),
        vec![
            Ev::Begin(0o644, b"f".to_vec()),
            data(b"Cat"),
            Ev::End(false),
            text(&format!("{long}after\n")),
        ]
    );
}

#[test]
fn text_without_blocks_passes_through_untouched() {
    let input: Vec<u8> = (0..3000u32)
        .flat_map(|i| format!("line {i} with b and begin inside\n").into_bytes())
        .collect();
    let events = scan_chunked(&input, 7);
    assert_eq!(events, vec![Ev::Text(input)]);
}

#[test]
fn a_scanner_can_be_reused_after_finish() {
    let mut scanner = UuScanner::new(Rec::default());
    scanner.feed(b"begin 644 f\n#0V%T\n").unwrap();
    scanner.finish().unwrap();
    scanner.feed(b"plain\n").unwrap();
    scanner.finish().unwrap();
    assert_eq!(
        scanner.into_handler().events,
        vec![
            Ev::Begin(0o644, b"f".to_vec()),
            data(b"Cat"),
            Ev::End(false),
            text("plain\n"),
        ]
    );
}

#[test]
fn a_multi_megabyte_block_decodes_in_constant_memory() {
    struct Count {
        bytes: usize,
        sum: u64,
    }
    impl UuHandler for Count {
        fn data(&mut self, data: &[u8]) -> ParseResult<()> {
            self.bytes += data.len();
            self.sum += data.iter().map(|&b| b as u64).sum::<u64>();
            Ok(())
        }
    }

    let peak_for = |size: usize| {
        let piece = sample(45 * 1000);
        let mut encoder = rmimeparser::UuencodeEncoder::new("big.bin", 0o644);
        let mut scanner = UuScanner::new(Count { bytes: 0, sum: 0 });
        let mut out = Vec::new();
        let mut expected_sum = 0u64;

        let base = start_measuring();
        let mut fed = 0;
        while fed < size {
            out.clear();
            encoder.write(&mut out, &piece).unwrap();
            scanner.feed(&out).unwrap();
            expected_sum += piece.iter().map(|&b| b as u64).sum::<u64>();
            fed += piece.len();
        }
        out.clear();
        encoder.finish(&mut out).unwrap();
        scanner.feed(&out).unwrap();
        scanner.finish().unwrap();
        let count = scanner.into_handler();
        assert_eq!(count.bytes, fed);
        assert_eq!(count.sum, expected_sum);
        peak(base)
    };

    let small = peak_for(45 * 1000);
    let large = peak_for(8 * 1024 * 1024);
    // The scanner's own share is what is left after the test's buffers, which
    // are the same size in both runs
    assert!(
        large < small + 16 * 1024,
        "peak grew with the block: {small} -> {large}"
    );
}
