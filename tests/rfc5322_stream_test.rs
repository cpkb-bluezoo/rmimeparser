//! The RFC 5322 layer delivers a header an element at a time, so a header of
//! any size passes through a small ring and nothing is held but one element.

use loopbuf::LoopBuf;
use rmimeparser::{
    MessageHandler, MessageParser, MimeHandler, ObsoleteStructureType, ParseResult,
};

/// Logs the events, and counts the mailboxes and ids.
#[derive(Default)]
struct Log {
    events: Vec<String>,
    mailboxes: usize,
    ids: usize,
    last: Option<(String, String)>,
    text: String,
}

impl MimeHandler for Log {
    fn malformed_header(&mut self, name: &str, reason: &str) -> ParseResult<()> {
        self.events.push(format!("malformed {name}: {reason}"));
        Ok(())
    }
    // The text after a failure arrives in pieces of no particular size
    fn header_content(&mut self, text: &str) -> ParseResult<()> {
        self.text.push_str(text);
        Ok(())
    }
    fn end_header(&mut self) -> ParseResult<()> {
        let text = std::mem::take(&mut self.text);
        self.events.push(format!("text {text:?}"));
        Ok(())
    }
}

impl MessageHandler for Log {
    fn start_address_header(&mut self, name: &str) -> ParseResult<()> {
        self.events.push(format!("start {name}"));
        Ok(())
    }
    fn mailbox(&mut self, d: Option<&str>, l: &str, dom: &str) -> ParseResult<()> {
        self.mailboxes += 1;
        self.last = Some((l.to_string(), dom.to_string()));
        self.events.push(format!("mailbox {}|{l}|{dom}", d.unwrap_or("-")));
        Ok(())
    }
    fn start_group(&mut self, name: &str) -> ParseResult<()> {
        self.events.push(format!("group {name}"));
        Ok(())
    }
    fn end_group(&mut self) -> ParseResult<()> {
        self.events.push("end group".into());
        Ok(())
    }
    fn end_address_header(&mut self) -> ParseResult<()> {
        self.events.push("end".into());
        Ok(())
    }
    fn start_message_id_header(&mut self, name: &str) -> ParseResult<()> {
        self.events.push(format!("start {name}"));
        Ok(())
    }
    fn message_id(&mut self, l: &str, d: &str) -> ParseResult<()> {
        self.ids += 1;
        self.last = Some((l.to_string(), d.to_string()));
        Ok(())
    }
    fn end_message_id_header(&mut self) -> ParseResult<()> {
        self.events.push("end".into());
        Ok(())
    }
    fn obsolete_structure(&mut self, kind: ObsoleteStructureType) -> ParseResult<()> {
        self.events.push(format!("obsolete {kind:?}"));
        Ok(())
    }
}

fn run(message: &str, configure: impl FnOnce(&mut MessageParser<&mut Log>)) -> Log {
    let mut log = Log::default();
    {
        let mut parser = MessageParser::new(&mut log);
        configure(&mut parser);
        let mut ring = LoopBuf::with_capacity(message.len() + 64);
        ring.extend_from_slice(message.as_bytes());
        parser.receive(&mut ring).unwrap();
        parser.close(&mut ring).unwrap();
    }
    log
}

/// Feeds `message` through a ring of `capacity` bytes, `step` at a time.
fn run_small_ring(message: &str, capacity: usize, step: usize, limit: Option<usize>) -> Log {
    let mut log = Log::default();
    {
        let mut parser = MessageParser::new(&mut log);
        parser.limits_mut().max_element_length = limit;
        let mut ring = LoopBuf::with_capacity(capacity);
        for chunk in message.as_bytes().chunks(step) {
            ring.extend_from_slice(chunk);
            parser.receive(&mut ring).unwrap();
        }
        parser.close(&mut ring).unwrap();
    }
    log
}

/// `count` addresses folded onto lines well under 998 bytes.
fn many_addresses(count: usize) -> String {
    let mut s = String::from("To: ");
    let mut line = 4;
    for i in 0..count {
        let a = format!("User {i} <user{i}@example.org>, ");
        if line + a.len() > 900 {
            s.push_str("\r\n ");
            line = 1;
        }
        line += a.len();
        s.push_str(&a);
    }
    s.push_str("last@example.org\r\n\r\nbody");
    s
}

#[test]
fn a_header_of_thousands_of_addresses_passes_through_a_small_ring_an_address_at_a_time() {
    // a header of ~200 KB through a ring of 2 KB, with a limit of 100 bytes
    // on what is held: nothing can have been held but one address
    let message = many_addresses(8000);
    assert!(message.len() > 200_000);
    let log = run_small_ring(&message, 2048, 700, Some(100));
    assert_eq!(log.mailboxes, 8001);
    assert_eq!(log.last, Some(("last".to_string(), "example.org".to_string())));
    assert!(log.events.last().unwrap() == "end");
    assert!(!log.events.iter().any(|e| e.starts_with("malformed")));
}

#[test]
fn a_references_header_of_thousands_of_ids_streams_too() {
    let mut message = String::from("References:");
    let mut line = 11;
    for i in 0..6000 {
        let id = format!(" <id{i}@example.org>");
        if line + id.len() > 900 {
            message.push_str("\r\n");
            line = 0;
        }
        line += id.len();
        message.push_str(&id);
    }
    message.push_str("\r\n\r\nbody");
    let log = run_small_ring(&message, 2048, 333, Some(100));
    assert_eq!(log.ids, 6000);
    assert_eq!(log.last, Some(("id5999".to_string(), "example.org".to_string())));
}

#[test]
fn the_events_are_the_same_whatever_the_chunking() {
    let message = many_addresses(60);
    let whole = run_small_ring(&message, message.len() + 64, message.len(), None).events;
    for (capacity, step) in [(2048, 1), (2048, 7), (3000, 100), (1500, 400)] {
        assert_eq!(run_small_ring(&message, capacity, step, None).events, whole);
    }
}

#[test]
fn a_group_is_a_start_its_members_and_an_end() {
    let log = run("To: Team: a@x.org, B <b@y.org>;, c@z.org, undisclosed-recipients:;\r\n\r\n", |_| {});
    assert_eq!(
        log.events,
        vec![
            "start To",
            "group Team",
            "mailbox -|a|x.org",
            "mailbox B|b|y.org",
            "end group",
            "mailbox -|c|z.org",
            "group undisclosed-recipients",
            "end group",
            "end",
        ]
    );
}

#[test]
fn what_was_read_before_a_bad_element_is_delivered_and_the_rest_is_text() {
    let log = run("To: a@x.org, Bob <b@y.org>, this is no address, d@w.org\r\n\r\n", |_| {});
    assert_eq!(
        log.events,
        vec![
            "start To".to_string(),
            "mailbox -|a|x.org".to_string(),
            "mailbox Bob|b|y.org".to_string(),
            "malformed To: not a mailbox".to_string(),
            "text \"this is no address, d@w.org\"".to_string(),
        ]
    );
}

#[test]
fn a_bad_element_inside_a_group_ends_the_group_with_the_header() {
    let log = run("To: Team: a@x.org, nonsense, b@y.org;\r\n\r\n", |_| {});
    assert_eq!(log.events[..3], ["start To", "group Team", "mailbox -|a|x.org"]);
    assert!(log.events[3].starts_with("malformed To"));
    // no `end group` and no `end`: the failure ended them
    assert!(!log.events.iter().any(|e| e == "end group" || e == "end"));
}

#[test]
fn the_element_limit_reaches_the_rfc5322_layer() {
    let long = "x".repeat(60);
    let message = format!("To: a@x.org, {long} <b@y.org>\r\n\r\n");
    let log = run(&message, |p| p.limits_mut().max_element_length = Some(40));
    assert!(log.events.iter().any(|e| e.contains("too long")), "{:?}", log.events);
    assert_eq!(log.mailboxes, 1);
    // within the limit it is fine
    let log = run(&message, |p| p.limits_mut().max_element_length = Some(200));
    assert_eq!(log.mailboxes, 2);
}

#[test]
fn smtp_utf8_reads_utf8_names_as_the_grammar_and_otherwise_says_it_is_obsolete() {
    let message = "To: Jos\u{e9} <jose@example.org>\r\n\r\n";
    let log = run(message, |p| p.set_smtp_utf8(true));
    assert_eq!(log.events, vec!["start To", "mailbox Jos\u{e9}|jose|example.org", "end"]);
    let log = run(message, |_| {});
    assert_eq!(
        log.events,
        vec![
            "start To".to_string(),
            "obsolete ObsoleteAddressSyntax".to_string(),
            "mailbox Jos\u{e9}|jose|example.org".to_string(),
            "end".to_string(),
        ]
    );
}

#[test]
fn an_encoded_word_cannot_change_the_structure() {
    // decoded, this display name would contain a comma and angle brackets
    let log = run("To: =?utf-8?q?a=2C_b_=3Cc=40d=3E?= <e@f.org>, g@h.org\r\n\r\n", |_| {});
    assert_eq!(
        log.events,
        vec!["start To", "mailbox a, b <c@d>|e|f.org", "mailbox -|g|h.org", "end"]
    );
}
