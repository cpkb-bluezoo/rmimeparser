use rmimeparser::{
    Address, EmailAddressParser, MimeHandler, MimeParser, ParseResult,
};

#[derive(Default)]
struct Collect {
    bodies: Vec<Vec<u8>>,
    current: Vec<u8>,
    entities: usize,
}

impl MimeHandler for Collect {
    fn start_entity(&mut self, _b: Option<&str>) -> ParseResult<()> {
        self.entities += 1;
        self.current.clear();
        Ok(())
    }
    fn body_content(&mut self, data: &[u8]) -> ParseResult<()> {
        self.current.extend_from_slice(data);
        Ok(())
    }
    fn end_entity(&mut self, _b: Option<&str>) -> ParseResult<()> {
        if !self.current.is_empty() {
            self.bodies.push(std::mem::take(&mut self.current));
        }
        Ok(())
    }
}

fn finish_in_chunks(raw: &[u8], step: usize) -> Collect {
    let mut h = Collect::default();
    {
        let mut p = MimeParser::new(&mut h);
        let mut pending: Vec<u8> = Vec::new();
        let mut offset = 0;
        while offset < raw.len() {
            let end = (offset + step).min(raw.len());
            pending.extend_from_slice(&raw[offset..end]);
            offset = end;
            let mut slice = pending.as_slice();
            if offset == raw.len() {
                p.finish(&mut slice).unwrap();
            } else {
                p.receive(&mut slice).unwrap();
            }
            let left = slice.len();
            let consumed = pending.len() - left;
            pending.drain(..consumed);
        }
        if raw.is_empty() {
            let mut empty: &[u8] = &[];
            p.finish(&mut empty).unwrap();
        }
    }
    h
}

/// A body whose last line has no terminator is still delivered by `finish`.
#[test]
fn final_line_without_terminator_is_body_content() {
    let raw = b"Content-Type: text/plain\r\n\r\nHello, world.";
    for step in [1usize, 7, raw.len()] {
        let h = finish_in_chunks(raw, step);
        assert_eq!(h.bodies, vec![b"Hello, world.".to_vec()], "step {step}");
    }
}

/// A closing boundary without a trailing CRLF ends the multipart cleanly.
#[test]
fn closing_boundary_without_crlf_is_accepted() {
    let raw = b"Content-Type: multipart/alternative; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nPlain.\r\n--x\r\nContent-Type: text/html\r\n\r\n<b>HTML</b>\r\n--x--";
    for step in [1usize, 13, raw.len()] {
        let h = finish_in_chunks(raw, step);
        assert_eq!(h.bodies, vec![b"Plain.".to_vec(), b"<b>HTML</b>".to_vec()], "step {step}");
        assert_eq!(h.entities, 3);
    }
}

/// A base64 body ending without a terminator decodes completely.
#[test]
fn final_base64_quantum_without_terminator_is_decoded() {
    let raw = b"Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8sIHdvcmxk";
    let h = finish_in_chunks(raw, 5);
    assert_eq!(h.bodies, vec![b"Hello, world".to_vec()]);
}

/// A plain address followed by a display-name mailbox parses as two
/// addresses; a `<` later in the list must not be read as this address's.
#[test]
fn address_list_with_display_name_after_bare_address() {
    let list = EmailAddressParser::parse_email_address_list("a@x.org, Bob <b@x.org>").expect("two addresses");
    let addrs: Vec<String> = list.iter().filter_map(Address::as_mailbox).map(|m| m.address()).collect();
    assert_eq!(addrs, vec!["a@x.org", "b@x.org"]);
    let list = EmailAddressParser::parse_email_address_list("Team: a@x.org, Bob <b@x.org>;, c@y.org").expect("group then address");
    assert_eq!(list.len(), 2);
    assert!(matches!(list[0], Address::Group(ref g) if g.members().len() == 2));
    assert_eq!(list[1].as_mailbox().unwrap().address(), "c@y.org");
}
