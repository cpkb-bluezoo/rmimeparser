//! What the RFC 5322 layer makes of the headers it parses (addresses,
//! message-ids, dates) and of the small MIME headers, through the whole
//! parser.

use loopbuf::LoopBuf;
use rmimeparser::{
    Address, AddressListCollector, ContentId, EmailAddress, MessageHandler, MessageIdListCollector,
    MessageParser, MimeHandler, MimeVersion, ObsoleteStructureType, OffsetDateTime, ParseResult,
};

/// `(header name, value bytes, expected events)`
const CASES: &[(&str, &[u8], &str)] = &[
    ("To", b"a@example.com", r##"addresses [-|a|example.com]"##),
    ("To", b"Alice <alice@example.com>", r##"addresses [Alice|alice|example.com]"##),
    ("To", b"\"Alice B\" <alice@example.com>", r##"addresses [Alice B|alice|example.com]"##),
    ("To", b"Alice <alice@example.com>, Bob <bob@example.com>", r##"addresses [Alice|alice|example.com, Bob|bob|example.com]"##),
    ("To", b"alice@example.com, bob@example.com", r##"addresses [-|alice|example.com, -|bob|example.com]"##),
    ("To", b"=?UTF-8?Q?Jos=C3=A9?= <jose@example.com>", r##"addresses [José|jose|example.com]"##),
    ("To", b"\"=?UTF-8?B?Sm9zw6k=?=\" <jose@example.com>", r##"addresses [José|jose|example.com]"##),
    // differs from before: a comment is not part of the display name
    ("To", b"Alice (comment) <alice@example.com>", r##"addresses [Alice|alice|example.com]"##),
    // differs from before: a comment is not part of the domain
    ("To", b"alice@example.com (Alice)", r##"addresses [-|alice|example.com]"##),
    // differs from before: a group is a group, not two bad mailboxes
    ("To", b"Team: a@x.org, b@y.org;", r##"addresses [group Team{-|a|x.org, -|b|y.org}]"##),
    // differs from before: a group is a group, not two bad mailboxes
    ("To", b"Team: a@x.org;, c@z.org", r##"addresses [group Team{-|a|x.org}, -|c|z.org]"##),
    // differs from before: a group with no members is valid
    ("To", b"undisclosed-recipients:;", r##"addresses [group undisclosed-recipients{}]"##),
    ("To", b"\"Smith, John\" <js@example.com>", r##"addresses [Smith, John|js|example.com]"##),
    // differs from before: an element that cannot be read is reported, with the text from there on, instead of dropping `Smith`
    ("To", b"Smith, John <js@example.com>", r##"malformed (not a mailbox) "Smith, John <js@example.com>""##),
    // differs from before: an empty element is obsolete syntax, and is said to be
    ("To", b"a@x.org,,b@y.org", r##"obsolete ObsoleteAddressSyntax; addresses [-|a|x.org, -|b|y.org]"##),
    // differs from before: an empty element is obsolete syntax, and is said to be
    ("To", b"a@x.org, , b@y.org,", r##"obsolete ObsoleteAddressSyntax; addresses [-|a|x.org, -|b|y.org]"##),
    ("To", b"<alice@example.com>", r##"addresses [-|alice|example.com]"##),
    // differs from before: an unclosed angle bracket is reported, not read as a mailbox
    ("To", b"Alice <alice@example.com", r##"malformed (a quoted string, comment or angle bracket is not closed) "Alice <alice@example.com""##),
    // differs from before: two words are not a local part
    ("To", b"Alice alice@example.com", r##"malformed (not a mailbox) "Alice alice@example.com""##),
    // differs from before: reported through malformed_header
    ("To", b"not an address", r##"malformed (not a mailbox) "not an address""##),
    // differs from before: a source route is read
    ("To", b"<@a.com,@b.com:alice@example.com>", r##"obsolete ObsoleteAddressSyntax; addresses [-|alice|example.com]"##),
    ("To", b"\"quoted local\"@example.com", r##"addresses [-|"quoted local"|example.com]"##),
    ("To", b"alice@[192.0.2.1]", r##"addresses [-|alice|[192.0.2.1]]"##),
    ("To", b"alice@example", r##"addresses [-|alice|example]"##),
    // differs from before: an element that cannot be read is reported, not the end of the list silently
    ("To", b"x@y.org, garbage, z@w.org", r##"malformed (not a mailbox) "garbage, z@w.org""##),
    // differs from before: an element that cannot be read is reported, not dropped silently
    ("To", b"Alice <alice@example.com>, garbage", r##"malformed (not a mailbox) "garbage""##),
    // differs from before: an element that cannot be read is reported, not skipped silently
    ("To", b"garbage, Alice <alice@example.com>", r##"malformed (not a mailbox) "garbage, Alice <alice@example.com>""##),
    // differs from before: an empty address list is an empty list; an empty date or id is malformed
    ("To", b"", r##"addresses []"##),
    // differs from before: an empty address list is an empty list
    ("To", b"   ", r##"addresses []"##),
    ("To", b"a@b.c,d@e.f", r##"addresses [-|a|b.c, -|d|e.f]"##),
    ("To", b"A <a@b.c> (c1) , (c2) B <b@c.d>", r##"addresses [A|a|b.c, B|b|c.d]"##),
    // differs from before: raw 8-bit text is read, and said to be outside the grammar
    ("To", b"Jos\xe9 <jose@example.com>", r##"obsolete ObsoleteAddressSyntax; addresses [José|jose|example.com]"##),
    // differs from before: raw UTF-8 is read as UTF-8, and said to be outside the grammar
    ("To", b"Jos\xc3\xa9 <jose@example.com>", r##"obsolete ObsoleteAddressSyntax; addresses [José|jose|example.com]"##),
    ("From", b"Alice <alice@example.com>", r##"addresses [Alice|alice|example.com]"##),
    ("Message-ID", b"<abc@example.com>", r##"ids [<abc@example.com>]"##),
    ("References", b"<a@b.org> <c@d.org>", r##"ids [<a@b.org>, <c@d.org>]"##),
    ("References", b"<a@b.org>, <c@d.org>", r##"ids [<a@b.org>, <c@d.org>]"##),
    ("References", b"<a@b.org> (comment) <c@d.org>", r##"ids [<a@b.org>, <c@d.org>]"##),
    ("References", b"a@b.org", r##"obsolete ObsoleteMessageIdSyntax; ids [<a@b.org>]"##),
    // differs from before: reported through malformed_header, where it was `unexpected_header` or nothing
    ("References", b"<abc>", r##"malformed (not a message-id) "<abc>""##),
    // differs from before: reported through malformed_header, where it was `unexpected_header` or nothing
    ("References", b"<a@b.org", r##"malformed (a message-id is not closed) "<a@b.org""##),
    // differs from before: reported through malformed_header, where it was `unexpected_header` or nothing
    ("References", b"<a b@c.org>", r##"malformed (not a message-id) "<a b@c.org>""##),
    // differs from before: reported through malformed_header, where it was `unexpected_header` or nothing
    ("References", b"garbage <a@b.org>", r##"malformed (not a message-id) "garbage <a@b.org>""##),
    // differs from before: reported through malformed_header, where it was `unexpected_header` or nothing
    ("References", b"<a@b.org> garbage", r##"malformed (not a message-id) "garbage""##),
    // differs from before: an empty address list is an empty list; an empty date or id is malformed
    ("References", b"", r##"ids []"##),
    // differs from before: reported through malformed_header, where it was `unexpected_header` or nothing
    ("References", b"<\"q a\"@example.com>", r##"malformed (not a message-id) "<\"q a\"@example.com>""##),
    ("References", b"<a@[1.2.3.4]>", r##"ids [<a@[1.2.3.4]>]"##),
    ("Date", b"Tue, 6 Oct 2026 10:00:00 +0000", r##"date Tue, 6 Oct 2026 10:00:00 +0000"##),
    ("Date", b"Tue, 6 Oct 2026 10:00:00 +0000 (UTC)", r##"date Tue, 6 Oct 2026 10:00:00 +0000"##),
    ("Date", b"6 Oct 2026 10:00:00 GMT", r##"obsolete ObsoleteDateTimeSyntax; date Tue, 6 Oct 2026 10:00:00 +0000"##),
    ("Date", b"Tue, 06 Oct 26 10:00 EST", r##"obsolete ObsoleteDateTimeSyntax; date Tue, 6 Oct 2026 10:00:00 -0500"##),
    ("Date", b"Tue, 6 Oct 2026 10:00:00 -0500", r##"date Tue, 6 Oct 2026 10:00:00 -0500"##),
    // differs from before: reported through malformed_header, where it was `unexpected_header` or nothing
    ("Date", b"garbage", r##"malformed (not a date and time) "garbage""##),
    // differs from before: an empty address list is an empty list; an empty date or id is malformed
    ("Date", b"", r##"malformed (not a date and time) """##),
    // differs from before: reported through malformed_header, where it was `unexpected_header` or nothing
    ("Date", b"Tue, 6 Oct 2026 25:00:00 +0000", r##"malformed (not a date and time) "Tue, 6 Oct 2026 25:00:00 +0000""##),
    ("Content-Transfer-Encoding", b"base64", r##"cte "base64""##),
    ("Content-Transfer-Encoding", b" Quoted-Printable ", r##"cte "Quoted-Printable""##),
    ("Content-Transfer-Encoding", b"x-foo", r##"cte "x-foo""##),
    ("Content-Transfer-Encoding", b"7bit", r##"cte "7bit""##),
    // differs from before: reported through malformed_header, where it was `unexpected_header` or nothing
    ("Content-Transfer-Encoding", b"bad value", r##"malformed (not a known Content-Transfer-Encoding) "bad value""##),
    ("Content-Transfer-Encoding", b"8BIT", r##"cte "8BIT""##),
    ("Content-ID", b"<a@b.org>", r##"cid <a@b.org>"##),
    // differs from before: reported through malformed_header, where it was `unexpected_header` or nothing
    ("Content-ID", b"<a@b.org> <c@d.org>", r##"malformed (a Content-ID is one <local@domain> message-id) "<a@b.org> <c@d.org>""##),
    // differs from before: reported through malformed_header, where it was `unexpected_header` or nothing
    ("Content-ID", b"a@b.org", r##"malformed (a Content-ID is one <local@domain> message-id) "a@b.org""##),
    // differs from before: an empty address list is an empty list; an empty date or id is malformed
    ("Content-ID", b"", r##"malformed (a Content-ID is one <local@domain> message-id) """##),
    ("MIME-Version", b"1.0", r##"mv 1.0"##),
    ("MIME-Version", b" 1.0 ", r##"mv 1.0"##),
    // differs from before: reported through malformed_header, where it was `unexpected_header` or nothing
    ("MIME-Version", b"1.0 (Generated by X)", r##"mv 1.0"##),
    // differs from before: reported through malformed_header, where it was `unexpected_header` or nothing
    ("MIME-Version", b"2.0", r##"malformed (not a MIME version) "2.0""##),
    // differs from before: reported through malformed_header, where it was `unexpected_header` or nothing
    ("MIME-Version", b"abc", r##"malformed (not a MIME version) "abc""##),
];

fn mailbox(a: &EmailAddress) -> String {
    format!("{}|{}|{}", a.display_name().unwrap_or("-"), a.local_part(), a.domain())
}

fn address(a: &Address) -> String {
    match a {
        Address::Mailbox(m) => mailbox(m),
        Address::Group(g) => {
            let members: Vec<String> = g.members().iter().map(mailbox).collect();
            format!("group {}{{{}}}", g.group_name(), members.join(", "))
        }
    }
}

#[derive(Default)]
struct Render {
    out: Vec<String>,
    addresses: AddressListCollector,
    ids: MessageIdListCollector,
    /// The text after a `malformed_header`, while it is arriving.
    malformed: Option<(String, String)>,
}

impl MimeHandler for Render {
    fn content_transfer_encoding(&mut self, e: &str) -> ParseResult<()> {
        self.out.push(format!("cte {e:?}"));
        Ok(())
    }
    fn content_id(&mut self, id: &ContentId) -> ParseResult<()> {
        self.out.push(format!("cid {}", id));
        Ok(())
    }
    fn mime_version(&mut self, v: MimeVersion) -> ParseResult<()> {
        self.out.push(format!("mv {v}"));
        Ok(())
    }
    fn malformed_header(&mut self, _: &str, reason: &str) -> ParseResult<()> {
        self.malformed = Some((reason.to_string(), String::new()));
        Ok(())
    }
    fn header_content(&mut self, text: &str) -> ParseResult<()> {
        if let Some((_, t)) = self.malformed.as_mut() {
            t.push_str(text);
        }
        Ok(())
    }
    fn end_header(&mut self) -> ParseResult<()> {
        if let Some((reason, text)) = self.malformed.take() {
            self.out.push(format!("malformed ({reason}) {text:?}"));
        }
        Ok(())
    }
}

impl MessageHandler for Render {
    fn start_address_header(&mut self, _: &str) -> ParseResult<()> {
        self.addresses.clear();
        Ok(())
    }
    fn mailbox(&mut self, d: Option<&str>, l: &str, dom: &str) -> ParseResult<()> {
        self.addresses.mailbox(d, l, dom);
        Ok(())
    }
    fn start_group(&mut self, name: &str) -> ParseResult<()> {
        self.addresses.start_group(name);
        Ok(())
    }
    fn end_group(&mut self) -> ParseResult<()> {
        self.addresses.end_group();
        Ok(())
    }
    fn end_address_header(&mut self) -> ParseResult<()> {
        let list: Vec<String> = self.addresses.take().iter().map(address).collect();
        self.out.push(format!("addresses [{}]", list.join(", ")));
        Ok(())
    }
    fn start_message_id_header(&mut self, _: &str) -> ParseResult<()> {
        self.ids.clear();
        Ok(())
    }
    fn message_id(&mut self, l: &str, d: &str) -> ParseResult<()> {
        self.ids.message_id(l, d);
        Ok(())
    }
    fn end_message_id_header(&mut self) -> ParseResult<()> {
        let list: Vec<String> = self.ids.take().iter().map(|i| i.to_string()).collect();
        self.out.push(format!("ids [{}]", list.join(", ")));
        Ok(())
    }
    fn date_header(&mut self, _: &str, d: OffsetDateTime) -> ParseResult<()> {
        self.out.push(format!("date {d}"));
        Ok(())
    }
    fn obsolete_structure(&mut self, kind: ObsoleteStructureType) -> ParseResult<()> {
        self.out.push(format!("obsolete {kind:?}"));
        Ok(())
    }
}

fn render(name: &str, value: &[u8]) -> String {
    let mut message = format!("{name}: ").into_bytes();
    message.extend_from_slice(value);
    message.extend_from_slice(b"\r\n\r\n");
    let mut handler = Render::default();
    {
        let mut parser = MessageParser::new(&mut handler);
        let mut ring = LoopBuf::with_capacity(message.len() + 64);
        ring.extend_from_slice(&message);
        parser.receive(&mut ring).unwrap();
        parser.close(&mut ring).unwrap();
    }
    handler.out.join("; ")
}


#[test]
fn headers_parse_as_recorded() {
    for (name, value, expected) in CASES {
        assert_eq!(&render(name, value), expected, "{name}: {:?}", String::from_utf8_lossy(value));
    }
}

/// Wherever the input is cut, the events are the same.
#[test]
fn headers_are_the_same_wherever_the_input_is_cut() {
    for (name, value, _) in CASES {
        let mut message = format!("{name}: ").into_bytes();
        message.extend_from_slice(value);
        message.extend_from_slice(b"\r\n\r\n");
        let whole = render_chunks(&message, &[]);
        for cut in 1..message.len() {
            assert_eq!(
                render_chunks(&message, &[cut]),
                whole,
                "{name}: {:?} cut at {cut}",
                String::from_utf8_lossy(value)
            );
        }
        let ones: Vec<usize> = vec![1; message.len()];
        assert_eq!(render_chunks(&message, &ones), whole, "{name}: {:?} byte by byte", String::from_utf8_lossy(value));
    }
}

fn render_chunks(message: &[u8], sizes: &[usize]) -> String {
    let mut handler = Render::default();
    {
        let mut parser = MessageParser::new(&mut handler);
        let mut ring = LoopBuf::with_capacity(message.len() + 64);
        let mut at = 0;
        for &n in sizes {
            let n = n.min(message.len() - at);
            ring.extend_from_slice(&message[at..at + n]);
            at += n;
            parser.receive(&mut ring).unwrap();
        }
        ring.extend_from_slice(&message[at..]);
        parser.receive(&mut ring).unwrap();
        parser.close(&mut ring).unwrap();
    }
    handler.out.join("; ")
}
