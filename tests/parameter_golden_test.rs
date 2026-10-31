//! What the parameter grammar makes of a wide set of inputs, written down
//! from the buffered parsers before the streaming grammar replaced them.
//! Where the streaming grammar deliberately differs, the entry says why.

use rmimeparser::{ContentDispositionParser, ContentTypeParser};

/// `(input bytes, expected rendering)`; `None` is a header that does not parse.
const CONTENT_TYPES: &[(&[u8], &str)] = &[
    (b"text/plain", r##"text/plain"##),
    (
        b"text/plain; charset=utf-8",
        r##"text/plain | charset="utf-8""##,
    ),
    (
        b"text/plain;charset=utf-8;format=flowed",
        r##"text/plain | charset="utf-8" | format="flowed""##,
    ),
    (
        b"  text/plain  ;  charset = utf-8  ",
        r##"text/plain | charset="utf-8""##,
    ),
    (
        b"TEXT/Plain; CHARSET=UTF-8",
        r##"TEXT/Plain | CHARSET="UTF-8""##,
    ),
    (
        b"text/plain; name=\"a b.txt\"",
        r##"text/plain | name="a b.txt""##,
    ),
    (
        b"text/plain; name=\"a\\\"b\\\\c\"",
        r##"text/plain | name="a\"b\\c""##,
    ),
    (
        b"text/plain; name= \"spaced quote\"",
        r##"text/plain | name="spaced quote""##,
    ),
    // differs from the buffered parser: an unterminated quoted value is kept, as far as it goes
    (
        b"text/plain; name=\"unterminated",
        r##"text/plain | name="unterminated""##,
    ),
    (
        b"text/plain; =noname; charset=x",
        r##"text/plain | charset="x""##,
    ),
    // differs from the buffered parser: a parameter with no value is skipped, not the rest of the list
    (
        b"text/plain; novalue; charset=x",
        r##"text/plain | charset="x""##,
    ),
    (
        b"text/plain; bad name=1; charset=x",
        r##"text/plain | charset="x""##,
    ),
    (
        b"text/plain; charset=x; charset=y",
        r##"text/plain | charset="x""##,
    ),
    (b"text/plain;;charset=x;", r##"text/plain | charset="x""##),
    (
        b"text/plain; name=\"=?UTF-8?B?dGVzdC50eHQ=?=\"",
        r##"text/plain | name="test.txt""##,
    ),
    (
        b"text/plain; name==?UTF-8?Q?a_b?=",
        r##"text/plain | name="a b""##,
    ),
    (
        b"text/plain; filename*=UTF-8''na%C3%AFve%20file.txt",
        r##"text/plain | filename="naïve file.txt""##,
    ),
    (
        b"text/plain; filename*=iso-8859-1'en'caf%E9",
        r##"text/plain | filename="café""##,
    ),
    // differs from the buffered parser: plain continuations are joined
    (
        b"text/plain; filename*0=\"abc\"; filename*1=\"def\"",
        r##"text/plain | filename="abcdef""##,
    ),
    // differs from the buffered parser: extended continuations are decoded and joined
    (
        b"text/plain; filename*0*=UTF-8''a%20b; filename*1*=%20c; filename*2=d",
        r##"text/plain | filename="a b cd""##,
    ),
    // differs from the buffered parser: a segment out of order is dropped
    (
        b"text/plain; filename*1=\"def\"; filename*0=\"abc\"",
        r##"text/plain | filename="abc""##,
    ),
    // differs from the buffered parser: an extended continuation is decoded, and replaces the plain parameter
    (
        b"text/plain; filename*0*=UTF-8''ab; filename=\"plain.txt\"",
        r##"text/plain | filename="ab""##,
    ),
    (
        b"text/plain; filename=\"plain.txt\"; filename*=UTF-8''ext.txt",
        r##"text/plain | filename="ext.txt""##,
    ),
    (b"text/plain; title*=bad", r##"text/plain | title="bad""##),
    (b"text/plain; title*=UTF-8''", r##"text/plain | title="""##),
    (
        b"multipart/mixed; boundary=\"b\"",
        r##"multipart/mixed | boundary="b""##,
    ),
    (
        b"multipart/mixed; boundary=b; charset=x",
        r##"multipart/mixed | boundary="b" | charset="x""##,
    ),
    (b"text", r##"None"##),
    (b"text/", r##"None"##),
    (b"/plain", r##"None"##),
    (b"te xt/plain", r##"None"##),
    (b"text/pl ain", r##"None"##),
    (b"text/plain junk", r##"None"##),
    (b"text/plain (comment)", r##"None"##),
    // differs from the buffered parser: raw UTF-8 in a value is read as UTF-8
    (
        b"text/plain; name=\"caf\xc3\xa9\"",
        r##"text/plain | name="café""##,
    ),
    (
        b"text/plain; name=\"caf\xe9\"",
        r##"text/plain | name="café""##,
    ),
    // differs from the buffered parser: an unquoted value is kept whole, spaces and all
    (b"text/plain; name=a b c", r##"text/plain | name="a b c""##),
    // differs from the buffered parser: text after the closing quote is ignored, and the list goes on
    (
        b"text/plain; name=\"x\"junk; k=v",
        r##"text/plain | name="x" | k="v""##,
    ),
    (
        b"text/plain; a=1;b=2;c=3;d=4",
        r##"text/plain | a="1" | b="2" | c="3" | d="4""##,
    ),
    (b"text/plain; name=\"\"", r##"text/plain | name="""##),
    (b"text/plain; name=", r##"text/plain | name="""##),
    (
        b"text/plain\t;\tcharset=utf-8",
        r##"text/plain | charset="utf-8""##,
    ),
    (b"a/b;c=d", r##"a/b | c="d""##),
    (b"a/", r##"None"##),
    (b"", r##"None"##),
    (
        b"text/plain; name=\"  padded  \"",
        r##"text/plain | name="padded""##,
    ),
    (
        b"text/plain; name=  padded  ",
        r##"text/plain | name="padded""##,
    ),
    // differs from the buffered parser: a character split across two segments is decoded whole
    (
        b"text/plain; n*0*=utf-8''%C3; n*1*=%A9",
        r##"text/plain | n="é""##,
    ),
    (
        b"text/plain; n*0=\"a\"; n*2=\"c\"",
        r##"text/plain | n="a""##,
    ),
];

const DISPOSITIONS: &[(&[u8], &str)] = &[
    (b"attachment", r##"attachment"##),
    (b"inline", r##"inline"##),
    (
        b"form-data; name=\"f\"; filename=\"x.txt\"",
        r##"form-data | name="f" | filename="x.txt""##,
    ),
    (
        b"attachment; filename*=UTF-8''%E6%97%A5%E6%9C%AC%E8%AA%9E.txt",
        r##"attachment | filename="日本語.txt""##,
    ),
    (b"attachment;", r##"attachment"##),
    (
        b"Attachment ; FileName = \"T.TXT\"",
        r##"Attachment | FileName="T.TXT""##,
    ),
    (b"bad type; x=1", r##"None"##),
    (
        b"attachment; size=123; creation-date=\"Tue, 6 Oct 2026 10:00:00 +0000\"",
        r##"attachment | size="123" | creation-date="Tue, 6 Oct 2026 10:00:00 +0000""##,
    ),
    (
        b"attachment; filename=\"=?UTF-8?B?dGVzdC50eHQ=?=\"",
        r##"attachment | filename="test.txt""##,
    ),
    (
        b"attachment; filename=C:\\dir\\x.pdf",
        r##"attachment | filename="C:\\dir\\x.pdf""##,
    ),
    (b"", r##"None"##),
    (b"; filename=x", r##"None"##),
    // differs from the buffered parser: plain continuations are joined, white space inside a segment kept
    (
        b"attachment; filename*0=\"my \"; filename*1=\"file.txt\"",
        r##"attachment | filename="my file.txt""##,
    ),
];

fn render_ct(input: &[u8]) -> String {
    use rmimeparser::{ByteCursor, HeaderCharset};
    let mut cursor = ByteCursor::new(input);
    match ContentTypeParser::parse(&mut cursor, HeaderCharset::Iso88591) {
        None => "None".to_string(),
        Some(ct) => {
            let mut s = format!("{}/{}", ct.primary_type(), ct.sub_type());
            for p in ct.parameters().unwrap_or(&[]) {
                s.push_str(&format!(" | {}={:?}", p.name(), p.value()));
            }
            s
        }
    }
}

fn render_cd(input: &[u8]) -> String {
    use rmimeparser::{ByteCursor, HeaderCharset};
    let mut cursor = ByteCursor::new(input);
    match ContentDispositionParser::parse(&mut cursor, HeaderCharset::Iso88591) {
        None => "None".to_string(),
        Some(cd) => {
            let mut s = cd.disposition_type().to_string();
            for p in cd.parameters().unwrap_or(&[]) {
                s.push_str(&format!(" | {}={:?}", p.name(), p.value()));
            }
            s
        }
    }
}

#[test]
fn content_types_parse_as_recorded() {
    for (input, expected) in CONTENT_TYPES {
        assert_eq!(
            &render_ct(input),
            expected,
            "{:?}",
            String::from_utf8_lossy(input)
        );
    }
}

#[test]
fn dispositions_parse_as_recorded() {
    for (input, expected) in DISPOSITIONS {
        assert_eq!(
            &render_cd(input),
            expected,
            "{:?}",
            String::from_utf8_lossy(input)
        );
    }
}

// ---- the chunking of the input never changes the result ----

mod chunking {
    use super::{CONTENT_TYPES, DISPOSITIONS};
    use loopbuf::LoopBuf;
    use rmimeparser::{
        ContentDispositionCollector, ContentTypeCollector, MimeHandler, MimeParser, ParseResult,
    };

    #[derive(Default)]
    struct Handler {
        ct: ContentTypeCollector,
        cd: ContentDispositionCollector,
        out: String,
        malformed: bool,
    }

    impl MimeHandler for Handler {
        fn start_content_type(&mut self, p: &str, s: &str) -> ParseResult<()> {
            self.ct.start(p, s);
            Ok(())
        }
        fn end_content_type(&mut self) -> ParseResult<()> {
            let ct = self.ct.finish();
            self.out
                .push_str(&format!("{}/{}", ct.primary_type(), ct.sub_type()));
            for p in ct.parameters().unwrap_or(&[]) {
                self.out
                    .push_str(&format!(" | {}={:?}", p.name(), p.value()));
            }
            Ok(())
        }
        fn start_content_disposition(&mut self, k: &str) -> ParseResult<()> {
            self.cd.start(k);
            Ok(())
        }
        fn end_content_disposition(&mut self) -> ParseResult<()> {
            let cd = self.cd.finish();
            self.out.push_str(cd.disposition_type());
            for p in cd.parameters().unwrap_or(&[]) {
                self.out
                    .push_str(&format!(" | {}={:?}", p.name(), p.value()));
            }
            Ok(())
        }
        fn start_parameter(&mut self, n: &str, l: Option<&str>) -> ParseResult<()> {
            self.ct.start_parameter(n, l);
            self.cd.start_parameter(n, l);
            Ok(())
        }
        fn parameter_content(&mut self, t: &str) -> ParseResult<()> {
            self.ct.parameter_content(t);
            self.cd.parameter_content(t);
            Ok(())
        }
        fn end_parameter(&mut self) -> ParseResult<()> {
            self.ct.end_parameter();
            self.cd.end_parameter();
            Ok(())
        }
        fn malformed_header(&mut self, _: &str, _: &str) -> ParseResult<()> {
            self.malformed = true;
            self.out.push_str("MALFORMED:");
            Ok(())
        }
        fn header_content(&mut self, t: &str) -> ParseResult<()> {
            if self.malformed {
                self.out.push_str(t);
            }
            Ok(())
        }
    }

    fn run(header: &str, value: &[u8], chunks: &[&[u8]]) -> String {
        let mut message = format!("{header}: ").into_bytes();
        message.extend_from_slice(value);
        message.extend_from_slice(b"\r\n\r\n");
        let _ = chunks;
        let mut handler = Handler::default();
        {
            let mut parser = MimeParser::new(&mut handler);
            let mut ring = LoopBuf::with_capacity(4096);
            for chunk in split(&message, chunks) {
                ring.extend_from_slice(chunk);
                parser.receive(&mut ring).unwrap();
            }
            // a multipart header with no body is an unclosed multipart; the header is what counts
            let _ = parser.close(&mut ring);
        }
        handler.out
    }

    /// `message` cut into the pieces whose lengths `cuts` gives (the last
    /// piece takes the rest).
    fn split<'a>(message: &'a [u8], cuts: &[&[u8]]) -> Vec<&'a [u8]> {
        let mut at = 0;
        let mut out = Vec::new();
        for cut in cuts {
            let n = cut.len().min(message.len() - at);
            out.push(&message[at..at + n]);
            at += n;
        }
        out.push(&message[at..]);
        out
    }

    fn check(header: &str, value: &[u8]) {
        let whole = run(header, value, &[]);
        let total = format!("{header}: ").len() + value.len() + 4;
        for cut in 1..total {
            let first = vec![0u8; cut];
            assert_eq!(
                run(header, value, &[&first]),
                whole,
                "{header}: {:?} cut at {cut}",
                String::from_utf8_lossy(value)
            );
        }
        let ones = vec![&[0u8][..]; total];
        assert_eq!(
            run(header, value, &ones),
            whole,
            "{header}: {:?} byte by byte",
            String::from_utf8_lossy(value)
        );
    }

    #[test]
    fn content_types_are_the_same_wherever_the_input_is_cut() {
        for (input, _) in CONTENT_TYPES {
            if !input.is_empty() {
                check("Content-Type", input);
            }
        }
    }

    #[test]
    fn dispositions_are_the_same_wherever_the_input_is_cut() {
        for (input, _) in DISPOSITIONS {
            if !input.is_empty() {
                check("Content-Disposition", input);
            }
        }
    }
}
