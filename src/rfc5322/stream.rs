//! The headers of the RFC 5322 layer (address lists, message-id lists and
//! dates), read as the bytes arrive.
//!
//! A header is never held whole. It is cut into *elements* as it passes (one
//! mailbox, one group member, one message-id), each element is held while it
//! is read and judged, and an event is delivered for it. A `To` with a
//! thousand addresses is a thousand events and one address in memory. An
//! element is limited by [`crate::ParserLimits::max_element_length`]; a date is
//! one element.
//!
//! The bytes arrive raw, unfolded but undecoded. Elements are cut out of them
//! by their quotes, comments and angle brackets before anything is decoded, so
//! that a decoded RFC 2047 word can never change the structure.
//!
//! If an element cannot be read, `malformed_header` is delivered and the rest
//! of the header, from that element on, follows as unstructured text.

use crate::charset::decode_header_element;
use crate::mime::error::ParseResult;
use crate::mime::message_id_parser::parse_msg_id_text;
use crate::rfc2047::HeaderTextDecoder;

use super::email_address_parser::{parse_group_name, parse_mailbox_element, MailboxScratch};
use super::headers::RawKind;
use super::message_date_time::MessageDateTimeFormatter;
use super::message_handler::MessageHandler;
use super::obsolete_parser_utils::parse_obsolete_message_id_text;
use super::obsolete_structure_type::ObsoleteStructureType;

#[derive(Clone, Copy, PartialEq, Eq)]
enum IdState {
    /// Between ids: white space, comments and commas.
    Outside,
    /// In a comment between ids.
    Comment,
    /// In `<...>`.
    Angle,
    /// A word that is not in angle brackets.
    Bare,
}

/// The bytes the address tokenizer has to look at: quotes, comments, angle
/// brackets, the separators, and the escape.
static ADDRESS_SPECIAL: [bool; 256] = {
    let mut table = [false; 256];
    let specials = *b"\"(<>,:;\\";
    let mut i = 0;
    while i < specials.len() {
        table[specials[i] as usize] = true;
        i += 1;
    }
    table
};

pub(crate) struct HeaderStream {
    kind: Option<RawKind>,
    name: String,
    smtp_utf8: bool,
    max_element: usize,
    /// The element being read.
    buf: Vec<u8>,
    quote: bool,
    escaped: bool,
    comment: u32,
    angle: bool,
    in_group: bool,
    /// A group has just ended: a comma after it separates nothing.
    after_group: bool,
    ids: IdState,
    obsolete_flagged: bool,
    /// An element could not be read: the rest is text.
    failed: bool,
    text: HeaderTextDecoder,
    scratch: MailboxScratch,
}

impl HeaderStream {
    pub(crate) fn new() -> Self {
        Self {
            kind: None,
            name: String::new(),
            smtp_utf8: false,
            max_element: usize::MAX,
            buf: Vec::new(),
            quote: false,
            escaped: false,
            comment: 0,
            angle: false,
            in_group: false,
            after_group: false,
            ids: IdState::Outside,
            obsolete_flagged: false,
            failed: false,
            text: HeaderTextDecoder::new(false),
            scratch: MailboxScratch::default(),
        }
    }

    /// Whether a header is being read.
    pub(crate) fn active(&self) -> bool {
        self.kind.is_some()
    }

    /// Starts reading a header of `kind` called `name`.
    pub(crate) fn start<H: MessageHandler>(
        &mut self,
        inner: &mut H,
        kind: RawKind,
        name: &str,
        smtp_utf8: bool,
        max_element: usize,
    ) -> ParseResult<()> {
        self.kind = Some(kind);
        self.name.clear();
        self.name.push_str(name);
        if self.smtp_utf8 != smtp_utf8 {
            self.text = HeaderTextDecoder::new(smtp_utf8);
        }
        self.smtp_utf8 = smtp_utf8;
        self.max_element = max_element;
        self.buf.clear();
        self.quote = false;
        self.escaped = false;
        self.comment = 0;
        self.angle = false;
        self.in_group = false;
        self.after_group = false;
        self.ids = IdState::Outside;
        self.obsolete_flagged = false;
        self.failed = false;
        match kind {
            RawKind::Address => inner.start_address_header(name),
            RawKind::MessageId => inner.start_message_id_header(name),
            RawKind::Date => Ok(()),
        }
    }

    /// More of the header's raw, unfolded value.
    pub(crate) fn feed<H: MessageHandler>(
        &mut self,
        inner: &mut H,
        bytes: &[u8],
    ) -> ParseResult<()> {
        let mut i = 0;
        while i < bytes.len() {
            if self.failed {
                return self.text(inner, &bytes[i..]);
            }
            match self.kind {
                Some(RawKind::Address) => {
                    // the bytes that mean nothing to the tokenizer go in together
                    if !self.quote && !self.escaped && self.comment == 0 {
                        let run = bytes[i..]
                            .iter()
                            .position(|&b| ADDRESS_SPECIAL[b as usize])
                            .unwrap_or(bytes.len() - i);
                        if run > 0 {
                            self.push_run(inner, &bytes[i..i + run])?;
                            i += run;
                            continue;
                        }
                    }
                    let b = bytes[i];
                    i += 1;
                    self.address_byte(inner, b)?;
                }
                Some(RawKind::MessageId) => {
                    let b = bytes[i];
                    i += 1;
                    self.id_byte(inner, b)?;
                }
                Some(RawKind::Date) => {
                    self.buf.extend_from_slice(&bytes[i..]);
                    i = bytes.len();
                    if self.buf.len() > self.max_element {
                        self.fail(inner, "a date is not that long", b"", b"")?;
                    }
                }
                None => i += 1,
            }
        }
        Ok(())
    }

    /// The header's value is complete.
    pub(crate) fn finish<H: MessageHandler>(&mut self, inner: &mut H) -> ParseResult<()> {
        let Some(kind) = self.kind.take() else {
            return Ok(());
        };
        if !self.failed {
            match kind {
                RawKind::Address => self.finish_addresses(inner)?,
                RawKind::MessageId => self.finish_ids(inner)?,
                RawKind::Date => self.finish_date(inner)?,
            }
        }
        if self.failed {
            self.text.finish(&mut |t| inner.header_content(t))?;
            return inner.end_header();
        }
        match kind {
            RawKind::Address => inner.end_address_header(),
            RawKind::MessageId => inner.end_message_id_header(),
            RawKind::Date => Ok(()),
        }
    }

    // ---- addresses ----

    fn address_byte<H: MessageHandler>(&mut self, inner: &mut H, b: u8) -> ParseResult<()> {
        if self.escaped {
            self.escaped = false;
            return self.push(inner, b);
        }
        if self.quote {
            match b {
                b'\\' => self.escaped = true,
                b'"' => self.quote = false,
                _ => {}
            }
            return self.push(inner, b);
        }
        if self.comment > 0 {
            match b {
                b'\\' => self.escaped = true,
                b'(' => self.comment += 1,
                b')' => self.comment -= 1,
                _ => {}
            }
            return self.push(inner, b);
        }
        match b {
            b'"' => {
                self.quote = true;
                self.push(inner, b)
            }
            b'(' => {
                self.comment = 1;
                self.push(inner, b)
            }
            b'<' => {
                self.angle = true;
                self.push(inner, b)
            }
            b'>' => {
                self.angle = false;
                self.push(inner, b)
            }
            b',' if !self.angle => self.end_member(inner, b','),
            b':' if !self.angle && !self.in_group => self.start_group(inner),
            b';' if !self.angle && self.in_group => {
                self.end_member(inner, b';')?;
                if !self.failed {
                    self.in_group = false;
                    self.after_group = true;
                    inner.end_group()?;
                }
                Ok(())
            }
            _ => self.push(inner, b),
        }
    }

    /// Adds bytes that need no deciding to the element.
    fn push_run<H: MessageHandler>(&mut self, inner: &mut H, run: &[u8]) -> ParseResult<()> {
        self.buf.extend_from_slice(run);
        if self.buf.len() > self.max_element {
            return self.fail(inner, "an address is too long", b"", b"");
        }
        Ok(())
    }

    /// Adds a byte to the element.
    fn push<H: MessageHandler>(&mut self, inner: &mut H, b: u8) -> ParseResult<()> {
        if self.buf.len() >= self.max_element {
            self.buf.push(b);
            return self.fail(inner, "an address is too long", b"", b"");
        }
        self.buf.push(b);
        Ok(())
    }

    /// A comma, or the semicolon that ends a group, has ended an element: a
    /// mailbox, or a member of a group. `delimiter` is 0 at the end of the
    /// header.
    fn end_member<H: MessageHandler>(&mut self, inner: &mut H, delimiter: u8) -> ParseResult<()> {
        // `None` is an empty element
        let parsed = {
            let text = decode_header_element(&self.buf, self.smtp_utf8);
            let element = text.trim();
            if element.is_empty() {
                None
            } else {
                Some(parse_mailbox_element(
                    element,
                    self.smtp_utf8,
                    &mut self.scratch,
                ))
            }
        };
        let Some(parsed) = parsed else {
            // an empty element is obsolete syntax, except in an empty group
            // and after the end of one
            if delimiter == b',' && !self.after_group && !self.in_group {
                self.flag_obsolete(inner, ObsoleteStructureType::ObsoleteAddressSyntax)?;
            }
            self.buf.clear();
            self.after_group = false;
            return Ok(());
        };
        self.after_group = false;
        match parsed {
            Some(mailbox) => {
                if mailbox.obsolete {
                    self.flag_obsolete(inner, ObsoleteStructureType::ObsoleteAddressSyntax)?;
                }
                inner.mailbox(
                    mailbox.display_name.as_deref(),
                    &mailbox.local_part,
                    &mailbox.domain,
                )?;
                self.buf.clear();
                Ok(())
            }
            None => {
                let suffix = [delimiter];
                self.fail(
                    inner,
                    "not a mailbox",
                    b"",
                    &suffix[..(delimiter != 0) as usize],
                )
            }
        }
    }

    fn start_group<H: MessageHandler>(&mut self, inner: &mut H) -> ParseResult<()> {
        let name = {
            let text = decode_header_element(&self.buf, self.smtp_utf8);
            parse_group_name(&text, self.smtp_utf8, &mut self.scratch)
        };
        match name {
            Some(name) => {
                self.after_group = false;
                self.in_group = true;
                self.buf.clear();
                inner.start_group(&name)
            }
            None => self.fail(inner, "not the name of a group", b"", b":"),
        }
    }

    fn finish_addresses<H: MessageHandler>(&mut self, inner: &mut H) -> ParseResult<()> {
        if self.quote || self.comment > 0 || self.angle {
            return self.fail(
                inner,
                "a quoted string, comment or angle bracket is not closed",
                b"",
                b"",
            );
        }
        self.end_member(inner, 0)?;
        if !self.failed && self.in_group {
            // a group that is never closed
            self.flag_obsolete(inner, ObsoleteStructureType::ObsoleteAddressSyntax)?;
            self.in_group = false;
            inner.end_group()?;
        }
        Ok(())
    }

    // ---- message-ids ----

    fn id_byte<H: MessageHandler>(&mut self, inner: &mut H, b: u8) -> ParseResult<()> {
        match self.ids {
            IdState::Outside => match b {
                b' ' | b'\t' | b',' => Ok(()),
                b'(' => {
                    self.comment = 1;
                    self.ids = IdState::Comment;
                    Ok(())
                }
                b'<' => {
                    self.buf.clear();
                    self.quote = false;
                    self.ids = IdState::Angle;
                    Ok(())
                }
                _ => {
                    self.buf.clear();
                    self.ids = IdState::Bare;
                    self.push(inner, b)
                }
            },
            IdState::Comment => {
                if self.escaped {
                    self.escaped = false;
                } else {
                    match b {
                        b'\\' => self.escaped = true,
                        b'(' => self.comment += 1,
                        b')' => {
                            self.comment -= 1;
                            if self.comment == 0 {
                                self.ids = IdState::Outside;
                            }
                        }
                        _ => {}
                    }
                }
                Ok(())
            }
            IdState::Angle => {
                if self.escaped {
                    self.escaped = false;
                } else if self.quote {
                    match b {
                        b'\\' => self.escaped = true,
                        b'"' => self.quote = false,
                        _ => {}
                    }
                } else if b == b'"' {
                    self.quote = true;
                } else if b == b'>' {
                    return self.end_angle(inner);
                }
                self.push(inner, b)
            }
            IdState::Bare => match b {
                b' ' | b'\t' | b',' | b'(' | b'<' => {
                    // the byte that ends the word is part of the text if it fails
                    self.end_bare(inner, &[b])?;
                    if !self.failed {
                        self.ids = IdState::Outside;
                        return self.id_byte(inner, b);
                    }
                    Ok(())
                }
                _ => self.push(inner, b),
            },
        }
    }

    fn end_angle<H: MessageHandler>(&mut self, inner: &mut H) -> ParseResult<()> {
        self.ids = IdState::Outside;
        let text = decode_header_element(&self.buf, self.smtp_utf8);
        if let Some(id) = parse_msg_id_text(&text, self.smtp_utf8) {
            inner.message_id(id.local_part(), id.domain())?;
            self.buf.clear();
            return Ok(());
        }
        let bracketed = format!("<{text}>");
        match parse_obsolete_message_id_text(&bracketed) {
            Some(id) => {
                self.flag_obsolete(inner, ObsoleteStructureType::ObsoleteMessageIdSyntax)?;
                inner.message_id(id.local_part(), id.domain())?;
                self.buf.clear();
                Ok(())
            }
            None => self.fail(inner, "not a message-id", b"<", b">"),
        }
    }

    /// A word that is not in angle brackets: obsolete syntax, if it is an id.
    fn end_bare<H: MessageHandler>(&mut self, inner: &mut H, suffix: &[u8]) -> ParseResult<()> {
        let text = decode_header_element(&self.buf, self.smtp_utf8);
        match parse_obsolete_message_id_text(&text) {
            Some(id) => {
                self.flag_obsolete(inner, ObsoleteStructureType::ObsoleteMessageIdSyntax)?;
                inner.message_id(id.local_part(), id.domain())?;
                self.buf.clear();
                Ok(())
            }
            None => self.fail(inner, "not a message-id", b"", suffix),
        }
    }

    fn finish_ids<H: MessageHandler>(&mut self, inner: &mut H) -> ParseResult<()> {
        match self.ids {
            IdState::Outside => Ok(()),
            IdState::Bare => self.end_bare(inner, b""),
            IdState::Angle => self.fail(inner, "a message-id is not closed", b"<", b""),
            IdState::Comment => self.fail(inner, "a comment is not closed", b"", b""),
        }
    }

    // ---- dates ----

    fn finish_date<H: MessageHandler>(&mut self, inner: &mut H) -> ParseResult<()> {
        let text = decode_header_element(&self.buf, self.smtp_utf8);
        let text = text.trim();
        if let Ok(date) = MessageDateTimeFormatter::parse(text) {
            return inner.date_header(&self.name, date);
        }
        match MessageDateTimeFormatter::parse_obsolete(text) {
            Some(date) => {
                self.flag_obsolete(inner, ObsoleteStructureType::ObsoleteDateTimeSyntax)?;
                inner.date_header(&self.name, date)
            }
            None => self.fail(inner, "not a date and time", b"", b""),
        }
    }

    // ---- failure ----

    fn flag_obsolete<H: MessageHandler>(
        &mut self,
        inner: &mut H,
        kind: ObsoleteStructureType,
    ) -> ParseResult<()> {
        if !self.obsolete_flagged {
            self.obsolete_flagged = true;
            inner.obsolete_structure(kind)?;
        }
        Ok(())
    }

    /// The element cannot be read. The handler is told, and the rest of the
    /// header (`prefix`, the element, `suffix`, then whatever follows) is
    /// delivered as text.
    fn fail<H: MessageHandler>(
        &mut self,
        inner: &mut H,
        reason: &str,
        prefix: &[u8],
        suffix: &[u8],
    ) -> ParseResult<()> {
        inner.malformed_header(&self.name, reason)?;
        self.failed = true;
        self.in_group = false;
        self.text.reset();
        let buf = std::mem::take(&mut self.buf);
        let result = self
            .text(inner, prefix)
            .and_then(|()| self.text(inner, &buf))
            .and_then(|()| self.text(inner, suffix));
        self.buf = buf;
        self.buf.clear();
        result
    }

    fn text<H: MessageHandler>(&mut self, inner: &mut H, bytes: &[u8]) -> ParseResult<()> {
        self.text.feed(bytes, &mut |t| inner.header_content(t))
    }
}
