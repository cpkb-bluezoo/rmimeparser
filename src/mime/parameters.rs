//! The grammar of `Content-Type` and `Content-Disposition`, read as the bytes
//! arrive.
//!
//! ```text
//! content-type        = type "/" subtype *( ";" parameter )
//! content-disposition = disposition-type *( ";" parameter )
//! parameter           = name [ "*" [ index ] [ "*" ] ] "=" value
//! ```
//!
//! The head (the media type or disposition type) is short, so it is held until
//! it is complete and judged whole. Parameter values can be long and are not
//! held: each is decoded as it arrives and handed on in pieces.
//!
//! A value is decoded one of three ways:
//!
//! * as text, for an ordinary parameter: quoted-pairs resolved, RFC 2047 encoded
//!   words decoded, raw 8-bit text read as UTF-8 where valid;
//! * as an RFC 2231 extended value (`name*=charset'language'%xx...`), which is
//!   percent-decoded and read in its charset;
//! * as an RFC 2231 continuation, which is either of those over several
//!   parameters (`name*0`, `name*1*`, ...), joined into one value. Segments
//!   have to arrive in order, starting at 0; a segment out of order is
//!   skipped.
//!
//! Anything the grammar cannot make sense of in a parameter is skipped, and
//! parsing goes on with the next. Only a head that is not valid is reported, as
//! [`Fed::Malformed`], and then nothing has been delivered.

use crate::charset::{ByteCharset, ByteDecoder};
use crate::mime::error::ParseResult;
use crate::rfc2047::HeaderTextDecoder;

/// Which header is being read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    ContentType,
    ContentDisposition,
}

/// Where the events go.
pub(crate) trait ParameterSink {
    /// The head: `type` and `subtype` of a media type, or the disposition type
    /// and an empty second string.
    fn head(&mut self, first: &str, second: &str) -> ParseResult<()>;
    /// `language` is `Some` for an RFC 2231 extended value, possibly empty.
    fn start_parameter(&mut self, name: &str, language: Option<&str>) -> ParseResult<()>;
    fn content(&mut self, text: &str) -> ParseResult<()>;
    fn end_parameter(&mut self) -> ParseResult<()>;
}

/// The result of feeding the grammar.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Fed {
    Continue,
    /// The head is not valid. Nothing was delivered. [`ParameterParser::head`]
    /// holds every byte of the value up to and including the one that showed
    /// it, and `rest` is where in the bytes just fed the unread ones begin.
    Malformed { reason: &'static str, rest: usize },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Head,
    /// Between parameters: white space and semicolons.
    Between,
    Name,
    AfterEquals,
    Quoted,
    Unquoted,
    /// After a closing quote: whatever is there is ignored.
    AfterQuoted,
    /// Skipping a parameter that cannot be used.
    Skip,
}

/// How the bytes of the current segment's value are decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Route {
    None,
    Text,
    /// Reading `charset'language'` at the start of an extended value.
    Prefix,
    /// Percent-decoded and read in the charset.
    Ext,
    /// Read in the charset without percent-decoding: a plain segment of a
    /// continuation whose first segment was extended.
    Raw,
}

/// A parameter that can be continued by the next segment.
struct Open {
    base: Vec<u8>,
    next_index: u32,
    route: Route,
}

/// Longest `charset'language'` prefix.
const MAX_PREFIX: usize = 160;
/// Trailing white space of an unquoted value held to see whether more follows.
const MAX_PENDING_WHITESPACE: usize = 64;

pub(crate) struct ParameterParser {
    kind: Kind,
    max_token: usize,
    state: State,
    escaped: bool,
    head: Vec<u8>,
    name: Vec<u8>,
    route: Route,
    /// Whether the current segment's parameter ends with it.
    segment_ends_parameter: bool,
    /// The name of an extended parameter, until its prefix is read.
    pending_name: Vec<u8>,
    open: Option<Open>,
    /// A parameter has been started and not ended.
    in_parameter: bool,
    text: HeaderTextDecoder,
    bytes: ByteDecoder,
    prefix: Vec<u8>,
    /// Percent-decoding: 0 outside, 1 after `%`, 2 after `%` and a digit.
    percent: u8,
    percent_high: u8,
    decoded: Vec<u8>,
    scratch: String,
    /// White space at the end of what has been read of an unquoted value.
    pending_whitespace: Vec<u8>,
}

impl ParameterParser {
    pub(crate) fn new(utf8_headers: bool) -> Self {
        Self {
            kind: Kind::ContentType,
            max_token: 256,
            state: State::Head,
            escaped: false,
            head: Vec::new(),
            name: Vec::new(),
            route: Route::None,
            segment_ends_parameter: true,
            pending_name: Vec::new(),
            open: None,
            in_parameter: false,
            text: HeaderTextDecoder::new(utf8_headers),
            bytes: ByteDecoder::new(ByteCharset::Utf8),
            prefix: Vec::new(),
            percent: 0,
            percent_high: 0,
            decoded: Vec::new(),
            scratch: String::new(),
            pending_whitespace: Vec::new(),
        }
    }

    /// Readies the grammar for another header of `kind`. `max_token` bounds the
    /// head's tokens, parameter names and the parts of a language prefix.
    pub(crate) fn start(&mut self, kind: Kind, max_token: usize) {
        self.kind = kind;
        self.max_token = max_token;
        self.state = State::Head;
        self.escaped = false;
        self.head.clear();
        self.name.clear();
        self.route = Route::None;
        self.pending_name.clear();
        self.open = None;
        self.in_parameter = false;
        self.text.reset();
        self.percent = 0;
        self.pending_whitespace.clear();
    }

    /// The bytes of the value so far, while the head is unfinished or after
    /// [`Fed::Malformed`].
    pub(crate) fn head(&self) -> &[u8] {
        &self.head
    }

    pub(crate) fn feed(
        &mut self,
        bytes: &[u8],
        sink: &mut impl ParameterSink,
    ) -> ParseResult<Fed> {
        let mut i = 0;
        while i < bytes.len() {
            match self.state {
                State::Head => {
                    let semicolon = bytes[i..].iter().position(|&b| b == b';');
                    let end = semicolon.map_or(bytes.len(), |p| i + p + 1);
                    self.head.extend_from_slice(&bytes[i..end]);
                    i = end;
                    if semicolon.is_some() {
                        self.head.pop();
                        match self.complete_head(sink)? {
                            Ok(()) => self.state = State::Between,
                            Err(reason) => {
                                self.head.push(b';');
                                return Ok(Fed::Malformed { reason, rest: i });
                            }
                        }
                    } else if self.head.len() > 2 * self.max_token + 32 {
                        return Ok(Fed::Malformed {
                            reason: "the media type or disposition type is too long",
                            rest: i,
                        });
                    }
                }
                State::Between => {
                    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b';') {
                        i += 1;
                    }
                    if i < bytes.len() {
                        self.state = State::Name;
                        self.name.clear();
                    }
                }
                State::Name => {
                    let b = bytes[i];
                    i += 1;
                    match b {
                        b'=' => self.begin_value(sink)?,
                        b';' => self.state = State::Between,
                        _ => {
                            if self.name.len() >= self.max_token {
                                self.state = State::Skip;
                            } else {
                                self.name.push(b);
                            }
                        }
                    }
                }
                State::AfterEquals => {
                    match bytes[i] {
                        b' ' | b'\t' => i += 1,
                        b'"' => {
                            i += 1;
                            self.state = State::Quoted;
                            self.escaped = false;
                        }
                        b';' => {
                            i += 1;
                            self.end_segment(sink)?;
                            self.state = State::Between;
                        }
                        _ => {
                            self.state = State::Unquoted;
                            self.pending_whitespace.clear();
                        }
                    }
                }
                State::Quoted => i = self.quoted(bytes, i, sink)?,
                State::Unquoted => i = self.unquoted(bytes, i, sink)?,
                State::AfterQuoted | State::Skip => {
                    match bytes[i..].iter().position(|&b| b == b';') {
                        Some(p) => {
                            i += p + 1;
                            self.state = State::Between;
                        }
                        None => i = bytes.len(),
                    }
                }
            }
        }
        Ok(Fed::Continue)
    }

    /// The value has ended. If the head was still unfinished, it is judged now.
    pub(crate) fn finish(&mut self, sink: &mut impl ParameterSink) -> ParseResult<Fed> {
        match self.state {
            State::Head => {
                if let Err(reason) = self.complete_head(sink)? {
                    return Ok(Fed::Malformed { reason, rest: 0 });
                }
            }
            State::AfterEquals | State::Quoted | State::Unquoted => self.end_segment(sink)?,
            _ => {}
        }
        self.state = State::Between;
        self.close_open(sink)?;
        Ok(Fed::Continue)
    }

    /// Judges the head and, if it is valid, delivers it. `Err` is the reason it
    /// is not.
    fn complete_head(
        &mut self,
        sink: &mut impl ParameterSink,
    ) -> ParseResult<Result<(), &'static str>> {
        let head = trim(&self.head);
        let max = self.max_token;
        let ok = |t: &[u8]| !t.is_empty() && t.len() <= max && t.iter().all(|&b| is_token_byte(b));
        match self.kind {
            Kind::ContentType => {
                let Some(slash) = head.iter().position(|&b| b == b'/') else {
                    return Ok(Err("a media type is type/subtype"));
                };
                let (primary, sub) = (trim(&head[..slash]), trim(&head[slash + 1..]));
                if !ok(primary) || !ok(sub) {
                    return Ok(Err("the type or subtype of the media type is not a token"));
                }
                // tokens are ASCII
                let primary = std::str::from_utf8(primary).unwrap();
                let sub = std::str::from_utf8(sub).unwrap();
                sink.head(primary, sub)?;
            }
            Kind::ContentDisposition => {
                if !ok(head) {
                    return Ok(Err("the disposition type is not a token"));
                }
                sink.head(std::str::from_utf8(head).unwrap(), "")?;
            }
        }
        Ok(Ok(()))
    }

    /// `name` is complete and an `=` followed it: starts the parameter's value,
    /// or skips it.
    fn begin_value(&mut self, sink: &mut impl ParameterSink) -> ParseResult<()> {
        let name = std::mem::take(&mut self.name);
        let trimmed = trim(&name);
        let name_ok = !trimmed.is_empty() && trimmed.iter().all(|&b| is_token_byte(b));
        let result = if name_ok {
            self.start_segment(trimmed, sink)
        } else {
            self.state = State::Skip;
            Ok(())
        };
        self.name = name;
        result
    }

    fn start_segment(&mut self, name: &[u8], sink: &mut impl ParameterSink) -> ParseResult<()> {
        self.state = State::AfterEquals;
        self.pending_whitespace.clear();
        match classify(name) {
            Form::Plain => {
                self.close_open(sink)?;
                self.start_text_parameter(name, sink)?;
                self.segment_ends_parameter = true;
            }
            Form::Extended(base) => {
                self.close_open(sink)?;
                self.start_prefix(base);
                self.segment_ends_parameter = true;
            }
            Form::Continuation { base, index, extended } => {
                let continues = self
                    .open
                    .as_ref()
                    .is_some_and(|o| o.base == base && o.next_index == index);
                if continues {
                    let open = self.open.as_mut().unwrap();
                    open.next_index += 1;
                    self.route = match (open.route, extended) {
                        (Route::Ext, true) => Route::Ext,
                        (Route::Ext, false) => {
                            self.percent = 0;
                            Route::Raw
                        }
                        _ => Route::Text,
                    };
                    self.segment_ends_parameter = false;
                } else if index == 0 {
                    self.close_open(sink)?;
                    self.open = Some(Open {
                        base: base.to_vec(),
                        next_index: 1,
                        route: if extended { Route::Ext } else { Route::Text },
                    });
                    if extended {
                        self.start_prefix(base);
                    } else {
                        self.start_text_parameter(base, sink)?;
                    }
                    self.segment_ends_parameter = false;
                } else {
                    // out of order, or a continuation that never began
                    self.route = Route::None;
                    self.state = State::Skip;
                }
            }
        }
        Ok(())
    }

    fn start_text_parameter(
        &mut self,
        name: &[u8],
        sink: &mut impl ParameterSink,
    ) -> ParseResult<()> {
        sink.start_parameter(ascii(name), None)?;
        self.in_parameter = true;
        self.route = Route::Text;
        self.text.reset();
        Ok(())
    }

    fn start_prefix(&mut self, base: &[u8]) {
        self.pending_name.clear();
        self.pending_name.extend_from_slice(base);
        self.prefix.clear();
        self.route = Route::Prefix;
    }

    /// The text of a quoted value, from `i`; returns where it ended.
    fn quoted(
        &mut self,
        bytes: &[u8],
        mut i: usize,
        sink: &mut impl ParameterSink,
    ) -> ParseResult<usize> {
        while i < bytes.len() {
            if self.escaped {
                self.escaped = false;
                self.value(&bytes[i..i + 1], sink)?;
                i += 1;
                continue;
            }
            let end = bytes[i..]
                .iter()
                .position(|&b| b == b'"' || b == b'\\')
                .map_or(bytes.len(), |p| i + p);
            if end > i {
                self.value(&bytes[i..end], sink)?;
                i = end;
                continue;
            }
            i += 1;
            if bytes[i - 1] == b'\\' {
                self.escaped = true;
            } else {
                self.end_segment(sink)?;
                self.state = State::AfterQuoted;
                break;
            }
        }
        Ok(i)
    }

    /// The text of an unquoted value, from `i`; returns where it ended. White
    /// space at its end is not part of it.
    fn unquoted(
        &mut self,
        bytes: &[u8],
        mut i: usize,
        sink: &mut impl ParameterSink,
    ) -> ParseResult<usize> {
        while i < bytes.len() {
            let end = bytes[i..]
                .iter()
                .position(|&b| b == b';' || b == b' ' || b == b'\t')
                .map_or(bytes.len(), |p| i + p);
            if end > i {
                self.flush_pending_whitespace(sink)?;
                self.value(&bytes[i..end], sink)?;
                i = end;
                continue;
            }
            let b = bytes[i];
            i += 1;
            if b == b';' {
                self.pending_whitespace.clear();
                self.end_segment(sink)?;
                self.state = State::Between;
                break;
            }
            if self.pending_whitespace.len() >= MAX_PENDING_WHITESPACE {
                self.flush_pending_whitespace(sink)?;
            }
            self.pending_whitespace.push(b);
        }
        Ok(i)
    }

    fn flush_pending_whitespace(&mut self, sink: &mut impl ParameterSink) -> ParseResult<()> {
        if !self.pending_whitespace.is_empty() {
            let whitespace = std::mem::take(&mut self.pending_whitespace);
            let result = self.value(&whitespace, sink);
            self.pending_whitespace = whitespace;
            self.pending_whitespace.clear();
            result?;
        }
        Ok(())
    }

    /// Value bytes, quotes and escapes already resolved, decoded by the
    /// current route.
    fn value(&mut self, bytes: &[u8], sink: &mut impl ParameterSink) -> ParseResult<()> {
        match self.route {
            Route::None => Ok(()),
            Route::Text => self.text.feed(bytes, &mut |t| sink.content(t)),
            Route::Prefix => self.prefix_bytes(bytes, sink),
            Route::Ext => self.extended_bytes(bytes, sink),
            Route::Raw => {
                self.scratch.clear();
                self.bytes.feed(bytes, &mut self.scratch);
                self.emit_scratch(sink)
            }
        }
    }

    fn emit_scratch(&mut self, sink: &mut impl ParameterSink) -> ParseResult<()> {
        if self.scratch.is_empty() {
            return Ok(());
        }
        let result = sink.content(&self.scratch);
        self.scratch.clear();
        result
    }

    /// Bytes at the start of an extended value, up to its second apostrophe.
    fn prefix_bytes(&mut self, bytes: &[u8], sink: &mut impl ParameterSink) -> ParseResult<()> {
        for (n, &b) in bytes.iter().enumerate() {
            if self.prefix.len() >= MAX_PREFIX || !(0x21..=0x7E).contains(&b) {
                // not `charset'language'`
                return self.prefix_fallback(&bytes[n..], sink);
            }
            self.prefix.push(b);
            if b == b'\'' && self.prefix.iter().filter(|&&p| p == b'\'').count() == 2 {
                return match self.prefix_complete(sink)? {
                    true => self.extended_bytes(&bytes[n + 1..], sink),
                    false => self.prefix_fallback_after(&bytes[n + 1..], sink),
                };
            }
        }
        Ok(())
    }

    /// `prefix` is `charset'language'`: starts the parameter. False if it is
    /// not a usable one.
    fn prefix_complete(&mut self, sink: &mut impl ParameterSink) -> ParseResult<bool> {
        let first = self.prefix.iter().position(|&b| b == b'\'').unwrap();
        let (charset, language) = (&self.prefix[..first], &self.prefix[first + 1..self.prefix.len() - 1]);
        if charset.is_empty() || charset.len() > self.max_token || language.len() > self.max_token {
            return Ok(false);
        }
        self.bytes = ByteDecoder::new(ByteCharset::from_name(ascii(charset)));
        self.percent = 0;
        let name = std::mem::take(&mut self.pending_name);
        let result = sink.start_parameter(ascii(&name), Some(ascii(language)));
        self.pending_name = name;
        result?;
        self.in_parameter = true;
        self.route = Route::Ext;
        Ok(true)
    }

    /// What was read is not a prefix: the value is plain text, with the bytes
    /// so far and `rest` as its start.
    fn prefix_fallback(&mut self, rest: &[u8], sink: &mut impl ParameterSink) -> ParseResult<()> {
        self.prefix_fallback_after(rest, sink)
    }

    fn prefix_fallback_after(
        &mut self,
        rest: &[u8],
        sink: &mut impl ParameterSink,
    ) -> ParseResult<()> {
        let name = std::mem::take(&mut self.pending_name);
        let started = self.start_text_parameter(&name, sink);
        self.pending_name = name;
        started?;
        if let Some(open) = self.open.as_mut() {
            open.route = Route::Text;
        }
        let prefix = std::mem::take(&mut self.prefix);
        let fed = self.text.feed(&prefix, &mut |t| sink.content(t));
        self.prefix = prefix;
        self.prefix.clear();
        fed?;
        self.value(rest, sink)
    }

    /// Percent-encoded bytes of an extended value.
    fn extended_bytes(&mut self, bytes: &[u8], sink: &mut impl ParameterSink) -> ParseResult<()> {
        self.decoded.clear();
        for &b in bytes {
            match self.percent {
                0 if b == b'%' => self.percent = 1,
                0 => self.decoded.push(b),
                1 => match hex(b) {
                    Some(h) => {
                        self.percent_high = h;
                        self.percent = 2;
                    }
                    None => {
                        self.percent = 0;
                        self.decoded.push(b'%');
                        self.decoded.push(b);
                    }
                },
                _ => {
                    self.percent = 0;
                    match hex(b) {
                        Some(l) => self.decoded.push(self.percent_high << 4 | l),
                        None => {
                            self.decoded.push(b'%');
                            self.decoded.push(HEX[self.percent_high as usize]);
                            self.decoded.push(b);
                        }
                    }
                }
            }
        }
        self.scratch.clear();
        let mut decoded = std::mem::take(&mut self.decoded);
        self.bytes.feed(&decoded, &mut self.scratch);
        decoded.clear();
        self.decoded = decoded;
        self.emit_scratch(sink)
    }

    /// The current segment's value is complete.
    fn end_segment(&mut self, sink: &mut impl ParameterSink) -> ParseResult<()> {
        if self.route == Route::Prefix {
            self.prefix_fallback_after(&[], sink)?;
        }
        self.pending_whitespace.clear();
        if self.segment_ends_parameter {
            self.end_value(sink)?;
        } else if self.percent != 0 {
            // a percent sign cut short by the end of a segment is text
            self.flush_percent();
        }
        self.route = Route::None;
        Ok(())
    }

    /// Ends the parameter being read, finishing its decoders.
    fn end_value(&mut self, sink: &mut impl ParameterSink) -> ParseResult<()> {
        match self.route {
            Route::Text => self.text.finish(&mut |t| sink.content(t))?,
            Route::Ext | Route::Raw => {
                self.flush_percent();
                self.scratch.clear();
                let decoded = std::mem::take(&mut self.decoded);
                self.bytes.feed(&decoded, &mut self.scratch);
                self.decoded = decoded;
                self.decoded.clear();
                self.bytes.finish(&mut self.scratch);
                self.emit_scratch(sink)?;
            }
            Route::None | Route::Prefix => {}
        }
        if self.in_parameter {
            self.in_parameter = false;
            sink.end_parameter()?;
        }
        Ok(())
    }

    /// Ends the parameter a continuation has kept open.
    fn close_open(&mut self, sink: &mut impl ParameterSink) -> ParseResult<()> {
        let Some(open) = self.open.take() else {
            return Ok(());
        };
        if self.in_parameter {
            // the route of its last segment is not necessarily the parameter's
            self.route = open.route;
            self.end_value(sink)?;
        }
        Ok(())
    }

    /// A percent sign (and digit) cut short is text.
    fn flush_percent(&mut self) {
        match self.percent {
            1 => self.decoded.push(b'%'),
            2 => {
                self.decoded.push(b'%');
                self.decoded.push(HEX[self.percent_high as usize]);
            }
            _ => {}
        }
        self.percent = 0;
    }
}

enum Form<'a> {
    Plain,
    /// `name*`
    Extended(&'a [u8]),
    /// `name*0`, `name*1*`
    Continuation {
        base: &'a [u8],
        index: u32,
        extended: bool,
    },
}

fn classify(name: &[u8]) -> Form<'_> {
    let Some(star) = name.iter().position(|&b| b == b'*') else {
        return Form::Plain;
    };
    let (base, rest) = (&name[..star], &name[star + 1..]);
    if base.is_empty() {
        return Form::Plain;
    }
    if rest.is_empty() {
        return Form::Extended(base);
    }
    let (digits, extended) = match rest.split_last() {
        Some((b'*', digits)) => (digits, true),
        _ => (rest, false),
    };
    if digits.is_empty() || digits.len() > 9 || !digits.iter().all(u8::is_ascii_digit) {
        return Form::Plain;
    }
    let index = digits.iter().fold(0u32, |n, &d| n * 10 + u32::from(d - b'0'));
    Form::Continuation { base, index, extended }
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn hex(b: u8) -> Option<u8> {
    crate::charset::hex_value(b)
}

/// Bytes that are known to be ASCII tokens (checked by the caller).
fn ascii(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap_or("")
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(start, |p| p + 1);
    &bytes[start..end]
}

fn is_token_byte(b: u8) -> bool {
    b < 0x80 && crate::mime::utils::is_token_char(b as char)
}
