//! Accumulates raw headers and body bytes from the parser wire sink.

use crate::mime::error::ParseResult;
use crate::mime::wire_sink::MimeWireSink;

use super::raw_header::RawHeader;

/// Type-erased callback fed each raw body chunk as it streams in, in wire
/// order — see [`RawCapture::set_body_sink`].
type BodySink = Box<dyn FnMut(&[u8])>;

/// Says from a header's name whether to capture it — see
/// [`RawCapture::set_header_filter`].
type HeaderFilter = Box<dyn FnMut(&str) -> bool>;

/// Told of each header as it is captured — see
/// [`RawCapture::set_header_callback`].
type HeaderCallback = Box<dyn FnMut(&RawHeader)>;

#[derive(Default)]
pub struct RawCapture {
    raw_headers: Vec<RawHeader>,
    raw_body: Vec<u8>,
    headers_complete: bool,
    body_sink: Option<BodySink>,
    header_filter: Option<HeaderFilter>,
    header_callback: Option<HeaderCallback>,
}

impl std::fmt::Debug for RawCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawCapture")
            .field("raw_headers", &self.raw_headers)
            .field("raw_body_len", &self.raw_body.len())
            .field("headers_complete", &self.headers_complete)
            .field("body_sink", &self.body_sink.is_some())
            .field("header_filter", &self.header_filter.is_some())
            .finish()
    }
}

impl RawCapture {
    pub fn add_raw_header(&mut self, name: &str, bytes: &[u8]) {
        self.raw_headers
            .push(RawHeader::new(name.to_string(), bytes.to_vec()));
        if let (Some(callback), Some(header)) =
            (self.header_callback.as_mut(), self.raw_headers.last())
        {
            callback(header);
        }
    }

    /// Capture only the headers `filter` says yes to, asked once per header
    /// with its name as soon as that is known. The others are never copied or
    /// held. With no filter every header is captured.
    pub fn set_header_filter(&mut self, filter: HeaderFilter) {
        self.header_filter = Some(filter);
    }

    /// Call `callback` with each header as soon as it has been captured. The
    /// way to widen a filter once a header (a `DKIM-Signature`) says which
    /// others are wanted.
    pub fn set_header_callback(&mut self, callback: HeaderCallback) {
        self.header_callback = Some(callback);
    }

    /// Stream body bytes to `sink` as they arrive instead of retaining them
    /// — see [`crate::DkimMessageParser::set_body_sink`] for the rationale
    /// and contract (must be set before the body starts arriving;
    /// [`Self::raw_body`] returns empty once a sink is installed).
    pub fn set_body_sink(&mut self, sink: BodySink) {
        self.body_sink = Some(sink);
    }

    pub fn append_raw_body(&mut self, content: &[u8]) {
        match self.body_sink.as_mut() {
            Some(sink) => sink(content),
            None => self.raw_body.extend_from_slice(content),
        }
    }

    pub fn mark_headers_complete(&mut self) {
        self.headers_complete = true;
    }

    pub fn raw_headers(&self) -> &[RawHeader] {
        &self.raw_headers
    }

    /// The first header called `name` (case-insensitive). A message has a
    /// few dozen headers, so a scan beats keeping a lowercased index.
    pub fn raw_header(&self, name: &str) -> Option<&RawHeader> {
        self.raw_headers
            .iter()
            .find(|h| h.name().eq_ignore_ascii_case(name))
    }

    pub fn all_raw_headers(&self, name: &str) -> Vec<&RawHeader> {
        self.raw_headers
            .iter()
            .filter(|h| h.name().eq_ignore_ascii_case(name))
            .collect()
    }

    pub fn header_bytes(&self, name: &str) -> Option<&[u8]> {
        self.raw_header(name).map(RawHeader::bytes)
    }

    pub fn all_header_bytes(&self, name: &str) -> Vec<&[u8]> {
        self.all_raw_headers(name)
            .into_iter()
            .map(RawHeader::bytes)
            .collect()
    }

    pub fn raw_body(&self) -> &[u8] {
        &self.raw_body
    }

    pub fn is_headers_complete(&self) -> bool {
        self.headers_complete
    }

    /// Resets captured headers/body **and** drops any installed body sink —
    /// a sink is normally tied to one message's digest context, so callers
    /// re-streaming a fresh message must call [`Self::set_body_sink`] again.
    pub fn clear(&mut self) {
        self.raw_headers.clear();
        self.raw_body.clear();
        self.headers_complete = false;
        self.body_sink = None;
        self.header_filter = None;
        self.header_callback = None;
    }
}

impl MimeWireSink for RawCapture {
    fn wants_header(&mut self, name: &str) -> bool {
        match self.header_filter.as_mut() {
            Some(filter) => filter(name),
            None => true,
        }
    }

    fn raw_header(&mut self, name: &str, raw_bytes: &[u8]) -> ParseResult<()> {
        self.add_raw_header(name, raw_bytes);
        Ok(())
    }

    fn raw_body_content(&mut self, content: &[u8]) -> ParseResult<()> {
        self.append_raw_body(content);
        Ok(())
    }

    fn mark_headers_complete(&mut self) -> ParseResult<()> {
        RawCapture::mark_headers_complete(self);
        Ok(())
    }
}
