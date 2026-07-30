//! Accumulates raw headers and body bytes from the parser wire sink.

use std::collections::HashMap;

use crate::mime::error::ParseResult;
use crate::mime::wire_sink::MimeWireSink;

use super::raw_header::RawHeader;

/// Type-erased callback fed each raw body chunk as it streams in, in wire
/// order — see [`RawCapture::set_body_sink`].
type BodySink<'a> = Box<dyn FnMut(&[u8]) + 'a>;

#[derive(Default)]
pub struct RawCapture<'a> {
    raw_headers: Vec<RawHeader>,
    raw_header_map: HashMap<String, Vec<usize>>,
    raw_body: Vec<u8>,
    headers_complete: bool,
    body_sink: Option<BodySink<'a>>,
}

impl<'a> std::fmt::Debug for RawCapture<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawCapture")
            .field("raw_headers", &self.raw_headers)
            .field("raw_body_len", &self.raw_body.len())
            .field("headers_complete", &self.headers_complete)
            .field("body_sink", &self.body_sink.is_some())
            .finish()
    }
}

impl<'a> RawCapture<'a> {
    pub fn add_raw_header(&mut self, name: &str, bytes: &[u8]) {
        let header = RawHeader::new(name.to_string(), bytes.to_vec());
        let index = self.raw_headers.len();
        self.raw_headers.push(header);
        self.raw_header_map
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(index);
    }

    /// Stream body bytes to `sink` as they arrive instead of retaining them
    /// — see [`crate::DkimMessageParser::set_body_sink`] for the rationale
    /// and contract (must be set before the body starts arriving;
    /// [`Self::raw_body`] returns empty once a sink is installed).
    pub fn set_body_sink(&mut self, sink: BodySink<'a>) {
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

    pub fn raw_header(&self, name: &str) -> Option<&RawHeader> {
        self.raw_header_map
            .get(&name.to_ascii_lowercase())
            .and_then(|indices| indices.first().copied())
            .map(|index| &self.raw_headers[index])
    }

    pub fn all_raw_headers(&self, name: &str) -> Vec<&RawHeader> {
        self.raw_header_map
            .get(&name.to_ascii_lowercase())
            .map(|indices| indices.iter().map(|&i| &self.raw_headers[i]).collect())
            .unwrap_or_default()
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
        self.raw_header_map.clear();
        self.raw_body.clear();
        self.headers_complete = false;
        self.body_sink = None;
    }
}

impl<'a> MimeWireSink for RawCapture<'a> {
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
