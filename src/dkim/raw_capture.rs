//! Accumulates raw headers and body bytes from parser callbacks.

use std::collections::HashMap;

use super::raw_header::RawHeader;

#[derive(Debug, Default)]
pub struct RawCapture {
    raw_headers: Vec<RawHeader>,
    raw_header_map: HashMap<String, Vec<usize>>,
    raw_body: Vec<u8>,
    headers_complete: bool,
}

impl RawCapture {
    pub fn add_raw_header(&mut self, name: &str, bytes: &[u8]) {
        let header = RawHeader::new(name.to_string(), bytes.to_vec());
        let index = self.raw_headers.len();
        self.raw_headers.push(header);
        self.raw_header_map
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(index);
    }

    pub fn append_raw_body(&mut self, content: &[u8]) {
        self.raw_body.extend_from_slice(content);
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

    pub fn clear(&mut self) {
        self.raw_headers.clear();
        self.raw_header_map.clear();
        self.raw_body.clear();
        self.headers_complete = false;
    }
}
