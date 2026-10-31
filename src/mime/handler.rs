use std::cell::Cell;
use std::rc::Rc;

use crate::mime::content_types::{ContentDisposition, ContentId, ContentType, MimeVersion};
use crate::mime::error::ParseResult;

/// Where the parser is in the message.
///
/// A handler receives one of these from [`MimeHandler::set_locator`] and may
/// keep it, reading the live position from inside any later callback. The
/// offset counts bytes consumed; lines start at 1 and a column counts bytes
/// since the last line feed.
pub trait Locator {
    fn offset(&self) -> u64;
    fn line_number(&self) -> u64;
    fn column_number(&self) -> u64;
}

/// Live position storage the parser updates as it consumes bytes.
///
/// `Cell`s: `receive` is always called on one thread, so the parser, the
/// handler and any locator the handler keeps all live on it, and nothing here
/// needs to be `Send` or `Sync`.
#[derive(Debug)]
pub(crate) struct SharedLocator {
    offset: Cell<u64>,
    line: Cell<u64>,
    column: Cell<u64>,
}

impl SharedLocator {
    pub(crate) fn new() -> Self {
        Self {
            offset: Cell::new(0),
            line: Cell::new(1),
            column: Cell::new(0),
        }
    }

    /// Counts `bytes`, none of which contains a line feed except as the last.
    pub(crate) fn advance_line(&self, len: usize) {
        self.offset.set(self.offset.get() + len as u64);
        self.column.set(self.column.get() + len as u64);
    }

    pub(crate) fn end_line(&self) {
        self.line.set(self.line.get() + 1);
        self.column.set(0);
    }

    /// Counts a run of bytes of any shape.
    pub(crate) fn advance(&self, bytes: &[u8]) {
        self.offset.set(self.offset.get() + bytes.len() as u64);
        match bytes.iter().rposition(|&b| b == b'\n') {
            None => self.column.set(self.column.get() + bytes.len() as u64),
            Some(last) => {
                let lines = bytes.iter().filter(|&&b| b == b'\n').count() as u64;
                self.line.set(self.line.get() + lines);
                self.column.set((bytes.len() - 1 - last) as u64);
            }
        }
    }
}

impl Locator for SharedLocator {
    fn offset(&self) -> u64 {
        self.offset.get()
    }
    fn line_number(&self) -> u64 {
        self.line.get()
    }
    fn column_number(&self) -> u64 {
        self.column.get()
    }
}

/// Callback interface for push-based MIME parsing events.
///
/// Override typed methods (`content_type`, `body_content`, …) for normal use.
/// Wire-accurate header/body capture is not part of this trait—use
/// [`crate::DkimMessageParser`] when you need raw bytes for DKIM.
pub trait MimeHandler {
    /// Called once, before the first event, with the parser's locator. It is
    /// live: keep it and read it from inside later callbacks.
    fn set_locator(&mut self, _locator: Rc<dyn Locator>) {}

    /// Return `true` if this header was handled and default MIME dispatch should be skipped.
    fn pre_mime_header(&mut self, _name: &str, _value: &[u8]) -> ParseResult<bool> {
        Ok(false)
    }

    fn start_entity(&mut self, _boundary: Option<&str>) -> ParseResult<()> {
        Ok(())
    }

    fn content_type(&mut self, _content_type: &ContentType) -> ParseResult<()> {
        Ok(())
    }

    fn content_disposition(&mut self, _disposition: &ContentDisposition) -> ParseResult<()> {
        Ok(())
    }

    fn content_transfer_encoding(&mut self, _encoding: &str) -> ParseResult<()> {
        Ok(())
    }

    fn content_id(&mut self, _content_id: &ContentId) -> ParseResult<()> {
        Ok(())
    }

    fn content_description(&mut self, _description: &str) -> ParseResult<()> {
        Ok(())
    }

    fn mime_version(&mut self, _version: MimeVersion) -> ParseResult<()> {
        Ok(())
    }

    fn end_headers(&mut self) -> ParseResult<()> {
        Ok(())
    }

    fn body_content(&mut self, _content: &[u8]) -> ParseResult<()> {
        Ok(())
    }

    fn unexpected_content(&mut self, _content: &[u8]) -> ParseResult<()> {
        Ok(())
    }

    fn end_entity(&mut self, _boundary: Option<&str>) -> ParseResult<()> {
        Ok(())
    }
}

macro_rules! forward_handler {
    ($target:ty) => {
        impl<H: MimeHandler + ?Sized> MimeHandler for $target {
            fn set_locator(&mut self, locator: Rc<dyn Locator>) {
                (**self).set_locator(locator)
            }
            fn pre_mime_header(&mut self, name: &str, value: &[u8]) -> ParseResult<bool> {
                (**self).pre_mime_header(name, value)
            }
            fn start_entity(&mut self, boundary: Option<&str>) -> ParseResult<()> {
                (**self).start_entity(boundary)
            }
            fn content_type(&mut self, content_type: &ContentType) -> ParseResult<()> {
                (**self).content_type(content_type)
            }
            fn content_disposition(&mut self, disposition: &ContentDisposition) -> ParseResult<()> {
                (**self).content_disposition(disposition)
            }
            fn content_transfer_encoding(&mut self, encoding: &str) -> ParseResult<()> {
                (**self).content_transfer_encoding(encoding)
            }
            fn content_id(&mut self, content_id: &ContentId) -> ParseResult<()> {
                (**self).content_id(content_id)
            }
            fn content_description(&mut self, description: &str) -> ParseResult<()> {
                (**self).content_description(description)
            }
            fn mime_version(&mut self, version: MimeVersion) -> ParseResult<()> {
                (**self).mime_version(version)
            }
            fn end_headers(&mut self) -> ParseResult<()> {
                (**self).end_headers()
            }
            fn body_content(&mut self, content: &[u8]) -> ParseResult<()> {
                (**self).body_content(content)
            }
            fn unexpected_content(&mut self, content: &[u8]) -> ParseResult<()> {
                (**self).unexpected_content(content)
            }
            fn end_entity(&mut self, boundary: Option<&str>) -> ParseResult<()> {
                (**self).end_entity(boundary)
            }
        }
    };
}

// A borrowed handler drives the parser like an owned one: `MimeParser::new(&mut handler)`.
forward_handler!(&mut H);
// So does a boxed one, `Box<dyn MimeHandler>` included.
forward_handler!(Box<H>);

/// rprotobuf-style handler trait alias.
pub trait Handler: MimeHandler {}

impl<T: MimeHandler> Handler for T {}

pub struct DefaultHandler;

impl MimeHandler for DefaultHandler {}
