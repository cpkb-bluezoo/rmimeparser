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

/// How the value of a header the parser does not itself understand is
/// delivered; see [`MimeHandler::header_delivery`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderDelivery {
    /// As decoded text in [`MimeHandler::header_content`] pieces.
    Unstructured,
    /// As the bytes that arrived, in [`MimeHandler::raw_header_content`] pieces,
    /// for a layer that parses the value itself.
    Raw,
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

    /// Asked once for each header the parser does not itself understand (the
    /// ones it does are `Content-Type`, `Content-Disposition`,
    /// `Content-Transfer-Encoding`, `Content-ID` and `MIME-Version`), just
    /// before [`Self::start_header`]. The answer says how its value arrives.
    ///
    /// This is how a layer on top of MIME (RFC 5322 is one) takes the headers
    /// it understands for itself: it asks for them [`HeaderDelivery::Raw`].
    fn header_delivery(&mut self, _name: &str) -> HeaderDelivery {
        HeaderDelivery::Unstructured
    }

    /// The start of a header the parser does not itself understand. Its value
    /// follows as [`Self::header_content`] calls, or [`Self::raw_header_content`]
    /// if [`Self::header_delivery`] asked for it raw, and then [`Self::end_header`].
    fn start_header(&mut self, _name: &str) -> ParseResult<()> {
        Ok(())
    }

    /// A piece of an unstructured header's value, in order: unfolded, with
    /// leading and trailing white space removed, RFC 2047 encoded words decoded,
    /// and raw 8-bit text read as UTF-8 where it is valid and as windows-1252
    /// where it is not. The value is never held whole by the parser, and a piece
    /// has no particular size.
    fn header_content(&mut self, _text: &str) -> ParseResult<()> {
        Ok(())
    }

    /// A piece of a header's value delivered raw: the bytes as they arrived,
    /// unfolded (a folded line ending is removed and the white space after it
    /// kept), with nothing decoded.
    fn raw_header_content(&mut self, _bytes: &[u8]) -> ParseResult<()> {
        Ok(())
    }

    /// The value of the header started by [`Self::start_header`] is complete.
    fn end_header(&mut self) -> ParseResult<()> {
        Ok(())
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
            fn header_delivery(&mut self, name: &str) -> HeaderDelivery {
                (**self).header_delivery(name)
            }
            fn start_header(&mut self, name: &str) -> ParseResult<()> {
                (**self).start_header(name)
            }
            fn header_content(&mut self, text: &str) -> ParseResult<()> {
                (**self).header_content(text)
            }
            fn raw_header_content(&mut self, bytes: &[u8]) -> ParseResult<()> {
                (**self).raw_header_content(bytes)
            }
            fn end_header(&mut self) -> ParseResult<()> {
                (**self).end_header()
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
