//! RFC 5322 message handler callbacks.

use crate::mime::error::ParseResult;
use crate::mime::MimeHandler;
use crate::rfc5322::message_date_time::OffsetDateTime;
use crate::rfc5322::obsolete_structure_type::ObsoleteStructureType;

/// RFC 5322 message handler (extends the MIME handler).
///
/// The headers this layer parses arrive as events, an element at a time, so
/// that a header with many elements is never held: a `To` with a thousand
/// addresses is a thousand [`Self::mailbox`] calls. Every other header, known
/// or not, arrives as unstructured text through [`MimeHandler::start_header`],
/// [`MimeHandler::header_content`] and [`MimeHandler::end_header`].
///
/// An element that cannot be read is reported by
/// [`MimeHandler::malformed_header`]; see there for what follows.
pub trait MessageHandler: MimeHandler {
    /// An address header (`From`, `To`, `Cc`, `Reply-To`, ...) begins. Its
    /// [`Self::mailbox`] and group events follow, then
    /// [`Self::end_address_header`].
    fn start_address_header(&mut self, _name: &str) -> ParseResult<()> {
        Ok(())
    }

    /// A mailbox: `display_name` is decoded, with its quotes, comments and RFC
    /// 2047 encoded words resolved. The local part and domain are as written.
    fn mailbox(
        &mut self,
        _display_name: Option<&str>,
        _local_part: &str,
        _domain: &str,
    ) -> ParseResult<()> {
        Ok(())
    }

    /// A group begins: its members follow as [`Self::mailbox`] calls, then
    /// [`Self::end_group`]. (`undisclosed-recipients:;` is a group with no
    /// members.)
    fn start_group(&mut self, _name: &str) -> ParseResult<()> {
        Ok(())
    }

    fn end_group(&mut self) -> ParseResult<()> {
        Ok(())
    }

    fn end_address_header(&mut self) -> ParseResult<()> {
        Ok(())
    }

    /// A message-id header (`Message-ID`, `In-Reply-To`, `References`, ...)
    /// begins. A [`Self::message_id`] follows for each id, then
    /// [`Self::end_message_id_header`].
    fn start_message_id_header(&mut self, _name: &str) -> ParseResult<()> {
        Ok(())
    }

    fn message_id(&mut self, _local_part: &str, _domain: &str) -> ParseResult<()> {
        Ok(())
    }

    fn end_message_id_header(&mut self) -> ParseResult<()> {
        Ok(())
    }

    /// A `Date` or `Resent-Date`.
    fn date_header(&mut self, _name: &str, _date: OffsetDateTime) -> ParseResult<()> {
        Ok(())
    }

    /// The header being read, or an element of it, is in an obsolete syntax
    /// that RFC 5322 only allows to be read. It is reported once for a header,
    /// before the first event that was affected.
    fn obsolete_structure(&mut self, _kind: ObsoleteStructureType) -> ParseResult<()> {
        Ok(())
    }
}

macro_rules! forward_message_handler {
    ($target:ty) => {
        impl<H: MessageHandler + ?Sized> MessageHandler for $target {
            fn start_address_header(&mut self, name: &str) -> ParseResult<()> {
                (**self).start_address_header(name)
            }
            fn mailbox(
                &mut self,
                display_name: Option<&str>,
                local_part: &str,
                domain: &str,
            ) -> ParseResult<()> {
                (**self).mailbox(display_name, local_part, domain)
            }
            fn start_group(&mut self, name: &str) -> ParseResult<()> {
                (**self).start_group(name)
            }
            fn end_group(&mut self) -> ParseResult<()> {
                (**self).end_group()
            }
            fn end_address_header(&mut self) -> ParseResult<()> {
                (**self).end_address_header()
            }
            fn start_message_id_header(&mut self, name: &str) -> ParseResult<()> {
                (**self).start_message_id_header(name)
            }
            fn message_id(&mut self, local_part: &str, domain: &str) -> ParseResult<()> {
                (**self).message_id(local_part, domain)
            }
            fn end_message_id_header(&mut self) -> ParseResult<()> {
                (**self).end_message_id_header()
            }
            fn date_header(&mut self, name: &str, date: OffsetDateTime) -> ParseResult<()> {
                (**self).date_header(name, date)
            }
            fn obsolete_structure(&mut self, kind: ObsoleteStructureType) -> ParseResult<()> {
                (**self).obsolete_structure(kind)
            }
        }
    };
}

forward_message_handler!(&mut H);
forward_message_handler!(Box<H>);
