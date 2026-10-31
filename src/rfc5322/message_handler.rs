//! RFC 5322 message handler callbacks.

use crate::mime::error::ParseResult;
use crate::mime::ContentId;
use crate::mime::MimeHandler as MimeHandler;
use crate::rfc5322::email_address::EmailAddress;
use crate::rfc5322::message_date_time::OffsetDateTime;
use crate::rfc5322::obsolete_structure_type::ObsoleteStructureType;

/// RFC 5322 message handler (extends MIME handler).
pub trait MessageHandler: MimeHandler {
    fn header(&mut self, _name: &str, _value: &str) -> ParseResult<()> {
        Ok(())
    }
    fn unexpected_header(&mut self, _name: &str, _value: &str) -> ParseResult<()> {
        Ok(())
    }
    fn date_header(&mut self, _name: &str, _date: OffsetDateTime) -> ParseResult<()> {
        Ok(())
    }
    fn address_header(&mut self, _name: &str, _addresses: &[EmailAddress]) -> ParseResult<()> {
        Ok(())
    }
    fn message_id_header(&mut self, _name: &str, _content_ids: &[ContentId]) -> ParseResult<()> {
        Ok(())
    }
    fn obsolete_structure(&mut self, _kind: ObsoleteStructureType) -> ParseResult<()> {
        Ok(())
    }
}

macro_rules! forward_message_handler {
    ($target:ty) => {
        impl<H: MessageHandler + ?Sized> MessageHandler for $target {
            fn header(&mut self, name: &str, value: &str) -> ParseResult<()> {
                (**self).header(name, value)
            }
            fn unexpected_header(&mut self, name: &str, value: &str) -> ParseResult<()> {
                (**self).unexpected_header(name, value)
            }
            fn date_header(&mut self, name: &str, date: OffsetDateTime) -> ParseResult<()> {
                (**self).date_header(name, date)
            }
            fn address_header(&mut self, name: &str, addresses: &[EmailAddress]) -> ParseResult<()> {
                (**self).address_header(name, addresses)
            }
            fn message_id_header(&mut self, name: &str, content_ids: &[ContentId]) -> ParseResult<()> {
                (**self).message_id_header(name, content_ids)
            }
            fn obsolete_structure(&mut self, kind: ObsoleteStructureType) -> ParseResult<()> {
                (**self).obsolete_structure(kind)
            }
        }
    };
}

forward_message_handler!(&mut H);
forward_message_handler!(Box<H>);
