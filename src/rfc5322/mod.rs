mod collectors;
mod email_address;
mod email_address_parser;
mod group_email_address;
mod message_date_time;
mod message_handler;
pub(crate) mod stream;
mod message_writer;
mod obsolete_parser_utils;
mod obsolete_structure_type;

pub(crate) mod headers;
pub(crate) mod message_parser;

pub use collectors::{AddressListCollector, MessageIdListCollector};
pub use email_address::EmailAddress;
pub use email_address_parser::EmailAddressParser;
pub use group_email_address::{Address, GroupEmailAddress};
pub use message_date_time::{MessageDateTimeFormatter, OffsetDateTime};
pub use message_handler::MessageHandler;
pub use crate::mime::MessageIdParser;
pub use message_parser::MessageParser;
pub use message_writer::MessageWriter;
pub use obsolete_parser_utils::ObsoleteParserUtils;
pub use obsolete_structure_type::ObsoleteStructureType;
