//! DKIM raw byte capture (gumdrop `org.bluezoo.gumdrop.smtp.auth`).

mod capture_bridge;
mod message_parser;
mod raw_capture;
mod raw_header;

pub use message_parser::DkimMessageParser;
pub use raw_header::RawHeader;
