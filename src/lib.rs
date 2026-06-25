//! Push-based MIME and RFC 5322 message parser (gumdrop port, rprotobuf-style).
//!
//! Port of gumdrop `org.bluezoo.gumdrop.mime` — not Java SAM.

pub mod buffer;
pub mod charset;
pub mod dkim;
pub mod mime;
pub mod rfc2047;
pub mod rfc2231;
pub mod rfc5322;

pub use buffer::ByteCursor;
pub use charset::HeaderCharset;
pub use dkim::{DkimMessageParser, RawHeader};
pub use mime::{
    Base64Decoder, ContentDisposition, ContentDispositionParser, ContentId, ContentIdParser,
    ContentType, ContentTypeParser, DefaultHandler, Handler, HeaderLineTooLongError,
    HeaderValueTooLongError, Locator, MIMEMessages, MimeHandler, MimeLocator, MimeParseError,
    MimeParser, MimeVersion, Parameter, ParseError, ParseResult, QuotedPrintableDecoder,
    MIMEUtils, ParserLocator,
    decode_base64, decode_header_bytes, decode_quoted_printable, decode_slice,
    decode_token_header_value, estimate_base64_decoded_size, estimate_qp_decoded_size,
    index_of, is_special, is_token, is_valid_boundary, BASE64_MAX_LINE_LENGTH,
};
pub use rfc2047::{Decoder as Rfc2047Decoder, Encoder as Rfc2047Encoder};
pub use rfc2231::Decoder as Rfc2231Decoder;
pub use rfc5322::{
    Address, EmailAddress, EmailAddressParser, GroupEmailAddress, MessageDateTimeFormatter,
    MessageHandler, MessageIdParser, MessageParser, ObsoleteParserUtils, OffsetDateTime,
};

pub type ContentID = ContentId;
pub type ContentIDParser = ContentIdParser;
pub type MIMEVersion = MimeVersion;
