//! Push-based MIME and RFC 5322 message parser and writer (gumdrop port, rprotobuf-style).
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
    Base64Decoder, Base64Encoder, ContentDisposition, ContentDispositionParser, ContentId,
    ContentIdParser, ContentType, ContentTypeParser, DefaultHandler, Handler,
    HeaderLineTooLongError, HeaderValueTooLongError, Locator, MIMEMessages, MimeHandler,
    MimeLocator, MimeParseError, MimeParser, MimeVersion, MimeWriteError, MimeWriter, Parameter,
    ParseError, ParseResult, QuotedPrintableDecoder, QuotedPrintableEncoder, MIMEUtils,
    ParserLocator, WriteResult, decode_base64, decode_header_bytes, decode_quoted_printable,
    decode_slice, decode_token_header_value, encode_base64, encode_quoted_printable,
    estimate_base64_decoded_size, estimate_qp_decoded_size, index_of, is_special, is_token,
    is_valid_boundary, write_folded_header, BASE64_MAX_LINE_LENGTH, HARD_LINE_LIMIT,
    SOFT_LINE_LIMIT,
};
pub use rfc2047::{Decoder as Rfc2047Decoder, Encoder as Rfc2047Encoder};
pub use rfc2231::Decoder as Rfc2231Decoder;
pub use rfc5322::{
    Address, EmailAddress, EmailAddressParser, GroupEmailAddress, MessageDateTimeFormatter,
    MessageHandler, MessageIdParser, MessageParser, MessageWriter, ObsoleteParserUtils,
    OffsetDateTime,
};

pub type ContentID = ContentId;
pub type ContentIDParser = ContentIdParser;
pub type MIMEVersion = MimeVersion;
