pub mod content_types;
pub mod content_id_parser;
pub mod content_type_parser;
pub mod decoders;
pub mod encoders;
pub mod error;
pub mod folding;
pub mod handler;
pub mod messages;
pub mod parameter;
pub mod parser;
pub mod utils;
pub mod wire_sink;
pub mod write_error;
pub mod writer;

pub use content_types::{
    ContentDisposition, ContentId, ContentType, MimeVersion,
};
pub use content_type_parser::{ContentDispositionParser, ContentTypeParser};
pub use content_id_parser::ContentIdParser;
pub use decoders::{
    decode_base64, decode_quoted_printable, estimate_base64_decoded_size,
    estimate_qp_decoded_size, Base64Decoder, QuotedPrintableDecoder, BASE64_MAX_LINE_LENGTH,
};
pub use encoders::{
    encode_base64, encode_quoted_printable, Base64Encoder, QuotedPrintableEncoder,
};
pub use error::{
    HeaderLineTooLongError, HeaderValueTooLongError, MimeParseError, ParseResult,
};
pub use folding::{write_folded_header, HARD_LINE_LIMIT, SOFT_LINE_LIMIT};
pub use handler::{DefaultHandler, Handler, Locator, MimeHandler, MimeLocator, ParserLocator};
pub use parser::{check_boundary, BoundaryMatch, MessageHeaderState, MimeParser};
pub use messages::MIMEMessages;
pub use parameter::Parameter;
pub use utils::{
    decode_header_bytes, decode_slice, decode_token_header_value, index_of, is_special, is_token,
    is_valid_boundary, MIMEUtils,
};
pub use write_error::{MimeWriteError, WriteResult};
pub use writer::MimeWriter;

// Gumdrop-style aliases
pub type ParseError = MimeParseError;
pub type ContentID = ContentId;
pub type ContentIDParser = ContentIdParser;
pub type MIMEVersion = MimeVersion;
