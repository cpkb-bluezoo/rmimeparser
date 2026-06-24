//! Top-level error type (re-export MIME parse errors).

pub use crate::mime::MimeParseError as ParseError;
pub type ParseResult<T> = Result<T, ParseError>;
