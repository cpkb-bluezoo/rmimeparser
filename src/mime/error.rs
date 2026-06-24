use std::fmt;

use crate::mime::handler::MimeLocator;

/// Error during MIME parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimeParseError {
    message: String,
    offset: i64,
    line_number: i64,
    column_number: i64,
}

impl MimeParseError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            offset: -1,
            line_number: -1,
            column_number: -1,
        }
    }

    pub fn with_locator(message: impl Into<String>, locator: &MimeLocator) -> Self {
        Self {
            message: format!(
                "{} (line {}, column {}, offset {})",
                message.into(),
                locator.line_number,
                locator.column_number,
                locator.offset
            ),
            offset: locator.offset,
            line_number: locator.line_number,
            column_number: locator.column_number,
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MimeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MimeParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderLineTooLongError {
    inner: MimeParseError,
}

impl HeaderLineTooLongError {
    pub fn new(message: impl Into<String>, locator: &MimeLocator) -> Self {
        Self {
            inner: MimeParseError::with_locator(message, locator),
        }
    }
}

impl fmt::Display for HeaderLineTooLongError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl std::error::Error for HeaderLineTooLongError {}

impl From<HeaderLineTooLongError> for MimeParseError {
    fn from(err: HeaderLineTooLongError) -> Self {
        err.inner
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderValueTooLongError {
    inner: MimeParseError,
}

impl HeaderValueTooLongError {
    pub fn new(message: impl Into<String>, locator: &MimeLocator) -> Self {
        Self {
            inner: MimeParseError::with_locator(message, locator),
        }
    }
}

impl fmt::Display for HeaderValueTooLongError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl std::error::Error for HeaderValueTooLongError {}

impl From<HeaderValueTooLongError> for MimeParseError {
    fn from(err: HeaderValueTooLongError) -> Self {
        err.inner
    }
}

pub type ParseResult<T> = Result<T, MimeParseError>;
