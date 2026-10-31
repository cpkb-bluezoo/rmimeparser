use std::fmt;

use crate::mime::handler::Locator;

/// Error during MIME parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    message: String,
}

impl ParseError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// An error that says where in the message it was found.
    pub fn with_locator(message: impl Into<String>, locator: &dyn Locator) -> Self {
        Self {
            message: format!(
                "{} (line {}, column {}, offset {})",
                message.into(),
                locator.line_number(),
                locator.column_number(),
                locator.offset()
            ),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ParseError {}

pub type ParseResult<T> = Result<T, ParseError>;
