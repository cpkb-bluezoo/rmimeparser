//! Errors for MIME / RFC 5322 writing.

use std::fmt;

/// Error during MIME / RFC 5322 writing.
#[derive(Debug)]
pub enum MimeWriteError {
    /// Underlying `Write` failed.
    Io(std::io::Error),
    /// Event called in an illegal writer state.
    InvalidState(String),
    /// Input would produce invalid or unsafe MIME (boundary collision, 7bit, etc.).
    Validation(String),
}

impl MimeWriteError {
    pub fn invalid_state(message: impl Into<String>) -> Self {
        Self::InvalidState(message.into())
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    pub fn message(&self) -> String {
        match self {
            Self::Io(e) => e.to_string(),
            Self::InvalidState(m) | Self::Validation(m) => m.clone(),
        }
    }
}

impl fmt::Display for MimeWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "MIME write I/O error: {e}"),
            Self::InvalidState(m) => write!(f, "MIME write invalid state: {m}"),
            Self::Validation(m) => write!(f, "MIME write validation error: {m}"),
        }
    }
}

impl std::error::Error for MimeWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for MimeWriteError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

pub type WriteResult<T> = Result<T, MimeWriteError>;
