//! MIME content-id value.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentId {
    local_part: String,
    domain: String,
}

impl ContentId {
    pub fn new(local_part: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            local_part: local_part.into(),
            domain: domain.into(),
        }
    }

    pub fn local_part(&self) -> &str {
        &self.local_part
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}@{}>", self.local_part, self.domain)
    }
}
