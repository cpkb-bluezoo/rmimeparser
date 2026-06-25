//! RFC 5322 email address value type.

use std::fmt;

/// Internet email address (RFC 5322 §3.4).
#[derive(Debug, Clone)]
pub struct EmailAddress {
    display_name: Option<String>,
    local_part: String,
    domain: String,
    comments: Option<Vec<String>>,
    simple_address: bool,
}

impl EmailAddress {
    pub fn new(
        display_name: Option<String>,
        local_part: impl Into<String>,
        domain: impl Into<String>,
        simple_address: bool,
    ) -> Self {
        Self {
            display_name,
            local_part: local_part.into(),
            domain: domain.into(),
            comments: None,
            simple_address,
        }
    }

    pub fn with_comments(
        display_name: Option<String>,
        local_part: impl Into<String>,
        domain: impl Into<String>,
        comments: Vec<String>,
    ) -> Self {
        Self {
            display_name,
            local_part: local_part.into(),
            domain: domain.into(),
            comments: Some(comments),
            simple_address: false,
        }
    }

    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    pub fn local_part(&self) -> &str {
        &self.local_part
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn address(&self) -> String {
        if self.local_part.is_empty() && self.domain.is_empty() {
            return String::new();
        }
        format!("{}@{}", self.local_part, self.domain)
    }

    pub fn envelope_address(&self) -> String {
        self.address()
    }

    pub fn comments(&self) -> Option<&[String]> {
        self.comments.as_deref()
    }

    pub fn is_simple_address(&self) -> bool {
        self.simple_address
    }
}

impl PartialEq for EmailAddress {
    fn eq(&self, other: &Self) -> bool {
        self.local_part == other.local_part
            && self.domain.eq_ignore_ascii_case(&other.domain)
    }
}

impl Eq for EmailAddress {}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = &self.display_name {
            if !name.is_empty() {
                write!(f, "{name} ")?;
            }
        }
        write!(f, "<{}>", self.address())?;
        if let Some(comments) = &self.comments {
            for comment in comments {
                write!(f, " ({comment})")?;
            }
        }
        Ok(())
    }
}
