//! MIME-Version header value.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimeVersion {
    Version1_0,
}

impl MimeVersion {
    pub fn parse(s: &str) -> Option<Self> {
        if s.trim() == "1.0" {
            Some(Self::Version1_0)
        } else {
            None
        }
    }
}

impl std::fmt::Display for MimeVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Version1_0 => write!(f, "1.0"),
        }
    }
}
