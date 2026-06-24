//! RFC 5322 group address value type.

use std::fmt;

use super::email_address::EmailAddress;

/// Group email address (RFC 5322 §3.4).
#[derive(Debug, Clone)]
pub struct GroupEmailAddress {
    group_name: String,
    members: Vec<EmailAddress>,
    comments: Option<Vec<String>>,
}

impl GroupEmailAddress {
    pub fn new(
        group_name: impl Into<String>,
        members: Vec<EmailAddress>,
        comments: Option<Vec<String>>,
    ) -> Self {
        Self {
            group_name: group_name.into(),
            members,
            comments,
        }
    }

    pub fn local_part(&self) -> &str {
        ""
    }

    pub fn domain(&self) -> &str {
        ""
    }

    pub fn address(&self) -> &str {
        ""
    }

    pub fn group_name(&self) -> &str {
        &self.group_name
    }

    pub fn members(&self) -> &[EmailAddress] {
        &self.members
    }

    pub fn comments(&self) -> Option<&[String]> {
        self.comments.as_deref()
    }
}

impl fmt::Display for GroupEmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.group_name)?;
        for (i, member) in self.members.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{member}")?;
        }
        write!(f, ";")?;
        if let Some(comments) = &self.comments {
            for comment in comments {
                write!(f, " ({comment})")?;
            }
        }
        Ok(())
    }
}

/// Address list entry: individual mailbox or group.
#[derive(Debug, Clone)]
pub enum Address {
    Mailbox(EmailAddress),
    Group(GroupEmailAddress),
}

impl Address {
    pub fn as_mailbox(&self) -> Option<&EmailAddress> {
        match self {
            Self::Mailbox(m) => Some(m),
            Self::Group(_) => None,
        }
    }
}
