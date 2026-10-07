use std::fmt;

use super::parameter::Parameter;

#[derive(Debug, Clone)]
pub struct ContentType {
    primary_type: String,
    sub_type: String,
    parameters: Option<Vec<Parameter>>,
}

impl ContentType {
    pub fn new(
        primary_type: impl Into<String>,
        sub_type: impl Into<String>,
        parameters: Option<Vec<Parameter>>,
    ) -> Self {
        let primary_type = primary_type.into();
        let sub_type = sub_type.into();
        let parameters = non_empty(parameters);
        Self {
            primary_type,
            sub_type,
            parameters,
        }
    }

    pub fn primary_type(&self) -> &str {
        &self.primary_type
    }

    pub fn sub_type(&self) -> &str {
        &self.sub_type
    }

    pub fn is_primary_type(&self, primary: &str) -> bool {
        self.primary_type.eq_ignore_ascii_case(primary)
    }

    pub fn is_sub_type(&self, sub: &str) -> bool {
        self.sub_type.eq_ignore_ascii_case(sub)
    }

    pub fn is_mime_type(&self, primary: &str, sub: &str) -> bool {
        self.is_primary_type(primary) && self.is_sub_type(sub)
    }

    /// Returns true if this content type matches `type/subtype` (case insensitive).
    pub fn is_mime_type_str(&self, mime_type: &str) -> bool {
        let Some(slash) = mime_type.find('/') else {
            return false;
        };
        let primary = &mime_type[..slash];
        let sub = &mime_type[slash + 1..];
        if primary.is_empty() || sub.is_empty() {
            return false;
        }
        self.is_mime_type(primary, sub)
    }

    pub fn parameters(&self) -> Option<&[Parameter]> {
        self.parameters.as_deref()
    }

    pub fn get_parameter(&self, name: &str) -> Option<&str> {
        self.parameter(name)
    }

    /// The first parameter called `name` (case-insensitive).
    pub fn parameter(&self, name: &str) -> Option<&str> {
        find_parameter(&self.parameters, name)
    }

    pub fn has_parameter(&self, name: &str) -> bool {
        self.parameter(name).is_some()
    }

    pub fn to_header_value(&self) -> String {
        let mut buf = format!("{}/{}", self.primary_type, self.sub_type);
        if let Some(params) = &self.parameters {
            for param in params {
                buf.push_str("; ");
                buf.push_str(&param.to_header_value());
            }
        }
        buf
    }
}

impl PartialEq for ContentType {
    fn eq(&self, other: &Self) -> bool {
        self.primary_type.eq_ignore_ascii_case(&other.primary_type)
            && self.sub_type.eq_ignore_ascii_case(&other.sub_type)
            && self.parameters == other.parameters
    }
}

impl Eq for ContentType {}

impl std::hash::Hash for ContentType {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.primary_type.to_ascii_lowercase().hash(state);
        self.sub_type.to_ascii_lowercase().hash(state);
        if let Some(params) = &self.parameters {
            params.hash(state);
        }
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.primary_type, self.sub_type)?;
        if let Some(params) = &self.parameters {
            for param in params {
                write!(f, "; {param}")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ContentDisposition {
    disposition_type: String,
    parameters: Option<Vec<Parameter>>,
}

impl ContentDisposition {
    pub fn new(
        disposition_type: impl Into<String>,
        parameters: Option<Vec<Parameter>>,
    ) -> Self {
        let disposition_type = disposition_type.into();
        let parameters = non_empty(parameters);
        Self {
            disposition_type,
            parameters,
        }
    }

    pub fn disposition_type(&self) -> &str {
        &self.disposition_type
    }

    pub fn is_disposition_type(&self, disposition_type: &str) -> bool {
        self.disposition_type
            .eq_ignore_ascii_case(disposition_type)
    }

    pub fn parameters(&self) -> Option<&[Parameter]> {
        self.parameters.as_deref()
    }

    pub fn get_parameter(&self, name: &str) -> Option<&str> {
        self.parameter(name)
    }

    /// The first parameter called `name` (case-insensitive).
    pub fn parameter(&self, name: &str) -> Option<&str> {
        find_parameter(&self.parameters, name)
    }

    pub fn has_parameter(&self, name: &str) -> bool {
        self.parameter(name).is_some()
    }

    pub fn to_header_value(&self) -> String {
        let mut buf = self.disposition_type.clone();
        if let Some(params) = &self.parameters {
            for param in params {
                buf.push_str("; ");
                buf.push_str(&param.to_header_value());
            }
        }
        buf
    }
}

impl PartialEq for ContentDisposition {
    fn eq(&self, other: &Self) -> bool {
        self.disposition_type
            .eq_ignore_ascii_case(&other.disposition_type)
            && self.parameters == other.parameters
    }
}

impl Eq for ContentDisposition {}

impl std::hash::Hash for ContentDisposition {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.disposition_type.to_ascii_lowercase().hash(state);
        if let Some(params) = &self.parameters {
            params.hash(state);
        }
    }
}

impl fmt::Display for ContentDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.disposition_type)?;
        if let Some(params) = &self.parameters {
            for param in params {
                write!(f, "; {param}")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimeVersion {
    Version1_0,
}

impl MimeVersion {
    pub const VERSION_1_0: Self = Self::Version1_0;
    pub const V1_0: Self = Self::Version1_0;

    pub fn parse(value: &str) -> Option<Self> {
        if value.trim() == "1.0" {
            Some(Self::Version1_0)
        } else {
            None
        }
    }
}

impl fmt::Display for MimeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version1_0 => f.write_str("1.0"),
        }
    }
}

fn non_empty(parameters: Option<Vec<Parameter>>) -> Option<Vec<Parameter>> {
    parameters.filter(|p| !p.is_empty())
}

/// Parameter lists are short; a scan beats hashing and allocating keys.
fn find_parameter<'p>(parameters: &'p Option<Vec<Parameter>>, name: &str) -> Option<&'p str> {
    parameters
        .as_ref()?
        .iter()
        .find(|p| p.name().eq_ignore_ascii_case(name))
        .map(Parameter::value)
}
