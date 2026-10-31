//! Collectors that rebuild the materialized types from the parser's events.
//!
//! The parser delivers a `Content-Type` as events so that nothing has to be
//! held; a handler that does want a [`ContentType`] puts the events through a
//! collector and takes it at the end:
//!
//! ```ignore
//! fn start_content_type(&mut self, primary: &str, sub: &str) -> ParseResult<()> {
//!     self.content_type.start(primary, sub);
//!     Ok(())
//! }
//! fn start_parameter(&mut self, name: &str, language: Option<&str>) -> ParseResult<()> {
//!     self.content_type.start_parameter(name, language);
//!     Ok(())
//! }
//! // ... parameter_content, end_parameter likewise
//! fn end_content_type(&mut self) -> ParseResult<()> {
//!     let content_type = self.content_type.finish();
//!     Ok(())
//! }
//! ```
//!
//! Parameters are kept by the usual rule: the first of a name wins, except that
//! an RFC 2231 extended value replaces a plain one.

use super::content_types::ContentDisposition;
use super::content_types::ContentType;
use super::parameter::Parameter;

/// Collects the parameters of a `Content-Type` or `Content-Disposition`.
#[derive(Debug, Default)]
pub struct ParameterCollector {
    parameters: Vec<Parameter>,
    /// Whether each of `parameters` was an extended value.
    extended: Vec<bool>,
    name: String,
    value: String,
    is_extended: bool,
    open: bool,
}

impl ParameterCollector {
    pub fn clear(&mut self) {
        self.parameters.clear();
        self.extended.clear();
        self.open = false;
    }

    pub fn start_parameter(&mut self, name: &str, language: Option<&str>) {
        self.name.clear();
        self.name.push_str(name);
        self.value.clear();
        self.is_extended = language.is_some();
        self.open = true;
    }

    pub fn parameter_content(&mut self, text: &str) {
        self.value.push_str(text);
    }

    pub fn end_parameter(&mut self) {
        if !self.open {
            return;
        }
        self.open = false;
        let existing = self
            .parameters
            .iter()
            .position(|p| p.name().eq_ignore_ascii_case(&self.name));
        let parameter = Parameter::new(
            std::mem::take(&mut self.name),
            std::mem::take(&mut self.value),
        );
        match existing {
            None => {
                self.parameters.push(parameter);
                self.extended.push(self.is_extended);
            }
            Some(at) if self.is_extended && !self.extended[at] => {
                self.parameters[at] = parameter;
                self.extended[at] = true;
            }
            Some(_) => {}
        }
    }

    /// The parameters collected, or `None` if there were none.
    pub fn take(&mut self) -> Option<Vec<Parameter>> {
        self.extended.clear();
        let parameters = std::mem::take(&mut self.parameters);
        (!parameters.is_empty()).then_some(parameters)
    }
}

/// Collects a [`ContentType`] from `start_content_type`, `start_parameter`,
/// `parameter_content` and `end_parameter`.
#[derive(Debug, Default)]
pub struct ContentTypeCollector {
    primary: String,
    sub: String,
    parameters: ParameterCollector,
}

impl ContentTypeCollector {
    pub fn start(&mut self, primary: &str, sub: &str) {
        self.parameters.clear();
        self.primary.clear();
        self.primary.push_str(primary);
        self.sub.clear();
        self.sub.push_str(sub);
    }

    pub fn start_parameter(&mut self, name: &str, language: Option<&str>) {
        self.parameters.start_parameter(name, language);
    }

    pub fn parameter_content(&mut self, text: &str) {
        self.parameters.parameter_content(text);
    }

    pub fn end_parameter(&mut self) {
        self.parameters.end_parameter();
    }

    /// The content type, once `end_content_type` has been seen.
    pub fn finish(&mut self) -> ContentType {
        ContentType::new(
            std::mem::take(&mut self.primary),
            std::mem::take(&mut self.sub),
            self.parameters.take(),
        )
    }
}

/// Collects a [`ContentDisposition`] likewise.
#[derive(Debug, Default)]
pub struct ContentDispositionCollector {
    kind: String,
    parameters: ParameterCollector,
}

impl ContentDispositionCollector {
    pub fn start(&mut self, kind: &str) {
        self.parameters.clear();
        self.kind.clear();
        self.kind.push_str(kind);
    }

    pub fn start_parameter(&mut self, name: &str, language: Option<&str>) {
        self.parameters.start_parameter(name, language);
    }

    pub fn parameter_content(&mut self, text: &str) {
        self.parameters.parameter_content(text);
    }

    pub fn end_parameter(&mut self) {
        self.parameters.end_parameter();
    }

    /// The disposition, once `end_content_disposition` has been seen.
    pub fn finish(&mut self) -> ContentDisposition {
        ContentDisposition::new(std::mem::take(&mut self.kind), self.parameters.take())
    }
}
