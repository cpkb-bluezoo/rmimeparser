use std::collections::HashMap;
use std::fmt;

use super::parameter::Parameter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDisposition {
    disposition_type: String,
    parameters: Option<Vec<Parameter>>,
    parameter_map: Option<HashMap<String, String>>,
}

impl ContentDisposition {
    pub fn new(disposition_type: impl Into<String>, parameters: Option<Vec<Parameter>>) -> Self {
        let disposition_type = disposition_type.into();
        let (parameters, parameter_map) = build_parameter_map(parameters);
        Self {
            disposition_type,
            parameters,
            parameter_map,
        }
    }

    pub fn disposition_type(&self) -> &str {
        &self.disposition_type
    }

    pub fn get_parameter(&self, name: &str) -> Option<&str> {
        self.parameter_map
            .as_ref()
            .and_then(|m| m.get(&name.to_ascii_lowercase()))
            .map(String::as_str)
    }
}

impl fmt::Display for ContentDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.disposition_type)
    }
}

fn build_parameter_map(
    parameters: Option<Vec<Parameter>>,
) -> (Option<Vec<Parameter>>, Option<HashMap<String, String>>) {
    let Some(parameters) = parameters.filter(|p| !p.is_empty()) else {
        return (None, None);
    };
    let mut map = HashMap::new();
    for p in &parameters {
        map.entry(p.name().to_ascii_lowercase())
            .or_insert_with(|| p.value().to_string());
    }
    (Some(parameters), Some(map))
}
