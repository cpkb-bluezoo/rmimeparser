//! English error message strings (from gumdrop `L10N.properties`).

pub struct MIMEMessages;

impl MIMEMessages {
    pub const FIELD_NAME_EMPTY: &'static str = "field-name is empty";
    pub const HEADER_LINE_TOO_LONG: &'static str =
        "Header line exceeds maximum of 998 characters (RFC 5322 §2.1.1)";
    pub const HEADER_VALUE_TOO_LONG: &'static str =
        "Unfolded header value exceeds maximum of {0} bytes";
    pub const ILLEGAL_FIELD_NAME_CHAR: &'static str = "Illegal field-name character";
    pub const HEADER_LINE_DOES_NOT_FIT: &'static str =
        "Header line does not fit the receive buffer";
    pub const NO_COLON_IN_HEADER: &'static str = "No colon in header";
    pub const NO_FIELD_NAME: &'static str = "No field-name";
    pub const NO_HANDLER: &'static str = "No handler set";
    pub const UNCLOSED_BOUNDARY: &'static str = "Unclosed multipart boundary: {0}";
    pub const UNEXPECTED_PARSER_STATE: &'static str =
        "Unexpected parser state {0} in body processing";
}

pub(crate) fn format_header_value_too_long(max_bytes: usize) -> String {
    MIMEMessages::HEADER_VALUE_TOO_LONG.replace("{0}", &max_bytes.to_string())
}

pub(crate) fn format_unclosed_boundary(boundary: &str) -> String {
    MIMEMessages::UNCLOSED_BOUNDARY.replace("{0}", boundary)
}
