/// Limits guarding a parser against hostile input.
///
/// A limit of `None` is no limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserLimits {
    /// The longest header line, line ending not counted. RFC 5322 allows 998.
    /// A line must also fit the ring the parser is given, so a ring smaller
    /// than the longest line it will see is an error however this is set.
    /// Default: 998.
    pub max_header_line_length: Option<usize>,
    /// The longest header name. It has to arrive whole, in the header's first
    /// line. Default: 1024.
    pub max_header_name_length: Option<usize>,
    /// The longest token the grammar of `Content-Type` and `Content-Disposition`
    /// holds to judge: the type, subtype and disposition type, parameter names,
    /// and the charset and language of an extended value. Default: 256.
    pub max_token_length: Option<usize>,
    /// The longest element a parser holds to judge whole: the value of
    /// `Content-Transfer-Encoding`, `Content-ID` and `MIME-Version`, and, in the
    /// RFC 5322 layer, one address, one message-id or a date. A header with many
    /// elements (a long `To` or `References`) is not held: it passes through an
    /// element at a time. Default: 4096.
    pub max_element_length: Option<usize>,
    /// The most a raw-capturing parser ([`crate::DkimMessageParser`]) keeps of
    /// one header, which it retains whole by design. Default: 32768.
    pub max_captured_header_size: Option<usize>,
}

impl Default for ParserLimits {
    fn default() -> Self {
        Self {
            max_header_line_length: Some(998),
            max_header_name_length: Some(1024),
            max_token_length: Some(256),
            max_element_length: Some(4096),
            max_captured_header_size: Some(32 * 1024),
        }
    }
}

impl ParserLimits {
    /// No limit at all.
    pub fn unlimited() -> Self {
        Self {
            max_header_line_length: None,
            max_header_name_length: None,
            max_token_length: None,
            max_element_length: None,
            max_captured_header_size: None,
        }
    }
}
