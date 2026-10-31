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
    /// The longest header value once its folded lines are joined. A header is
    /// held whole until its last line has arrived, so this bounds what the
    /// parser holds for one. Default: 32768.
    pub max_header_value_size: Option<usize>,
}

impl Default for ParserLimits {
    fn default() -> Self {
        Self {
            max_header_line_length: Some(998),
            max_header_value_size: Some(32 * 1024),
        }
    }
}

impl ParserLimits {
    /// No limit at all.
    pub fn unlimited() -> Self {
        Self {
            max_header_line_length: None,
            max_header_value_size: None,
        }
    }
}
