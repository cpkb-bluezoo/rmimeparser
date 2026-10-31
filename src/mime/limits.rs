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
    /// The longest value, once its folded lines are joined, of a header the
    /// parser holds whole to parse: the MIME headers it understands, and any
    /// header a layer on top asks to be given raw because it holds the value
    /// itself. A header delivered as unstructured text is never held, so this
    /// does not apply to it. Default: 32768.
    pub max_header_value_size: Option<usize>,
}

impl Default for ParserLimits {
    fn default() -> Self {
        Self {
            max_header_line_length: Some(998),
            max_header_name_length: Some(1024),
            max_header_value_size: Some(32 * 1024),
        }
    }
}

impl ParserLimits {
    /// No limit at all.
    pub fn unlimited() -> Self {
        Self {
            max_header_line_length: None,
            max_header_name_length: None,
            max_header_value_size: None,
        }
    }
}
