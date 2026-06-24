//! Obsolete but recoverable RFC 5322 structure types.

/// Types of obsolete but recoverable message structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObsoleteStructureType {
    ObsoleteFoldingWhitespace,
    ObsoleteHeaderSyntax,
    ObsoleteDateTimeSyntax,
    ObsoleteAddressSyntax,
    ObsoleteMessageIdSyntax,
    ObsoleteStructuredParameters,
}
