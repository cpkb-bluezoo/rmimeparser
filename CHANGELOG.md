# Changelog

## Unreleased

### Added

- `UuScanner`, with `UuHandler` and `UuScannerLimits`: a push scanner that
  finds uuencoded blocks inline in a text body and delivers the text, each
  block's `begin` line, its decoded bytes and whether it was complete.
- `ParserLimits::max_multipart_depth` (default 32, `None` in `unlimited()`)
  bounds the nesting of multipart entities. A `multipart` entity that would
  exceed it is a parse error naming the limit.

### Fixed

- `ParserLimits::unlimited()` no longer panics (arithmetic overflow in debug
  builds) when a `Content-Type` or `Content-Disposition` header is parsed.
