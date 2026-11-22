# Changelog

## Unreleased

### Added

- `ParserLimits::max_multipart_depth` (default 32, `None` in `unlimited()`)
  bounds the nesting of multipart entities. A `multipart` entity that would
  exceed it is a parse error naming the limit.

### Fixed

- `ParserLimits::unlimited()` no longer panics (arithmetic overflow in debug
  builds) when a `Content-Type` or `Content-Disposition` header is parsed.
