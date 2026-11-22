# Changelog

## 0.7.0 - 2026-11-22

### Changed

- **Breaking:** `MimeHandler::content_id` now takes the local part and domain
  (`content_id(&str, &str)`) and `MimeHandler::mime_version` the numbers
  (`mime_version(u32, u32)`, so `1.0` is `(1, 0)`), instead of a `ContentId`
  and a `MimeVersion`. The handler no longer receives a value object for any
  header. `ContentId` and `MimeVersion` remain for `MimeWriter`.

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
