//! Raw header bytes for DKIM canonicalization (gumdrop `DKIMMessageParser.RawHeader`).

/// One logical header with wire-format bytes preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHeader {
    name: String,
    bytes: Vec<u8>,
}

impl RawHeader {
    pub fn new(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            bytes,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Raw bytes for DKIM simple header canonicalization (fold CRLFs preserved).
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Bytes with fold line-endings removed (CRLF or bare LF before SP/TAB).
    pub fn bytes_unfolded(&self) -> Vec<u8> {
        let bytes = &self.bytes;
        let mut fold_bytes = 0usize;
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                if i + 2 < bytes.len() {
                    let next = bytes[i + 2];
                    if next == b' ' || next == b'\t' {
                        fold_bytes += 2;
                        i += 2;
                        continue;
                    }
                }
            } else if bytes[i] == b'\n' {
                if i + 1 < bytes.len() {
                    let next = bytes[i + 1];
                    if next == b' ' || next == b'\t' {
                        fold_bytes += 1;
                    }
                }
            }
            i += 1;
        }

        if fold_bytes == 0 {
            return bytes.to_vec();
        }

        let mut result = Vec::with_capacity(bytes.len() - fold_bytes);
        i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                if i + 2 < bytes.len() {
                    let next = bytes[i + 2];
                    if next == b' ' || next == b'\t' {
                        i += 2;
                        continue;
                    }
                }
                result.push(bytes[i]);
                result.push(bytes[i + 1]);
                i += 2;
            } else if bytes[i] == b'\n' {
                if i + 1 < bytes.len() {
                    let next = bytes[i + 1];
                    if next == b' ' || next == b'\t' {
                        i += 1;
                        continue;
                    }
                }
                result.push(bytes[i]);
                i += 1;
            } else {
                result.push(bytes[i]);
                i += 1;
            }
        }
        result
    }

    /// Header as ISO-8859-1 string (byte-preserving).
    pub fn as_string(&self) -> String {
        self.bytes.iter().map(|&b| b as char).collect()
    }

    /// Unfolded header as ISO-8859-1 string.
    pub fn as_string_unfolded(&self) -> String {
        self.bytes_unfolded().iter().map(|&b| b as char).collect()
    }
}
