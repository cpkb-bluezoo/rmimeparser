//! Errors for MIME / RFC 5322 writing: the one every writer built on a
//! [`loopbuf::LoopBuf`] returns.

pub use loopbuf::{WriteError, WriteResult};
