//! RFC 2047 encoded-word support.

mod decoder;
mod encoder;
mod stream;

pub use decoder::Decoder;
pub use encoder::{Encoder, MAX_ENCODED_WORD_LENGTH};
pub use stream::HeaderTextDecoder;
