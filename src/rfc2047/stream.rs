//! Streaming decoder for the text of an unstructured header.
//!
//! Takes the header's unfolded bytes in any chunking and emits decoded text:
//! RFC 2047 encoded words are decoded, whitespace between adjacent encoded words
//! is dropped, leading and trailing whitespace is trimmed, and raw 8-bit bytes
//! are read as UTF-8 where they form valid sequences and as the header's
//! fallback charset where they do not.
//!
//! The decoder holds only a bounded amount: a possible encoded word (at most
//! [`MAX_ENCODED_WORD`] bytes, the RFC's 75 with room for sloppy writers), the
//! whitespace that might sit between two encoded words (at most
//! [`MAX_HELD_WHITESPACE`] bytes), and an unfinished UTF-8 sequence (at most 3 bytes).

use crate::charset::{bytes_to_iso88591, WINDOWS_1252};

use super::decoder::decode_single_encoded_word;

/// The longest possible encoded word held while it is being recognised. The RFC
/// limits one to 75 bytes; a longer candidate is text.
pub const MAX_ENCODED_WORD: usize = 256;

/// The most whitespace held back to see whether an encoded word follows it.
/// More than this is emitted without waiting.
pub const MAX_HELD_WHITESPACE: usize = 256;

/// Text is handed on in chunks of about this many bytes.
const CHUNK: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Recognising {
    /// Not inside a possible encoded word.
    No,
    /// `held` is `=?` and the charset so far, or the rest of the word.
    Word,
}

/// See the module documentation.
pub struct HeaderTextDecoder {
    smtp_utf8: bool,
    recognising: Recognising,
    /// A possible encoded word, from its `=`.
    held: [u8; MAX_ENCODED_WORD],
    held_len: usize,
    /// How many `?` `held` has after its opening `=?`: the word ends at the
    /// third, when an `=` follows it.
    word_questions: usize,
    /// Whitespace not yet decided: dropped between two encoded words, trailing,
    /// or leading, and otherwise emitted.
    whitespace: [u8; MAX_HELD_WHITESPACE],
    whitespace_len: usize,
    /// Something other than whitespace has been emitted or is pending.
    started: bool,
    /// The last thing emitted was an encoded word.
    after_word: bool,
    /// The start of a UTF-8 sequence, or of bytes that proved not to be one.
    carry: [u8; 4],
    carry_len: usize,
    carry_need: usize,
    /// Decoded text waiting to be handed on.
    out: String,
}

impl HeaderTextDecoder {
    /// A decoder for headers read as ISO-8859-1/windows-1252 where they are not
    /// UTF-8, or, with `smtp_utf8`, as ISO-8859-1 where they are not UTF-8.
    pub fn new(smtp_utf8: bool) -> Self {
        Self {
            smtp_utf8,
            recognising: Recognising::No,
            held: [0; MAX_ENCODED_WORD],
            held_len: 0,
            word_questions: 0,
            whitespace: [0; MAX_HELD_WHITESPACE],
            whitespace_len: 0,
            started: false,
            after_word: false,
            carry: [0; 4],
            carry_len: 0,
            carry_need: 0,
            out: String::new(),
        }
    }

    /// Readies the decoder for another header.
    pub fn reset(&mut self) {
        self.recognising = Recognising::No;
        self.held_len = 0;
        self.whitespace_len = 0;
        self.started = false;
        self.after_word = false;
        self.carry_len = 0;
        self.carry_need = 0;
        self.out.clear();
    }

    /// Decodes `bytes`, handing decoded text to `emit` as it is ready. What
    /// might still change (a possible encoded word, whitespace) is kept for the
    /// next call.
    pub fn feed<E>(
        &mut self,
        bytes: &[u8],
        emit: &mut impl FnMut(&str) -> Result<(), E>,
    ) -> Result<(), E> {
        if self.out.capacity() == 0 {
            // Once, so a header does not grow it a doubling at a time
            self.out.reserve(2 * CHUNK);
        }
        let mut i = 0;
        while i < bytes.len() {
            // Ordinary printable ASCII is the bulk of any header: take a run,
            // and in it a single space with a word either side, which needs no
            // deciding.
            if self.recognising == Recognising::No && self.carry_len == 0 {
                let lone_space_ok = self.started && self.whitespace_len == 0;
                let mut j = i;
                while j < bytes.len() {
                    let b = bytes[j];
                    let lone_space = b == b' '
                        && (j > i || lone_space_ok)
                        && bytes.get(j + 1).is_some_and(|&n| PLAIN[n as usize]);
                    if PLAIN[b as usize] || lone_space {
                        j += 1;
                    } else {
                        break;
                    }
                }
                if j > i {
                    self.settle_whitespace();
                    self.started = true;
                    self.after_word = false;
                    self.out
                        .push_str(std::str::from_utf8(&bytes[i..j]).unwrap());
                    i = j;
                    self.flush_if_full(emit)?;
                    continue;
                }
            }
            self.byte(bytes[i]);
            i += 1;
            self.flush_if_full(emit)?;
        }
        self.flush(emit)
    }

    /// Ends the header: what is still held is text (leading and trailing
    /// whitespace is dropped, so trailing whitespace is not emitted).
    pub fn finish<E>(&mut self, emit: &mut impl FnMut(&str) -> Result<(), E>) -> Result<(), E> {
        // reading the held bytes again may open a new possible word
        while self.recognising == Recognising::Word {
            self.fail_word();
        }
        self.flush_carry();
        self.whitespace_len = 0;
        self.flush(emit)
    }

    fn byte(&mut self, b: u8) {
        if self.recognising == Recognising::Word {
            self.word_byte(b);
            return;
        }
        match b {
            b' ' | b'\t' => {
                self.flush_carry();
                if self.started {
                    if self.whitespace_len >= MAX_HELD_WHITESPACE {
                        self.settle_whitespace();
                        self.after_word = false;
                    }
                    self.whitespace[self.whitespace_len] = b;
                    self.whitespace_len += 1;
                }
            }
            b'=' => {
                self.flush_carry();
                self.recognising = Recognising::Word;
                self.held[0] = b;
                self.held_len = 1;
                self.word_questions = 0;
            }
            0x80..=0xFF => self.high_byte(b),
            _ => {
                self.flush_carry();
                self.settle_whitespace();
                self.started = true;
                self.after_word = false;
                self.out.push(b as char);
            }
        }
    }

    /// A byte of a possible encoded word.
    fn word_byte(&mut self, b: u8) {
        // `held` is full: it is not an encoded word, whatever follows
        if self.held_len == MAX_ENCODED_WORD {
            self.fail_word();
            self.byte(b);
            return;
        }
        self.held[self.held_len] = b;
        self.held_len += 1;
        let n = self.held_len;
        // `=` then `?` is the start; anything else is just an equals sign
        if n == 2 && b != b'?' {
            self.fail_word();
            return;
        }
        // The end: the `?` that closes the word, then `=`. (The text of a
        // Q-encoded word may well start with `=`.)
        let closing = b == b'=' && self.held[n - 2] == b'?' && self.word_questions >= 3;
        if b == b'?' && n > 2 {
            self.word_questions += 1;
        }
        if closing {
            if let Some(decoded) = self.decode_held() {
                self.recognising = Recognising::No;
                self.held_len = 0;
                // whitespace between two encoded words is not part of the text
                if self.after_word {
                    self.whitespace_len = 0;
                } else {
                    self.settle_whitespace();
                }
                self.started = true;
                self.after_word = true;
                self.out.push_str(&decoded);
            } else {
                self.fail_word();
            }
        }
    }

    /// `held` is `=?charset?E?text?=`: its decoded text, or `None` if it is not
    /// an encoded word after all.
    fn decode_held(&self) -> Option<String> {
        let inner = &self.held[2..self.held_len - 2];
        let mut parts = inner.splitn(3, |&b| b == b'?');
        let charset = parts.next()?;
        let encoding = parts.next()?;
        let text = parts.next()?;
        if charset.is_empty() || encoding.len() != 1 {
            return None;
        }
        let encoding = match encoding[0] {
            b'B' | b'b' => 'B',
            b'Q' | b'q' => 'Q',
            _ => return None,
        };
        decode_single_encoded_word(
            &bytes_to_iso88591(charset),
            encoding,
            &bytes_to_iso88591(text),
        )
        .ok()
    }

    /// What was held was not an encoded word: its first byte is text, and the
    /// rest is read again, since it may hold the start of one.
    fn fail_word(&mut self) {
        let held = self.held;
        let n = self.held_len;
        self.held_len = 0;
        self.recognising = Recognising::No;
        self.settle_whitespace();
        self.started = true;
        self.after_word = false;
        self.out.push(held[0] as char);
        for &b in &held[1..n] {
            self.byte(b);
        }
    }

    /// Emits the held whitespace: it is not leading, trailing or between two
    /// encoded words.
    fn settle_whitespace(&mut self) {
        if self.whitespace_len > 0 {
            // ASCII whitespace
            for &b in &self.whitespace[..self.whitespace_len] {
                self.out.push(b as char);
            }
            self.whitespace_len = 0;
        }
    }

    /// A byte of 0x80 or more outside an encoded word: part of a UTF-8
    /// sequence if it can be, otherwise the fallback charset's character.
    fn high_byte(&mut self, b: u8) {
        if self.carry_len == 0 {
            let need = match b {
                0xC2..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF4 => 4,
                _ => {
                    self.fallback(b);
                    return;
                }
            };
            self.carry[0] = b;
            self.carry_len = 1;
            self.carry_need = need;
            return;
        }
        if b & 0xC0 != 0x80 {
            // not a continuation: what was held is not a sequence
            self.flush_carry();
            self.high_byte(b);
            return;
        }
        self.carry[self.carry_len] = b;
        self.carry_len += 1;
        if self.carry_len == self.carry_need {
            let bytes = self.carry;
            let n = self.carry_len;
            match std::str::from_utf8(&bytes[..n]) {
                Ok(s) => {
                    self.carry_len = 0;
                    self.settle_whitespace();
                    self.started = true;
                    self.after_word = false;
                    self.out.push_str(s);
                }
                Err(_) => self.flush_carry(),
            }
        }
    }

    fn fallback(&mut self, b: u8) {
        self.settle_whitespace();
        self.started = true;
        self.after_word = false;
        let c = if self.smtp_utf8 {
            b as char
        } else {
            WINDOWS_1252[b as usize]
        };
        self.out.push(c);
    }

    /// An unfinished UTF-8 sequence is not one: its bytes are fallback text.
    fn flush_carry(&mut self) {
        let bytes = self.carry;
        let n = self.carry_len;
        self.carry_len = 0;
        for &b in &bytes[..n] {
            self.fallback(b);
        }
    }

    fn flush_if_full<E>(&mut self, emit: &mut impl FnMut(&str) -> Result<(), E>) -> Result<(), E> {
        if self.out.len() >= CHUNK {
            self.flush(emit)?;
        }
        Ok(())
    }

    fn flush<E>(&mut self, emit: &mut impl FnMut(&str) -> Result<(), E>) -> Result<(), E> {
        if !self.out.is_empty() {
            let result = emit(&self.out);
            self.out.clear();
            result?;
        }
        Ok(())
    }
}

/// Printable ASCII with no special treatment here: not white space, `=` or
/// DEL.
static PLAIN: [bool; 256] = {
    let mut table = [false; 256];
    let mut b = 0x21;
    while b < 0x7F {
        table[b] = b != b'=' as usize;
        b += 1;
    }
    table
};
