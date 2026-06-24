//! Byte-buffer cursor matching gumdrop's `ByteBuffer` position/limit contract.

/// Read-only byte slice with a movable position (Java `ByteBuffer` read mode).
#[derive(Debug, Clone)]
pub struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
    limit: usize,
}

impl<'a> ByteCursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            limit: data.len(),
        }
    }

    pub fn from_slice(data: &'a [u8], pos: usize, limit: usize) -> Self {
        Self { data, pos, limit }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
    }

    pub fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.pos)
    }

    pub fn has_remaining(&self) -> bool {
        self.pos < self.limit
    }

    pub fn get(&self, index: usize) -> u8 {
        self.data[index]
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.data
    }

    pub fn slice(&self) -> &'a [u8] {
        &self.data[self.pos..self.limit]
    }

    pub fn duplicate(&self) -> Self {
        self.clone()
    }

    pub fn advance(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.limit);
    }

    pub fn consume_to_limit(&mut self) {
        self.pos = self.limit;
    }
}

/// Finds the first occurrence of `target` between position and limit.
pub fn index_of(cursor: &ByteCursor<'_>, target: u8) -> Option<usize> {
    cursor
        .slice()
        .iter()
        .position(|&b| b == target)
        .map(|i| cursor.position() + i)
}
