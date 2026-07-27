//! Internal byte-reading helper (`cursor`)
//!
//! Provides bounds-checked cursor-reading primitives for the `reader`
//! module to use when parsing message bodies. Every method returns a
//! `ProtocolError` on out-of-bounds access and never panics (a
//! prerequisite for satisfying Property 51).

use super::ProtocolError;

pub(crate) struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        ByteReader { buf, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        let byte = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| ProtocolError::Malformed("unexpected end of message body".into()))?;
        self.pos += 1;
        Ok(byte)
    }

    pub(crate) fn read_i16(&mut self) -> Result<i16, ProtocolError> {
        let bytes = self.read_bytes(2)?;
        Ok(i16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn read_i32(&mut self) -> Result<i32, ProtocolError> {
        let bytes = self.read_bytes(4)?;
        Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ProtocolError> {
        if self.remaining() < len {
            return Err(ProtocolError::Malformed(format!(
                "expected {len} more bytes but only {} remain",
                self.remaining()
            )));
        }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// Reads a C string terminated by `\0` (not including the trailing
    /// `\0`), and verifies it is valid UTF-8.
    pub(crate) fn read_cstring(&mut self) -> Result<String, ProtocolError> {
        let start = self.pos;
        let nul_offset = self.buf[start..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| ProtocolError::Malformed("missing null terminator in cstring".into()))?;
        let end = start + nul_offset;
        let s = String::from_utf8(self.buf[start..end].to_vec())?;
        self.pos = end + 1;
        Ok(s)
    }

    /// Reads a "length-prefixed" nullable byte sequence (in PostgreSQL,
    /// an `int32` length, with `-1` meaning NULL).
    pub(crate) fn read_len_prefixed_nullable(&mut self) -> Result<Option<Vec<u8>>, ProtocolError> {
        let len = self.read_i32()?;
        if len < 0 {
            return Ok(None);
        }
        let bytes = self.read_bytes(len as usize)?;
        Ok(Some(bytes.to_vec()))
    }

    /// Verifies that the message body has been fully consumed (no
    /// leftover trailing bytes); otherwise treats it as malformed.
    pub(crate) fn expect_exhausted(&self) -> Result<(), ProtocolError> {
        if self.remaining() != 0 {
            return Err(ProtocolError::Malformed(format!(
                "{} trailing bytes after message body",
                self.remaining()
            )));
        }
        Ok(())
    }
}
