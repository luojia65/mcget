//! Minecraft Bedrock / Pocket Edition RakNet utilities.
//!
//! This module is split into two submodules:
//!
//! - [`ping()`] — connectionless **Unconnected Ping** (single UDP round-trip to
//!   read a server's MOTD / player count, no session established). This is the
//!   original Bedrock support in this crate.
//! - [`conn`] — connection-oriented **RakNet handshake** ([`conn::Connection`]),
//!   which establishes a persistent UDP session with a server (negotiating the
//!   MTU, server GUID and encryption flag). After `connect()` succeeds the
//!   session is established but no application-layer packets can be sent yet
//!   (that requires the datagram layer, planned for a later iteration).
//!
//! All original public items ([`Client`], [`RequestBuilder`], [`PongResponse`],
//! [`ping()`]) are re-exported here so the `mcget::bedrock::…` paths are
//! unchanged from before the module split.

use crate::error::PingError;

pub mod conn;
pub mod ping;

pub use ping::{ping as ping_bedrock_inner, Client, PongResponse, RequestBuilder};

/// Default port for Bedrock Edition.
pub const DEFAULT_PORT: u16 = 19132;

/// Fixed RakNet offline-message magic (16 bytes).
pub const MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];

// ==================== PacketBuf: shared parsing helper ====================

/// A cursor-based reader for RakNet packet byte streams.
///
/// Wraps a `&[u8]` and tracks a read position, exposing typed field readers
/// (`read_u8` / `read_u16` / `read_i64` / `read_magic` / `read_bytes`) that all
/// return [`PingError::Protocol`] on truncation — eliminating the
/// `data[a..b].try_into().unwrap()` panics and hand-computed slice indices that
/// would otherwise be scattered across the [`ping`] and [`conn`] parsers.
///
/// Constructed with [`PacketBuf::new`] (carrying a human-readable `name` used
/// in error messages, e.g. `"Pong"` / `"Reply 1"`). The typical parse flow is:
///
/// 1. `expect_id(expected)` — checks the first byte and advances past it.
/// 2. `read_magic()` — validates the 16-byte offline magic at the current
///    position and advances.
/// 3. Typed field reads for the rest of the body.
///
/// This type is deliberately allocation-free and borrow-only; it exists purely
/// to centralize length checks, magic validation, and big-endian field decoding
/// for both the connectionless ([`ping`]) and connection-oriented ([`conn`])
/// code paths.
#[derive(Debug)]
pub(crate) struct PacketBuf<'a> {
    data: &'a [u8],
    pos: usize,
    /// Human-readable packet name, included in error messages for diagnosis.
    name: &'static str,
}

impl<'a> PacketBuf<'a> {
    /// Wraps `data` for parsing, tagging all subsequent errors with `name`.
    pub(crate) fn new(data: &'a [u8], name: &'static str) -> Self {
        Self { data, pos: 0, name }
    }

    /// Number of bytes not yet consumed.
    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Returns `Err` if fewer than `n` bytes remain to be read.
    ///
    /// The error message names the packet and reports both the required and
    /// actual byte counts.
    pub(crate) fn ensure(&self, n: usize) -> Result<(), PingError> {
        if self.remaining() >= n {
            Ok(())
        } else {
            Err(PingError::Protocol(format!(
                "{} packet too short: {} bytes consumed, only {} remain (need {n})",
                self.name,
                self.pos,
                self.remaining()
            )))
        }
    }

    /// Peeks at the next byte without consuming it, or `None` at end of buffer.
    pub(crate) fn peek_u8(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Reads the packet ID byte, returning `Err` if it does not match `expected`.
    ///
    /// Advances past the ID on success. The error message names the packet and
    /// reports both the expected and actual IDs in `0xNN` form.
    pub(crate) fn expect_id(&mut self, expected: u8) -> Result<(), PingError> {
        let got = self.read_u8()?;
        if got == expected {
            Ok(())
        } else {
            Err(PingError::Protocol(format!(
                "{} packet ID is not 0x{:02X}: 0x{:02X}",
                self.name, expected, got
            )))
        }
    }

    /// Reads one big-endian `u8` and advances.
    pub(crate) fn read_u8(&mut self) -> Result<u8, PingError> {
        self.ensure(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Reads one big-endian `u16` and advances.
    pub(crate) fn read_u16(&mut self) -> Result<u16, PingError> {
        self.ensure(2)?;
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Reads one big-endian `i64` and advances.
    pub(crate) fn read_i64(&mut self) -> Result<i64, PingError> {
        self.ensure(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(i64::from_be_bytes(arr))
    }

    /// Reads the next `n` bytes as a borrowed slice and advances.
    pub(crate) fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], PingError> {
        self.ensure(n)?;
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Reads and validates the 16-byte RakNet offline [`MAGIC`] at the current
    /// position, advancing past it on success.
    ///
    /// Returns [`PingError::Protocol`] (naming the packet) if the bytes do not
    /// match [`MAGIC`].
    pub(crate) fn read_magic(&mut self) -> Result<(), PingError> {
        let got = self.read_bytes(MAGIC.len())?;
        if got == MAGIC {
            Ok(())
        } else {
            Err(PingError::Protocol(format!(
                "{} packet magic mismatch: {:02x?}",
                self.name, got
            )))
        }
    }

    /// Current read offset (bytes consumed so far).
    #[cfg(test)]
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    /// Returns the unconsumed tail as a borrowed slice, without advancing.
    #[cfg(test)]
    pub(crate) fn tail(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }
}

/// Convenience entry point: performs a one-shot RakNet Unconnected Ping.
///
/// Re-exported at the crate root as `mcget::ping_bedrock`.
pub async fn ping<A>(addr: A) -> crate::error::Result<PongResponse>
where
    A: crate::addr::HostAddr,
{
    ping::ping(addr).await
}

#[cfg(test)]
mod tests {
    //! Unit tests for the shared `PacketBuf` parsing helper.

    use super::*;

    #[test]
    fn packetbuf_reads_typed_fields_in_order() {
        // Layout: u8 | u16 | i64 | magic | 3 raw bytes.
        let mut buf = Vec::new();
        buf.push(0xAB);
        buf.extend_from_slice(&0x1234u16.to_be_bytes());
        buf.extend_from_slice(&(-42i64).to_be_bytes());
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&[1, 2, 3]);

        let mut p = PacketBuf::new(&buf, "Test");
        assert_eq!(p.read_u8().unwrap(), 0xAB);
        assert_eq!(p.read_u16().unwrap(), 0x1234);
        assert_eq!(p.read_i64().unwrap(), -42);
        p.read_magic().unwrap();
        assert_eq!(p.read_bytes(3).unwrap(), &[1, 2, 3]);
        assert_eq!(p.remaining(), 0);
        assert_eq!(p.pos(), buf.len());
    }

    #[test]
    fn packetbuf_ensure_reports_truncation_with_packet_name() {
        let buf = [0u8; 2];
        let p = PacketBuf::new(&buf, "Pong");
        let err = p.ensure(35).unwrap_err();
        let msg = match err {
            crate::PingError::Protocol(s) => s,
            _ => panic!("expected Protocol error"),
        };
        assert!(msg.contains("Pong"), "error should name the packet: {msg}");
        assert!(
            msg.contains("need 35"),
            "error should report required size: {msg}"
        );
    }

    #[test]
    fn packetbuf_expect_id_matches_and_advances() {
        let buf = [0x1Cu8, 0xFF];
        let mut p = PacketBuf::new(&buf, "Pong");
        p.expect_id(0x1C).unwrap();
        assert_eq!(p.pos(), 1, "expect_id should advance past the ID byte");
        assert_eq!(p.peek_u8(), Some(0xFF));
    }

    #[test]
    fn packetbuf_expect_id_rejects_mismatch() {
        let buf = [0x00u8];
        let mut p = PacketBuf::new(&buf, "Pong");
        let err = p.expect_id(0x1C).unwrap_err();
        let msg = match err {
            crate::PingError::Protocol(s) => s,
            _ => panic!("expected Protocol error"),
        };
        assert!(msg.contains("0x1C"), "error should name expected ID: {msg}");
        assert!(msg.contains("0x00"), "error should name actual ID: {msg}");
    }

    #[test]
    fn packetbuf_read_magic_rejects_bad_bytes() {
        let buf = [0u8; 16];
        let mut p = PacketBuf::new(&buf, "Reply 1");
        let err = p.read_magic().unwrap_err();
        let msg = match err {
            crate::PingError::Protocol(s) => s,
            _ => panic!("expected Protocol error"),
        };
        assert!(
            msg.contains("Reply 1"),
            "error should name the packet: {msg}"
        );
        assert!(msg.contains("magic"), "error should mention magic: {msg}");
    }

    #[test]
    fn packetbuf_read_u8_returns_err_at_end() {
        let buf = [];
        let mut p = PacketBuf::new(&buf, "Empty");
        assert!(p.read_u8().is_err());
    }

    #[test]
    fn packetbuf_read_i64_returns_err_on_short_buffer() {
        // Only 4 bytes — i64 needs 8.
        let buf = [1, 2, 3, 4];
        let mut p = PacketBuf::new(&buf, "Short");
        assert!(p.read_i64().is_err());
    }

    #[test]
    fn packetbuf_tail_returns_unconsumed_without_advancing() {
        let buf = [0xAA, 0xBB, 0xCC];
        let mut p = PacketBuf::new(&buf, "Test");
        let _ = p.read_u8().unwrap();
        assert_eq!(p.tail(), &[0xBB, 0xCC]);
        // Calling tail again must not advance.
        assert_eq!(p.tail(), &[0xBB, 0xCC]);
        assert_eq!(p.pos(), 1);
    }

    #[test]
    fn packetbuf_peek_does_not_advance() {
        let buf = [0x42u8, 0x99];
        let p = PacketBuf::new(&buf, "Test");
        assert_eq!(p.peek_u8(), Some(0x42));
        assert_eq!(p.peek_u8(), Some(0x42), "peek must be idempotent");
        assert_eq!(p.pos(), 0);
    }
}
