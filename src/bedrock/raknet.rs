//! RakNet **online-format primitives** — the protocol building blocks shared by
//! the connectionless ([`super::ping`]) and connection-oriented ([`super::conn`])
//! code paths.
//!
//! This module centralizes the wire-format decoding layer that is independent of
//! any particular packet's business logic:
//!
//! - [`MAGIC`]: the fixed 16-byte RakNet offline-message magic, validated by
//!   every offline handshake / ping packet.
//! - [`PacketBuf`]: a cursor-based big-endian reader for RakNet packet byte
//!   streams, returning [`PingError::Protocol`] on truncation so callers never
//!   hand-compute slice indices or `.try_into().unwrap()` into panics.
//! - IPv4 **system-address** codec ([`encode_ipv4_addr`] / [`decode_ipv4_addr`]):
//!   the compact 7-byte `family | ipv4 | port` form used in Open Connection
//!   Request 2 / Reply 2.
//!
//! Packet ID constants and the per-packet parsers (`parse_pong`,
//! `parse_reply1/2`, `classify_rejection`, …) live in their respective modules,
//! since they encode business semantics rather than reusable wire-format rules.
//!
//! Everything here is `pub(crate)` except [`MAGIC`], which is `pub` so that
//! [`super`] can re-export it as `mcget::bedrock::MAGIC`. The `raknet` module
//! itself is private, so the constant is not independently reachable from
//! downstream crates.

use crate::error::PingError;
use std::net::{Ipv4Addr, SocketAddrV4};

/// Fixed RakNet offline-message magic (16 bytes).
///
/// Declared `pub` so that [`super`] can re-export it as `mcget::bedrock::MAGIC`.
/// The canonical public path is the re-export; this module (`bedrock::raknet`)
/// is itself private, so the constant is not independently reachable from
/// downstream crates.
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
/// would otherwise be scattered across the [`super::ping`] and [`super::conn`]
/// parsers.
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
/// for both the connectionless ([`super::ping`]) and connection-oriented
/// ([`super::conn`]) code paths.
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

    /// Reads one little-endian 24-bit unsigned integer (3 bytes) into a `u32`
    /// and advances.
    ///
    /// RakNet's connected layer (datagram sequence numbers and the
    /// reliable/sequenced/ordering indices inside frames) uses 24-bit
    /// little-endian values everywhere, so this is the natural counterpart to
    /// the big-endian readers above for the [`super::datagram`] codec.
    #[allow(dead_code)] // consumed by datagram.rs + its own unit tests
    pub(crate) fn read_u24_le(&mut self) -> Result<u32, PingError> {
        self.ensure(3)?;
        let [b0, b1, b2] = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
        ];
        self.pos += 3;
        Ok(u32::from_le_bytes([b0, b1, b2, 0]))
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

// ==================== RakNet IPv4 address codec ====================

/// RakNet IPv4 system address wire length (used in Request 2 / Reply 2):
/// `family(1) | ipv4(4 BE) | port(2 BE)` = 7 bytes.
///
/// Note this is the *offline handshake* address encoding — it is a compact
/// fixed 7-byte form with a 1-byte family, not the full `SystemAddress` struct
/// (which in the datagram layer can be longer and carry a scope id). This was
/// previously mis-sized as 16, which truncated Reply 2 parsing on real servers
/// (e.g. EaseCation / NetherGames send a 35-byte Reply 2).
pub(crate) const RAKNET_IPV4_LEN: usize = 7;
/// Family byte for RakNet IPv4 addresses (RakNet uses 4, not AF_INET).
pub(crate) const RAKNET_FAMILY_IPV4: u8 = 4;

/// Encodes a [`SocketAddrV4`] into the 7-byte RakNet offline system-address
/// form: `family(1, =4) | ipv4(4 BE) | port(2 BE)`.
pub(crate) fn encode_ipv4_addr(addr: &SocketAddrV4) -> [u8; RAKNET_IPV4_LEN] {
    let mut out = [0u8; RAKNET_IPV4_LEN];
    out[0] = RAKNET_FAMILY_IPV4;
    out[1..5].copy_from_slice(&addr.ip().octets());
    out[5..7].copy_from_slice(&addr.port().to_be_bytes());
    out
}

/// Decodes a 7-byte RakNet offline system-address slice back into a
/// [`SocketAddrV4`].
///
/// Returns `Err` if the slice is the wrong length or the family byte is not 4.
pub(crate) fn decode_ipv4_addr(data: &[u8]) -> Result<SocketAddrV4, PingError> {
    if data.len() != RAKNET_IPV4_LEN {
        return Err(PingError::Protocol(format!(
            "RakNet address is {} bytes, expected {RAKNET_IPV4_LEN}",
            data.len()
        )));
    }
    if data[0] != RAKNET_FAMILY_IPV4 {
        return Err(PingError::Protocol(format!(
            "RakNet address family {} is not IPv4 (4)",
            data[0]
        )));
    }
    let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
    let port = u16::from_be_bytes([data[5], data[6]]);
    Ok(SocketAddrV4::new(ip, port))
}

#[cfg(test)]
mod tests {
    //! Unit tests for the RakNet online-format primitives:
    //! [`PacketBuf`] cursor reader and the IPv4 system-address codec.

    use super::*;

    // ---------- PacketBuf ----------

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
    fn packetbuf_read_u24_le_decodes_little_endian() {
        // 0x030201 little-endian on the wire = bytes [0x01, 0x02, 0x03] → value 0x030201.
        let buf = [0x01, 0x02, 0x03, 0xff];
        let mut p = PacketBuf::new(&buf, "Test");
        assert_eq!(p.read_u24_le().unwrap(), 0x030201);
        assert_eq!(p.pos(), 3, "read_u24_le should advance 3 bytes");
        assert_eq!(p.peek_u8(), Some(0xff), "next byte should be unconsumed");
    }

    #[test]
    fn packetbuf_read_u24_le_max_value() {
        // All 0xff = 0x00ffffff (24-bit max), high byte must be zero.
        let buf = [0xff, 0xff, 0xff];
        let mut p = PacketBuf::new(&buf, "Test");
        assert_eq!(p.read_u24_le().unwrap(), 0x00ff_ffff);
    }

    #[test]
    fn packetbuf_read_u24_le_returns_err_on_short_buffer() {
        // Only 2 bytes — u24 needs 3.
        let buf = [0x01, 0x02];
        let mut p = PacketBuf::new(&buf, "Short");
        assert!(p.read_u24_le().is_err());
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

    // ---------- IPv4 system-address codec ----------

    #[test]
    fn raknet_ipv4_addr_roundtrip() {
        let cases = [
            (Ipv4Addr::new(127, 0, 0, 1), 19132u16),
            (Ipv4Addr::new(8, 8, 8, 8), 53),
            (Ipv4Addr::new(192, 168, 1, 1), 0),
            (Ipv4Addr::new(0, 0, 0, 0), 65535),
        ];
        for (ip, port) in cases {
            let addr = SocketAddrV4::new(ip, port);
            let encoded = encode_ipv4_addr(&addr);
            // 7 bytes: family(1) + octets(4) + BE port(2).
            assert_eq!(encoded.len(), RAKNET_IPV4_LEN);
            assert_eq!(encoded[0], RAKNET_FAMILY_IPV4);
            assert_eq!(&encoded[1..5], &ip.octets());
            assert_eq!(&encoded[5..7], &port.to_be_bytes());
            let decoded = decode_ipv4_addr(&encoded).unwrap();
            assert_eq!(decoded, addr, "roundtrip failed for {ip}:{port}");
        }
    }

    #[test]
    fn decode_ipv4_addr_rejects_wrong_length() {
        assert!(decode_ipv4_addr(&[0u8; 6]).is_err());
        assert!(decode_ipv4_addr(&[0u8; 8]).is_err());
    }

    #[test]
    fn decode_ipv4_addr_rejects_wrong_family() {
        // Family byte 6 = IPv6, not supported.
        let mut buf = vec![6u8];
        buf.resize(RAKNET_IPV4_LEN, 0);
        assert_eq!(buf.len(), RAKNET_IPV4_LEN);
        assert!(decode_ipv4_addr(&buf).is_err());
    }
}
