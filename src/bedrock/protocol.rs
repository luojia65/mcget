//! Bedrock **game-layer protocol** infrastructure — the framing that sits on
//! top of RakNet: batch-packet encapsulation, zlib compression, varuint32
//! integers, and the game-packet ID constants.
//!
//! This module is independent of RakNet (datagrams, frames, ACK/NACK). Every
//! game packet travels inside a RakNet frame as a **batch** (`ID_BATCH`): a
//! single `0xfe`-prefixed blob whose payload is zlib-compressed and holds zero
//! or more [`GamePacket`]s. Each game packet is
//! `varuint32(header) | varuint32(payload_len) | payload`, where the header
//! packs the packet ID and (for split-screen) sender/target sub-client IDs.
//!
//! References: gophertunnel `minecraft/protocol/packet` (id.go, batch.go),
//! <https://wiki.bedrock.dev/servers/bedrock>.

use crate::error::{PingError, Result};
use flate2::write::{ZlibDecoder, ZlibEncoder};
use flate2::Compression;
use std::io::Write;

// ==================== Game-packet IDs ====================
//
// These mirror gophertunnel's `id.go`, where they are declared as
// `iota + 1` in a single block (with a few blank `_` slots). The numeric
// values below were computed by counting the entries in that block; the unit
// tests pin the login-relevant ones so an ordering drift is caught.

/// Login (client → server). First game packet of the login flow.
pub const ID_LOGIN: u32 = 1;
/// Play Status (server → client). Carries LOGIN_SUCCESS / OUTDATED / etc.
pub const ID_PLAY_STATUS: u32 = 2;
/// Server→Client Handshake (encryption init). Not supported in offline login.
pub const ID_SERVER_TO_CLIENT_HANDSHAKE: u32 = 3;
/// Client→Server Handshake (encryption response). Not supported in offline login.
pub const ID_CLIENT_TO_SERVER_HANDSHAKE: u32 = 4;
/// Disconnect (either direction).
pub const ID_DISCONNECT: u32 = 5;
/// Network Settings (server → client). Compression configuration.
pub const ID_NETWORK_SETTINGS: u32 = 129;
/// Request Network Settings (client → server). First step of the login flow.
pub const ID_REQUEST_NETWORK_SETTINGS: u32 = 179;
/// Batch — the envelope that carries every other game packet inside a frame.
/// A frame body starting with `0xfe` is a batch (not a RakNet system message).
pub const ID_BATCH: u32 = 0xfe;

// ==================== Compression algorithms ====================

/// Compression algorithm carried by [`NetworkSettings`] and the per-packet
/// compression prefix. Matches gophertunnel's `network_settings.go` constants.
pub const COMPRESSION_FLATE: u16 = 0;
pub const COMPRESSION_SNAPPY: u16 = 1;
/// "No compression" sentinel (`0xffff`).
pub const COMPRESSION_NONE: u16 = 0xffff;

// ==================== varuint32 (unsigned LEB128) ====================

/// Writes a `u32` as an unsigned LEB128 varint (7-bit groups, little-endian
/// within the byte stream, MSB continuation bit). This is Bedrock's varuint32.
pub fn write_varuint32(mut value: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80; // continuation
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

/// Reads an unsigned LEB128 varint, returning the value and the number of bytes
/// consumed. Fails on truncation or on a varint longer than 5 bytes.
pub fn read_varuint32(data: &[u8]) -> Result<(u32, usize)> {
    let mut value: u32 = 0;
    let mut shift = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        if shift >= 35 {
            return Err(PingError::Protocol(
                "varuint32 is longer than 5 bytes".to_string(),
            ));
        }
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(PingError::Protocol(
        "varuint32 was truncated (no terminating byte)".to_string(),
    ))
}

/// Zig-zag encodes a signed `i32` and writes it as an unsigned LEB128 varint.
/// Bedrock uses this for signed varint32 fields (protocol version, etc.).
pub fn write_varint32(value: i32) -> Vec<u8> {
    let zz = ((value << 1) ^ (value >> 31)) as u32;
    write_varuint32(zz)
}

/// Reads a zig-zag varint32 (signed), returning the value and bytes consumed.
pub fn read_varint32(data: &[u8]) -> Result<(i32, usize)> {
    let (zz, n) = read_varuint32(data)?;
    let value = ((zz >> 1) as i32) ^ -((zz & 1) as i32);
    Ok((value, n))
}

// ==================== GamePacket ====================

/// One game packet (the unit carried inside a batch). On the wire its header is
/// a varuint32 packing the packet ID and optional sub-client IDs (split screen);
/// this implementation always uses sub-client IDs of 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GamePacket {
    /// The packet ID (e.g. [`ID_LOGIN`]).
    pub id: u32,
    /// The packet payload (fields after the ID).
    pub payload: Vec<u8>,
}

impl GamePacket {
    /// Creates a game packet with the given ID and payload.
    pub fn new(id: u32, payload: Vec<u8>) -> Self {
        Self { id, payload }
    }

    /// Encodes to wire bytes: `varuint32(id) | varuint32(payload_len) | payload`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = write_varuint32(self.id);
        buf.extend_from_slice(&write_varuint32(self.payload.len() as u32));
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decodes one game packet from `data`, returning it and the bytes consumed.
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        let (id, n1) = read_varuint32(data)?;
        let (len, n2) = read_varuint32(&data[n1..])?;
        let len = len as usize;
        let start = n1 + n2;
        if data.len() < start + len {
            return Err(PingError::Protocol(format!(
                "game packet declares {len} payload bytes but only {} remain",
                data.len() - start
            )));
        }
        let payload = data[start..start + len].to_vec();
        Ok((Self { id, payload }, start + len))
    }
}

// ==================== Batch encapsulation + zlib ====================

/// A decoded batch's payload: zero or more [`GamePacket`]s concatenated. This
/// builds the raw (pre-compression) batch body from a slice of packets.
fn build_batch_body(packets: &[GamePacket]) -> Vec<u8> {
    let mut buf = Vec::new();
    for p in packets {
        buf.extend_from_slice(&p.encode());
    }
    buf
}

/// Compresses `data` with zlib (raw DEFLATE + Adler-32, no gzip/zlib header
/// mismatch — `ZlibEncoder` produces the exact zlib stream Bedrock expects).
fn zlib_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder
        .finish()
        .map_err(|e| PingError::Protocol(format!("zlib compress: {e}")))
}

/// Decompresses a zlib stream back to the original bytes.
fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(Vec::new());
    decoder.write_all(data)?;
    decoder
        .finish()
        .map_err(|e| PingError::Protocol(format!("zlib decompress: {e}")))
}

/// Encodes a batch in the **legacy** format: `0xfe | zlib_stream` (no
/// algorithm-prefix byte). Used for packets sent before NetworkSettings
/// negotiates the modern prefixed format.
pub fn encode_batch_legacy(packets: &[GamePacket]) -> Result<Vec<u8>> {
    let body = build_batch_body(packets);
    let mut out = Vec::with_capacity(1 + body.len() + 16);
    out.push(ID_BATCH as u8);
    out.extend_from_slice(&zlib_compress(&body)?);
    Ok(out)
}

/// Encodes a batch: concatenates the packets, optionally zlib-compresses the
/// body, and prefixes the [`ID_BATCH`] byte (`0xfe`) and, when compressed, the
/// compression-algorithm ID byte.
///
/// Wire layout:
/// - Compressed:   `0xfe | algorithm(u8) | zlib_stream`
/// - Uncompressed: `0xfe | raw_game_packets`
///
/// The algorithm prefix byte was introduced in Bedrock 1.19.30 (protocol 553).
/// `compress_with` selects the algorithm; [`COMPRESSION_NONE`] omits both the
/// prefix byte and the compression.
pub fn encode_batch(packets: &[GamePacket], compress_with: u16) -> Result<Vec<u8>> {
    let body = build_batch_body(packets);
    let mut out = Vec::with_capacity(2 + body.len() + 16);
    out.push(ID_BATCH as u8);
    match compress_with {
        COMPRESSION_FLATE => {
            // 0xfe | algorithm(0) | zlib_stream
            out.push(COMPRESSION_FLATE as u8);
            out.extend_from_slice(&zlib_compress(&body)?);
        }
        COMPRESSION_NONE => {
            // 0xfe | raw packets (no algorithm prefix).
            out.extend_from_slice(&body);
        }
        COMPRESSION_SNAPPY => {
            return Err(PingError::Protocol(
                "snappy compression is not supported yet".to_string(),
            ));
        }
        other => {
            return Err(PingError::Protocol(format!(
                "unknown compression algorithm {other}"
            )));
        }
    }
    Ok(out)
}

/// Decodes a batch: strips the `0xfe` prefix, decompresses (if applicable),
/// and returns the contained game packets in order.
///
/// Three payload shapes are accepted, tried in this order:
/// 1. **Modern compressed** — `0xfe | alg(u8) | zlib_stream`. The byte after
///    `0xfe` is a known algorithm ID (0 = flate) and the remainder is a valid
///    zlib stream. (Introduced in Bedrock 1.19.30 / protocol 553.)
/// 2. **Legacy compressed** — `0xfe | zlib_stream`. No algorithm prefix; the
///    whole payload after `0xfe` decompresses cleanly.
/// 3. **Uncompressed** — `0xfe | raw_game_packets`. Used when the server's
///    compression threshold is not met.
///
/// Returns an error if `data` is not a batch (wrong leading byte) or the
/// decompressed/raw body is malformed.
pub fn decode_batch(data: &[u8]) -> Result<Vec<GamePacket>> {
    let (&first, rest) = data
        .split_first()
        .ok_or_else(|| PingError::Protocol("empty batch".to_string()))?;
    if first != ID_BATCH as u8 {
        return Err(PingError::Protocol(format!(
            "not a batch packet: leading byte 0x{first:02X} (expected 0xFE)"
        )));
    }
    // 1. Modern compressed: first byte is the flate algorithm ID (0) and the
    //    rest decompresses as zlib. (We don't check Snappy here: the byte 1
    //    collides with common game-packet IDs, so only fail on it if the body
    //    truly isn't anything else — see the Snappy note below.)
    if let Some((&alg, compressed)) = rest.split_first() {
        if (alg as u16) == COMPRESSION_FLATE {
            if let Ok(b) = zlib_decompress(compressed) {
                return decode_batch_body(&b);
            }
        }
    }
    // 2. Legacy compressed: the whole payload decompresses as zlib.
    if let Ok(b) = zlib_decompress(rest) {
        return decode_batch_body(&b);
    }
    // 3. Uncompressed: treat the payload as raw game packets.
    match decode_batch_body(rest) {
        Ok(p) => Ok(p),
        // If raw parsing failed too, the body may be a Snappy stream we can't
        // decode (algorithm byte 1 + Snappy). Report that specifically.
        Err(e) => {
            if let Some((&alg, _)) = rest.split_first() {
                if (alg as u16) == COMPRESSION_SNAPPY {
                    return Err(PingError::Protocol(
                        "snappy compression is not supported yet".to_string(),
                    ));
                }
            }
            Err(e)
        }
    }
}

/// Decodes the (already decompressed/raw) batch body into game packets.
fn decode_batch_body(body: &[u8]) -> Result<Vec<GamePacket>> {
    let mut packets = Vec::new();
    let mut off = 0;
    while off < body.len() {
        let (p, n) = GamePacket::decode(&body[off..])?;
        packets.push(p);
        off += n;
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- varuint32 ----------

    #[test]
    fn varuint32_known_values() {
        // 0 → [0x00], 1 → [0x01], 127 → [0x7f], 128 → [0x80, 0x01].
        assert_eq!(write_varuint32(0), [0x00]);
        assert_eq!(write_varuint32(1), [0x01]);
        assert_eq!(write_varuint32(127), [0x7f]);
        assert_eq!(write_varuint32(128), [0x80, 0x01]);
        assert_eq!(write_varuint32(300), [0xac, 0x02]);
    }

    #[test]
    fn varuint32_max_u32() {
        let bytes = write_varuint32(u32::MAX);
        assert_eq!(bytes.len(), 5);
        let (v, n) = read_varuint32(&bytes).unwrap();
        assert_eq!(v, u32::MAX);
        assert_eq!(n, 5);
    }

    #[test]
    fn varuint32_round_trips() {
        for &v in &[
            0u32,
            1,
            127,
            128,
            255,
            256,
            16383,
            16384,
            0x00ff_ffff,
            u32::MAX,
        ] {
            let bytes = write_varuint32(v);
            let (back, n) = read_varuint32(&bytes).unwrap();
            assert_eq!(back, v, "round-trip for {v}");
            assert_eq!(n, bytes.len());
        }
    }

    #[test]
    fn varuint32_truncated_is_error() {
        // Continuation bit set but no following byte.
        assert!(read_varuint32(&[0x80]).is_err());
        assert!(read_varuint32(&[]).is_err());
    }

    // ---------- GamePacket ----------

    #[test]
    fn game_packet_encode_decode_round_trip() {
        let p = GamePacket::new(ID_LOGIN, vec![0x01, 0x02, 0x03]);
        let bytes = p.encode();
        let (back, n) = GamePacket::decode(&bytes).unwrap();
        assert_eq!(back, p);
        assert_eq!(n, bytes.len());
    }

    #[test]
    fn game_packet_decode_truncated_payload_is_error() {
        // id=1 (1 byte), len=5 (1 byte), but only 1 payload byte.
        let bytes = [0x01, 0x05, 0xaa];
        assert!(GamePacket::decode(&bytes).is_err());
    }

    // ---------- batch / zlib ----------

    #[test]
    fn batch_round_trip_single_packet_compressed() {
        let packets = vec![GamePacket::new(ID_PLAY_STATUS, vec![0xff; 64])];
        let bytes = encode_batch(&packets, COMPRESSION_FLATE).unwrap();
        assert_eq!(bytes[0], ID_BATCH as u8);
        let back = decode_batch(&bytes).unwrap();
        assert_eq!(back, packets);
    }

    #[test]
    fn batch_round_trip_multiple_packets() {
        let packets = vec![
            GamePacket::new(ID_LOGIN, vec![0x01]),
            GamePacket::new(ID_NETWORK_SETTINGS, vec![0x02, 0x03]),
            GamePacket::new(ID_DISCONNECT, vec![]),
        ];
        let bytes = encode_batch(&packets, COMPRESSION_FLATE).unwrap();
        let back = decode_batch(&bytes).unwrap();
        assert_eq!(back, packets);
    }

    #[test]
    fn batch_uncompressed_round_trip() {
        let packets = vec![GamePacket::new(ID_LOGIN, vec![0xab, 0xcd])];
        let bytes = encode_batch(&packets, COMPRESSION_NONE).unwrap();
        let back = decode_batch(&bytes).unwrap();
        assert_eq!(back, packets);
    }

    #[test]
    fn batch_decode_rejects_wrong_prefix() {
        // Leading byte 0x01, not 0xfe.
        assert!(decode_batch(&[0x01, 0x02, 0x03]).is_err());
    }

    #[test]
    fn batch_compression_is_actually_zlib() {
        // A highly compressible payload must shrink under zlib.
        let packets = vec![GamePacket::new(ID_LOGIN, vec![0x00; 500])];
        let compressed = encode_batch(&packets, COMPRESSION_FLATE).unwrap();
        let raw = encode_batch(&packets, COMPRESSION_NONE).unwrap();
        assert!(
            compressed.len() < raw.len(),
            "zlib should compress a repetitive payload: {} vs {}",
            compressed.len(),
            raw.len()
        );
    }

    // ---------- packet ID sanity ----------

    #[test]
    fn login_packet_ids_match_gophertunnel() {
        // Pin the critical IDs so an ordering drift in id.go is caught.
        assert_eq!(ID_LOGIN, 1);
        assert_eq!(ID_PLAY_STATUS, 2);
        assert_eq!(ID_DISCONNECT, 5);
        assert_eq!(ID_NETWORK_SETTINGS, 129);
        assert_eq!(ID_REQUEST_NETWORK_SETTINGS, 179);
        assert_eq!(ID_BATCH, 0xfe);
    }
}
