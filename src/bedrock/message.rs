//! RakNet **connected system messages** — the small protocol packets exchanged
//! *inside* datagram frames once the offline handshake is done.
//!
//! Each message is the body of a [`super::datagram::Frame`]; its first byte is
//! the message ID (a separate namespace from the datagram flag byte `0x80`).
//! Fields are big-endian unless noted. The IDs and layouts here match go-raknet
//! (`internal/message/`), the de-facto Bedrock reference.
//!
//! ## Message inventory
//!
//! | ID    | Name                      | Dir  | Purpose                          |
//! |-------|---------------------------|------|----------------------------------|
//! | `0x00`| [`ConnectedPing`]         | both | keep-alive; server replies Pong  |
//! | `0x03`| [`ConnectedPong`]         | both | reply to a ConnectedPing         |
//! | `0x09`| [`ConnectionRequest`]     | C→S  | ask to enter the connected state |
//! | `0x10`| [`ConnectionRequestAccepted`] | S→C | server accepts the request   |
//! | `0x13`| [`NewIncomingConnection`] | C→S  | client finalises the session     |
//! | `0x15`| [`Disconnect`]            | both | graceful close                   |
//!
//! > **Note**: these IDs (`0x00`–`0x15`) are the *message* IDs that appear as
//! > the first byte of a frame body — they are unrelated to the datagram flag
//! > byte (`0x80`/`0xC0`/`0xA0`) and the offline handshake IDs (`0x05`–`0x08`).
//!
//! ## Online handshake flow
//!
//! After the offline handshake ([`super::conn`]), the client completes the
//! *online* handshake before the server will deliver any application frames:
//!
//! ```text
//! Client                                     Server
//!   |  0x09 ConnectionRequest (guid, time)    |
//!   |---------------------------------------->|
//!   |  0x10 ConnectionRequestAccepted         |
//!   |    (client_addr, sys addrs, times)      |
//!   |<----------------------------------------|
//!   |  0x13 NewIncomingConnection             |
//!   |    (server_addr, sys addrs, times)      |
//!   |---------------------------------------->|
//!   |          session fully established      |
//! ```

use crate::error::{PingError, Result};
use std::net::{Ipv4Addr, SocketAddrV4};

// ==================== Message IDs ====================

/// Connected Ping keep-alive.
pub const ID_CONNECTED_PING: u8 = 0x00;
/// Connected Pong (reply to a Connected Ping).
pub const ID_CONNECTED_PONG: u8 = 0x03;
/// Connection Request (C→S, start of the online handshake).
pub const ID_CONNECTION_REQUEST: u8 = 0x09;
/// Connection Request Accepted (S→C).
pub const ID_CONNECTION_REQUEST_ACCEPTED: u8 = 0x10;
/// New Incoming Connection (C→S, finalises the online handshake).
pub const ID_NEW_INCOMING_CONNECTION: u8 = 0x13;
/// Disconnect Notification (graceful close).
pub const ID_DISCONNECT: u8 = 0x15;

// ==================== Concrete messages ====================

/// `0x00` — Connected Ping. Body: `id(1) | ping_time(i64 BE)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectedPing {
    /// Client timestamp (ms) echoed back in the [`ConnectedPong`] reply.
    pub time: i64,
}

/// `0x03` — Connected Pong. Body: `id(1) | ping_time(i64 BE) | pong_time(i64 BE)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectedPong {
    /// The `ping_time` from the [`ConnectedPing`] being answered.
    pub ping_time: i64,
    /// Server timestamp (ms) at the moment of reply.
    pub pong_time: i64,
}

/// `0x09` — Connection Request. Body:
/// `id(1) | client_guid(i64 BE) | request_time(i64 BE) | use_security(bool)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRequest {
    pub client_guid: i64,
    pub request_time: i64,
    pub use_security: bool,
}

/// `0x10` — Connection Request Accepted (S→C). Body:
/// `id(1) | client_address | system_index(u16 BE) | system_addresses[20] |
///  ping_time(i64 BE) | pong_time(i64 BE)`.
///
/// Only the IPv4 form is supported for encoding/decoding addresses here (this
/// crate is IPv4-only for the handshake today).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRequestAccepted {
    /// The client's address as the server saw it.
    pub client_address: SocketAddrV4,
    /// Index into the server's system-address list (usually 0).
    pub system_index: u16,
    /// The server's advertised system addresses (20 slots; trailing slots are
    /// `0.0.0.0:0` placeholders).
    pub system_addresses: Vec<SocketAddrV4>,
    /// The `request_time` from the [`ConnectionRequest`].
    pub ping_time: i64,
    /// Server timestamp (ms) at acceptance.
    pub pong_time: i64,
}

/// `0x13` — New Incoming Connection (C→S). Body:
/// `id(1) | server_address | system_addresses[20] | ping_time(i64 BE) |
///  pong_time(i64 BE)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewIncomingConnection {
    /// The server's address as the client saw it.
    pub server_address: SocketAddrV4,
    /// System addresses echoed back from the server's accepted packet.
    pub system_addresses: Vec<SocketAddrV4>,
    /// The `pong_time` from [`ConnectionRequestAccepted`].
    pub ping_time: i64,
    /// Client timestamp (ms) at sending.
    pub pong_time: i64,
}

/// `0x15` — Disconnect Notification. No body beyond the ID byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disconnect;

/// The number of system-address slots the protocol reserves in
/// [`ConnectionRequestAccepted`] / [`NewIncomingConnection`] (matches go-raknet
/// / PocketMine: 20 entries).
const SYSTEM_ADDRESS_COUNT: usize = 20;

// ==================== Encode / decode ====================

impl ConnectedPing {
    /// Encodes to wire bytes (id + ping_time BE).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(9);
        b.push(ID_CONNECTED_PING);
        b.extend_from_slice(&self.time.to_be_bytes());
        b
    }

    /// Decodes from the bytes *after* the message ID (i.e. `data` is the frame
    /// body with the ID already consumed). The caller matches the ID first.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let time = read_i64_be(data, "ConnectedPing")?;
        Ok(Self { time })
    }
}

impl ConnectedPong {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(17);
        b.push(ID_CONNECTED_PONG);
        b.extend_from_slice(&self.ping_time.to_be_bytes());
        b.extend_from_slice(&self.pong_time.to_be_bytes());
        b
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let ping_time = read_i64_be(&data[0..], "ConnectedPong.ping_time")?;
        let pong_time = read_i64_be(&data[8..], "ConnectedPong.pong_time")?;
        Ok(Self { ping_time, pong_time })
    }
}

impl ConnectionRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(18);
        b.push(ID_CONNECTION_REQUEST);
        b.extend_from_slice(&self.client_guid.to_be_bytes());
        b.extend_from_slice(&self.request_time.to_be_bytes());
        b.push(self.use_security as u8);
        b
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let client_guid = read_i64_be(&data[0..], "ConnectionRequest.client_guid")?;
        let request_time = read_i64_be(&data[8..], "ConnectionRequest.request_time")?;
        let use_security = data.get(16).copied().unwrap_or(0) != 0;
        Ok(Self { client_guid, request_time, use_security })
    }
}

impl ConnectionRequestAccepted {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + 7 + 2 + SYSTEM_ADDRESS_COUNT * 7 + 16);
        b.push(ID_CONNECTION_REQUEST_ACCEPTED);
        b.extend_from_slice(&encode_addr_v4(&self.client_address));
        b.extend_from_slice(&self.system_index.to_be_bytes());
        for addr in self.system_addresses.iter().take(SYSTEM_ADDRESS_COUNT) {
            b.extend_from_slice(&encode_addr_v4(addr));
        }
        // Pad to 20 slots if the caller supplied fewer.
        for _ in self.system_addresses.len()..SYSTEM_ADDRESS_COUNT {
            b.extend_from_slice(&encode_addr_v4(&SocketAddrV4::new(
                Ipv4Addr::new(0, 0, 0, 0),
                0,
            )));
        }
        b.extend_from_slice(&self.ping_time.to_be_bytes());
        b.extend_from_slice(&self.pong_time.to_be_bytes());
        b
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut off = 0;
        let (client_address, n) = decode_addr_v4(&data[off..], "ConnectionRequestAccepted.client_address")?;
        off += n;
        let system_index = read_u16_be(&data[off..off + 2], "ConnectionRequestAccepted.system_index")?;
        off += 2;
        let mut system_addresses = Vec::with_capacity(SYSTEM_ADDRESS_COUNT);
        for _ in 0..SYSTEM_ADDRESS_COUNT {
            let (addr, n) = decode_addr_v4(&data[off..], "ConnectionRequestAccepted.system_address")?;
            system_addresses.push(addr);
            off += n;
        }
        let ping_time = read_i64_be(&data[off..], "ConnectionRequestAccepted.ping_time")?;
        let pong_time = read_i64_be(&data[off + 8..], "ConnectionRequestAccepted.pong_time")?;
        Ok(Self { client_address, system_index, system_addresses, ping_time, pong_time })
    }
}

impl NewIncomingConnection {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + 7 + SYSTEM_ADDRESS_COUNT * 7 + 16);
        b.push(ID_NEW_INCOMING_CONNECTION);
        b.extend_from_slice(&encode_addr_v4(&self.server_address));
        for addr in self.system_addresses.iter().take(SYSTEM_ADDRESS_COUNT) {
            b.extend_from_slice(&encode_addr_v4(addr));
        }
        for _ in self.system_addresses.len()..SYSTEM_ADDRESS_COUNT {
            b.extend_from_slice(&encode_addr_v4(&SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)));
        }
        b.extend_from_slice(&self.ping_time.to_be_bytes());
        b.extend_from_slice(&self.pong_time.to_be_bytes());
        b
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut off = 0;
        let (server_address, n) = decode_addr_v4(&data[off..], "NewIncomingConnection.server_address")?;
        off += n;
        let mut system_addresses = Vec::with_capacity(SYSTEM_ADDRESS_COUNT);
        for _ in 0..SYSTEM_ADDRESS_COUNT {
            let (addr, n) = decode_addr_v4(&data[off..], "NewIncomingConnection.system_address")?;
            system_addresses.push(addr);
            off += n;
        }
        let ping_time = read_i64_be(&data[off..], "NewIncomingConnection.ping_time")?;
        let pong_time = read_i64_be(&data[off + 8..], "NewIncomingConnection.pong_time")?;
        Ok(Self { server_address, system_addresses, ping_time, pong_time })
    }
}

impl Disconnect {
    pub fn encode(&self) -> Vec<u8> {
        vec![ID_DISCONNECT]
    }

    pub fn decode(_data: &[u8]) -> Result<Self> {
        Ok(Disconnect)
    }
}

// ==================== Address codec (connected-message variant) ====================

/// Encodes an IPv4 address in the connected-message form used by
/// [`ConnectionRequestAccepted`] / [`NewIncomingConnection`]:
/// `family(1, =4) | ipv4(4, BE, bitwise-NOTed) | port(2, BE)`.
///
/// The IPv4 octets are bitwise-NOTed on the wire (a RakNet quirk verified
/// against go-raknet's `addr.go`). This differs from the offline-handshake
/// address codec in [`super::raknet`], which does not NOT the bytes.
fn encode_addr_v4(addr: &SocketAddrV4) -> [u8; 7] {
    let octets = addr.ip().octets();
    let mut b = [0u8; 7];
    b[0] = 4;
    b[1] = !octets[0];
    b[2] = !octets[1];
    b[3] = !octets[2];
    b[4] = !octets[3];
    b[5..7].copy_from_slice(&addr.port().to_be_bytes());
    b
}

/// Decodes the 7-byte connected-message IPv4 address. Inverse of
/// [`encode_addr_v4`]. Returns the address and the number of bytes consumed (7).
fn decode_addr_v4(data: &[u8], ctx: &str) -> Result<(SocketAddrV4, usize)> {
    if data.len() < 7 {
        return Err(PingError::Protocol(format!(
            "{ctx}: address needs 7 bytes, got {}",
            data.len()
        )));
    }
    let ip = Ipv4Addr::new(!data[1], !data[2], !data[3], !data[4]);
    let port = u16::from_be_bytes([data[5], data[6]]);
    Ok((SocketAddrV4::new(ip, port), 7))
}

// ==================== Byte readers ====================

fn read_i64_be(data: &[u8], ctx: &str) -> Result<i64> {
    if data.len() < 8 {
        return Err(PingError::Protocol(format!(
            "{ctx}: need 8 bytes, got {}",
            data.len()
        )));
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&data[..8]);
    Ok(i64::from_be_bytes(a))
}

fn read_u16_be(data: &[u8], ctx: &str) -> Result<u16> {
    if data.len() < 2 {
        return Err(PingError::Protocol(format!(
            "{ctx}: need 2 bytes, got {}",
            data.len()
        )));
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
}

/// The decoded kind of a connected system message, after stripping the ID byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemMessage {
    ConnectedPing(ConnectedPing),
    ConnectedPong(ConnectedPong),
    ConnectionRequest(ConnectionRequest),
    ConnectionRequestAccepted(ConnectionRequestAccepted),
    NewIncomingConnection(NewIncomingConnection),
    Disconnect(Disconnect),
    /// An application-layer (non-system) frame body; the first byte did not
    /// match any system message ID.
    Application(Vec<u8>),
}

impl SystemMessage {
    /// A short human-readable name for the variant (debug logging).
    pub fn debug_name(&self) -> &'static str {
        match self {
            SystemMessage::ConnectedPing(_) => "ConnectedPing",
            SystemMessage::ConnectedPong(_) => "ConnectedPong",
            SystemMessage::ConnectionRequest(_) => "ConnectionRequest",
            SystemMessage::ConnectionRequestAccepted(_) => "ConnectionRequestAccepted",
            SystemMessage::NewIncomingConnection(_) => "NewIncomingConnection",
            SystemMessage::Disconnect(_) => "Disconnect",
            SystemMessage::Application(_) => "Application",
        }
    }
}

/// Classifies a frame body by its leading byte into a [`SystemMessage`], or
/// [`SystemMessage::Application`] if it is not a recognised system message.
pub fn classify(body: &[u8]) -> Result<SystemMessage> {
    let id = *body.first().ok_or_else(|| {
        PingError::Protocol("cannot classify an empty frame body".to_string())
    })?;
    let rest = &body[1..];
    Ok(match id {
        ID_CONNECTED_PING => SystemMessage::ConnectedPing(ConnectedPing::decode(rest)?),
        ID_CONNECTED_PONG => SystemMessage::ConnectedPong(ConnectedPong::decode(rest)?),
        ID_CONNECTION_REQUEST => {
            SystemMessage::ConnectionRequest(ConnectionRequest::decode(rest)?)
        }
        ID_CONNECTION_REQUEST_ACCEPTED => SystemMessage::ConnectionRequestAccepted(
            ConnectionRequestAccepted::decode(rest)?,
        ),
        ID_NEW_INCOMING_CONNECTION => SystemMessage::NewIncomingConnection(
            NewIncomingConnection::decode(rest)?,
        ),
        ID_DISCONNECT => SystemMessage::Disconnect(Disconnect::decode(rest)?),
        _ => SystemMessage::Application(body.to_vec()),
    })
}

#[cfg(test)]
mod tests {
    //! Byte-level encode/decode tests for the connected system messages.

    use super::*;

    #[test]
    fn connected_ping_round_trip() {
        let m = ConnectedPing { time: 0x0102030405060708 };
        let bytes = m.encode();
        assert_eq!(bytes[0], ID_CONNECTED_PING);
        assert_eq!(bytes.len(), 9);
        let back = ConnectedPing::decode(&bytes[1..]).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn connected_ping_encode_exact_bytes() {
        // id(0x00) | time BE.
        let m = ConnectedPing { time: 1 };
        assert_eq!(m.encode(), [0x00, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn connected_pong_round_trip() {
        let m = ConnectedPong { ping_time: 100, pong_time: 200 };
        let bytes = m.encode();
        assert_eq!(bytes[0], ID_CONNECTED_PONG);
        assert_eq!(bytes.len(), 17);
        let back = ConnectedPong::decode(&bytes[1..]).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn connection_request_round_trip() {
        let m = ConnectionRequest { client_guid: -1, request_time: 42, use_security: false };
        let bytes = m.encode();
        assert_eq!(bytes[0], ID_CONNECTION_REQUEST);
        assert_eq!(bytes.len(), 18);
        let back = ConnectionRequest::decode(&bytes[1..]).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn connection_request_security_flag_round_trips() {
        let m = ConnectionRequest { client_guid: 7, request_time: 9, use_security: true };
        let back = ConnectionRequest::decode(&m.encode()[1..]).unwrap();
        assert!(back.use_security);
    }

    #[test]
    fn connection_request_accepted_round_trip() {
        let m = ConnectionRequestAccepted {
            client_address: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 19132),
            system_index: 0,
            system_addresses: vec![
                SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 19132),
                SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0),
            ],
            ping_time: 1,
            pong_time: 2,
        };
        let bytes = m.encode();
        assert_eq!(bytes[0], ID_CONNECTION_REQUEST_ACCEPTED);
        let back = ConnectionRequestAccepted::decode(&bytes[1..]).unwrap();
        // The decode pads to 20 slots, so compare field-by-field.
        assert_eq!(back.client_address, m.client_address);
        assert_eq!(back.system_index, m.system_index);
        assert_eq!(back.system_addresses.len(), SYSTEM_ADDRESS_COUNT);
        assert_eq!(back.system_addresses[0], m.system_addresses[0]);
        assert_eq!(back.ping_time, m.ping_time);
        assert_eq!(back.pong_time, m.pong_time);
    }

    #[test]
    fn addr_v4_bytes_are_bitwise_noted() {
        // 127.0.0.1 → !each = 128.255.255.254 on the wire.
        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 19132);
        let enc = encode_addr_v4(&addr);
        assert_eq!(enc[0], 4); // family
        assert_eq!(&enc[1..5], &[128, 255, 255, 254]); // NOTed octets
        assert_eq!(&enc[5..7], &19132u16.to_be_bytes()); // port BE
        // Round-trip.
        let (back, n) = decode_addr_v4(&enc, "test").unwrap();
        assert_eq!(back, addr);
        assert_eq!(n, 7);
    }

    #[test]
    fn new_incoming_connection_round_trip() {
        let m = NewIncomingConnection {
            server_address: SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
            system_addresses: vec![],
            ping_time: 5,
            pong_time: 6,
        };
        let bytes = m.encode();
        assert_eq!(bytes[0], ID_NEW_INCOMING_CONNECTION);
        let back = NewIncomingConnection::decode(&bytes[1..]).unwrap();
        assert_eq!(back.server_address, m.server_address);
        assert_eq!(back.system_addresses.len(), SYSTEM_ADDRESS_COUNT);
        assert_eq!(back.ping_time, m.ping_time);
        assert_eq!(back.pong_time, m.pong_time);
    }

    #[test]
    fn disconnect_is_single_byte() {
        let bytes = Disconnect.encode();
        assert_eq!(bytes, [ID_DISCONNECT]);
    }

    #[test]
    fn classify_routes_each_message() {
        // Build each message, classify the encoded body, expect the right variant.
        let ping = ConnectedPing { time: 1 }.encode();
        assert!(matches!(classify(&ping).unwrap(), SystemMessage::ConnectedPing(_)));
        let pong = ConnectedPong { ping_time: 1, pong_time: 2 }.encode();
        assert!(matches!(classify(&pong).unwrap(), SystemMessage::ConnectedPong(_)));
        let disc = Disconnect.encode();
        assert!(matches!(classify(&disc).unwrap(), SystemMessage::Disconnect(_)));
    }

    #[test]
    fn classify_routes_unknown_to_application() {
        // 0x99 is not a system message ID → Application.
        match classify(&[0x99, 0x01, 0x02]).unwrap() {
            SystemMessage::Application(b) => assert_eq!(b, vec![0x99, 0x01, 0x02]),
            other => panic!("expected Application, got {other:?}"),
        }
    }

    #[test]
    fn classify_rejects_empty() {
        assert!(classify(&[]).is_err());
    }
}
