//! Minecraft Java Edition Server List Ping (SLP) implementation.
//!
//! Follows a reqwest-style [`Client`] + [`RequestBuilder`] pattern: create a
//! reusable [`Client`], call [`Client::ping`] to get a [`RequestBuilder`],
//! chain configuration, then call [`RequestBuilder::send`] to issue the
//! request.
//!
//! Protocol flow (over TCP, default port 25565):
//! 1. The client sends a **Handshake** packet (ID `0x00`) with Next State = `1` (Status).
//! 2. The client sends a **Status Request** packet (ID `0x00`, empty payload).
//! 3. The server replies with a **Status Response** packet (ID `0x00`, payload is a JSON string).
//! 4. (Optional) The client sends a **Ping Request** packet (ID `0x01`, 8-byte timestamp);
//!    the server replies with **Pong** (ID `0x01`, echoing the same timestamp), used to
//!    measure round-trip latency.
//!
//! Each packet is prefixed with a VarInt encoding the "remaining payload length"
//! (i.e. length of Packet ID + Data).
//!
//! This crate does not build in a timeout; callers can wrap
//! [`RequestBuilder::send`] with `tokio::time::timeout`.
//!
//! Reference: <https://minecraft.wiki/w/Java_Edition_protocol/Server_List_Ping>

use std::io::{self, Cursor};
use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::addr::HostAddr;
use crate::error::{PingError, Result};
use crate::varint::{VarInt, VarIntRead, VarIntWrite};

/// Default port for Java Edition.
pub const DEFAULT_PORT: u16 = 25565;

// ==================== Response types ====================

/// Root structure of the Status Response (corresponds to the server's JSON).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Server version info.
    pub version: Version,
    /// Current player info.
    pub players: Players,
    /// Server MOTD. May be a plain string or an object with extra styling.
    #[serde(deserialize_with = "deserialize_description")]
    pub description: Description,
    /// Server icon (base64-encoded PNG), optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favicon: Option<String>,
    /// Whether secure chat is enforced (1.19+).
    #[serde(
        default,
        rename = "enforcesSecureChat",
        skip_serializing_if = "Option::is_none"
    )]
    pub enforces_secure_chat: Option<bool>,
    /// Whether chat preview is enabled (1.19+).
    #[serde(
        default,
        rename = "previewsChat",
        skip_serializing_if = "Option::is_none"
    )]
    pub previews_chat: Option<bool>,
}

/// The `version` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    /// Human-readable version name, e.g. `"1.21.8"` or `"26.1"`.
    pub name: String,
    /// Protocol version number, e.g. `772`.
    pub protocol: i32,
}

/// The `players` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Players {
    /// Maximum number of players.
    pub max: i32,
    /// Number of players currently online.
    pub online: i32,
    /// Sample of online players (may be empty or absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample: Option<Vec<PlayerSample>>,
}

/// A single player sample entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayerSample {
    /// Player name.
    pub name: String,
    /// Player UUID (as a string).
    pub id: String,
}

/// MOTD. Supports two historical formats:
/// - Legacy/simple: a plain string like `"A Minecraft Server"`.
/// - Modern: an object like `{"text": "...", "extra": [...]}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Description {
    /// Plain-text form.
    Plain(String),
    /// Structured / styled object form.
    Object {
        /// Main text.
        text: String,
        /// Extra fragments (optional).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extra: Option<Vec<serde_json::Value>>,
        /// Remaining raw JSON fields (preserves unrecognized fields).
        #[serde(flatten)]
        other: serde_json::Map<String, serde_json::Value>,
    },
}

impl Description {
    /// Best-effort extraction of readable plain text (concatenates `text` and
    /// any `text` inside `extra`).
    pub fn to_plain_text(&self) -> String {
        match self {
            Description::Plain(s) => s.clone(),
            Description::Object { text, extra, .. } => {
                let mut out = text.clone();
                if let Some(extras) = extra {
                    for e in extras {
                        if let Some(t) = e.get("text").and_then(|v| v.as_str()) {
                            out.push_str(t);
                        }
                    }
                }
                out
            }
        }
    }
}

/// Custom deserialization mapping the description field onto [`Description`].
fn deserialize_description<'de, D>(deserializer: D) -> std::result::Result<Description, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(deserializer)
}

// ==================== Client / RequestBuilder ====================

/// A reusable Java Edition SLP client.
///
/// Created via [`Client::new`]; queries are issued via [`Client::ping`].
/// Currently holds no connection state internally; it may be extended with a
/// connection pool in the future.
#[derive(Debug, Clone, Default)]
pub struct Client {}

impl Client {
    /// Creates a client with default configuration.
    pub fn new() -> Self {
        Self {}
    }

    /// Starts an SLP against the target address, returning a
    /// [`RequestBuilder`] for chained configuration and sending.
    ///
    /// `addr` accepts anything implementing [`HostAddr`], e.g. a
    /// `("host.example.com", 25565)` tuple or a [`SocketAddr`]. DNS resolution
    /// happens synchronously at this point (on failure [`PingError::Io`] is
    /// returned).
    pub fn ping<A: HostAddr>(&self, addr: A) -> Result<RequestBuilder> {
        RequestBuilder::new(addr)
    }
}

/// The "any version" protocol number sent in the handshake. The server ignores
/// it and returns its own protocol version.
const ANY_PROTOCOL_VERSION: i32 = -1;

/// SLP request builder (reqwest style).
///
/// Created by [`Client::ping`]. Chain [`RequestBuilder::protocol_version`] to
/// adjust the handshake protocol version, then call [`RequestBuilder::send`] to
/// issue the request.
///
/// To measure round-trip latency, call [`RequestBuilder::with_latency`] to
/// switch to a [`LatencyRequestBuilder`], whose [`LatencyRequestBuilder::send`]
/// additionally returns the latency.
#[derive(Debug, Clone)]
pub struct RequestBuilder {
    /// Resolved target address, used for the TCP connection.
    addr: SocketAddr,
    /// String used in the handshake packet's Server Address field.
    /// In the Minecraft protocol this field is mainly for virtual-host routing;
    /// passing an IP or a domain works for the vast majority of servers.
    host_for_handshake: String,
    /// Port.
    port: u16,
    /// Protocol version declared in the handshake. `-1` means "any".
    protocol_version: i32,
}

impl RequestBuilder {
    fn new<A: HostAddr>(addr: A) -> Result<Self> {
        let host_for_handshake = addr.host_string();
        let mut addrs = addr.to_socket_addrs_with_default(DEFAULT_PORT)?;
        let socket = addrs.pop().ok_or_else(|| {
            PingError::Protocol("to_socket_addrs returned no address".to_string())
        })?;
        Ok(RequestBuilder {
            addr: socket,
            host_for_handshake,
            port: socket.port(),
            protocol_version: ANY_PROTOCOL_VERSION,
        })
    }

    /// Sets the protocol version declared in the handshake (default `-1`,
    /// meaning "any").
    pub fn protocol_version(mut self, v: i32) -> Self {
        self.protocol_version = v;
        self
    }

    /// Switches to a latency-measuring request builder.
    ///
    /// The returned [`LatencyRequestBuilder::send`] performs one extra
    /// ping/pong round trip and returns `(StatusResponse, Duration)`.
    pub fn with_latency(self) -> LatencyRequestBuilder {
        LatencyRequestBuilder { inner: self }
    }

    /// Sends the request and returns the [`StatusResponse`].
    pub async fn send(self) -> Result<StatusResponse> {
        let mut stream = TcpStream::connect(self.addr).await?;
        let _ = stream.set_nodelay(true);

        // ---- Handshake ----
        let mut handshake = Vec::new();
        handshake.push(0x00); // Packet ID
        handshake.write_var_int(VarInt::from(self.protocol_version))?;
        write_string(&mut handshake, &self.host_for_handshake)?;
        handshake.extend_from_slice(&self.port.to_be_bytes()); // Unsigned Short, big-endian
        handshake.write_var_int(VarInt::from(1))?; // Next State = 1 (Status)
        send_packet(&mut stream, &handshake).await?;

        // ---- Status Request ----
        let status_request = vec![0x00]; // Packet ID, no payload
        send_packet(&mut stream, &status_request).await?;

        // ---- Status Response ----
        let payload = recv_packet(&mut stream).await?;
        if payload.first().copied() != Some(0x00) {
            return Err(PingError::Protocol(format!(
                "Status Response packet ID is not 0x00: {:?}",
                payload.first()
            )));
        }
        let (json_str, _consumed) = read_string(&payload[1..])?;
        let status: StatusResponse = serde_json::from_str(&json_str)?;
        Ok(status)
    }
}

/// A latency-measuring SLP request builder.
///
/// Created by [`RequestBuilder::with_latency`]. Its
/// [`LatencyRequestBuilder::send`] performs one extra ping/pong round trip and
/// returns `(StatusResponse, Duration)`.
#[derive(Debug, Clone)]
pub struct LatencyRequestBuilder {
    inner: RequestBuilder,
}

impl LatencyRequestBuilder {
    /// Sets the protocol version declared in the handshake (default `-1`,
    /// meaning "any").
    pub fn protocol_version(mut self, v: i32) -> Self {
        self.inner.protocol_version = v;
        self
    }

    /// Sends the request and returns `([`StatusResponse`], latency)`.
    pub async fn send(self) -> Result<(StatusResponse, Duration)> {
        let this = self.inner;
        let mut stream = TcpStream::connect(this.addr).await?;
        let _ = stream.set_nodelay(true);

        // ---- Handshake ----
        let mut handshake = Vec::new();
        handshake.push(0x00);
        handshake.write_var_int(VarInt::from(this.protocol_version))?;
        write_string(&mut handshake, &this.host_for_handshake)?;
        handshake.extend_from_slice(&this.port.to_be_bytes());
        handshake.write_var_int(VarInt::from(1))?;
        send_packet(&mut stream, &handshake).await?;

        // ---- Status Request ----
        let status_request = vec![0x00];
        send_packet(&mut stream, &status_request).await?;

        // ---- Status Response ----
        let payload = recv_packet(&mut stream).await?;
        if payload.first().copied() != Some(0x00) {
            return Err(PingError::Protocol(format!(
                "Status Response packet ID is not 0x00: {:?}",
                payload.first()
            )));
        }
        let (json_str, _) = read_string(&payload[1..])?;
        let status: StatusResponse = serde_json::from_str(&json_str)?;

        // ---- Ping Request / Pong ----
        let sent = chrono_now_millis();
        let mut ping_request = Vec::new();
        ping_request.push(0x01); // Packet ID
        ping_request.extend_from_slice(&sent.to_be_bytes()); // 8-byte payload
        let t0 = tokio::time::Instant::now();
        send_packet(&mut stream, &ping_request).await?;

        let pong = recv_packet(&mut stream).await?;
        let elapsed = t0.elapsed();
        if pong.first().copied() != Some(0x01) {
            return Err(PingError::Protocol(format!(
                "Pong packet ID is not 0x01: {:?}",
                pong.first()
            )));
        }
        if pong.len() < 9 {
            return Err(PingError::Protocol(format!(
                "Pong payload too short: {} bytes",
                pong.len()
            )));
        }
        let echoed = i64::from_be_bytes(pong[1..9].try_into().unwrap());
        if echoed != sent {
            return Err(PingError::Protocol(format!(
                "Pong echoed timestamp mismatch: sent {sent}, received {echoed}"
            )));
        }
        Ok((status, elapsed))
    }
}

/// Convenience method: performs a one-shot Server List Ping against the target.
///
/// **Note**: this function creates a new internal [`Client`] on each call, so it
/// is not suitable for large volumes of concurrent queries. To reuse a client or
/// measure latency, use [`Client::ping`] instead.
///
/// `addr` accepts anything implementing [`HostAddr`]: a `"host:port"` string
/// (when no port is given, [`DEFAULT_PORT`] = 25565 is filled in), a
/// `("host", port)` tuple, a [`SocketAddr`], etc. IPv6 bracket form
/// (`"[::1]:25565"`) is supported.
///
/// # Examples
///
/// Using a string address (the default port 25565 is filled in when omitted):
///
/// ```no_run
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let status = mcget::ping_java("mc.hypixel.net:25565").await?;
/// println!("{} online {}/{}",
///     status.version.name, status.players.online, status.players.max);
/// # Ok(())
/// # }
/// ```
///
/// Using a tuple form (also supported):
///
/// ```no_run
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let status = mcget::ping_java(("mc.hypixel.net", 25565)).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// This function returns [`Err`] ([`PingError`]) when:
///
/// - `addr` cannot be resolved to a socket address (DNS failure, [`PingError::Io`])
/// - the TCP connection cannot be established (refused / timed out, [`PingError::Io`])
/// - an I/O error occurs while talking to the server (connection reset, [`PingError::Io`])
/// - the server's response does not conform to the SLP protocol (wrong packet ID, etc., [`PingError::Protocol`])
/// - the JSON response cannot be parsed ([`PingError::Json`])
pub async fn ping<A: HostAddr>(addr: A) -> Result<StatusResponse> {
    Client::new().ping(addr)?.send().await
}

// ==================== Packet-level I/O helpers ====================

/// Sends a complete packet: writes the VarInt length prefix, then the payload.
async fn send_packet(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.write_var_int(VarInt::from(payload.len() as i32))?;
    frame.extend_from_slice(payload);
    stream.write_all(&frame).await?;
    Ok(())
}

/// Reads a complete packet: reads the VarInt length, then the payload of that length.
async fn recv_packet(stream: &mut TcpStream) -> Result<Vec<u8>> {
    // The VarInt length prefix: accumulate byte by byte into `len` with no
    // intermediate buffer. A one-element slice is constructed on each read as
    // the read target.
    let mut len: i32 = 0;
    let mut shift: u32 = 0;
    loop {
        let mut byte = 0u8;
        let n = stream.read(std::slice::from_mut(&mut byte)).await?;
        if n == 0 {
            return Err(PingError::Protocol(
                "connection closed while reading packet length".to_string(),
            ));
        }
        if shift >= 35 {
            // A VarInt for i32 is at most 5 bytes; the highest significant
            // shift for the 5th byte is 28. Reaching shift 35 means a 6th byte,
            // which is invalid.
            return Err(PingError::Protocol(
                "packet length VarInt exceeds 5 bytes".to_string(),
            ));
        }
        len |= ((byte & 0x7F) as i32) << shift;
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
    }
    if len < 0 {
        return Err(PingError::Protocol(format!(
            "negative packet length: {len}"
        )));
    }
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Writes a Minecraft-style string: VarInt length (in bytes) + UTF-8 bytes.
///
/// Follows the `std::io::Write` style: accepts any `io::Write` target and
/// returns `io::Result`.
fn write_string<W: io::Write>(buf: &mut W, s: &str) -> io::Result<()> {
    let bytes = s.as_bytes();
    buf.write_var_int(VarInt::from(bytes.len() as i32))?;
    buf.write_all(bytes)
}

/// Reads a Minecraft-style string from the start of a byte slice, returning
/// `(string, number of bytes consumed)`.
fn read_string(bytes: &[u8]) -> Result<(String, usize)> {
    // Parse the length prefix using a synchronous Cursor + the VarIntRead trait.
    let mut cursor = Cursor::new(bytes);
    let vi = cursor.read_var_int().map_err(io_to_ping)?;
    let len = i32::from(vi);
    if len < 0 {
        return Err(PingError::Protocol(format!(
            "negative string length: {len}"
        )));
    }
    // cursor.position() reports how many bytes have been consumed.
    let n = cursor.position() as usize;
    let len = len as usize;
    if bytes.len() < n + len {
        return Err(PingError::Protocol(format!(
            "string declares {len} bytes but not enough input remains"
        )));
    }
    let s = std::str::from_utf8(&bytes[n..n + len])
        .map_err(|e| PingError::Protocol(format!("string is not UTF-8: {e}")))?;
    Ok((s.to_string(), n + len))
}

/// Maps an [`std::io::Error`] to a [`PingError`].
fn io_to_ping(e: std::io::Error) -> PingError {
    PingError::Protocol(format!("VarInt parse I/O error: {e}"))
}

/// Current time as a millisecond timestamp (i64). Uses SystemTime to avoid
/// pulling in chrono.
fn chrono_now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_description() {
        let json = r#"{"text":"hello"}"#;
        let d: Description = serde_json::from_str(json).unwrap();
        assert_eq!(d.to_plain_text(), "hello");
    }

    #[test]
    fn parse_plain_string_description() {
        let json = r#""A Minecraft Server""#;
        let d: Description = serde_json::from_str(json).unwrap();
        assert_eq!(d.to_plain_text(), "A Minecraft Server");
    }

    #[test]
    fn parse_full_status_response() {
        let json = r#"{
            "version": {"name": "1.21.8", "protocol": 772},
            "players": {"max": 20, "online": 3, "sample": [{"name": "Steve", "id": "abc"}]},
            "description": {"text": "Hi", "extra": [{"text": "!"}]},
            "favicon": "data:image/png;base64,xxx",
            "enforcesSecureChat": true
        }"#;
        let s: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(s.version.protocol, 772);
        assert_eq!(s.players.online, 3);
        assert_eq!(s.description.to_plain_text(), "Hi!");
        assert_eq!(s.enforces_secure_chat, Some(true));
        assert!(s.favicon.is_some());
    }

    #[test]
    fn string_helpers_roundtrip() {
        let mut buf = Vec::new();
        write_string(&mut buf, "hello").unwrap();
        let (s, n) = read_string(&buf).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(n, buf.len());
    }

    #[test]
    fn client_ping_resolves_addr() {
        // localhost should always resolve.
        let client = Client::new();
        let req = client.ping(("127.0.0.1", 25565)).unwrap();
        assert_eq!(req.port, 25565);
        assert_eq!(req.host_for_handshake, "127.0.0.1");
        assert_eq!(req.protocol_version, ANY_PROTOCOL_VERSION);
    }

    #[test]
    fn protocol_version_builder_chain() {
        let client = Client::new();
        let req = client.ping(("127.0.0.1", 25565)).unwrap();
        let req = req.protocol_version(770);
        assert_eq!(req.protocol_version, 770);
    }
}
