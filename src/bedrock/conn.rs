//! RakNet **connection handshake** — establish a persistent UDP session with a
//! Bedrock server.
//!
//! Unlike [`super::ping()`] (a single connectionless round-trip), this module
//! performs the full 4-packet RakNet handshake and returns a [`Connection`]
//! that holds an open socket plus the negotiated session parameters
//! (`server_guid`, MTU, encryption flag).
//!
//! ## Handshake flow
//!
//! ```text
//! Client                              Server
//!   |  0x05 Open Connection Request 1   |
//!   |  (magic, proto_version, MTU pad)  |
//!   |---------------------------------->|
//!   |                                   |
//!   |  0x06 Open Connection Reply 1     |
//!   |  (magic, server_guid, use_enc,    |
//!   |   mtu)                             |
//!   |<----------------------------------|
//!   |                                   |
//!   |  0x07 Open Connection Request 2   |
//!   |  (magic, client_addr, mtu,        |
//!   |   client_guid)                     |
//!   |---------------------------------->|
//!   |                                   |
//!   |  0x08 Open Connection Reply 2     |
//!   |  (magic, server_guid, client_addr,|
//!   |   mtu, use_enc)                    |
//!   |<----------------------------------|
//!   |                                   |
//!   |     session established           |
//! ```
//!
//! If the server refuses the connection it replies with one of the rejection
//! packets `0x09`–`0x0c` (IncompatibleProtocolVersion / IP banned / already
//! connected / no free incoming connections) instead of a Reply; the specific
//! reason appears in the resulting [`crate::error::PingError::Protocol`] message.
//!
//! ## Current limitations
//!
//! After [`Connection::connect`] succeeds the UDP session is established, but
//! **no application-layer packets can be sent yet** — RakNet wraps them in
//! datagram frames (`0x80`–`0x8D`) with 24-bit sequence numbers and ACK/NACK
//! handling, which is not implemented in this crate today. [`Connection::close`]
//! therefore simply drops the socket rather than sending a graceful `0x13`
//! Disconnect (which itself must be framed).
//!
//! References: <https://wiki.bedrock.dev/servers/raknet>, <https://minecraft.wiki/w/RakNet>

use super::*;
use crate::addr::HostAddr;
use crate::error::{PingError, Result};
use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

// Re-export the connected-layer wire-format types so callers can build
// datagrams and inspect incoming packets through the
// `mcget::bedrock::conn::{Datagram, Frame, Reliability, Incoming}` path. The
// `send_datagram` / `recv_raw` methods below refer to these in their signatures.
pub use super::datagram::{Datagram, Frame, Incoming, Reliability};

// ==================== Packet IDs ====================

/// Open Connection Request 1.
const ID_OPEN_CONN_REQ_1: u8 = 0x05;
/// Open Connection Reply 1.
const ID_OPEN_CONN_REPL_1: u8 = 0x06;
/// Open Connection Request 2.
const ID_OPEN_CONN_REQ_2: u8 = 0x07;
/// Open Connection Reply 2.
const ID_OPEN_CONN_REPL_2: u8 = 0x08;

/// Handshake rejection: incompatible protocol version (0x09).
const ID_INCOMPATIBLE_PROTOCOL: u8 = 0x09;
/// Handshake rejection: IP recently banned (0x0a).
const ID_IP_BANNED: u8 = 0x0a;
/// Handshake rejection: already connected (0x0b).
const ID_ALREADY_CONNECTED: u8 = 0x0b;
/// Handshake rejection: no free incoming connections / server full (0x0c).
const ID_NO_FREE_INCOMING: u8 = 0x0c;

/// Receive buffer for handshake packets.
const RECV_BUF_LEN: usize = 2048;

/// Minimum safe MTU for the RakNet handshake (Ethernet minimum payload minus headers).
const MIN_MTU: u16 = 46;

// IPv4 system-address codec (`encode_ipv4_addr` / `decode_ipv4_addr`) lives in
// [`super::raknet`] now — it is a shared wire-format primitive reused by both
// the Request 2 builder and the Reply 2 parser below.

// ==================== Parsed reply structs ====================

/// Fields parsed from a Reply 1 (0x06) packet.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reply1 {
    server_guid: i64,
    use_encryption: bool,
    mtu: u16,
}

/// Fields parsed from a Reply 2 (0x08) packet.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reply2 {
    server_guid: i64,
    client_addr: SocketAddr,
    mtu: u16,
    use_encryption: bool,
}

/// Structured reason for a handshake rejection (packets 0x09–0x0c).
///
/// Rejections are surfaced to the caller as [`PingError::Protocol`] with a
/// human-readable message derived from this enum via [`HandshakeRejection::as_message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeRejection {
    /// 0x09 — server protocol version differs from `protocol_version`.
    IncompatibleProtocol { server_protocol: u8 },
    /// 0x0a — this client IP was recently banned.
    IpBanned,
    /// 0x0b — a session from this client already exists.
    AlreadyConnected,
    /// 0x0c — server is full / not accepting new connections.
    NoFreeIncomingConnections,
}

impl HandshakeRejection {
    /// Returns the human-readable explanation used in the [`PingError::Protocol`]
    /// message string.
    fn as_message(self, client_protocol: u8) -> String {
        match self {
            HandshakeRejection::IncompatibleProtocol { server_protocol } => format!(
                "incompatible protocol version (server={server_protocol}, client={client_protocol})"
            ),
            HandshakeRejection::IpBanned => "client IP was recently banned".to_string(),
            HandshakeRejection::AlreadyConnected => "already connected".to_string(),
            HandshakeRejection::NoFreeIncomingConnections => {
                "no free incoming connections (server full)".to_string()
            }
        }
    }
}

// ==================== Connection ====================

/// A persistent RakNet session with a Bedrock server, established via the
/// 4-packet handshake.
///
/// Created with [`Connection::connect`] (default settings) or
/// [`Connection::builder`] for tunable parameters. The struct owns the UDP
/// socket, so it is **not** `Clone`; drop or [`Connection::close`] it to release
/// the socket.
///
/// ## Current limitations
///
/// The session is established but no application-layer packets can be sent or
/// received yet (see the [module docs](self)). [`Connection::close`] drops the
/// socket without sending a graceful Disconnect.
///
/// # Examples
///
/// Connect with defaults (client GUID 0, protocol version 11):
///
/// ```no_run
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let conn = mcget::bedrock::conn::Connection::connect("play.x.net").await?;
/// println!("server_guid={} mtu={} encryption={}",
///     conn.server_guid(), conn.mtu(), conn.use_encryption());
/// conn.close().await?;
/// # Ok(())
/// # }
/// ```
///
/// Connect with a custom client GUID and protocol version:
///
/// ```no_run
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// use std::time::Duration;
/// use mcget::bedrock::conn::{Connection, ConnectBuilder};
/// let conn = ConnectBuilder::default()
///     .client_guid(12345)
///     .protocol_version(11)
///     .timeout(Duration::from_secs(5))
///     .send("play.x.net")
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// Or, via a [`crate::bedrock::Client`] so the client GUID is configured once:
///
/// ```no_run
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let client = mcget::bedrock::Client::new().client_guid(12345);
/// // `connect` inherits client_guid(12345); `ping` does too.
/// let conn = client.connect().send("play.x.net").await?;
/// # Ok(())
/// # }
/// ```
pub struct Connection {
    // Held open for the lifetime of the session. Exposed (read/write) via the
    // `send_datagram` / `recv_raw` methods; tokio's UdpSocket accepts `&self`
    // for both, so no interior mutability is needed.
    socket: UdpSocket,
    server_addr: SocketAddr,
    server_guid: i64,
    mtu: u16,
    use_encryption: bool,
    client_guid: i64,
}

impl Connection {
    /// Connects to `addr` using default handshake settings.
    ///
    /// Equivalent to [`Connection::builder`]`().send(addr)`. Defaults:
    /// client GUID 0, RakNet protocol version 11, MTU candidates
    /// `[1492, 1200, 576]`, overall timeout 10 s, 3 retries per stage.
    ///
    /// `addr` accepts anything implementing [`HostAddr`]: a `"host:port"`
    /// string (default port 19132 when omitted), a `("host", port)` tuple, or a
    /// [`SocketAddr`].
    ///
    /// # Errors
    ///
    /// Returns [`PingError::Io`] on DNS / socket failure, [`PingError::Protocol`]
    /// on handshake rejection (one of `0x09`–`0x0c`), bad packet, or
    /// timeout.
    pub async fn connect<A: HostAddr>(addr: A) -> Result<Self> {
        ConnectBuilder::default().send(addr).await
    }

    /// Returns a [`ConnectBuilder`] for tuning handshake parameters.
    pub fn builder() -> ConnectBuilder {
        ConnectBuilder::default()
    }

    /// The server's 64-bit GUID (negotiated in Reply 1 / Reply 2).
    pub fn server_guid(&self) -> i64 {
        self.server_guid
    }

    /// The negotiated MTU (smallest of the candidates the server accepted).
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Consumes the connection and returns the owned UDP socket, severing the
    /// session from this type. Used by [`super::reliable_conn::ReliableConnection`]
    /// to drive the socket through a reliability engine. Callers that want to
    /// keep using [`send_datagram`](Self::send_datagram) /
    /// [`recv_raw`](Self::recv_raw) should not call this.
    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }

    /// Whether the server requested packet encryption for this session.
    pub fn use_encryption(&self) -> bool {
        self.use_encryption
    }

    /// This client's GUID (as sent in Request 2).
    pub fn client_guid(&self) -> i64 {
        self.client_guid
    }

    /// The server's resolved socket address.
    pub fn peer(&self) -> SocketAddr {
        self.server_addr
    }

    /// Sends a fully-constructed [`Datagram`] to the server over the open socket.
    ///
    /// This is the **lowest-level send**: the caller is responsible for setting
    /// the datagram's sequence number and the reliability/index fields of every
    /// [`Frame`] it carries. No sequence-number allocation, no ACK tracking, no
    /// retransmission is performed here — those live in a future reliability
    /// layer built on top of this primitive.
    ///
    /// The encoded datagram is checked against the negotiated [`MTU`](Self::mtu):
    /// a datagram larger than the MTU would be fragmented by the IP layer, which
    /// RakNet forbids, so it is rejected with [`PingError::Protocol`].
    ///
    /// # Examples
    ///
    /// Send a single unreliable frame carrying arbitrary bytes (no reliability
    /// guarantees — the server may or may not act on it):
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// use mcget::bedrock::conn::{Connection, Datagram, Frame, Reliability};
    /// let conn = Connection::connect("play.x.net").await?;
    /// let dg = Datagram::new(0, vec![Frame::new(Reliability::Unreliable, vec![0x42])])?;
    /// conn.send_datagram(&dg).await?;
    /// conn.close().await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`PingError::Protocol`] if the encoded datagram exceeds the MTU,
    /// or if frame encoding itself fails (e.g. a reliability/index mismatch).
    /// Returns [`PingError::Io`] on socket send failure.
    pub async fn send_datagram(&self, datagram: &Datagram) -> Result<()> {
        let buf = datagram.encode()?;
        if buf.len() > self.mtu as usize {
            return Err(PingError::Protocol(format!(
                "datagram is {} bytes which exceeds the negotiated MTU of {}",
                buf.len(),
                self.mtu
            )));
        }
        self.socket.send(&buf).await?;
        Ok(())
    }

    /// Receives one UDP datagram from the server and decodes it via
    /// [`datagram::classify`](super::datagram::classify) into a datagram, ACK,
    /// or NACK.
    ///
    /// This is the **lowest-level receive**: it returns the raw classification
    /// result so the caller can dispatch (`Incoming::Datagram` carries
    /// application/system frames; `Incoming::Ack` / `Incoming::Nack` carry
    /// sequence-number ranges a reliability layer would act on). No ACK is sent
    /// automatically — without one, the peer will eventually retransmit or time
    /// the session out.
    ///
    /// This method does **not** time out on its own; wrap it with
    /// `tokio::time::timeout` to bound the wait (matching the crate convention
    /// of no built-in timeouts).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::time::Duration;
    /// use mcget::bedrock::conn::{Connection, Incoming};
    /// let conn = Connection::connect("play.x.net").await?;
    /// match tokio::time::timeout(Duration::from_secs(5), conn.recv_raw()).await {
    ///     Ok(Ok(incoming)) => println!("received: {incoming:?}"),
    ///     Ok(Err(e)) => return Err(e.into()),
    ///     Err(_) => println!("timed out waiting for a packet"),
    /// }
    /// conn.close().await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`PingError::Io`] on socket receive failure, or
    /// [`PingError::Protocol`] if the received bytes are not a valid datagram /
    /// ACK / NACK (e.g. a truncated or unknown packet).
    pub async fn recv_raw(&self) -> Result<Incoming> {
        // Size the receive buffer to just past the MTU so a well-formed datagram
        // always fits, while a too-large packet (which shouldn't happen on a
        // healthy link) is still caught rather than silently truncated.
        let mut buf = vec![0u8; self.mtu as usize + 1];
        let n = self.socket.recv(&mut buf).await?;
        super::datagram::classify(&buf[..n])
    }

    /// Closes the session by dropping the socket.
    ///
    /// **Note**: this does **not** send a graceful `0x13` Disconnect (that
    /// packet must itself be framed by the datagram layer, which is not yet
    /// implemented). The server will detect the loss via its own keep-alive
    /// timeout.
    pub async fn close(self) -> Result<()> {
        // Explicit drop documents intent; the socket is released when self is dropped.
        drop(self);
        Ok(())
    }
}

// ==================== ConnectBuilder ====================

/// Tunable configuration for the RakNet handshake.
///
/// Built via [`ConnectBuilder::default`] (or [`Connection::builder`]); consume
/// with [`ConnectBuilder::send`]. To inherit a client GUID from a
/// [`crate::bedrock::Client`], call [`crate::bedrock::Client::connect`] instead
/// of constructing the builder directly.
#[derive(Debug, Clone)]
pub struct ConnectBuilder {
    client_guid: i64,
    protocol_version: u8,
    mtu_candidates: Vec<u16>,
    timeout: Duration,
    max_retries: u32,
}

impl Default for ConnectBuilder {
    fn default() -> Self {
        Self::with_client_guid(0)
    }
}

impl ConnectBuilder {
    /// Creates a builder with the given client GUID and otherwise-default
    /// settings.
    ///
    /// This is the entry point used by [`crate::bedrock::Client::connect`] to
    /// seed the builder with the client's configured GUID. Standalone callers
    /// usually want [`ConnectBuilder::default`] (GUID 0) or
    /// [`ConnectBuilder::client_guid`] to override.
    pub(super) fn with_client_guid(client_guid: i64) -> Self {
        Self {
            client_guid,
            protocol_version: 11,
            mtu_candidates: vec![1492, 1200, 576],
            timeout: Duration::from_secs(10),
            max_retries: 3,
        }
    }
    /// Sets the client GUID sent in Request 2 (default 0, or the GUID inherited
    /// from [`crate::bedrock::Client::connect`]).
    pub fn client_guid(mut self, guid: i64) -> Self {
        self.client_guid = guid;
        self
    }

    /// Sets the RakNet protocol version advertised in Request 1 (default 11).
    pub fn protocol_version(mut self, version: u8) -> Self {
        self.protocol_version = version;
        self
    }

    /// Sets the MTU candidates tried in order (default `[1492, 1200, 576]`).
    ///
    /// The first candidate the server accepts (via Reply 1) wins. If none
    /// succeed the handshake fails with `Protocol("all MTU candidates rejected")`.
    pub fn mtu_candidates(mut self, candidates: Vec<u16>) -> Self {
        self.mtu_candidates = candidates;
        self
    }

    /// Sets the overall handshake timeout (default 10 s).
    ///
    /// Covers the entire Request 1 → Reply 1 → Request 2 → Reply 2 exchange.
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Sets the per-stage retry count (default 3).
    ///
    /// Each of the two stages retransmits its Request up to this many times
    /// while waiting for a Reply.
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Runs the handshake against `addr` and returns a live [`Connection`].
    ///
    /// This is the fully-tunable entry point (see [`Connection::connect`] for a
    /// no-configuration shortcut). Named `send` to mirror
    /// [`crate::bedrock::RequestBuilder::send`], so both `client.ping(addr).send()`
    /// and `client.connect().send(addr)` read the same way.
    pub async fn send<A: HostAddr>(self, addr: A) -> Result<Connection> {
        // Resolve the peer. DNS is synchronous here, as elsewhere in this crate.
        let mut addrs = addr.to_socket_addrs_with_default(DEFAULT_PORT)?;
        let server_addr = addrs.pop().ok_or_else(|| {
            PingError::Protocol("to_socket_addrs returned no address".to_string())
        })?;

        let peer_addr_v4 = match server_addr {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => {
                return Err(PingError::Protocol(
                    "IPv6 server addresses are not supported by the handshake yet".to_string(),
                ));
            }
        };

        // Bind the persistent socket. This crate is IPv4-only for the handshake.
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(server_addr).await?;

        // Wrap the whole exchange in the overall timeout.
        let handshake = async {
            // Stage 1: Request 1 / Reply 1 — negotiate MTU.
            let reply1 = self.stage1(&socket, peer_addr_v4).await?;

            // Stage 2: Request 2 / Reply 2 — finalize the session.
            let local_addr = match socket.local_addr()? {
                SocketAddr::V4(v4) => v4,
                SocketAddr::V6(_) => {
                    return Err(PingError::Protocol(
                        "local socket bound to IPv6 (handshake is IPv4-only)".to_string(),
                    ));
                }
            };
            let reply2 = self.stage2(&socket, local_addr, reply1.mtu).await?;

            Ok::<_, PingError>((reply1, reply2))
        };

        let (reply1, reply2) = match timeout(self.timeout, handshake).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(PingError::Protocol(format!(
                    "handshake timed out after {:?}",
                    self.timeout
                )));
            }
        };

        // Reply 2 is the server's final confirmation; sanity-check that the
        // negotiated MTU / server GUID agree with Reply 1 (they always should).
        if reply2.mtu != reply1.mtu || reply2.server_guid != reply1.server_guid {
            return Err(PingError::Protocol(format!(
                "handshake parameters diverged between Reply 1 and Reply 2 \
                 (guid {0}/{1}, mtu {2}/{3})",
                reply1.server_guid, reply2.server_guid, reply1.mtu, reply2.mtu
            )));
        }

        Ok(Connection {
            socket,
            server_addr,
            server_guid: reply2.server_guid,
            mtu: reply2.mtu,
            use_encryption: reply2.use_encryption,
            client_guid: self.client_guid,
        })
    }

    /// Stage 1: try each MTU candidate in turn until a server replies 0x06.
    ///
    /// A rejection packet (0x09–0x0c) fails the whole handshake immediately.
    /// Timeouts / unknown packets advance to the next candidate; if all are
    /// exhausted the handshake fails with "all MTU candidates rejected".
    async fn stage1(&self, socket: &UdpSocket, _peer: SocketAddrV4) -> Result<Reply1> {
        for &mtu in &self.mtu_candidates {
            if mtu < MIN_MTU {
                continue;
            }
            let req = build_request1(self.protocol_version, mtu);

            for _ in 0..self.max_retries {
                socket.send(&req).await?;

                // Per-attempt wait: a fraction of the overall timeout, evenly
                // divided across (candidates × retries) attempts.
                let per_attempt =
                    self.timeout / (self.mtu_candidates.len() as u32 * self.max_retries);
                let per_attempt = per_attempt.max(Duration::from_millis(500));
                let mut buf = [0u8; RECV_BUF_LEN];
                match timeout(per_attempt, socket.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        if let Some(rej) = classify_rejection(&buf[..n])? {
                            return Err(PingError::Protocol(format!(
                                "handshake rejected: {}",
                                rej.as_message(self.protocol_version)
                            )));
                        }
                        if let Some(reply) = parse_reply1(&buf[..n])? {
                            return Ok(reply);
                        }
                        // Unknown packet — fall through to retry.
                    }
                    Ok(Err(_)) | Err(_) => {
                        // I/O error or per-attempt timeout: retry / next MTU.
                        continue;
                    }
                }
            }
        }
        Err(PingError::Protocol(
            "all MTU candidates rejected".to_string(),
        ))
    }

    /// Stage 2: send Request 2 and wait for Reply 2.
    async fn stage2(
        &self,
        socket: &UdpSocket,
        local_addr: SocketAddrV4,
        mtu: u16,
    ) -> Result<Reply2> {
        let req = build_request2(local_addr, mtu, self.client_guid);

        for _ in 0..self.max_retries {
            socket.send(&req).await?;

            let per_attempt = self.timeout / self.max_retries;
            let per_attempt = per_attempt.max(Duration::from_millis(500));
            let mut buf = [0u8; RECV_BUF_LEN];
            match timeout(per_attempt, socket.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    if let Some(rej) = classify_rejection(&buf[..n])? {
                        return Err(PingError::Protocol(format!(
                            "handshake rejected: {}",
                            rej.as_message(self.protocol_version)
                        )));
                    }
                    if let Some(reply) = parse_reply2(&buf[..n])? {
                        return Ok(reply);
                    }
                    // Unknown packet — retry.
                }
                Ok(Err(_)) | Err(_) => continue,
            }
        }
        Err(PingError::Protocol(format!(
            "no Reply 2 (0x08) after {} retries",
            self.max_retries
        )))
    }
}

// ==================== Packet builders ====================

/// Builds an Open Connection Request 1 (0x05):
/// `id | magic | protocol_version | zero-padding to MTU`.
///
/// The padding length encodes the client's proposed MTU: the total on-wire size
/// of this packet is the MTU the client wants the server to confirm.
fn build_request1(protocol_version: u8, mtu: u16) -> Vec<u8> {
    // Packet layout: id(1) + magic(16) + protocol_version(1) = 18 fixed bytes,
    // plus (mtu - 18) zero-padding bytes to pad the whole datagram to `mtu`.
    let mtu = mtu as usize;
    let fixed = 1 + MAGIC.len() + 1; // 18
    let total = if mtu >= fixed { mtu } else { fixed };
    let mut buf = Vec::with_capacity(total);
    buf.push(ID_OPEN_CONN_REQ_1);
    buf.extend_from_slice(&MAGIC);
    buf.push(protocol_version);
    buf.resize(total, 0);
    buf
}

/// Builds an Open Connection Request 2 (0x07):
/// `id | magic | client_addr(7) | mtu(u16 BE) | client_guid(i64 BE)`.
fn build_request2(client_addr: SocketAddrV4, mtu: u16, client_guid: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + MAGIC.len() + super::raknet::RAKNET_IPV4_LEN + 2 + 8);
    buf.push(ID_OPEN_CONN_REQ_2);
    buf.extend_from_slice(&MAGIC);
    buf.extend_from_slice(&super::raknet::encode_ipv4_addr(&client_addr));
    buf.extend_from_slice(&mtu.to_be_bytes());
    buf.extend_from_slice(&client_guid.to_be_bytes());
    buf
}

// ==================== Packet parsers ====================

/// Parses an Open Connection Reply 1 (0x06) from `data`.
///
/// Returns `Ok(Some(reply))` for a valid Reply 1, `Ok(None)` if `data` is not a
/// Reply 1 (wrong ID), and `Err` for a structurally valid Reply 1 with a
/// truncated body or bad magic.
fn parse_reply1(data: &[u8]) -> Result<Option<Reply1>> {
    // Peek at the ID without consuming: a mismatch means "not my packet" (Ok(None)),
    // distinct from a malformed-but-mine packet (Err).
    if data.first().copied() != Some(ID_OPEN_CONN_REPL_1) {
        return Ok(None);
    }
    // Layout: id(1) + magic(16) + server_guid(8) + use_encryption(1) + mtu(2) = 28.
    let mut p = super::raknet::PacketBuf::new(data, "Reply 1");
    p.expect_id(ID_OPEN_CONN_REPL_1)?;
    p.read_magic()?;
    let server_guid = p.read_i64()?;
    let use_encryption = p.read_u8()? != 0;
    let mtu = p.read_u16()?;
    Ok(Some(Reply1 {
        server_guid,
        use_encryption,
        mtu,
    }))
}

/// Parses an Open Connection Reply 2 (0x08) from `data`.
///
/// See [`parse_reply1`] for the `Option` convention.
fn parse_reply2(data: &[u8]) -> Result<Option<Reply2>> {
    // Peek at the ID without consuming: a mismatch means "not my packet" (Ok(None)),
    // distinct from a malformed-but-mine packet (Err).
    if data.first().copied() != Some(ID_OPEN_CONN_REPL_2) {
        return Ok(None);
    }
    // Layout: id(1) + magic(16) + server_guid(8) + client_addr(7) + mtu(2) + use_encryption(1) = 35.
    let mut p = super::raknet::PacketBuf::new(data, "Reply 2");
    p.expect_id(ID_OPEN_CONN_REPL_2)?;
    p.read_magic()?;
    let server_guid = p.read_i64()?;
    let client_addr = SocketAddr::V4(super::raknet::decode_ipv4_addr(
        p.read_bytes(super::raknet::RAKNET_IPV4_LEN)?,
    )?);
    let mtu = p.read_u16()?;
    let use_encryption = p.read_u8()? != 0;
    Ok(Some(Reply2 {
        server_guid,
        client_addr,
        mtu,
        use_encryption,
    }))
}

/// Inspects `data` and returns a structured rejection if it is one of
/// `0x09`–`0x0c`, `Ok(None)` if it is some other (non-rejection) packet, or
/// `Err` for a malformed rejection body.
///
/// Rejection packets all carry the magic prefix (`id + magic`), so a buffer
/// too short for the magic, or whose magic doesn't match, is reported as
/// `Ok(None)` rather than an error — matching how the handshake loop treats
/// any unrecognized packet as "keep waiting".
fn classify_rejection(data: &[u8]) -> Result<Option<HandshakeRejection>> {
    let mut p = super::raknet::PacketBuf::new(data, "Rejection");
    let id = match p.peek_u8() {
        Some(id) => id,
        None => return Ok(None), // empty buffer
    };
    // Rejection packets carry: id(1) + magic(16) + body. A buffer too short
    // for the magic, or a non-matching magic, is treated as "not a rejection"
    // (Ok(None)), not an error.
    p.read_u8()?; // consume the peeked ID
    if p.read_magic().is_err() {
        return Ok(None);
    }
    match id {
        ID_INCOMPATIBLE_PROTOCOL => {
            // Body: server_protocol(u8); a missing body byte defaults to 0.
            let server_protocol = p.read_u8().unwrap_or(0);
            Ok(Some(HandshakeRejection::IncompatibleProtocol {
                server_protocol,
            }))
        }
        ID_IP_BANNED => Ok(Some(HandshakeRejection::IpBanned)),
        ID_ALREADY_CONNECTED => Ok(Some(HandshakeRejection::AlreadyConnected)),
        ID_NO_FREE_INCOMING => Ok(Some(HandshakeRejection::NoFreeIncomingConnections)),
        _ => Ok(None),
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    // The IPv4 system-address encoder now lives in the shared `raknet` module;
    // pull it in unqualified so the test bodies stay readable.
    use super::super::raknet::encode_ipv4_addr;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_reply1_valid() {
        let mut buf = Vec::new();
        buf.push(ID_OPEN_CONN_REPL_1);
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&987654321i64.to_be_bytes()); // server_guid
        buf.push(1); // use_encryption = true
        buf.extend_from_slice(&1492u16.to_be_bytes()); // mtu
        let r = parse_reply1(&buf).unwrap().unwrap();
        assert_eq!(r.server_guid, 987654321);
        assert!(r.use_encryption);
        assert_eq!(r.mtu, 1492);
    }

    #[test]
    fn parse_reply1_wrong_id_returns_none() {
        let mut buf = vec![0x00u8];
        buf.resize(28, 0);
        // Not a Reply 1 (wrong ID) — Ok(None), not an error.
        assert!(parse_reply1(&buf).unwrap().is_none());
    }

    #[test]
    fn parse_reply1_too_short_is_error() {
        let mut buf = vec![ID_OPEN_CONN_REPL_1];
        buf.extend_from_slice(&MAGIC);
        // Only 17 bytes total — well under the 28-byte minimum.
        assert!(parse_reply1(&buf).is_err());
    }

    #[test]
    fn parse_reply1_wrong_magic_is_error() {
        let mut buf = vec![ID_OPEN_CONN_REPL_1];
        buf.extend_from_slice(&[0u8; 16]); // bad magic
        buf.resize(28, 0);
        assert!(parse_reply1(&buf).is_err());
    }

    #[test]
    fn parse_reply2_valid() {
        let mut buf = Vec::new();
        buf.push(ID_OPEN_CONN_REPL_2);
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&111111i64.to_be_bytes()); // server_guid
        let client_addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 54321);
        buf.extend_from_slice(&encode_ipv4_addr(&client_addr));
        buf.extend_from_slice(&1200u16.to_be_bytes()); // mtu
        buf.push(0); // use_encryption = false
        let r = parse_reply2(&buf).unwrap().unwrap();
        assert_eq!(r.server_guid, 111111);
        assert_eq!(r.client_addr, SocketAddr::V4(client_addr));
        assert_eq!(r.mtu, 1200);
        assert!(!r.use_encryption);
    }

    #[test]
    fn parse_reply2_too_short_is_error() {
        let mut buf = vec![ID_OPEN_CONN_REPL_2];
        buf.extend_from_slice(&MAGIC);
        assert!(parse_reply2(&buf).is_err());
    }

    #[test]
    fn parse_reply2_wrong_id_returns_none() {
        let mut buf = vec![0x00u8];
        buf.resize(44, 0);
        assert!(parse_reply2(&buf).unwrap().is_none());
    }

    /// Regression: real Bedrock servers (EaseCation, NetherGames) send a 35-byte
    /// Reply 2 with a compact 7-byte IPv4 system address. Previously the parser
    /// assumed a 16-byte address and rejected these with
    /// "Reply 2 packet too short: 25 bytes consumed, only 10 remain (need 16)".
    #[test]
    fn parse_reply2_real_35_byte_shape() {
        let client_addr = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 54321);
        let mut buf = Vec::with_capacity(35);
        buf.push(ID_OPEN_CONN_REPL_2);
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&111111i64.to_be_bytes()); // server_guid
        buf.extend_from_slice(&encode_ipv4_addr(&client_addr)); // 7 bytes
        buf.extend_from_slice(&1200u16.to_be_bytes()); // mtu
        buf.push(0); // use_encryption = false
        assert_eq!(buf.len(), 35, "real Reply 2 is 35 bytes");

        let r = parse_reply2(&buf).unwrap().unwrap();
        assert_eq!(r.server_guid, 111111);
        assert_eq!(r.client_addr, SocketAddr::V4(client_addr));
        assert_eq!(r.mtu, 1200);
        assert!(!r.use_encryption);
    }

    #[test]
    fn classify_incompatible_protocol_rejection() {
        let mut buf = vec![ID_INCOMPATIBLE_PROTOCOL];
        buf.extend_from_slice(&MAGIC);
        buf.push(10); // server protocol version
        let rej = classify_rejection(&buf).unwrap().unwrap();
        assert_eq!(
            rej,
            HandshakeRejection::IncompatibleProtocol {
                server_protocol: 10
            }
        );
        assert_eq!(
            rej.as_message(11),
            "incompatible protocol version (server=10, client=11)"
        );
    }

    #[test]
    fn classify_ip_banned_rejection() {
        let mut buf = vec![ID_IP_BANNED];
        buf.extend_from_slice(&MAGIC);
        let rej = classify_rejection(&buf).unwrap().unwrap();
        assert_eq!(rej, HandshakeRejection::IpBanned);
        assert!(rej.as_message(11).contains("banned"));
    }

    #[test]
    fn classify_already_connected_rejection() {
        let mut buf = vec![ID_ALREADY_CONNECTED];
        buf.extend_from_slice(&MAGIC);
        let rej = classify_rejection(&buf).unwrap().unwrap();
        assert_eq!(rej, HandshakeRejection::AlreadyConnected);
    }

    #[test]
    fn classify_no_free_incoming_rejection() {
        let mut buf = vec![ID_NO_FREE_INCOMING];
        buf.extend_from_slice(&MAGIC);
        let rej = classify_rejection(&buf).unwrap().unwrap();
        assert_eq!(rej, HandshakeRejection::NoFreeIncomingConnections);
        assert!(rej.as_message(11).contains("full"));
    }

    #[test]
    fn classify_rejection_ignores_non_rejection_packets() {
        // A Reply 1 packet (0x06) has magic, but is not a rejection.
        let mut buf = vec![ID_OPEN_CONN_REPL_1];
        buf.extend_from_slice(&MAGIC);
        buf.resize(28, 0);
        assert!(classify_rejection(&buf).unwrap().is_none());

        // Truncated (no magic) — also None, not an error.
        assert!(classify_rejection(&[ID_IP_BANNED]).unwrap().is_none());

        // Empty — None.
        assert!(classify_rejection(&[]).unwrap().is_none());
    }

    #[test]
    fn build_request1_padding_matches_mtu() {
        let req = build_request1(11, 576);
        assert_eq!(req[0], ID_OPEN_CONN_REQ_1);
        assert_eq!(&req[1..17], &MAGIC);
        assert_eq!(req[17], 11); // protocol_version
        assert_eq!(req.len(), 576); // whole datagram equals the proposed MTU
                                    // Trailing bytes must be zero padding.
        assert!(req[18..].iter().all(|&b| b == 0));
    }

    #[test]
    fn build_request1_clamps_below_fixed_overhead() {
        // An MTU smaller than the 18-byte fixed header can't fit padding;
        // the builder must still emit a valid (padding-free) request.
        let req = build_request1(11, 10);
        assert_eq!(req.len(), 18);
        assert_eq!(req[17], 11);
    }

    #[test]
    fn build_request2_layout() {
        let addr = SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 5), 12345);
        let req = build_request2(addr, 1200, 42);
        // id(1) + magic(16) + addr(7) + mtu(2) + guid(8) = 34.
        assert_eq!(req.len(), 34);
        assert_eq!(req[0], ID_OPEN_CONN_REQ_2);
        assert_eq!(&req[1..17], &MAGIC);
        assert_eq!(&req[17..24], &encode_ipv4_addr(&addr));
        assert_eq!(u16::from_be_bytes([req[24], req[25]]), 1200);
        assert_eq!(i64::from_be_bytes(req[26..34].try_into().unwrap()), 42);
    }

    #[test]
    fn connection_builder_defaults() {
        let b = ConnectBuilder::default();
        assert_eq!(b.client_guid, 0);
        assert_eq!(b.protocol_version, 11);
        assert_eq!(b.mtu_candidates, vec![1492, 1200, 576]);
        assert_eq!(b.timeout, Duration::from_secs(10));
        assert_eq!(b.max_retries, 3);
    }

    #[test]
    fn connection_builder_setters_chain() {
        let b = ConnectBuilder::default()
            .client_guid(7)
            .protocol_version(10)
            .mtu_candidates(vec![1400])
            .timeout(Duration::from_secs(2))
            .max_retries(1);
        assert_eq!(b.client_guid, 7);
        assert_eq!(b.protocol_version, 10);
        assert_eq!(b.mtu_candidates, vec![1400]);
        assert_eq!(b.timeout, Duration::from_secs(2));
        assert_eq!(b.max_retries, 1);
    }
}
