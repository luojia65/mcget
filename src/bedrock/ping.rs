//! RakNet **Unconnected Ping** — a single UDP round-trip to read a server's
//! MOTD / player count without establishing a session.
//!
//! Follows a reqwest-style [`Client`] + [`RequestBuilder`] pattern: create a
//! reusable [`Client`], call [`Client::ping`] to get a [`RequestBuilder`], then
//! call [`RequestBuilder::send`] to issue the request.
//!
//! Protocol flow (over UDP, default port [`super::DEFAULT_PORT`] = 19132):
//! 1. The client sends an **Unconnected Ping** packet (ID `0x01`):
//!    `01 | time(u64 BE) | magic(16B) | client_guid(i64 BE)`
//! 2. The server replies with an **Unconnected Pong** packet (ID `0x1C`):
//!    `1C | time(u64 BE) | server_guid(i64 BE) | magic(16B) | len(u16 BE) | server_id_string`
//!
//! Here `magic` is [`super::MAGIC`]. `server_id_string` is a semicolon-separated
//! field string (usually prefixed with `MCPE;`); its format is documented on
//! [`PongResponse`].
//!
//! This crate does not build in a timeout; callers can wrap
//! [`RequestBuilder::send`] with `tokio::time::timeout`.
//!
//! References: <https://wiki.bedrock.dev/servers/raknet>, <https://minecraft.wiki/w/RakNet>

use super::*;
use crate::addr::HostAddr;
use crate::error::{PingError, Result};
use serde::Serialize;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Packet ID: Unconnected Ping.
const ID_UNCONNECTED_PING: u8 = 0x01;
/// Packet ID: Unconnected Pong.
const ID_UNCONNECTED_PONG: u8 = 0x1c;

/// Total length of an Unconnected Ping packet: 1 + 8 + 16 + 8 = 33 bytes.
const PING_LEN: usize = 33;
/// Receive buffer size: 1 + 8 + 8 + 16 + 2 + (up to ~1300 bytes of MOTD). Larger is safer.
const RECV_BUF_LEN: usize = 4096;

// ==================== Response types ====================

/// Parsed structure of an Unconnected Pong.
///
/// The `server_id_string` is semicolon-separated, and the number of fields
/// filled in varies between servers. The official BDS / standard order has 13
/// fields:
/// ```text
/// MCPE;edition;motd1;protocol;versionName;playerCount;maxPlayers;
///       serverId;motd2;gamemode;gamemodeNumeric;portIPv4;portIPv6
/// ```
/// However, many third-party / hosted servers omit some fields (most commonly
/// `edition` or the trailing ports). Therefore this struct exposes both:
/// - best-effort parsed semantic fields (based on the standard order, with safe
///   defaults for missing fields);
/// - [`PongResponse::fields`], the raw field slice, so callers can do custom
///   parsing for non-standard servers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PongResponse {
    /// The client timestamp (milliseconds) echoed back by the server.
    pub time: i64,
    /// The server's 64-bit GUID.
    pub server_guid: i64,
    /// The raw `server_id_string` (un-split), useful for debugging / non-standard fields.
    pub raw_server_id: String,
    /// Raw field list after splitting on `;` (including the `"MCPE"` prefix).
    /// Callers can use `fields[i]` for positional access on non-standard servers.
    pub fields: Vec<String>,
    /// Edition prefix, usually `"MCPE"`.
    pub edition: String,
    /// Main MOTD (first line).
    pub motd: String,
    /// Protocol version number (0 if the numeric string fails to parse).
    pub protocol_version: u32,
    /// Version name (e.g. `"1.21.80"`).
    pub version_name: String,
    /// Number of players currently online.
    pub player_count: u32,
    /// Maximum number of players.
    pub max_players: u32,
    /// Server ID field (as a string).
    pub server_id_field: String,
    /// Second MOTD line.
    pub second_motd: String,
    /// Game mode name (e.g. `"Survival"`).
    pub gamemode: String,
    /// Numeric game mode (e.g. 0=Survival, 1=Creative).
    pub gamemode_numeric: u32,
    /// IPv4 port.
    pub port_ipv4: u16,
    /// IPv6 port.
    pub port_ipv6: u16,
    /// Network round-trip latency (wall-clock delta from sending the ping to receiving the pong).
    pub latency: Duration,
}

// ==================== Client / RequestBuilder ====================

/// A reusable Bedrock RakNet client.
///
/// Created via [`Client::new`] (default `client_guid = 0`); adjust the client
/// GUID with [`Client::client_guid`], then issue queries via [`Client::ping`].
#[derive(Debug, Clone)]
pub struct Client {
    client_guid: i64,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Creates a client with default configuration (`client_guid = 0`).
    pub fn new() -> Self {
        Self { client_guid: 0 }
    }

    /// Sets the client GUID (any value works; 0 is a common default).
    pub fn client_guid(mut self, guid: i64) -> Self {
        self.client_guid = guid;
        self
    }

    /// Starts an Unconnected Ping against the target address, returning a
    /// [`RequestBuilder`].
    ///
    /// `addr` accepts anything implementing [`HostAddr`], e.g. a
    /// `"host:19132"` string, a `("host", 19132)` tuple, or a [`SocketAddr`].
    /// DNS resolution happens synchronously at this point (on failure
    /// [`PingError::Io`] is returned).
    pub fn ping<A: HostAddr>(&self, addr: A) -> Result<RequestBuilder> {
        RequestBuilder::new(addr, self.client_guid)
    }

    /// Returns a [`super::conn::ConnectBuilder`] pre-seeded with this client's
    /// `client_guid`, ready to run a RakNet handshake.
    ///
    /// This is the connection-oriented counterpart of [`Client::ping`]. Unlike
    /// `ping` (which resolves `addr` immediately), `connect` does **not** take an
    /// address here — the target is passed to
    /// [`super::conn::ConnectBuilder::send`], where DNS resolution actually
    /// happens. So the call reads:
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = mcget::bedrock::Client::new().client_guid(12345);
    /// let conn = client.connect()              // seed config, no I/O yet
    ///     .send("play.x.net")                  // resolve + handshake
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The returned builder inherits the client's `client_guid` as its default;
    /// override it (or any other handshake parameter) by chaining builder
    /// methods before [`super::conn::ConnectBuilder::send`].
    pub fn connect(&self) -> super::conn::ConnectBuilder {
        // DNS resolution is deferred to `ConnectBuilder::send`, matching how
        // `ConnectBuilder` already works as a standalone entry point. Here we
        // only seed the client GUID; the address is captured at send time.
        super::conn::ConnectBuilder::with_client_guid(self.client_guid)
    }
}

/// Bedrock Unconnected Ping request builder (reqwest style).
///
/// Created by [`Client::ping`]. Call [`RequestBuilder::send`] to issue the
/// request.
#[derive(Debug, Clone)]
pub struct RequestBuilder {
    /// Resolved target address, used for the UDP connection.
    addr: SocketAddr,
    /// Client GUID.
    client_guid: i64,
}

impl RequestBuilder {
    fn new<A: HostAddr>(addr: A, client_guid: i64) -> Result<Self> {
        let mut addrs = addr.to_socket_addrs_with_default(DEFAULT_PORT)?;
        let socket = addrs.pop().ok_or_else(|| {
            PingError::Protocol("to_socket_addrs returned no address".to_string())
        })?;
        Ok(RequestBuilder {
            addr: socket,
            client_guid,
        })
    }

    /// Sends the request and returns a [`PongResponse`] (whose `latency` is the
    /// network round-trip time).
    ///
    /// Some servers may reply with other offline packets first; this method
    /// loops until it receives a `0x1C` Pong.
    pub async fn send(self) -> Result<PongResponse> {
        // Bind to any local port, preferring IPv4.
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(self.addr).await?;

        // Build the Unconnected Ping.
        // time uses "milliseconds since the epoch", matching the server's time field.
        let now_millis = current_millis();
        let mut packet = Vec::with_capacity(PING_LEN);
        packet.push(ID_UNCONNECTED_PING);
        packet.extend_from_slice(&now_millis.to_be_bytes());
        packet.extend_from_slice(&MAGIC);
        packet.extend_from_slice(&self.client_guid.to_be_bytes());
        debug_assert_eq!(packet.len(), PING_LEN);

        let start = Instant::now();
        sock.send(&packet).await?;

        // Receive the Pong. Some servers reply with other offline packets first,
        // so loop until we get the 0x1C Pong.
        let mut buf = [0u8; RECV_BUF_LEN];
        loop {
            let (n, _peer) = sock.recv_from(&mut buf).await?;
            if n == 0 {
                continue;
            }
            if buf[0] == ID_UNCONNECTED_PONG {
                let elapsed = start.elapsed();
                return parse_pong(&buf[..n], elapsed);
            }
            // Other packets (e.g. offline messages other than 0x1c) -- keep waiting.
        }
    }
}

/// Convenience method: performs a one-shot RakNet Unconnected Ping against the target.
///
/// **Note**: this function creates a new internal [`Client`] on each call, so it
/// is not suitable for large volumes of concurrent queries. To reuse a client or
/// adjust the client GUID, use [`Client::ping`] instead.
///
/// `addr` accepts anything implementing [`HostAddr`]: a `"host:port"` string
/// (when no port is given, [`DEFAULT_PORT`] = 19132 is filled in), a
/// `("host", port)` tuple, a [`SocketAddr`], etc. IPv6 bracket form
/// (`"[::1]:19132"`) is supported.
///
/// # Examples
///
/// Using a string address (the default port 19132 is filled in when omitted):
///
/// ```no_run
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let resp = mcget::ping_bedrock("play.easecation.net").await?;
/// println!("{} online {}/{}",
///     resp.version_name, resp.player_count, resp.max_players);
/// # Ok(())
/// # }
/// ```
///
/// Using a tuple form (also supported):
///
/// ```no_run
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let resp = mcget::ping_bedrock(("play.easecation.net", 19132)).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// This function returns [`Err`] ([`PingError`]) when:
///
/// - `addr` cannot be resolved to a socket address (DNS failure, [`PingError::Io`])
/// - the UDP socket cannot be bound or connected ([`PingError::Io`])
/// - an I/O error occurs while talking to the server ([`PingError::Io`])
/// - the server's response does not conform to the RakNet protocol (wrong packet ID, magic mismatch, etc., [`PingError::Protocol`])
/// - `server_id_string` is not UTF-8 or field parsing fails ([`PingError::Protocol`])
pub async fn ping<A: HostAddr>(addr: A) -> Result<PongResponse> {
    Client::new().ping(addr)?.send().await
}

// ==================== Parsing helpers ====================

/// Parses an Unconnected Pong byte stream.
///
/// `latency` is supplied by the caller (typically the wall-clock delta from
/// sending the ping to receiving the pong).
pub fn parse_pong(data: &[u8], latency: Duration) -> Result<PongResponse> {
    // Layout: id(1) | time(8) | server_guid(8) | magic(16) | str_len(2) | str(str_len).
    let mut p = super::PacketBuf::new(data, "Pong");
    p.expect_id(ID_UNCONNECTED_PONG)?;
    let time = p.read_i64()?;
    let server_guid = p.read_i64()?;
    p.read_magic()?;
    let str_len = p.read_u16()? as usize;
    let str_bytes = p.read_bytes(str_len).map_err(|e| match e {
        // Replace the generic truncation message with a more specific one for
        // the trailing server_id_string field.
        PingError::Protocol(_) => PingError::Protocol(format!(
            "server_id_string declares {str_len} bytes but only {} remain",
            p.remaining()
        )),
        other => other,
    })?;
    let raw = std::str::from_utf8(str_bytes)
        .map_err(|e| PingError::Protocol(format!("server_id_string is not UTF-8: {e}")))?;
    let mut resp = parse_server_id_string(raw)?;
    resp.time = time;
    resp.server_guid = server_guid;
    resp.latency = latency;
    Ok(resp)
}

/// Parses the semicolon-separated `server_id_string`.
///
/// Following the official standard format from the Minecraft Wiki [RakNet docs][wiki],
/// the field order is:
/// ```text
/// edition;motd1;protocolVersion;versionName;playerCount;maxPlayers;
///         serverUniqueId;motd2;gamemode;gamemodeNumeric;portIpv4;portIpv6
/// ```
/// where `edition` is usually `"MCPE"` (or `"MCEE"` for Education Edition).
///
/// Many third-party / hosted servers omit trailing fields (most commonly
/// `gamemodeNumeric` / `portIpv4` / `portIpv6`). This function parses front to
/// back in standard order and returns safe defaults for missing fields (0 for
/// numbers, empty for strings).
///
/// Regardless of completeness, the raw field slice is stored in full in
/// [`PongResponse::fields`], so callers can do custom parsing for extremely
/// non-standard servers.
///
/// [wiki]: https://minecraft.wiki/w/RakNet
fn parse_server_id_string(raw: &str) -> Result<PongResponse> {
    // Note: `split(';')` yields an extra empty field when the string ends with a
    // semicolon. Using `split_terminator` drops that trailing empty field, making
    // the field count more stable.
    let fields: Vec<String> = raw.split_terminator(';').map(|s| s.to_string()).collect();

    // Safe index accessors and numeric parsers.
    let get = |idx: usize| -> String { fields.get(idx).cloned().unwrap_or_default() };
    let parse_u = |idx: usize| -> u32 {
        fields
            .get(idx)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0)
    };
    let parse_port = |idx: usize| -> u16 {
        fields
            .get(idx)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0)
    };

    // Official standard field order (0-indexed):
    // 0: edition (MCPE/MCEE) / 1: motd1 / 2: protocol version
    // 3: version name / 4: player count / 5: max players
    // 6: server unique id / 7: motd2 / 8: gamemode
    // 9: gamemode numeric / 10: port ipv4 / 11: port ipv6
    Ok(PongResponse {
        time: 0,
        server_guid: 0,
        raw_server_id: raw.to_string(),
        fields: fields.clone(),
        edition: get(0),
        motd: get(1),
        protocol_version: parse_u(2),
        version_name: get(3),
        player_count: parse_u(4),
        max_players: parse_u(5),
        server_id_field: get(6),
        second_motd: get(7),
        gamemode: get(8),
        gamemode_numeric: parse_u(9),
        port_ipv4: parse_port(10),
        port_ipv6: parse_port(11),
        latency: Duration::ZERO,
    })
}

/// Current time as a millisecond timestamp.
fn current_millis() -> i64 {
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
    fn parse_nethergames_style_server_id_string() {
        // Real NetherGames response (13 fields, full official standard order).
        let raw = "MCPE;𝗡𝗚: 𝟭𝟬𝘁𝗵 𝗔𝗻𝗻𝗶𝘃𝗲𝗿𝘀𝗮𝗿𝘆 ♛;975;1.26.20;304;309;2207098668697635884;NetherGames;Creative;1;19132;19132;0;";
        let r = parse_server_id_string(raw).unwrap();
        assert_eq!(r.edition, "MCPE");
        assert_eq!(r.motd, "𝗡𝗚: 𝟭𝟬𝘁𝗵 𝗔𝗻𝗻𝗶𝘃𝗲𝗿𝘀𝗮𝗿𝘆 ♛");
        assert_eq!(r.protocol_version, 975);
        assert_eq!(r.version_name, "1.26.20");
        assert_eq!(r.player_count, 304);
        assert_eq!(r.max_players, 309);
        assert_eq!(r.server_id_field, "2207098668697635884");
        assert_eq!(r.second_motd, "NetherGames");
        assert_eq!(r.gamemode, "Creative");
        assert_eq!(r.gamemode_numeric, 1);
        assert_eq!(r.port_ipv4, 19132);
        assert_eq!(r.port_ipv6, 19132);
    }

    #[test]
    fn parse_hive_style_server_id_string() {
        // Real Hive response (9 fields, omitting trailing gamemode numeric / port / ipv6).
        let raw =
            "MCPE;EGG HUNT | BEDWARS;121;1.0;15563;100001;-3029535197259639200;Hive Games;Survival";
        let r = parse_server_id_string(raw).unwrap();
        assert_eq!(r.edition, "MCPE");
        assert_eq!(r.motd, "EGG HUNT | BEDWARS");
        assert_eq!(r.protocol_version, 121);
        assert_eq!(r.version_name, "1.0");
        assert_eq!(r.player_count, 15563);
        assert_eq!(r.max_players, 100001);
        assert_eq!(r.server_id_field, "-3029535197259639200");
        assert_eq!(r.second_motd, "Hive Games");
        assert_eq!(r.gamemode, "Survival");
        // Omitted fields should be defaults.
        assert_eq!(r.gamemode_numeric, 0);
        assert_eq!(r.port_ipv4, 0);
    }

    #[test]
    fn parse_full_standard_layout() {
        // Full official standard, 12 fields (with trailing semicolon).
        let raw =
            "MCPE;§aMy Server;685;1.21.80;42;100;13251324523;§eSecond line;Survival;0;19132;19133;";
        let r = parse_server_id_string(raw).unwrap();
        assert_eq!(r.edition, "MCPE");
        assert_eq!(r.motd, "§aMy Server");
        assert_eq!(r.protocol_version, 685);
        assert_eq!(r.version_name, "1.21.80");
        assert_eq!(r.player_count, 42);
        assert_eq!(r.max_players, 100);
        assert_eq!(r.gamemode, "Survival");
        assert_eq!(r.gamemode_numeric, 0);
        assert_eq!(r.port_ipv4, 19132);
        assert_eq!(r.port_ipv6, 19133);
    }

    #[test]
    fn parse_partial_server_id_string_does_not_panic() {
        // Should return safely when fields are missing; missing fields get defaults.
        let raw = "MCPE;Hello;1;1.0;0;20";
        let r = parse_server_id_string(raw).unwrap();
        assert_eq!(r.motd, "Hello");
        assert_eq!(r.protocol_version, 1);
        assert_eq!(r.player_count, 0);
        assert_eq!(r.max_players, 20);
        assert_eq!(r.gamemode, "");
        assert_eq!(r.port_ipv4, 0);
    }

    #[test]
    fn parse_full_pong_packet() {
        // Build a complete 0x1c pong byte stream (official standard field order).
        let server_id = "MCPE;MOTD;685;1.21.80;5;20;12345;MOTD2;Survival;0;19132;19133;";
        let mut buf = Vec::new();
        buf.push(ID_UNCONNECTED_PONG);
        buf.extend_from_slice(&123456789i64.to_be_bytes()); // time
        buf.extend_from_slice(&987654321i64.to_be_bytes()); // server guid
        buf.extend_from_slice(&MAGIC);
        let len = server_id.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(server_id.as_bytes());

        let r = parse_pong(&buf, Duration::from_millis(50)).unwrap();
        assert_eq!(r.time, 123456789);
        assert_eq!(r.server_guid, 987654321);
        assert_eq!(r.edition, "MCPE");
        assert_eq!(r.motd, "MOTD");
        assert_eq!(r.protocol_version, 685);
        assert_eq!(r.player_count, 5);
        assert_eq!(r.max_players, 20);
        assert_eq!(r.gamemode, "Survival");
        assert_eq!(r.gamemode_numeric, 0);
        assert_eq!(r.port_ipv4, 19132);
        assert_eq!(r.port_ipv6, 19133);
        assert_eq!(r.latency, Duration::from_millis(50));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = Vec::new();
        buf.push(ID_UNCONNECTED_PONG);
        buf.extend_from_slice(&0i64.to_be_bytes());
        buf.extend_from_slice(&0i64.to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]); // wrong magic
        buf.extend_from_slice(&0u16.to_be_bytes());
        assert!(parse_pong(&buf, Duration::ZERO).is_err());
    }

    #[test]
    fn rejects_wrong_packet_id() {
        let mut buf = vec![0x00u8]; // wrong ID
        buf.resize(40, 0);
        assert!(parse_pong(&buf, Duration::ZERO).is_err());
    }

    #[test]
    fn client_guid_builder_chain() {
        let client = Client::new().client_guid(42);
        let req = client.ping(("127.0.0.1", 19132)).unwrap();
        assert_eq!(req.client_guid, 42);
    }

    #[test]
    fn client_default_guid_is_zero() {
        let client = Client::new();
        let req = client.ping(("127.0.0.1", 19132)).unwrap();
        assert_eq!(req.client_guid, 0);
    }
}
