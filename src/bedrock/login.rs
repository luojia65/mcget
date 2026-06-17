//! Bedrock **offline login** — construction of the login chain and the
//! encode/decode of the login-stage game packets, without encryption.
//!
//! This is independent of RakNet: it produces/consumes [`GamePacket`](super::
//! protocol::GamePacket) payloads that the caller sends through a
//! [`ReliableConnection`](super::reliable_conn::ReliableConnection). The
//! offline login flow (for servers with `use_encryption = false`) is:
//!
//! ```text
//! Client → Server:  RequestNetworkSettings
//! Server → Client:  NetworkSettings        (compression config)
//! Client → Server:  Login                  (offline JWT chain)
//! Server → Client:  PlayStatus(LOGIN_SUCCESS)
//! ```
//!
//! A server that wants encryption responds with `ServerToClientHandshake`
//! instead; this module surfaces that as an error (offline login cannot
//! proceed). Xbox-Live signed chains are out of scope.
//!
//! References: gophertunnel `minecraft/protocol/login`, `minecraft/auth`,
//! `wiki.bedrock.dev/servers/bedrock`.

use super::protocol::{
    read_varint32, write_varint32, write_varuint32, ID_LOGIN, ID_REQUEST_NETWORK_SETTINGS,
};
use crate::error::{PingError, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

// ==================== PlayStatus values ====================

/// `PlayStatus` enum values carried in the PlayStatus packet.
pub mod play_status {
    /// Login successful — the server will proceed to send game data.
    pub const LOGIN_SUCCESS: i32 = 0;
    /// Client protocol is outdated.
    pub const CLIENT_OUTDATED: i32 = 1;
    /// Server is full.
    pub const SERVER_FULL: i32 = 2;
    /// (Editor/spawn scene transition; not a login outcome.)
    pub const SPAWN_SCENE: i32 = 3;
}

// ==================== Login-stage packets ====================

/// `RequestNetworkSettings` (client → server). Body: `protocol(i32 BE)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestNetworkSettings {
    pub protocol: i32,
}

/// `NetworkSettings` (server → client). Body: `threshold(u16 BE) |
/// algorithm(u16 BE) | client_throttle(bool) | throttle_threshold(u8) |
/// throttle_scalar(f32 BE)`.
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkSettings {
    pub compression_threshold: u16,
    pub compression_algorithm: u16,
    pub client_throttle: bool,
    pub client_throttle_threshold: u8,
    pub client_throttle_scalar: f32,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            compression_threshold: 0,
            compression_algorithm: super::protocol::COMPRESSION_FLATE,
            client_throttle: false,
            client_throttle_threshold: 0,
            client_throttle_scalar: 0.0,
        }
    }
}

/// `PlayStatus` (server → client). Body: `status(i32 BE)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlayStatus {
    pub status: i32,
}

impl RequestNetworkSettings {
    /// Encodes to a [`GamePacket`](super::protocol::GamePacket) payload
    /// (without the ID — the caller prepends it).
    pub fn encode_payload(&self) -> Vec<u8> {
        // Bedrock encodes the protocol version as a varint32 (zigzag), not a
        // big-endian i32 — see gophertunnel request_network_settings.go.
        write_varint32(self.protocol)
    }

    pub fn decode_payload(data: &[u8]) -> Result<Self> {
        let (protocol, _) = read_varint32(data)?;
        Ok(Self { protocol })
    }
}

impl NetworkSettings {
    pub fn decode_payload(data: &[u8]) -> Result<Self> {
        if data.len() < 10 {
            return Err(PingError::Protocol(format!(
                "NetworkSettings needs 10 bytes, got {}",
                data.len()
            )));
        }
        let compression_threshold = u16::from_be_bytes([data[0], data[1]]);
        let compression_algorithm = u16::from_be_bytes([data[2], data[3]]);
        let client_throttle = data[4] != 0;
        let client_throttle_threshold = data[5];
        let mut f = [0u8; 4];
        f.copy_from_slice(&data[6..10]);
        let client_throttle_scalar = f32::from_be_bytes(f);
        Ok(Self {
            compression_threshold,
            compression_algorithm,
            client_throttle,
            client_throttle_threshold,
            client_throttle_scalar,
        })
    }
}

impl PlayStatus {
    pub fn decode_payload(data: &[u8]) -> Result<Self> {
        let status = read_i32_be(data, "PlayStatus.status")?;
        Ok(Self { status })
    }
}

/// Parsed contents of a `ServerToClientHandshake` JWT: the server's P-384 public
/// key (base64url) and the salt used for key derivation.
#[derive(Debug, Clone)]
pub struct ServerHandshake {
    /// The server's P-384 public key, base64url-no-pad encoded (as it appears in
    /// the JWT header `x5u`).
    pub server_public_key_b64: String,
    /// The raw salt bytes (decoded from the JWT payload `salt`).
    pub salt: Vec<u8>,
}

impl ServerHandshake {
    /// Decodes a `ServerToClientHandshake` payload (the bytes after the packet
    /// ID): `varuint32(jwt_len) | jwt`. The JWT is parsed to extract the
    /// `x5u` header and `salt` payload claim.
    pub fn decode_payload(data: &[u8]) -> Result<Self> {
        let (jwt_len, n) = super::protocol::read_varuint32(data)
            .map_err(|e| PingError::Protocol(format!("ServerHandshake jwt_len: {e}")))?;
        let jwt_bytes = data
            .get(n..n + jwt_len as usize)
            .ok_or_else(|| PingError::Protocol("ServerHandshake JWT truncated".to_string()))?;
        let jwt_str = std::str::from_utf8(jwt_bytes)
            .map_err(|e| PingError::Protocol(format!("ServerHandshake JWT utf-8: {e}")))?;
        Self::decode_jwt(jwt_str)
    }

    /// Splits a JWT (`header.payload.signature`) and pulls `x5u` from the header
    /// and `salt` (base64url) from the payload.
    pub fn decode_jwt(jwt: &str) -> Result<Self> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let mut parts = jwt.split('.');
        let header_b64 = parts.next().ok_or_else(|| {
            PingError::Protocol("ServerHandshake JWT: missing header".to_string())
        })?;
        let payload_b64 = parts.next().ok_or_else(|| {
            PingError::Protocol("ServerHandshake JWT: missing payload".to_string())
        })?;
        let header: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(header_b64)
                .map_err(|e| PingError::Protocol(format!("header base64: {e}")))?,
        )
        .map_err(|e| PingError::Protocol(format!("header json: {e}")))?;
        let payload: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(payload_b64)
                .map_err(|e| PingError::Protocol(format!("payload base64: {e}")))?,
        )
        .map_err(|e| PingError::Protocol(format!("payload json: {e}")))?;
        let server_public_key_b64 = header
            .get("x5u")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PingError::Protocol("ServerHandshake JWT: missing x5u".to_string()))?
            .to_string();
        let salt_b64 = payload
            .get("salt")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PingError::Protocol("ServerHandshake JWT: missing salt".to_string()))?;
        let salt = URL_SAFE_NO_PAD
            .decode(salt_b64)
            .map_err(|e| PingError::Protocol(format!("salt base64: {e}")))?;
        Ok(Self {
            server_public_key_b64,
            salt,
        })
    }
}

/// Builds a [`GamePacket`](super::protocol::GamePacket) for the
/// RequestNetworkSettings packet (ID prepended to the payload).
pub fn request_network_settings_packet(protocol: i32) -> super::protocol::GamePacket {
    super::protocol::GamePacket::new(
        ID_REQUEST_NETWORK_SETTINGS,
        RequestNetworkSettings { protocol }.encode_payload(),
    )
}

/// Builds a Login game packet carrying an offline JWT chain.
pub fn login_packet(protocol: i32, connection_request: Vec<u8>) -> super::protocol::GamePacket {
    let mut payload = Vec::with_capacity(8 + connection_request.len());
    // Protocol version is a signed varint32 (zig-zag), not a big-endian i32.
    payload.extend_from_slice(&write_varint32(protocol));
    // The connection request is a length-prefixed byte slice: varuint32(len) + bytes.
    payload.extend_from_slice(&write_varuint32(connection_request.len() as u32));
    payload.extend_from_slice(&connection_request);
    super::protocol::GamePacket::new(ID_LOGIN, payload)
}

// ==================== Offline JWT chain ====================

/// Identity data carried inside the identity JWT's `extraData` claim. For an
/// offline login the XUID is empty and the identity is a placeholder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityData {
    /// XUID (Xbox Live user ID); empty string for offline login.
    #[serde(rename = "XUID")]
    pub xuid: String,
    /// The player identity (a random UUID-like string for offline).
    pub identity: String,
    /// The display name shown to the server.
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Minimal client data payload. A real client sends a large struct (skin,
/// device info, …); for offline login the server usually only inspects a few
/// fields, so we send sensible defaults and an empty skin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientData {
    /// Client GUID (the same one used in the RakNet handshake).
    #[serde(rename = "ClientRandomId")]
    pub client_random_id: i64,
    /// Device OS (0 = unknown).
    #[serde(rename = "DeviceOS")]
    pub device_os: i32,
    /// Game version string.
    #[serde(rename = "GameVersion")]
    pub game_version: String,
    /// Language code.
    #[serde(rename = "LanguageCode")]
    pub language_code: String,
    /// Device model (empty = unknown).
    #[serde(rename = "DeviceModel")]
    pub device_model: String,
}

impl ClientData {
    /// Defaults for an offline desktop client.
    pub fn offline(client_random_id: i64) -> Self {
        Self {
            client_random_id,
            device_os: 0,
            game_version: "1.21.0".to_string(),
            language_code: "en".to_string(),
            device_model: String::new(),
        }
    }
}

/// A Bedrock login JWT: `base64url(header).base64url(payload).<signature>`.
/// For offline login the signature is empty (servers that don't verify will
/// accept it; servers that require Xbox signatures will reject with encryption).
struct Jwt {
    header_json: serde_json::Value,
    payload_json: serde_json::Value,
}

impl Jwt {
    /// Encodes to `header.payload.` (empty signature). The header and payload
    /// are JSON objects, base64url-no-pad encoded.
    fn encode(&self) -> Result<Vec<u8>> {
        let header = serde_json::to_string(&self.header_json)
            .map_err(|e| PingError::Protocol(format!("jwt header json: {e}")))?;
        let payload = serde_json::to_string(&self.payload_json)
            .map_err(|e| PingError::Protocol(format!("jwt payload json: {e}")))?;
        let mut out = URL_SAFE_NO_PAD.encode(header).into_bytes();
        out.push(b'.');
        out.extend_from_slice(URL_SAFE_NO_PAD.encode(payload).as_bytes());
        out.push(b'.'); // empty signature
        Ok(out)
    }
}

/// Builds the **connection request** bytes for an offline login: a chain JSON
/// holding one self-signed identity JWT, followed by the client-data JWT.
///
/// Wire layout: `varuint32(chain_len) | chain_json | varuint32(client_jwt_len)
/// | client_jwt`.
pub fn build_offline_connection_request(
    client_guid: i64,
    identity: IdentityData,
) -> Result<Vec<u8>> {
    // The public key used as a self-signed placeholder. Servers that don't
    // require Xbox auth accept any well-formed key here.
    let identity_public_key = "MHYwEAYHKoZIzj0CA3YFK4EEACIDYQAE";
    let identity_jwt = Jwt {
        header_json: serde_json::json!({ "alg": "es384", "x5u": identity_public_key }),
        payload_json: serde_json::json!({
            "extraData": identity,
            "identityPublicKey": identity_public_key,
        }),
    }
    .encode()?;

    let client_jwt = Jwt {
        header_json: serde_json::json!({ "alg": "es384", "x5u": identity_public_key }),
        payload_json: serde_json::json!(ClientData::offline(client_guid)),
    }
    .encode()?;

    // The chain is a JSON object: { "chain": [ "<identity_jwt>" ] }.
    let chain_json = serde_json::json!({ "chain": [ String::from_utf8(identity_jwt).map_err(|e| PingError::Protocol(format!("jwt not utf-8: {e}")))? ] });
    let chain_bytes = serde_json::to_vec(&chain_json)
        .map_err(|e| PingError::Protocol(format!("chain json: {e}")))?;

    let mut out = Vec::new();
    out.extend_from_slice(&write_varuint32(chain_bytes.len() as u32));
    out.extend_from_slice(&chain_bytes);
    out.extend_from_slice(&write_varuint32(client_jwt.len() as u32));
    out.extend_from_slice(&client_jwt);
    Ok(out)
}

/// Builds a default offline connection request with a placeholder identity.
pub fn default_offline_connection_request(client_guid: i64) -> Result<Vec<u8>> {
    let identity = IdentityData {
        xuid: String::new(),
        identity: format!("{client_guid:032x}"),
        display_name: "mcget".to_string(),
    };
    build_offline_connection_request(client_guid, identity)
}

// ==================== Helpers ====================

fn read_i32_be(data: &[u8], ctx: &str) -> Result<i32> {
    if data.len() < 4 {
        return Err(PingError::Protocol(format!(
            "{ctx}: need 4 bytes, got {}",
            data.len()
        )));
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&data[..4]);
    Ok(i32::from_be_bytes(a))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bedrock::protocol::{read_varuint32, ID_LOGIN};

    #[test]
    fn request_network_settings_round_trip() {
        let p = RequestNetworkSettings { protocol: 685 };
        let payload = p.encode_payload();
        let back = RequestNetworkSettings::decode_payload(&payload).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn request_network_settings_packet_has_correct_id() {
        let pkt = request_network_settings_packet(685);
        assert_eq!(pkt.id, ID_REQUEST_NETWORK_SETTINGS);
    }

    #[test]
    fn network_settings_decode() {
        // Hand-build: threshold=256, algorithm=0(flate), throttle=false,
        // threshold=0, scalar=0.0.
        let mut data = Vec::new();
        data.extend_from_slice(&256u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.push(0); // throttle false
        data.push(0); // throttle threshold
        data.extend_from_slice(&0f32.to_be_bytes());
        let ns = NetworkSettings::decode_payload(&data).unwrap();
        assert_eq!(ns.compression_threshold, 256);
        assert_eq!(ns.compression_algorithm, 0);
        assert!(!ns.client_throttle);
    }

    #[test]
    fn play_status_decode_login_success() {
        let data = play_status::LOGIN_SUCCESS.to_be_bytes();
        let ps = PlayStatus::decode_payload(&data).unwrap();
        assert_eq!(ps.status, play_status::LOGIN_SUCCESS);
    }

    #[test]
    fn login_packet_structure() {
        // Login payload: protocol(varint32) | varuint32(conn_req_len) | conn_req.
        let conn_req = vec![0xab, 0xcd, 0xef];
        let pkt = login_packet(685, conn_req.clone());
        assert_eq!(pkt.id, ID_LOGIN);
        // Decode it back by hand.
        let p = &pkt.payload;
        let (proto, n1) = read_varint32(p).unwrap();
        assert_eq!(proto, 685);
        let (len, n2) = read_varuint32(&p[n1..]).unwrap();
        assert_eq!(len as usize, conn_req.len());
        assert_eq!(&p[n1 + n2..n1 + n2 + conn_req.len()], &conn_req[..]);
    }

    #[test]
    fn offline_connection_request_is_well_formed() {
        // Build a default offline chain and verify it parses back as JSON.
        let req = default_offline_connection_request(0xAD).unwrap();
        // chain_len | chain_json | client_jwt_len | client_jwt
        let (chain_len, n1) = read_varuint32(&req).unwrap();
        let chain_json: serde_json::Value =
            serde_json::from_slice(&req[n1..n1 + chain_len as usize]).unwrap();
        let chain = chain_json["chain"].as_array().unwrap();
        assert!(!chain.is_empty(), "offline chain has at least one JWT");
        // The identity JWT must have three dot-separated parts.
        let jwt_str = chain[0].as_str().unwrap();
        let parts: Vec<&str> = jwt_str.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT has header.payload.signature");

        let (client_len, n2) = read_varuint32(&req[n1 + chain_len as usize..]).unwrap();
        let client_jwt = &req[n1 + chain_len as usize + n2..];
        assert_eq!(client_jwt.len(), client_len as usize);
        let client_str = std::str::from_utf8(client_jwt).unwrap();
        let client_parts: Vec<&str> = client_str.split('.').collect();
        assert_eq!(client_parts.len(), 3);
    }

    #[test]
    fn server_handshake_decodes_jwt() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        // Build a JWT with a known x5u and salt.
        let salt = b"my-salt-bytes";
        let header = serde_json::json!({ "alg": "ES384", "x5u": "FAKEPUBKEY" });
        let payload = serde_json::json!({ "salt": URL_SAFE_NO_PAD.encode(salt) });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let jwt = format!("{header_b64}.{payload_b64}.");
        let hs = ServerHandshake::decode_jwt(&jwt).unwrap();
        assert_eq!(hs.server_public_key_b64, "FAKEPUBKEY");
        assert_eq!(hs.salt, salt);
    }

    #[test]
    fn server_handshake_decode_payload_round_trips() {
        use super::super::protocol::write_varuint32;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let salt = b"salt";
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::json!({ "x5u": "PK" }).to_string());
        let payload_b64 = URL_SAFE_NO_PAD
            .encode(serde_json::json!({ "salt": URL_SAFE_NO_PAD.encode(salt) }).to_string());
        let jwt = format!("{header_b64}.{payload_b64}.");
        // varuint32(len) + jwt
        let mut payload = write_varuint32(jwt.len() as u32);
        payload.extend_from_slice(jwt.as_bytes());
        let hs = ServerHandshake::decode_payload(&payload).unwrap();
        assert_eq!(hs.server_public_key_b64, "PK");
        assert_eq!(hs.salt, salt);
    }

    #[test]
    fn offline_chain_carries_identity_data() {
        let identity = IdentityData {
            xuid: String::new(),
            identity: "deadbeef".to_string(),
            display_name: "test".to_string(),
        };
        let req = build_offline_connection_request(1, identity.clone()).unwrap();
        let (chain_len, n1) = read_varuint32(&req).unwrap();
        let chain_json: serde_json::Value =
            serde_json::from_slice(&req[n1..n1 + chain_len as usize]).unwrap();
        let jwt_str = chain_json["chain"][0].as_str().unwrap();
        // Decode the payload (second segment) and check extraData.
        let payload_b64 = jwt_str.split('.').nth(1).unwrap();
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["extraData"]["identity"], "deadbeef");
        assert_eq!(payload["extraData"]["displayName"], "test");
    }
}
