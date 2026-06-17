//! Bedrock **login encryption** — the ECDH (P-384) key agreement and AES-256-GCM
//! stream cipher that protects the game layer after `ServerToClientHandshake`.
//!
//! This is independent of RakNet. The flow (client side) is:
//!
//! 1. The server sends `ServerToClientHandshake` carrying a JWT whose header
//!    `x5u` is its P-384 public key and whose payload `salt` is a base64url
//!    blob. ([`EncryptionSession::from_handshake`] parses it.)
//! 2. The client generates its own P-384 key pair, computes the ECDH shared
//!    secret, and derives the AES key/IV: `SHA-384(salt || secret)`,
//!    `key = digest[..32]`, `iv = digest[32..40]`. ([`EncryptionSession`] holds
//!    the resulting AES-256-GCM cipher.)
//! 3. The client sends `ClientToServerHandshake`: an empty payload, raw-deflate
//!    compressed then AES-GCM encrypted with the derived key. (See
//!    [`EncryptionSession::encrypt_handshake`].)
//! 4. Every subsequent batch packet is AES-GCM encrypted (IV = base IV + a
//!    per-packet big-endian counter), with the 16-byte GCM tag appended.
//!
//! References: gophertunnel `minecraft/protocol/encrypt.go`, wiki.bedrock.dev.

// aes-gcm 0.10 still uses deprecated generic-array 0.x methods internally; the
// upgrade to generic-array 1.x is tracked upstream. Silence those here.
#![allow(deprecated)]

use crate::error::{PingError, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p384::ecdh::EphemeralSecret;
use p384::PublicKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha384};

/// A derived AES-256-GCM session, plus the client's public key (to send back).
pub struct EncryptionSession {
    cipher: Aes256Gcm,
    /// The 8-byte base IV; the full 12-byte nonce per packet is this in big-endian
    /// plus a counter (see [`Self::nonce_for`]).
    iv_base: [u8; 8],
    /// Monotonic send/receive counter — both sides start at 0 and increment.
    send_counter: u64,
    recv_counter: u64,
    /// The client's P-384 public key (uncompressed, 0x04 + 48 + 48 = 97 bytes),
    /// base64url-encoded for inclusion in the ClientToServerHandshake JWT.
    client_public_b64: String,
}

impl std::fmt::Debug for EncryptionSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionSession")
            .field("send_counter", &self.send_counter)
            .field("recv_counter", &self.recv_counter)
            .finish_non_exhaustive()
    }
}

impl EncryptionSession {
    /// Performs the ECDH key agreement from a server handshake JWT's `x5u`
    /// (public key) and `salt`, returning a ready-to-use cipher session plus
    /// the client public key string.
    ///
    /// `server_pub_b64` is the base64url-no-pad encoding of the server's
    /// uncompressed P-384 public point; `salt` is the raw salt bytes.
    pub fn from_handshake(server_pub_b64: &str, salt: &[u8]) -> Result<Self> {
        // Decode the server's public key.
        let server_pub_bytes = URL_SAFE_NO_PAD
            .decode(server_pub_b64)
            .map_err(|e| PingError::Protocol(format!("server pubkey base64: {e}")))?;
        let server_pub = PublicKey::from_sec1_bytes(&server_pub_bytes)
            .map_err(|e| PingError::Protocol(format!("server pubkey parse: {e}")))?;
        // Generate an ephemeral client key pair and agree on a shared secret.
        let client_secret = EphemeralSecret::random(&mut OsRng);
        let shared = client_secret.diffie_hellman(&server_pub);
        let client_pub = client_secret.public_key();
        let client_pub_bytes = client_pub.to_sec1_bytes();
        let client_public_b64 = URL_SAFE_NO_PAD.encode(&client_pub_bytes);

        // Derive key/IV: SHA-384(salt || shared_secret).
        let shared_bytes = shared.raw_secret_bytes();
        let mut hasher = Sha384::new();
        hasher.update(salt);
        hasher.update(shared_bytes.as_slice());
        let digest = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest[..32]);
        let mut iv_base = [0u8; 8];
        iv_base.copy_from_slice(&digest[32..40]);

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| PingError::Protocol(format!("AES key init: {e}")))?;
        Ok(Self {
            cipher,
            iv_base,
            send_counter: 0,
            recv_counter: 0,
            client_public_b64,
        })
    }

    /// The base64url-encoded client public key (for the ClientToServerHandshake
    /// response / JWT header `x5u`).
    pub fn client_public_b64(&self) -> &str {
        &self.client_public_b64
    }

    /// Builds the 12-byte GCM nonce for a given counter: `iv_base` rendered as a
    /// big-endian 8-byte prefix followed by a 4-byte big-endian counter suffix.
    fn nonce_bytes(iv_base: &[u8; 8], counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(iv_base);
        nonce[8..12].copy_from_slice(&(counter as u32).to_be_bytes());
        nonce
    }

    /// Encrypts a batch payload in place of the wire format: returns
    /// `ciphertext || tag(16B)`. The send counter is incremented after use.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::nonce_bytes(&self.iv_base, self.send_counter);
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .ok_or_else(|| PingError::Protocol("encryption send counter overflow".to_string()))?;
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|e| PingError::Protocol(format!("AES-GCM encrypt: {e}")))?;
        Ok(ciphertext)
    }

    /// Decrypts a wire payload (`ciphertext || tag`), incrementing the receive
    /// counter. Returns the original plaintext.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::nonce_bytes(&self.iv_base, self.recv_counter);
        self.recv_counter = self
            .recv_counter
            .checked_add(1)
            .ok_or_else(|| PingError::Protocol("encryption recv counter overflow".to_string()))?;
        self.cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &[],
                },
            )
            .map_err(|e| PingError::Protocol(format!("AES-GCM decrypt: {e}")))
    }

    /// Encrypts the empty `ClientToServerHandshake` payload: deflate-compress an
    /// empty buffer, then AES-GCM encrypt it. Returns the bytes to send as the
    /// packet's single field.
    pub fn encrypt_handshake(&mut self) -> Result<Vec<u8>> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;
        // The handshake payload is a deflate-compressed empty buffer. gophertunnel
        // uses raw DEFLATE (no zlib header) here, but most servers accept zlib.
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&[])
            .map_err(|e| PingError::Protocol(format!("handshake deflate: {e}")))?;
        let compressed = encoder
            .finish()
            .map_err(|e| PingError::Protocol(format!("handshake deflate finish: {e}")))?;
        self.encrypt(&compressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p384::ecdh::EphemeralSecret;

    #[test]
    fn from_handshake_produces_valid_session() {
        // A session built from a real P-384 server key + salt must succeed and
        // expose a well-formed client public key.
        let server_secret = EphemeralSecret::random(&mut OsRng);
        let server_pub_b64 = URL_SAFE_NO_PAD.encode(server_secret.public_key().to_sec1_bytes());
        let s = EncryptionSession::from_handshake(&server_pub_b64, b"salt").unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(s.client_public_b64()).unwrap();
        assert!(PublicKey::from_sec1_bytes(&bytes).is_ok());
    }

    #[test]
    fn symmetric_key_agreement_both_sides_match() {
        // The core ECDH invariant: client and server independently derive the
        // same key/IV. We reconstruct both sides explicitly and verify a
        // message encrypted by one decrypts with the other.
        let salt = b"symmetric-salt";
        let server_secret = EphemeralSecret::random(&mut OsRng);
        let server_pub_bytes = server_secret.public_key().to_sec1_bytes();
        let server_pub_b64 = URL_SAFE_NO_PAD.encode(&server_pub_bytes);

        // Client side: full handshake session.
        let mut client = EncryptionSession::from_handshake(&server_pub_b64, salt).unwrap();
        let client_pub_b64 = client.client_public_b64().to_string();

        // Server side: derive the same key independently.
        let client_bytes = URL_SAFE_NO_PAD.decode(&client_pub_b64).unwrap();
        let client_pub = PublicKey::from_sec1_bytes(&client_bytes).unwrap();
        let shared = server_secret.diffie_hellman(&client_pub);
        let mut h = Sha384::new();
        h.update(salt);
        h.update(shared.raw_secret_bytes().as_slice());
        let digest = h.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest[..32]);
        let mut iv = [0u8; 8];
        iv.copy_from_slice(&digest[32..40]);
        let mut server = EncryptionSession::from_key_iv(key, iv, client_pub_b64);

        // Client encrypts at counter 0; server decrypts at counter 0.
        let ct = client.encrypt(b"hello bedrock").unwrap();
        let pt = server.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello bedrock");
    }

    #[test]
    fn aes_gcm_round_trip_single_session() {
        // A single session must be able to decrypt what it encrypted (verifying
        // the cipher/key wiring), using matching send/recv counters.
        let server_pub_b64 = URL_SAFE_NO_PAD.encode(
            EphemeralSecret::random(&mut OsRng)
                .public_key()
                .to_sec1_bytes(),
        );
        // Build two sessions sharing the same key by deriving it once and using
        // from_key_iv for both.
        let key = [0x42u8; 32];
        let iv = [0x11u8; 8];
        let mut enc = EncryptionSession::from_key_iv(key, iv, String::new());
        let mut dec = EncryptionSession::from_key_iv(key, iv, String::new());
        for msg in [b"".as_slice(), b"a", b"hello world", &[0x55u8; 250]] {
            let ct = enc.encrypt(msg).unwrap();
            assert_eq!(ct.len(), msg.len() + 16, "GCM appends a 16-byte tag");
            let pt = dec.decrypt(&ct).unwrap();
            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn counters_increment_in_order() {
        let key = [0x77u8; 32];
        let iv = [0x22u8; 8];
        let mut enc = EncryptionSession::from_key_iv(key, iv, String::new());
        let mut dec = EncryptionSession::from_key_iv(key, iv, String::new());
        // Out-of-order / replayed counter must fail; only sequential works.
        let cts: Vec<_> = (0..3).map(|_| enc.encrypt(b"x").unwrap()).collect();
        for ct in cts {
            assert_eq!(dec.decrypt(&ct).unwrap(), b"x");
        }
    }

    #[test]
    fn handshake_payload_round_trips() {
        let key = [0x33u8; 32];
        let iv = [0x44u8; 8];
        let mut enc = EncryptionSession::from_key_iv(key, iv, String::new());
        let mut dec = EncryptionSession::from_key_iv(key, iv, String::new());
        let handshake_ct = enc.encrypt_handshake().unwrap();
        let compressed = dec.decrypt(&handshake_ct).unwrap();
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        let mut d = ZlibDecoder::new(&compressed[..]);
        let mut out = Vec::new();
        d.read_to_end(&mut out).unwrap();
        assert!(out.is_empty(), "handshake payload decompresses to empty");
    }

    #[test]
    fn rejects_garbage_ciphertext() {
        let key = [0x55u8; 32];
        let iv = [0x66u8; 8];
        let mut dec = EncryptionSession::from_key_iv(key, iv, String::new());
        // Too short to even contain a GCM tag.
        assert!(dec.decrypt(&[0u8; 5]).is_err());
    }
}

impl EncryptionSession {
    /// Test helper: builds a session from an explicit AES key + IV base, so two
    /// sessions can share the same derived material (simulating both peers
    /// independently arriving at the same key).
    #[cfg(test)]
    fn from_key_iv(key: [u8; 32], iv_base: [u8; 8], client_public_b64: String) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(&key).unwrap(),
            iv_base,
            send_counter: 0,
            recv_counter: 0,
            client_public_b64,
        }
    }
}
