//! Async **reliable transport** wrapper around [`Connection`].
//!
//! [`Connection`] hands back an open socket after the offline handshake but
//! performs no reliability: every datagram is fire-and-forget, nothing is
//! acknowledged or retransmitted, and frames arrive in arbitrary order.
//! [`ReliableConnection`] layers a [`ReliabilityEngine`] on top of that socket:
//!
//! - Sending ([`ReliableConnection::send`]): assign sequence numbers and frame
//!   indices, split oversized payloads, encapsulate into a datagram, and
//!   remember it for retransmission.
//! - Receiving ([`ReliableConnection::recv`]): classify the incoming packet,
//!   ACK datagrams, NACK gaps, retransmit on request, reassemble fragments,
//!   and deliver ordered frames to the caller in order.
//! - A background tick task flushes ACKs periodically, resends stale datagrams,
//!   and watches the inactivity window.

// The public surface is exercised by the connect_bedrock example and external
// callers; internal helpers tick until then. Silence dead-code for the parts
// not yet wired into a compiled call site.
#![allow(dead_code)]
//!
//! The engine state lives behind a [`tokio::sync::Mutex`] shared between the
//! caller-facing methods and the tick task; the socket is shared via
//! [`std::sync::Arc`]. This is the "add tokio sync feature" design chosen in
//! the plan.
//!
//! ## Scope
//!
//! Single ordering channel (channel 0), as Bedrock uses in practice. No
//! connected-ping heartbeat yet (a Layer 3 concern); the tick task only does
//! ACK flushing and retransmission. The session is considered dead after the
//! inactivity window elapses, at which point [`ReliableConnection::recv`]
//! returns an error.

use super::conn::Connection;
use super::datagram::{Acknowledgement, Frame, Incoming, Reliability};
use super::login::{self, NetworkSettings, PlayStatus};
use super::message::{
    self, ConnectedPing, ConnectionRequest, ConnectionRequestAccepted, NewIncomingConnection,
    SystemMessage,
};
use super::protocol::{self, GamePacket, ID_BATCH};
use super::reliability::ReliabilityEngine;
use crate::error::{PingError, Result};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout};

/// Interval at which the background task flushes pending ACKs / resends stale
/// datagrams. Matches go-raknet's coarse tick (~10 ms granularity).
const TICK_INTERVAL: Duration = Duration::from_millis(10);

/// Per-datatype channel capacities for the mpsc pipes between the tick task
/// and the [`ReliableConnection`] owner.
const OUTGOING_CHANNEL: usize = 256;
const DELIVERY_CHANNEL: usize = 256;

/// How long [`ReliableConnection::recv`] waits for a packet before it polls
/// the engine / outgoing queue, so it can make progress even when the network
/// is momentarily idle.
const RECV_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The maximum per-frame body the reliability layer will pack into a datagram,
/// derived from the MTU minus the worst-case frame + datagram header overhead.
fn max_frame_body(mtu: u16) -> usize {
    // datagram flag(1) + seq(3) + worst-case frame header (see FRAME_HEADER_MAX_OVERHEAD).
    let reserved = 1 + 3 + super::datagram::FRAME_HEADER_MAX_OVERHEAD;
    (mtu as usize).saturating_sub(reserved)
}

/// Shared session state read/written by the recv path, the online handshake,
/// and (for ping timing) the tick task. Lives behind a `Mutex`.
#[derive(Debug, Default)]
struct SessionState {
    /// True once the online handshake (Request→Accepted→NewIncoming) is done.
    online: bool,
    /// The server's system addresses as advertised in
    /// [`ConnectionRequestAccepted`] (echoed back in NewIncomingConnection).
    server_system_addresses: Vec<SocketAddrV4>,
    /// The last Pong we received (ping/pong time), for latency measurement.
    last_pong: Option<(i64, i64)>,
    /// Set when the server sent a [`message::Disconnect`].
    disconnected: bool,
}

/// A reliable, ordered, retransmitting session built on top of a [`Connection`].
///
/// Created with [`ReliableConnection::new`], which takes ownership of the
/// [`Connection`] (its socket is shared via `Arc` and driven by a background
/// tick task). Drop the `ReliableConnection` to stop the task and close the
/// socket.
pub struct ReliableConnection {
    socket: Arc<UdpSocket>,
    engine: Arc<Mutex<ReliabilityEngine>>,
    state: Arc<Mutex<SessionState>>,
    /// Login-layer encryption session, established after ServerToClientHandshake.
    /// When `Some`, every batch frame body is AES-GCM encrypted/decrypted.
    encryption: Arc<Mutex<Option<super::encryption::EncryptionSession>>>,
    /// Outgoing bytes produced by the tick task (ACK/NACK packets, resends)
    /// that the owner must transmit. Drained lazily inside [`Self::recv`] and
    /// eagerly inside [`Self::send`].
    outgoing_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Sender for reassembled, in-order application frames (written by
    /// [`Self::handle_incoming`]).
    delivery_tx: mpsc::Sender<Frame>,
    /// Receiver for those frames (read by [`Self::recv`]).
    delivery_rx: Mutex<mpsc::Receiver<Frame>>,
    mtu: u16,
    server_guid: i64,
    client_guid: i64,
    /// Compression settings negotiated via NetworkSettings during login.
    network_settings: Arc<Mutex<Option<NetworkSettings>>>,
    /// Handle to the background tick task; aborted on drop.
    _tick: JoinHandle<()>,
}

impl ReliableConnection {
    /// Wraps a live [`Connection`], starting the background reliability task.
    /// Takes ownership of the connection (the socket moves into this wrapper).
    pub fn new(conn: Connection) -> Self {
        let mtu = conn.mtu();
        let server_guid = conn.server_guid();
        let client_guid = conn.client_guid();
        let socket = Arc::new(conn.into_socket());
        let engine = Arc::new(Mutex::new(ReliabilityEngine::new(Instant::now())));
        let state = Arc::new(Mutex::new(SessionState::default()));
        let network_settings = Arc::new(Mutex::new(None));
        let encryption = Arc::new(Mutex::new(None));

        let (outgoing_tx, outgoing_rx) = mpsc::channel(OUTGOING_CHANNEL);
        let (delivery_tx, delivery_rx) = mpsc::channel(DELIVERY_CHANNEL);

        let tick = tokio::spawn(tick_loop(
            Arc::clone(&socket),
            Arc::clone(&engine),
            outgoing_tx,
        ));

        Self {
            socket,
            engine,
            state,
            outgoing_rx: Mutex::new(outgoing_rx),
            delivery_tx,
            delivery_rx: Mutex::new(delivery_rx),
            mtu,
            server_guid,
            client_guid,
            network_settings,
            encryption,
            _tick: tick,
        }
    }

    /// Sends a payload reliably. The reliability determines the delivery
    /// guarantees (ordered frames are delivered in order on the receiver).
    /// Oversized payloads are transparently split into fragments.
    ///
    /// Sequence numbers and frame indices are allocated automatically.
    pub async fn send(&self, reliability: Reliability, body: Vec<u8>) -> Result<()> {
        let max_body = max_frame_body(self.mtu);
        let bytes = {
            let mut eng = self.engine.lock().await;
            eng.prepare_send(reliability, body, max_body, Instant::now())?
        };
        self.socket.send(&bytes).await?;
        // Also flush any outgoing bytes the tick task queued while we held data.
        self.flush_outgoing().await;
        Ok(())
    }

    /// Receives the next application frame, blocking until one is available.
    ///
    /// Internally this pumps the socket: datagrams are fed to the engine (which
    /// ACKs them, reassembles fragments, and releases ordered frames), ACK/NACK
    /// packets drive retransmission, and any bytes the engine wants to send are
    /// transmitted. The call returns once a frame is ready in the delivery
    /// queue.
    pub async fn recv(&self) -> Result<Frame> {
        loop {
            // First, opportunistically deliver anything already queued.
            {
                let mut rx = self.delivery_rx.lock().await;
                match rx.try_recv() {
                    Ok(frame) => return Ok(frame),
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        return Err(PingError::Protocol(
                            "reliability delivery channel closed".to_string(),
                        ));
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {}
                }
            }

            // Pump the socket for one packet (bounded so we stay responsive).
            let mut buf = vec![0u8; self.mtu as usize + 1];
            match timeout(RECV_POLL_INTERVAL, self.socket.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    self.handle_incoming(&buf[..n]).await?;
                }
                Ok(Err(e)) => return Err(PingError::Io(e)),
                Err(_) => {
                    // Idle: still flush outgoing and let the loop continue.
                    self.flush_outgoing().await;
                }
            }
        }
    }

    /// The negotiated MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// The server's 64-bit GUID (negotiated during the handshake).
    pub fn server_guid(&self) -> i64 {
        self.server_guid
    }

    /// This client's GUID.
    pub fn client_guid(&self) -> i64 {
        self.client_guid
    }

    /// Whether the online handshake has completed (the server accepted the
    /// connection via ConnectionRequestAccepted and we replied
    /// NewIncomingConnection).
    pub async fn is_online(&self) -> bool {
        self.state.lock().await.online
    }

    /// Runs the **online handshake**: sends a [`ConnectionRequest`], waits for
    /// the server's [`ConnectionRequestAccepted`] (the recv loop replies with
    /// [`NewIncomingConnection`] automatically), and marks the session online.
    ///
    /// After this returns `Ok(())` the server treats us as a fully connected
    /// client and will begin sending application frames.
    ///
    /// `timeout` bounds the whole exchange. Call this once, right after
    /// [`ReliableConnection::new`].
    pub async fn connect_online(&self, timeout: Duration) -> Result<()> {
        // 1. Send the ConnectionRequest.
        let req = ConnectionRequest {
            client_guid: self.client_guid,
            request_time: current_millis(),
            use_security: false,
        };
        self.send(Reliability::ReliableOrdered, req.encode())
            .await?;

        // 2. Pump recv until the state flips to "online" (set when the recv loop
        //    finishes replying to ConnectionRequestAccepted) or the timeout fires.
        let deadline = Instant::now() + timeout;
        loop {
            if self.is_online().await {
                return Ok(());
            }
            if self.state.lock().await.disconnected {
                return Err(PingError::Protocol(
                    "server disconnected during online handshake".to_string(),
                ));
            }
            if Instant::now() >= deadline {
                return Err(PingError::Protocol(
                    "online handshake timed out waiting for ConnectionRequestAccepted".to_string(),
                ));
            }
            // Pump one packet to make progress; a short timeout keeps the loop
            // responsive to the deadline.
            let mut buf = vec![0u8; self.mtu as usize + 1];
            match tokio::time::timeout(Duration::from_millis(100), self.socket.recv(&mut buf)).await
            {
                Ok(Ok(n)) => self.handle_incoming(&buf[..n]).await?,
                Ok(Err(e)) => return Err(PingError::Io(e)),
                Err(_) => self.flush_outgoing().await,
            }
        }
    }

    /// Called when a [`ConnectionRequestAccepted`] arrives: stores the server's
    /// system addresses and replies with [`NewIncomingConnection`] to finalise
    /// the online handshake.
    async fn on_request_accepted(&self, accepted: &ConnectionRequestAccepted) -> Result<()> {
        let server_address = accepted
            .system_addresses
            .first()
            .copied()
            .unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
        let new_incoming = NewIncomingConnection {
            server_address,
            system_addresses: accepted.system_addresses.clone(),
            ping_time: accepted.pong_time,
            pong_time: current_millis(),
        };
        self.send(Reliability::ReliableOrdered, new_incoming.encode())
            .await?;
        let mut st = self.state.lock().await;
        st.online = true;
        st.server_system_addresses = accepted.system_addresses.clone();
        Ok(())
    }

    /// Sends a [`message::ConnectedPing`] keep-alive. The recv loop replies to
    /// the server's pings automatically with [`message::ConnectedPong`].
    pub async fn ping(&self) -> Result<()> {
        let ping = ConnectedPing {
            time: current_millis(),
        };
        self.send(Reliability::Unreliable, ping.encode()).await
    }

    /// Gracefully closes the session by sending a [`message::Disconnect`], then
    /// stops the background task. The socket is released on drop.
    pub async fn disconnect(&self) -> Result<()> {
        self.send(Reliability::ReliableOrdered, message::Disconnect.encode())
            .await?;
        Ok(())
    }

    // ====== Game-layer (Bedrock protocol) integration ======

    /// Handles a received `ServerToClientHandshake`: parses its JWT to recover
    /// the server's P-384 public key and salt, performs ECDH key agreement to
    /// derive an AES-256-GCM session, sends `ClientToServerHandshake` (the first
    /// encrypted packet), and flips encryption on for all subsequent traffic.
    async fn establish_encryption(&self, handshake_payload: &[u8]) -> Result<()> {
        let hs = login::ServerHandshake::decode_payload(handshake_payload)?;
        let mut session = super::encryption::EncryptionSession::from_handshake(
            &hs.server_public_key_b64,
            &hs.salt,
        )?;
        // Build the ClientToServerHandshake game packet: a single length-prefixed
        // field carrying the encrypted empty payload.
        let c2s_payload = session.encrypt_handshake()?;
        let c2s = protocol::GamePacket::new(super::protocol::ID_CLIENT_TO_SERVER_HANDSHAKE, {
            // The field is varuint32(encrypted_len) + encrypted bytes.
            let mut field = protocol::write_varuint32(c2s_payload.len() as u32);
            field.extend_from_slice(&c2s_payload);
            field
        });
        // Install the session BEFORE sending so send_game_packet encrypts this
        // very packet (the ClientToServerHandshake batch must be encrypted).
        *self.encryption.lock().await = Some(session);
        self.send_game_packet(&c2s).await
    }

    /// Sends a [`GamePacket`] as a compressed batch frame. The packet is wrapped
    /// in a batch (zlib, per the negotiated [`NetworkSettings`] or flate by
    /// default) and handed to the reliability layer with `ReliableOrdered`. If
    /// the login-layer encryption is active, the whole batch body (including the
    /// `0xfe` prefix) is AES-GCM encrypted first.
    pub async fn send_game_packet(&self, packet: &GamePacket) -> Result<()> {
        // Before NetworkSettings is negotiated, send the legacy batch format
        // (no algorithm-prefix byte) — the server hasn't told us which format
        // it expects yet, and many servers reject the modern prefixed format
        // pre-login. Once NetworkSettings arrives we honour its algorithm.
        let ns = self.network_settings.lock().await.clone();
        let (algorithm, use_prefix) = match &ns {
            Some(ns) => (ns.compression_algorithm, true),
            None => (protocol::COMPRESSION_FLATE, false),
        };
        let batch = if use_prefix {
            protocol::encode_batch(std::slice::from_ref(packet), algorithm)?
        } else {
            protocol::encode_batch_legacy(std::slice::from_ref(packet))?
        };
        // If encryption is active, encrypt the whole batch body (0xfe + payload).
        let frame_body = {
            let mut enc = self.encryption.lock().await;
            match enc.as_mut() {
                Some(session) => session.encrypt(&batch)?,
                None => batch,
            }
        };
        self.send(Reliability::ReliableOrdered, frame_body).await
    }

    /// Receives the next [`GamePacket`] from the server. Internally this pumps
    /// [`recv`](Self::recv) until a frame carrying a batch arrives; the batch is
    /// decompressed (and, if encryption is active, decrypted) and its first game
    /// packet is returned. Non-batch frames (e.g. stray system messages) are
    /// skipped.
    pub async fn recv_game_packet(&self) -> Result<GamePacket> {
        loop {
            let frame = self.recv().await?;
            // If encryption is active, every frame carrying a batch is encrypted
            // (no 0xfe prefix visible). Decrypt first, then decode.
            let body: Vec<u8> = {
                let mut enc = self.encryption.lock().await;
                match enc.as_mut() {
                    Some(session) => session.decrypt(frame.body())?,
                    None => frame.body().to_vec(),
                }
            };
            // After decryption (or if unencrypted) a batch starts with 0xfe.
            if body.first().copied() == Some(ID_BATCH as u8) {
                let packets = protocol::decode_batch(&body)?;
                if let Some(first) = packets.into_iter().next() {
                    return Ok(first);
                }
            }
            // Otherwise loop: ignore non-batch frames (system messages).
        }
    }

    /// Runs the **offline Bedrock login**: requests network settings, sends the
    /// login chain, and waits for PlayStatus(LOGIN_SUCCESS). Fails if the server
    /// requires encryption (ServerToClientHandshake) or rejects the login.
    ///
    /// `protocol_version` is the Bedrock protocol number (e.g. 685 for 1.21.80).
    pub async fn login_offline(
        &self,
        protocol_version: i32,
        deadline_timeout: Duration,
    ) -> Result<()> {
        // 1. Request network settings.
        self.send_game_packet(&login::request_network_settings_packet(protocol_version))
            .await?;

        // 2. Wait for NetworkSettings (or an early encryption request / disconnect).
        let deadline = Instant::now() + deadline_timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(PingError::Protocol(
                    "login timed out waiting for NetworkSettings".to_string(),
                ));
            }
            let pkt = self.recv_game_packet_with_deadline(deadline).await?;
            match pkt.id {
                super::protocol::ID_NETWORK_SETTINGS => {
                    let ns = NetworkSettings::decode_payload(&pkt.payload)?;
                    *self.network_settings.lock().await = Some(ns);
                    break; // proceed to send Login
                }
                super::protocol::ID_SERVER_TO_CLIENT_HANDSHAKE => {
                    // Some servers send the handshake before NetworkSettings.
                    self.establish_encryption(&pkt.payload).await?;
                }
                super::protocol::ID_PLAY_STATUS => {
                    let ps = PlayStatus::decode_payload(&pkt.payload)?;
                    return Err(PingError::Protocol(format!(
                        "server rejected login before NetworkSettings: PlayStatus({})",
                        ps.status
                    )));
                }
                _ => { /* ignore unexpected packets, keep waiting */ }
            }
        }

        // 3. Send Login with the offline JWT chain.
        let conn_req = login::default_offline_connection_request(self.client_guid)?;
        self.send_game_packet(&login::login_packet(protocol_version, conn_req))
            .await?;

        // 4. Wait for PlayStatus(LOGIN_SUCCESS) (or ServerToClientHandshake, which
        //    means the server wants to establish login-layer encryption).
        loop {
            if Instant::now() >= deadline {
                return Err(PingError::Protocol(
                    "login timed out waiting for PlayStatus".to_string(),
                ));
            }
            let pkt = self.recv_game_packet_with_deadline(deadline).await?;
            match pkt.id {
                super::protocol::ID_PLAY_STATUS => {
                    let ps = PlayStatus::decode_payload(&pkt.payload)?;
                    return match ps.status {
                        login::play_status::LOGIN_SUCCESS => Ok(()),
                        other => Err(PingError::Protocol(format!(
                            "login rejected: PlayStatus({other})"
                        ))),
                    };
                }
                super::protocol::ID_SERVER_TO_CLIENT_HANDSHAKE => {
                    // Establish the login-layer encryption: parse the JWT,
                    // derive the AES key/IV, send ClientToServerHandshake, and
                    // flip encryption on for all subsequent packets.
                    self.establish_encryption(&pkt.payload).await?;
                    // After encryption is on, continue waiting for PlayStatus
                    // (which now arrives encrypted).
                }
                _ => { /* ignore */ }
            }
        }
    }

    /// Like [`recv_game_packet`](Self::recv_game_packet) but bounded by a
    /// deadline; used internally by [`login_offline`](Self::login_offline).
    async fn recv_game_packet_with_deadline(&self, deadline: Instant) -> Result<GamePacket> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, self.recv_game_packet()).await {
            Ok(r) => r,
            Err(_) => Err(PingError::Protocol(
                "login timed out waiting for a game packet".to_string(),
            )),
        }
    }

    /// Processes one classified-or-raw incoming packet: ACK/NACK drive the
    /// engine's bookkeeping; datagrams yield (possibly ordered) frames.
    async fn handle_incoming(&self, data: &[u8]) -> Result<()> {
        let incoming = super::datagram::classify(data)?;
        match incoming {
            Incoming::Ack(ack) => {
                let mut eng = self.engine.lock().await;
                eng.on_ack(&ack, Instant::now());
            }
            Incoming::Nack(nack) => {
                let to_resend = {
                    let mut eng = self.engine.lock().await;
                    eng.on_nack(&nack, Instant::now())
                };
                for bytes in to_resend {
                    self.socket.send(&bytes).await?;
                }
            }
            Incoming::Datagram(dg) => {
                let (immediate, ordered) = {
                    let mut eng = self.engine.lock().await;
                    let immediate = eng.on_datagram_received(&dg, Instant::now())?;
                    let ordered = eng.drain_ordered();
                    (immediate, ordered)
                };
                let frames_vec: Vec<_> = immediate.into_iter().chain(ordered).collect();
                for frame in frames_vec {
                    // Classify each delivered frame body: system messages are
                    // handled internally (ping→pong, handshake, disconnect),
                    // application frames are forwarded to the caller.
                    match message::classify(frame.body())? {
                        SystemMessage::ConnectedPing(ping) => {
                            // Reply with a ConnectedPong carrying both timestamps.
                            let pong = message::ConnectedPong {
                                ping_time: ping.time,
                                pong_time: current_millis(),
                            };
                            self.send(Reliability::Unreliable, pong.encode()).await?;
                        }
                        SystemMessage::ConnectedPong(pong) => {
                            let mut st = self.state.lock().await;
                            st.last_pong = Some((pong.ping_time, pong.pong_time));
                        }
                        SystemMessage::ConnectionRequestAccepted(accepted) => {
                            // The server accepted our online request. We should
                            // reply with NewIncomingConnection to finalise.
                            self.on_request_accepted(&accepted).await?;
                        }
                        SystemMessage::Disconnect(_) => {
                            let mut st = self.state.lock().await;
                            st.disconnected = true;
                        }
                        // Forward application-layer frames (and messages we
                        // originate ourselves, like ConnectionRequest /
                        // NewIncomingConnection) to the caller.
                        SystemMessage::ConnectionRequest(_)
                        | SystemMessage::NewIncomingConnection(_)
                        | SystemMessage::Application(_) => {
                            if self.delivery_tx.try_send(frame).is_err() {
                                return Err(PingError::Protocol(
                                    "delivery queue full; application recv too slow".to_string(),
                                ));
                            }
                        }
                    }
                }
                // The ACK for this datagram is flushed by the tick task.
            }
        }
        self.flush_outgoing().await;
        Ok(())
    }

    /// Transmits every byte the tick task queued for sending.
    async fn flush_outgoing(&self) {
        let mut rx = self.outgoing_rx.lock().await;
        loop {
            match rx.try_recv() {
                Ok(bytes) => {
                    // A send failure here is non-fatal for the receive loop; the
                    // tick task will retry on the next resend window.
                    let _ = self.socket.send(&bytes).await;
                }
                Err(mpsc::error::TryRecvError::Empty)
                | Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
    }
}

impl Drop for ReliableConnection {
    fn drop(&mut self) {
        self._tick.abort();
    }
}

/// The background reliability loop: every [`TICK_INTERVAL`] it flushes pending
/// ACKs/NACKs and resends datagrams that have been outstanding too long. Bytes
/// to transmit are pushed onto `outgoing` for the owner to send.
async fn tick_loop(
    socket: Arc<UdpSocket>,
    engine: Arc<Mutex<ReliabilityEngine>>,
    outgoing: mpsc::Sender<Vec<u8>>,
) {
    let mut ticker = interval(TICK_INTERVAL);
    loop {
        ticker.tick().await;
        let now = Instant::now();
        let actions = {
            let mut eng = engine.lock().await;
            let mut to_send = Vec::new();
            // ACK flush.
            if let Some(ack) = eng.drain_acks() {
                if let Ok(bytes) = encode_acknowledgement(&ack) {
                    to_send.push(bytes);
                }
            }
            // NACK for detected gaps.
            if let Some(nack) = eng.build_nack() {
                if let Ok(bytes) = encode_acknowledgement(&nack) {
                    to_send.push(bytes);
                }
            }
            // Resend stale datagrams.
            to_send.extend(eng.resend_due(now));
            // Liveness check: if dead, stop the loop (the owner's recv will
            // surface the channel closure).
            if !eng.is_alive(now) {
                break;
            }
            to_send
        };
        for bytes in actions {
            // If the outgoing queue is full (owner not draining), skip rather
            // than block the tick loop; these are best-effort control packets.
            if outgoing.try_send(bytes).is_err() {
                break;
            }
        }
    }
    // Hold the socket reference until the task exits (avoids a use-after-close).
    drop(socket);
}

/// Encodes an [`Acknowledgement`] to its wire bytes. Returns an error only if
/// the packet is malformed (which the engine never produces).
fn encode_acknowledgement(ack: &Acknowledgement) -> Result<Vec<u8>> {
    ack.encode()
}

/// Current time as milliseconds since the UNIX epoch (the timestamp RakNet
/// system messages carry).
fn current_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
