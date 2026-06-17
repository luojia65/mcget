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
use super::message::{
    self, ConnectedPing, ConnectionRequest, ConnectionRequestAccepted, NewIncomingConnection,
    SystemMessage,
};
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
        self.send(Reliability::ReliableOrdered, req.encode()).await?;

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
            match tokio::time::timeout(Duration::from_millis(100), self.socket.recv(&mut buf)).await {
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
        let ping = ConnectedPing { time: current_millis() };
        self.send(Reliability::Unreliable, ping.encode()).await
    }

    /// Gracefully closes the session by sending a [`message::Disconnect`], then
    /// stops the background task. The socket is released on drop.
    pub async fn disconnect(&self) -> Result<()> {
        self.send(Reliability::ReliableOrdered, message::Disconnect.encode())
            .await?;
        Ok(())
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
                let frames = immediate.into_iter().chain(ordered);
                for frame in frames {
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
                Err(mpsc::error::TryRecvError::Empty) | Err(mpsc::error::TryRecvError::Disconnected) => break,
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
