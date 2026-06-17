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
use super::reliability::ReliabilityEngine;
use crate::error::{PingError, Result};
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

/// A reliable, ordered, retransmitting session built on top of a [`Connection`].
///
/// Created with [`ReliableConnection::new`], which takes ownership of the
/// [`Connection`] (its socket is shared via `Arc` and driven by a background
/// tick task). Drop the `ReliableConnection` to stop the task and close the
/// socket.
pub struct ReliableConnection {
    socket: Arc<UdpSocket>,
    engine: Arc<Mutex<ReliabilityEngine>>,
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
    /// Handle to the background tick task; aborted on drop.
    _tick: JoinHandle<()>,
}

impl ReliableConnection {
    /// Wraps a live [`Connection`], starting the background reliability task.
    /// Takes ownership of the connection (the socket moves into this wrapper).
    pub fn new(conn: Connection) -> Self {
        let mtu = conn.mtu();
        let server_guid = conn.server_guid();
        let socket = Arc::new(conn.into_socket());
        let engine = Arc::new(Mutex::new(ReliabilityEngine::new(Instant::now())));

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
            outgoing_rx: Mutex::new(outgoing_rx),
            delivery_tx,
            delivery_rx: Mutex::new(delivery_rx),
            mtu,
            server_guid,
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
                let frames = {
                    let mut eng = self.engine.lock().await;
                    eng.on_datagram_received(&dg, Instant::now())?;
                    eng.drain_ordered()
                };
                for frame in frames {
                    // try_send so a full delivery queue doesn't deadlock the
                    // receive loop; a backed-up caller surfaces as an error.
                    if self.delivery_tx.try_send(frame).is_err() {
                        return Err(PingError::Protocol(
                            "delivery queue full; application recv too slow".to_string(),
                        ));
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
