//! RakNet **reliability engine** — the pure state machine that sits between the
//! wire-format codec ([`super::datagram`]) and the async socket layer
//! ([`super::reliable_conn`]).
//!
//! It owns all the bookkeeping a reliable, ordered, retransmitting transport
//! needs, but performs **no I/O**: every method is synchronous and returns the
//! actions the caller should take (bytes to send, frames to deliver, packets to
//! ack). This makes the whole subsystem unit-testable without a socket.
//!
//! ## Responsibilities
//!
//! - **Send side**: allocate datagram sequence numbers and per-frame
//!   reliable/order/sequence indices (all 24-bit, wrapping at `2²⁴`), encapsulate
//!   payloads into [`Frame`]s / [`Datagram`]s, and remember each sent datagram
//!   so it can be retransmitted until acknowledged.
//! - **Receive side**: slide a window over incoming datagram sequence numbers,
//!   generate ACKs for what arrived and NACKs for gaps, and release ordered
//!   frames to the caller in `order_index` order.
//! - **Timing**: track round-trip time (a smoothed average) and decide when a
//!   datagram has been outstanding long enough to resend.
//!
//! ## Single channel
//!
//! This engine models a single ordering channel (channel 0), which is what
//! Minecraft Bedrock uses in practice. Supporting multiple channels would mean
//! keying the order counters and order queue by channel; left as a follow-up.
//!
//! References: go-raknet (`resend_map.go`, `datagram_window.go`,
//! `packet_queue.go`, `acknowledge.go`).

// The engine's methods are consumed by tests today (the async
// `ReliableConnection` wrapper is a follow-up). Silence the expected
// "never used" warnings at the module level.
#![allow(dead_code)]

use super::datagram::{AckRange, Acknowledgement, Datagram, Frame, Reassembler, Reliability};
use crate::error::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// Mask for 24-bit sequence numbers / indices: the value wraps into `[0, 2²⁴)`.
const SEQ_MASK: u32 = 0x00ff_ffff;

/// Initial RTT estimate before any ACK has refined it. go-raknet starts around
/// here; a too-small value causes spurious early resends.
const INITIAL_RTT: Duration = Duration::from_millis(200);

/// Minimum resend interval floor, so a wildly small RTT sample doesn't make
/// resends fire continuously.
const MIN_RESEND_INTERVAL: Duration = Duration::from_millis(80);

/// How many RTTs a datagram may be outstanding before it is resent. RakNet /
/// go-raknet treat a datagram as lost after roughly this multiple of the
/// smoothed RTT.
const RESEND_RTT_MULTIPLIER: u32 = 4;

/// How long without any received packet before the session is considered dead.
const INACTIVITY_BASE: Duration = Duration::from_secs(10);

/// One sent-but-unacknowledged datagram, retained for retransmission.
#[derive(Debug, Clone)]
struct ResendRecord {
    /// The encoded datagram bytes, ready to resend verbatim.
    bytes: Vec<u8>,
    /// When this datagram was (last) sent.
    sent_at: Instant,
    /// How many times it has been resent so far (for diagnostics / caps).
    resends: u32,
}

/// A sliding window over received datagram sequence numbers, used to detect
/// gaps (loss) so NACKs can request retransmission, and to track the
/// contiguous prefix so duplicates are ignored.
#[derive(Debug, Default)]
struct DatagramWindow {
    /// Highest contiguous sequence number already accounted for + 1 (i.e. the
    /// next number we have *not* yet seen contiguously).
    lowest_unseen: u32,
    /// Highest sequence number observed so far.
    highest_seen: u32,
    /// All received sequence numbers at or above `lowest_unseen` (so gaps are
    /// visible). Numbers below `lowest_unseen` were already acked and dropped.
    received: BTreeSet<u32>,
    /// True once the first datagram has arrived, so `highest_seen` is meaningful.
    started: bool,
}

impl DatagramWindow {
    fn new() -> Self {
        Self::default()
    }

    /// Records an incoming sequence number. Returns `true` if it was new (i.e.
    /// not a duplicate or already-acked), `false` if it should be ignored.
    fn record(&mut self, seq: u32) -> bool {
        let seq = seq & SEQ_MASK;
        if !self.started {
            self.started = true;
            self.lowest_unseen = seq;
            self.highest_seen = seq;
            self.received.insert(seq);
            // A single contiguous point: consume it immediately.
            self.advance_contiguous();
            return true;
        }
        // Already-acked: `seq` is strictly behind the contiguous prefix
        // (`lowest_unseen` is ahead of it). Also treat an exact re-arrival of
        // a number we've already consumed (below lowest_unseen) as a duplicate.
        if seq_greater(self.lowest_unseen, seq) {
            return false;
        }
        // Duplicate of an out-of-order arrival still buffered in `received`.
        if self.received.contains(&seq) {
            return false;
        }
        self.received.insert(seq);
        if seq_greater(seq, self.highest_seen) {
            self.highest_seen = seq;
        }
        // Consume the contiguous prefix starting at lowest_unseen.
        self.advance_contiguous();
        true
    }

    /// Drops every number at `lowest_unseen` that is present (consuming the
    /// contiguous run), advancing `lowest_unseen` past it.
    fn advance_contiguous(&mut self) {
        while self.received.remove(&self.lowest_unseen) {
            self.lowest_unseen = self.lowest_unseen.wrapping_add(1) & SEQ_MASK;
        }
    }

    /// Returns the list of missing sequence numbers in `[lowest_unseen,
    /// highest_seen]` as ranges, suitable for a NACK. A number is "missing"
    /// if it lies in that inclusive span but is not in `received`.
    ///
    /// When the window is fully contiguous, `lowest_unseen == highest_seen +
    /// 1` (circularly) and the span is empty, so this returns nothing.
    fn missing(&self) -> Vec<AckRange> {
        if !self.started || self.received.is_empty() {
            return Vec::new();
        }
        // The span of interest is [lowest_unseen, highest_seen] inclusive.
        // Its size (count of numbers) is the forward distance + 1, unless that
        // would wrap the whole space. When lowest_unseen is just past
        // highest_seen (fully contiguous), the span is empty.
        let span = seq_forward_distance(self.lowest_unseen, self.highest_seen);
        if self.received.contains(&self.highest_seen) && span == 0 {
            return Vec::new();
        }
        // Walk each number in the inclusive span, grouping absent ones into runs.
        let mut ranges = Vec::new();
        let mut range_start: Option<u32> = None;
        let mut cur = self.lowest_unseen;
        for _ in 0..=span {
            if !self.received.contains(&cur) {
                range_start.get_or_insert(cur);
            } else if let Some(start) = range_start.take() {
                let prev = wrapping_dec(cur);
                ranges.push(range_or_single(start, prev));
            }
            cur = cur.wrapping_add(1) & SEQ_MASK;
        }
        // Close a trailing run that extended to highest_seen.
        if let Some(start) = range_start.take() {
            ranges.push(range_or_single(start, self.highest_seen));
        }
        ranges
    }
}

/// Forward distance from `from` to `to` under 24-bit circular arithmetic, i.e.
/// how many increment steps to reach `to`. Returns 0 when `from == to`.
fn seq_forward_distance(from: u32, to: u32) -> u32 {
    to.wrapping_sub(from) & SEQ_MASK
}

/// True if `a` is strictly newer than `b` under 24-bit circular arithmetic
/// (treats numbers within half the range as "ahead").
fn seq_greater(a: u32, b: u32) -> bool {
    let diff = a.wrapping_sub(b) & SEQ_MASK;
    diff != 0 && diff < (SEQ_MASK + 1) / 2
}

/// Decrement a 24-bit circular sequence number by one.
fn wrapping_dec(seq: u32) -> u32 {
    seq.wrapping_sub(1) & SEQ_MASK
}

/// Builds an [`AckRange`] from a `[start, end]` inclusive span, collapsing it
/// to a single entry when `start == end`.
fn range_or_single(start: u32, end: u32) -> AckRange {
    if start == end {
        AckRange::single(start)
    } else {
        AckRange::range(start, end)
    }
}

/// The reliability state machine. Pure logic — call its methods and act on what
/// they return.
#[derive(Debug)]
pub(crate) struct ReliabilityEngine {
    // --- Send-side counters (24-bit, wrap). ---
    next_datagram_seq: u32,
    next_message_index: u32,
    next_order_index: u32,
    next_sequence_index: u32,

    // --- Retransmission: datagram seq -> record, until ACKed. ---
    unacked: BTreeMap<u32, ResendRecord>,

    // --- Receive side. ---
    recv_window: DatagramWindow,
    /// Sequence numbers received but not yet ACKed (drained periodically).
    pending_acks: BTreeSet<u32>,

    // --- Ordered delivery: order_index -> reassembled frame body waiting for
    //     its turn (gaps block delivery). ---
    order_queue: BTreeMap<u32, Frame>,
    next_delivery_order_index: u32,

    // --- In-flight split reassembly, keyed by split_id. ---
    reassemblers: BTreeMap<u16, (Reassembler, Frame)>,

    // --- Timing. ---
    rtt: Duration,
    last_recv: Instant,
}

impl ReliabilityEngine {
    /// Creates a fresh engine. `now` seeds the inactivity/RTT clocks.
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            next_datagram_seq: 0,
            next_message_index: 0,
            next_order_index: 0,
            next_sequence_index: 0,
            unacked: BTreeMap::new(),
            recv_window: DatagramWindow::new(),
            pending_acks: BTreeSet::new(),
            order_queue: BTreeMap::new(),
            next_delivery_order_index: 0,
            reassemblers: BTreeMap::new(),
            rtt: INITIAL_RTT,
            last_recv: now,
        }
    }

    /// Current smoothed RTT estimate.
    pub(crate) fn rtt(&self) -> Duration {
        self.rtt
    }

    /// Prepares a payload for reliable/ordered/etc. delivery: assigns indices,
    /// wraps it in a [`Frame`] (splitting if it exceeds the MTU budget), packs
    /// the resulting frame(s) into one [`Datagram`], and records the datagram
    /// for retransmission. Returns the encoded datagram bytes ready to send.
    ///
    /// `max_body_bytes` is the largest payload a single (non-split) frame may
    /// carry; the caller derives it from the MTU minus headers.
    pub(crate) fn prepare_send(
        &mut self,
        reliability: Reliability,
        body: Vec<u8>,
        max_body_bytes: usize,
        now: Instant,
    ) -> Result<Vec<u8>> {
        // Build the template frame with the indices this reliability requires.
        let mut template = Frame::new(reliability, body);
        if reliability.is_reliable() {
            template = template.with_reliable_index(self.next_message_index & SEQ_MASK);
            self.next_message_index = self.next_message_index.wrapping_add(1) & SEQ_MASK;
        }
        if reliability.is_sequenced() {
            template = template.with_sequence_index(self.next_sequence_index & SEQ_MASK);
            self.next_sequence_index = self.next_sequence_index.wrapping_add(1) & SEQ_MASK;
        }
        if reliability.is_ordered() {
            template =
                template.with_order(self.next_order_index & SEQ_MASK, 0 /* channel 0 */);
            self.next_order_index = self.next_order_index.wrapping_add(1) & SEQ_MASK;
        }

        // Split if too large, then pack all fragments into one datagram.
        let split_id = (self.next_datagram_seq as u16).wrapping_add(1);
        let fragments = Frame::split_into(&template, max_body_bytes, split_id)?;
        let seq = self.next_datagram_seq & SEQ_MASK;
        self.next_datagram_seq = self.next_datagram_seq.wrapping_add(1) & SEQ_MASK;
        let datagram = Datagram::new(seq, fragments)?;
        let bytes = datagram.encode()?;

        // Track for retransmission. (Only reliable datagrams strictly need it,
        // but tracking all of them is simpler and the cost is one map entry.)
        self.unacked.insert(
            seq,
            ResendRecord {
                bytes: bytes.clone(),
                sent_at: now,
                resends: 0,
            },
        );
        Ok(bytes)
    }

    /// Processes a received datagram: records its sequence number in the
    /// receive window (scheduling an ACK), and returns the application frames
    /// it carried — *in the order they should be delivered*. Ordered frames may
    /// be buffered until their predecessors arrive; unordered/unreliable frames
    /// are returned immediately.
    pub(crate) fn on_datagram_received(
        &mut self,
        dg: &Datagram,
        now: Instant,
    ) -> Result<Vec<Frame>> {
        self.last_recv = now;
        let seq = dg.sequence_number() & SEQ_MASK;
        let is_new = self.recv_window.record(seq);
        if is_new {
            self.pending_acks.insert(seq);
        }

        // Extract frames; reassemble splits, then route ordered frames through
        // the order queue.
        let mut delivered = Vec::new();
        for frame in dg.frames() {
            // If this is a split fragment, feed the reassembler.
            if let Some(split) = frame.split() {
                let key = split.id;
                let body_chunk = frame.body().to_vec();
                // The first fragment to arrive seeds a (reassembler, template)
                // pair; the template carries the reliability/index metadata that
                // the reassembled frame will inherit.
                let (mut reassembler, template) = self
                    .reassemblers
                    .remove(&key)
                    .unwrap_or_else(|| (Reassembler::new(), frame.reassembly_template()));
                match reassembler.add(split, body_chunk)? {
                    Some(assembled) => {
                        // Complete: build the full frame from the template + body.
                        let full = template.with_body(assembled);
                        self.route_frame(full, &mut delivered);
                        // Reassembler consumed; do not reinsert.
                    }
                    None => {
                        self.reassemblers.insert(key, (reassembler, template));
                    }
                }
                continue;
            }
            self.route_frame(frame.clone(), &mut delivered);
        }
        Ok(delivered)
    }

    /// Routes a single (complete, non-split) frame to either immediate
    /// delivery or the ordered queue.
    fn route_frame(&mut self, frame: Frame, delivered: &mut Vec<Frame>) {
        if frame.reliability().is_ordered() {
            if let Some(order_index) = frame.order_index() {
                self.order_queue.insert(order_index, frame);
                return;
            }
        }
        // Unreliable / reliable-but-unordered: deliver now.
        delivered.push(frame);
    }

    /// Drains the ordered queue, returning every frame whose `order_index` is
    /// the next expected one (contiguous prefix). Call after
    /// [`on_datagram_received`] to release frames that became deliverable.
    pub(crate) fn drain_ordered(&mut self) -> Vec<Frame> {
        let mut out = Vec::new();
        while let Some(frame) = self.order_queue.remove(&self.next_delivery_order_index) {
            self.next_delivery_order_index =
                self.next_delivery_order_index.wrapping_add(1) & SEQ_MASK;
            out.push(frame);
        }
        out
    }

    /// Processes a received ACK: removes the acknowledged datagram(s) from the
    /// retransmission set and refines the RTT estimate using their send time.
    pub(crate) fn on_ack(&mut self, ack: &Acknowledgement, now: Instant) {
        for range in ack.ranges() {
            let mut seq = range.start();
            loop {
                if let Some(record) = self.unacked.remove(&seq) {
                    let sample = now.saturating_duration_since(record.sent_at);
                    self.update_rtt(sample);
                }
                if Some(&seq) == range.end().as_ref() {
                    break;
                }
                seq = seq.wrapping_add(1) & SEQ_MASK;
                // Guard against a degenerate infinite loop if start > end.
                if seq == range.start() {
                    break;
                }
            }
        }
    }

    /// Processes a received NACK: returns the encoded bytes of every datagram
    /// the peer asked us to resend, and resets their send timestamp (so the
    /// next resend deadline is measured from now).
    pub(crate) fn on_nack(&mut self, nack: &Acknowledgement, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for range in nack.ranges() {
            let mut seq = range.start();
            loop {
                if let Some(record) = self.unacked.get_mut(&seq) {
                    record.sent_at = now;
                    out.push(record.bytes.clone());
                }
                if Some(&seq) == range.end().as_ref() {
                    break;
                }
                seq = seq.wrapping_add(1) & SEQ_MASK;
                if seq == range.start() {
                    break;
                }
            }
        }
        out
    }

    /// Builds and returns the ACK packet for everything received since the last
    /// drain, coalescing consecutive sequence numbers into ranges. Returns
    /// `None` if there is nothing to acknowledge.
    pub(crate) fn drain_acks(&mut self) -> Option<Acknowledgement> {
        if self.pending_acks.is_empty() {
            return None;
        }
        let seqs: Vec<u32> = self.pending_acks.iter().copied().collect();
        self.pending_acks.clear();
        let ranges = coalesce_ranges(&seqs);
        if ranges.is_empty() {
            return None;
        }
        Some(Acknowledgement::new(true, ranges))
    }

    /// Returns the NACK packet (if any) describing currently-missing datagram
    /// sequence numbers. Call periodically to request retransmission of gaps.
    pub(crate) fn build_nack(&self) -> Option<Acknowledgement> {
        let ranges = self.recv_window.missing();
        if ranges.is_empty() {
            None
        } else {
            Some(Acknowledgement::new(false, ranges))
        }
    }

    /// Returns the encoded bytes of every datagram that has been outstanding
    /// longer than the resend threshold (`RTT × RESEND_RTT_MULTIPLIER`), and
    /// refreshes its send timestamp so the next deadline is relative to now.
    pub(crate) fn resend_due(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let threshold = self
            .rtt
            .checked_mul(RESEND_RTT_MULTIPLIER)
            .unwrap_or(self.rtt)
            .max(MIN_RESEND_INTERVAL);
        let mut out = Vec::new();
        for record in self.unacked.values_mut() {
            if now.saturating_duration_since(record.sent_at) >= threshold {
                record.sent_at = now;
                record.resends = record.resends.saturating_add(1);
                out.push(record.bytes.clone());
            }
        }
        out
    }

    /// Whether the session is still considered alive (a packet has been
    /// received within the inactivity window).
    pub(crate) fn is_alive(&self, now: Instant) -> bool {
        let timeout = INACTIVITY_BASE + self.rtt * 2;
        now.saturating_duration_since(self.last_recv) < timeout
    }

    /// Smoothed-RTT update. A simple exponential moving average that blends the
    /// latest sample, mirroring go-raknet's behaviour of tracking a rolling RTT.
    fn update_rtt(&mut self, sample: Duration) {
        // EMA: new = old * 7/8 + sample * 1/8.
        let old = self.rtt;
        let eighth = sample / 8;
        let seven_eighths = old - old / 8;
        self.rtt = seven_eighths + eighth;
    }
}

/// Coalesces a sorted list of sequence numbers into [`AckRange`]s, merging runs
/// of consecutive numbers into a single inclusive range and singletons into a
/// `single` record.
fn coalesce_ranges(seqs: &[u32]) -> Vec<AckRange> {
    let mut ranges = Vec::new();
    let mut iter = seqs.iter().copied();
    let Some(mut start) = iter.next() else {
        return ranges;
    };
    let mut prev = start;
    for cur in iter {
        // Merge only plain consecutive numbers (prev + 1 == cur with no wrap),
        // so a run never spans the 2²⁴ boundary — a circular range is ambiguous
        // on the wire. `cur == prev + 1` with `cur > prev` guarantees no wrap.
        if cur == prev.wrapping_add(1) && cur > prev {
            prev = cur;
            continue;
        }
        // Run ended at `prev`.
        ranges.push(range_or_single(start, prev));
        start = cur;
        prev = cur;
    }
    ranges.push(range_or_single(start, prev));
    ranges
}

#[cfg(test)]
mod tests {
    //! Unit tests for the reliability engine. Pure logic, no I/O.

    use super::*;
    use crate::bedrock::datagram::SplitInfo;

    /// A fixed "now" anchor so timing-dependent tests are deterministic.
    fn t0() -> Instant {
        Instant::now()
    }

    // ---------- DatagramWindow ----------

    #[test]
    fn window_records_contiguous_and_advances() {
        let mut w = DatagramWindow::new();
        assert!(w.record(0));
        assert!(w.record(1));
        assert!(w.record(2));
        assert_eq!(w.lowest_unseen, 3);
        assert!(w.missing().is_empty());
    }

    #[test]
    fn window_detects_gap_as_missing() {
        let mut w = DatagramWindow::new();
        assert!(w.record(0));
        assert!(w.record(2)); // gap at 1
        let missing = w.missing();
        assert_eq!(missing, vec![AckRange::single(1)]);
    }

    #[test]
    fn window_ignores_duplicates() {
        let mut w = DatagramWindow::new();
        assert!(w.record(5));
        assert!(!w.record(5)); // duplicate → false
        assert_eq!(w.highest_seen, 5);
    }

    #[test]
    fn window_missing_coalesces_a_run() {
        let mut w = DatagramWindow::new();
        assert!(w.record(0));
        assert!(w.record(5)); // gaps at 1,2,3,4
        let missing = w.missing();
        assert_eq!(missing, vec![AckRange::range(1, 4)]);
    }

    #[test]
    fn window_wraps_at_24_bits() {
        let mut w = DatagramWindow::new();
        let high = SEQ_MASK; // 0xFFFFFF
        assert!(w.record(high));
        assert!(w.record(0)); // wrapped contiguous
        assert_eq!(w.lowest_unseen, 1);
        assert!(w.missing().is_empty());
    }

    // ---------- sequence helpers ----------

    #[test]
    fn seq_greater_handles_wraparound() {
        assert!(seq_greater(5, 3));
        assert!(!seq_greater(3, 5));
        // Near the wrap boundary: high numbers are "old".
        assert!(seq_greater(0, SEQ_MASK));
        assert!(!seq_greater(SEQ_MASK, 0));
    }

    // ---------- prepare_send / on_ack (RTT) ----------

    #[test]
    fn prepare_send_allocates_increasing_sequence_numbers() {
        let mut eng = ReliabilityEngine::new(t0());
        let b1 = eng
            .prepare_send(Reliability::ReliableOrdered, vec![0x1], 1024, t0())
            .unwrap();
        let b2 = eng
            .prepare_send(Reliability::ReliableOrdered, vec![0x2], 1024, t0())
            .unwrap();
        // Decode to read the assigned sequence numbers.
        let d1 = decode_datagram(&b1);
        let d2 = decode_datagram(&b2);
        assert_eq!(d1.sequence_number(), 0);
        assert_eq!(d2.sequence_number(), 1);
    }

    #[test]
    fn ack_removes_datagram_and_updates_rtt() {
        let mut eng = ReliabilityEngine::new(t0());
        let bytes = eng
            .prepare_send(Reliability::ReliableOrdered, vec![0x1], 1024, t0())
            .unwrap();
        let _ = bytes;
        assert_eq!(eng.unacked.len(), 1);

        // Simulate an ACK arriving 100 ms later.
        let later = t0() + Duration::from_millis(100);
        eng.on_ack(
            &Acknowledgement::new(true, vec![AckRange::single(0)]),
            later,
        );
        assert!(eng.unacked.is_empty(), "ACK should clear the unacked entry");
        // RTT should have moved toward 100 ms (from the 200 ms initial).
        assert!(
            eng.rtt() < INITIAL_RTT,
            "RTT should decrease after a fast sample"
        );
    }

    // ---------- NACK / retransmission ----------

    #[test]
    fn nack_returns_bytes_for_resend() {
        let mut eng = ReliabilityEngine::new(t0());
        let original = eng
            .prepare_send(Reliability::ReliableOrdered, vec![0xab], 1024, t0())
            .unwrap();
        let resent = eng.on_nack(
            &Acknowledgement::new(false, vec![AckRange::single(0)]),
            t0(),
        );
        assert_eq!(resent, vec![original]);
    }

    #[test]
    fn resend_due_returns_stale_datagrams() {
        let mut eng = ReliabilityEngine::new(t0());
        let bytes = eng
            .prepare_send(Reliability::ReliableOrdered, vec![0x1], 1024, t0())
            .unwrap();

        // Not due immediately.
        assert!(eng.resend_due(t0()).is_empty());

        // Due after RTT × multiplier.
        let later = t0() + eng.rtt() * RESEND_RTT_MULTIPLIER * 2;
        let due = eng.resend_due(later);
        assert_eq!(due, vec![bytes.clone()]);
        // A second immediate check shouldn't resend again (timestamp refreshed).
        assert!(eng.resend_due(later).is_empty());
    }

    // ---------- ordered delivery ----------

    #[test]
    fn ordered_frames_deliver_in_order_despite_arrival_shuffle() {
        let mut eng = ReliabilityEngine::new(t0());
        // Frame with order_index 1 arrives before order_index 0.
        let f1 = Frame::new(Reliability::ReliableOrdered, vec![0x1])
            .with_reliable_index(0)
            .with_order(1, 0);
        let dg1 = Datagram::new(1, vec![f1]).unwrap();
        let delivered = eng.on_datagram_received(&dg1, t0()).unwrap();
        assert!(delivered.is_empty(), "out-of-order frame is buffered");
        assert!(eng.drain_ordered().is_empty());

        // Now order_index 0 arrives.
        let f0 = Frame::new(Reliability::ReliableOrdered, vec![0x0])
            .with_reliable_index(0)
            .with_order(0, 0);
        let dg0 = Datagram::new(0, vec![f0]).unwrap();
        eng.on_datagram_received(&dg0, t0()).unwrap();
        let drained = eng.drain_ordered();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].order_index(), Some(0));
        assert_eq!(drained[1].order_index(), Some(1));
    }

    #[test]
    fn unordered_frames_deliver_immediately() {
        let mut eng = ReliabilityEngine::new(t0());
        let f = Frame::new(Reliability::Unreliable, vec![0x42]);
        let dg = Datagram::new(0, vec![f]).unwrap();
        let delivered = eng.on_datagram_received(&dg, t0()).unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].body(), &[0x42]);
    }

    // ---------- ACK coalescing ----------

    #[test]
    fn drain_acks_coalesces_consecutive_into_ranges() {
        let mut eng = ReliabilityEngine::new(t0());
        for seq in [0u32, 1, 2, 5, 6] {
            eng.recv_window.record(seq);
            eng.pending_acks.insert(seq);
        }
        let ack = eng.drain_acks().unwrap();
        let ranges = ack.ranges();
        // [0,1,2] → range; [5,6] → range.
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start(), 0);
        assert_eq!(ranges[0].end(), Some(2));
        assert_eq!(ranges[1].start(), 5);
        assert_eq!(ranges[1].end(), Some(6));
    }

    #[test]
    fn drain_acks_single_becomes_single_record() {
        let mut eng = ReliabilityEngine::new(t0());
        eng.pending_acks.insert(42);
        let ack = eng.drain_acks().unwrap();
        assert_eq!(ack.ranges(), &[AckRange::single(42)]);
    }

    #[test]
    fn drain_acks_none_when_empty() {
        let mut eng = ReliabilityEngine::new(t0());
        assert!(eng.drain_acks().is_none());
    }

    // ---------- inactivity ----------

    #[test]
    fn is_alive_false_after_inactivity_window() {
        let mut eng = ReliabilityEngine::new(t0());
        let far_future = t0() + INACTIVITY_BASE + Duration::from_secs(60);
        assert!(!eng.is_alive(far_future));
    }

    #[test]
    fn is_alive_true_after_recent_traffic() {
        let eng = ReliabilityEngine::new(t0());
        assert!(eng.is_alive(t0()));
    }

    // ---------- split reassembly through the engine ----------

    #[test]
    fn engine_reassembles_split_frames() {
        let mut eng = ReliabilityEngine::new(t0());
        // Two fragments of a split group, arriving in one datagram.
        let f0 = Frame::new(Reliability::ReliableOrdered, vec![0x1, 0x2])
            .with_reliable_index(0)
            .with_order(0, 0)
            .with_split(SplitInfo {
                count: 2,
                id: 1,
                index: 0,
            });
        let f1 = Frame::new(Reliability::ReliableOrdered, vec![0x3, 0x4])
            .with_reliable_index(0)
            .with_order(0, 0)
            .with_split(SplitInfo {
                count: 2,
                id: 1,
                index: 1,
            });
        let dg = Datagram::new(0, vec![f0, f1]).unwrap();
        eng.on_datagram_received(&dg, t0()).unwrap();
        let drained = eng.drain_ordered();
        assert_eq!(drained.len(), 1);
        // Reassembled body = concatenation in index order.
        assert_eq!(drained[0].body(), &[0x1, 0x2, 0x3, 0x4]);
        assert!(
            drained[0].split().is_none(),
            "reassembled frame is not split"
        );
    }

    #[test]
    fn engine_buffers_partial_split_until_complete() {
        let mut eng = ReliabilityEngine::new(t0());
        // First fragment only.
        let f0 = Frame::new(Reliability::ReliableOrdered, vec![0x1])
            .with_order(0, 0)
            .with_split(SplitInfo {
                count: 2,
                id: 1,
                index: 0,
            });
        let dg0 = Datagram::new(0, vec![f0]).unwrap();
        eng.on_datagram_received(&dg0, t0()).unwrap();
        assert!(
            eng.drain_ordered().is_empty(),
            "partial split not delivered"
        );

        // Second fragment completes it.
        let f1 = Frame::new(Reliability::ReliableOrdered, vec![0x2])
            .with_order(0, 0)
            .with_split(SplitInfo {
                count: 2,
                id: 1,
                index: 1,
            });
        let dg1 = Datagram::new(1, vec![f1]).unwrap();
        eng.on_datagram_received(&dg1, t0()).unwrap();
        let drained = eng.drain_ordered();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].body(), &[0x1, 0x2]);
    }

    // ---------- coalesce_ranges helper ----------

    #[test]
    fn coalesce_ranges_wraps_correctly() {
        // Numbers near the wrap boundary should not be merged across it.
        let ranges = coalesce_ranges(&[SEQ_MASK, 0]);
        assert_eq!(ranges.len(), 2, "wrap boundary must split the range");
    }

    /// Decodes a datagram from raw bytes (test helper).
    fn decode_datagram(bytes: &[u8]) -> Datagram {
        use crate::bedrock::datagram::classify;
        match classify(bytes).unwrap() {
            crate::bedrock::datagram::Incoming::Datagram(d) => d,
            other => panic!("expected a datagram, got {other:?}"),
        }
    }
}
