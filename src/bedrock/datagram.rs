//! RakNet **connected-layer wire format** — encode/decode for datagrams, the
//! frames they carry, and the ACK/NACK packets that acknowledge them.
//!
//! After the offline handshake completes ([`super::conn`]), every RakNet message
//! is wrapped in a **datagram** (a.k.a. Frame Set Packet): a single UDP datagram
//! carrying one flag byte, a 24-bit sequence number, and zero or more
//! [`Frame`]s. Each frame is itself an envelope with a reliability header plus
//! the application payload. Peers acknowledge received datagrams with
//! [`Acknowledgement`] packets (ACK `0xC0` / NACK `0xA0`) that carry a range
//! list of sequence numbers.
//!
//! ## Layout
//!
//! ```text
//! Datagram:  flag(0x80–0x8D) | seq(u24 LE) | frame | frame | ...
//!
//! Frame:     flags(u8: reliability<<5 | split<<4)
//!            | body_length_bits(u16 BE)   -- size in BITS, divide by 8 for bytes
//!            | [reliable_index(u24 LE)]   if reliable
//!            | [sequence_index (u24 LE)]  if sequenced
//!            | [order_index    (u24 LE)]  if ordered
//!            | [order_channel  (u8)]      if ordered
//!            | [split_count (u32 BE)]     if split   -- NB: these three are BE,
//!            | [split_id    (u16 BE)]     if split      unlike the LE index fields
//!            | [split_index (u32 BE)]     if split
//!            | body(body_length_bits / 8 bytes)
//!
//! ACK/NACK:  flag(0xC0 ACK | 0xA0 NACK)
//!            | record_count(u16 BE)
//!            | record × record_count
//!               record: is_single(u8) | start(u24 LE) | [end(u24 LE) if !is_single]
//! ```
//!
//! ## Scope
//!
//! This module is the connected-layer **wire format** — encode/decode for
//! datagrams, frames (including split/fragment fields), and ACK/NACK packets.
//! It is pure code with no socket I/O. Frame splitting and reassembly are
//! provided as pure functions ([`Frame::split_into`] / [`Reassembler`]); the
//! reliability state machine (ACK tracking, retransmission, ordered delivery)
//! lives in [`super::reliability`], and the async send/receive wrapper in
//! [`super::reliable_conn`].
//!
//! All items are `pub(crate)`: internal implementation detail. The
//! `dead_code` allowance below silences the (expected) "never used" warnings:
//! the codec is fully exercised by its unit tests today, and will be consumed
//! by the send/receive layer in a later iteration.
//!
//! References (cross-checked, endianness resolved against go-raknet source):
//! - <https://wiki.bedrock.dev/servers/raknet>
//! - <https://minecraft.wiki/w/RakNet>
//! - <https://github.com/sandertv/go-raknet> (`packet.go`, `acknowledge.go`)

// This module is a self-contained codec whose public surface is consumed only
// by tests today (the reliability/send layer is a planned follow-up). Silence
// the dead-code lint at the module level rather than sprinkling attributes.
#![allow(dead_code)]

use super::raknet::PacketBuf;
use crate::error::{PingError, Result};
use std::collections::BTreeMap;

// ==================== Constants ====================

/// Flag byte that marks a datagram (Frame Set Packet). Bits 0–4 carry per-
/// datagram hints (packet-pair, continuous-send, …).
const FLAG_DATAGRAM: u8 = 0x80;
/// Flag byte that marks an ACK packet.
const FLAG_ACK: u8 = 0xc0;
/// Flag byte that marks a NACK packet.
const FLAG_NACK: u8 = 0xa0;

/// Mask selecting the top two bits of the flag byte. All connected-mode
/// packets have bit 7 set; bit 6 further distinguishes ACK (`0xC0`) from the
/// datagram/NACK group (`0x80`).
const KIND_MASK: u8 = 0xc0;
/// Mask selecting bit 5, which splits the datagram/NACK group: NACK sets it
/// (`0xA0`), datagrams leave it clear (`0x80`).
const NACK_BIT: u8 = 0x20;

/// ACK/NACK record marker: `1` = single sequence number (no `end` field).
const ACK_RECORD_SINGLE: u8 = 1;
/// ACK/NACK record marker: `0` = a `[start, end]` range.
const ACK_RECORD_RANGE: u8 = 0;

/// Bit position of the `is_split` flag inside a frame's flags byte.
const FRAME_SPLIT_BIT: u8 = 4;

/// Exclusive upper bound for a 24-bit value (`0x00FF_FFFF + 1`).
const U24_MAX: u32 = 0x00ff_ffff;

// ==================== Reliability ====================

/// Delivery guarantee of a [`Frame`], encoded in the top 3 bits of the frame
/// flags byte.
///
/// Only the five variants Minecraft Bedrock actually uses are modelled. The
/// three "with ack receipt" variants (5–7) are rare and rejected as
/// unsupported on decode; if needed later they can be added without breaking
/// the existing wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reliability {
    /// 0 — fire and forget; no index fields on the wire.
    Unreliable,
    /// 1 — drop-if-stale; sequenced + ordered index fields.
    UnreliableSequenced,
    /// 2 — guaranteed delivery; reliable index field.
    Reliable,
    /// 3 — guaranteed, in-order per channel; reliable + ordered index fields.
    ReliableOrdered,
    /// 4 — guaranteed, latest-only per channel; all three index fields.
    ReliableSequenced,
}

impl Reliability {
    /// Numeric value stored in the frame flags (matches RakNet's enum order).
    fn as_raw(self) -> u8 {
        match self {
            Reliability::Unreliable => 0,
            Reliability::UnreliableSequenced => 1,
            Reliability::Reliable => 2,
            Reliability::ReliableOrdered => 3,
            Reliability::ReliableSequenced => 4,
        }
    }

    /// Decodes the raw 3-bit value from the flags byte, or `Err` for an
    /// unsupported (or out-of-range) value.
    fn from_raw(raw: u8) -> Result<Self> {
        match raw {
            0 => Ok(Reliability::Unreliable),
            1 => Ok(Reliability::UnreliableSequenced),
            2 => Ok(Reliability::Reliable),
            3 => Ok(Reliability::ReliableOrdered),
            4 => Ok(Reliability::ReliableSequenced),
            other => Err(PingError::Protocol(format!(
                "unsupported frame reliability {other} (only 0–4 are supported)"
            ))),
        }
    }

    /// Whether frames of this reliability carry a `reliable_index` (u24 LE).
    pub(crate) fn is_reliable(self) -> bool {
        matches!(
            self,
            Reliability::Reliable | Reliability::ReliableOrdered | Reliability::ReliableSequenced
        )
    }

    /// Whether frames of this reliability carry a `sequence_index` (u24 LE).
    pub(crate) fn is_sequenced(self) -> bool {
        matches!(
            self,
            Reliability::UnreliableSequenced | Reliability::ReliableSequenced
        )
    }

    /// Whether frames of this reliability carry an `order_index` + `order_channel`.
    pub(crate) fn is_ordered(self) -> bool {
        matches!(
            self,
            Reliability::UnreliableSequenced
                | Reliability::ReliableOrdered
                | Reliability::ReliableSequenced
        )
    }
}

// ==================== Frame ====================

/// One encapsulated payload inside a [`Datagram`], with its reliability header.
///
/// The index fields are `Option` and only populated when the
/// [`Reliability`] calls for them; the encoder emits/omits them accordingly,
/// so a freshly-decoded frame round-trips byte-for-byte. The split fields are
/// likewise `Option`: `Some` only on fragment frames produced by
/// [`Frame::split_into`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    reliability: Reliability,
    /// Per-frame index of reliable messages (`Some` only when reliable).
    reliable_index: Option<u32>,
    /// Per-frame index of sequenced messages (`Some` only when sequenced).
    sequence_index: Option<u32>,
    /// Per-channel ordering index (`Some` only when ordered).
    order_index: Option<u32>,
    /// Ordering channel (`0` unless the caller picks another). Meaningful only
    /// when ordered; kept unconditionally so a decoded frame is a faithful
    /// representation of what was on the wire.
    order_channel: u8,
    /// Split metadata (`Some` only for fragment frames). When present, `body`
    /// is one slice of a larger payload; [`Reassembler`] collects the slices
    /// keyed by `split_id` and concatenates them in `split_index` order.
    split: Option<SplitInfo>,
    /// The encapsulated payload (application bytes or a RakNet system message).
    body: Vec<u8>,
}

/// The three split/fragment header fields, present only on fragment frames.
///
/// Wire encoding is **big-endian** for all three (unlike the LE index fields) —
/// see go-raknet `packet.go` (`binary.BigEndian.Uint32/Uint16`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitInfo {
    /// Total number of fragments the original payload was split into.
    pub count: u32,
    /// Identifier shared by all fragments of the same original payload.
    pub id: u16,
    /// Zero-based position of this fragment within the split group.
    pub index: u32,
}

impl Frame {
    /// Creates a frame with the given reliability carrying `body`. Index fields
    /// default to `None`; set the ones the reliability calls for with the
    /// `with_*` builders (an unreliable frame needs none of them).
    pub fn new(reliability: Reliability, body: Vec<u8>) -> Self {
        Self {
            reliability,
            reliable_index: None,
            sequence_index: None,
            order_index: None,
            order_channel: 0,
            split: None,
            body,
        }
    }

    /// Sets the reliable index. Must be `<= 0x00FF_FFFF`.
    pub fn with_reliable_index(mut self, idx: u32) -> Self {
        self.reliable_index = Some(idx);
        self
    }
    /// Sets the sequenced index.
    pub fn with_sequence_index(mut self, idx: u32) -> Self {
        self.sequence_index = Some(idx);
        self
    }
    /// Sets the order index and channel.
    pub fn with_order(mut self, idx: u32, channel: u8) -> Self {
        self.order_index = Some(idx);
        self.order_channel = channel;
        self
    }
    /// Marks this frame as a fragment of a larger payload.
    pub fn with_split(mut self, split: SplitInfo) -> Self {
        self.split = Some(split);
        self
    }

    /// Encodes this frame into a freshly-allocated byte buffer.
    ///
    /// Layout: `flags | body_length_bits(u16 BE) | [reliable_index] |
    /// [sequence_index] | [order_index] | [order_channel] | [split_count |
    /// split_id | split_index] | body`. The length field carries the body size
    /// **in bits** (per RakNet's wire format). The split fields (if present)
    /// are big-endian, unlike the LE index fields.
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        // Validate the index values fit in 24 bits and are consistent with the
        // reliability (a wrong combination would produce a malformed frame that
        // only a buggy peer could accept).
        if self.reliability.is_reliable() != self.reliable_index.is_some() {
            return Err(PingError::Protocol(format!(
                "reliability {:?} requires reliable_index {}",
                self.reliability,
                if self.reliable_index.is_some() {
                    "to be absent"
                } else {
                    "to be set"
                }
            )));
        }
        if self.reliability.is_sequenced() != self.sequence_index.is_some() {
            return Err(PingError::Protocol(format!(
                "reliability {:?} requires sequence_index {}",
                self.reliability,
                if self.sequence_index.is_some() {
                    "to be absent"
                } else {
                    "to be set"
                }
            )));
        }
        if self.reliability.is_ordered() != self.order_index.is_some() {
            return Err(PingError::Protocol(format!(
                "reliability {:?} requires order_index {}",
                self.reliability,
                if self.order_index.is_some() {
                    "to be absent"
                } else {
                    "to be set"
                }
            )));
        }
        for idx in [self.reliable_index, self.sequence_index, self.order_index]
            .into_iter()
            .flatten()
        {
            if idx > U24_MAX {
                return Err(PingError::Protocol(format!(
                    "frame index {idx:#x} exceeds 24-bit maximum {U24_MAX:#x}"
                )));
            }
        }

        // The on-wire "length" field is the body size **in bits** (BE u16), not
        // bytes — see go-raknet `packet.go` (`uint16(len(content))<<3` on write,
        // `Uint16(...) >> 3` on read). So the body must fit in 65535 bits
        // (~8 KiB), well within any MTU; the bound below catches overflow.
        let body_bits = (self.body.len() as u32)
            .checked_mul(8)
            .and_then(|b| u16::try_from(b).ok())
            .ok_or_else(|| {
                PingError::Protocol(format!(
                    "frame body too large to encode: {} bytes ({} bits > 65535)",
                    self.body.len(),
                    self.body.len() as u32 * 8
                ))
            })?;

        let mut buf = Vec::with_capacity(3 + self.body.len() + 20);
        // Flags byte: reliability in the top 3 bits, split bit set if present.
        let split_flag = if self.split.is_some() {
            1 << FRAME_SPLIT_BIT
        } else {
            0
        };
        buf.push((self.reliability.as_raw() << 5) | split_flag);
        buf.extend_from_slice(&body_bits.to_be_bytes());
        if let Some(idx) = self.reliable_index {
            buf.extend_from_slice(&write_u24_le(idx));
        }
        if let Some(idx) = self.sequence_index {
            buf.extend_from_slice(&write_u24_le(idx));
        }
        if let Some(idx) = self.order_index {
            buf.extend_from_slice(&write_u24_le(idx));
            buf.push(self.order_channel);
        }
        // Split fields are big-endian (unlike the LE index fields above).
        if let Some(split) = self.split {
            buf.extend_from_slice(&split.count.to_be_bytes());
            buf.extend_from_slice(&split.id.to_be_bytes());
            buf.extend_from_slice(&split.index.to_be_bytes());
        }
        buf.extend_from_slice(&self.body);
        Ok(buf)
    }

    /// Decodes one frame from the cursor, advancing it past the frame. Returns
    /// `Ok(None)` if the cursor is exactly at the end of the datagram (i.e.
    /// there are no more frames), so callers can loop until drained.
    fn decode(buf: &mut PacketBuf<'_>) -> Result<Option<Self>> {
        if buf.remaining() == 0 {
            return Ok(None);
        }

        let flags = buf.read_u8()?;
        let reliability = Reliability::from_raw(flags >> 5)?;
        let is_split = (flags >> FRAME_SPLIT_BIT) & 1 == 1;

        // The length field is the body size in bits (BE u16) — convert to bytes
        // with `>> 3`. It must be a whole number of bytes; a non-multiple-of-8
        // value would indicate a malformed frame (the encoder always writes
        // `len_bytes << 3`).
        let body_len_bits = buf.read_u16()?;
        if body_len_bits & 0b111 != 0 {
            return Err(PingError::Protocol(format!(
                "frame body length {body_len_bits} is not a whole number of bytes"
            )));
        }
        let body_len = (body_len_bits >> 3) as usize;
        let reliable_index = if reliability.is_reliable() {
            Some(buf.read_u24_le()?)
        } else {
            None
        };
        let sequence_index = if reliability.is_sequenced() {
            Some(buf.read_u24_le()?)
        } else {
            None
        };
        let (order_index, order_channel) = if reliability.is_ordered() {
            (Some(buf.read_u24_le()?), buf.read_u8()?)
        } else {
            (None, 0)
        };
        // Split fields are big-endian (unlike the LE index fields above).
        let split = if is_split {
            let count = read_be_u32(buf)?;
            let id = read_be_u16(buf)?;
            let index = read_be_u32(buf)?;
            Some(SplitInfo { count, id, index })
        } else {
            None
        };
        let body = buf.read_bytes(body_len)?.to_vec();

        Ok(Some(Self {
            reliability,
            reliable_index,
            sequence_index,
            order_index,
            order_channel,
            split,
            body,
        }))
    }

    /// Read-only accessors used by tests (and, later, the receive layer).
    /// The delivery guarantee this frame was sent with.
    pub fn reliability(&self) -> Reliability {
        self.reliability
    }
    /// The reliable index (`Some` only for reliable frames).
    pub fn reliable_index(&self) -> Option<u32> {
        self.reliable_index
    }
    /// The sequenced index (`Some` only for sequenced frames).
    pub fn sequence_index(&self) -> Option<u32> {
        self.sequence_index
    }
    /// The order index (`Some` only for ordered frames).
    pub fn order_index(&self) -> Option<u32> {
        self.order_index
    }
    /// The ordering channel (meaningful only for ordered frames).
    pub fn order_channel(&self) -> u8 {
        self.order_channel
    }
    /// The split metadata (`Some` only for fragment frames).
    pub fn split(&self) -> Option<SplitInfo> {
        self.split
    }
    /// The encapsulated payload (application bytes or a RakNet system message).
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Produces a copy of this frame stripped of its split metadata and body,
    /// keeping only the reliability/index header. Used as the "template" the
    /// reliability layer fills with a reassembled body once all fragments of a
    /// split group have arrived.
    pub(crate) fn reassembly_template(&self) -> Frame {
        Frame {
            reliability: self.reliability,
            reliable_index: self.reliable_index,
            sequence_index: self.sequence_index,
            order_index: self.order_index,
            order_channel: self.order_channel,
            split: None,
            body: Vec::new(),
        }
    }

    /// Returns a copy of this template frame with its body replaced by `body`.
    /// Counterpart to [`reassembly_template`](Self::reassembly_template).
    pub(crate) fn with_body(&self, body: Vec<u8>) -> Frame {
        Frame {
            reliability: self.reliability,
            reliable_index: self.reliable_index,
            sequence_index: self.sequence_index,
            order_index: self.order_index,
            order_channel: self.order_channel,
            split: None,
            body,
        }
    }
}

// ==================== Datagram ====================

/// A Frame Set Packet: the connected-mode envelope carrying zero or more
/// [`Frame`]s, identified by a 24-bit sequence number the receiver acknowledges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    sequence_number: u32,
    frames: Vec<Frame>,
}

impl Datagram {
    /// Creates a datagram with the given sequence number and frames. The
    /// sequence number must fit in 24 bits (`<= 0x00FF_FFFF`).
    pub fn new(sequence_number: u32, frames: Vec<Frame>) -> Result<Self> {
        if sequence_number > U24_MAX {
            return Err(PingError::Protocol(format!(
                "datagram sequence number {sequence_number:#x} exceeds 24-bit maximum {U24_MAX:#x}"
            )));
        }
        Ok(Self {
            sequence_number,
            frames,
        })
    }

    /// Sequence number used for ACK/NACK tracking (24-bit, little-endian on wire).
    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    /// The frames this datagram carries, in wire order.
    pub fn frames(&self) -> &[Frame] {
        &self.frames
    }

    /// Encodes the datagram into a freshly-allocated byte buffer.
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.push(FLAG_DATAGRAM);
        buf.extend_from_slice(&write_u24_le(self.sequence_number));
        for frame in &self.frames {
            buf.extend_from_slice(&frame.encode()?);
        }
        Ok(buf)
    }

    /// Parses a datagram from `data`. Returns `Ok(None)` if `data` is not a
    /// datagram (i.e. it's an ACK/NACK instead), so the caller's dispatch loop
    /// can fall through; returns `Err` for a datagram whose body is malformed.
    fn decode(data: &[u8]) -> Result<Option<Self>> {
        // Dispatch table lives in `classify`; here we only accept genuine
        // datagrams. ACK has bit 6 set (`0xC0`); NACK has bit 5 set (`0xA0`).
        // Both share the 0x80 top group with datagrams, so bit 6 alone can't
        // separate a NACK from a datagram — check bit 5 explicitly.
        let first = match data.first().copied() {
            None => return Ok(None),
            Some(b) => b,
        };
        if first & KIND_MASK == FLAG_ACK || first & NACK_BIT != 0 {
            return Ok(None);
        }
        if first & FLAG_DATAGRAM == 0 {
            return Ok(None);
        }

        let mut p = PacketBuf::new(data, "Datagram");
        p.read_u8()?; // flag (already validated above)
        let sequence_number = p.read_u24_le()?;
        let mut frames = Vec::new();
        while let Some(frame) = Frame::decode(&mut p)? {
            frames.push(frame);
        }
        Ok(Some(Self {
            sequence_number,
            frames,
        }))
    }
}

// ==================== Acknowledgement (ACK / NACK) ====================

/// One entry in an ACK/NACK range list: either a single sequence number or a
/// `[start, end]` inclusive range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange {
    start: u32,
    /// `None` = a single sequence number; `Some(end)` = an inclusive range.
    end: Option<u32>,
}

impl AckRange {
    /// A single sequence number.
    pub fn single(seq: u32) -> Self {
        Self {
            start: seq,
            end: None,
        }
    }
    /// An inclusive `[start, end]` range.
    pub fn range(start: u32, end: u32) -> Self {
        Self {
            start,
            end: Some(end),
        }
    }

    pub fn start(&self) -> u32 {
        self.start
    }
    pub fn end(&self) -> Option<u32> {
        self.end
    }
}

/// An ACK (`0xC0`) or NACK (`0xA0`) packet: a list of datagram sequence-number
/// ranges being acknowledged or requested for retransmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acknowledgement {
    is_ack: bool,
    ranges: Vec<AckRange>,
}

impl Acknowledgement {
    /// Creates an ACK (`is_ack = true`) or NACK (`is_ack = false`) with the
    /// given range list.
    pub fn new(is_ack: bool, ranges: Vec<AckRange>) -> Self {
        Self { is_ack, ranges }
    }

    /// `true` for ACK, `false` for NACK.
    pub fn is_ack(&self) -> bool {
        self.is_ack
    }

    pub fn ranges(&self) -> &[AckRange] {
        &self.ranges
    }

    /// Encodes the packet into a freshly-allocated byte buffer.
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let count = u16::try_from(self.ranges.len()).map_err(|_| {
            PingError::Protocol(format!("too many ACK/NACK records: {}", self.ranges.len()))
        })?;
        let mut buf = Vec::with_capacity(3 + self.ranges.len() * 7);
        buf.push(if self.is_ack { FLAG_ACK } else { FLAG_NACK });
        buf.extend_from_slice(&count.to_be_bytes());
        for r in &self.ranges {
            match r.end {
                None => {
                    buf.push(ACK_RECORD_SINGLE);
                    buf.extend_from_slice(&write_u24_le(r.start));
                }
                Some(end) => {
                    buf.push(ACK_RECORD_RANGE);
                    buf.extend_from_slice(&write_u24_le(r.start));
                    buf.extend_from_slice(&write_u24_le(end));
                }
            }
        }
        Ok(buf)
    }

    /// Parses an ACK or NACK from `data`. Returns `Ok(None)` if `data` is not
    /// an acknowledgement packet (so `classify` can try the other kinds).
    fn decode(data: &[u8]) -> Result<Option<Self>> {
        let first = match data.first().copied() {
            None => return Ok(None),
            Some(b) => b,
        };
        // ACK: bit 6 set (`0xC0`). NACK: bit 6 clear but bit 5 set (`0xA0`),
        // which is what tells it apart from a datagram (`0x80`).
        let is_ack = if first & KIND_MASK == FLAG_ACK {
            true
        } else if first & FLAG_DATAGRAM != 0 && first & NACK_BIT != 0 {
            false
        } else {
            return Ok(None);
        };

        let mut p = PacketBuf::new(data, if is_ack { "ACK" } else { "NACK" });
        p.read_u8()?; // flag
        let count = p.read_u16()? as usize;
        let mut ranges = Vec::with_capacity(count);
        for _ in 0..count {
            let is_single = p.read_u8()?;
            let start = p.read_u24_le()?;
            let end = if is_single == ACK_RECORD_SINGLE {
                None
            } else {
                Some(p.read_u24_le()?)
            };
            ranges.push(AckRange { start, end });
        }
        Ok(Some(Self { is_ack, ranges }))
    }
}

// ==================== Top-level dispatch ====================

/// Result of classifying a single incoming UDP datagram by its first byte.
///
/// This is the entry point a future receive loop will call: it reads exactly
/// one byte to route to the right parser, without requiring the caller to know
/// the flag layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// A Frame Set Packet carrying application/system frames.
    Datagram(Datagram),
    /// An acknowledgement of received datagrams (`0xC0`).
    Ack(Acknowledgement),
    /// A request to retransmit missing datagrams (`0xA0`).
    Nack(Acknowledgement),
}

/// Classifies `data` by its leading flag byte and decodes it fully.
///
/// Returns `Err` for a recognised packet whose body is malformed, or for an
/// unrecognised leading byte (not a datagram / ACK / NACK).
///
/// Flag layout: all connected-mode packets have bit 7 set. Bit 6 distinguishes
/// ACK (`0xC0`) from the rest; bit 5 distinguishes NACK (`0xA0`) from a
/// datagram (`0x80`) within the bit-6-clear group. Matching on the full flag
/// (not just the masked top bits) is what separates NACK from datagram.
pub fn classify(data: &[u8]) -> Result<Incoming> {
    let first = *data.first().ok_or_else(|| {
        PingError::Protocol("empty packet: cannot classify a 0-byte datagram".to_string())
    })?;
    // ACK: bit 6 set.
    if first & KIND_MASK == FLAG_ACK {
        let ack = Acknowledgement::decode(data)?.ok_or_else(|| {
            PingError::Protocol("ACK flag set but decode returned None".to_string())
        })?;
        return Ok(Incoming::Ack(ack));
    }
    // NACK: bit 6 clear, bit 5 set.
    if first & NACK_BIT != 0 && first & FLAG_DATAGRAM != 0 {
        let nack = Acknowledgement::decode(data)?.ok_or_else(|| {
            PingError::Protocol("NACK flag set but decode returned None".to_string())
        })?;
        return Ok(Incoming::Nack(nack));
    }
    // Datagram: bit 7 set, bits 5–6 clear.
    if first & FLAG_DATAGRAM != 0 {
        let dg = Datagram::decode(data)?.ok_or_else(|| {
            PingError::Protocol("datagram flag set but decode returned None".to_string())
        })?;
        return Ok(Incoming::Datagram(dg));
    }
    Err(PingError::Protocol(format!(
        "unknown RakNet connected packet flag 0x{first:02X} (need 0x80 datagram / 0xC0 ACK / 0xA0 NACK)"
    )))
}

// ==================== Helpers ====================

/// Writes a 24-bit value as 3 little-endian bytes (the on-wire form RakNet uses
/// for sequence numbers and frame indices). The high byte of `value` must be 0.
fn write_u24_le(value: u32) -> [u8; 3] {
    let bytes = value.to_le_bytes();
    [bytes[0], bytes[1], bytes[2]]
}

/// Reads a big-endian `u16` from the cursor and advances.
fn read_be_u16(buf: &mut PacketBuf<'_>) -> Result<u16> {
    // PacketBuf::read_u16 is already big-endian; reuse it.
    buf.read_u16()
}

/// Reads a big-endian `u32` from the cursor and advances.
fn read_be_u32(buf: &mut PacketBuf<'_>) -> Result<u32> {
    let bytes = buf.read_bytes(4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

// ==================== Frame splitting / reassembly ====================

/// Per-frame overhead (bytes) that every fragment pays on top of its body, used
/// to compute how large a body slice fits under the MTU:
/// `flags(1) + body_len_bits(2) + reliable_index(3) + order_index(3) +
///  order_channel(1) + split_count(4) + split_id(2) + split_index(4)` = 20.
/// (We always assume a reliable-ordered split frame, the worst case.)
pub(crate) const FRAME_HEADER_MAX_OVERHEAD: usize = 20;

impl Frame {
    /// Splits a payload that is too large for a single frame into multiple
    /// fragment [`Frame`]s, each carrying a body slice of at most
    /// `max_body_bytes`. The caller supplies the reliability and the index
    /// fields that every fragment shares (the reliability header is identical
    /// across fragments; only `split_index` differs).
    ///
    /// Returns the list of fragments, in `split_index` order. The number of
    /// fragments is recorded as `SplitInfo::count` on each. If `body` already
    /// fits in one frame (`body.len() <= max_body_bytes`), a single non-split
    /// frame is returned.
    ///
    /// This is a pure function — it allocates sequence numbers for neither the
    /// datagram nor the reliable/order indices; the caller (reliability layer)
    /// fills those in. `reliable_index` / `order` set on the template frame are
    /// copied verbatim to every fragment.
    pub(crate) fn split_into(
        template: &Frame,
        max_body_bytes: usize,
        split_id: u16,
    ) -> Result<Vec<Frame>> {
        if max_body_bytes == 0 {
            return Err(PingError::Protocol(
                "cannot split a frame with a zero-byte MTU budget".to_string(),
            ));
        }
        let body = &template.body;
        if body.len() <= max_body_bytes {
            // Fits in one frame — emit a single non-split frame.
            return Ok(vec![template.clone()]);
        }
        let count = body.len().div_ceil(max_body_bytes);
        let count_u32 = u32::try_from(count)
            .map_err(|_| PingError::Protocol(format!("too many split fragments: {count}")))?;
        let mut fragments = Vec::with_capacity(count);
        for (index, chunk) in body.chunks(max_body_bytes).enumerate() {
            let split = SplitInfo {
                count: count_u32,
                id: split_id,
                index: index as u32,
            };
            fragments.push(Frame {
                reliability: template.reliability,
                reliable_index: template.reliable_index,
                sequence_index: template.sequence_index,
                order_index: template.order_index,
                order_channel: template.order_channel,
                split: Some(split),
                body: chunk.to_vec(),
            });
        }
        Ok(fragments)
    }
}

/// Collects fragment [`Frame`]s that share a `split_id` and reassembles the
/// original payload once all `count` fragments have arrived.
///
/// Fragments are buffered by `split_index`; when the set is complete the body
/// slices are concatenated in index order. Use one `Reassembler` per
/// outstanding split group (keyed by `split_id`).
#[derive(Debug, Default)]
pub(crate) struct Reassembler {
    fragments: BTreeMap<u32, Vec<u8>>,
    count: u32,
}

impl Reassembler {
    /// Creates an empty reassembler.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Adds a fragment. Returns `Some(reassembled_body)` once the final fragment
    /// needed to complete the group is added (the body slices concatenated in
    /// `split_index` order), or `None` if more fragments are still missing.
    ///
    /// A fragment whose `split_index >= split.count` is rejected as malformed,
    /// as is a duplicate index.
    pub(crate) fn add(&mut self, split: SplitInfo, body: Vec<u8>) -> Result<Option<Vec<u8>>> {
        if split.count == 0 {
            return Err(PingError::Protocol(
                "split frame declares count=0".to_string(),
            ));
        }
        if split.index >= split.count {
            return Err(PingError::Protocol(format!(
                "split_index {} >= split_count {}",
                split.index, split.count
            )));
        }
        if self.fragments.contains_key(&split.index) {
            return Err(PingError::Protocol(format!(
                "duplicate split fragment index {}",
                split.index
            )));
        }
        // First fragment seeds the expected count; later ones must agree.
        if self.fragments.is_empty() {
            self.count = split.count;
        } else if self.count != split.count {
            return Err(PingError::Protocol(format!(
                "split count mismatch: expected {}, got {}",
                self.count, split.count
            )));
        }
        self.fragments.insert(split.index, body);
        if self.fragments.len() == self.count as usize {
            // All present — concatenate in index order and reset.
            let mut assembled = Vec::new();
            for (_idx, chunk) in std::mem::take(&mut self.fragments) {
                assembled.extend_from_slice(&chunk);
            }
            self.count = 0;
            Ok(Some(assembled))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    //! Byte-level encode/decode tests for the RakNet connected wire format.
    //!
    //! These deliberately assert exact byte sequences (not just round-trips):
    //! an endianness bug round-trips cleanly, so only a fixed expected buffer
    //! catches it.

    use super::*;

    // ---------- write_u24_le / read_u24_le round-trip ----------

    #[test]
    fn write_u24_le_matches_read_u24_le() {
        for &v in &[0u32, 1, 0xff, 0x0100, 0x010203, 0xff_ffff] {
            let bytes = write_u24_le(v);
            let mut p = PacketBuf::new(&bytes, "Test");
            assert_eq!(p.read_u24_le().unwrap(), v, "u24 LE round-trip for {v:#x}");
        }
    }

    #[test]
    fn write_u24_le_is_little_endian() {
        // 0x030201 on the wire (LE) = [0x01, 0x02, 0x03].
        assert_eq!(write_u24_le(0x030201), [0x01, 0x02, 0x03]);
    }

    // ---------- Reliability ----------

    #[test]
    fn reliability_flags_are_consistent() {
        assert!(!Reliability::Unreliable.is_reliable());
        assert!(!Reliability::Unreliable.is_ordered());
        assert!(!Reliability::Unreliable.is_sequenced());

        assert!(Reliability::Reliable.is_reliable());
        assert!(!Reliability::Reliable.is_ordered());

        assert!(Reliability::ReliableOrdered.is_reliable());
        assert!(Reliability::ReliableOrdered.is_ordered());
        assert!(!Reliability::ReliableOrdered.is_sequenced());

        assert!(Reliability::ReliableSequenced.is_reliable());
        assert!(Reliability::ReliableSequenced.is_ordered());
        assert!(Reliability::ReliableSequenced.is_sequenced());

        assert!(Reliability::UnreliableSequenced.is_sequenced());
        assert!(Reliability::UnreliableSequenced.is_ordered());
    }

    #[test]
    fn reliability_from_raw_rejects_unsupported() {
        assert!(Reliability::from_raw(0).is_ok());
        assert!(Reliability::from_raw(4).is_ok());
        // Variants 5–7 (with ack receipt) are unsupported.
        for raw in 5..=7u8 {
            assert!(
                Reliability::from_raw(raw).is_err(),
                "raw {raw} should be rejected"
            );
        }
        // Anything >= 8 can't fit in 3 bits, but defend anyway.
        assert!(Reliability::from_raw(8).is_err());
    }

    #[test]
    fn reliability_round_trips_through_raw() {
        for r in [
            Reliability::Unreliable,
            Reliability::UnreliableSequenced,
            Reliability::Reliable,
            Reliability::ReliableOrdered,
            Reliability::ReliableSequenced,
        ] {
            assert_eq!(Reliability::from_raw(r.as_raw()).unwrap(), r);
        }
    }

    // ---------- Frame ----------

    #[test]
    fn frame_unreliable_encode_exact_bytes() {
        // flags(0x00) | body_len_bits(BE: 3<<3 = 0x0018) | body(0xaa 0xbb 0xcc).
        let f = Frame::new(Reliability::Unreliable, vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(f.encode().unwrap(), [0x00, 0x00, 0x18, 0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn frame_reliable_encode_exact_bytes() {
        // flags(0x40 = 2<<5) | len_bits(BE 2<<3=0x10) | reliable_index(LE 0x05 0x00 0x00) | body.
        let f = Frame::new(Reliability::Reliable, vec![0xde, 0xad]).with_reliable_index(5);
        assert_eq!(
            f.encode().unwrap(),
            [0x40, 0x00, 0x10, 0x05, 0x00, 0x00, 0xde, 0xad]
        );
    }

    #[test]
    fn frame_reliable_ordered_encode_exact_bytes() {
        // flags(0x60 = 3<<5) | len_bits(BE) | reliable_idx(LE) | order_idx(LE) | channel | body.
        let f = Frame::new(Reliability::ReliableOrdered, vec![0x01])
            .with_reliable_index(0x010203)
            .with_order(0x0a, 2);
        assert_eq!(
            f.encode().unwrap(),
            [
                0x60, // reliability 3 << 5
                0x00, 0x08, // body_len_bits BE (1 << 3 = 8)
                0x03, 0x02, 0x01, // reliable_index LE (0x010203)
                0x0a, 0x00, 0x00, // order_index LE
                0x02, // order_channel
                0x01, // body
            ]
        );
    }

    #[test]
    fn frame_reliable_sequenced_encode_exact_bytes() {
        // flags(0x80 = 4<<5) | len_bits(BE) | reliable | sequenced | order+channel | body.
        let f = Frame::new(Reliability::ReliableSequenced, vec![0xff])
            .with_reliable_index(1)
            .with_sequence_index(2)
            .with_order(3, 1);
        assert_eq!(
            f.encode().unwrap(),
            [
                0x80, 0x00, 0x08, // flags + len_bits (1 << 3 = 8)
                0x01, 0x00, 0x00, // reliable
                0x02, 0x00, 0x00, // sequenced
                0x03, 0x00, 0x00, 0x01, // order + channel
                0xff,
            ]
        );
    }

    #[test]
    fn frame_split_encode_decode_round_trips() {
        // A reliable-ordered frame split into 3 fragments, each with body [0xAB].
        // Reliability 3 → flags high bits 0x60; split set → bit 4 → 0x70.
        let body = vec![0xAB];
        let split = SplitInfo {
            count: 3,
            id: 0x1234,
            index: 1,
        };
        let f = Frame::new(Reliability::ReliableOrdered, body.clone())
            .with_reliable_index(7)
            .with_order(9, 0)
            .with_split(split);
        let bytes = f.encode().unwrap();
        let mut p = PacketBuf::new(&bytes, "SplitFrame");
        let decoded = Frame::decode(&mut p).unwrap().unwrap();
        assert_eq!(decoded, f);
        assert_eq!(p.remaining(), 0);
    }

    #[test]
    fn frame_split_encode_exact_bytes_big_endian() {
        // Prove the split fields are big-endian (unlike the LE index fields).
        // Unreliable (flags 0x00) split frame: body [0x42] (1 byte → 0x08 bits).
        // split_count=1 (BE: 00 00 00 01), split_id=0x0102 (BE: 01 02),
        // split_index=0 (BE: 00 00 00 00).
        let f = Frame::new(Reliability::Unreliable, vec![0x42]).with_split(SplitInfo {
            count: 1,
            id: 0x0102,
            index: 0,
        });
        assert_eq!(
            f.encode().unwrap(),
            [
                0x10, // flags: unreliable(0) | split bit(0x10)
                0x00, 0x08, // body_len_bits (1 << 3)
                0x00, 0x00, 0x00, 0x01, // split_count BE
                0x01, 0x02, // split_id BE
                0x00, 0x00, 0x00, 0x00, // split_index BE
                0x42, // body
            ]
        );
    }

    #[test]
    fn frame_decode_reads_split_fields() {
        // Hand-build a split frame to prove the decoder reads BE split fields.
        let data = [
            0x10, // flags: unreliable | split
            0x00, 0x08, // body_len_bits = 8 = 1 byte
            0x00, 0x00, 0x00, 0x02, // split_count BE = 2
            0x00, 0x05, // split_id BE = 5
            0x00, 0x00, 0x00, 0x01, // split_index BE = 1
            0x99, // body
        ];
        let mut p = PacketBuf::new(&data, "Split");
        let f = Frame::decode(&mut p).unwrap().unwrap();
        let s = f.split().expect("split metadata present");
        assert_eq!(s.count, 2);
        assert_eq!(s.id, 5);
        assert_eq!(s.index, 1);
        assert_eq!(f.body(), &[0x99]);
    }

    #[test]
    fn frame_non_split_has_no_split_fields() {
        // A plain unreliable frame: flags 0x00, no split bit, no split bytes.
        let f = Frame::new(Reliability::Unreliable, vec![0x01]);
        assert_eq!(f.encode().unwrap(), [0x00, 0x00, 0x08, 0x01]);
        assert!(f.split().is_none());
    }

    #[test]
    fn frame_split_into_fits_in_one_returns_single() {
        // Body already fits → single non-split frame, no SplitInfo.
        let template = Frame::new(Reliability::ReliableOrdered, vec![0x1, 0x2]);
        let frags = Frame::split_into(&template, 100, 0).unwrap();
        assert_eq!(frags.len(), 1);
        assert!(frags[0].split().is_none());
        assert_eq!(frags[0].body(), &[0x1, 0x2]);
    }

    #[test]
    fn frame_split_into_chunks_evenly() {
        // 10-byte body, max 4 bytes each → 3 fragments (4, 4, 2).
        let body: Vec<u8> = (0..10u8).collect();
        let template = Frame::new(Reliability::ReliableOrdered, body.clone()).with_order(0, 0);
        let frags = Frame::split_into(&template, 4, 0xAB).unwrap();
        assert_eq!(frags.len(), 3);
        for (i, f) in frags.iter().enumerate() {
            let s = f.split().expect("fragment has split info");
            assert_eq!(s.count, 3);
            assert_eq!(s.id, 0xAB);
            assert_eq!(s.index, i as u32);
        }
        // Bodies concatenate back to the original.
        let mut reassembled = Vec::new();
        for f in &frags {
            reassembled.extend_from_slice(f.body());
        }
        assert_eq!(reassembled, body);
    }

    #[test]
    fn frame_split_into_preserves_reliability_header() {
        // The reliability/index fields are copied verbatim to every fragment.
        let template = Frame::new(Reliability::ReliableOrdered, vec![0u8; 10])
            .with_reliable_index(5)
            .with_order(7, 2);
        let frags = Frame::split_into(&template, 3, 1).unwrap();
        for f in &frags {
            assert_eq!(f.reliability(), Reliability::ReliableOrdered);
            assert_eq!(f.reliable_index(), Some(5));
            assert_eq!(f.order_index(), Some(7));
            assert_eq!(f.order_channel(), 2);
        }
    }

    #[test]
    fn reassembler_collects_and_concatenates_in_index_order() {
        // Fragments arriving out of order must reassemble in index order.
        let mut r = Reassembler::new();
        assert!(r
            .add(
                SplitInfo {
                    count: 3,
                    id: 1,
                    index: 2
                },
                vec![0x3]
            )
            .unwrap()
            .is_none());
        assert!(r
            .add(
                SplitInfo {
                    count: 3,
                    id: 1,
                    index: 0
                },
                vec![0x1]
            )
            .unwrap()
            .is_none());
        let assembled = r
            .add(
                SplitInfo {
                    count: 3,
                    id: 1,
                    index: 1,
                },
                vec![0x2],
            )
            .unwrap()
            .expect("complete after 3rd fragment");
        assert_eq!(assembled, vec![0x1, 0x2, 0x3]); // index order, not arrival order
    }

    #[test]
    fn reassembler_rejects_duplicate_index() {
        let mut r = Reassembler::new();
        r.add(
            SplitInfo {
                count: 2,
                id: 1,
                index: 0,
            },
            vec![0x1],
        )
        .unwrap();
        assert!(r
            .add(
                SplitInfo {
                    count: 2,
                    id: 1,
                    index: 0
                },
                vec![0x9]
            )
            .is_err());
    }

    #[test]
    fn reassembler_rejects_count_mismatch() {
        let mut r = Reassembler::new();
        r.add(
            SplitInfo {
                count: 3,
                id: 1,
                index: 0,
            },
            vec![0x1],
        )
        .unwrap();
        assert!(r
            .add(
                SplitInfo {
                    count: 2,
                    id: 1,
                    index: 1
                },
                vec![0x2]
            )
            .is_err());
    }

    #[test]
    fn reassembler_rejects_index_out_of_range() {
        let mut r = Reassembler::new();
        assert!(r
            .add(
                SplitInfo {
                    count: 2,
                    id: 1,
                    index: 5
                },
                vec![0x1]
            )
            .is_err());
    }

    #[test]
    fn split_round_trip_through_wire() {
        // Split a payload, encode each fragment, decode it, reassemble — the
        // reassembled body must equal the original. End-to-end split path.
        let original: Vec<u8> = (0..25u8).collect();
        let template = Frame::new(Reliability::ReliableOrdered, original.clone())
            .with_reliable_index(1)
            .with_order(1, 0);
        let frags = Frame::split_into(&template, 10, 0x55).unwrap();
        assert_eq!(frags.len(), 3);

        let mut r = Reassembler::new();
        for f in frags {
            let bytes = f.encode().unwrap();
            let mut p = PacketBuf::new(&bytes, "WireSplit");
            let decoded = Frame::decode(&mut p).unwrap().unwrap();
            let split = decoded.split().expect("decoded fragment is split");
            let done = r.add(split, decoded.body().to_vec()).unwrap();
            if let Some(assembled) = done {
                assert_eq!(assembled, original);
            }
        }
    }

    #[test]
    fn frame_decode_reads_body_length_in_bits() {
        // Hand-build a frame whose length field is in BITS to prove the decoder
        // converts correctly (an endianness/units bug round-trips but fails
        // against a real server's bytes). Body = [0xaa, 0xbb] → len_bits = 0x0010.
        let data = [0x00, 0x00, 0x10, 0xaa, 0xbb];
        let mut p = PacketBuf::new(&data, "BitsLen");
        let f = Frame::decode(&mut p).unwrap().unwrap();
        assert_eq!(f.body(), &[0xaa, 0xbb]);
        assert_eq!(p.remaining(), 0);
    }

    #[test]
    fn frame_decode_rejects_non_byte_aligned_length() {
        // len_bits = 0x0009 (9 bits) — not a whole number of bytes.
        let data = [0x00, 0x00, 0x09, 0xaa];
        let mut p = PacketBuf::new(&data, "BadLen");
        assert!(Frame::decode(&mut p).is_err());
    }

    #[test]
    fn frame_round_trips_all_reliabilities() {
        let cases: Vec<Frame> = vec![
            Frame::new(Reliability::Unreliable, vec![]),
            Frame::new(Reliability::UnreliableSequenced, vec![0x1, 0x2])
                .with_sequence_index(7)
                .with_order(8, 0),
            Frame::new(Reliability::Reliable, vec![0x0]).with_reliable_index(0xff_ffff),
            Frame::new(Reliability::ReliableOrdered, vec![0xa, 0xb, 0xc])
                .with_reliable_index(10)
                .with_order(11, 1),
            Frame::new(Reliability::ReliableSequenced, vec![0x5])
                .with_reliable_index(12)
                .with_sequence_index(13)
                .with_order(14, 3),
        ];
        for original in cases {
            let bytes = original.encode().unwrap();
            let mut p = PacketBuf::new(&bytes, "RoundTrip");
            let decoded = Frame::decode(&mut p)
                .unwrap()
                .expect("a frame should decode");
            assert_eq!(decoded, original, "frame round-trip mismatch");
            assert_eq!(p.remaining(), 0, "no trailing bytes after frame");
        }
    }

    #[test]
    fn frame_encode_rejects_index_reliability_mismatch() {
        // Reliable reliability but no reliable_index.
        let f = Frame::new(Reliability::Reliable, vec![0x0]);
        assert!(f.encode().is_err());
        // Unreliable but with a stray reliable_index.
        let f = Frame::new(Reliability::Unreliable, vec![0x0]).with_reliable_index(1);
        assert!(f.encode().is_err());
    }

    #[test]
    fn frame_encode_rejects_oversized_index() {
        let f = Frame::new(Reliability::Reliable, vec![0x0]).with_reliable_index(0x01_00_00_00); // > 24-bit max
        assert!(f.encode().is_err());
    }

    #[test]
    fn frame_decode_returns_none_at_end_of_buffer() {
        let mut p = PacketBuf::new(&[], "Empty");
        assert!(Frame::decode(&mut p).unwrap().is_none());
    }

    #[test]
    fn frame_decode_truncated_body_is_error() {
        // Declare body_len_bits=0x0010 (2 bytes) but only 1 body byte present.
        let data = [0x00, 0x00, 0x10, 0xaa];
        let mut p = PacketBuf::new(&data, "Trunc");
        assert!(Frame::decode(&mut p).is_err());
    }

    // ---------- Datagram ----------

    #[test]
    fn datagram_encode_exact_bytes_empty() {
        let d = Datagram::new(0x010203, vec![]).unwrap();
        // flag(0x80) | seq LE (0x03 0x02 0x01).
        assert_eq!(d.encode().unwrap(), [0x80, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn datagram_encode_exact_bytes_with_one_frame() {
        let frame = Frame::new(Reliability::Unreliable, vec![0x42]);
        let d = Datagram::new(0, vec![frame]).unwrap();
        // 0x80 | seq(0,0,0) | frame(flags 0x00 | len_bits BE 1<<3=0x08 | 0x42).
        assert_eq!(
            d.encode().unwrap(),
            [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x42]
        );
    }

    #[test]
    fn datagram_round_trips_multiple_frames() {
        let frames = vec![
            Frame::new(Reliability::Unreliable, vec![0x1]),
            Frame::new(Reliability::ReliableOrdered, vec![0x2, 0x3])
                .with_reliable_index(100)
                .with_order(200, 0),
            Frame::new(Reliability::Unreliable, vec![]),
        ];
        let original = Datagram::new(0xabcdef, frames).unwrap();
        let bytes = original.encode().unwrap();
        let decoded = Datagram::decode(&bytes)
            .unwrap()
            .expect("should decode as a datagram");
        assert_eq!(decoded, original);
    }

    #[test]
    fn datagram_decode_returns_none_for_ack() {
        let ack = Acknowledgement::new(true, vec![AckRange::single(0)])
            .encode()
            .unwrap();
        assert!(Datagram::decode(&ack).unwrap().is_none());
    }

    #[test]
    fn datagram_decode_returns_none_for_nack() {
        let nack = Acknowledgement::new(false, vec![AckRange::single(0)])
            .encode()
            .unwrap();
        assert!(Datagram::decode(&nack).unwrap().is_none());
    }

    #[test]
    fn datagram_new_rejects_oversized_sequence() {
        assert!(Datagram::new(0x01_00_00_00, vec![]).is_err());
        assert!(Datagram::new(0x00ff_ffff, vec![]).is_ok());
    }

    #[test]
    fn datagram_decode_reads_sequence_le() {
        // Manually build a datagram with a known LE sequence to prove the
        // decode side reads little-endian (an endianness bug round-trips).
        let bytes = [0x80, 0x05, 0x00, 0x00]; // flag + seq=5 (LE)
        let d = Datagram::decode(&bytes).unwrap().unwrap();
        assert_eq!(d.sequence_number(), 5);
        assert!(d.frames().is_empty());
    }

    // ---------- Acknowledgement ----------

    #[test]
    fn ack_encode_exact_bytes_single_records() {
        let ack = Acknowledgement::new(true, vec![AckRange::single(0x010203), AckRange::single(0)]);
        // flag(0xc0) | count(BE 0x00 0x02) | rec1(is_single=1 | start LE) | rec2(...).
        assert_eq!(
            ack.encode().unwrap(),
            [
                0xc0,
                0x00,
                0x02,
                ACK_RECORD_SINGLE,
                0x03,
                0x02,
                0x01,
                ACK_RECORD_SINGLE,
                0x00,
                0x00,
                0x00,
            ]
        );
    }

    #[test]
    fn nack_encode_exact_bytes_mixed_ranges() {
        let nack = Acknowledgement::new(false, vec![AckRange::single(5), AckRange::range(10, 12)]);
        assert_eq!(
            nack.encode().unwrap(),
            [
                0xa0,
                0x00,
                0x02,
                ACK_RECORD_SINGLE,
                0x05,
                0x00,
                0x00,
                ACK_RECORD_RANGE,
                0x0a,
                0x00,
                0x00,
                0x0c,
                0x00,
                0x00,
            ]
        );
    }

    #[test]
    fn acknowledgement_round_trips() {
        let cases = vec![
            Acknowledgement::new(true, vec![]),
            Acknowledgement::new(true, vec![AckRange::single(0xff_ffff)]),
            Acknowledgement::new(
                false,
                vec![
                    AckRange::range(0, 9),
                    AckRange::single(100),
                    AckRange::range(200, 299),
                ],
            ),
        ];
        for original in cases {
            let bytes = original.encode().unwrap();
            let decoded = Acknowledgement::decode(&bytes)
                .unwrap()
                .expect("should decode as an ack/nack");
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn acknowledgement_decode_reads_record_count_be() {
        // count is u16 BE: [0x00, 0x01] = 1 record.
        let bytes = [0xc0, 0x00, 0x01, ACK_RECORD_SINGLE, 0x00, 0x00, 0x00];
        let ack = Acknowledgement::decode(&bytes).unwrap().unwrap();
        assert!(ack.is_ack());
        assert_eq!(ack.ranges().len(), 1);
        assert_eq!(ack.ranges()[0], AckRange::single(0));
    }

    #[test]
    fn acknowledgement_decode_returns_none_for_datagram() {
        let dg = Datagram::new(0, vec![]).unwrap().encode().unwrap();
        assert!(Acknowledgement::decode(&dg).unwrap().is_none());
    }

    // ---------- classify ----------

    #[test]
    fn classify_routes_datagram() {
        let bytes = Datagram::new(42, vec![Frame::new(Reliability::Unreliable, vec![0x9])])
            .unwrap()
            .encode()
            .unwrap();
        match classify(&bytes).unwrap() {
            Incoming::Datagram(d) => {
                assert_eq!(d.sequence_number(), 42);
                assert_eq!(d.frames().len(), 1);
            }
            other => panic!("expected Datagram, got {other:?}"),
        }
    }

    #[test]
    fn classify_routes_ack_and_nack() {
        let ack = Acknowledgement::new(true, vec![AckRange::single(0)])
            .encode()
            .unwrap();
        assert!(matches!(classify(&ack).unwrap(), Incoming::Ack(_)));

        let nack = Acknowledgement::new(false, vec![AckRange::single(0)])
            .encode()
            .unwrap();
        assert!(matches!(classify(&nack).unwrap(), Incoming::Nack(_)));
    }

    #[test]
    fn classify_rejects_unknown_flag() {
        // 0x00 is not a datagram/ACK/NACK.
        assert!(classify(&[0x00, 0x01, 0x02]).is_err());
    }

    #[test]
    fn classify_rejects_empty_input() {
        assert!(classify(&[]).is_err());
    }
}
