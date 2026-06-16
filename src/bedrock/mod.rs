//! Minecraft Bedrock / Pocket Edition RakNet utilities.
//!
//! This module is split into three submodules:
//!
//! - [`ping()`] — connectionless **Unconnected Ping** (single UDP round-trip to
//!   read a server's MOTD / player count, no session established). This is the
//!   original Bedrock support in this crate.
//! - [`conn`] — connection-oriented **RakNet handshake** ([`conn::Connection`]),
//!   which establishes a persistent UDP session with a server (negotiating the
//!   MTU, server GUID and encryption flag). After `connect()` succeeds the
//!   session is established but no application-layer packets can be sent yet
//!   (that requires the datagram layer, planned for a later iteration).
//! - [`raknet`] — shared **online-format primitives** (offline-message magic,
//!   the [`PacketBuf`][raknet::PacketBuf] cursor reader, and the IPv4
//!   system-address codec) reused by both [`ping`] and [`conn`]. Internal only.
//!
//! All original public items ([`Client`], [`RequestBuilder`], [`PongResponse`],
//! [`ping()`], [`MAGIC`]) are re-exported here so the `mcget::bedrock::…` paths
//! are unchanged from before the module split.

pub mod conn;
pub mod ping;
// Wire-format primitives (magic / PacketBuf / IPv4 system-address codec). Internal.
mod raknet;

pub use ping::{ping as ping_bedrock_inner, Client, PongResponse, RequestBuilder};
// MAGIC is defined in `raknet` and surfaced here so the public path
// `mcget::bedrock::MAGIC` stays stable.
pub use raknet::MAGIC;

/// Default port for Bedrock Edition.
pub const DEFAULT_PORT: u16 = 19132;

/// Convenience entry point: performs a one-shot RakNet Unconnected Ping.
///
/// Re-exported at the crate root as `mcget::ping_bedrock`.
pub async fn ping<A>(addr: A) -> crate::error::Result<PongResponse>
where
    A: crate::addr::HostAddr,
{
    ping::ping(addr).await
}
