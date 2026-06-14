//! # mcget
//!
//! An async Rust library and CLI tool for querying the status of Minecraft
//! servers, supporting two editions:
//!
//! - **Java Edition** (PC): the TCP-based [Server List Ping][slp] protocol.
//!   See the [`java`] module.
//! - **Bedrock / Pocket Edition**: the UDP-based [RakNet Unconnected Ping][raknet]
//!   protocol. See the [`bedrock`] module.
//!
//! The API follows a reqwest-style `Client` + `RequestBuilder` design.
//!
//! ## Quick start
//!
//! ### Java Edition
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use mcget::java;
//!
//! // Option 1: convenience free function (one-shot query).
//! let status = java::ping(("mc.hypixel.net", 25565)).await?;
//! println!("{} online {}/{}", status.version.name, status.players.online, status.players.max);
//!
//! // Option 2: Client + RequestBuilder (reusable, configurable, can measure latency).
//! let client = java::Client::new();
//! let (status, latency) = client
//!     .ping(("mc.hypixel.net", 25565))?
//!     .with_latency()
//!     .send()
//!     .await?;
//! println!("latency: {:?}", latency);
//! # Ok(())
//! # }
//! ```
//!
//! ### Bedrock Edition
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use mcget::bedrock;
//!
//! let resp = bedrock::ping(("play.nethergames.org", 19132)).await?;
//! println!("{} online {}/{}", resp.version_name, resp.player_count, resp.max_players);
//! # Ok(())
//! # }
//! ```
//!
//! ## Design notes
//!
//! - Fully async, built on [`tokio`].
//! - reqwest-style API: `Client` (reusable) -> `RequestBuilder` (chain config) -> `send()`.
//! - Address arguments accept [`HostAddr`](addr::HostAddr) (e.g. a `"host:port"` string,
//!   a `("host", port)` tuple, or a `SocketAddr`). When a string carries no port the
//!   edition-specific default is filled in (25565 for Java, 19132 for Bedrock); IPv6
//!   bracket form is supported.
//! - No built-in timeout; callers can wrap `send()` with `tokio::time::timeout`.
//! - Errors are unified as [`PingError`], derived via [`thiserror`].
//!
//! [slp]: https://minecraft.wiki/w/Java_Edition_protocol/Server_List_Ping
//! [raknet]: https://wiki.bedrock.dev/servers/raknet

pub mod addr;
pub mod bedrock;
pub mod error;
pub mod java;
pub mod varint;

pub use bedrock::ping as ping_bedrock;
pub use error::{PingError, Result};
pub use java::ping as ping_java;

#[cfg(test)]
mod tests {
    //! Cross-module integration tests (most unit tests live in each module).

    #[test]
    fn public_api_compiles() {
        // Only verifies that re-export paths exist; no runtime side effects.
        let _ = std::any::TypeId::of::<crate::PingError>();
        let _ = std::any::TypeId::of::<crate::java::StatusResponse>();
        let _ = std::any::TypeId::of::<crate::bedrock::PongResponse>();
        let _ = std::any::TypeId::of::<crate::java::Client>();
        let _ = std::any::TypeId::of::<crate::bedrock::Client>();
        // Verify that the convenience ping functions are re-exported at the crate root.
        let _ping_java = crate::ping_java::<&str>;
        let _ping_bedrock = crate::ping_bedrock::<&str>;
    }
}
