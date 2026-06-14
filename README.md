# mcping

[中文](README_zh.md)

A Rust library and command-line tool for querying the status of [Minecraft][mc] servers, supporting both **Java Edition (PC)** and **Bedrock / Pocket Edition (PE)**.

- **Java Edition**: the TCP-based [Server List Ping (SLP)][slp] protocol, default port `25565`.
- **Bedrock Edition**: the UDP-based [RakNet Unconnected Ping][raknet] protocol, default port `19132`.

`mcping` is both a dependable **async Rust library** (using a reqwest-style `Client` + `RequestBuilder` design) and a `curl`-like **command-line tool** that lets players check server status in one line.

---

## Command-line tool

### Install

```sh
cargo install mcping
```

Or build from source:

```sh
git clone https://github.com/lojia/mcping
cd mcping
cargo build --release
# binary at target/release/mcping
```

### Usage

```sh
# Auto-detect edition (try Java first, then Bedrock on failure)
mcping mc.hypixel.net
mcping play.easecation.net

# Force an edition
mcping -j mc.hypixel.net          # Java Edition
mcping -b play.easecation.net     # Bedrock Edition

# Measure and show latency (Java does an extra ping/pong round trip)
mcping -t mc.hypixel.net

# JSON output (for jq pipelines)
mcping --json mc.hypixel.net | jq '.players.online'

# Multiple targets
mcping mc.hypixel.net play.cubecraft.net play.easecation.net

# Timeout control (seconds)
mcping --max-time 5 mc.hypixel.net

# Full help
mcping --help
```

### Output example

Human-readable (default):

```
--- mc.hypixel.net (Java) ---
  Version: Requires MC 1.8 / 1.21 (protocol 47)
  Players: 31496/200000
  MOTD: §aHypixel Network [1.8/26.1]
  Favicon: provided (15738 chars)
  Latency: 198.5ms
```

JSON (`--json`):

```json
{
  "edition": "Java",
  "host": "mc.hypixel.net",
  "version": { "name": "Requires MC 1.8 / 1.21", "protocol": 47 },
  "players": { "max": 200000, "online": 31496 }
}
```

---

## As a library

`mcping` uses a reqwest-style `Client` + `RequestBuilder` design; fully async, built on [`tokio`][tokio].
**The library has no built-in timeout** -- callers compose one with `tokio::time::timeout`.

### Java Edition

```rust
use mcping::java;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Option 1: convenience free function (one-shot query).
    let status = java::ping(("mc.hypixel.net", 25565)).await?;
    println!("{} online {}/{}", status.version.name, status.players.online, status.players.max);

    // Option 2: Client + RequestBuilder (reusable, configurable, latency measurement).
    let client = java::Client::new();
    let (status, latency) = client
        .ping(("mc.hypixel.net", 25565))?
        .with_latency()
        .send()
        .await?;
    println!("latency: {:?}", latency);
    Ok(())
}
```

### Bedrock Edition

```rust
use mcping::bedrock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = bedrock::Client::new();
    let resp = client.ping(("play.nethergames.org", 19132))?.send().await?;
    println!("{} online {}/{}", resp.version_name, resp.player_count, resp.max_players);
    Ok(())
}
```

### Composing your own timeout

```rust
use std::time::Duration;
use mcping::java::Client;
use mcping::PingError;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::new();
let status = tokio::time::timeout(
    Duration::from_secs(5),
    client.ping(("mc.hypixel.net", 25565))?.send(),
).await
 .map_err(|_| PingError::Protocol("timed out".into()))??;
# Ok(())
# }
```

### Run the examples

```sh
cargo run --example ping_java
cargo run --example ping_bedrock
```

---

## API overview

The library uses a reqwest-style three-layer structure:

| Layer | Java | Bedrock | Description |
|-------|------|---------|-------------|
| `Client` | `java::Client` | `bedrock::Client` | Reusable client, created with `new()` |
| `RequestBuilder` | `java::RequestBuilder` / `LatencyRequestBuilder` | `bedrock::RequestBuilder` | Chain config, `send()` issues the request |
| Convenience fn | `ping_java(addr)` | `ping_bedrock(addr)` | One-shot query |

Address arguments accept [`HostAddr`](addr::HostAddr) (e.g. a `"host:port"` string, a `("host", port)` tuple, or a `SocketAddr`).
When a string carries no port the edition-specific default is filled in (25565 for Java, 19132 for Bedrock); IPv6 bracket form is supported.

---

## Design notes

- **reqwest style**: `Client` (reusable, zero-cost clone) -> `RequestBuilder` (chain config) -> `send()` (future).
- **`HostAddr` generic**: `Client::ping<A: HostAddr>(addr: A)`. DNS resolution happens synchronously at the `ping()` call (on failure `PingError::Io` is returned).
- **No built-in timeout**: the library does not manage timeouts; callers compose one with `tokio::time::timeout`.
- **Single error type**: all errors are unified as `PingError` (`Io` / `Json` / `Protocol`), derived via `thiserror`.

---

## Protocol details

### Java Edition Server List Ping (TCP)

Each packet is prefixed with a VarInt length; the handshake protocol version is `-1` (any). Flow: Handshake(0x00) -> Status Request(0x00) -> Status Response(JSON) -> optional Ping/Pong for latency.

`description` supports both a plain string and the `{"text": ..., "extra": [...]}` object form.

### Bedrock Edition RakNet Unconnected Ping (UDP)

Fixed magic `00 ff ff 00 fe fe fe fe fd fd fd fd 12 34 56 78`. The `server_id_string` is semicolon-separated with the official standard field order:

```
edition;motd1;protocolVersion;versionName;playerCount;maxPlayers;
        serverUniqueId;motd2;gamemode;gamemodeNumeric;portIpv4;portIpv6
```

---

## Running tests

```sh
cargo test
```

---

## License

MIT or Apache-2.0, at your option.

## References

- [Java Edition protocol / Server List Ping][slp]
- [Bedrock Wiki -- RakNet Protocol][raknet]
- [Minecraft Wiki -- RakNet](https://minecraft.wiki/w/RakNet)

[mc]: https://www.minecraft.net/
[slp]: https://minecraft.wiki/w/Java_Edition_protocol/Server_List_Ping
[raknet]: https://wiki.bedrock.dev/servers/raknet
[tokio]: https://tokio.rs/
