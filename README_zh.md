# mcget

[English](README.md)

一个用于查询 [Minecraft][mc] 服务器状态的 Rust 库与命令行工具，同时支持 **Java 版（PC 版）** 与 **Bedrock / Pocket Edition（PE 版）**。

- **Java 版**：基于 TCP 的 [Server List Ping (SLP)][slp] 协议，默认端口 `25565`。
- **Bedrock 版**：基于 UDP 的 [RakNet Unconnected Ping][raknet] 协议，默认端口 `19132`。

`mcget` 既是可依赖的 **异步 Rust 库**（采用 reqwest 风格的 `Client` + `RequestBuilder` 设计），也是一个类 `curl` 的 **命令行工具**，让玩家一行命令查服务器状态。

---

## 命令行工具

### 安装

```sh
cargo install mcget
```

或从源码构建：

```sh
git clone https://github.com/lojia/mcget
cd mcget
cargo build --release
# 二进制在 target/release/mcget
```

### 用法

```sh
# 自动探测版本（先试 Java，失败再试 Bedrock）
mcget mc.hypixel.net
mcget play.easecation.net

# 强制版本
mcget -j mc.hypixel.net          # Java 版
mcget -b play.easecation.net     # Bedrock 版

# 测量并显示延迟（Java 版额外 ping/pong 往返）
mcget -t mc.hypixel.net

# JSON 输出（方便 jq 管道）
mcget --json mc.hypixel.net | jq '.players.online'

# 多目标
mcget mc.hypixel.net play.cubecraft.net play.easecation.net

# 超时控制（秒）
mcget --max-time 5 mc.hypixel.net

# 完整帮助
mcget --help
```

### 输出示例

人类可读（默认）：

```
━━━ mc.hypixel.net (Java) ━━━
  版本: Requires MC 1.8 / 1.21 (协议 47)
  玩家: 31496/200000
  MOTD: §aHypixel Network [1.8/26.1]
  图标: 已提供 (15738 字符)
  延迟: 198.5ms
```

JSON（`--json`）：

```json
{
  "edition": "Java",
  "host": "mc.hypixel.net",
  "version": { "name": "Requires MC 1.8 / 1.21", "protocol": 47 },
  "players": { "max": 200000, "online": 31496 }
}
```

---

## 作为库使用

`mcget` 采用 reqwest 风格的 `Client` + `RequestBuilder` 设计；全异步，基于 [`tokio`][tokio]。
**库本身不内置超时**——调用方用 `tokio::time::timeout` 自行组合。

### Java 版

```rust
use mcget::java;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 方式一：便捷自由函数（一次性查询）。
    let status = java::ping(("mc.hypixel.net", 25565)).await?;
    println!("{} 在线 {}/{}", status.version.name, status.players.online, status.players.max);

    // 方式二：Client + RequestBuilder（可复用、可配置、可测延迟）。
    let client = java::Client::new();
    let (status, latency) = client
        .ping(("mc.hypixel.net", 25565))?
        .with_latency()
        .send()
        .await?;
    println!("延迟: {:?}", latency);
    Ok(())
}
```

### Bedrock 版

```rust
use mcget::bedrock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = bedrock::Client::new();
    let resp = client.ping(("play.nethergames.org", 19132))?.send().await?;
    println!("{} 在线 {}/{}", resp.version_name, resp.player_count, resp.max_players);
    Ok(())
}
```

### 自行组合超时

```rust
use std::time::Duration;
use mcget::java::Client;
use mcget::PingError;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::new();
let status = tokio::time::timeout(
    Duration::from_secs(5),
    client.ping(("mc.hypixel.net", 25565))?.send(),
).await
 .map_err(|_| PingError::Protocol("超时".into()))??;
# Ok(())
# }
```

### 运行示例

```sh
cargo run --example ping_java
cargo run --example ping_bedrock
```

---

## API 一览

库采用 reqwest 风格的三层结构：

| 层级 | Java | Bedrock | 说明 |
|------|------|---------|------|
| `Client` | `java::Client` | `bedrock::Client` | 可复用客户端，`new()` 创建 |
| `RequestBuilder` | `java::RequestBuilder` / `LatencyRequestBuilder` | `bedrock::RequestBuilder` | 链式配置，`send()` 发起请求 |
| 便捷函数 | `ping_java(addr)` | `ping_bedrock(addr)` | 一次性查询 |

地址参数接受 [`HostAddr`](addr::HostAddr)（如 `"host:port"` 字符串、`("host", port)` 元组、`SocketAddr`），
字符串无端口时补各版本默认端口（Java 版 25565，Bedrock 版 19132），支持 IPv6 方括号格式。

---

## 设计说明

- **reqwest 风格**：`Client`（可复用、零成本 clone）→ `RequestBuilder`（链式配置）→ `send()`（future）。
- **`HostAddr` 泛型**：`Client::ping<A: HostAddr>(addr: A)`，DNS 解析在 `ping()` 调用时同步完成（失败返回 `PingError::Io`）。
- **不内置超时**：库本身不管理超时，调用方用 `tokio::time::timeout` 自行组合。
- **单一错误类型**：所有错误统一为 `PingError`（`Io` / `Json` / `Protocol`），通过 `thiserror` 派生。

---

## 协议细节

### Java 版 Server List Ping（TCP）

每个包都以 VarInt 长度前缀；握手协议号用 `-1`（任意版本）。流程：Handshake(0x00) → Status Request(0x00) → Status Response(JSON) → 可选 Ping/Pong 测延迟。

`description` 兼容纯字符串与 `{"text": ..., "extra": [...]}` 两种历史格式。

### Bedrock 版 RakNet Unconnected Ping（UDP）

固定 magic `00 ff ff 00 fe fe fe fe fd fd fd fd 12 34 56 78`。`server_id_string` 以分号分隔，官方标准字段顺序：

```
edition;motd1;protocolVersion;versionName;playerCount;maxPlayers;
        serverUniqueId;motd2;gamemode;gamemodeNumeric;portIpv4;portIpv6
```

---

## 运行测试

```sh
cargo test
```

---

## 许可证

MIT 或 Apache-2.0，任选其一。

## 参考

- [Java Edition protocol / Server List Ping][slp]
- [Bedrock Wiki — RakNet Protocol][raknet]
- [Minecraft Wiki — RakNet](https://minecraft.wiki/w/RakNet)

[mc]: https://www.minecraft.net/
[slp]: https://minecraft.wiki/w/Java_Edition_protocol/Server_List_Ping
[raknet]: https://wiki.bedrock.dev/servers/raknet
[tokio]: https://tokio.rs/
