//! Example: query popular Bedrock / Pocket Edition Minecraft servers.
//!
//! Run with:
//! ```sh
//! cargo run --example ping_bedrock
//! ```
//!
//! By default it queries in parallel:
//! - `play.nethergames.org:19132` (NetherGames, a popular Bedrock minigame server)
//! - `geo.hivebedrock.network:19132` (The Hive, a popular Bedrock minigame server)
//! - `play.easecation.net:19132` (EaseCation, a popular Chinese Bedrock minigame server)
//!
//! Pass a custom target via command-line args (the Bedrock default port 19132 is
//! filled in when omitted):
//! ```sh
//! cargo run --example ping_bedrock -- play.nethergames.org
//! cargo run --example ping_bedrock -- play.easecation.net:19132
//! ```
//!
//! Demonstrates the reqwest-style `Client` + `RequestBuilder` usage and wrapping
//! `send()` with `tokio::time::timeout`.

use std::time::Duration;

use mcping::bedrock::{Client, PongResponse};
use mcping::PingError;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Command-line args take priority (the library fills in the Bedrock default
    // port 19132 when omitted); otherwise use the default target list.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let targets: Vec<&str> = if args.is_empty() {
        vec![
            "play.nethergames.org:19132",
            "geo.hivebedrock.network:19132",
            // If the port is 19132 (the Bedrock default), it can be omitted;
            // the library fills it in automatically.
            "play.easecation.net",
        ]
    } else {
        args.iter().map(String::as_str).collect()
    };

    println!(
        "Bedrock RakNet Unconnected Ping -- querying {} servers\n",
        targets.len()
    );

    // Reuse a single Client.
    let client = Client::new();

    // Query all targets in parallel: one tokio task per target.
    let mut handles = Vec::new();
    for &target in &targets {
        let client = client.clone();
        // spawn requires 'static; convert to an owned String here.
        let target = target.to_string();
        let handle = tokio::spawn(async move {
            // String form with no port auto-fills 19132.
            // Demonstrate wrapping send() with tokio::time::timeout (the library
            // has no built-in timeout): map Elapsed to PingError, then flatten
            // the nested Result with `?`.
            let result = async {
                let req = client.ping(target.as_str())?;
                tokio::time::timeout(Duration::from_secs(6), req.send())
                    .await
                    .map_err(|_| PingError::Protocol("query timed out (6s)".into()))?
            }
            .await;
            (target, result)
        });
        handles.push(handle);
    }

    for handle in handles {
        let (target, result) = handle.await?;
        println!("--- {target} ---");
        match result {
            Ok(resp) => print_response(&resp),
            Err(e) => println!("  FAILED: {e}"),
        }
        println!();
    }

    Ok(())
}

fn print_response(resp: &PongResponse) {
    println!(
        "  Version: {} (protocol {})",
        resp.version_name, resp.protocol_version
    );
    println!("  Players: {}/{}", resp.player_count, resp.max_players);
    println!("  Edition: {}", resp.edition);
    println!("  MOTD: {}", resp.motd);
    if !resp.second_motd.is_empty() {
        println!("  MOTD2: {}", resp.second_motd);
    }
    println!("  Gamemode: {} ({})", resp.gamemode, resp.gamemode_numeric);
    if resp.port_ipv4 != 0 || resp.port_ipv6 != 0 {
        println!("  Ports: IPv4={}, IPv6={}", resp.port_ipv4, resp.port_ipv6);
    }
    println!("  Server GUID: {}", resp.server_guid);
    println!("  Latency: {:.1?}", resp.latency);
}
