//! Example: query popular Java Edition (PC) Minecraft servers.
//!
//! Run with:
//! ```sh
//! cargo run --example ping_java
//! ```
//!
//! By default it queries in parallel:
//! - `mc.hypixel.net:25565` (Hypixel, the largest Java Edition server)
//! - `play.cubecraft.net:25565` (CubeCraft, a popular minigame server)
//!
//! Pass a custom target via command-line args (the Java default port 25565 is
//! filled in when omitted):
//! ```sh
//! cargo run --example ping_java -- mc.hypixel.net
//! cargo run --example ping_java -- play.cubecraft.net:25565
//! ```
//!
//! Demonstrates the reqwest-style `Client` + `RequestBuilder` usage and wrapping
//! `send()` with `tokio::time::timeout`.

use std::time::Duration;

use mcget::java::{Client, StatusResponse};
use mcget::PingError;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Command-line args take priority (the library fills in the Java default
    // port 25565 when omitted); otherwise use the default target list.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let targets: Vec<&str> = if args.is_empty() {
        vec!["mc.hypixel.net:25565", "play.cubecraft.net:25565"]
    } else {
        args.iter().map(String::as_str).collect()
    };

    println!(
        "Java Edition Server List Ping -- querying {} servers\n",
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
            // String form with no port auto-fills 25565.
            // Demonstrate wrapping send() with tokio::time::timeout (the library
            // has no built-in timeout): map Elapsed to PingError, then flatten
            // the nested Result with `?`.
            let result = async {
                let req = client.ping(target.as_str())?.with_latency();
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
            Ok((status, latency)) => print_status(&status, latency),
            Err(e) => println!("  FAILED: {e}"),
        }
        println!();
    }

    Ok(())
}

fn print_status(status: &StatusResponse, latency: Duration) {
    println!(
        "  Version: {} (protocol {})",
        status.version.name, status.version.protocol
    );
    println!(
        "  Players: {}/{}",
        status.players.online, status.players.max
    );
    println!("  MOTD: {}", status.description.to_plain_text());
    if let Some(favicon) = &status.favicon {
        println!("  Favicon: provided ({} chars)", favicon.len());
    }
    if let Some(secure) = status.enforces_secure_chat {
        println!("  Enforces secure chat: {secure}");
    }
    println!("  Latency: {:.1?}", latency);
}
