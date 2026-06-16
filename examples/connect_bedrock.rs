//! Example: open a persistent RakNet session with a Bedrock server.
//!
//! Run with:
//! ```sh
//! cargo run --example connect_bedrock
//! ```
//!
//! By default it handshakes with `play.easecation.net:19132` (EaseCation, a
//! popular Chinese Bedrock minigame server) and prints the negotiated session
//! parameters. Pass a custom target via command-line args (the Bedrock default
//! port 19132 is filled in when omitted):
//!
//! ```sh
//! cargo run --example connect_bedrock -- play.nethergames.org
//! cargo run --example connect_bedrock -- geo.hivebedrock.network:19132
//! ```
//!
//! This demonstrates the reqwest-style `Client::connect()` + `ConnectBuilder`
//! usage: `client.connect()` seeds a builder with the client's GUID, and
//! `.send(addr)` performs the full 4-packet RakNet handshake
//! (Request 1 → Reply 1 → Request 2 → Reply 2), returning a live [`Connection`]
//! that owns the open UDP socket plus the negotiated session parameters
//! (`server_guid`, MTU, encryption flag).
//!
//! > **Note**: after the handshake the UDP session is established, but the
//! > datagram framing layer (`0x80`–`0x8D`) is not implemented yet, so no
//! > application-layer packets can be sent through the returned `Connection`.
//! > We therefore immediately print the session info and close it.

use std::time::Duration;

use mcget::bedrock::Client;
use mcget::PingError;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Command-line args take priority (the library fills in the Bedrock default
    // port 19132 when omitted); otherwise default to EaseCation.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let target: String = if let Some(host) = args.first() {
        host.clone()
    } else {
        "play.easecation.net".to_string()
    };

    println!("Bedrock RakNet handshake -- connecting to {target}\n");

    // A reusable Client. Configure a non-zero client GUID so the server can
    // distinguish this session from others; both `connect` and `ping` inherit it.
    let client = Client::new().client_guid(0xAD);

    // `client.connect()` returns a `ConnectBuilder` seeded with our GUID; it
    // performs no I/O yet. `.send(addr)` is where DNS resolution and the
    // 4-packet handshake actually happen. Wrap it in `tokio::time::timeout`
    // (the library has no built-in overall timeout for the *whole* call; the
    // builder does enforce one internally, but an outer guard makes the bound
    // explicit and lets us map `Elapsed` to a `PingError`).
    let connect = client
        .connect()
        .timeout(Duration::from_secs(10))
        .send(target.as_str());

    let conn = match tokio::time::timeout(Duration::from_secs(15), connect).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            println!("  FAILED: {e}");
            return Err(e.into());
        }
        Err(_) => {
            let e = PingError::Protocol("connect timed out (15s)".into());
            println!("  FAILED: {e}");
            return Err(e.into());
        }
    };

    // Print the basic connection facts negotiated during the handshake.
    print_connection(&conn);

    // Close the session. This drops the socket; the server will detect the loss
    // via its own keep-alive timeout (no graceful 0x13 Disconnect is sent yet).
    conn.close().await?;
    println!("\n  (session closed)");

    Ok(())
}

fn print_connection(conn: &mcget::bedrock::conn::Connection) {
    println!("  Peer address : {}", conn.peer());
    println!("  Server GUID  : {}", conn.server_guid());
    println!("  Client GUID  : {:#x}", conn.client_guid());
    println!("  MTU          : {} bytes", conn.mtu());
    println!(
        "  Encryption   : {}",
        if conn.use_encryption() {
            "requested"
        } else {
            "off"
        }
    );
}
