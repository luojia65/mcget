//! Example: open a persistent RakNet session with a Bedrock server, then
//! exercise the lowest-level send/receive methods.
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
//! ## What it does
//!
//! 1. Performs the full 4-packet RakNet handshake
//!    (Request 1 → Reply 1 → Request 2 → Reply 2) via the reqwest-style
//!    `Client::connect()` + `ConnectBuilder` API, returning a live
//!    [`Connection`] that owns the open UDP socket plus the negotiated
//!    parameters (`server_guid`, MTU, encryption flag).
//! 2. Sends one minimal datagram through [`Connection::send_datagram`] and
//!    receives one packet through [`Connection::recv_raw`], to prove the
//!    connected-layer wire format round-trips against a live server.
//!
//! > **Note**: `send_datagram` / `recv_raw` are the **lowest-level** methods.
//! > No sequence numbers are auto-allocated, no ACK is sent for what we
//! > receive, and nothing is retransmitted. The server will therefore treat
//! > our datagram as unacknowledged and eventually time the session out — this
//! > example sends a single datagram, receives a single packet, and exits, just
//! > to demonstrate that the bytes we encode are accepted and that we can
//! > decode the reply.

use std::time::Duration;

use mcget::bedrock::conn::{Datagram, Frame, Incoming, Reliability};
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

    // Send a minimal datagram to exercise the lowest-level send path.
    send_and_receive(&conn).await?;

    // Close the session. This drops the socket; the server will detect the loss
    // via its own keep-alive timeout (no graceful 0x13 Disconnect is sent yet).
    conn.close().await?;
    println!("\n  (session closed)");

    Ok(())
}

/// Prints the negotiated session parameters.
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

/// Sends one datagram and receives one packet, proving the connected-layer
/// wire format round-trips against the live server.
async fn send_and_receive(
    conn: &mcget::bedrock::conn::Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    // Build a minimal datagram: sequence number 0, one Unreliable frame whose
    // body is a placeholder. (A real RakNet client would send a Connected Ping
    // here; the system-message codec is a follow-up, so we just send a tiny
    // Unreliable frame to prove the wire format is accepted by the server.)
    let frame = Frame::new(Reliability::Unreliable, vec![0x00, 0x01, 0x02, 0x03]);
    let datagram = Datagram::new(0, vec![frame])?;

    println!("\n  >> sending datagram (seq=0, 1 unreliable frame)...");
    conn.send_datagram(&datagram).await.map_err(|e| {
        println!("  send FAILED: {e}");
        Box::<dyn std::error::Error>::from(e)
    })?;
    println!("  >> sent ok");

    // Receive a single packet. We expect either an ACK of our datagram or a
    // datagram from the server. Timeout after 5 s — the library's recv_raw does
    // not time out on its own (crate convention).
    println!("\n  << waiting for a packet (5s timeout)...");
    match tokio::time::timeout(Duration::from_secs(5), conn.recv_raw()).await {
        Ok(Ok(incoming)) => print_incoming(&incoming),
        Ok(Err(e)) => {
            println!("  recv FAILED: {e}");
            return Err(e.into());
        }
        Err(_) => println!("  << timed out waiting for a packet"),
    }
    Ok(())
}

/// Prints the decoded incoming packet (datagram / ACK / NACK).
fn print_incoming(incoming: &Incoming) {
    match incoming {
        Incoming::Datagram(dg) => {
            println!(
                "  << Datagram: seq={} frames={}",
                dg.sequence_number(),
                dg.frames().len()
            );
            for (i, frame) in dg.frames().iter().enumerate() {
                println!(
                    "     frame {i}: reliability={:?} body_len={}",
                    frame.reliability(),
                    frame.body().len()
                );
            }
        }
        Incoming::Ack(ack) => {
            println!("  << ACK: {} range(s)", ack.ranges().len());
            for r in ack.ranges() {
                match r.end() {
                    None => println!("     single seq {}", r.start()),
                    Some(end) => println!("     range {}..={}", r.start(), end),
                }
            }
        }
        Incoming::Nack(nack) => {
            println!("  << NACK: {} range(s)", nack.ranges().len());
            for r in nack.ranges() {
                match r.end() {
                    None => println!("     single seq {}", r.start()),
                    Some(end) => println!("     range {}..={}", r.start(), end),
                }
            }
        }
    }
}
