//! Example: open a persistent RakNet session with a Bedrock server, then
//! exercise the lowest-level send/receive methods AND the reliable transport.
//!
//! Run with:
//! ```sh
//! cargo run --example connect_bedrock
//! ```
//!
//! By default it handshakes with `play.easecation.net:19132` (EaseCation, a
//! popular Chinese Bedrock minigame server). Pass a custom target via
//! command-line args (the Bedrock default port 19132 is filled in when
//! omitted):
//!
//! ```sh
//! cargo run --example connect_bedrock -- play.nethergames.org
//! cargo run --example connect_bedrock -- geo.hivebedrock.network:19132
//! ```
//!
//! ## What it does
//!
//! 1. Performs the full 4-packet RakNet handshake, returning a live
//!    [`Connection`] with the open socket + negotiated parameters.
//! 2. **Phase A — raw send/receive**: one datagram via
//!    [`Connection::send_datagram`] / [`Connection::recv_raw`], proving the
//!    wire format round-trips against a live server.
//! 3. **Phase B — reliable transport**: the [`Connection`] is moved into a
//!    [`ReliableConnection`], which auto-ACKs, retransmits, and delivers
//!    ordered frames. We send a reliable-ordered frame and receive one.

use std::time::Duration;

use mcget::bedrock::conn::{Datagram, Frame, Incoming, Reliability};
use mcget::bedrock::reliable_conn::ReliableConnection;
use mcget::bedrock::Client;
use mcget::PingError;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let target: String = if let Some(host) = args.first() {
        host.clone()
    } else {
        "play.easecation.net".to_string()
    };

    println!("Bedrock RakNet handshake -- connecting to {target}\n");

    let client = Client::new().client_guid(0xAD);
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

    print_connection(&conn);

    // Phase A: raw send/receive (lowest-level wire format).
    raw_send_and_receive(&conn).await?;

    // Phase B: reliable transport (auto-ACK, retransmit, ordered delivery).
    // The Connection moves into the ReliableConnection (its socket is taken).
    println!("\n--- Phase B: reliable transport ---");
    let reliable = ReliableConnection::new(conn);
    println!(
        "  reliable session up: server_guid={} mtu={}",
        reliable.server_guid(),
        reliable.mtu()
    );

    // Send a reliable-ordered frame. The reliability layer assigns sequence
    // numbers / indices, encapsulates, and will retransmit until ACKed.
    println!("\n  >> sending reliable-ordered frame...");
    reliable
        .send(Reliability::ReliableOrdered, vec![0x00; 4])
        .await?;
    println!("  >> sent ok");

    // Receive one application frame (the engine ACKs the server's datagrams,
    // reassembles fragments, and delivers ordered frames in order).
    println!("\n  << waiting for a reliable frame (5s timeout)...");
    match tokio::time::timeout(Duration::from_secs(5), reliable.recv()).await {
        Ok(Ok(frame)) => {
            println!(
                "  << frame: reliability={:?} body_len={}",
                frame.reliability(),
                frame.body().len()
            );
        }
        Ok(Err(e)) => {
            println!("  recv FAILED: {e}");
            return Err(e.into());
        }
        Err(_) => println!("  << timed out waiting for a reliable frame"),
    }

    // Dropping the ReliableConnection aborts the background tick task and
    // closes the socket (no graceful 0x13 Disconnect yet).
    drop(reliable);
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

/// Phase A: one raw datagram send + one raw packet receive.
async fn raw_send_and_receive(
    conn: &mcget::bedrock::conn::Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n--- Phase A: raw send/receive ---");
    let frame = Frame::new(Reliability::Unreliable, vec![0x00, 0x01, 0x02, 0x03]);
    let datagram = Datagram::new(0, vec![frame])?;

    println!("  >> sending datagram (seq=0, 1 unreliable frame)...");
    conn.send_datagram(&datagram)
        .await
        .map_err(|e| {
            println!("  send FAILED: {e}");
            Box::<dyn std::error::Error>::from(e)
        })?;
    println!("  >> sent ok");

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

/// Prints a classified incoming packet.
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
