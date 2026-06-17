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

    // Phase A: raw send/receive (lowest-level wire format). This is OFF by
    // default because a raw recv does not ACK the server's datagrams, which
    // makes strict servers (NetherGames, …) give up on the session before the
    // online handshake. Set MCGET_PHASE_A=1 to include it for debugging.
    if std::env::var("MCGET_PHASE_A").is_ok() {
        raw_send_and_receive(&conn).await?;
    }

    // Phase B: reliable transport + online handshake.
    // The Connection moves into the ReliableConnection (its socket is taken).
    println!("\n--- Phase B: reliable transport + online handshake ---");
    let reliable = ReliableConnection::new(conn);
    println!(
        "  reliable session up: server_guid={} mtu={}",
        reliable.server_guid(),
        reliable.mtu()
    );

    // Run the online handshake: ConnectionRequest → ConnectionRequestAccepted
    // → NewIncomingConnection. After this the server treats us as a fully
    // connected client and may send application frames.
    println!("\n  >> running online handshake (10s timeout)...");
    match reliable.connect_online(Duration::from_secs(10)).await {
        Ok(()) => println!("  >> online handshake complete"),
        Err(e) => {
            println!("  online handshake FAILED: {e}");
            return Err(e.into());
        }
    }

    // Send a ConnectedPing keep-alive (the recv loop auto-replies Pong to the
    // server's pings).
    println!("\n  >> sending ConnectedPing...");
    reliable.ping().await?;
    println!("  >> sent ok");

    // Phase C: offline Bedrock login (RequestNetworkSettings → Login →
    // PlayStatus). This attempts a real game-layer login. Public servers
    // (EaseCation, NetherGames, …) require encryption and won't reply to an
    // offline login, so this typically times out or reports "server requires
    // encryption". Against a local offline-mode BDS server it reaches
    // PlayStatus(LOGIN_SUCCESS). The protocol version must match the server's.
    println!("\n--- Phase C: offline Bedrock login ---");
    println!("  >> running offline login (protocol 766, 15s timeout)...");
    match reliable.login_offline(766, Duration::from_secs(15)).await {
        Ok(()) => println!("  >> login successful (PlayStatus LOGIN_SUCCESS)"),
        Err(e) => println!("  login result: {e}"),
    }

    // Graceful close: send a Disconnect notification.
    println!("\n  >> sending Disconnect...");
    let _ = reliable.disconnect().await;
    drop(reliable);
    println!("  (session closed)");

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
    conn.send_datagram(&datagram).await.map_err(|e| {
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
