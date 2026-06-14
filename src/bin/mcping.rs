//! `mcping` -- a curl-like command-line tool for querying Minecraft server
//! status.
//!
//! Supports auto-detecting Java vs Bedrock edition, and both human-readable and
//! JSON output.
//!
//! ## Usage examples
//!
//! ```sh
//! # Auto-detect edition
//! mcping mc.hypixel.net
//! mcping play.easecation.net
//!
//! # Force an edition
//! mcping -j mc.hypixel.net
//! mcping -b play.easecation.net
//!
//! # JSON output (for jq pipelines)
//! mcping --json mc.hypixel.net
//!
//! # Measure latency (Java does an extra ping/pong round trip)
//! mcping -t mc.hypixel.net
//!
//! # Multiple targets + timeout
//! mcping --max-time 5 mc.hypixel.net play.cubecraft.net
//! ```

use std::time::Duration;

use clap::Parser;
use mcping::bedrock;
use mcping::java;
use mcping::PingError;

/// A curl-like Minecraft server status query tool.
///
/// Auto-detects Java vs Bedrock edition; supports human-readable and JSON output.
#[derive(Parser, Debug)]
#[command(name = "mcping", version, about, long_about = None)]
struct Cli {
    /// Target address(es), e.g. mc.hypixel.net or play.easecation.net:19132.
    ///
    /// When no port is given: Java fills in 25565, Bedrock fills in 19132.
    hosts: Vec<String>,

    /// Force querying as Java Edition.
    #[arg(short = 'j', long, conflicts_with = "bedrock")]
    java: bool,

    /// Force querying as Bedrock Edition.
    #[arg(short = 'b', long, conflicts_with = "java")]
    bedrock: bool,

    /// Measure and show latency (Java does an extra ping/pong round trip).
    #[arg(short = 't', long)]
    latency: bool,

    /// Output as JSON (for jq and similar pipelines).
    #[arg(long)]
    json: bool,

    /// Maximum timeout (in seconds) for a single query.
    #[arg(long, default_value_t = 6)]
    max_time: u64,
}

/// Query result carrying the edition, for unified formatting.
enum QueryResult {
    Java(java::StatusResponse, Option<Duration>),
    Bedrock(bedrock::PongResponse),
}

impl QueryResult {
    fn edition_label(&self) -> &'static str {
        match self {
            QueryResult::Java(..) => "Java",
            QueryResult::Bedrock(_) => "Bedrock",
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.hosts.is_empty() {
        eprintln!("Error: at least one target address is required. Use --help for usage.");
        std::process::exit(2);
    }

    // Note: cli.max_time is accepted but per-attempt timeouts are fixed at
    // QUERY_TIMEOUT below (see its docs). This keeps the CLI simple; a future
    // version can wire max_time through.
    let _ = cli.max_time;
    let exit_code = run(&cli).await;
    std::process::exit(exit_code);
}

/// Queries all targets in parallel. Returns the process exit code
/// (0 = all succeeded, 1 = at least one failed).
async fn run(cli: &Cli) -> i32 {
    let mut handles = Vec::new();
    for host in &cli.hosts {
        let host = host.clone();
        let java_flag = cli.java;
        let bedrock_flag = cli.bedrock;
        let latency_flag = cli.latency;
        let handle = tokio::spawn(async move {
            let result = query_one(&host, java_flag, bedrock_flag, latency_flag).await;
            (host, result)
        });
        handles.push(handle);
    }

    let mut any_failed = false;
    for handle in handles {
        let (host, result) = match handle.await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("Internal error: {e}");
                any_failed = true;
                continue;
            }
        };
        match result {
            Ok(res) => {
                if cli.json {
                    print_json(&host, &res);
                } else {
                    print_human(&host, &res);
                }
            }
            Err(e) => {
                eprintln!("--- {host} ---");
                eprintln!("  FAILED: {e}");
                any_failed = true;
            }
        }
    }

    i32::from(any_failed)
}

/// Queries a single target. The java/bedrock flags decide the edition, or auto-detect.
///
/// On auto-detect: Java is tried first (timed out by QUERY_TIMEOUT); on failure
/// Bedrock is tried (same QUERY_TIMEOUT), so the worst case is 2 * QUERY_TIMEOUT.
/// Each attempt has its own independent timeout.
async fn query_one(
    host: &str,
    java_flag: bool,
    bedrock_flag: bool,
    latency_flag: bool,
) -> Result<QueryResult, PingError> {
    if java_flag {
        query_java(host, latency_flag)
            .await
            .map(|(s, l)| QueryResult::Java(s, l))
    } else if bedrock_flag {
        query_bedrock(host).await.map(QueryResult::Bedrock)
    } else {
        // Auto-detect: Java first, then Bedrock.
        match query_java(host, latency_flag).await {
            Ok((s, l)) => Ok(QueryResult::Java(s, l)),
            Err(_) => query_bedrock(host).await.map(QueryResult::Bedrock),
        }
    }
}

/// Java Edition query. Returns (StatusResponse, optional latency).
async fn query_java(
    host: &str,
    latency_flag: bool,
) -> Result<(java::StatusResponse, Option<Duration>), PingError> {
    let client = java::Client::new();
    // Wrap with tokio::time::timeout (the library has no built-in timeout).
    let pair = tokio::time::timeout(QUERY_TIMEOUT, async {
        if latency_flag {
            let (status, latency) = client.ping(host)?.with_latency().send().await?;
            Ok::<_, PingError>((status, Some(latency)))
        } else {
            let status = client.ping(host)?.send().await?;
            Ok((status, None))
        }
    })
    .await
    .map_err(|_| PingError::Protocol("query timed out".into()))??;
    Ok(pair)
}

/// Bedrock Edition query. Returns a PongResponse (which already carries latency).
async fn query_bedrock(host: &str) -> Result<bedrock::PongResponse, PingError> {
    let client = bedrock::Client::new();
    tokio::time::timeout(QUERY_TIMEOUT, async {
        let resp = client.ping(host)?.send().await?;
        Ok::<_, PingError>(resp)
    })
    .await
    .map_err(|_| PingError::Protocol("query timed out".into()))?
}

/// Timeout for a single query attempt (non-auto-detect).
/// On auto-detect the total can be up to twice this (Java fails, then Bedrock).
const QUERY_TIMEOUT: Duration = Duration::from_secs(6);

/// Human-readable output.
fn print_human(host: &str, res: &QueryResult) {
    let edition = res.edition_label();
    println!("--- {host} ({edition}) ---");
    match res {
        QueryResult::Java(status, latency) => {
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
            if let Some(lat) = latency {
                println!("  Latency: {:.1?}", lat);
            }
        }
        QueryResult::Bedrock(resp) => {
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
    }
    println!();
}

/// JSON output. Serializes the response via serde_json, adding edition/host fields.
fn print_json(host: &str, res: &QueryResult) {
    let edition = res.edition_label();
    match res {
        QueryResult::Java(status, latency) => {
            let mut obj = serde_json::to_value(status).unwrap_or(serde_json::Value::Null);
            if let Some(map) = obj.as_object_mut() {
                map.insert("edition".into(), serde_json::json!(edition));
                map.insert("host".into(), serde_json::json!(host));
                if let Some(lat) = latency {
                    map.insert(
                        "latency_ms".into(),
                        serde_json::json!(lat.as_millis() as u64),
                    );
                }
            }
            println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
        }
        QueryResult::Bedrock(resp) => {
            let mut obj = serde_json::to_value(resp).unwrap_or(serde_json::Value::Null);
            if let Some(map) = obj.as_object_mut() {
                map.insert("edition".into(), serde_json::json!(edition));
                map.insert("host".into(), serde_json::json!(host));
            }
            println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
        }
    }
}
