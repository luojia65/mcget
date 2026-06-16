//! `mcget` -- a curl-like command-line tool for querying Minecraft server
//! status.
//!
//! Supports auto-detecting Java vs Bedrock edition, and both human-readable and
//! JSON output.
//!
//! ## Usage examples
//!
//! ```sh
//! # Auto-detect edition
//! mcget mc.hypixel.net
//! mcget play.easecation.net
//!
//! # Force an edition
//! mcget -j mc.hypixel.net
//! mcget -b play.easecation.net
//!
//! # JSON output (for jq pipelines)
//! mcget --json mc.hypixel.net
//!
//! # Measure latency (Java does an extra ping/pong round trip)
//! mcget -t mc.hypixel.net
//!
//! # Multiple targets + timeout
//! mcget --max-time 5 mc.hypixel.net play.cubecraft.net
//! ```
//!
//! ## Internationalization
//!
//! All natural-language output (including `--help`) is translated via the
//! `rust-i18n` crate, with locale files under `locales/`. The active locale is
//! chosen in this order: `--lang <tag>`, then the system locale (via
//! `sys-locale`), falling back to English. Currently `en` and `zh-CN` are
//! bundled.

use std::time::Duration;

use clap::{Arg, ArgAction, Command};
use mcget::bedrock;
use mcget::java;
use mcget::PingError;
use rust_i18n::t;

// Load translations at compile time from the `locales/` directory. Files are
// named `<locale>.yml` (e.g. `en.yml`, `zh-CN.yml`); the top-level key in each
// file is the locale tag.
rust_i18n::i18n!("locales");

/// Default timeout for a single query attempt (seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 6;

fn main() {
    // Build the clap Command with runtime-translated help strings. We do this
    // before parsing so that `--help`/`-h` text and error messages are already
    // localized. A `--lang` flag overrides the locale detection.
    let matches = build_command().get_matches();

    // Apply the chosen locale (explicit `--lang`, else system locale, else en).
    let locale = resolve_locale(matches.get_one::<String>("lang").map(|s| s.as_str()));
    rust_i18n::set_locale(&locale);

    let hosts: Vec<String> = matches
        .get_many::<String>("hosts")
        .map(|v| v.cloned().collect())
        .unwrap_or_default();

    if hosts.is_empty() {
        eprintln!("{}", t!("err_no_target"));
        std::process::exit(2);
    }

    let java_flag = matches.get_flag("java");
    let bedrock_flag = matches.get_flag("bedrock");
    let latency_flag = matches.get_flag("latency");
    let json_flag = matches.get_flag("json");

    let timeout: Duration = Duration::from_secs(
        matches
            .get_one::<String>("max_time")
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECS),
    );

    let exit_code = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create Tokio runtime")
        .block_on(run(
            &hosts,
            java_flag,
            bedrock_flag,
            latency_flag,
            json_flag,
            timeout,
        ));
    std::process::exit(exit_code);
}

/// Builds the clap `Command` with all help strings passed through `t!`, so the
/// `--help` output respects the active locale. The locale is resolved *after*
/// parsing the `--lang` flag; to still localize help on the *first* parse, we
/// detect the system locale up front if `--lang` is not present.
///
/// Because clap resolves help strings eagerly, we read `--lang` from argv first
/// (a light pre-scan), set the locale, then build the command.
fn build_command() -> Command {
    // Pre-scan argv for `--lang <tag>` / `--lang=<tag>` so the help text uses
    // the right locale on this same invocation.
    let pre_lang = pre_scan_lang();
    let locale = resolve_locale(pre_lang.as_deref());
    rust_i18n::set_locale(&locale);

    Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(t!("about").to_string())
        .long_about(t!("long_about").to_string())
        .arg(
            Arg::new("hosts")
                .help(t!("hosts_help").to_string())
                .num_args(1..)
                .value_name("HOST"),
        )
        .arg(
            Arg::new("java")
                .short('j')
                .long("java")
                .help(t!("java_help").to_string())
                .action(ArgAction::SetTrue)
                .conflicts_with("bedrock"),
        )
        .arg(
            Arg::new("bedrock")
                .short('b')
                .long("bedrock")
                .help(t!("bedrock_help").to_string())
                .action(ArgAction::SetTrue)
                .conflicts_with("java"),
        )
        .arg(
            Arg::new("latency")
                .short('t')
                .long("latency")
                .help(t!("latency_help").to_string())
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help(t!("json_help").to_string())
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("max_time")
                .long("max-time")
                .help(t!("max_time_help").to_string())
                .value_name("SECONDS")
                .default_value("6"),
        )
        .arg(
            Arg::new("lang")
                .long("lang")
                .help("Override the display locale (e.g. en, zh-CN).")
                .value_name("LOCALE"),
        )
}

/// A minimal pre-scan of argv for `--lang`/`-l` to decide the locale *before*
/// clap renders help text. Returns `None` when not present.
fn pre_scan_lang() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--lang" {
            return args.next();
        } else if let Some(v) = a.strip_prefix("--lang=") {
            return Some(v.to_string());
        }
    }
    None
}

/// Resolves the active locale tag from (in priority order):
/// 1. an explicit `--lang` value, if it names a bundled locale;
/// 2. the system locale, mapped onto a bundled locale;
/// 3. `"en"` as the ultimate fallback.
fn resolve_locale(explicit: Option<&str>) -> String {
    let bundled = bundled_locales();
    if let Some(tag) = explicit {
        let normalized = normalize_locale_tag(tag);
        if bundled.contains(&normalized.as_str()) {
            return normalized;
        }
        // Try matching the language part alone (e.g. "zh-TW" -> "zh-CN").
        if let Some(lang) = normalized.split('-').next() {
            if let Some(matched) = bundled.iter().find(|b| b.split('-').next() == Some(lang)) {
                return (*matched).to_string();
            }
        }
    }
    // Fall back to the system locale.
    if let Some(sys) = sys_locale::get_locale() {
        let normalized = normalize_locale_tag(&sys);
        if bundled.contains(&normalized.as_str()) {
            return normalized;
        }
        if let Some(lang) = normalized.split('-').next() {
            if let Some(matched) = bundled.iter().find(|b| b.split('-').next() == Some(lang)) {
                return (*matched).to_string();
            }
        }
    }
    "en".to_string()
}

/// Lowercases the language part and uppercases the region subtag
/// (e.g. "zh-cn" / "ZH_cn" -> "zh-CN"), matching our locale file names.
fn normalize_locale_tag(tag: &str) -> String {
    let parts: Vec<&str> = tag.split('-').collect();
    if parts.len() >= 2 {
        format!(
            "{}-{}",
            parts[0].to_ascii_lowercase(),
            parts[1].to_ascii_uppercase()
        )
    } else {
        parts[0].to_ascii_lowercase()
    }
}

/// Returns the locale tags bundled in the `locales/` directory, using
/// `rust_i18n::available_locales!`.
fn bundled_locales() -> Vec<&'static str> {
    rust_i18n::available_locales!().to_vec()
}

/// Spawns queries for all hosts and prints each **success** as soon as it
/// resolves. When a host is queried on two protocols in auto-detect mode, a
/// failure on one protocol is suppressed if the other protocol succeeds; only
/// when every protocol fails for a given host are the failure messages printed.
/// Returns the process exit code (0 = all succeeded, 1 = at least one failed).
async fn run(
    hosts: &[String],
    java_flag: bool,
    bedrock_flag: bool,
    latency_flag: bool,
    json_flag: bool,
    timeout: Duration,
) -> i32 {
    use std::collections::HashMap;
    use std::sync::mpsc;

    /// Per-host bookkeeping while multiple protocol queries are in flight.
    struct Pending {
        /// Number of protocol queries still outstanding for this host.
        remaining: usize,
        /// Whether at least one success has been seen (and printed).
        had_success: bool,
        /// Error strings buffered until we know whether they matter.
        /// Each entry is (edition_label, error_message).
        failures: Vec<(&'static str, String)>,
    }

    // Channel carries (host, edition_label, result). The edition is a static
    // string ("java"/"bedrock") so JSON error objects can declare which protocol
    // failed; it is `""` for unknown.
    let (tx, rx) = mpsc::channel::<(String, &'static str, Result<QueryResult, PingError>)>();
    let mut pending = HashMap::<String, Pending>::new();

    for host in hosts {
        // Register the host *before* spawning, so the receiver loop finds it.
        let count = if java_flag || bedrock_flag { 1 } else { 2 };
        pending.insert(
            host.clone(),
            Pending {
                remaining: count,
                had_success: false,
                failures: Vec::new(),
            },
        );

        if java_flag {
            let tx = tx.clone();
            let host = host.clone();
            tokio::spawn(async move {
                let r = query_java(&host, latency_flag, timeout)
                    .await
                    .map(|(s, l)| QueryResult::Java(s, l));
                let _ = tx.send((host, "java", r));
            });
        } else if bedrock_flag {
            let tx = tx.clone();
            let host = host.clone();
            tokio::spawn(async move {
                let r = query_bedrock(&host, timeout)
                    .await
                    .map(QueryResult::Bedrock);
                let _ = tx.send((host, "bedrock", r));
            });
        } else {
            // Auto-detect: fire both concurrently through separate tasks.
            let host = host.clone(); // move into closures
            let tx1 = tx.clone();
            let h1 = host.clone();
            tokio::spawn(async move {
                let r = query_java(&h1, latency_flag, timeout)
                    .await
                    .map(|(s, l)| QueryResult::Java(s, l));
                let _ = tx1.send((h1, "java", r));
            });
            let tx2 = tx.clone();
            tokio::spawn(async move {
                let r = query_bedrock(&host, timeout)
                    .await
                    .map(QueryResult::Bedrock);
                let _ = tx2.send((host, "bedrock", r));
            });
        }
    }

    // Drop our copy of the sender so the channel closes after all spawned
    // tasks have finished and dropped their senders.
    drop(tx);

    let mut any_failed = false;

    for (host, _edition, result) in rx {
        let state = match pending.get_mut(&host) {
            Some(s) => s,
            None => continue, // should never happen
        };
        state.remaining -= 1;

        match result {
            Ok(res) => {
                // Success – print it immediately and note we had a success so
                // that any buffered failures for this host will be discarded.
                state.had_success = true;
                if json_flag {
                    print_json(&host, &res);
                } else {
                    print_human(&host, &res);
                }
            }
            Err(e) => {
                // Buffer the failure; we decide later whether to show it.
                state.failures.push((_edition, e.to_string()));
            }
        }

        // When the last outstanding query for this host lands, either flush
        // the buffered failures (no success) or discard them (had success).
        if state.remaining == 0 {
            if !state.had_success {
                if json_flag {
                    for (edition, err) in state.failures.drain(..) {
                        print_json_error(&host, edition, &err);
                    }
                } else {
                    for (_, err) in state.failures.drain(..) {
                        eprintln!("{}", t!("failed_header", host = host));
                        eprintln!("  {}", t!("failed", error = err));
                    }
                }
                any_failed = true;
            }
            pending.remove(&host);
        }
    }

    // Any leftover pending entries (shouldn't happen) are hosts whose tasks
    // panicked rather than reporting through the channel. Treat them as failed.
    for (host, state) in pending.drain() {
        if !state.had_success {
            if json_flag {
                print_json_error(&host, "", "task panicked");
            } else {
                eprintln!("{}", t!("failed_header", host = host));
                eprintln!("  {}", t!("err_internal", error = "task panicked"));
            }
            any_failed = true;
        }
    }

    i32::from(any_failed)
}

/// Java Edition query. Returns (StatusResponse, optional latency).
async fn query_java(
    host: &str,
    latency_flag: bool,
    timeout: Duration,
) -> Result<(java::StatusResponse, Option<Duration>), PingError> {
    let client = java::Client::new();
    let pair = tokio::time::timeout(timeout, async {
        if latency_flag {
            let (status, latency) = client.ping(host)?.with_latency().send().await?;
            Ok::<_, PingError>((status, Some(latency)))
        } else {
            let status = client.ping(host)?.send().await?;
            Ok((status, None))
        }
    })
    .await
    .map_err(|_| PingError::Protocol(t!("query_timed_out").to_string()))??;
    Ok(pair)
}

/// Bedrock Edition query. Returns a PongResponse (which already carries latency).
async fn query_bedrock(host: &str, timeout: Duration) -> Result<bedrock::PongResponse, PingError> {
    let client = bedrock::Client::new();
    tokio::time::timeout(timeout, async {
        let resp = client.ping(host)?.send().await?;
        Ok::<_, PingError>(resp)
    })
    .await
    .map_err(|_| PingError::Protocol(t!("query_timed_out").to_string()))?
}

/// Query result carrying the edition, for unified formatting.
enum QueryResult {
    Java(java::StatusResponse, Option<Duration>),
    Bedrock(bedrock::PongResponse),
}

impl QueryResult {
    fn edition_label(&self) -> String {
        match self {
            QueryResult::Java(..) => t!("edition_java").to_string(),
            QueryResult::Bedrock(_) => t!("edition_bedrock").to_string(),
        }
    }
}

/// Human-readable output.
fn print_human(host: &str, res: &QueryResult) {
    let edition = res.edition_label();
    println!("{}", t!("header", host = host, edition = edition));
    match res {
        QueryResult::Java(status, latency) => {
            println!(
                "  {}",
                t!(
                    "version_with_protocol",
                    name = status.version.name,
                    protocol = status.version.protocol
                )
            );
            println!(
                "  {}",
                t!(
                    "players",
                    online = status.players.online,
                    max = status.players.max
                )
            );
            println!(
                "  {}",
                t!("motd", motd = status.description.to_plain_text())
            );
            if let Some(favicon) = &status.favicon {
                println!("  {}", t!("favicon_provided", count = favicon.len()));
            }
            if let Some(secure) = status.enforces_secure_chat {
                println!("  {}", t!("enforces_secure_chat", value = secure));
            }
            if let Some(lat) = latency {
                println!("  {}", t!("latency", latency = format!("{:.1?}", lat)));
            }
        }
        QueryResult::Bedrock(resp) => {
            println!(
                "  {}",
                t!(
                    "version_with_protocol",
                    name = resp.version_name,
                    protocol = resp.protocol_version
                )
            );
            println!(
                "  {}",
                t!(
                    "players",
                    online = resp.player_count,
                    max = resp.max_players
                )
            );
            println!("  {}", t!("edition_label", edition = &resp.edition));
            println!("  {}", t!("motd", motd = &resp.motd));
            if !resp.second_motd.is_empty() {
                println!("  {}", t!("motd2", motd = &resp.second_motd));
            }
            println!(
                "  {}",
                t!(
                    "gamemode",
                    gamemode = &resp.gamemode,
                    numeric = resp.gamemode_numeric
                )
            );
            if resp.port_ipv4 != 0 || resp.port_ipv6 != 0 {
                println!(
                    "  {}",
                    t!("ports", ipv4 = resp.port_ipv4, ipv6 = resp.port_ipv6)
                );
            }
            println!("  {}", t!("server_guid", guid = resp.server_guid));
            println!(
                "  {}",
                t!("latency", latency = format!("{:.1?}", resp.latency))
            );
        }
    }
    println!();
}

/// JSON output. Serializes the response via serde_json, adding edition/host fields.
fn print_json(host: &str, res: &QueryResult) {
    // JSON is machine-readable; keep edition identifiers canonical (English).
    let edition: &str = match res {
        QueryResult::Java(..) => "Java",
        QueryResult::Bedrock(_) => "Bedrock",
    };
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

/// JSON error output — produces a minimal JSON object suitable for machine
/// consumption (same style as [`print_json`]).
fn print_json_error(host: &str, edition: &str, error: &str) {
    let obj = serde_json::json!({
        "host": host,
        "edition": edition,
        "error": error,
    });
    println!("{}", serde_json::to_string(&obj).unwrap_or_default());
}
