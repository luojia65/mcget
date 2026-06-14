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
use mcping::bedrock;
use mcping::java;
use mcping::PingError;
use rust_i18n::t;

// Load translations at compile time from the `locales/` directory. Files are
// named `<locale>.yml` (e.g. `en.yml`, `zh-CN.yml`); the top-level key in each
// file is the locale tag.
rust_i18n::i18n!("locales");

/// Timeout for a single query attempt.
/// Auto-detect races Java and Bedrock concurrently, so the worst-case total
/// for any host is QUERY_TIMEOUT (not twice it).
const QUERY_TIMEOUT: Duration = Duration::from_secs(6);

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

    // max_time is accepted but per-attempt timeouts are fixed at QUERY_TIMEOUT
    // (see its docs). A future version can wire max_time through.
    let _max_time: u64 = matches
        .get_one::<String>("max_time")
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);

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
            if let Some(matched) = bundled
                .iter()
                .find(|b| b.split('-').next() == Some(lang))
            {
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
            if let Some(matched) = bundled
                .iter()
                .find(|b| b.split('-').next() == Some(lang))
            {
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

/// Queries all targets in parallel. Returns the process exit code
/// (0 = all succeeded, 1 = at least one failed).
async fn run(
    hosts: &[String],
    java_flag: bool,
    bedrock_flag: bool,
    latency_flag: bool,
    json_flag: bool,
) -> i32 {
    let mut handles = Vec::new();
    for host in hosts {
        let host = host.clone();
        let handle = tokio::spawn(async move {
            let result =
                query_one(&host, java_flag, bedrock_flag, latency_flag).await;
            (host, result)
        });
        handles.push(handle);
    }

    let mut any_failed = false;
    for handle in handles {
        let (host, result) = match handle.await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("{}", t!("err_internal", error = e));
                any_failed = true;
                continue;
            }
        };
        match result {
            Ok(results) => {
                for res in results {
                    if json_flag {
                        print_json(&host, &res);
                    } else {
                        print_human(&host, &res);
                    }
                }
            }
            Err(e) => {
                eprintln!("{}", t!("failed_header", host = host));
                eprintln!("  {}", t!("failed", error = e));
                any_failed = true;
            }
        }
    }

    i32::from(any_failed)
}

/// Queries a single target. The java/bedrock flags decide the edition, or auto-detect.
///
/// On auto-detect: Java and Bedrock are queried concurrently (each with its own
/// QUERY_TIMEOUT), so the worst-case total is QUERY_TIMEOUT rather than twice it.
/// If the host answers on both protocols, both results are returned and printed
/// as if they were separate servers.
async fn query_one(
    host: &str,
    java_flag: bool,
    bedrock_flag: bool,
    latency_flag: bool,
) -> Result<Vec<QueryResult>, PingError> {
    if java_flag {
        let (s, l) = query_java(host, latency_flag).await?;
        Ok(vec![QueryResult::Java(s, l)])
    } else if bedrock_flag {
        let r = query_bedrock(host).await?;
        Ok(vec![QueryResult::Bedrock(r)])
    } else {
        // Auto-detect: race both protocols at once instead of trying them in
        // sequence. Whichever answers wins; a dual-protocol host yields both.
        let (java_res, bed_res) =
            tokio::join!(query_java(host, latency_flag), query_bedrock(host));

        let mut results = Vec::new();
        // Fully consume each Result via match so the borrow checker is happy
        // and we capture the error string for the both-failed report below.
        let java_err = match java_res {
            Ok((s, l)) => {
                results.push(QueryResult::Java(s, l));
                None
            }
            Err(e) => Some(e.to_string()),
        };
        let bed_err = match bed_res {
            Ok(r) => {
                results.push(QueryResult::Bedrock(r));
                None
            }
            Err(e) => Some(e.to_string()),
        };

        if results.is_empty() {
            // Both failed: report both reasons so the user can tell why.
            let java_err = java_err.unwrap_or_else(|| "unknown".into());
            let bed_err = bed_err.unwrap_or_else(|| "unknown".into());
            return Err(PingError::Protocol(t!(
                "java_query_failed",
                java_err = java_err,
                bed_err = bed_err
            )
            .to_string()));
        }
        Ok(results)
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
    .map_err(|_| PingError::Protocol(t!("query_timed_out").to_string()))??;
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
                println!(
                    "  {}",
                    t!("favicon_provided", count = favicon.len())
                );
            }
            if let Some(secure) = status.enforces_secure_chat {
                println!(
                    "  {}",
                    t!("enforces_secure_chat", value = secure)
                );
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
            println!(
                "  {}",
                t!("edition_label", edition = &resp.edition)
            );
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
                    t!(
                        "ports",
                        ipv4 = resp.port_ipv4,
                        ipv6 = resp.port_ipv6
                    )
                );
            }
            println!(
                "  {}",
                t!("server_guid", guid = resp.server_guid)
            );
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
