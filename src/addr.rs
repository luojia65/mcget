//! Minecraft server address parsing.
//!
//! Provides the [`HostAddr`] trait, which extends [`ToSocketAddrs`] with:
//! - **Default port**: when a string form has no port, a specified default is
//!   filled in (25565 for Java Edition, 19132 for Bedrock Edition).
//! - **IPv6 bracket form**: correctly parses `[::1]:25565`, `[::1]`, avoiding
//!   colon ambiguity.
//! - **Handshake host extraction**: [`HostAddr::host_string`] returns the
//!   string to use in the handshake packet's Server Address field (the host
//!   part, without the port).
//!
//! ## IPv6 format note
//!
//! Minecraft (and [RFC 3986][rfc]) requires an IPv6 address carrying a port to
//! be wrapped in brackets, e.g. `[2001:db8::1]:25565`. Otherwise a string like
//! `::1:8080` cannot be distinguished from a bare IPv6 address. This module
//! follows that convention: a bare IPv6 (no brackets) is treated as having no
//! port.
//!
//! [rfc]: https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

/// A type that can provide a "handshake host string" and be resolved to socket
/// addresses.
///
/// It is compatible with [`ToSocketAddrs`] (used for TCP/UDP connections) while
/// also supporting default-port filling when a string carries no port
/// ([`HostAddr::to_socket_addrs_with_default`]), and exposing the string to use
/// in the handshake packet's Server Address field ([`HostAddr::host_string`]).
///
/// For `(&str, u16)` / `(String, u16)` the original domain is preserved; for
/// plain string forms the [`parse_host_port`] rules are applied; for
/// [`SocketAddr`] the IP string is used. This is necessary so that servers like
/// Hypixel, which route by domain name (virtual hosting), respond correctly.
///
/// # Examples
///
/// ```
/// use mcget::addr::HostAddr;
///
/// // Tuple form: preserves the original domain.
/// let addr = ("mc.hypixel.net", 25565);
/// assert_eq!(addr.host_string(), "mc.hypixel.net");
///
/// // String form without a port: the default port is filled in.
/// let s = "mc.hypixel.net";
/// assert_eq!(s.host_string(), "mc.hypixel.net");
/// let addrs = s.to_socket_addrs_with_default(25565).unwrap();
/// assert!(addrs.iter().all(|a| a.port() == 25565));
///
/// // String form with a port: the given port is preserved.
/// let s = "play.cubecraft.net:25565";
/// let addrs = s.to_socket_addrs_with_default(25565).unwrap();
/// assert!(addrs.iter().all(|a| a.port() == 25565));
/// ```
pub trait HostAddr {
    /// Resolves to a list of socket addresses. `default_port` is used to fill
    /// in a missing port for string forms.
    ///
    /// DNS resolution happens here (synchronously, blocking); on failure an
    /// [`io::Error`] is returned.
    fn to_socket_addrs_with_default(&self, default_port: u16) -> io::Result<Vec<SocketAddr>>;

    /// The string to use in the handshake packet's Server Address field (the
    /// host part, without the port).
    fn host_string(&self) -> String;
}

impl HostAddr for (&str, u16) {
    fn to_socket_addrs_with_default(&self, _default_port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(self.to_socket_addrs()?.collect())
    }
    fn host_string(&self) -> String {
        self.0.to_string()
    }
}

impl HostAddr for (String, u16) {
    fn to_socket_addrs_with_default(&self, _default_port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(self.to_socket_addrs()?.collect())
    }
    fn host_string(&self) -> String {
        self.0.clone()
    }
}

impl HostAddr for str {
    fn to_socket_addrs_with_default(&self, default_port: u16) -> io::Result<Vec<SocketAddr>> {
        let (host, port) = parse_host_port(self, default_port);
        Ok((host.as_str(), port).to_socket_addrs()?.collect())
    }
    fn host_string(&self) -> String {
        let (host, _port) = parse_host_port(self, 0);
        // Strip IPv6 brackets so the handshake carries a bare address.
        host.trim_matches(|c| c == '[' || c == ']').to_string()
    }
}

impl HostAddr for &str {
    fn to_socket_addrs_with_default(&self, default_port: u16) -> io::Result<Vec<SocketAddr>> {
        (*self).to_socket_addrs_with_default(default_port)
    }
    fn host_string(&self) -> String {
        (*self).host_string()
    }
}

impl HostAddr for String {
    fn to_socket_addrs_with_default(&self, default_port: u16) -> io::Result<Vec<SocketAddr>> {
        self.as_str().to_socket_addrs_with_default(default_port)
    }
    fn host_string(&self) -> String {
        self.as_str().host_string()
    }
}

impl HostAddr for SocketAddr {
    fn to_socket_addrs_with_default(&self, _default_port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![*self])
    }
    fn host_string(&self) -> String {
        self.ip().to_string()
    }
}

/// Parses an address string into `(host, port)`. When no port is present,
/// `default_port` is used.
///
/// The following forms are supported (following Minecraft / [RFC 3986][rfc]):
/// - `"host"` → `("host", default_port)`
/// - `"host:port"` → `("host", port)`
/// - `"[::1]:port"` → `("::1", port)` (IPv6 with brackets + port)
/// - `"[::1]"` → `("::1", default_port)` (IPv6 with brackets, no port)
/// - `"::1"` → `("::1", default_port)` (bare IPv6: without brackets the port
///   cannot be identified, so per the Minecraft convention it is treated as
///   port-less)
///
/// [rfc]: https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2
pub fn parse_host_port(s: &str, default_port: u16) -> (String, u16) {
    // Case A: IPv6 bracket form [addr]:port or [addr]
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((ipv6, after)) = rest.split_once(']') {
            // [addr]:port
            if let Some(port_str) = after.strip_prefix(':') {
                if let Ok(p) = port_str.parse::<u16>() {
                    return (ipv6.to_string(), p);
                }
            }
            // [addr] with no port (after is empty or not ":<digits>")
            return (ipv6.to_string(), default_port);
        }
        // Starts with '[' but no ']': malformed input, treat as a whole with the default port.
    }
    // Case B: ordinary host:port or host
    // Use rsplit_once to find the last colon; only treat it as a port separator
    // when the suffix is a valid port and the host contains no colon (this
    // excludes bare IPv6 such as "::1:8080").
    match s.rsplit_once(':') {
        Some((host, port_str)) if port_str.parse::<u16>().is_ok() && !host.contains(':') => {
            (host.to_string(), port_str.parse().unwrap())
        }
        _ => (s.to_string(), default_port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_host_no_port() {
        assert_eq!(
            parse_host_port("mc.hypixel.net", 25565),
            ("mc.hypixel.net".into(), 25565)
        );
    }

    #[test]
    fn parse_host_with_port() {
        assert_eq!(
            parse_host_port("play.cubecraft.net:25565", 25565),
            ("play.cubecraft.net".into(), 25565)
        );
        assert_eq!(
            parse_host_port("example.com:1234", 25565),
            ("example.com".into(), 1234)
        );
    }

    #[test]
    fn parse_ipv6_bracketed_with_port() {
        assert_eq!(parse_host_port("[::1]:25565", 25565), ("::1".into(), 25565));
        assert_eq!(
            parse_host_port("[2001:db8::1]:19132", 25565),
            ("2001:db8::1".into(), 19132)
        );
    }

    #[test]
    fn parse_ipv6_bracketed_no_port() {
        assert_eq!(parse_host_port("[::1]", 25565), ("::1".into(), 25565));
        assert_eq!(
            parse_host_port("[2001:db8::1]", 19132),
            ("2001:db8::1".into(), 19132)
        );
    }

    #[test]
    fn parse_bare_ipv6_treated_as_no_port() {
        // A bare IPv6 (no brackets) cannot be identified as having a port, so
        // per the Minecraft convention it is treated as port-less.
        assert_eq!(parse_host_port("::1", 25565), ("::1".into(), 25565));
        assert_eq!(
            parse_host_port("2001:db8::1", 25565),
            ("2001:db8::1".into(), 25565)
        );
    }

    #[test]
    fn parse_ipv4_with_port() {
        assert_eq!(
            parse_host_port("127.0.0.1:8080", 25565),
            ("127.0.0.1".into(), 8080)
        );
    }

    #[test]
    fn parse_ipv4_no_port() {
        assert_eq!(
            parse_host_port("127.0.0.1", 25565),
            ("127.0.0.1".into(), 25565)
        );
    }

    #[test]
    fn host_string_for_tuple() {
        assert_eq!(("mc.hypixel.net", 25565).host_string(), "mc.hypixel.net");
    }

    #[test]
    fn host_string_for_str_with_port() {
        assert_eq!(
            "play.cubecraft.net:25565".host_string(),
            "play.cubecraft.net"
        );
        assert_eq!("example.com:1234".host_string(), "example.com");
    }

    #[test]
    fn host_string_for_str_no_port() {
        assert_eq!("mc.hypixel.net".host_string(), "mc.hypixel.net");
    }

    #[test]
    fn host_string_for_ipv6_bracketed() {
        assert_eq!("[::1]:25565".host_string(), "::1");
        assert_eq!("[2001:db8::1]:19132".host_string(), "2001:db8::1");
        assert_eq!("[::1]".host_string(), "::1");
    }

    #[test]
    fn host_string_for_bare_ipv6() {
        assert_eq!("::1".host_string(), "::1");
    }

    #[test]
    fn host_string_for_socketaddr() {
        use std::net::{IpAddr, Ipv4Addr};
        let sa = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 25565);
        assert_eq!(sa.host_string(), "127.0.0.1");
    }

    #[test]
    fn resolve_localhost_default_port() {
        // localhost should resolve successfully with the default port.
        let addrs = "localhost".to_socket_addrs_with_default(25565).unwrap();
        assert!(addrs.iter().all(|a| a.port() == 25565));
    }

    #[test]
    fn resolve_localhost_explicit_port() {
        let addrs = "localhost:12345"
            .to_socket_addrs_with_default(25565)
            .unwrap();
        assert!(addrs.iter().all(|a| a.port() == 12345));
    }

    #[test]
    fn resolve_ipv4_literal() {
        let addrs = "127.0.0.1:8080"
            .to_socket_addrs_with_default(25565)
            .unwrap();
        assert_eq!(addrs[0].port(), 8080);
    }
}
