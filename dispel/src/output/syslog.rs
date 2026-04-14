//! Syslog (CEF) and webhook output for dispel findings.
//!
//! Provides two external output channels for findings:
//! - **Syslog**: formats findings as CEF (Common Event Format) strings and sends
//!   them to local syslog via UDP to 127.0.0.1:514. This integrates with any
//!   SIEM or log aggregator listening on the local syslog socket.
//! - **Webhook**: serializes findings as JSON and POSTs them to an HTTP URL
//!   using raw TCP (no TLS). Useful for alerting to Slack, PagerDuty, etc.
//!
//! Both outputs are best-effort: errors are silently ignored to avoid disrupting
//! the scan loop.

use crate::{Finding, Tier};
use std::io::Write;
use std::net::UdpSocket;

/// Map a detection tier to a CEF severity value (0-10 scale).
///
/// CEF severity levels:
/// - Tier3 (conclusive evidence) -> 10 (highest)
/// - Behavioral (runtime anomaly) -> 7
/// - Tier2 (strong indicator) -> 5
/// - Tier1 (name-based artifact) -> 3
fn cef_severity(tier: &Tier) -> u8 {
    match tier {
        Tier::Tier3 => 10,
        Tier::Behavioral => 7,
        Tier::Tier2 => 5,
        Tier::Tier1 => 3,
    }
}

/// Format a finding as a CEF (Common Event Format) syslog line.
///
/// Output format:
/// `CEF:0|dispel|dispel|0.1.0|<tier_label>|<description>|<severity>|src=<detail>`
///
/// Pipes and backslashes in the description and detail fields are escaped
/// per the CEF specification.
pub fn format_syslog_line(finding: &Finding) -> String {
    let severity = cef_severity(&finding.tier);
    // Escape pipes and backslashes per CEF spec
    let desc = finding.description.replace('\\', "\\\\").replace('|', "\\|");
    // Escape backslashes and equals signs in the extension field
    let detail = finding.detail.replace('\\', "\\\\").replace('=', "\\=");
    format!(
        "CEF:0|dispel|dispel|0.1.0|{}|{}|{}|src={}",
        finding.tier.label(),
        desc,
        severity,
        detail,
    )
}

/// Send a finding to local syslog via UDP to 127.0.0.1:514.
///
/// Wraps the CEF line in an RFC 3164 syslog message with priority 14
/// (facility=user(1), severity=info(6) -> 1*8+6=14).
///
/// Best-effort: silently ignores errors (syslog may not be running).
pub fn send_to_syslog(finding: &Finding) {
    let line = format_syslog_line(finding);
    // RFC 3164 format: <priority>message
    let msg = format!("<14>{}", line);

    // Bind to an ephemeral port and send the datagram
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        let _ = socket.send_to(msg.as_bytes(), "127.0.0.1:514");
    }
}

/// Send a finding as JSON to a webhook URL via raw HTTP POST over TCP.
///
/// Constructs a minimal HTTP/1.1 POST request with Content-Type: application/json
/// and sends it over a plain TCP connection. Does not support HTTPS.
///
/// Expects `url` in the form `http://host:port/path` or `http://host/path`.
/// Best-effort: silently ignores errors (webhook may not be reachable).
pub fn send_to_webhook(finding: &Finding, url: &str) {
    let json_body = match serde_json::to_string(finding) {
        Ok(j) => j,
        Err(_) => return,
    };

    // Parse URL into host, port, and path components
    let (host, port, path) = match parse_http_url(url) {
        Some(v) => v,
        None => return,
    };

    let addr = format!("{}:{}", host, port);
    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        path, host, json_body.len(), json_body,
    );

    // Try parsing as a direct socket address first; fall back to DNS resolution
    let sock_addr: std::net::SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(_) => {
            use std::net::ToSocketAddrs;
            match addr.to_socket_addrs() {
                Ok(mut addrs) => match addrs.next() {
                    Some(a) => a,
                    None => return,
                },
                Err(_) => return,
            }
        }
    };

    // Connect with a 5-second timeout to avoid blocking the scan loop
    let stream = match std::net::TcpStream::connect_timeout(
        &sock_addr,
        std::time::Duration::from_secs(5),
    ) {
        Ok(s) => s,
        Err(_) => return,
    };

    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
    let mut writer = std::io::BufWriter::new(stream);
    let _ = writer.write_all(request.as_bytes());
    let _ = writer.flush();
}

/// Parse a simple HTTP URL into (host, port, path).
///
/// Only supports `http://` scheme (not https). Defaults to port 80 if no
/// port is specified. Defaults to path "/" if no path is present.
///
/// Returns None for non-http URLs or malformed input.
fn parse_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;

    // Split authority (host:port) from path at the first '/'
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    // Split host from port at the last ':' (to handle IPv6 brackets)
    let (host, port) = match authority.rfind(':') {
        Some(i) => {
            let port: u16 = authority[i + 1..].parse().ok()?;
            (&authority[..i], port)
        }
        None => (authority, 80),
    };

    Some((host.to_string(), port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Finding, Tier};

    #[test]
    fn test_format_syslog_line() {
        let finding = Finding::new("proc", "test description", Tier::Tier1, "path=/tmp/imix");
        let line = format_syslog_line(&finding);
        assert!(line.starts_with("CEF:0|dispel|dispel|0.1.0|T1|"));
        assert!(line.contains("test description"));
        assert!(line.contains("|3|"));
        assert!(line.contains("src=path\\=/tmp/imix"));
    }

    #[test]
    fn test_cef_severity_mapping() {
        assert_eq!(cef_severity(&Tier::Tier3), 10);
        assert_eq!(cef_severity(&Tier::Behavioral), 7);
        assert_eq!(cef_severity(&Tier::Tier2), 5);
        assert_eq!(cef_severity(&Tier::Tier1), 3);
    }

    #[test]
    fn test_parse_http_url() {
        let (h, p, path) = parse_http_url("http://example.com:8080/hook").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 8080);
        assert_eq!(path, "/hook");

        let (h, p, path) = parse_http_url("http://10.0.0.1/alerts").unwrap();
        assert_eq!(h, "10.0.0.1");
        assert_eq!(p, 80);
        assert_eq!(path, "/alerts");

        let (h, p, path) = parse_http_url("http://10.0.0.1:9000").unwrap();
        assert_eq!(h, "10.0.0.1");
        assert_eq!(p, 9000);
        assert_eq!(path, "/");

        assert!(parse_http_url("https://foo.com/bar").is_none());
    }
}
