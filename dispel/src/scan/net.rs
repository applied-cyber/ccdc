//! Network scanning module for detecting Realm C2 indicators in live traffic and connections.
//!
//! This module provides both passive and active network analysis:
//!
//! - **Passive scanning** (`scan`): Inspects active TCP connections via `/proc/net/tcp`
//!   (Linux) or the Windows TCP table to flag ESTABLISHED connections on non-standard
//!   ports to external addresses.
//!
//! - **Active payload inspection** (`check_grpc_payload`, `check_dns_c2_query`,
//!   `check_encrypted_prefix`): Examines raw packet data or DNS queries for Realm-specific
//!   signatures such as gRPC service paths, base32-encoded DNS tunnel labels, and
//!   high-entropy cryptographic prefixes (X25519 pubkey + nonce).
//!
//! - **Beacon detection** (`ConnectionTracker`): Accumulates timestamped connection events
//!   per destination and uses statistical analysis (inter-arrival interval standard
//!   deviation) to identify periodic callback patterns characteristic of C2 beaconing.
//!
//! Filtering helpers (`is_container_network`, `is_internal_network`, `is_common_port`)
//! suppress false positives from infrastructure ranges and well-known services.

use std::collections::HashMap;
use crate::{Finding, Tier, ScanResult};
use crate::signatures::strings::GRPC_PATHS;

// --- Beacon detection ---

/// A detected beaconing pattern on a specific destination.
///
/// Produced by [`ConnectionTracker::detect_beacons`] when a destination's connection
/// timestamps show a consistent periodic interval (low jitter relative to the mean).
#[derive(Debug, Clone)]
pub struct BeaconDetection {
    /// The remote host or IP:port being beaconed to.
    pub destination: String,
    /// Mean inter-arrival time between connections, in seconds.
    pub interval_secs: f64,
    /// Number of connection timestamps recorded for this destination.
    pub sample_count: usize,
    /// Standard deviation of inter-arrival intervals; lower values indicate
    /// more regular (and therefore more suspicious) timing.
    pub jitter: f64,
}

/// Tracks connection timestamps per destination to detect regular beaconing.
///
/// Callers feed timestamped connection events via [`record_connection`], then
/// periodically call [`detect_beacons`] to identify destinations exhibiting
/// suspiciously regular callback intervals.
pub struct ConnectionTracker {
    /// Maps destination string -> sorted list of timestamps (Unix seconds).
    pub connections: HashMap<String, Vec<u64>>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    /// Record a connection to `destination` at the given Unix timestamp (seconds).
    pub fn record_connection(&mut self, destination: &str, timestamp_secs: u64) {
        self.connections
            .entry(destination.to_string())
            .or_default()
            .push(timestamp_secs);
    }

    /// Detect beaconing patterns among recorded connections.
    ///
    /// A destination is flagged if:
    /// - It has at least 4 timestamps (minimum sample size for meaningful stats), AND
    /// - The standard deviation of intervals between consecutive timestamps
    ///   is <= `tolerance_secs` (i.e., the callback timing is regular enough to
    ///   indicate automated, not human, behavior).
    ///
    /// Returns a [`BeaconDetection`] for each destination that meets the criteria.
    pub fn detect_beacons(&self, tolerance_secs: f64) -> Vec<BeaconDetection> {
        let mut detections = Vec::new();

        for (dest, timestamps) in &self.connections {
            // Require a minimum of 4 samples; fewer timestamps cannot reliably
            // distinguish periodic beaconing from coincidental connections.
            if timestamps.len() < 4 {
                continue;
            }

            // Sort timestamps chronologically so we can compute consecutive deltas.
            let mut sorted = timestamps.clone();
            sorted.sort_unstable();

            // Compute inter-arrival intervals (delta between each pair of
            // consecutive timestamps).
            let intervals: Vec<f64> = sorted
                .windows(2)
                .map(|w| (w[1] as f64) - (w[0] as f64))
                .collect();

            if intervals.is_empty() {
                continue;
            }

            // Compute mean and standard deviation of the intervals.
            // A low standard deviation relative to the mean indicates a regular
            // periodic pattern -- the hallmark of C2 beaconing.
            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            let variance = intervals
                .iter()
                .map(|&x| (x - mean).powi(2))
                .sum::<f64>()
                / intervals.len() as f64;
            let std_dev = variance.sqrt();

            // Flag this destination if jitter is within the caller's tolerance.
            if std_dev <= tolerance_secs {
                detections.push(BeaconDetection {
                    destination: dest.clone(),
                    interval_secs: mean,
                    sample_count: timestamps.len(),
                    jitter: std_dev,
                });
            }
        }

        detections
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// --- Container network filter ---

/// Returns true if `ip` falls within a known container/cluster infrastructure
/// range that should not be flagged as suspicious:
///   - `10.42.0.0/16` -- k3s pod CIDR
///   - `10.43.0.0/16` -- k3s service CIDR
///   - `172.17.0.0/16` -- Docker default bridge
///
/// Connections to these ranges are expected in containerized environments and
/// would generate excessive false positives if reported.
fn is_container_network(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    // Only the first two octets are needed to match /16 ranges.
    let Ok(a) = parts[0].parse::<u16>() else { return false; };
    let Ok(b) = parts[1].parse::<u16>() else { return false; };

    match (a, b) {
        (10, 42) | (10, 43) | (172, 17) => true,
        _ => false,
    }
}

// --- Common port helper ---

/// Returns true if `port` is a well-known / commonly-allowed port that should
/// not be flagged as suspicious on its own.
///
/// Covers standard services: SSH (22), SMTP (25/465/587), DNS (53), HTTP(S)
/// (80/443/8080/8443), POP3 (110/995), IMAP (143/993), MySQL (3306),
/// PostgreSQL (5432).
fn is_common_port(port: u16) -> bool {
    matches!(
        port,
        22 | 25 | 53 | 80 | 110 | 143 | 443 | 465 | 587 | 993 | 995 | 3306 | 5432 | 8080 | 8443
    )
}

/// Returns true if `ip` belongs to an RFC 1918 private range, link-local range,
/// or loopback range. Connections to these addresses are generally not C2
/// callback targets and are filtered to reduce noise.
fn is_internal_network(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let Ok(a) = parts[0].parse::<u16>() else { return false; };
    let Ok(b) = parts[1].parse::<u16>() else { return false; };

    match a {
        10 => true,                                    // 10.0.0.0/8
        172 if (16..=31).contains(&b) => true,         // 172.16.0.0/12
        192 if b == 168 => true,                       // 192.168.0.0/16
        169 if b == 254 => true,                       // 169.254.0.0/16 link-local
        127 => true,                                   // 127.0.0.0/8
        _ => false,
    }
}

// --- Active packet inspection ---

/// Check raw payload bytes for Realm C2 gRPC paths or `application/grpc` content-type.
///
/// Scans the payload (interpreted as lossy UTF-8) against the known Realm gRPC
/// service paths defined in [`GRPC_PATHS`] (e.g., `/c2.C2/ClaimTasks`). Also
/// detects the `application/grpc` content-type header, with elevated severity
/// when it appears over HTTP/1.1 (gRPC normally uses HTTP/2, so HTTP/1.1 is
/// anomalous and a stronger indicator).
///
/// Returns a list of findings, potentially multiple if several paths match.
pub fn check_grpc_payload(data: &[u8]) -> Vec<Finding> {
    // Lossy conversion is acceptable here; we only need to match ASCII path strings
    // and non-UTF8 bytes will be replaced with the Unicode replacement character.
    let text = String::from_utf8_lossy(data);
    let mut findings = Vec::new();

    // Check for specific Realm C2 gRPC service paths (e.g., /c2.C2/ClaimTasks).
    for &path in GRPC_PATHS {
        if text.contains(path) {
            findings.push(Finding::new(
                "net",
                format!("Realm C2 gRPC path detected: {path}"),
                Tier::Tier3,
                path.to_string(),
            ));
        }
    }

    // Check for application/grpc content-type header.
    if text.contains("application/grpc") {
        // gRPC over HTTP/1.1 is unusual -- legitimate gRPC uses HTTP/2.
        // Seeing it on HTTP/1.1 suggests a non-standard or covert transport,
        // so it receives a higher confidence tier.
        let tier = if text.contains("HTTP/1.1") {
            Tier::Tier3
        } else {
            Tier::Tier1
        };
        findings.push(Finding::new(
            "net",
            "gRPC content-type detected in traffic".to_string(),
            tier,
            "application/grpc".to_string(),
        ));
    }

    findings
}

/// Check a DNS query label string for signs of DNS tunnelling / C2 exfiltration.
///
/// DNS tunnelling encodes data as subdomain labels. Realm's DNS C2 uses base32
/// encoding, producing long labels (30+ chars) composed entirely of `A-Z`, `2-7`,
/// and `=`. Normal domain labels rarely exceed ~20 chars or use pure base32.
///
/// Returns `Some(description)` if a suspicious label is found, `None` otherwise.
pub fn check_dns_c2_query(query: &str) -> Option<String> {
    // Split the FQDN into individual labels (e.g., "MFRA.example.com" -> ["MFRA", "example", "com"]).
    let labels: Vec<&str> = query.split('.').collect();

    for label in labels {
        // A label >= 30 chars that is valid base32 is a strong DNS tunnel indicator.
        // Normal hostnames are rarely this long, and almost never pure base32.
        if label.len() >= 30 && is_base32(label) {
            return Some(format!(
                "Suspicious long base32-encoded DNS label ({} chars): {}",
                label.len(),
                label
            ));
        }
    }

    None
}

/// Check the first 56 bytes of `data` for high Shannon entropy indicating
/// random cryptographic material.
///
/// Realm's transport prepends a 32-byte X25519 ephemeral public key followed
/// by a 24-byte XSalsa20 nonce (56 bytes total). This prefix will exhibit
/// near-uniform byte distribution and correspondingly high entropy.
///
/// Returns a Tier3 finding if entropy exceeds the threshold, `None` otherwise.
pub fn check_encrypted_prefix(data: &[u8]) -> Option<Finding> {
    // Need at least 56 bytes to cover the full pubkey (32) + nonce (24).
    if data.len() < 56 {
        return None;
    }

    let entropy = shannon_entropy(&data[..56]);
    // For a 56-byte window, the theoretical maximum Shannon entropy (all 56 bytes
    // distinct) is log2(56) ~ 5.807. A threshold of 5.4 catches buffers with
    // near-uniform distribution -- characteristic of cryptographic key material --
    // while remaining below what normal structured data (text, headers) produces.
    if entropy > 5.4 {
        Some(Finding::new(
            "net",
            "High-entropy prefix detected — possible Realm X25519 pubkey + nonce".to_string(),
            Tier::Tier3,
            format!("entropy={entropy:.4}"),
        ))
    } else {
        None
    }
}

/// Compute the Shannon entropy of a byte sequence.
///
/// Returns a value between 0.0 (all identical bytes) and 8.0 (perfectly uniform
/// distribution across all 256 byte values). Higher entropy indicates more
/// randomness, which is expected for encrypted or compressed data.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Count occurrences of each byte value (0-255).
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    // Sum -p * log2(p) for each byte value that appears at least once.
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Returns true if every character in `s` is a valid base32 character
/// per RFC 4648: uppercase `A-Z`, digits `2-7`, and padding `=`.
///
/// Used to identify DNS labels that carry base32-encoded tunnel payloads.
fn is_base32(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || matches!(c, '2'..='7') || c == '=')
}

// --- Passive network scan ---

/// Scan active network connections for suspicious outbound activity.
///
/// Platform behavior:
/// - **Linux**: Parses `/proc/net/tcp` and `/proc/net/tcp6` to enumerate
///   ESTABLISHED connections. Flags connections to external, non-private IPs
///   on non-standard ports as behavioral indicators.
/// - **Windows**: Uses the platform-specific TCP table reader from
///   [`crate::platform::windows`] with similar filtering logic.
/// - **Other**: No-op (macOS, etc. are not currently supported for passive scanning).
///
/// Filtering suppresses connections to loopback, RFC 1918, link-local,
/// container network ranges, and well-known service ports to reduce noise.
pub fn scan(verbose: bool) -> ScanResult {
    let mut result = ScanResult::new();

    #[cfg(target_os = "linux")]
    {
        scan_linux(&mut result, verbose);
    }

    #[cfg(windows)]
    {
        use crate::platform::windows;

        let connections = windows::read_tcp_connections();
        if verbose {
            eprintln!("[verbose] Found {} TCP connections", connections.len());
        }

        for conn in &connections {
            // Only flag ESTABLISHED connections to non-loopback, non-private,
            // non-standard-port destinations.
            if conn.state == "ESTABLISHED"
                && conn.remote_addr != "0.0.0.0"
                && conn.remote_addr != "127.0.0.1"
                && !is_internal_network(&conn.remote_addr)
                && !is_common_port(conn.remote_port)
            {
                result.add_finding(Finding::new(
                    "net",
                    format!(
                        "Outbound to non-standard port {}:{} (PID {})",
                        conn.remote_addr, conn.remote_port, conn.owning_pid
                    ),
                    Tier::Tier1,
                    format!("local={}:{}", conn.local_addr, conn.local_port),
                ));
            }
        }
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = verbose; // suppress unused-variable warning on unsupported platforms
    }

    result
}

/// Linux-specific scanner that parses `/proc/net/tcp` and `/proc/net/tcp6`.
///
/// Each line after the header represents a socket. We extract the remote address
/// and port, then apply filtering to flag only external connections on
/// non-standard ports.
#[cfg(target_os = "linux")]
fn scan_linux(result: &mut ScanResult, verbose: bool) {
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            // Skip the header line (first line contains column names).
            for line in content.lines().skip(1) {
                // /proc/net/tcp line format (whitespace-delimited):
                //   sl  local_address  rem_address  st  tx_queue:rx_queue  ...
                // We need fields[2] (remote address) and fields[3] (state).
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 4 {
                    continue;
                }

                // State "01" == TCP_ESTABLISHED in the kernel's enum.
                // We only care about active connections, not listeners or TIME_WAIT.
                if fields[3] != "01" {
                    continue;
                }

                let remote_hex = fields[2];
                // Skip IPv6-mapped loopback (::ffff:127.0.0.1). In /proc/net/tcp6,
                // this appears as the 32-hex-char representation with FFFF prefix
                // and 0100007F (127.0.0.1 in little-endian) suffix.
                if remote_hex == "0000000000000000FFFF00000100007F:0000"
                    || remote_hex.starts_with("0000000000000000FFFF00000100007F:")
                {
                    continue;
                }

                if let Some((ip, port)) = parse_proc_net_addr(remote_hex) {
                    // Skip loopback and wildcard addresses.
                    if ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "::1" || ip == "::" {
                        continue;
                    }

                    // Skip internal/private and container infrastructure networks
                    // to avoid flooding results in lab and containerized environments.
                    if is_internal_network(&ip) || is_container_network(&ip) {
                        continue;
                    }

                    // Only flag connections to non-standard ports. Connections to
                    // ports like 80/443 are expected and not inherently suspicious.
                    if !is_common_port(port) {
                        let detail = format!("{ip}:{port}");
                        if verbose {
                            eprintln!("[net] ESTABLISHED to non-standard port: {detail}");
                        }
                        result.add_finding(Finding::new(
                            "net",
                            format!("ESTABLISHED connection to non-standard port {port}"),
                            Tier::Behavioral,
                            detail,
                        ));
                    }
                }
            }
        }
    }
}

/// Parse a hex-encoded address:port pair from `/proc/net/tcp` or `/proc/net/tcp6`.
///
/// Format:
/// - **IPv4** (`8 hex chars`): `AABBCCDD:PPPP` where the address is a 32-bit
///   integer stored in **little-endian** byte order, and the port is 16-bit
///   big-endian hex.
/// - **IPv6** (`32 hex chars`): Four 32-bit words, each in little-endian order.
///   Special cases handle `::1` (loopback), `::` (wildcard), and IPv4-mapped
///   addresses (`::ffff:a.b.c.d`).
///
/// Returns `(ip_string, port)` on success, `None` if the hex cannot be parsed.
#[cfg(target_os = "linux")]
fn parse_proc_net_addr(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    // Port is always big-endian hex after the colon.
    let port = u16::from_str_radix(parts[1], 16).ok()?;

    let addr_hex = parts[0];
    if addr_hex.len() == 8 {
        // IPv4: parse the 4-byte hex as a u32, then convert from the kernel's
        // little-endian storage to individual octets.
        let n = u32::from_str_radix(addr_hex, 16).ok()?;
        let b = n.to_le_bytes();
        let ip = format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
        Some((ip, port))
    } else if addr_hex.len() == 32 {
        // IPv6: 16 bytes represented as 32 hex chars.
        // Handle well-known addresses explicitly for reliable filtering.

        // ::1 (loopback)
        if addr_hex == "00000000000000000000000001000000" {
            return Some(("::1".to_string(), port));
        }
        // :: (wildcard / unspecified)
        if addr_hex == "00000000000000000000000000000000" {
            return Some((("::").to_string(), port));
        }
        // IPv4-mapped IPv6 (::ffff:a.b.c.d) -- extract the trailing 4 bytes
        // and decode as an IPv4 address so our IPv4 filtering logic applies.
        if addr_hex.starts_with("0000000000000000FFFF0000") {
            let ipv4_hex = &addr_hex[24..32];
            if let Ok(n) = u32::from_str_radix(ipv4_hex, 16) {
                let b = n.to_le_bytes();
                let ip = format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
                return Some((ip, port));
            }
        }
        // For other IPv6 addresses, return a prefixed hex string.
        // Full IPv6 formatting is not needed since we primarily filter on IPv4.
        Some((format!("ipv6:{addr_hex}"), port))
    } else {
        None
    }
}
