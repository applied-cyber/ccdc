//! Incident Response report: gathers forensic context about detected implants.
//!
//! When dispel detects a Realm C2 binary, this module collects:
//! - File metadata (SHA256, size, owner, timestamps, permissions)
//! - Process info (PID, parent, user, cmdline, cwd, environment)
//! - Network connections originating from the process
//! - Persistence mechanisms found

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::ScanResult;

/// Full IR report for all detected implants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrReport {
    pub implants: Vec<ImplantReport>,
}

/// Configuration extracted from the implant binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedConfig {
    /// Callback URIs found in the binary (compiled-in C2 addresses).
    pub callback_uris: Vec<String>,
    /// Beacon ID variable name or value if found.
    pub beacon_id: Option<String>,
    /// Callback interval if found.
    pub callback_interval: Option<String>,
    /// Any other interesting config strings.
    pub other: Vec<String>,
}

/// Forensic report for a single detected implant binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplantReport {
    pub path: String,
    pub file_info: Option<FileInfo>,
    pub extracted_config: Option<ExtractedConfig>,
    pub processes: Vec<ProcessDetail>,
    pub connections: Vec<ConnectionDetail>,
    pub persistence: Vec<PersistenceDetail>,
}

/// File-level forensic metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub sha256: String,
    pub size_bytes: u64,
    pub owner: String,
    pub group: String,
    pub permissions: String,
    pub modified: String,
    pub accessed: String,
    pub created: String,
}

/// Process-level forensic detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDetail {
    pub pid: u32,
    pub ppid: u32,
    pub user: String,
    pub parent_name: String,
    pub cmdline: String,
    pub cwd: String,
    pub start_time: String,
    pub env_vars: Vec<String>,
}

/// Network connection from the implant process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionDetail {
    pub pid: u32,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
}

/// Persistence mechanism found for this implant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceDetail {
    pub mechanism: String,
    pub path: String,
    pub detail: String,
}

impl ImplantReport {
    /// Returns a single-line summary of this implant for quick triage.
    pub fn summary_line(&self) -> String {
        let callback = self
            .extracted_config
            .as_ref()
            .and_then(|c| c.callback_uris.first())
            .map(|s| s.as_str())
            .unwrap_or("(no callback found)");

        let (user, pid) = self
            .processes
            .first()
            .map(|p| (p.user.as_str(), p.pid))
            .unwrap_or(("unknown", 0));

        let installed = self
            .file_info
            .as_ref()
            .map(|fi| fi.created.as_str())
            .unwrap_or("unknown");

        format!(
            "Realm C2 implant (imix) at {} -> {}, running as {} (PID {}), installed {}",
            self.path, callback, user, pid, installed
        )
    }
}

/// Extract unique binary paths from proc-layer findings.
fn extract_implant_paths(result: &ScanResult) -> Vec<String> {
    let mut paths = HashSet::new();
    for f in &result.findings {
        if f.layer == "proc" {
            // detail format: "path=/tmp/imix" or "pid=123 name=imix exe=/tmp/imix"
            for part in f.detail.split_whitespace() {
                if let Some(path) = part.strip_prefix("path=") {
                    if !path.is_empty() {
                        paths.insert(path.to_string());
                    }
                }
                if let Some(path) = part.strip_prefix("exe=") {
                    if !path.is_empty() {
                        paths.insert(path.to_string());
                    }
                }
            }
        }
    }
    let mut sorted: Vec<String> = paths.into_iter().collect();
    sorted.sort();
    sorted
}

/// Extract persistence findings from the scan result.
fn extract_persistence(result: &ScanResult, implant_path: &str) -> Vec<PersistenceDetail> {
    let mut details = Vec::new();
    for f in &result.findings {
        if f.layer == "persist" {
            details.push(PersistenceDetail {
                mechanism: f.description.clone(),
                path: f.detail.clone(),
                detail: String::new(),
            });
        }
        // Also catch proc-layer persistence findings (e.g. install path detection)
        if f.layer == "proc"
            && f.description.contains("install path")
            && f.detail.contains(implant_path)
        {
            details.push(PersistenceDetail {
                mechanism: f.description.clone(),
                path: implant_path.to_string(),
                detail: String::new(),
            });
        }
    }
    details
}

/// Generate a full IR report from scan results.
/// On Linux, reads /proc for live forensic data. On other platforms, collects file info only.
pub fn generate_report(result: &ScanResult) -> IrReport {
    let paths = extract_implant_paths(result);
    let mut implants = Vec::new();

    for path in &paths {
        let file_info = collect_file_info(path);
        let extracted_config = extract_config(path);
        let processes = collect_process_details(path);
        let connections = collect_process_connections(&processes);
        let persistence = extract_persistence(result, path);

        implants.push(ImplantReport {
            path: path.clone(),
            file_info,
            extracted_config,
            processes,
            connections,
            persistence,
        });
    }

    IrReport { implants }
}

/// Extract compiled-in configuration from the implant binary.
///
/// Realm's imix agent compiles callback URIs, beacon IDs, and intervals
/// into the binary via env!() macros at build time. These appear as
/// string literals that survive even when the process isn't connected.
fn extract_config(path: &str) -> Option<ExtractedConfig> {
    use std::fs;

    let data = fs::read(path).ok()?;

    // Extract printable ASCII strings of length >= 6
    let strings = extract_strings(&data, 6);

    let mut callback_uris = Vec::new();
    let _beacon_id: Option<String> = None;
    let _callback_interval: Option<String> = None;
    let mut other = Vec::new();

    // Rust compiles string literals into contiguous read-only data without null
    // separators, so the callback URI ends up inside a huge blob of concatenated
    // strings. We need to regex-search inside each extracted string for URLs.
    // Match URLs: scheme + authority (host:port) + optional path
    // Stop at lowercase letters immediately after port (no path separator) to avoid
    // bleeding into adjacent concatenated strings like "http://10.0.0.1:8080jitter..."
    let url_re = regex::Regex::new(r"https?://[A-Za-z0-9.-]+(?::\d+)?(?:/[A-Za-z0-9._:/%?&=-]*)?").unwrap();
    let pubkey_re = regex::Regex::new(r"[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]=").unwrap();

    let ignored_domains = [
        "mozilla.org", "rust-lang.org", "github.com", "crates.io",
        "w3.org", "schema.org", "example.com", "hyper.rs", "docs.rs",
        "httpbin.org", "localhost", "127.0.0.1", "apple.com",
        "cloudflare", "google", "doh", "tonic", "www.",
    ];

    for s in &strings {
        // Find all URLs embedded within the string
        for url_match in url_re.find_iter(s) {
            let url = url_match.as_str();
            if !ignored_domains.iter().any(|d| url.contains(d)) {
                callback_uris.push(url.to_string());
            }
        }

        // Find base64 public keys (44 chars, ends with =)
        // Only check reasonably-sized strings to avoid scanning megabytes
        if s.len() < 100 {
            for key_match in pubkey_re.find_iter(s) {
                let key = key_match.as_str();
                if key.len() == 44 {
                    other.push(format!("server_pubkey: {}", key));
                }
            }
        }
    }

    // Deduplicate
    callback_uris.sort();
    callback_uris.dedup();
    other.sort();
    other.dedup();

    // beacon_id and callback_interval are found via the persistence layer
    // and process env vars respectively — don't try to parse them from
    // giant concatenated string blobs in the binary.

    Some(ExtractedConfig {
        callback_uris,
        beacon_id: None,
        callback_interval: None,
        other,
    })
}

/// Extract printable ASCII strings of at least `min_len` from binary data.
fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();

    for &b in data {
        if b >= 0x20 && b < 0x7f {
            current.push(b as char);
        } else {
            if current.len() >= min_len {
                strings.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        strings.push(current);
    }

    strings
}

/// Collect file metadata including SHA256 hash.
fn collect_file_info(path: &str) -> Option<FileInfo> {
    use sha2::{Digest, Sha256};
    use std::fs;

    let metadata = fs::metadata(path).ok()?;
    let contents = fs::read(path).ok()?;

    let mut hasher = Sha256::new();
    hasher.update(&contents);
    let hash = format!("{:x}", hasher.finalize());

    let size = metadata.len();
    let modified = format_system_time(metadata.modified().ok());
    let accessed = format_system_time(metadata.accessed().ok());
    let created = format_system_time(metadata.created().ok());

    #[cfg(unix)]
    let (owner, group, permissions) = {
        use std::os::unix::fs::MetadataExt;
        let uid = metadata.uid();
        let gid = metadata.gid();
        let mode = metadata.mode();
        (
            resolve_uid(uid),
            resolve_gid(gid),
            format!("{:o}", mode & 0o7777),
        )
    };

    #[cfg(not(unix))]
    let (owner, group, permissions) = {
        ("unknown".to_string(), "unknown".to_string(), "unknown".to_string())
    };

    Some(FileInfo {
        sha256: hash,
        size_bytes: size,
        owner,
        group,
        permissions,
        modified,
        accessed,
        created,
    })
}

fn format_system_time(time: Option<std::time::SystemTime>) -> String {
    match time {
        Some(t) => {
            let dur = t
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let secs = dur.as_secs();
            // Format as ISO-ish timestamp
            let ts = chrono_lite(secs);
            ts
        }
        None => "unknown".to_string(),
    }
}

/// Minimal timestamp formatting without pulling in chrono.
fn chrono_lite(epoch_secs: u64) -> String {
    // Good enough for IR — shows UTC date/time from epoch seconds
    let days = epoch_secs / 86400;
    let time_of_day = epoch_secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate date from days since epoch (1970-01-01)
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let month_days: &[u64] = if is_leap(year) {
        &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u64;
    for &md in month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

#[cfg(unix)]
fn resolve_uid(uid: u32) -> String {
    // Try to read /etc/passwd for the name
    if let Ok(contents) = std::fs::read_to_string("/etc/passwd") {
        for line in contents.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(u) = parts[2].parse::<u32>() {
                    if u == uid {
                        return parts[0].to_string();
                    }
                }
            }
        }
    }
    uid.to_string()
}

#[cfg(unix)]
fn resolve_gid(gid: u32) -> String {
    if let Ok(contents) = std::fs::read_to_string("/etc/group") {
        for line in contents.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(g) = parts[2].parse::<u32>() {
                    if g == gid {
                        return parts[0].to_string();
                    }
                }
            }
        }
    }
    gid.to_string()
}

/// Find all PIDs running the given executable path.
#[cfg(target_os = "linux")]
fn collect_process_details(exe_path: &str) -> Vec<ProcessDetail> {
    use std::fs;

    let mut details = Vec::new();
    let proc_entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return details,
    };

    for entry in proc_entries.flatten() {
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();
        let pid: u32 = match fname_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        // Check if this process's exe matches
        let exe_link = format!("/proc/{}/exe", pid);
        let actual_exe = match fs::read_link(&exe_link) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        // Handle " (deleted)" suffix
        let clean_exe = actual_exe.trim_end_matches(" (deleted)");
        if clean_exe != exe_path {
            continue;
        }

        // Read process details
        let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();

        let cwd = fs::read_link(format!("/proc/{}/cwd", pid))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let status = fs::read_to_string(format!("/proc/{}/status", pid)).unwrap_or_default();
        let ppid = parse_status_field(&status, "PPid:");
        let uid_str = parse_status_field(&status, "Uid:");
        let uid: u32 = uid_str.parse().unwrap_or(0);
        let user = resolve_uid(uid);

        // Get parent name
        let parent_name = fs::read_to_string(format!("/proc/{}/comm", ppid.parse::<u32>().unwrap_or(0)))
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();

        // Process start time from /proc/<pid>/stat field 22
        let stat_content = fs::read_to_string(format!("/proc/{}/stat", pid)).unwrap_or_default();
        let start_time = parse_start_time(&stat_content);

        // Environment variables (filter for interesting ones)
        let environ = fs::read_to_string(format!("/proc/{}/environ", pid))
            .unwrap_or_default();
        let env_vars: Vec<String> = environ
            .split('\0')
            .filter(|e| {
                let upper = e.to_uppercase();
                upper.starts_with("IMIX_")
                    || upper.starts_with("CALLBACK")
                    || upper.starts_with("C2_")
                    || upper.starts_with("HOME=")
                    || upper.starts_with("USER=")
                    || upper.starts_with("PWD=")
                    || upper.starts_with("LD_PRELOAD")
                    || upper.starts_with("LD_LIBRARY_PATH")
            })
            .map(|s| s.to_string())
            .collect();

        details.push(ProcessDetail {
            pid,
            ppid: ppid.parse().unwrap_or(0),
            user,
            parent_name,
            cmdline,
            cwd,
            start_time,
            env_vars,
        });
    }

    details
}

#[cfg(not(target_os = "linux"))]
fn collect_process_details(_exe_path: &str) -> Vec<ProcessDetail> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn parse_status_field(status: &str, field: &str) -> String {
    for line in status.lines() {
        if line.starts_with(field) {
            return line
                .trim_start_matches(field)
                .trim()
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .to_string();
        }
    }
    "0".to_string()
}

#[cfg(target_os = "linux")]
fn parse_start_time(stat: &str) -> String {
    // /proc/<pid>/stat format: pid (comm) state ppid ... field 22 is starttime in clock ticks
    // Find the closing paren to skip comm field (which can contain spaces)
    if let Some(close_paren) = stat.rfind(')') {
        let after_comm = &stat[close_paren + 2..]; // skip ") "
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        // starttime is field index 19 (0-indexed from after comm)
        if fields.len() > 19 {
            if let Ok(ticks) = fields[19].parse::<u64>() {
                // Convert clock ticks to approximate epoch seconds
                // CLK_TCK is typically 100 on Linux
                let clk_tck = 100u64;
                // Get system boot time from /proc/stat
                if let Ok(proc_stat) = std::fs::read_to_string("/proc/stat") {
                    for line in proc_stat.lines() {
                        if line.starts_with("btime ") {
                            if let Some(btime_str) = line.split_whitespace().nth(1) {
                                if let Ok(btime) = btime_str.parse::<u64>() {
                                    let start_epoch = btime + ticks / clk_tck;
                                    return chrono_lite(start_epoch);
                                }
                            }
                        }
                    }
                }
                return format!("{} ticks", ticks);
            }
        }
    }
    "unknown".to_string()
}

/// Collect network connections belonging to the implant processes.
#[cfg(target_os = "linux")]
fn collect_process_connections(processes: &[ProcessDetail]) -> Vec<ConnectionDetail> {
    use std::fs;

    let mut connections = Vec::new();
    if processes.is_empty() {
        return connections;
    }

    let pids: HashSet<u32> = processes.iter().map(|p| p.pid).collect();

    // For each process, read its fd directory and find socket inodes
    for &pid in &pids {
        let mut socket_inodes: HashSet<String> = HashSet::new();
        let fd_dir = format!("/proc/{}/fd", pid);

        if let Ok(entries) = fs::read_dir(&fd_dir) {
            for entry in entries.flatten() {
                if let Ok(target) = fs::read_link(entry.path()) {
                    let target_str = target.to_string_lossy().to_string();
                    if target_str.starts_with("socket:[") {
                        // Extract inode number
                        if let Some(inode) = target_str
                            .strip_prefix("socket:[")
                            .and_then(|s| s.strip_suffix(']'))
                        {
                            socket_inodes.insert(inode.to_string());
                        }
                    }
                }
            }
        }

        if socket_inodes.is_empty() {
            continue;
        }

        // Match socket inodes to /proc/net/tcp entries
        for tcp_path in &["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(content) = fs::read_to_string(tcp_path) {
                for line in content.lines().skip(1) {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() < 10 {
                        continue;
                    }

                    let inode = fields[9];
                    if !socket_inodes.contains(inode) {
                        continue;
                    }

                    let local = format_tcp_addr(fields[1]);
                    let remote = format_tcp_addr(fields[2]);
                    let state = match fields[3] {
                        "01" => "ESTABLISHED",
                        "02" => "SYN_SENT",
                        "03" => "SYN_RECV",
                        "06" => "TIME_WAIT",
                        "0A" => "LISTEN",
                        _ => "OTHER",
                    };

                    connections.push(ConnectionDetail {
                        pid,
                        local_addr: local,
                        remote_addr: remote,
                        state: state.to_string(),
                    });
                }
            }
        }
    }

    connections
}

#[cfg(not(target_os = "linux"))]
fn collect_process_connections(_processes: &[ProcessDetail]) -> Vec<ConnectionDetail> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn format_tcp_addr(hex: &str) -> String {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return hex.to_string();
    }

    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);
    let addr_hex = parts[0];

    if addr_hex.len() == 8 {
        let n = u32::from_str_radix(addr_hex, 16).unwrap_or(0);
        let b = n.to_le_bytes();
        format!("{}.{}.{}.{}:{}", b[0], b[1], b[2], b[3], port)
    } else {
        format!("[ipv6]:{}", port)
    }
}
