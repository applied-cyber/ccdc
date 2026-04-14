//! Linux process enumeration and network connection parsing via /proc.
//!
//! This module reads the /proc filesystem to enumerate running processes
//! and parse TCP connection state. It is the primary data source for the
//! proc, net, and behavior scan layers on Linux.
//!
//! All reads are race-safe: if a process exits while we're reading its
//! /proc entry, the read error is silently ignored and the process is skipped.

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::SystemTime;

use super::{ProcessInfo, TcpConnection};

/// Read all processes from /proc and return a Vec<ProcessInfo>.
///
/// For each numeric directory in /proc (one per PID), reads:
/// - `/proc/<pid>/comm`: short process name
/// - `/proc/<pid>/exe`: symlink to the on-disk binary
/// - `/proc/<pid>/status`: thread count
///
/// Silently skips any PID whose /proc entry disappears mid-scan (race-safe).
pub fn enumerate_processes() -> Vec<ProcessInfo> {
    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    let mut result = Vec::new();

    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Only numeric entries are PIDs; skip /proc/self, /proc/net, etc.
        let pid: u32 = match name_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let pid_path = format!("/proc/{}", pid);

        // --- comm: short process name (max 16 chars, no path) ---
        let proc_name = fs::read_to_string(format!("{}/comm", pid_path))
            .unwrap_or_default()
            .trim()
            .to_string();

        if proc_name.is_empty() {
            continue;
        }

        // --- exe: symlink to the on-disk binary path ---
        let exe_link = format!("{}/exe", pid_path);
        let (exe_path, deleted_exe) = match fs::read_link(&exe_link) {
            Ok(target) => {
                let path_str = target.to_string_lossy().to_string();
                // Linux appends " (deleted)" to the symlink target when the
                // binary has been unlinked from disk (common with in-memory implants)
                if path_str.ends_with(" (deleted)") {
                    let clean = path_str
                        .trim_end_matches(" (deleted)")
                        .to_string();
                    (Some(clean), true)
                } else {
                    (Some(path_str), false)
                }
            }
            Err(_) => (None, false),
        };

        // --- status: extract thread count ---
        let thread_count = read_thread_count(&format!("{}/status", pid_path));

        result.push(ProcessInfo {
            pid,
            name: proc_name,
            exe_path,
            deleted_exe,
            thread_count,
        });
    }

    result
}

/// Parse /proc/<pid>/status to extract the `Threads:` field value.
/// Returns 1 as a safe default if the file can't be read or parsed.
fn read_thread_count(status_path: &str) -> u32 {
    let content = match fs::read_to_string(status_path) {
        Ok(c) => c,
        Err(_) => return 1,
    };

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Threads:") {
            if let Ok(n) = rest.trim().parse::<u32>() {
                return n;
            }
        }
    }

    1
}

/// Parse /proc/net/tcp into a Vec<TcpConnection>.
///
/// Each row in /proc/net/tcp has the format:
/// `sl local_address rem_address st tx:rx_queue tr:tm->when retrnsmt uid timeout inode`
///
/// Addresses are stored as hex `AABBCCDD:PPPP` in little-endian byte order.
/// The inode field is used to correlate connections back to process fds.
pub fn read_tcp_connections() -> Vec<TcpConnection> {
    let content = match fs::read_to_string("/proc/net/tcp") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut connections = Vec::new();

    for line in content.lines().skip(1) {
        // Skip the header line
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        // fields[1] = local "AABBCCDD:PORT", fields[2] = remote, fields[3] = state hex
        let local = match parse_hex_addr_port(fields[1]) {
            Some(v) => v,
            None => continue,
        };
        let remote = match parse_hex_addr_port(fields[2]) {
            Some(v) => v,
            None => continue,
        };

        // State is a 2-digit hex code (e.g. "01" = ESTABLISHED, "0A" = LISTEN)
        let state = fields[3].to_string();

        // Inode field (index 9) links this socket to a process fd via
        // /proc/<pid>/fd/<n> -> socket:[inode]
        let inode: u64 = fields[9].parse().unwrap_or(0);

        connections.push(TcpConnection {
            local_addr: local.0,
            local_port: local.1,
            remote_addr: remote.0,
            remote_port: remote.1,
            state,
            inode,
        });
    }

    connections
}

/// Parse a "AABBCCDD:PPPP" hex address:port pair from /proc/net/tcp into
/// (Ipv4Addr, u16).
///
/// The 32-bit address is stored in little-endian byte order in /proc/net/tcp,
/// so we need to byte-swap to get the standard network-order IP address.
fn parse_hex_addr_port(s: &str) -> Option<(Ipv4Addr, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;

    let addr_le = u32::from_str_radix(addr_hex, 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    // Byte-swap from little-endian to network order for Ipv4Addr constructor
    let addr = Ipv4Addr::from(u32::from_be(addr_le.swap_bytes()));

    Some((addr, port))
}

/// Check whether a binary has been timestomped by comparing its mtime against /bin/sh.
///
/// Returns true if the binary's mtime is within 1 second of /bin/sh's mtime.
/// Attackers often copy the timestamp of a legitimate system binary to their
/// implant to make it blend in with directory listings sorted by date.
///
/// Returns false if the path doesn't exist or /bin/sh can't be stat'd.
pub fn check_timestomp(binary_path: &str) -> bool {
    let bin_sh_mtime = match get_mtime("/bin/sh") {
        Some(t) => t,
        None => return false,
    };

    let binary_mtime = match get_mtime(binary_path) {
        Some(t) => t,
        None => return false,
    };

    // Suspicious if mtime matches /bin/sh within 1 second -- attacker copied the timestamp
    let diff = if binary_mtime >= bin_sh_mtime {
        binary_mtime - bin_sh_mtime
    } else {
        bin_sh_mtime - binary_mtime
    };

    diff <= 1
}

/// Return mtime as seconds since UNIX epoch, or None on error.
fn get_mtime(path: &str) -> Option<u64> {
    let meta = fs::metadata(path).ok()?;
    let mtime = meta.modified().ok()?;
    Some(
        mtime
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}
