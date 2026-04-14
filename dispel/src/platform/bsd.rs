//! BSD platform backend -- process enumeration via `ps` for FreeBSD, OpenBSD,
//! and NetBSD.
//!
//! Since BSD systems lack a /proc filesystem (or have a limited one), this
//! module shells out to `ps -axo pid,comm,args` and parses the tabular output.
//! On FreeBSD, it additionally tries `procstat -b <pid>` to resolve the exact
//! binary path for each process.

use std::process::Command;

use super::ProcessInfo;

/// Enumerate all processes on BSD by parsing `ps -axo pid,comm,args`.
///
/// Returns an empty Vec if ps is unavailable or exits with a non-zero status.
/// Thread count is hardcoded to 1 since ps doesn't expose thread info in this
/// output format. `deleted_exe` is always false since BSD doesn't track
/// deleted executables the way Linux does via /proc/<pid>/exe.
pub fn enumerate_processes() -> Vec<ProcessInfo> {
    let output = match Command::new("ps")
        .args(["-axo", "pid,comm,args"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    if !output.status.success() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut result = Vec::new();

    for line in stdout.lines().skip(1) {
        // Skip the header line (PID COMM ARGS)
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Format: "  PID COMM ARGS..."
        // Use splitn(3, ...) to split into at most 3 fields so the full
        // command line (which may contain spaces) stays intact.
        let mut parts = trimmed.splitn(3, char::is_whitespace);

        let pid_str = match parts.next() {
            Some(s) => s.trim(),
            None => continue,
        };
        let pid: u32 = match pid_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let comm = match parts.next() {
            Some(s) => s.trim().to_string(),
            None => continue,
        };

        // The rest is the full command line (args column)
        let args = parts.next().map(|s| s.trim().to_string()).unwrap_or_default();

        // Try to determine the executable path from procstat (FreeBSD) or
        // from the first token of the args column if it's an absolute path
        let exe_path = extract_exe_path(pid, &args);

        result.push(ProcessInfo {
            pid,
            name: comm,
            exe_path,
            deleted_exe: false,  // BSD doesn't track deleted exe the same way
            thread_count: 1,     // not easily available via ps
        });
    }

    result
}

/// Try to determine the executable path for a process.
///
/// Strategy:
/// 1. On FreeBSD, try `procstat -b <pid>` which reports the exact binary path.
/// 2. Fall back to the first token of the `args` column if it starts with `/`
///    (indicating an absolute path).
///
/// Returns None if neither approach yields a path.
fn extract_exe_path(pid: u32, args: &str) -> Option<String> {
    // Try procstat on FreeBSD
    #[cfg(target_os = "freebsd")]
    {
        if let Some(path) = procstat_exe_path(pid) {
            return Some(path);
        }
    }

    // Fallback: first token of args if it looks like an absolute path
    let first_token = args.split_whitespace().next().unwrap_or("");
    if first_token.starts_with('/') {
        Some(first_token.to_string())
    } else {
        None
    }
}

/// Use `procstat -b <pid>` on FreeBSD to get the binary path.
///
/// procstat output format:
/// ```text
///   PID COMM            PATH
///   123 imix            /tmp/imix
/// ```
/// The path is extracted as the last whitespace-delimited field.
#[cfg(target_os = "freebsd")]
fn procstat_exe_path(pid: u32) -> Option<String> {
    let output = Command::new("procstat")
        .args(["-b", &pid.to_string()])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Skip header, parse the path from the last field of each data line
    for line in stdout.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() >= 3 {
            let path = fields[fields.len() - 1];
            if path.starts_with('/') {
                return Some(path.to_string());
            }
        }
    }

    None
}
