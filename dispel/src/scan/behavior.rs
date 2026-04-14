//! Behavioral detection layer for identifying suspicious runtime activity.
//!
//! This module detects anomalous process behavior that may indicate active
//! compromise, including:
//! - Reverse shells: shell processes with file descriptors redirected to
//!   network sockets or pseudo-terminals (Linux), or shell processes with
//!   established connections to non-loopback IPs (Windows).
//! - Credential harvesting: recent access to /etc/shadow (Linux).
//! - Suspicious parent processes: shell processes spawned by unexpected parents
//!   on Windows, which may indicate an implant-spawned shell.
//!
//! Findings from this module are classified as `Tier::Behavioral` (weight 4).

use std::path::Path;

use crate::ScanResult;

/// Return true if the path refers to a known shell binary.
/// Comparison is done on the filename component only (not the full path),
/// so /usr/bin/bash and /bin/bash both match "bash".
pub fn is_shell_binary(path: &str) -> bool {
    const SHELL_NAMES: &[&str] = &[
        "bash",
        "sh",
        "zsh",
        "dash",
        "csh",
        "tcsh",
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "powershell",
    ];

    let filename = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    SHELL_NAMES.contains(&filename)
}

/// Check whether any fd in `fds` is a socket or points to ptmx while the
/// owning process is a shell binary.
///
/// `fds` is a slice of `(target, is_socket)` where `target` is the symlink
/// destination of the fd and `is_socket` indicates the kernel reported the
/// fd as a socket type.
///
/// A shell with a socket fd typically means its stdin/stdout/stderr have been
/// redirected over a network connection -- the hallmark of a reverse shell.
///
/// Returns a Behavioral Finding if the process is a shell with a socket fd.
#[cfg(target_os = "linux")]
pub fn check_fd_redirected_to_socket(
    fds: &[(&str, bool)],
    proc_name: &str,
    pid: u32,
) -> Option<crate::Finding> {
    use crate::Tier;

    if !is_shell_binary(proc_name) {
        return None;
    }

    // A socket fd is identified three ways:
    //   1. The kernel flagged it as a socket type (is_socket == true)
    //   2. The symlink target starts with "socket:" (e.g. "socket:[12345]")
    //   3. The symlink target contains "ptmx" (pseudo-terminal master, used
    //      by pty-based reverse shells)
    let has_socket = fds.iter().any(|(target, is_socket)| {
        *is_socket || target.starts_with("socket:") || target.contains("ptmx")
    });

    if has_socket {
        Some(crate::Finding::new(
            "behavior",
            "Possible reverse shell",
            Tier::Behavioral,
            format!("pid={} proc={}", pid, proc_name),
        ))
    } else {
        None
    }
}

/// Run all behavioral detection checks and return accumulated findings.
///
/// Platform-specific checks:
/// - Linux: enumerates /proc to find shell processes with socket fds;
///   checks /etc/shadow access time for credential harvesting.
/// - Windows: checks shell processes for external TCP connections and
///   suspicious parent processes.
/// - BSD: stub (not yet implemented).
pub fn scan(verbose: bool) -> ScanResult {
    let mut result = ScanResult::new();

    // --- Linux ---
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        use std::os::unix::fs::MetadataExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        use crate::{Finding, Tier};

        // 1. Enumerate processes and check shell processes for socket fd redirections.
        //    Read /proc directly so we don't depend on platform::linux which may be a stub.
        if let Ok(proc_entries) = fs::read_dir("/proc") {
            for entry in proc_entries.flatten() {
                let fname = entry.file_name();
                let fname_str = fname.to_string_lossy();

                // Only process numeric directories (PIDs)
                let pid: u32 = match fname_str.parse() {
                    Ok(n) => n,
                    Err(_) => continue,
                };

                // Read the process executable name via /proc/<pid>/comm
                let comm_path = format!("/proc/{}/comm", pid);
                let proc_name = match fs::read_to_string(&comm_path) {
                    Ok(s) => s.trim().to_string(),
                    Err(_) => continue,
                };

                // Skip non-shell processes early to avoid expensive fd enumeration
                if !is_shell_binary(&proc_name) {
                    continue;
                }

                // Enumerate file descriptors for this shell process.
                // Each fd is a symlink under /proc/<pid>/fd/ pointing to the
                // underlying resource (file, socket, pipe, etc.).
                let fd_dir = format!("/proc/{}/fd", pid);
                let fds: Vec<(String, bool)> = match fs::read_dir(&fd_dir) {
                    Ok(entries) => entries
                        .flatten()
                        .filter_map(|fd_entry| {
                            let link_target = fs::read_link(fd_entry.path()).ok()?;
                            let target_str = link_target.to_string_lossy().to_string();
                            let is_socket = target_str.starts_with("socket:");
                            Some((target_str, is_socket))
                        })
                        .collect(),
                    Err(_) => continue,
                };

                // Convert owned strings to borrowed references for the check function
                let fd_refs: Vec<(&str, bool)> =
                    fds.iter().map(|(s, b)| (s.as_str(), *b)).collect();

                if let Some(finding) = check_fd_redirected_to_socket(&fd_refs, &proc_name, pid) {
                    if verbose {
                        eprintln!(
                            "[behavior] possible reverse shell: pid={} proc={}",
                            pid, proc_name
                        );
                    }
                    result.add_finding(finding);
                }
            }
        }

        // 2. Check /etc/shadow atime -- if accessed in the last 60 seconds,
        //    something read the shadow file recently. This is a strong indicator
        //    of credential harvesting (e.g. `cat /etc/shadow` or password cracking).
        {
            let shadow_path = "/etc/shadow";
            if let Ok(meta) = fs::metadata(shadow_path) {
                let atime_secs = meta.atime() as u64;
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                if now_secs >= atime_secs && (now_secs - atime_secs) <= 60 {
                    if verbose {
                        eprintln!(
                            "[behavior] /etc/shadow accessed within the last 60 seconds"
                        );
                    }
                    result.add_finding(Finding::new(
                        "behavior",
                        "/etc/shadow accessed recently (possible credential harvesting)",
                        Tier::Behavioral,
                        format!(
                            "path={} atime_delta_secs={}",
                            shadow_path,
                            now_secs - atime_secs
                        ),
                    ));
                }
            }
        }
    }

    // --- Windows ---
    #[cfg(windows)]
    {
        use crate::{Finding, Tier};
        use crate::platform::windows;

        // Known legitimate parent processes for shell binaries on Windows.
        // Shells spawned by processes NOT in this list are flagged as suspicious.
        const EXPECTED_PARENTS: &[&str] = &[
            "explorer.exe",
            "services.exe",
            "svchost.exe",
            "winlogon.exe",
            "userinit.exe",
            "conhost.exe",
        ];

        // Windows shell binary names (lowercase for case-insensitive comparison)
        const WIN_SHELLS: &[&str] = &[
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
        ];

        let procs = windows::enumerate_processes();

        // Build a PID -> process name lookup for parent process checks
        let pid_to_name: std::collections::HashMap<u32, &str> = procs
            .iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect();

        // Get TCP connections to correlate with shell processes
        let connections = windows::read_tcp_connections();

        for proc_info in &procs {
            let lower_name = proc_info.name.to_lowercase();
            if !WIN_SHELLS.contains(&lower_name.as_str()) {
                continue;
            }

            // Check if this shell PID has an ESTABLISHED TCP connection
            // to a non-loopback IP. This pattern (shell + external connection)
            // strongly suggests a reverse shell or remote access tool.
            let shell_connections: Vec<&windows::WindowsTcpConnection> = connections
                .iter()
                .filter(|c| c.owning_pid == proc_info.pid && c.state == "ESTABLISHED")
                .filter(|c| {
                    // Filter to non-loopback remote addresses
                    !c.remote_addr.starts_with("127.")
                        && c.remote_addr != "0.0.0.0"
                        && c.remote_addr != "::1"
                        && c.remote_addr != "[::1]"
                })
                .collect();

            if !shell_connections.is_empty() {
                let remote_addrs: Vec<String> = shell_connections
                    .iter()
                    .map(|c| format!("{}:{}", c.remote_addr, c.remote_port))
                    .collect();

                if verbose {
                    eprintln!(
                        "[behavior] shell {} (PID {}) has external connections: {:?}",
                        proc_info.name, proc_info.pid, remote_addrs
                    );
                }

                result.add_finding(Finding::new(
                    "behavior",
                    "Shell process with external network connection (possible reverse shell)",
                    Tier::Behavioral,
                    format!(
                        "pid={} proc={} remote={}",
                        proc_info.pid,
                        proc_info.name,
                        remote_addrs.join(",")
                    ),
                ));
            }
        }

        // Re-enumerate with parent PID tracking for suspicious parent detection.
        // Uses CreateToolhelp32Snapshot which exposes th32ParentProcessID.
        check_shell_parents_windows(&procs, &pid_to_name, verbose, &mut result);
    }

    // --- BSD stub ---
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        // TODO: enumerate BSD processes for shell fd redirections
    }

    let _ = verbose; // suppress unused warning when no platform matches

    result
}

/// Check shell processes for suspicious parent processes on Windows.
///
/// Uses CreateToolhelp32Snapshot to get parent PIDs, then flags shells whose
/// parent is not in the expected parents list. An unexpected parent (e.g. a
/// webserver or random executable spawning cmd.exe) indicates an implant or
/// exploit may have spawned a shell.
#[cfg(windows)]
fn check_shell_parents_windows(
    procs: &[crate::platform::ProcessInfo],
    pid_to_name: &std::collections::HashMap<u32, &str>,
    verbose: bool,
    result: &mut ScanResult,
) {
    use crate::{Finding, Tier};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::Foundation::CloseHandle;

    // Extended expected parents list including common legitimate shell parents.
    // SSH daemons and existing shells are expected to spawn new shells.
    const EXPECTED_PARENTS: &[&str] = &[
        "explorer.exe",
        "services.exe",
        "svchost.exe",
        "winlogon.exe",
        "userinit.exe",
        "conhost.exe",
        "wmiprvse.exe",
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "openssh.exe",
        "sshd.exe",
    ];

    const WIN_SHELLS: &[&str] = &[
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
    ];

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return;
        }

        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) != 0 {
            loop {
                // Extract null-terminated process name from the fixed-size char array
                let name = entry
                    .szExeFile
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8 as char)
                    .collect::<String>();

                let lower_name = name.to_lowercase();
                if WIN_SHELLS.contains(&lower_name.as_str()) {
                    let ppid = entry.th32ParentProcessID;
                    // Look up the parent process name from our PID map
                    let parent_name = pid_to_name
                        .get(&ppid)
                        .copied()
                        .unwrap_or("unknown");
                    let parent_lower = parent_name.to_lowercase();

                    // Flag if parent is not in the expected list
                    if !EXPECTED_PARENTS.contains(&parent_lower.as_str()) {
                        if verbose {
                            eprintln!(
                                "[behavior] shell {} (PID {}) has unexpected parent {} (PID {})",
                                name, entry.th32ProcessID, parent_name, ppid
                            );
                        }

                        result.add_finding(Finding::new(
                            "behavior",
                            "Shell process with unexpected parent (possible implant-spawned shell)",
                            Tier::Behavioral,
                            format!(
                                "pid={} proc={} ppid={} parent={}",
                                entry.th32ProcessID, name, ppid, parent_name
                            ),
                        ));
                    }
                }

                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }
}
