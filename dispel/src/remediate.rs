//! Remediation module: detect, quarantine, and remove Realm C2 implants.
//!
//! This module is the backend for `dispel kill`. It performs a four-phase
//! remediation sequence for each detected implant:
//!
//!   1. **Scan** -- Runs the proc scanner to identify implant processes via
//!      behavioral and signature-based heuristics (see `scan::proc`).
//!   2. **Report** -- Generates an incident-response report that groups raw
//!      findings into resolved implant records (binary path + associated PIDs).
//!   3. **Quarantine** -- Copies the implant binary to a forensic quarantine
//!      directory (named by SHA-256 prefix) before any destructive action.
//!   4. **Eradicate** -- Kills/terminates implant processes, deletes the binary
//!      from disk, and scrubs persistence mechanisms (systemd units, SysV init
//!      scripts, Windows services, registry keys, beacon ID files).
//!
//! All destructive operations respect `KillConfig::dry_run` so that operators
//! can preview actions before committing. Exit codes follow the convention:
//!   - 0 = system clean, no implants found
//!   - 1 = unsupported platform
//!   - 2 = implants detected (and killed, unless dry-run)
//!   - 3 = internal error (propagated via `anyhow`)
//!
//! Platform support: Linux (via `libc::kill` + systemd/sysvinit cleanup) and
//! Windows (via `windows-sys` `TerminateProcess` + `sc.exe`/`reg.exe` cleanup).

use std::path::PathBuf;
#[cfg(any(target_os = "linux", windows))]
use std::path::Path;

// ---------------------------------------------------------------------------
// ANSI color helpers -- lightweight terminal coloring without pulling in a
// dependency like `colored`. Each wraps the input string in an escape sequence
// and resets afterward.
// ---------------------------------------------------------------------------

/// Wrap `s` in ANSI green (used for success messages).
fn green(s: &str) -> String {
    format!("\x1b[32m{}\x1b[0m", s)
}

/// Wrap `s` in ANSI red (used for errors and alerts).
fn red(s: &str) -> String {
    format!("\x1b[31m{}\x1b[0m", s)
}

/// Wrap `s` in ANSI yellow (used for warnings and dry-run labels).
fn yellow(s: &str) -> String {
    format!("\x1b[33m{}\x1b[0m", s)
}

// ---------------------------------------------------------------------------
// Kill configuration
// ---------------------------------------------------------------------------

/// Configuration for a remediation ("kill") run.
///
/// Passed through to every remediation helper so each can check `dry_run`
/// and resolve the quarantine directory consistently.
pub struct KillConfig {
    /// When true, print what *would* happen without modifying the system.
    pub dry_run: bool,
    /// Directory where implant binaries are copied before deletion.
    /// Defaults to `/var/lib/dispel/quarantine` (Linux) or
    /// `C:\ProgramData\dispel\quarantine` (Windows).
    pub quarantine_dir: PathBuf,
    /// Emit extra diagnostic output to stderr.
    pub verbose: bool,
}

impl KillConfig {
    /// Build a new `KillConfig`, selecting the platform-appropriate default
    /// quarantine directory if none is provided.
    pub fn new(dry_run: bool, quarantine_dir: Option<PathBuf>, verbose: bool) -> Self {
        let qdir = quarantine_dir.unwrap_or_else(|| {
            #[cfg(windows)]
            {
                PathBuf::from(r"C:\ProgramData\dispel\quarantine")
            }
            #[cfg(not(windows))]
            {
                PathBuf::from("/var/lib/dispel/quarantine")
            }
        });
        Self { dry_run, quarantine_dir: qdir, verbose }
    }
}

// ---------------------------------------------------------------------------
// Top-level dispatch
// ---------------------------------------------------------------------------

/// Entry point for `dispel kill`.
///
/// Dispatches to the platform-specific implementation. Returns an exit code:
///   - 0 = clean (no implants found)
///   - 1 = unsupported platform
///   - 2 = implants found and acted upon (or would be, in dry-run mode)
pub fn run_kill(cfg: &KillConfig) -> anyhow::Result<i32> {
    #[cfg(target_os = "linux")]
    {
        return run_kill_linux(cfg);
    }

    #[cfg(windows)]
    {
        return run_kill_windows(cfg);
    }

    // Fallback for macOS, BSDs, etc. -- scanning is not implemented there.
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = cfg; // suppress unused-variable warning on unsupported platforms
        eprintln!("{}", red("Kill command is only supported on Linux and Windows."));
        return Ok(1);
    }
}

// ===========================================================================
// Linux kill implementation
// ===========================================================================

/// Linux-specific remediation pipeline.
///
/// Runs the proc scanner, generates an IR report, then for each resolved
/// implant: quarantines the binary, kills its PIDs, deletes it, and removes
/// persistence artifacts.
#[cfg(target_os = "linux")]
fn run_kill_linux(cfg: &KillConfig) -> anyhow::Result<i32> {
    use crate::ir::generate_report;
    use crate::scan;
    use crate::Severity;

    // Phase 1: scan /proc for implant indicators
    let result = scan::proc::scan(cfg.verbose);

    if result.severity == Severity::Clean {
        println!("{}", green("No Realm C2 implants detected."));
        return Ok(0);
    }

    // Phase 2: generate IR report -- this correlates raw findings into
    // implant records with resolved binary paths and associated PIDs
    let report = generate_report(&result);

    if report.implants.is_empty() {
        // The scanner found suspicious indicators but could not resolve them
        // to a concrete binary path. This can happen when the implant deletes
        // itself after exec or when /proc/<pid>/exe is unreadable. Print the
        // raw findings so the operator can investigate manually.
        println!(
            "{} {} finding(s), but no binary paths resolved. Manual investigation required.",
            yellow("WARNING:"),
            result.findings.len()
        );
        for f in &result.findings {
            println!("  [{}] {} — {}", f.tier.label(), f.description, f.detail);
        }
        return Ok(2);
    }

    println!(
        "{} {} Realm C2 implant(s) detected.",
        red("DETECTED:"),
        report.implants.len()
    );
    if cfg.dry_run {
        println!("{}", yellow("DRY RUN — no changes will be made."));
    }
    println!();

    // Phase 3: remediate each implant in sequence
    for implant in &report.implants {
        println!("--- {}", implant.summary_line());
        println!();

        let pids: Vec<u32> = implant.processes.iter().map(|p| p.pid).collect();

        // (a) Quarantine -- preserve a copy for forensic analysis before
        //     any destructive action. Must happen before kill, because
        //     killing the process may cause the kernel to release the
        //     last reference to a deleted-but-open binary.
        quarantine_binary(cfg, &implant.path, &pids);

        // (b) Kill -- SIGKILL all associated PIDs to stop C2 communication
        kill_processes(cfg, &pids, &implant.path);

        // (c) Delete -- remove the binary from disk so it cannot be re-exec'd
        remove_binary(cfg, &implant.path);

        // (d) Persistence -- scrub systemd units, sysvinit scripts, and
        //     beacon ID files that would re-spawn the implant on reboot
        remove_persistence(cfg);

        println!();
    }

    Ok(2)
}

/// Copy the implant binary to the quarantine directory before destruction.
///
/// The quarantine filename is `<sha256_prefix_16>_<original_basename>` to
/// avoid collisions while keeping the original name visible.
///
/// If the binary has already been unlinked from the filesystem (common with
/// Realm's self-delete behavior), falls back to reading via `/proc/<pid>/exe`
/// which remains valid as long as the process holds an open fd.
#[cfg(target_os = "linux")]
fn quarantine_binary(cfg: &KillConfig, binary_path: &str, pids: &[u32]) {
    use sha2::{Digest, Sha256};
    use std::fs;

    // Determine source path: prefer the on-disk file, fall back to the
    // /proc/<pid>/exe symlink which the kernel keeps alive while the
    // process is running even if the file is unlinked.
    let source = if Path::new(binary_path).exists() {
        binary_path.to_string()
    } else if let Some(&pid) = pids.first() {
        let proc_exe = format!("/proc/{}/exe", pid);
        if Path::new(&proc_exe).exists() {
            if cfg.verbose {
                eprintln!("[quarantine] Binary deleted from disk, using {}", proc_exe);
            }
            proc_exe
        } else {
            println!(
                "  {} quarantine: binary not on disk and no /proc/exe available ({})",
                red("SKIP"),
                binary_path
            );
            return;
        }
    } else {
        println!(
            "  {} quarantine: binary not found and no PIDs to fall back to ({})",
            red("SKIP"),
            binary_path
        );
        return;
    };

    // Read the binary and compute SHA-256 for the quarantine filename.
    // Reading the full file into memory is acceptable since implant
    // binaries are typically small (< 50 MB).
    let hash = match fs::read(&source) {
        Ok(data) => {
            let mut h = Sha256::new();
            h.update(&data);
            format!("{:x}", h.finalize())
        }
        Err(e) => {
            println!(
                "  {} quarantine: cannot read {} — {}",
                red("ERROR"),
                source,
                e
            );
            return;
        }
    };

    // Extract the original filename for human-readable quarantine naming
    let basename = Path::new(binary_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Use first 16 hex chars of SHA-256 as prefix -- enough to be unique
    // while keeping filenames manageable
    let dest_name = format!("{}_{}", &hash[..16], basename);
    let dest = cfg.quarantine_dir.join(&dest_name);

    if cfg.dry_run {
        println!(
            "  {} would quarantine {} -> {}",
            yellow("DRY-RUN"),
            source,
            dest.display()
        );
        return;
    }

    // Ensure the quarantine directory tree exists
    if let Err(e) = fs::create_dir_all(&cfg.quarantine_dir) {
        println!(
            "  {} quarantine: cannot create dir {} — {}",
            red("ERROR"),
            cfg.quarantine_dir.display(),
            e
        );
        return;
    }

    match fs::copy(&source, &dest) {
        Ok(bytes) => println!(
            "  {} quarantined {} -> {} ({} bytes)",
            green("OK"),
            source,
            dest.display(),
            bytes
        ),
        Err(e) => println!(
            "  {} quarantine: copy failed {} -> {} — {}",
            red("ERROR"),
            source,
            dest.display(),
            e
        ),
    }
}

/// Send SIGKILL to all PIDs associated with the implant.
///
/// Uses `libc::kill(2)` directly rather than shelling out, for reliability
/// and to avoid spawning a child process that the implant could intercept.
/// SIGKILL is chosen over SIGTERM because malware can trap SIGTERM.
#[cfg(target_os = "linux")]
fn kill_processes(cfg: &KillConfig, pids: &[u32], binary_path: &str) {
    if pids.is_empty() {
        println!(
            "  {} no live PIDs found for {}",
            yellow("NOTE"),
            binary_path
        );
        return;
    }

    for &pid in pids {
        if cfg.dry_run {
            println!(
                "  {} would SIGKILL PID {}",
                yellow("DRY-RUN"),
                pid
            );
            continue;
        }

        // SAFETY: kill(2) with SIGKILL is a standard POSIX operation.
        // The cast to pid_t is safe because we only store valid u32 PIDs
        // and pid_t is i32 on Linux (max PID is 2^22 by default).
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if ret == 0 {
            println!("  {} SIGKILL -> PID {}", green("OK"), pid);
        } else {
            // Common failures: ESRCH (process already exited), EPERM (not root)
            let err = std::io::Error::last_os_error();
            println!("  {} kill PID {} — {}", red("ERROR"), pid, err);
        }
    }
}

/// Delete the implant binary from disk.
///
/// Called after quarantine and kill so the binary cannot be re-exec'd by a
/// persistence mechanism (cron, systemd restart, etc.). If the file is
/// already gone (e.g., self-deleting implant), this is a no-op.
#[cfg(target_os = "linux")]
fn remove_binary(cfg: &KillConfig, binary_path: &str) {
    let p = Path::new(binary_path);

    if !p.exists() {
        println!("  {} binary already gone: {}", yellow("NOTE"), binary_path);
        return;
    }

    if cfg.dry_run {
        println!("  {} would delete {}", yellow("DRY-RUN"), binary_path);
        return;
    }

    match std::fs::remove_file(p) {
        Ok(()) => println!("  {} deleted {}", green("OK"), binary_path),
        Err(e) => println!("  {} delete {} — {}", red("ERROR"), binary_path, e),
    }
}

/// Remove Linux persistence artifacts left by Realm C2 implants.
///
/// Targets three categories of persistence:
///   - **Beacon ID files**: unique host identifiers written to well-known
///     paths that the C2 server uses to track compromised hosts.
///   - **Systemd units**: service files that auto-restart the implant.
///     After removal, triggers `systemctl daemon-reload` so systemd
///     picks up the change immediately.
///   - **SysV init script**: legacy init persistence for non-systemd hosts.
///
/// Paths are defined in `signatures::strings` to keep them in sync with
/// the detection scanner.
#[cfg(target_os = "linux")]
fn remove_persistence(cfg: &KillConfig) {
    use crate::signatures::strings::{BEACON_ID_PATHS_LINUX, SYSTEMD_PATHS, SYSVINIT_PATH};

    // Beacon ID files -- removing these forces the implant (if somehow
    // restarted) to re-register with the C2, which is noisier and gives
    // defenders another detection opportunity.
    for path in BEACON_ID_PATHS_LINUX {
        remove_file_if_exists(cfg, path, "beacon ID file");
    }

    // Systemd unit files -- track whether any were removed so we only
    // call daemon-reload when necessary (avoids spurious warnings on
    // systems where systemd is not running).
    let mut removed_systemd = false;
    for path in SYSTEMD_PATHS {
        if remove_file_if_exists(cfg, path, "systemd unit") {
            removed_systemd = true;
        }
    }

    // Reload systemd if we removed (or would remove in dry-run) any units
    if removed_systemd || cfg.dry_run {
        reload_systemd(cfg);
    }

    // SysV init script -- single well-known path
    remove_file_if_exists(cfg, SYSVINIT_PATH, "sysvinit script");
}

/// Delete a file if it exists, with dry-run support and labeled output.
///
/// Returns `true` if the file existed and was removed (or would be in
/// dry-run mode). Used by `remove_persistence` to track whether any
/// systemd units were cleaned up.
#[cfg(target_os = "linux")]
fn remove_file_if_exists(cfg: &KillConfig, path: &str, label: &str) -> bool {
    if !Path::new(path).exists() {
        return false;
    }

    if cfg.dry_run {
        println!("  {} would delete {} ({})", yellow("DRY-RUN"), path, label);
        return true;
    }

    match std::fs::remove_file(path) {
        Ok(()) => {
            println!("  {} deleted {} ({})", green("OK"), path, label);
            true
        }
        Err(e) => {
            println!("  {} delete {} ({}) — {}", red("ERROR"), path, label, e);
            false
        }
    }
}

/// Run `systemctl daemon-reload` to force systemd to re-read its unit
/// file directories after we removed implant service files.
///
/// Non-fatal: logs a warning instead of failing if systemd is unavailable
/// (e.g., container environments, SysV-only hosts).
#[cfg(target_os = "linux")]
fn reload_systemd(cfg: &KillConfig) {
    if cfg.dry_run {
        println!("  {} would run: systemctl daemon-reload", yellow("DRY-RUN"));
        return;
    }

    match std::process::Command::new("systemctl")
        .arg("daemon-reload")
        .status()
    {
        Ok(status) if status.success() => {
            println!("  {} systemctl daemon-reload", green("OK"));
        }
        Ok(status) => {
            println!(
                "  {} systemctl daemon-reload exited with status {}",
                yellow("WARN"),
                status
            );
        }
        Err(e) => {
            // This is expected in containers or on SysV-only hosts where
            // systemctl is not available. Not a hard failure.
            println!(
                "  {} systemctl daemon-reload — {} (systemd may not be present)",
                yellow("WARN"),
                e
            );
        }
    }
}

// ===========================================================================
// Windows kill implementation
// ===========================================================================

/// Windows-specific remediation pipeline.
///
/// Mirrors the Linux flow but uses Windows-native APIs and tools:
///   - `TerminateProcess` via `windows-sys` instead of `kill(2)`
///   - `sc.exe` for service management instead of systemd
///   - `reg.exe` for registry cleanup (Realm stores config in `HKLM\SOFTWARE\Imix`)
///   - No /proc fallback for quarantine (Windows does not expose exe via procfs)
#[cfg(windows)]
fn run_kill_windows(cfg: &KillConfig) -> anyhow::Result<i32> {
    use crate::ir::generate_report;
    use crate::scan;
    use crate::Severity;

    // Phase 1: scan for implant processes
    let result = scan::proc::scan(cfg.verbose);

    if result.severity == Severity::Clean {
        println!("{}", green("No Realm C2 implants detected."));
        return Ok(0);
    }

    // Phase 2: generate IR report to correlate findings into implant records
    let report = generate_report(&result);

    if report.implants.is_empty() {
        // Findings exist but no binary paths could be resolved -- the
        // operator needs to investigate manually.
        println!(
            "{} {} finding(s), but no binary paths resolved. Manual investigation required.",
            yellow("WARNING:"),
            result.findings.len()
        );
        for f in &result.findings {
            println!("  [{}] {} — {}", f.tier.label(), f.description, f.detail);
        }
        return Ok(2);
    }

    println!(
        "{} {} Realm C2 implant(s) detected.",
        red("DETECTED:"),
        report.implants.len()
    );
    if cfg.dry_run {
        println!("{}", yellow("DRY RUN — no changes will be made."));
    }
    println!();

    // Phase 3: remediate each implant
    for implant in &report.implants {
        println!("--- {}", implant.summary_line());
        println!();

        let pids: Vec<u32> = implant.processes.iter().map(|p| p.pid).collect();

        // (a) Quarantine -- no /proc fallback on Windows; if the binary
        //     is not on disk, quarantine is skipped.
        quarantine_binary_windows(cfg, &implant.path);

        // (b) Terminate -- TerminateProcess with exit code 1
        terminate_processes_windows(cfg, &pids, &implant.path);

        // (c) Delete the binary from disk
        remove_binary_windows(cfg, &implant.path);

        // (d) Persistence -- registry keys, services, beacon ID files
        remove_persistence_windows(cfg);

        println!();
    }

    Ok(2)
}

/// Copy the implant binary to the quarantine directory on Windows.
///
/// Unlike the Linux variant, there is no `/proc/<pid>/exe` fallback. If the
/// binary has been deleted from disk, quarantine is skipped and the operator
/// is notified.
#[cfg(windows)]
fn quarantine_binary_windows(cfg: &KillConfig, binary_path: &str) {
    use sha2::{Digest, Sha256};
    use std::fs;

    if !Path::new(binary_path).exists() {
        println!(
            "  {} quarantine: binary not found on disk ({})",
            red("SKIP"),
            binary_path
        );
        return;
    }

    // Read the binary and compute SHA-256 for the quarantine filename
    let hash = match fs::read(binary_path) {
        Ok(data) => {
            let mut h = Sha256::new();
            h.update(&data);
            format!("{:x}", h.finalize())
        }
        Err(e) => {
            println!(
                "  {} quarantine: cannot read {} — {}",
                red("ERROR"),
                binary_path,
                e
            );
            return;
        }
    };

    // Extract the original filename for human-readable naming
    let basename = Path::new(binary_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // First 16 hex chars of SHA-256 prefix + original name
    let dest_name = format!("{}_{}", &hash[..16], basename);
    let dest = cfg.quarantine_dir.join(&dest_name);

    if cfg.dry_run {
        println!(
            "  {} would quarantine {} -> {}",
            yellow("DRY-RUN"),
            binary_path,
            dest.display()
        );
        return;
    }

    // Ensure the quarantine directory tree exists
    if let Err(e) = fs::create_dir_all(&cfg.quarantine_dir) {
        println!(
            "  {} quarantine: cannot create dir {} — {}",
            red("ERROR"),
            cfg.quarantine_dir.display(),
            e
        );
        return;
    }

    match fs::copy(binary_path, &dest) {
        Ok(bytes) => println!(
            "  {} quarantined {} -> {} ({} bytes)",
            green("OK"),
            binary_path,
            dest.display(),
            bytes
        ),
        Err(e) => println!(
            "  {} quarantine: copy failed {} -> {} — {}",
            red("ERROR"),
            binary_path,
            dest.display(),
            e
        ),
    }
}

/// Terminate processes on Windows using the Win32 `TerminateProcess` API.
///
/// Opens each PID with `PROCESS_TERMINATE` access, then calls
/// `TerminateProcess` with exit code 1. The handle is always closed
/// afterward, even on failure.
///
/// Requires the calling process to have `SeDebugPrivilege` or be running
/// as Administrator to terminate elevated processes.
#[cfg(windows)]
fn terminate_processes_windows(cfg: &KillConfig, pids: &[u32], binary_path: &str) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, TerminateProcess, PROCESS_TERMINATE,
    };

    if pids.is_empty() {
        println!(
            "  {} no live PIDs found for {}",
            yellow("NOTE"),
            binary_path
        );
        return;
    }

    for &pid in pids {
        if cfg.dry_run {
            println!(
                "  {} would TerminateProcess PID {}",
                yellow("DRY-RUN"),
                pid
            );
            continue;
        }

        // SAFETY: Win32 API calls with proper handle management.
        // OpenProcess returns NULL on failure; we check before using.
        // CloseHandle is called unconditionally after TerminateProcess.
        unsafe {
            // Request a handle with only PROCESS_TERMINATE rights
            // (principle of least privilege)
            let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if handle.is_null() {
                let err = std::io::Error::last_os_error();
                println!("  {} OpenProcess PID {} — {}", red("ERROR"), pid, err);
                continue;
            }

            // Exit code 1 signals abnormal termination
            let ret = TerminateProcess(handle, 1);
            CloseHandle(handle);

            // TerminateProcess returns nonzero on success (Win32 BOOL convention)
            if ret != 0 {
                println!("  {} TerminateProcess -> PID {}", green("OK"), pid);
            } else {
                let err = std::io::Error::last_os_error();
                println!("  {} TerminateProcess PID {} — {}", red("ERROR"), pid, err);
            }
        }
    }
}

/// Delete the implant binary from disk on Windows.
///
/// Called after quarantine and terminate. If the file is locked by another
/// process, deletion will fail with a sharing violation -- the operator
/// should verify all implant processes were terminated.
#[cfg(windows)]
fn remove_binary_windows(cfg: &KillConfig, binary_path: &str) {
    let p = Path::new(binary_path);

    if !p.exists() {
        println!("  {} binary already gone: {}", yellow("NOTE"), binary_path);
        return;
    }

    if cfg.dry_run {
        println!("  {} would delete {}", yellow("DRY-RUN"), binary_path);
        return;
    }

    match std::fs::remove_file(p) {
        Ok(()) => println!("  {} deleted {}", green("OK"), binary_path),
        Err(e) => println!("  {} delete {} — {}", red("ERROR"), binary_path, e),
    }
}

/// Remove Windows persistence artifacts left by Realm C2 implants.
///
/// Targets three categories:
///   1. **Registry keys**: Realm's "Imix" variant stores configuration under
///      `HKLM\SOFTWARE\Imix`. Removed via `reg.exe delete /f`.
///   2. **Windows services**: Realm registers itself as a Windows service
///      for auto-start persistence. Stopped via `sc.exe stop`, then
///      deleted via `sc.exe delete`.
///   3. **Beacon ID files**: host-unique identifier files at well-known
///      Windows paths (e.g., `C:\ProgramData\...`).
#[cfg(windows)]
fn remove_persistence_windows(cfg: &KillConfig) {
    use crate::signatures::strings::{BEACON_ID_PATHS_WINDOWS, TIER1_SERVICE_NAMES};

    // 1. Delete the Imix registry key (stores C2 config/callback URL)
    remove_registry_key_windows(cfg, r"SOFTWARE\Imix");

    // 2. Stop and delete each known implant service
    for svc_name in TIER1_SERVICE_NAMES {
        stop_and_delete_service_windows(cfg, svc_name);
    }

    // 3. Remove beacon ID files
    for path in BEACON_ID_PATHS_WINDOWS {
        remove_file_if_exists_windows(cfg, path, "beacon ID file");
    }
}

/// Delete a registry key under HKLM using `reg.exe`.
///
/// First queries whether the key exists (via `reg.exe query`) to avoid
/// noisy error output for keys that were never created. Uses `/f` to
/// force deletion without confirmation prompt.
#[cfg(windows)]
fn remove_registry_key_windows(cfg: &KillConfig, subkey: &str) {
    use std::process::Command;

    let full_key = format!(r"HKLM\{}", subkey);

    // Probe for the key's existence before attempting deletion.
    // reg.exe query returns success (0) if the key exists.
    let query = Command::new("reg.exe")
        .args(["query", &full_key])
        .output();

    let exists = match query {
        Ok(out) => out.status.success(),
        Err(_) => false,
    };

    if !exists {
        return; // Key does not exist -- nothing to do
    }

    if cfg.dry_run {
        println!(
            "  {} would delete registry key {}",
            yellow("DRY-RUN"),
            full_key
        );
        return;
    }

    // /f = force deletion without interactive confirmation
    match Command::new("reg.exe")
        .args(["delete", &full_key, "/f"])
        .status()
    {
        Ok(status) if status.success() => {
            println!("  {} deleted registry key {}", green("OK"), full_key);
        }
        Ok(status) => {
            println!(
                "  {} delete registry key {} — exited with {}",
                red("ERROR"),
                full_key,
                status
            );
        }
        Err(e) => {
            println!(
                "  {} delete registry key {} — {}",
                red("ERROR"),
                full_key,
                e
            );
        }
    }
}

/// Stop and delete a Windows service using `sc.exe`.
///
/// The service is first queried to confirm it exists. If it does, we stop
/// it (ignoring errors since it may already be stopped) and then delete it.
/// Deletion removes the service entry from the SCM database so it will not
/// start on next boot.
#[cfg(windows)]
fn stop_and_delete_service_windows(cfg: &KillConfig, svc_name: &str) {
    use std::process::Command;

    // Query the service to determine if it exists. sc.exe query prints the
    // service state; we check for any recognized state string rather than
    // relying on the exit code alone (which can be ambiguous).
    let query = Command::new("sc.exe")
        .args(["query", svc_name])
        .output();

    let exists = match query {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Any of these states confirms the service is registered in
            // the Service Control Manager database.
            stdout.contains("RUNNING")
                || stdout.contains("STOPPED")
                || stdout.contains("PAUSED")
                || stdout.contains("START_PENDING")
                || stdout.contains("STOP_PENDING")
        }
        Err(_) => false,
    };

    if !exists {
        return; // Service not registered -- skip
    }

    if cfg.dry_run {
        println!(
            "  {} would stop and delete service '{}'",
            yellow("DRY-RUN"),
            svc_name
        );
        return;
    }

    // Stop the service first. Ignore non-zero exit -- the service may
    // already be in STOPPED state, which causes sc.exe to return an error.
    let stop_result = Command::new("sc.exe")
        .args(["stop", svc_name])
        .output();

    match stop_result {
        Ok(out) if out.status.success() => {
            println!("  {} stopped service '{}'", green("OK"), svc_name);
        }
        Ok(_) => {
            // Non-zero exit is expected if the service was already stopped
            if cfg.verbose {
                eprintln!("[remediate] sc.exe stop {} returned non-zero (may already be stopped)", svc_name);
            }
        }
        Err(e) => {
            println!("  {} stop service '{}' — {}", yellow("WARN"), svc_name, e);
        }
    }

    // Delete the service entry from the SCM database. This prevents the
    // implant from being started again via the service manager.
    match Command::new("sc.exe")
        .args(["delete", svc_name])
        .status()
    {
        Ok(status) if status.success() => {
            println!("  {} deleted service '{}'", green("OK"), svc_name);
        }
        Ok(status) => {
            println!(
                "  {} delete service '{}' — exited with {}",
                red("ERROR"),
                svc_name,
                status
            );
        }
        Err(e) => {
            println!(
                "  {} delete service '{}' — {}",
                red("ERROR"),
                svc_name,
                e
            );
        }
    }
}

/// Delete a file if it exists on Windows, with dry-run support.
///
/// Returns `true` if the file existed and was removed (or would be).
#[cfg(windows)]
fn remove_file_if_exists_windows(cfg: &KillConfig, path: &str, label: &str) -> bool {
    if !Path::new(path).exists() {
        return false;
    }

    if cfg.dry_run {
        println!("  {} would delete {} ({})", yellow("DRY-RUN"), path, label);
        return true;
    }

    match std::fs::remove_file(path) {
        Ok(()) => {
            println!("  {} deleted {} ({})", green("OK"), path, label);
            true
        }
        Err(e) => {
            println!("  {} delete {} ({}) — {}", red("ERROR"), path, label, e);
            false
        }
    }
}
