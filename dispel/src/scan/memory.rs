//! Live process memory scanner for Realm C2 implant detection.
//!
//! This module complements filesystem-based binary scanning by inspecting the
//! memory of running processes. It detects indicators that persist even when the
//! on-disk binary has been deleted, packed, or was never written to disk at all
//! (fileless execution). The scanner operates on both Linux and Windows, using
//! platform-specific APIs to enumerate processes and read their virtual memory.
//!
//! Detection techniques implemented here:
//!
//! 1. **Process masquerading** -- detects when a process's actual executable
//!    (`/proc/<pid>/exe`) differs from what it reports as `argv[0]`, which is a
//!    common evasion tactic used by implants to blend in with legitimate services.
//!
//! 2. **Suspicious environment variables** -- checks each process's environment
//!    block for variables with prefixes associated with IMIX (Realm's implant) or
//!    generic C2 beacon configuration.
//!
//! 3. **Memory map analysis** -- parses `/proc/<pid>/maps` to flag anonymous RWX
//!    regions (code injection), memfd-backed executable mappings (fileless exec),
//!    and shared libraries loaded from world-writable or hidden directories.
//!
//! 4. **memfd file descriptor detection** -- enumerates `/proc/<pid>/fd/` for open
//!    memfd handles, which are used for in-memory-only payload staging.
//!
//! 5. **In-memory signature scanning** -- reads process memory via `pread(2)` (Linux)
//!    or `ReadProcessMemory` (Windows) and runs Aho-Corasick pattern matching against
//!    known Realm/IMIX byte sequences. A per-process threshold of 3+ unique matches
//!    is required to suppress false positives from incidental string presence.
//!
//! 6. **Thread start address analysis** (Windows only) -- queries each thread's start
//!    address via `NtQueryInformationThread` and flags threads originating from
//!    non-image (private) memory, a hallmark of reflective injection.

use crate::{Finding, ScanResult, Tier};

/// Top-level entry point for the memory scanner.
///
/// Dispatches to the platform-specific implementation based on compile target.
/// Skips the calling process (`self_pid`) to avoid self-detection.
/// When `verbose` is true, diagnostic messages are written to stderr.
pub fn scan(verbose: bool) -> ScanResult {
    let mut result = ScanResult::new();
    let self_pid = std::process::id();

    #[cfg(target_os = "linux")]
    {
        scan_linux(&mut result, self_pid, verbose);
    }

    #[cfg(windows)]
    {
        scan_windows(&mut result, self_pid, verbose);
    }

    // Suppress "unused variable" warnings on platforms where neither cfg applies.
    let _ = (verbose, self_pid);
    result
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

/// Iterates over `/proc` to enumerate all running processes and applies each
/// detection technique in sequence. Each check is independent -- a failure
/// to read one proc file (e.g., due to permissions) does not prevent other
/// checks from running on the same process.
#[cfg(target_os = "linux")]
fn scan_linux(result: &mut ScanResult, self_pid: u32, verbose: bool) {
    use crate::scan::proc::BinaryScanner;
    use std::fs;

    let scanner = BinaryScanner::new();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    for entry in proc_dir.flatten() {
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();

        // Only numeric directory names correspond to PIDs; skip everything else
        // (e.g., /proc/self, /proc/net, /proc/sys).
        let pid: u32 = match fname_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        // Avoid scanning ourselves -- our own memory contains the signature
        // patterns we're searching for, which would cause a false positive.
        if pid == self_pid {
            continue;
        }

        let pid_path = format!("/proc/{}", pid);

        // Read the short process name from /proc/<pid>/comm (max 16 chars,
        // kernel-truncated). Used in findings for human-readable identification.
        let proc_name = fs::read_to_string(format!("{}/comm", pid_path))
            .unwrap_or_default()
            .trim()
            .to_string();
        if proc_name.is_empty() {
            continue;
        }

        // 1. Process masquerading detection
        check_masquerading(result, pid, &pid_path, &proc_name, verbose);

        // 2. Environment variable inspection
        check_environ(result, pid, &pid_path, &proc_name, verbose);

        // 3. Memory maps analysis (anonymous exec, memfd, suspicious .so paths)
        let maps = check_maps(result, pid, &pid_path, &proc_name, verbose);

        // 4. memfd file descriptor detection
        check_memfd_fds(result, pid, &pid_path, &proc_name, verbose);

        // 5. Process memory scanning for Realm/IMIX byte signatures.
        // Terminal multiplexers and session managers (sshd, tmux, screen, etc.)
        // are skipped because their PTY buffers often contain our own scan
        // output text, leading to false positives.
        if let Some(ref regions) = maps {
            let skip_mem_scan = matches!(
                proc_name.as_str(),
                "sshd" | "login" | "su" | "sudo" | "screen" | "tmux" | "script"
            );
            if !skip_mem_scan {
                scan_process_memory(result, &scanner, pid, &pid_path, &proc_name, regions, verbose);
            }
        }
    }
}

/// A single contiguous memory region parsed from `/proc/<pid>/maps`.
///
/// Each line in the maps file describes one VMA (virtual memory area) with its
/// address range, permission flags, and optional backing file path.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct MemRegion {
    /// Start address of the mapping (inclusive).
    start: u64,
    /// End address of the mapping (exclusive).
    end: u64,
    /// Permission string from the kernel, e.g. "rwxp" or "r--s".
    /// Characters: r/-, w/-, x/-, p(rivate)/s(hared).
    perms: String,
    /// Backing file path, or empty string for anonymous mappings.
    /// May also be a pseudo-path like "[heap]", "[stack]", or "/memfd:name".
    pathname: String,
}

#[cfg(target_os = "linux")]
impl MemRegion {
    /// Whether the region has the read permission bit set (position 0).
    fn is_readable(&self) -> bool {
        self.perms.starts_with('r')
    }

    /// Whether the region has the execute permission bit set (position 2).
    fn is_executable(&self) -> bool {
        self.perms.len() >= 3 && self.perms.as_bytes()[2] == b'x'
    }

    /// Whether the region has the write permission bit set (position 1).
    fn is_writable(&self) -> bool {
        self.perms.len() >= 2 && self.perms.as_bytes()[1] == b'w'
    }

    /// Anonymous mappings have no backing file -- their pathname field is empty.
    /// These are heap allocations, mmap(MAP_ANONYMOUS) regions, etc.
    fn is_anonymous(&self) -> bool {
        self.pathname.is_empty()
    }

    /// memfd regions use the `memfd_create(2)` syscall for in-memory file-like
    /// objects. The kernel displays these as "/memfd:<name>" or "memfd:<name>".
    fn is_memfd(&self) -> bool {
        self.pathname.starts_with("/memfd:")
            || self.pathname.starts_with("memfd:")
    }

    /// File-backed regions have a real filesystem path (starts with '/') but
    /// are NOT memfd pseudo-paths.
    fn is_file_backed(&self) -> bool {
        self.pathname.starts_with('/')
            && !self.is_memfd()
    }
}

/// Parse `/proc/<pid>/maps` into a vector of [`MemRegion`] structs.
///
/// Returns `None` if the maps file cannot be read (process exited, or
/// insufficient permissions). Each line in the file has the format:
/// ```text
/// address           perms offset  dev   inode   pathname
/// 7f8a1c000000-7f8a1c021000 rw-p 00000000 00:00 0    [heap]
/// ```
#[cfg(target_os = "linux")]
fn parse_maps(pid_path: &str) -> Option<Vec<MemRegion>> {
    use std::fs;

    let content = fs::read_to_string(format!("{}/maps", pid_path)).ok()?;
    let mut regions = Vec::new();

    for line in content.lines() {
        // Split into at most 6 fields; the 6th (pathname) may contain spaces.
        let parts: Vec<&str> = line.splitn(6, char::is_whitespace).collect();
        if parts.len() < 2 {
            continue;
        }

        let addr_range = parts[0];
        let perms = parts[1].to_string();

        // Pathname is optional -- anonymous mappings omit it entirely.
        let pathname = if parts.len() >= 6 {
            parts[5].trim().to_string()
        } else {
            String::new()
        };

        // Address range is formatted as "start-end" in lowercase hex without "0x" prefix.
        let (start, end) = match addr_range.split_once('-') {
            Some((s, e)) => {
                let start = u64::from_str_radix(s, 16).unwrap_or(0);
                let end = u64::from_str_radix(e, 16).unwrap_or(0);
                (start, end)
            }
            None => continue,
        };

        regions.push(MemRegion {
            start,
            end,
            perms,
            pathname,
        });
    }

    Some(regions)
}

/// Detect process masquerading by comparing the real executable path
/// (`/proc/<pid>/exe` symlink target) against `argv[0]` from `/proc/<pid>/cmdline`.
///
/// Implants commonly overwrite `argv[0]` to appear as a legitimate system service
/// (e.g., claiming to be `[kworker/0:1]` or `sshd`) while actually running a
/// different binary. This function compares basenames and filters out known
/// legitimate mismatches (busybox multicall, systemd/init, interpreter versioning).
#[cfg(target_os = "linux")]
fn check_masquerading(
    result: &mut ScanResult,
    pid: u32,
    pid_path: &str,
    proc_name: &str,
    verbose: bool,
) {
    use std::fs;
    use std::path::Path;

    // Resolve the /proc/<pid>/exe symlink to get the actual binary path.
    let exe_target = match fs::read_link(format!("{}/exe", pid_path)) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => return,
    };

    // The kernel appends " (deleted)" when the on-disk binary has been removed
    // but the process is still running. Strip it for comparison purposes.
    let exe_clean = exe_target
        .strip_suffix(" (deleted)")
        .unwrap_or(&exe_target);

    // /proc/<pid>/cmdline is a sequence of null-terminated strings.
    let cmdline = match fs::read(format!("{}/cmdline", pid_path)) {
        Ok(data) => data,
        Err(_) => return,
    };

    // Kernel threads have empty cmdline.
    if cmdline.is_empty() {
        return;
    }

    // Extract argv[0]: the first null-terminated string in the cmdline blob.
    let argv0_end = cmdline.iter().position(|&b| b == 0).unwrap_or(cmdline.len());
    let argv0 = String::from_utf8_lossy(&cmdline[..argv0_end]).trim().to_string();

    if argv0.is_empty() {
        return;
    }

    // Compare only the filename component (basename) -- full paths differ
    // legitimately due to symlinks (e.g., /usr/bin/python3 vs /usr/bin/python3.11).
    let exe_basename = Path::new(exe_clean)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let argv0_basename = Path::new(&argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if !exe_basename.is_empty() && !argv0_basename.is_empty() && exe_basename != argv0_basename {
        // Kernel threads and internal process names are enclosed in brackets
        // or parentheses (e.g., [kworker/0:1], (sd-pam)). These are not masquerading.
        if argv0_basename.starts_with('[') || exe_basename.starts_with('[')
            || argv0_basename.starts_with('(') || exe_basename.starts_with('(')
        {
            return;
        }

        // Interpreter version suffixes cause harmless mismatches
        // (e.g., exe="python3.11" argv0="python3"). Allow if one is a prefix of the other.
        if exe_basename.starts_with(argv0_basename) || argv0_basename.starts_with(exe_basename) {
            return;
        }

        // Whitelist of known-legitimate exe/argv0 pairs that would otherwise
        // trigger false positives. Each tuple is (exe_basename, argv0_basename).
        const LEGIT_PAIRS: &[(&str, &str)] = &[
            ("systemd", "init"),
            ("udevadm", "systemd-udevd"),
            ("busybox", "sh"),
            ("busybox", "ls"),
            ("busybox", "cat"),
            ("busybox", "grep"),
            ("busybox", "awk"),
            ("busybox", "sed"),
            ("busybox", "vi"),
            ("busybox", "wget"),
            ("busybox", "tar"),
            ("busybox", "gzip"),
            ("busybox", "find"),
            ("busybox", "xargs"),
            ("busybox", "entry"),
            ("systemd", "sd-pam"),
            ("containerd", "k3s"),
            ("k3s", "containerd"),
            ("dash", "sh"),
            ("k3s", "containerd-shim"),
        ];
        for (exe_match, argv0_match) in LEGIT_PAIRS {
            if exe_basename == *exe_match && argv0_basename == *argv0_match {
                return;
            }
            // Also allow partial matches on the exe side (e.g., "busybox-1.36" contains "busybox").
            if exe_basename.contains(exe_match) && argv0_basename == *argv0_match {
                return;
            }
        }

        if verbose {
            eprintln!(
                "[memory] masquerading: pid={} exe={} argv0={}",
                pid, exe_clean, argv0
            );
        }
        result.add_finding(Finding::new(
            "memory",
            "Process masquerading: exe does not match argv[0]",
            Tier::Behavioral,
            format!(
                "pid={} name={} exe={} argv0={}",
                pid, proc_name, exe_clean, argv0
            ),
        ));
    }
}

/// Inspect a process's environment block (`/proc/<pid>/environ`) for variables
/// that match known IMIX/C2 configuration patterns.
///
/// The environ file is a null-byte-delimited sequence of `KEY=VALUE` pairs.
/// We check each variable against a list of suspicious prefixes. A single match
/// is sufficient to generate a Tier2 finding because legitimate software rarely
/// uses these variable names.
#[cfg(target_os = "linux")]
fn check_environ(
    result: &mut ScanResult,
    pid: u32,
    pid_path: &str,
    proc_name: &str,
    verbose: bool,
) {
    use std::fs;

    let environ = match fs::read(format!("{}/environ", pid_path)) {
        Ok(data) => data,
        Err(_) => return,
    };

    // Prefixes associated with IMIX implant configuration or generic C2 beaconing.
    // IMIX_ variants cover the Realm framework's implant specifically.
    // C2_ and BEACON_/CALLBACK_ cover more generic implant patterns.
    let suspicious_prefixes: &[&str] = &[
        "IMIX_",
        "IMIX_CALLBACK",
        "IMIX_BEACON",
        "IMIX_SERVER",
        "IMIX_HOST",
        "IMIX_TRANSPORT",
        "IMIX_LOG",
        "IMIX_CONFIG",
        "C2_CALLBACK",
        "C2_SERVER",
        "BEACON_",
        "CALLBACK_URI",
        "CALLBACK_INTERVAL",
    ];

    // Split on null bytes to iterate individual KEY=VALUE entries.
    for var_bytes in environ.split(|&b| b == 0) {
        if var_bytes.is_empty() {
            continue;
        }
        let var = String::from_utf8_lossy(var_bytes);
        for prefix in suspicious_prefixes {
            if var.starts_with(prefix) {
                if verbose {
                    // Truncate to 80 chars to avoid flooding stderr with long values.
                    eprintln!(
                        "[memory] suspicious env var: pid={} var={}",
                        pid,
                        &var[..var.len().min(80)]
                    );
                }
                result.add_finding(Finding::new(
                    "memory",
                    format!("Suspicious environment variable: {}", prefix),
                    Tier::Tier2,
                    format!(
                        "pid={} name={} var={}",
                        pid,
                        proc_name,
                        &var[..var.len().min(120)]
                    ),
                ));
                // Break after first prefix match per variable to avoid duplicate
                // findings when one prefix is a subset of another (e.g., "IMIX_"
                // and "IMIX_CALLBACK" would both match "IMIX_CALLBACK_URL=...").
                break;
            }
        }
    }
}

/// Analyze a process's memory mappings for three classes of suspicious regions:
///
/// - **Anonymous RWX regions**: Memory with read+write+execute permissions and no
///   backing file. Normal programs rarely need RWX memory; it is a strong indicator
///   of runtime code generation or injection. Small regions (<4KB) are ignored as
///   they are commonly used for legitimate trampolines and signal handlers.
///
/// - **memfd-backed executable regions**: Code loaded from `memfd_create(2)` objects,
///   which exist only in memory. This is the primary mechanism for fileless execution
///   on Linux.
///
/// - **Shared libraries from suspicious paths**: `.so` files loaded from `/tmp`,
///   `/dev/shm`, `/var/tmp`, or hidden directories (paths containing `/.`). Legitimate
///   libraries are installed under `/usr/lib` or `/lib`; world-writable locations
///   suggest an attacker dropped a malicious library.
///
/// Returns the parsed regions for reuse by `scan_process_memory`.
#[cfg(target_os = "linux")]
fn check_maps(
    result: &mut ScanResult,
    pid: u32,
    pid_path: &str,
    proc_name: &str,
    verbose: bool,
) -> Option<Vec<MemRegion>> {
    let regions = parse_maps(pid_path)?;

    // Directories where legitimate shared libraries should never reside.
    let suspicious_lib_dirs: &[&str] = &[
        "/tmp/",
        "/dev/shm/",
        "/var/tmp/",
        "/run/shm/",
    ];

    // Track whether we've already reported each category to avoid duplicate
    // findings for the same process (one finding per category is sufficient).
    let mut found_anon_rwx = false;
    let mut found_memfd = false;

    for region in &regions {
        // --- Anonymous executable regions ---
        if region.is_anonymous() && region.is_executable() {
            let size = region.end - region.start;
            // Regions smaller than one page are likely JIT trampolines, signal
            // return frames, or glibc-internal stubs. Not worth flagging.
            if size < 4096 {
                continue;
            }

            if region.is_writable() && !found_anon_rwx {
                // RWX + anonymous = very suspicious. Legitimate programs almost
                // never need writable+executable anonymous memory.
                found_anon_rwx = true;
                if verbose {
                    eprintln!(
                        "[memory] anon RWX region: pid={} addr={:#x}-{:#x} size={}",
                        pid, region.start, region.end, size
                    );
                }
                result.add_finding(Finding::new(
                    "memory",
                    "Anonymous RWX memory region (possible code injection)",
                    Tier::Behavioral,
                    format!(
                        "pid={} name={} addr={:#x}-{:#x} size={} perms={}",
                        pid, proc_name, region.start, region.end, size, region.perms
                    ),
                ));
            }
            // Read+execute anonymous (r-xp) regions are less suspicious -- JIT
            // compilers (V8, .NET, JVM) and some language runtimes use these
            // legitimately, so we do not flag them.
        }

        // --- memfd-backed executable regions ---
        if region.is_memfd() && region.is_executable() && !found_memfd {
            found_memfd = true;
            if verbose {
                eprintln!(
                    "[memory] memfd exec: pid={} path={}",
                    pid, region.pathname
                );
            }
            result.add_finding(Finding::new(
                "memory",
                "Executable code loaded from memfd (fileless execution)",
                Tier::Tier2,
                format!(
                    "pid={} name={} memfd={} perms={}",
                    pid, proc_name, region.pathname, region.perms
                ),
            ));
        }

        // --- Shared libraries from suspicious paths ---
        if region.is_file_backed() && region.is_executable() {
            let path_lower = region.pathname.to_lowercase();
            // Only flag paths that look like shared objects (.so files).
            if path_lower.contains(".so") || path_lower.ends_with(".so") {
                for suspect_dir in suspicious_lib_dirs {
                    if region.pathname.starts_with(suspect_dir) {
                        if verbose {
                            eprintln!(
                                "[memory] suspicious .so: pid={} path={}",
                                pid, region.pathname
                            );
                        }
                        result.add_finding(Finding::new(
                            "memory",
                            "Shared library loaded from suspicious path",
                            Tier::Behavioral,
                            format!(
                                "pid={} name={} lib={}",
                                pid, proc_name, region.pathname
                            ),
                        ));
                        break;
                    }
                }
            }

            // Libraries loaded from hidden directories (containing "/." in the path)
            // are suspicious. Exclude "/.cache" which is a standard XDG directory.
            if region.pathname.contains("/.") && !region.pathname.contains("/.cache") {
                result.add_finding(Finding::new(
                    "memory",
                    "Shared library loaded from hidden directory",
                    Tier::Behavioral,
                    format!(
                        "pid={} name={} lib={}",
                        pid, proc_name, region.pathname
                    ),
                ));
            }
        }
    }

    Some(regions)
}

/// Enumerate all file descriptors in `/proc/<pid>/fd/` and check if any point
/// to memfd objects.
///
/// A process holding an open memfd handle may be staging a payload entirely in
/// memory (e.g., via `memfd_create` + `write` + `fexecve`). Only the first
/// memfd fd per process is reported to avoid noisy output.
#[cfg(target_os = "linux")]
fn check_memfd_fds(
    result: &mut ScanResult,
    pid: u32,
    pid_path: &str,
    proc_name: &str,
    verbose: bool,
) {
    use std::fs;

    let fd_dir = format!("{}/fd", pid_path);
    let entries = match fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        // Each entry in /proc/<pid>/fd/ is a symlink to the actual file/device.
        // For memfd objects, the target looks like "/memfd:<name>" or "memfd:<name>".
        let target = match fs::read_link(entry.path()) {
            Ok(t) => t.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        if target.starts_with("/memfd:") || target.starts_with("memfd:") {
            if verbose {
                eprintln!(
                    "[memory] memfd fd: pid={} fd={} target={}",
                    pid,
                    entry.file_name().to_string_lossy(),
                    target
                );
            }
            result.add_finding(Finding::new(
                "memory",
                "Process has memfd file descriptor (fileless staging)",
                Tier::Behavioral,
                format!(
                    "pid={} name={} fd={} target={}",
                    pid,
                    proc_name,
                    entry.file_name().to_string_lossy(),
                    target
                ),
            ));
            // Only report the first memfd fd per process -- additional handles
            // add no new information and would clutter the output.
            return;
        }
    }
}

/// Read and scan a process's virtual memory for Realm/IMIX byte-level signatures.
///
/// Uses `pread(2)` on `/proc/<pid>/mem` to read each eligible region identified
/// from the previously parsed maps. The `BinaryScanner` (Aho-Corasick automaton)
/// is run against each memory chunk to detect known C2 strings and byte patterns.
///
/// **Region selection heuristics:**
/// - Only readable regions are scanned (non-readable regions would fault on pread).
/// - Kernel pseudo-regions (vDSO, vsyscall, vvar) are skipped as they contain
///   only kernel-provided code.
/// - System library regions (`/usr/lib`, `/lib`, etc.) are skipped to reduce
///   scan time and false positives.
/// - A 32 MB cap per region and 100 MB cap per process prevent runaway memory
///   consumption when scanning large processes.
///
/// **False-positive suppression:**
/// A process must have 3 or more unique signature matches to be reported. This
/// threshold filters out incidental matches (e.g., the string "ssh_exec" appearing
/// in sshd's memory, or generic function names matching a single pattern). Multiple
/// distinct Realm-specific strings in one process is a strong indicator of an
/// actual implant.
#[cfg(target_os = "linux")]
fn scan_process_memory(
    result: &mut ScanResult,
    scanner: &crate::scan::proc::BinaryScanner,
    pid: u32,
    pid_path: &str,
    proc_name: &str,
    regions: &[MemRegion],
    verbose: bool,
) {
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::io::AsRawFd;

    let mem_path = format!("{}/mem", pid_path);
    let mem_file = match File::open(&mem_path) {
        Ok(f) => f,
        Err(_) => return,
    };

    // Track which pattern descriptions have already been seen for this process
    // to deduplicate matches across different memory regions.
    let mut found_patterns: HashSet<String> = HashSet::new();
    // Buffer findings until we know whether the threshold is met.
    let mut pending_findings: Vec<Finding> = Vec::new();
    let mut total_scanned: u64 = 0;
    const MAX_SCAN_BYTES: u64 = 100 * 1024 * 1024; // 100 MB cap per process
    const MAX_REGION_SIZE: u64 = 32 * 1024 * 1024;  // 32 MB cap per region

    for region in regions {
        if !region.is_readable() {
            continue;
        }

        let size = region.end - region.start;
        // Skip zero-size regions and regions exceeding the per-region cap.
        if size == 0 || size > MAX_REGION_SIZE {
            continue;
        }

        // Enforce per-process byte budget to bound total scan time.
        if total_scanned + size > MAX_SCAN_BYTES {
            break;
        }

        // vDSO, vsyscall, and vvar are kernel-mapped pages providing fast
        // syscall stubs. They never contain user-controlled data.
        if region.pathname.starts_with("[vdso]")
            || region.pathname.starts_with("[vsyscall]")
            || region.pathname.starts_with("[vvar]")
        {
            continue;
        }

        // For file-backed regions, skip standard system library paths to avoid
        // scanning hundreds of MB of libc, libssl, etc. per process. Only
        // non-system file-backed regions (user binaries, /tmp libs) are scanned.
        if region.is_file_backed() {
            let dominated_by_system = region.pathname.starts_with("/usr/lib")
                || region.pathname.starts_with("/lib")
                || region.pathname.starts_with("/usr/share")
                || region.pathname.starts_with("/usr/libexec");
            if dominated_by_system {
                continue;
            }
        }

        // Use pread(2) to read from the process's virtual address space at the
        // region's start offset. This avoids needing ptrace attach -- reading
        // /proc/<pid>/mem is allowed if we have CAP_SYS_PTRACE or are the same UID.
        let mut buf = vec![0u8; size as usize];
        let bytes_read = unsafe {
            libc::pread(
                mem_file.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                size as usize,
                region.start as i64,
            )
        };

        // pread returns -1 on error (e.g., region became unmapped) or 0 at EOF.
        if bytes_read <= 0 {
            continue;
        }

        let buf = &buf[..bytes_read as usize];
        total_scanned += bytes_read as u64;

        // Run the Aho-Corasick multi-pattern matcher against the memory chunk.
        // The scanner contains all known Realm/IMIX signature patterns.
        let findings = scanner.scan_bytes(buf, &format!("pid:{}", pid));

        for f in findings {
            // HashSet::insert returns true only for new entries, providing
            // automatic deduplication across regions within this process.
            if found_patterns.insert(f.description.clone()) {
                if verbose {
                    eprintln!(
                        "[memory] signature in memory: pid={} name={} {}",
                        pid, proc_name, f.description
                    );
                }
                pending_findings.push(Finding::new(
                    "memory",
                    format!("In-memory: {}", f.description),
                    f.tier,
                    format!(
                        "pid={} name={} region={:#x}-{:#x} backing={}",
                        pid,
                        proc_name,
                        region.start,
                        region.end,
                        if region.pathname.is_empty() {
                            "[anonymous]"
                        } else {
                            &region.pathname
                        }
                    ),
                ));
            }
        }
    }

    if verbose && total_scanned > 0 && !pending_findings.is_empty() {
        eprintln!(
            "[memory] pid={} scanned {} bytes, {} unique matches",
            pid,
            total_scanned,
            pending_findings.len()
        );
    }

    // Threshold gate: require 3+ unique pattern matches before reporting.
    // A single match (e.g., "ssh_exec" in sshd) is likely coincidental.
    // Multiple distinct Realm-specific signatures in one process strongly
    // suggests an actual implant is resident in memory.
    if pending_findings.len() >= 3 {
        for f in pending_findings {
            result.add_finding(f);
        }
    } else if verbose && !pending_findings.is_empty() {
        eprintln!(
            "[memory] pid={} name={}: {} match(es) below threshold, suppressed",
            pid, proc_name, pending_findings.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

/// Windows process enumeration and memory scanning entry point.
///
/// Uses a platform-specific `enumerate_processes` helper to list running
/// processes, then scans each one for private executable memory and
/// Realm/IMIX signatures. Skips PID 0 (System Idle) and PID 4 (System).
#[cfg(windows)]
fn scan_windows(result: &mut ScanResult, self_pid: u32, verbose: bool) {
    use crate::platform::windows::enumerate_processes;
    use crate::scan::proc::BinaryScanner;

    let scanner = BinaryScanner::new();
    let procs = enumerate_processes();

    for proc_info in &procs {
        // Skip self, System Idle (PID 0), and System (PID 4).
        if proc_info.pid == self_pid || proc_info.pid == 0 || proc_info.pid == 4 {
            continue;
        }

        // Combined check: private executable memory detection + signature scanning.
        scan_windows_process_memory(
            result,
            &scanner,
            proc_info.pid,
            &proc_info.name,
            verbose,
        );
    }
}

/// Scan a single Windows process for injected code and Realm/IMIX signatures.
///
/// Walks the process's virtual address space using `VirtualQueryEx` to enumerate
/// memory regions. For each region:
///
/// - **Private executable memory** (`MEM_PRIVATE` + `PAGE_EXECUTE*`): Flags regions
///   larger than 8KB. Small private exec regions are common in .NET, JIT compilers,
///   and Windows runtime trampolines. RWX private regions are elevated to Tier2
///   (higher severity) since they are rarely legitimate.
///
/// - **Signature scanning**: Reads non-system executable regions via
///   `ReadProcessMemory` and runs the Aho-Corasick scanner. `MEM_IMAGE` regions
///   (backed by loaded DLLs/EXEs) are skipped to reduce noise.
///
/// The same 3-match threshold as Linux is applied before findings are reported.
/// If the threshold is met, thread start address analysis is also performed.
#[cfg(windows)]
fn scan_windows_process_memory(
    result: &mut ScanResult,
    scanner: &crate::scan::proc::BinaryScanner,
    pid: u32,
    proc_name: &str,
    verbose: bool,
) {
    use std::collections::HashSet;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_IMAGE, MEM_PRIVATE,
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;

    unsafe {
        // Open the target process with query + read permissions.
        // This will fail for protected processes (csrss, lsass) unless running
        // with SeDebugPrivilege.
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() {
            return;
        }

        let mut address: usize = 0;
        let mut found_private_exec = false;
        let mut found_patterns: HashSet<String> = HashSet::new();
        let mut pending_findings: Vec<Finding> = Vec::new();
        let mut total_scanned: u64 = 0;
        const MAX_SCAN_BYTES: u64 = 100 * 1024 * 1024;
        const MAX_REGION_SIZE: usize = 32 * 1024 * 1024;

        loop {
            // Query the next memory region starting at `address`.
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let ret = VirtualQueryEx(
                handle,
                address as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            // VirtualQueryEx returns 0 when we've walked past the end of the
            // address space.
            if ret == 0 {
                break;
            }

            // Check if the region's page protection includes execute permission.
            let is_exec = matches!(
                mbi.Protect,
                PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            );

            // --- Private executable region detection ---
            // MEM_PRIVATE means the region is not backed by a file (DLL/EXE image)
            // or shared section. Executable private memory indicates dynamically
            // generated code, which is suspicious in most native processes.
            // Threshold: >8KB to skip JIT trampolines and .NET runtime stubs.
            if mbi.Type == MEM_PRIVATE && is_exec && mbi.RegionSize > 8192 && !found_private_exec {
                found_private_exec = true;
                if verbose {
                    eprintln!(
                        "[memory] private exec region: pid={} addr={:#x} size={} protect={:#x}",
                        pid, mbi.BaseAddress as usize, mbi.RegionSize, mbi.Protect
                    );
                }

                // RWX (read-write-execute) is the most suspicious combination --
                // it allows writing new code and immediately executing it.
                let tier = if mbi.Protect == PAGE_EXECUTE_READWRITE {
                    Tier::Tier2
                } else {
                    Tier::Behavioral
                };

                pending_findings.push(Finding::new(
                    "memory",
                    "Private executable memory region (possible code injection)",
                    tier,
                    format!(
                        "pid={} name={} addr={:#x} size={} protect={:#x}",
                        pid,
                        proc_name,
                        mbi.BaseAddress as usize,
                        mbi.RegionSize,
                        mbi.Protect
                    ),
                ));
            }

            // --- Signature scanning of non-system executable regions ---
            if is_exec && mbi.RegionSize >= 4096 && mbi.RegionSize <= MAX_REGION_SIZE {
                // Skip MEM_IMAGE regions (mapped from on-disk DLLs/EXEs). These
                // are the vast majority of executable memory in a Windows process
                // and scanning them would be too slow and noisy.
                let should_scan = mbi.Type == MEM_PRIVATE || mbi.Type != MEM_IMAGE;

                if should_scan && total_scanned + mbi.RegionSize as u64 <= MAX_SCAN_BYTES {
                    let mut buf = vec![0u8; mbi.RegionSize];
                    let mut bytes_read: usize = 0;

                    let ok = ReadProcessMemory(
                        handle,
                        mbi.BaseAddress,
                        buf.as_mut_ptr() as *mut _,
                        mbi.RegionSize,
                        &mut bytes_read,
                    );

                    if ok != 0 && bytes_read > 0 {
                        let buf = &buf[..bytes_read];
                        total_scanned += bytes_read as u64;

                        let findings = scanner.scan_bytes(buf, &format!("pid:{}", pid));
                        for f in findings {
                            if found_patterns.insert(f.description.clone()) {
                                if verbose {
                                    eprintln!(
                                        "[memory] signature in memory: pid={} name={} {}",
                                        pid, proc_name, f.description
                                    );
                                }
                                pending_findings.push(Finding::new(
                                    "memory",
                                    format!("In-memory: {}", f.description),
                                    f.tier,
                                    format!(
                                        "pid={} name={} addr={:#x} size={}",
                                        pid,
                                        proc_name,
                                        mbi.BaseAddress as usize,
                                        mbi.RegionSize
                                    ),
                                ));
                            }
                        }
                    }
                }
            }

            // Advance to the next region by adding the current region's size
            // to its base address.
            address = mbi.BaseAddress as usize + mbi.RegionSize;
            // Guard against wraparound at the top of the address space.
            if address == 0 {
                break;
            }
        }

        // Apply the same 3-match threshold as the Linux scanner.
        if pending_findings.len() >= 3 {
            for f in pending_findings {
                result.add_finding(f);
            }
            // Thread analysis is only performed for processes that already met
            // the signature threshold, since it requires additional API calls
            // and is only useful as supplementary evidence.
            check_thread_start_addresses(result, handle, pid, proc_name, verbose);
        } else if verbose && !pending_findings.is_empty() {
            eprintln!(
                "[memory] pid={} name={}: {} match(es) below threshold, suppressed",
                pid, proc_name, pending_findings.len()
            );
        }

        CloseHandle(handle);
    }
}

/// Enumerate threads belonging to `pid` and check whether any thread's Win32
/// start address falls within non-image (private) memory.
///
/// A thread whose start address is in `MEM_PRIVATE` memory (rather than
/// `MEM_IMAGE`, which is backed by a loaded DLL/EXE) strongly suggests
/// reflective DLL injection, shellcode injection, or similar code injection
/// techniques. This check uses `NtQueryInformationThread` with the
/// `ThreadQuerySetWin32StartAddress` (info class 9) to retrieve the start
/// address, then `VirtualQueryEx` to determine the memory type.
///
/// Only the first suspicious thread per process is reported.
///
/// # Safety
/// Requires a valid process handle with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`.
/// All Win32 handles are closed before returning.
#[cfg(windows)]
unsafe fn check_thread_start_addresses(
    result: &mut ScanResult,
    process_handle: windows_sys::Win32::Foundation::HANDLE,
    pid: u32,
    proc_name: &str,
    verbose: bool,
) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
    };
    use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_IMAGE};
    use windows_sys::Win32::System::Threading::{
        OpenThread, THREAD_QUERY_INFORMATION,
    };

    // Take a snapshot of all threads in the system (TH32CS_SNAPTHREAD captures
    // threads across all processes; we filter by PID below).
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if snap == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return;
    }

    let mut te: THREADENTRY32 = std::mem::zeroed();
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    let mut found_suspicious_thread = false;

    if Thread32First(snap, &mut te) != 0 {
        loop {
            // Only inspect threads belonging to our target process.
            if te.th32OwnerProcessID == pid && !found_suspicious_thread {
                let thread_handle = OpenThread(THREAD_QUERY_INFORMATION, 0, te.th32ThreadID);
                if !thread_handle.is_null() {
                    // Use NtQueryInformationThread to retrieve the thread's
                    // Win32 start address. This is an undocumented (but stable)
                    // NTDLL function. Info class 9 = ThreadQuerySetWin32StartAddress.
                    let mut start_addr: usize = 0;
                    let mut return_len: u32 = 0;

                    type NtQueryInformationThreadFn = unsafe extern "system" fn(
                        *mut std::ffi::c_void, u32, *mut std::ffi::c_void, u32, *mut u32,
                    ) -> i32;

                    // Dynamically resolve NtQueryInformationThread from ntdll.dll
                    // to avoid a static link dependency on ntdll.
                    let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(
                        b"ntdll.dll\0".as_ptr(),
                    );
                    if !ntdll.is_null() {
                        let func = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                            ntdll,
                            b"NtQueryInformationThread\0".as_ptr(),
                        );
                        if let Some(func) = func {
                            let query: NtQueryInformationThreadFn = std::mem::transmute(func);
                            let status = query(
                                thread_handle,
                                9, // ThreadQuerySetWin32StartAddress
                                &mut start_addr as *mut _ as *mut _,
                                std::mem::size_of::<usize>() as u32,
                                &mut return_len,
                            );

                            if status == 0 && start_addr != 0 {
                                // Determine what type of memory the start address
                                // resides in. MEM_IMAGE means it's backed by a
                                // loaded module (normal). Anything else (MEM_PRIVATE,
                                // MEM_MAPPED) is suspicious.
                                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                                let ret = VirtualQueryEx(
                                    process_handle,
                                    start_addr as *const _,
                                    &mut mbi,
                                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                                );

                                if ret != 0 && mbi.Type != MEM_IMAGE {
                                    found_suspicious_thread = true;
                                    if verbose {
                                        eprintln!(
                                            "[memory] thread from private mem: pid={} tid={} addr={:#x}",
                                            pid, te.th32ThreadID, start_addr
                                        );
                                    }
                                    result.add_finding(Finding::new(
                                        "memory",
                                        "Thread start address in non-image memory (possible injection)",
                                        Tier::Tier2,
                                        format!(
                                            "pid={} name={} tid={} start_addr={:#x} mem_type={:#x}",
                                            pid, proc_name, te.th32ThreadID, start_addr, mbi.Type
                                        ),
                                    ));
                                }
                            }
                        }
                    }

                    CloseHandle(thread_handle);
                }
            }

            if Thread32Next(snap, &mut te) == 0 {
                break;
            }
        }
    }

    CloseHandle(snap);
}
