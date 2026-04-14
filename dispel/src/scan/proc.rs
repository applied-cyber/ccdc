//! Process binary scanner for Realm C2 detection.
//!
//! This module scans running process executables and known install paths for
//! Realm C2 (imix/Eldritch) signatures. It uses Aho-Corasick multi-pattern
//! matching to efficiently search binary content against hundreds of indicator
//! strings in a single pass over each file.
//!
//! The scanning pipeline works in two phases per platform:
//! 1. **Live process scan** -- enumerate running processes, memory-map each
//!    executable, and run the Aho-Corasick automaton over the mapped bytes.
//!    Also checks behavioral indicators (deleted executables, high thread count).
//! 2. **Dormant install path scan** -- probe known filesystem paths where the
//!    Realm implant (imix) is commonly installed. Files found at these paths
//!    are flagged as Tier1 and optionally binary-scanned for additional evidence.
//!
//! The scanner avoids scanning its own executable to prevent false positives.
//! Files are memory-mapped read-only for zero-copy I/O, capped at 200 MB.

use aho_corasick::AhoCorasick;
use memmap2::Mmap;
use std::collections::HashSet;
use std::fs::File;

use crate::signatures::strings::{
    all_signatures, GRPC_PATHS, ELDRITCH_DISTINCTIVE, ELDRITCH_AGENT_API,
    ELDRITCH_OFFENSIVE, ELDRITCH_REPORT, TIER2_STRINGS,
};
#[cfg(target_os = "linux")]
use crate::signatures::strings::TIER1_INSTALL_PATHS_LINUX;
use crate::{Finding, ScanResult, Tier};

/// Upper bound on file size we will memory-map. Anything larger is skipped
/// to avoid excessive memory consumption on large binaries that are unlikely
/// to be the Realm implant.
const MAX_FILE_SIZE: u64 = 200 * 1024 * 1024; // 200 MB

/// Returns a human-readable category label for a matched pattern string.
///
/// The label is determined by checking which signature list the pattern belongs
/// to. Order matters: more specific lists are checked first. If no list claims
/// the pattern, it falls back to a generic "binary signature" label.
fn categorize_pattern(pattern: &str) -> &'static str {
    if GRPC_PATHS.contains(&pattern) {
        return "gRPC service path";
    }
    if ELDRITCH_DISTINCTIVE.contains(&pattern) {
        return "Eldritch distinctive function";
    }
    if ELDRITCH_AGENT_API.contains(&pattern) {
        return "Eldritch agent API";
    }
    if ELDRITCH_OFFENSIVE.contains(&pattern) {
        return "Eldritch offensive capability";
    }
    if ELDRITCH_REPORT.contains(&pattern) {
        return "Eldritch report module";
    }
    if TIER2_STRINGS.contains(&pattern) {
        return "Realm C2 string indicator";
    }
    "binary signature"
}

/// Multi-pattern binary scanner backed by an Aho-Corasick automaton.
///
/// Constructed once and reused across all files to amortize the O(n) automaton
/// build cost. The automaton matches all known Realm/Eldritch signature strings
/// simultaneously in a single linear scan over the input bytes.
pub struct BinaryScanner {
    /// The compiled Aho-Corasick automaton containing all signature patterns.
    ac: AhoCorasick,
    /// Parallel vector indexed by automaton pattern ID. Each entry holds the
    /// original pattern string and its detection tier, enabling O(1) lookup
    /// when a match is reported.
    patterns: Vec<(String, Tier)>,
}

impl BinaryScanner {
    /// Build the Aho-Corasick automaton from all registered signatures.
    ///
    /// Calls `all_signatures()` to collect every (pattern, tier) pair, then
    /// compiles them into a single automaton. Panics if automaton construction
    /// fails (indicates a bug in the signature definitions).
    pub fn new() -> Self {
        let sigs = all_signatures();
        let patterns: Vec<(String, Tier)> = sigs
            .iter()
            .map(|(s, t)| (s.to_string(), t.clone()))
            .collect();
        let pattern_strs: Vec<&str> = patterns.iter().map(|(s, _)| s.as_str()).collect();
        let ac = AhoCorasick::new(pattern_strs).expect("failed to build Aho-Corasick automaton");
        Self { ac, patterns }
    }

    /// Scan a byte slice for all signature matches and return findings.
    ///
    /// Iterates over every Aho-Corasick match in `data`. Duplicate pattern IDs
    /// are suppressed via `seen` so that a pattern appearing 1000 times in a
    /// binary still produces only one Finding. Each finding includes the
    /// category label, matched string, tier, and the originating file path.
    pub fn scan_bytes(&self, data: &[u8], binary_path: &str) -> Vec<Finding> {
        // Track which pattern indices we have already emitted to deduplicate.
        let mut seen: HashSet<usize> = HashSet::new();
        let mut findings: Vec<Finding> = Vec::new();

        for mat in self.ac.find_iter(data) {
            let idx = mat.pattern().as_usize();
            // HashSet::insert returns true only on first insertion, providing
            // deduplication without a separate contains() check.
            if seen.insert(idx) {
                let (pattern, tier) = &self.patterns[idx];
                let category = categorize_pattern(pattern.as_str());
                let description = format!("{}: {}", category, pattern);
                findings.push(Finding::new(
                    "proc",
                    description,
                    tier.clone(),
                    format!("path={}", binary_path),
                ));
            }
        }

        findings
    }

    /// Memory-map a file and scan its contents for signatures.
    ///
    /// Returns an empty vec if the file cannot be opened, has zero length,
    /// exceeds `MAX_FILE_SIZE`, or cannot be memory-mapped. Errors are silently
    /// swallowed because inaccessible files (permission denied, broken symlinks)
    /// are expected during a system-wide process scan.
    pub fn scan_file(&self, path: &str) -> Vec<Finding> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };

        let metadata = match file.metadata() {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };

        let size = metadata.len();
        if size == 0 || size > MAX_FILE_SIZE {
            return Vec::new();
        }

        // Safety: the file descriptor is opened read-only. The Mmap is treated
        // as an immutable byte slice and never written to. External mutation of
        // the underlying file while mapped is technically UB per Rust's aliasing
        // rules but is acceptable here since we only read and tolerate stale data.
        let mmap = match unsafe { Mmap::map(&file) } {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };

        self.scan_bytes(&mmap, path)
    }
}

impl Default for BinaryScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Hash checking helper
// ---------------------------------------------------------------------------

/// Check a binary file against known SHA-256 hashes of Realm C2 implant builds.
///
/// Computes the SHA-256 of the file at `path` and looks it up in the known-hash
/// database. Returns `Some(Finding)` at Tier1 if the hash matches a known imix
/// build, or `None` otherwise.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", windows))]
fn check_known_hash(path: &str) -> Option<Finding> {
    use crate::signatures::hashes::{check_hash, sha256_file};

    let hash = sha256_file(path)?;
    let description = check_hash(&hash)?;
    Some(Finding::new(
        "proc",
        format!("Binary matches known imix hash: {}", description),
        Tier::Tier1,
        format!("path={} sha256={}", path, hash),
    ))
}

// ---------------------------------------------------------------------------
// Top-level process scan entry point
// ---------------------------------------------------------------------------

/// Resolve the absolute path of the currently running executable.
///
/// Used to exclude ourselves from the scan so we do not trigger on our own
/// embedded signature strings. Returns `None` if the path cannot be determined
/// or canonicalized (e.g., on some sandboxed environments).
fn self_exe_path() -> Option<String> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.to_string_lossy().to_string())
}

/// Compare a candidate path against the scanner's own executable path.
///
/// On Windows, paths may differ in casing and may carry a `\\?\` extended-length
/// prefix depending on which API returned them. This function normalizes both
/// sides before comparing to avoid false negatives in self-detection.
fn is_self_exe(path: &str, self_exe: &Option<String>) -> bool {
    match self_exe.as_deref() {
        Some(s) => {
            #[cfg(windows)]
            {
                // Strip the extended-length path prefix that Win32 APIs sometimes add,
                // then compare case-insensitively (NTFS is case-preserving but not
                // case-sensitive by default).
                let norm_path = path.strip_prefix(r"\\?\").unwrap_or(path);
                let norm_self = s.strip_prefix(r"\\?\").unwrap_or(s);
                norm_path.eq_ignore_ascii_case(norm_self)
            }
            #[cfg(not(windows))]
            { path == s }
        }
        None => false,
    }
}

/// Main entry point for the process scanning layer.
///
/// Enumerates running processes and known install paths on the current platform,
/// scanning each binary for Realm C2 signatures and known hashes. Returns a
/// `ScanResult` aggregating all findings across three detection strategies:
///
/// - **Behavioral**: deleted executables, abnormal thread counts
/// - **Signature**: Aho-Corasick multi-pattern matching against binary content
/// - **Hash**: SHA-256 comparison against known imix builds
///
/// The scanner maintains a `scanned_paths` set to avoid redundant binary scans
/// when the same file appears both as a live process and at a known install path.
#[allow(unused_mut, unused_variables)]
pub fn scan(verbose: bool) -> ScanResult {
    let mut result = ScanResult::new();
    let scanner = BinaryScanner::new();
    let self_exe = self_exe_path();
    // Tracks exe paths already binary-scanned during the live process phase so
    // the install-path phase can skip files that were already analyzed.
    let mut scanned_paths: HashSet<String> = HashSet::new();

    // -----------------------------------------------------------------------
    // Linux: enumerate /proc to find running processes
    // -----------------------------------------------------------------------
    #[cfg(target_os = "linux")]
    {
        use crate::platform::linux::enumerate_processes;

        let procs = enumerate_processes();

        for proc in &procs {
            // A running process whose executable has been deleted from disk is a
            // strong behavioral indicator -- common when a dropper launches the
            // implant then removes the binary to hinder forensic recovery.
            if proc.deleted_exe {
                result.add_finding(Finding::new(
                    "proc",
                    "Running process has deleted executable on disk",
                    Tier::Behavioral,
                    format!(
                        "pid={} name={} exe={}",
                        proc.pid,
                        proc.name,
                        proc.exe_path.as_deref().unwrap_or("<unknown>")
                    ),
                ));
            }

            // Realm's imix agent spawns many gRPC/tasking threads. A thread
            // count above 50 is unusual for most system services and warrants
            // investigation.
            if proc.thread_count > 50 {
                result.add_finding(Finding::new(
                    "proc",
                    "Process has unusually high thread count",
                    Tier::Behavioral,
                    format!(
                        "pid={} name={} threads={}",
                        proc.pid, proc.name, proc.thread_count
                    ),
                ));
            }

            // Binary scan: memory-map the executable and run Aho-Corasick over it.
            // For deleted-on-disk binaries, /proc/<pid>/exe still provides access
            // to the executable image via the kernel's reference. We scan that path
            // but rewrite the finding detail to show the original filesystem path
            // for analyst clarity.
            if let Some(ref exe) = proc.exe_path {
                let is_self = is_self_exe(exe, &self_exe);
                if !is_self {
                    // Use /proc/<pid>/exe for deleted binaries since the original
                    // path no longer exists on disk.
                    let scan_path = if proc.deleted_exe {
                        format!("/proc/{}/exe", proc.pid)
                    } else {
                        exe.clone()
                    };
                    let mut findings = scanner.scan_file(&scan_path);
                    // Rewrite /proc/<pid>/exe back to the original path in finding
                    // details so the output references the meaningful filesystem
                    // location rather than the procfs symlink.
                    if proc.deleted_exe {
                        let proc_path_prefix = format!("path={}", scan_path);
                        let real_path_detail = format!("path={} (deleted)", exe);
                        for f in &mut findings {
                            if f.detail == proc_path_prefix {
                                f.detail = real_path_detail.clone();
                            }
                        }
                    }
                    if verbose && !findings.is_empty() {
                        eprintln!(
                            "[proc] {} finding(s) in pid={} exe={}{}",
                            findings.len(),
                            proc.pid,
                            exe,
                            if proc.deleted_exe { " (deleted)" } else { "" }
                        );
                    }
                    for f in findings {
                        result.add_finding(f);
                    }
                    // Also check the binary's SHA-256 against known imix hashes.
                    if let Some(hash_finding) = check_known_hash(&scan_path) {
                        result.add_finding(hash_finding);
                    }
                    scanned_paths.insert(exe.clone());
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Linux: check known filesystem install paths for dormant implant binaries
    // -----------------------------------------------------------------------
    #[cfg(target_os = "linux")]
    {
        for path in TIER1_INSTALL_PATHS_LINUX {
            // Canonicalize the install path and compare against self_exe to
            // avoid flagging our own binary if it happens to live at one of
            // these locations.
            let is_self = self_exe.as_deref().map_or(false, |s| {
                std::path::Path::new(path)
                    .canonicalize()
                    .map_or(false, |p| p.to_string_lossy() == s)
            });
            if is_self {
                continue;
            }
            if std::path::Path::new(path).exists() {
                // The mere existence of a binary at a known install path is a
                // Tier1 finding regardless of content.
                result.add_finding(Finding::new(
                    "proc",
                    "Realm C2 binary found at known install path",
                    Tier::Tier1,
                    format!("path={}", path),
                ));
                // Run the signature scan for supplementary evidence, but skip
                // if the live process phase already scanned this path.
                if !scanned_paths.contains(*path) {
                    for f in scanner.scan_file(path) {
                        result.add_finding(f);
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Windows: enumerate processes via toolhelp snapshots
    // -----------------------------------------------------------------------
    #[cfg(windows)]
    {
        use crate::platform::windows;
        use crate::signatures::strings;

        let procs = windows::enumerate_processes();
        if verbose {
            eprintln!("[verbose] Found {} Windows processes", procs.len());
        }

        // System processes that legitimately maintain many threads. Without this
        // allowlist, svchost.exe and friends would generate noise on every scan.
        const HIGH_THREAD_ALLOWLIST: &[&str] = &[
            "system", "svchost.exe", "lsass.exe", "csrss.exe",
            "services.exe", "wmiprvse.exe", "searchindexer.exe",
            "microsoftedgeupdate.exe", "runtimebroker.exe",
        ];

        for proc_info in &procs {
            let lower_name = proc_info.name.to_lowercase();

            // Flag high thread count, excluding known-noisy system processes
            // and the System process (PID 4).
            if proc_info.thread_count > 50
                && !HIGH_THREAD_ALLOWLIST.contains(&lower_name.as_str())
                && proc_info.pid != 4
            {
                result.add_finding(Finding::new(
                    "proc",
                    format!(
                        "Process {} (PID {}) has {} threads",
                        proc_info.name, proc_info.pid, proc_info.thread_count
                    ),
                    Tier::Behavioral,
                    proc_info.exe_path.clone().unwrap_or_default(),
                ));
            }
            // Check if the process name matches a known imix binary name
            // (case-insensitive comparison).
            if strings::TIER1_BINARY_NAMES
                .iter()
                .any(|n| lower_name == *n)
            {
                result.add_finding(Finding::new(
                    "proc",
                    format!(
                        "Process named '{}' matches known imix name",
                        proc_info.name
                    ),
                    Tier::Tier1,
                    proc_info.exe_path.clone().unwrap_or_default(),
                ));
            }

            // Binary signature scan and hash check for each process executable.
            if let Some(ref path) = proc_info.exe_path {
                let is_self = is_self_exe(path, &self_exe);
                if !is_self {
                    for f in scanner.scan_file(path) {
                        result.add_finding(f);
                    }
                    if let Some(hash_finding) = check_known_hash(path) {
                        result.add_finding(hash_finding);
                    }
                    scanned_paths.insert(path.clone());
                }
            }
        }

        // Check known Windows install paths for dormant implant binaries.
        for path in strings::TIER1_INSTALL_PATHS_WINDOWS {
            if std::path::Path::new(path).exists() {
                result.add_finding(Finding::new(
                    "proc",
                    format!("Known imix install path exists: {}", path),
                    Tier::Tier1,
                    path.to_string(),
                ));
                // Skip binary scan if already scanned as a live process exe.
                if !scanned_paths.contains(*path) {
                    for f in scanner.scan_file(path) {
                        result.add_finding(f);
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // BSD: enumerate processes via sysctl/kinfo_proc
    // -----------------------------------------------------------------------
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        use crate::platform::bsd::enumerate_processes;
        use crate::signatures::strings;

        let procs = enumerate_processes();
        if verbose {
            eprintln!("[verbose] Found {} BSD processes", procs.len());
        }

        for proc_info in &procs {
            // Check process name against known imix binary names.
            let lower_name = proc_info.name.to_lowercase();
            if strings::TIER1_BINARY_NAMES
                .iter()
                .any(|n| lower_name == *n)
            {
                result.add_finding(Finding::new(
                    "proc",
                    format!(
                        "Process named '{}' matches known imix name",
                        proc_info.name
                    ),
                    Tier::Tier1,
                    format!(
                        "pid={} exe={}",
                        proc_info.pid,
                        proc_info.exe_path.as_deref().unwrap_or("<unknown>")
                    ),
                ));
            }

            // Binary scan and hash check for each live process executable.
            if let Some(ref exe) = proc_info.exe_path {
                let is_self = is_self_exe(exe, &self_exe);
                if !is_self {
                    let findings = scanner.scan_file(exe);
                    if verbose && !findings.is_empty() {
                        eprintln!(
                            "[proc] {} finding(s) in pid={} exe={}",
                            findings.len(),
                            proc_info.pid,
                            exe,
                        );
                    }
                    for f in findings {
                        result.add_finding(f);
                    }
                    if let Some(hash_finding) = check_known_hash(exe) {
                        result.add_finding(hash_finding);
                    }
                    scanned_paths.insert(exe.clone());
                }
            }
        }

        // Check common BSD install paths for dormant implant binaries.
        let bsd_install_paths: &[&str] = &[
            "/bin/imix",
            "/usr/bin/imix",
            "/usr/local/bin/imix",
            "/tmp/imix",
            "/var/tmp/imix",
        ];
        for path in bsd_install_paths {
            // Canonicalize and compare against self_exe to skip our own binary.
            let is_self = self_exe.as_deref().map_or(false, |s| {
                std::path::Path::new(path)
                    .canonicalize()
                    .map_or(false, |p| p.to_string_lossy() == s)
            });
            if is_self {
                continue;
            }
            if std::path::Path::new(path).exists() {
                result.add_finding(Finding::new(
                    "proc",
                    "Realm C2 binary found at known install path",
                    Tier::Tier1,
                    format!("path={}", path),
                ));
                if !scanned_paths.contains(*path) {
                    for f in scanner.scan_file(path) {
                        result.add_finding(f);
                    }
                }
            }
        }
    }

    // Consume `verbose` to suppress unused-variable warnings on platforms that
    // lack a live process enumeration implementation (e.g., macOS).
    let _ = verbose;

    result
}
