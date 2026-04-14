//! Persistence detection layer for identifying Realm C2 persistence mechanisms.
//!
//! This module checks for artifacts that indicate an implant has established
//! persistence on the host. Checks include:
//! - Beacon ID files: UUID v4 files at known paths used by the imix agent to
//!   store its unique agent identifier.
//! - Systemd/sysvinit services: unit files and init scripts containing known
//!   Realm C2 service names.
//! - Timestomped binaries: files in system directories with modification times
//!   set to the future (Linux) or matching cmd.exe exactly (Windows).
//! - Windows registry keys: HKLM\SOFTWARE\Imix persistence entries.
//! - Windows services: registered services with known implant names.

use regex::Regex;
use std::fs;

use crate::{Finding, ScanResult, Tier};

/// Check whether a string matches UUID v4 format.
///
/// UUID v4 layout: `xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx`
/// The "4" in position 13 identifies the version; the variant nibble at
/// position 19 must be one of 8, 9, a, or b per RFC 4122.
pub fn is_uuid_v4(s: &str) -> bool {
    let re = Regex::new(
        r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )
    .expect("UUID v4 regex is valid");
    re.is_match(s)
}

/// Read the file at `path`, trim whitespace, and check whether it contains
/// a UUID v4 beacon identifier.
///
/// Realm's imix agent writes its agent ID as a bare UUID to a file. A valid
/// beacon ID file has exactly 36 characters after trimming (the canonical
/// UUID string length) and matches UUID v4 format.
///
/// Returns a Tier2 Finding if both conditions hold.
pub fn check_uuid_file(path: &str) -> Option<Finding> {
    let raw = fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();

    // UUID v4 canonical form is always 36 chars: 32 hex digits + 4 hyphens
    if trimmed.len() != 36 {
        return None;
    }

    if is_uuid_v4(trimmed) {
        Some(Finding::new(
            "persist",
            "Realm C2 beacon ID file found",
            Tier::Tier2,
            format!("path={} uuid={}", path, trimmed),
        ))
    } else {
        None
    }
}

/// Run all persistence detection checks and return accumulated findings.
///
/// Platform-specific checks:
/// - Linux: beacon ID files, systemd units, sysvinit scripts, timestomped binaries.
/// - BSD: beacon ID files at BSD-specific paths.
/// - Windows: beacon ID files, registry keys, Windows services, timestomped system binaries.
pub fn scan(verbose: bool) -> ScanResult {
    let mut result = ScanResult::new();

    // --- Linux ---
    #[cfg(target_os = "linux")]
    {
        use std::time::SystemTime;

        use crate::signatures::strings::{
            BEACON_ID_PATHS_LINUX, SYSTEMD_PATHS, SYSVINIT_PATH, TIER1_SERVICE_NAMES,
        };

        // 1. Check known beacon ID file paths for UUID v4 contents
        for path in BEACON_ID_PATHS_LINUX {
            if let Some(finding) = check_uuid_file(path) {
                if verbose {
                    eprintln!("[persist] beacon ID found at {}", path);
                }
                result.add_finding(finding);
            }
        }

        // 2. Check systemd unit files for known implant service names.
        //    Even if the service isn't running, its presence in a unit file
        //    indicates persistence was configured.
        for unit_path in SYSTEMD_PATHS {
            if let Ok(content) = fs::read_to_string(unit_path) {
                for svc_name in TIER1_SERVICE_NAMES {
                    if content.contains(svc_name) {
                        if verbose {
                            eprintln!(
                                "[persist] service name '{}' found in {}",
                                svc_name, unit_path
                            );
                        }
                        result.add_finding(Finding::new(
                            "persist",
                            "Realm C2 service name found in systemd unit",
                            Tier::Tier1,
                            format!("path={} name={}", unit_path, svc_name),
                        ));
                        // Only report the first match per file to avoid duplicates
                        break;
                    }
                }
            }
        }

        // 3. Check sysvinit script for known service names
        if let Ok(content) = fs::read_to_string(SYSVINIT_PATH) {
            for svc_name in TIER1_SERVICE_NAMES {
                if content.contains(svc_name) {
                    if verbose {
                        eprintln!(
                            "[persist] service name '{}' found in {}",
                            svc_name, SYSVINIT_PATH
                        );
                    }
                    result.add_finding(Finding::new(
                        "persist",
                        "Realm C2 service name found in sysvinit script",
                        Tier::Tier1,
                        format!("path={} name={}", SYSVINIT_PATH, svc_name),
                    ));
                    break;
                }
            }
        }

        // 4. Detect timestomped binaries in system directories.
        //    An attacker may set a binary's mtime to a past date to make it
        //    blend in with legitimate system files. We flag files whose mtime
        //    is both >365 days newer than /bin/sh AND in the future relative
        //    to the current wall clock time -- indicating deliberate timestamp
        //    manipulation.
        let reference_mtime = fs::metadata("/bin/sh")
            .and_then(|m| m.modified())
            .ok();

        if let Some(ref_mtime) = reference_mtime {
            let scan_dirs = ["/bin", "/usr/bin", "/sbin", "/usr/sbin"];
            for dir in &scan_dirs {
                let entries = match fs::read_dir(dir) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    let meta = match entry_path.metadata() {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if !meta.is_file() {
                        continue;
                    }
                    let mtime = match meta.modified() {
                        Ok(t) => t,
                        Err(_) => continue,
                    };

                    // Compute how much newer this file is than the /bin/sh reference
                    let delta = if mtime > ref_mtime {
                        mtime.duration_since(ref_mtime).unwrap_or_default()
                    } else {
                        continue;
                    };

                    // Flag anything that is MORE than 365 days newer than /bin/sh
                    // AND also in the future relative to now (timestamp manipulation)
                    if delta.as_secs() > 365 * 24 * 3600 {
                        let now = SystemTime::now();
                        if mtime > now {
                            if verbose {
                                eprintln!(
                                    "[persist] future mtime on {}",
                                    entry_path.display()
                                );
                            }
                            result.add_finding(Finding::new(
                                "persist",
                                "Binary has future modification time (possible timestomping)",
                                Tier::Behavioral,
                                format!("path={}", entry_path.display()),
                            ));
                        }
                    }
                }
            }
        }
    }

    // --- BSD ---
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        use crate::signatures::strings::BEACON_ID_PATHS_BSD;

        // Check BSD-specific beacon ID paths (e.g. /var/db/imix/agent_id)
        for path in BEACON_ID_PATHS_BSD {
            if let Some(finding) = check_uuid_file(path) {
                if verbose {
                    eprintln!("[persist] beacon ID found at {}", path);
                }
                result.add_finding(finding);
            }
        }
    }

    // --- Windows ---
    #[cfg(windows)]
    {
        use crate::platform::windows;
        use crate::signatures::strings::BEACON_ID_PATHS_WINDOWS;

        // Check beacon ID file paths on Windows
        for path in BEACON_ID_PATHS_WINDOWS {
            if let Some(finding) = check_uuid_file(path) {
                if verbose {
                    eprintln!("[persist] beacon ID found at {}", path);
                }
                result.add_finding(finding);
            }
        }

        // Check Windows registry for HKLM\SOFTWARE\Imix key and beacon ID value
        for finding in windows::check_registry_imix() {
            result.add_finding(finding);
        }

        // Check for registered Windows services with known implant names
        for finding in windows::check_windows_services() {
            result.add_finding(finding);
        }

        // Timestomp detection: check system directories for binaries whose
        // mtime exactly matches cmd.exe, which is suspicious because legitimate
        // binaries are installed at different times.
        let system_paths = [
            r"C:\Windows\System32",
            r"C:\Windows\SysWOW64",
            r"C:\Windows\Temp",
        ];
        for dir in &system_paths {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        // Skip cmd.exe itself -- it is the reference file
                        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if fname.eq_ignore_ascii_case("cmd.exe") {
                            continue;
                        }
                        if windows::check_timestomp(path.to_str().unwrap_or("")) {
                            result.add_finding(Finding::new(
                                "persist",
                                format!(
                                    "Binary timestomped to match cmd.exe: {}",
                                    path.display()
                                ),
                                Tier::Tier2,
                                path.display().to_string(),
                            ));
                        }
                    }
                }
            }
        }
    }

    let _ = verbose; // suppress unused warning when no platform block matches

    result
}
