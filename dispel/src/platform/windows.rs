//! Windows process enumeration, registry inspection, service checks, and TCP
//! connection parsing.
//!
//! This module provides the Windows-specific data collection layer used by
//! scan modules. It uses the Win32 ToolHelp API for process snapshots,
//! QueryFullProcessImageNameW for exe paths, the registry API for persistence
//! checks, `sc.exe` for service queries, and `netstat` for TCP connection state.
//!
//! All functions are conditionally compiled with `#[cfg(windows)]`.

#[cfg(windows)]
use super::ProcessInfo;

#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::CloseHandle;

/// Enumerate all running processes using the Win32 ToolHelp32 snapshot API.
///
/// Takes a point-in-time snapshot of the process table via
/// CreateToolhelp32Snapshot and iterates with Process32First/Process32Next.
/// For each process, attempts to resolve the full executable image path
/// via QueryFullProcessImageNameW.
///
/// Returns an empty Vec if the snapshot cannot be created (e.g. insufficient
/// privileges).
#[cfg(windows)]
pub fn enumerate_processes() -> Vec<ProcessInfo> {
    let mut procs = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return procs;
        }

        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        // dwSize must be set before the first call to Process32First
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) != 0 {
            loop {
                // Extract null-terminated process name from the fixed-size szExeFile array
                let name = entry
                    .szExeFile
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8 as char)
                    .collect::<String>();

                // Resolve the full path to the executable image
                let exe_path = get_process_image_path(entry.th32ProcessID);

                procs.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    name,
                    exe_path,
                    // Windows doesn't track deleted-exe state the way Linux does
                    deleted_exe: false,
                    thread_count: entry.cntThreads,
                });

                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }

    procs
}

/// Query the full executable image path for a process by PID.
///
/// Opens the process with PROCESS_QUERY_LIMITED_INFORMATION (minimal privilege)
/// and calls QueryFullProcessImageNameW to get the NT path.
/// Returns None if the process cannot be opened (e.g. system processes,
/// insufficient privileges).
#[cfg(windows)]
fn get_process_image_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }

        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;

        let result = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
        CloseHandle(handle);

        if result != 0 {
            Some(String::from_utf16_lossy(&buffer[..size as usize]))
        } else {
            None
        }
    }
}

/// Check whether a binary has been timestomped by comparing its mtime against
/// cmd.exe in System32.
///
/// Returns true if the binary's mtime exactly equals cmd.exe's mtime. This is
/// suspicious because legitimate binaries are installed at different times, so
/// an exact match suggests the attacker copied cmd.exe's timestamp to their
/// implant to avoid detection by timestamp-based investigation.
#[cfg(windows)]
pub fn check_timestomp(binary_path: &str) -> bool {
    use std::fs;
    let cmd_meta = match fs::metadata(r"C:\Windows\System32\cmd.exe") {
        Ok(m) => m,
        Err(_) => return false,
    };
    let bin_meta = match fs::metadata(binary_path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    match (cmd_meta.modified(), bin_meta.modified()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Parse TCP connections from `netstat -ano -p TCP` output.
///
/// Shells out to netstat and parses the tabular output. Each line has the
/// format: `TCP  local_addr:port  remote_addr:port  STATE  PID`
///
/// Returns an empty Vec if netstat fails or produces unexpected output.
#[cfg(windows)]
pub fn read_tcp_connections() -> Vec<WindowsTcpConnection> {
    use std::process::Command;

    let mut connections = Vec::new();

    let output = Command::new("netstat")
        .args(["-ano", "-p", "TCP"])
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        // Skip the first 4 lines (netstat header and column labels)
        for line in stdout.lines().skip(4) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Expected format: TCP <local> <remote> <state> <pid>
            if parts.len() >= 5 && parts[0] == "TCP" {
                if let (Some(local), Some(remote)) = (
                    parse_windows_addr(parts[1]),
                    parse_windows_addr(parts[2]),
                ) {
                    let pid: u32 = parts[4].parse().unwrap_or(0);
                    connections.push(WindowsTcpConnection {
                        local_addr: local.0,
                        local_port: local.1,
                        remote_addr: remote.0,
                        remote_port: remote.1,
                        state: parts[3].to_string(),
                        owning_pid: pid,
                    });
                }
            }
        }
    }

    connections
}

/// A TCP connection entry parsed from Windows netstat output.
#[cfg(windows)]
#[derive(Debug, Clone)]
pub struct WindowsTcpConnection {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    /// Connection state string (e.g. "ESTABLISHED", "LISTENING", "TIME_WAIT").
    pub state: String,
    /// PID of the process owning this connection.
    pub owning_pid: u32,
}

/// Parse a "host:port" or "[ipv6]:port" address string from netstat output.
///
/// Uses rfind(':') to handle IPv6 addresses that contain colons. Returns
/// the address string and port number, or None if parsing fails.
#[cfg(windows)]
fn parse_windows_addr(s: &str) -> Option<(String, u16)> {
    if let Some(last_colon) = s.rfind(':') {
        let addr = &s[..last_colon];
        let port: u16 = s[last_colon + 1..].parse().ok()?;
        Some((addr.to_string(), port))
    } else {
        None
    }
}

/// Check the Windows registry for Realm C2 persistence artifacts.
///
/// Looks for `HKLM\SOFTWARE\Imix` which is the registry key used by the imix
/// agent. If found, also reads the `system-id` value which contains the beacon
/// UUID. Returns a Tier1 finding for the key's existence and a Tier2 finding
/// if the system-id contains a valid UUID v4.
#[cfg(windows)]
pub fn check_registry_imix() -> Vec<crate::Finding> {
    use crate::{Finding, Tier};
    use crate::scan::persist::is_uuid_v4;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };

    let mut findings = Vec::new();

    unsafe {
        // Null-terminated UTF-16 encoded registry subkey path
        let subkey: Vec<u16> = "SOFTWARE\\Imix\0".encode_utf16().collect();
        let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();

        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        );

        // Status 0 means the key was opened successfully (it exists)
        if status == 0 {
            findings.push(Finding::new(
                "persist",
                "Registry key HKLM\\SOFTWARE\\Imix exists",
                Tier::Tier1,
                "HKLM\\SOFTWARE\\Imix",
            ));

            // Try to read the system-id value (beacon UUID)
            let value_name: Vec<u16> = "system-id\0".encode_utf16().collect();
            let mut data = [0u8; 256];
            let mut data_size = data.len() as u32;
            let mut data_type = 0u32;

            let val_status = RegQueryValueExW(
                hkey,
                value_name.as_ptr(),
                std::ptr::null(),
                &mut data_type,
                data.as_mut_ptr(),
                &mut data_size,
            );

            if val_status == 0 && data_type == REG_SZ {
                // Registry REG_SZ values are stored as null-terminated UTF-16LE.
                // Convert the raw bytes back to a Rust string.
                let uuid_bytes = &data[..data_size as usize];
                let uuid_str = String::from_utf16_lossy(
                    &uuid_bytes
                        .chunks(2)
                        .filter_map(|c| {
                            if c.len() == 2 {
                                Some(u16::from_le_bytes([c[0], c[1]]))
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<u16>>(),
                );
                let trimmed = uuid_str.trim_end_matches('\0');
                if is_uuid_v4(trimmed) {
                    findings.push(Finding::new(
                        "persist",
                        "Beacon ID found in registry",
                        Tier::Tier2,
                        format!("HKLM\\SOFTWARE\\Imix\\system-id = {}", trimmed),
                    ));
                }
            }

            RegCloseKey(hkey);
        }
    }

    findings
}

/// Check for registered Windows services with known Realm C2 service names.
///
/// Shells out to `sc.exe query <name>` for each known service name. If the
/// service exists (any state: RUNNING, STOPPED, PAUSED), emits a Tier1 finding
/// with the first few lines of sc output as detail.
#[cfg(windows)]
pub fn check_windows_services() -> Vec<crate::Finding> {
    use crate::{Finding, Tier};
    use std::process::Command;

    let mut findings = Vec::new();

    for svc_name in crate::signatures::strings::TIER1_SERVICE_NAMES {
        let output = Command::new("sc.exe")
            .args(["query", svc_name])
            .output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Any of these states means the service is registered
            if stdout.contains("RUNNING")
                || stdout.contains("STOPPED")
                || stdout.contains("PAUSED")
            {
                findings.push(Finding::new(
                    "persist",
                    format!("Windows service '{}' exists", svc_name),
                    Tier::Tier1,
                    // Include the first 5 lines of sc output for context
                    stdout.lines().take(5).collect::<Vec<_>>().join(" | "),
                ));
            }
        }
    }

    findings
}
