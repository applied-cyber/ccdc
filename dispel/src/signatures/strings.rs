use crate::Tier;

// --- Tier 3: Conclusive binary-level evidence ---

/// gRPC service paths unique to Realm C2's C2 service proto definition.
pub const GRPC_PATHS: &[&str] = &[
    "/c2.C2/ClaimTasks",
    "/c2.C2/FetchAsset",
    "/c2.C2/ReportCredential",
    "/c2.C2/ReportFile",
    "/c2.C2/ReportProcessList",
    "/c2.C2/ReportOutput",
    "/c2.C2/ReverseShell",
    "/c2.C2/CreatePortal",
];

/// Eldritch scripting engine function names that are highly distinctive and not found in
/// legitimate software.
pub const ELDRITCH_DISTINCTIVE: &[&str] = &[
    "_terminate_this_process_clowntown",
    "dll_inject",
    "dll_reflect",
    "reverse_shell_pty",
    "reverse_shell_repl",
];

/// Eldritch agent API surface — functions exported by the imix agent runtime.
/// Only includes names distinctive enough to avoid false positives in system binaries.
pub const ELDRITCH_AGENT_API: &[&str] = &[
    "report_credential",
    "report_process_list",
    "report_task_output",
    "get_callback_interval",
    "set_callback_interval",
    "set_callback_uri",
];

/// Eldritch offensive capability function names.
/// Removed short/generic strings (ncat, arp_scan, port_scan) that match in legitimate binaries.
/// reverse_shell_pty/repl already in ELDRITCH_DISTINCTIVE.
pub const ELDRITCH_OFFENSIVE: &[&str] = &[
    "create_portal",
    "ssh_exec",
    "ssh_copy",
];

/// Eldritch report module function signatures.
pub const ELDRITCH_REPORT: &[&str] = &[
    "report::file",
    "report::process_list",
    "report::ssh_key",
    "report::user_password",
    "report::ntlm_hash",
    "report::screenshot",
];

// --- Tier 2: Strong indicators ---

/// Rust module path strings and protobuf type names found in Realm C2 binaries.
/// Removed generic strings (ProcessList, FileMetadata, realm::, DnsPacket) that
/// match in legitimate binaries like systemd, k3s, docker, etc.
pub const TIER2_STRINGS: &[&str] = &[
    "imix-v",
    "imix::",
    "eldritch::",
    "Credential_Kind",
    "KIND_NTLM_HASH",
    "KIND_SSH_KEY",
    "KIND_PASSWORD",
    "ChachaCodec",
];

// --- Tier 1: Definitive name-based artifacts ---

/// Known imix agent binary names.
pub const TIER1_BINARY_NAMES: &[&str] = &["imix", "imix.exe"];

/// Known imix service/daemon names.
pub const TIER1_SERVICE_NAMES: &[&str] = &[
    "imix",
    "imixsvc",
    "Imix c2 agent",
    "Imix C2 Agent",
];

/// Known imix install paths on Linux.
pub const TIER1_INSTALL_PATHS_LINUX: &[&str] = &[
    "/bin/imix",
    "/usr/bin/imix",
    "/tmp/imix",
    "/var/tmp/imix",
];

/// Known imix install paths on Windows.
#[cfg(windows)]
pub const TIER1_INSTALL_PATHS_WINDOWS: &[&str] = &[
    r"C:\Windows\System32\imix.exe",
    r"C:\Windows\Temp\imix.exe",
    r"C:\ProgramData\imix.exe",
];

// --- Persistence artifact paths ---

/// Paths where Realm C2 may store its beacon/agent ID on Linux.
pub const BEACON_ID_PATHS_LINUX: &[&str] = &[
    "/etc/imix/agent_id",
    "/var/lib/imix/agent_id",
    "/tmp/.imix_id",
];

/// Paths where Realm C2 may store its beacon/agent ID on BSD systems.
pub const BEACON_ID_PATHS_BSD: &[&str] = &[
    "/etc/imix/agent_id",
    "/var/db/imix/agent_id",
    "/tmp/.imix_id",
];

/// Paths where Realm C2 may store its beacon/agent ID on Windows.
#[cfg(windows)]
pub const BEACON_ID_PATHS_WINDOWS: &[&str] = &[
    r"C:\ProgramData\imix\agent_id",
    r"C:\Windows\Temp\.imix_id",
];

/// Systemd unit file drop locations to check for imix persistence.
pub const SYSTEMD_PATHS: &[&str] = &[
    "/etc/systemd/system/imix.service",
    "/etc/systemd/system/imixsvc.service",
    "/lib/systemd/system/imix.service",
    "/usr/lib/systemd/system/imix.service",
];

/// SysV init script path for imix.
pub const SYSVINIT_PATH: &str = "/etc/init.d/imix";

/// BSD rc.d script path for imix.
pub const BSD_RC_PATH: &str = "/etc/rc.d/imix";

/// Windows registry key used by imix for persistence.
pub const REGISTRY_KEY_IMIX: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\imix";

/// Windows registry value name for the imix agent system ID.
pub const REGISTRY_VALUE_SYSTEM_ID: &str = "ImixSystemId";

/// Returns all signature patterns with their associated tier classification.
/// Used by scanning modules to build the Aho-Corasick automaton.
pub fn all_signatures() -> Vec<(&'static str, Tier)> {
    let mut sigs: Vec<(&'static str, Tier)> = Vec::new();

    for &s in GRPC_PATHS {
        sigs.push((s, Tier::Tier3));
    }
    for &s in ELDRITCH_DISTINCTIVE {
        sigs.push((s, Tier::Tier3));
    }
    for &s in ELDRITCH_AGENT_API {
        sigs.push((s, Tier::Tier3));
    }
    for &s in ELDRITCH_OFFENSIVE {
        sigs.push((s, Tier::Tier3));
    }
    for &s in ELDRITCH_REPORT {
        sigs.push((s, Tier::Tier3));
    }
    for &s in TIER2_STRINGS {
        sigs.push((s, Tier::Tier2));
    }
    // NOTE: TIER1_BINARY_NAMES, TIER1_SERVICE_NAMES, and TIER1_INSTALL_PATHS_LINUX
    // are intentionally excluded from binary content scanning. They are too short/generic
    // ("imix" = 4 chars) and cause massive false positives. They are only used for
    // process name matching and file path existence checks in scan/proc.rs.

    sigs
}
