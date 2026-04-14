//! Colored terminal output for scan results and incident response reports.
//!
//! This module renders findings and IR reports to stdout with ANSI color codes
//! via the `colored` crate. Color coding is based on detection tier:
//! - Tier1 (name-based): yellow
//! - Tier2 (strong indicator): orange
//! - Tier3 (conclusive): red
//! - Behavioral: magenta
//!
//! Overall severity is shown as a colored banner: green (CLEAN), yellow
//! (SUSPECT), or red (DETECTED).

use colored::Colorize;
use crate::{Finding, ScanResult, Severity, Tier};

/// Print a full scan result to stdout with colored terminal formatting.
///
/// Shows the overall severity status banner, score, individual findings
/// (if any), and a summary line.
pub fn print_result(result: &ScanResult) {
    let header = match result.severity {
        Severity::Clean => "  CLEAN  ".on_green().black().bold(),
        Severity::Suspect => "  SUSPECT  ".on_yellow().black().bold(),
        Severity::Detected => "  DETECTED  ".on_red().white().bold(),
    };

    println!();
    println!("Status: {} (score: {})", header, result.score);
    println!();

    if result.findings.is_empty() {
        println!("  No indicators found.");
    } else {
        println!("Findings ({}):", result.findings.len());
        for finding in &result.findings {
            print_finding(finding);
        }
    }

    println!();
    println!(
        "Summary: {} finding(s), score {}, severity {}",
        result.findings.len(),
        result.score,
        result.severity.as_str()
    );
    println!();
}

/// Print a single finding with a colored tier label.
///
/// Format: `[T1] [layer] description -- detail`
pub fn print_finding(finding: &Finding) {
    let tier_label = format_tier_label(&finding.tier);
    println!(
        "  {} [{}] {} — {}",
        tier_label,
        finding.layer,
        finding.description,
        finding.detail.dimmed()
    );
}

/// Print a finding alert for watch mode, prefixed with a UNIX timestamp.
///
/// Format: `[epoch] ALERT [T1] [layer] description -- detail`
pub fn print_alert(finding: &Finding) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let tier_label = format_tier_label(&finding.tier);
    println!(
        "[{}] ALERT {} [{}] {} — {}",
        now,
        tier_label,
        finding.layer,
        finding.description,
        finding.detail.dimmed()
    );
}

/// Print a full incident response report in human-readable colored format.
///
/// For each detected implant, renders sections for:
/// - File info (SHA256, size, owner, timestamps, permissions)
/// - Extracted config (C2 callback URIs, beacon ID, interval, public keys)
/// - Running processes (PID, parent, user, cmdline, cwd, start time, env)
/// - Network connections (state, local/remote addresses, PID)
/// - Persistence mechanisms (systemd, registry, etc.)
pub fn print_ir_report(report: &crate::ir::IrReport) {


    if report.implants.is_empty() {
        println!("  No implant binaries to report on.");
        return;
    }

    println!();
    println!("{}", "=== INCIDENT RESPONSE REPORT ===".bold());

    for (i, implant) in report.implants.iter().enumerate() {
        println!();
        println!(
            "{} {}",
            format!("--- Implant #{} ---", i + 1).red().bold(),
            implant.path.white().bold()
        );
        println!("  {}", implant.summary_line().yellow().bold());

        // File metadata section
        if let Some(ref fi) = implant.file_info {
            println!();
            println!("  {}", "File Info:".cyan().bold());
            println!("    SHA256:      {}", fi.sha256.yellow());
            println!("    Size:        {} bytes", fi.size_bytes);
            println!("    Owner:       {}:{}", fi.owner, fi.group);
            println!("    Permissions: {}", fi.permissions);
            println!("    Modified:    {}", fi.modified);
            println!("    Accessed:    {}", fi.accessed);
            println!("    Created:     {}", fi.created);
        }

        // Extracted configuration section (compiled-in values from the binary)
        if let Some(ref config) = implant.extracted_config {
            if !config.callback_uris.is_empty() || config.beacon_id.is_some() {
                println!();
                println!("  {}", "Extracted Config (compiled into binary):".cyan().bold());
                if !config.callback_uris.is_empty() {
                    println!("    C2 Callback:");
                    for uri in &config.callback_uris {
                        println!("      {}", uri.red().bold());
                    }
                }
                if let Some(ref interval) = config.callback_interval {
                    println!("    Interval:    {}", interval);
                }
                if let Some(ref bid) = config.beacon_id {
                    println!("    Beacon ID:   {}", bid);
                }
                for item in &config.other {
                    println!("    {}", item.yellow());
                }
            }
        }

        // Running processes section
        if !implant.processes.is_empty() {
            println!();
            println!("  {}", "Running Processes:".cyan().bold());
            for proc in &implant.processes {
                println!("    PID {} (parent: {} [{}])",
                    proc.pid.to_string().yellow().bold(),
                    proc.parent_name,
                    proc.ppid);
                println!("      User:      {}", proc.user);
                println!("      Command:   {}", proc.cmdline.dimmed());
                println!("      CWD:       {}", proc.cwd);
                println!("      Started:   {}", proc.start_time);
                if !proc.env_vars.is_empty() {
                    println!("      Env:");
                    for var in &proc.env_vars {
                        println!("        {}", var.dimmed());
                    }
                }
            }
        }

        // Network connections section
        if !implant.connections.is_empty() {
            println!();
            println!("  {}", "Network Connections:".cyan().bold());
            for conn in &implant.connections {
                // Color-code connection state for quick visual triage
                let state_colored = match conn.state.as_str() {
                    "ESTABLISHED" => conn.state.green().to_string(),
                    "SYN_SENT" => conn.state.yellow().to_string(),
                    "LISTEN" => conn.state.blue().to_string(),
                    _ => conn.state.clone(),
                };
                println!(
                    "    {} {} -> {} (pid {})",
                    state_colored,
                    conn.local_addr.dimmed(),
                    conn.remote_addr.white().bold(),
                    conn.pid
                );
            }
        } else {
            println!();
            println!("  {}", "Network Connections:".cyan().bold());
            println!("    (none found — binary may be dormant or connections already closed)");
        }

        // Persistence mechanisms section
        if !implant.persistence.is_empty() {
            println!();
            println!("  {}", "Persistence:".cyan().bold());
            for p in &implant.persistence {
                println!("    {} — {}", p.mechanism, p.path.dimmed());
            }
        }
    }

    println!();
    println!("{}", "================================".bold());
    println!();
}

/// Format a tier label with the appropriate color for terminal output.
fn format_tier_label(tier: &Tier) -> colored::ColoredString {
    let label = format!("[{}]", tier.label());
    match tier {
        Tier::Tier1 => label.yellow().bold(),
        Tier::Tier2 => label.truecolor(255, 140, 0).bold(), // orange (true color)
        Tier::Tier3 => label.red().bold(),
        Tier::Behavioral => label.magenta().bold(),
    }
}
