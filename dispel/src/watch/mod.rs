//! Continuous monitoring mode with deduplication.
//!
//! Watch mode runs scan layers in a polling loop and reports only new or
//! recurring findings. Deduplication suppresses identical findings for a
//! configurable window (default 300s) to avoid alert fatigue.
//!
//! Features:
//! - Optional baseline period: learns existing findings before alerting.
//! - Memory scan throttling: runs the memory scan layer every Nth iteration
//!   to reduce CPU overhead (memory scanning is expensive).
//! - Output to human-readable terminal, JSON lines, CEF syslog, and/or webhook.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::allowlist::Allowlist;
use crate::Layer;
use crate::output::{human, json, syslog};
use crate::{scan, Finding, ScanResult};

/// Tracks which findings have been reported recently to suppress duplicates.
///
/// Each entry maps a dedup key (layer + description) to:
/// - `first_seen`: when the finding was first observed
/// - `last_reported`: when the finding was last emitted as an alert
/// - `weight`: the tier weight of the finding (unused currently, reserved for scoring)
struct DedupTracker {
    seen: HashMap<String, (Instant, Instant, u32)>,
    /// How long to suppress a finding after it was last reported.
    suppress_duration: Duration,
}

impl DedupTracker {
    fn new() -> Self {
        Self {
            seen: HashMap::new(),
            suppress_duration: Duration::from_secs(300),
        }
    }

    /// Return true if this finding should be reported (not suppressed).
    ///
    /// A finding is suppressed if it was reported within the last `suppress_duration`.
    /// Otherwise, it is marked as reported and returns true.
    fn should_report(&mut self, finding: &Finding) -> bool {
        let key = finding.dedup_key();
        let now = Instant::now();

        if let Some((_, last_reported, _)) = self.seen.get(&key) {
            if now.duration_since(*last_reported) < self.suppress_duration {
                return false;
            }
        }

        self.seen.insert(key, (now, now, finding.tier.weight()));
        true
    }

    /// Remove stale entries that are older than 2x the suppress duration.
    /// Prevents the dedup map from growing unboundedly in long-running sessions.
    fn cleanup(&mut self) {
        let now = Instant::now();
        self.seen.retain(|_, (first_seen, _, _)| {
            now.duration_since(*first_seen) < self.suppress_duration * 2
        });
    }
}

/// Run continuous monitoring in a polling loop. Never returns under normal
/// operation (loops forever until Ctrl+C).
///
/// # Arguments
/// - `layer`: optional layer filter; None = scan all layers.
/// - `interval_secs`: seconds between scan iterations.
/// - `baseline_secs`: if Some, sleep this long then run one scan to learn
///   existing findings before entering the alert loop.
/// - `json_output`: emit JSON lines instead of colored terminal output.
/// - `allowlist`: finding suppression rules.
/// - `syslog_enabled`: also send findings to local syslog (UDP 127.0.0.1:514).
/// - `webhook_url`: also POST findings as JSON to this HTTP URL.
/// - `verbose`: enable diagnostic output on stderr.
pub fn run(
    layer: Option<&Layer>,
    interval_secs: u64,
    baseline_secs: Option<u64>,
    json_output: bool,
    allowlist: &Allowlist,
    syslog_enabled: bool,
    webhook_url: Option<&str>,
    verbose: bool,
) -> anyhow::Result<i32> {
    let interval = Duration::from_secs(interval_secs);
    let mut dedup = DedupTracker::new();

    if !json_output {
        eprintln!("dispel watch mode (interval={}s, Ctrl+C to stop)", interval_secs);
    }

    // Optional baseline phase: run one scan and feed all findings into the
    // dedup tracker so they are treated as "already known" and won't alert
    // on the first real iteration.
    if let Some(baseline) = baseline_secs {
        if !json_output {
            eprintln!("Baselining for {}s...", baseline);
        }
        std::thread::sleep(Duration::from_secs(baseline));
        let result = run_scan_layers(layer, verbose, false);
        for finding in &result.findings {
            dedup.should_report(finding);
        }
        if !json_output {
            eprintln!("Baseline complete. {} patterns learned. Monitoring...", dedup.seen.len());
        }
    }

    // Memory scans are expensive. Only run them every MEMORY_SCAN_EVERY iterations
    // to keep CPU usage reasonable during continuous monitoring.
    let mut memory_scan_counter: u64 = 0;
    const MEMORY_SCAN_EVERY: u64 = 6;

    loop {
        let skip_memory = memory_scan_counter % MEMORY_SCAN_EVERY != 0;
        memory_scan_counter += 1;

        let mut result = run_scan_layers(layer, verbose, skip_memory);
        result.filter(allowlist);

        // Only report findings that pass the dedup check
        for finding in &result.findings {
            if dedup.should_report(finding) {
                if json_output {
                    json::print_finding_line(finding);
                } else {
                    human::print_alert(finding);
                }
                if syslog_enabled {
                    syslog::send_to_syslog(finding);
                }
                if let Some(url) = webhook_url {
                    syslog::send_to_webhook(finding, url);
                }
            }
        }

        dedup.cleanup();
        std::thread::sleep(interval);
    }
}

/// Execute the requested scan layers and return a merged result.
///
/// If `skip_memory` is true, the memory scan layer is skipped even if
/// requested, to reduce CPU overhead in watch mode.
fn run_scan_layers(layer: Option<&Layer>, verbose: bool, skip_memory: bool) -> ScanResult {
    let mut result = ScanResult::new();

    let run_all = layer.is_none();

    if run_all || matches!(layer, Some(Layer::Proc)) {
        result.merge(scan::proc::scan(verbose));
    }
    if run_all || matches!(layer, Some(Layer::Net)) {
        result.merge(scan::net::scan(verbose));
    }
    if run_all || matches!(layer, Some(Layer::Persist)) {
        result.merge(scan::persist::scan(verbose));
    }
    if run_all || matches!(layer, Some(Layer::Behavior)) {
        result.merge(scan::behavior::scan(verbose));
    }
    if !skip_memory && (run_all || matches!(layer, Some(Layer::Memory))) {
        result.merge(scan::memory::scan(verbose));
    }

    result
}
