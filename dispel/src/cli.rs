use clap::{Parser, Subcommand};
use dispel::Layer;

/// Realm C2 detection and remediation tool.
#[derive(Debug, Parser)]
#[command(name = "dispel", version, about)]
pub struct Cli {
    /// Enable verbose output.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan the system for Realm C2 indicators.
    Scan {
        /// Limit scan to a specific layer (default: all layers).
        #[arg(short, long, value_enum)]
        layer: Option<Layer>,

        /// Output results as JSON instead of human-readable text.
        #[arg(long)]
        json: bool,

        /// Generate an incident response report with forensic details.
        #[arg(long)]
        ir: bool,

        /// Path to allowlist file.
        #[arg(long)]
        allowlist: Option<String>,
    },

    /// Detect, quarantine, and remove Realm C2 implants.
    Kill {
        /// Show what would be done without making any changes.
        #[arg(long)]
        dry_run: bool,

        /// Override the default quarantine directory (/var/lib/dispel/quarantine).
        #[arg(long)]
        quarantine_dir: Option<String>,
    },

    /// Watch mode: continuously monitor for Realm C2 indicators.
    Watch {
        /// Limit watch to a specific layer (default: all layers).
        #[arg(short, long, value_enum)]
        layer: Option<Layer>,

        /// Polling interval in seconds.
        #[arg(short, long, default_value_t = 10)]
        interval: u64,

        /// Path to baseline file (JSON) to diff against.
        #[arg(long)]
        baseline: Option<String>,

        /// Output alerts as JSON lines instead of human-readable text.
        #[arg(long)]
        json: bool,

        /// Path to allowlist file.
        #[arg(long)]
        allowlist: Option<String>,

        /// Send findings to local syslog (UDP 127.0.0.1:514) in CEF format.
        #[arg(long)]
        syslog: bool,

        /// Send findings as JSON to a webhook URL (HTTP POST).
        #[arg(long)]
        webhook: Option<String>,
    },
}

impl Cli {
    /// Dispatch to the appropriate subcommand handler.
    pub fn run(&self) -> anyhow::Result<i32> {
        match &self.command {
            Command::Scan { layer, json, ir, allowlist } => {
                run_scan(layer.as_ref(), *json, *ir, allowlist.as_deref(), self.verbose)
            }
            Command::Watch { layer, interval, baseline, json, allowlist, syslog, webhook } => {
                let baseline_secs = baseline.as_deref().and_then(|b| b.parse::<u64>().ok());
                run_watch(
                    layer.as_ref(),
                    *interval,
                    baseline_secs,
                    *json,
                    allowlist.as_deref(),
                    *syslog,
                    webhook.as_deref(),
                    self.verbose,
                )
            }
            Command::Kill { dry_run, quarantine_dir } => {
                run_kill(*dry_run, quarantine_dir.as_deref(), self.verbose)
            }
        }
    }
}

fn run_scan(
    layer: Option<&Layer>,
    json: bool,
    ir: bool,
    allowlist_path: Option<&str>,
    verbose: bool,
) -> anyhow::Result<i32> {
    use dispel::allowlist::Allowlist;
    use dispel::output;
    use dispel::scan;
    use dispel::{Layer, ScanResult};

    let allowlist = match allowlist_path {
        Some(path) => Allowlist::from_file(path)?,
        None => Allowlist::new(),
    };

    if verbose {
        eprintln!("[verbose] Starting scan, layer: {:?}", layer);
    }

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
    if run_all || matches!(layer, Some(Layer::Memory)) {
        result.merge(scan::memory::scan(verbose));
    }

    result.filter(&allowlist);

    if json {
        if ir {
            let report = dispel::ir::generate_report(&result);
            let combined = serde_json::json!({
                "scan": result,
                "ir_report": report,
            });
            println!("{}", serde_json::to_string_pretty(&combined).unwrap_or_default());
        } else {
            output::json::print_result(&result);
        }
    } else {
        output::human::print_result(&result);
        if ir {
            let report = dispel::ir::generate_report(&result);
            output::human::print_ir_report(&report);
        }
    }

    Ok(result.exit_code())
}

fn run_kill(dry_run: bool, quarantine_dir: Option<&str>, verbose: bool) -> anyhow::Result<i32> {
    use dispel::remediate::{KillConfig, run_kill as remediate_kill};
    use std::path::PathBuf;

    let qdir = quarantine_dir.map(PathBuf::from);
    let cfg = KillConfig::new(dry_run, qdir, verbose);
    remediate_kill(&cfg)
}

fn run_watch(
    layer: Option<&Layer>,
    interval: u64,
    baseline: Option<u64>,
    json: bool,
    allowlist_path: Option<&str>,
    syslog: bool,
    webhook: Option<&str>,
    verbose: bool,
) -> anyhow::Result<i32> {
    use dispel::allowlist::Allowlist;
    use dispel::watch;

    let allowlist = match allowlist_path {
        Some(path) => Allowlist::from_file(path)?,
        None => Allowlist::new(),
    };

    watch::run(layer, interval, baseline, json, &allowlist, syslog, webhook, verbose)
}
