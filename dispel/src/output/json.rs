//! JSON output for scan results and individual findings.
//!
//! Provides two output modes:
//! - `print_result`: pretty-printed JSON of the full ScanResult (for one-shot scans).
//! - `print_finding_line`: compact single-line JSON per finding (for watch mode
//!   streaming, compatible with `jq` and log pipelines).

use crate::{Finding, ScanResult};

/// Print a full scan result as pretty-printed JSON to stdout.
///
/// The output includes the findings array, aggregate score, and severity level.
/// On serialization error, prints the error to stderr instead.
pub fn print_result(result: &ScanResult) {
    match serde_json::to_string_pretty(result) {
        Ok(s) => println!("{}", s),
        Err(e) => eprintln!("JSON serialization error: {}", e),
    }
}

/// Print a single finding as a compact JSON line to stdout.
///
/// Used in watch mode to emit one JSON object per line (NDJSON format),
/// suitable for streaming to log aggregators or piping through `jq`.
pub fn print_finding_line(finding: &Finding) {
    match serde_json::to_string(finding) {
        Ok(s) => println!("{}", s),
        Err(e) => eprintln!("JSON serialization error: {}", e),
    }
}
