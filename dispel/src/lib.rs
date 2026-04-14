//! dispel — host-based detection and remediation library for the Realm C2 framework.
//!
//! This crate provides multi-layer scanning for Realm C2 (imix agent) artifacts:
//! - **proc**: binary inspection via Aho-Corasick string matching and SHA256 hashes
//! - **net**: suspicious network connections (known C2 ports, DNS tunneling)
//! - **persist**: persistence mechanisms (beacon IDs, systemd units, registry keys)
//! - **behavior**: runtime anomalies (reverse shells, credential harvesting)
//! - **memory**: live process memory scanning for implant signatures
//!
//! Findings are scored by tier (T1–T3 + Behavioral) and aggregated into an
//! overall severity (CLEAN / SUSPECT / DETECTED). Output formats include
//! human-readable terminal, JSON, CEF syslog, and webhook.

pub mod signatures;
pub mod output;
pub mod scan;
pub mod platform;
pub mod allowlist;
pub mod watch;
pub mod ir;
pub mod remediate;

use serde::{Deserialize, Serialize};

/// Tier classification for Realm C2 detection findings.
/// Each tier has a weight used for severity scoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Definitive artifact (binary name, service name, install path). Weight = 1 per hit,
    /// but presence alone can trigger Detected.
    Tier1,
    /// Strong indicator (distinctive strings, module paths). Weight = 3.
    Tier2,
    /// Conclusive binary-level evidence (gRPC paths, Eldritch API). Weight = 5.
    Tier3,
    /// Runtime behavior (network patterns, process behavior). Weight = 4.
    Behavioral,
}

impl Tier {
    pub fn weight(&self) -> u32 {
        match self {
            Tier::Tier1 => 1,
            Tier::Tier2 => 3,
            Tier::Tier3 => 5,
            Tier::Behavioral => 4,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Tier::Tier1 => "T1",
            Tier::Tier2 => "T2",
            Tier::Tier3 => "T3",
            Tier::Behavioral => "BH",
        }
    }
}

/// Overall severity assessment based on accumulated score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// No indicators found. Score = 0.
    Clean,
    /// Low-confidence indicators present. Score 1-4.
    Suspect,
    /// High-confidence detection. Score >= 5.
    Detected,
}

impl Severity {
    pub fn score(&self) -> u32 {
        match self {
            Severity::Clean => 0,
            Severity::Suspect => 1,
            Severity::Detected => 5,
        }
    }

    pub fn from_score(score: u32) -> Self {
        if score == 0 {
            Severity::Clean
        } else if score < 5 {
            Severity::Suspect
        } else {
            Severity::Detected
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Clean => "CLEAN",
            Severity::Suspect => "SUSPECT",
            Severity::Detected => "DETECTED",
        }
    }
}

/// Layer scanned — also used as CLI value enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Proc,
    Net,
    Persist,
    Behavior,
    Memory,
}

/// A single detection finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Which scan layer produced this finding (e.g. "proc", "net", "persist").
    pub layer: String,
    /// Human-readable description of what was found.
    pub description: String,
    /// Classification tier for this finding.
    pub tier: Tier,
    /// Additional context or raw evidence (path, PID, string, etc.).
    pub detail: String,
}

impl Finding {
    pub fn new(layer: impl Into<String>, description: impl Into<String>, tier: Tier, detail: impl Into<String>) -> Self {
        Self {
            layer: layer.into(),
            description: description.into(),
            tier,
            detail: detail.into(),
        }
    }

    /// Deduplication key: layer + description combo, used to deduplicate identical findings.
    pub fn dedup_key(&self) -> String {
        format!("{}:{}", self.layer, self.description)
    }
}

/// Accumulated scan result across one or more layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub score: u32,
    pub severity: Severity,
}

impl ScanResult {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            score: 0,
            severity: Severity::Clean,
        }
    }

    /// Add a finding and update score/severity.
    pub fn add_finding(&mut self, finding: Finding) {
        self.score += finding.tier.weight();
        self.findings.push(finding);
        self.severity = Severity::from_score(self.score);
    }

    /// Merge another ScanResult into this one.
    pub fn merge(&mut self, other: ScanResult) {
        for f in other.findings {
            self.add_finding(f);
        }
    }

    /// Filter out findings that match the allowlist and recalculate score/severity.
    pub fn filter(&mut self, allowlist: &allowlist::Allowlist) {
        self.findings.retain(|f| !allowlist.should_allow(f));
        self.score = self.findings.iter().map(|f| f.tier.weight()).sum();
        self.severity = Severity::from_score(self.score);
    }

    /// Exit code: 0 = clean, 1 = suspect, 2 = detected, 3 = error.
    pub fn exit_code(&self) -> i32 {
        match self.severity {
            Severity::Clean => 0,
            Severity::Suspect => 1,
            Severity::Detected => 2,
        }
    }
}

impl Default for ScanResult {
    fn default() -> Self {
        Self::new()
    }
}
