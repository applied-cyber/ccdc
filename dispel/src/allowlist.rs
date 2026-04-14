//! Finding suppression via allowlists.
//!
//! An allowlist file defines rules that suppress (filter out) specific findings
//! from scan results. This is used to reduce noise from known-good processes,
//! expected network connections, or entire scan layers.
//!
//! Allowlist file format (one rule per line, `#` comments supported):
//! ```text
//! # Suppress findings mentioning this IP in their detail field
//! ip 10.0.0.1
//!
//! # Suppress findings where detail contains "name=<procname>"
//! proc sshd
//!
//! # Suppress findings whose description contains this substring
//! desc "some expected description"
//!
//! # Suppress all findings from an entire scan layer
//! layer persist
//! ```
//!
//! A finding is suppressed if it matches ANY allowlist criterion (OR logic).

use std::collections::HashSet;

use crate::Finding;

/// A set of suppression rules parsed from an allowlist file.
///
/// Each field is a set of patterns for a different matching dimension:
/// - `ips`: match against the finding's detail field for IP addresses
/// - `procs`: match against "name=<value>" patterns in the detail field
/// - `descriptions`: substring match against the finding's description
/// - `layers`: exact match against the finding's scan layer name
#[derive(Debug, Clone)]
pub struct Allowlist {
    ips: HashSet<String>,
    procs: HashSet<String>,
    descriptions: HashSet<String>,
    layers: HashSet<String>,
}

impl Allowlist {
    /// Create an empty allowlist that suppresses nothing.
    pub fn new() -> Self {
        Self {
            ips: HashSet::new(),
            procs: HashSet::new(),
            descriptions: HashSet::new(),
            layers: HashSet::new(),
        }
    }

    /// Parse allowlist rules from a string.
    ///
    /// Each line has the format `<type> <value>` where type is one of:
    /// `ip`, `proc`, `desc`, `layer`. Blank lines and `#` comments are ignored.
    /// Description values may be optionally quoted with double quotes.
    pub fn parse(content: &str) -> Self {
        let mut al = Self::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Split into at most 2 parts: the rule type keyword and the value
            let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            if parts.len() != 2 {
                continue;
            }
            match parts[0] {
                "ip" => { al.ips.insert(parts[1].trim().to_string()); }
                "proc" => { al.procs.insert(parts[1].trim().to_string()); }
                "desc" => {
                    let val = parts[1].trim();
                    // Strip surrounding quotes if present
                    let val = val.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(val);
                    al.descriptions.insert(val.to_string());
                }
                "layer" => { al.layers.insert(parts[1].trim().to_lowercase()); }
                _ => {} // Unknown rule types are silently ignored
            }
        }
        al
    }

    /// Load and parse an allowlist from a file path.
    pub fn from_file(path: &str) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::parse(&content))
    }

    /// Return true if the given IP address is in the allowlist.
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        self.ips.contains(ip)
    }

    /// Return true if the given process name is in the allowlist.
    pub fn is_proc_allowed(&self, name: &str) -> bool {
        self.procs.contains(name)
    }

    /// Return true if any allowlisted description pattern is a substring of `desc`.
    pub fn is_description_allowed(&self, desc: &str) -> bool {
        self.descriptions.iter().any(|pattern| desc.contains(pattern.as_str()))
    }

    /// Return true if the given layer name is in the allowlist (case-insensitive).
    pub fn is_layer_allowed(&self, layer: &str) -> bool {
        self.layers.contains(&layer.to_lowercase())
    }

    /// Check if a finding should be filtered out by the allowlist.
    ///
    /// Returns true if the finding matches ANY allowlist criterion:
    /// 1. The finding's layer is allowlisted.
    /// 2. The finding's description contains an allowlisted description pattern.
    /// 3. The finding's detail field contains an allowlisted IP.
    /// 4. The finding's detail field contains "name=<allowlisted_proc>".
    pub fn should_allow(&self, finding: &Finding) -> bool {
        // Check layer-level suppression
        if self.is_layer_allowed(&finding.layer) {
            return true;
        }

        // Check description substring match
        if self.is_description_allowed(&finding.description) {
            return true;
        }

        // Check if detail contains an allowlisted IP address
        for ip in &self.ips {
            if finding.detail.contains(ip.as_str()) {
                return true;
            }
        }

        // Check if detail contains an allowlisted process name in "name=X" format
        for proc_name in &self.procs {
            let pattern = format!("name={}", proc_name);
            if finding.detail.contains(&pattern) {
                return true;
            }
        }

        false
    }
}

impl Default for Allowlist {
    fn default() -> Self {
        Self::new()
    }
}
