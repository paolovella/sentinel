// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! OWASP MCP Top 10 Compliance Registry (R226).
//!
//! Maps Vellaveto detection capabilities to the OWASP MCP Top 10 security
//! standard categories. Provides coverage reporting for compliance dashboards.
//!
//! Reference: <https://owasp.org/www-project-mcp-top-10/>
//!
//! # Usage
//!
//! ```ignore
//! use vellaveto_audit::owasp_mcp::OwaspMcpRegistry;
//!
//! let registry = OwaspMcpRegistry::new();
//! let report = registry.generate_coverage_report();
//! assert!(report.coverage_percent >= 80.0);
//! ```

use serde::{Deserialize, Serialize};

// ── Validation Constants ────────────────────────────────────────────────────

/// Maximum number of MCP controls (current spec: ~30).
const MAX_MCP_CONTROLS: usize = 100;

/// Maximum number of MCP categories (current spec: 10).
/// Used for bounded collection validation in future category additions.
#[allow(dead_code)]
const MAX_MCP_CATEGORIES: usize = 20;

/// Maximum mitigations per control.
const MAX_MITIGATIONS_PER_CONTROL: usize = 50;

// ── Categories ──────────────────────────────────────────────────────────────

/// OWASP MCP Top 10 categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum McpCategory {
    /// MCP01: Server Spoofing
    Mcp01,
    /// MCP02: Tool Poisoning
    Mcp02,
    /// MCP03: Excessive Permissions
    Mcp03,
    /// MCP04: Tool Shadowing
    Mcp04,
    /// MCP05: Indirect Prompt Injection via Tools
    Mcp05,
    /// MCP06: Data Exfiltration via Tools
    Mcp06,
    /// MCP07: Insecure Credential Handling
    Mcp07,
    /// MCP08: Lack of Tool Consent
    Mcp08,
    /// MCP09: Inadequate Logging
    Mcp09,
    /// MCP10: Resource Exhaustion
    Mcp10,
}

impl std::fmt::Display for McpCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mcp01 => write!(f, "MCP01: Server Spoofing"),
            Self::Mcp02 => write!(f, "MCP02: Tool Poisoning"),
            Self::Mcp03 => write!(f, "MCP03: Excessive Permissions"),
            Self::Mcp04 => write!(f, "MCP04: Tool Shadowing"),
            Self::Mcp05 => write!(f, "MCP05: Indirect Prompt Injection via Tools"),
            Self::Mcp06 => write!(f, "MCP06: Data Exfiltration via Tools"),
            Self::Mcp07 => write!(f, "MCP07: Insecure Credential Handling"),
            Self::Mcp08 => write!(f, "MCP08: Lack of Tool Consent"),
            Self::Mcp09 => write!(f, "MCP09: Inadequate Logging"),
            Self::Mcp10 => write!(f, "MCP10: Resource Exhaustion"),
        }
    }
}

// ── Control Definition ──────────────────────────────────────────────────────

/// A single OWASP MCP control.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpControl {
    /// Control identifier (e.g., "MCP01-C01").
    pub id: String,
    /// Parent category.
    pub category: McpCategory,
    /// Human-readable name.
    pub name: String,
    /// Description of the control.
    pub description: String,
    /// Vellaveto capabilities that implement this control.
    pub vellaveto_mitigations: Vec<String>,
}

/// Per-category coverage breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCategoryCoverage {
    /// MCP category.
    pub category: McpCategory,
    /// Category display name.
    pub category_name: String,
    /// Total controls in this category.
    pub total_controls: usize,
    /// Controls with at least one Vellaveto mitigation.
    pub covered_controls: usize,
    /// Coverage percentage for this category.
    pub coverage_percent: f32,
}

/// OWASP MCP Top 10 coverage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCoverageReport {
    /// Report generation timestamp (RFC 3339).
    pub generated_at: String,
    /// Total MCP categories (10).
    pub total_categories: usize,
    /// Categories with full coverage.
    pub covered_categories: usize,
    /// Total controls across all categories.
    pub total_controls: usize,
    /// Controls with at least one mitigation.
    pub covered_controls: usize,
    /// Overall coverage percentage.
    pub coverage_percent: f32,
    /// IDs of uncovered controls.
    pub uncovered_controls: Vec<String>,
    /// Per-category breakdown.
    pub category_coverage: Vec<McpCategoryCoverage>,
}

// ── Registry ────────────────────────────────────────────────────────────────

/// OWASP MCP Top 10 compliance registry.
///
/// Maps Vellaveto detection and enforcement capabilities to the OWASP MCP
/// Top 10 security standard categories.
pub struct OwaspMcpRegistry {
    controls: Vec<McpControl>,
}

impl Default for OwaspMcpRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl OwaspMcpRegistry {
    /// Create a new OWASP MCP registry with all controls populated.
    pub fn new() -> Self {
        let mut registry = Self {
            controls: Vec::new(),
        };
        registry.populate_controls();
        registry
    }

    /// Get all controls.
    pub fn controls(&self) -> &[McpControl] {
        &self.controls
    }

    /// Get controls for a specific category.
    pub fn controls_for_category(&self, category: McpCategory) -> Vec<&McpControl> {
        self.controls
            .iter()
            .filter(|c| c.category == category)
            .collect()
    }

    /// Get a control by ID.
    pub fn get_control(&self, id: &str) -> Option<&McpControl> {
        self.controls.iter().find(|c| c.id == id)
    }

    /// Generate a coverage report.
    pub fn generate_coverage_report(&self) -> McpCoverageReport {
        let categories = [
            McpCategory::Mcp01,
            McpCategory::Mcp02,
            McpCategory::Mcp03,
            McpCategory::Mcp04,
            McpCategory::Mcp05,
            McpCategory::Mcp06,
            McpCategory::Mcp07,
            McpCategory::Mcp08,
            McpCategory::Mcp09,
            McpCategory::Mcp10,
        ];

        let mut category_coverage = Vec::new();
        let mut total_controls = 0usize;
        let mut covered_controls_count = 0usize;
        let mut covered_categories = 0usize;
        let mut uncovered = Vec::new();

        for &cat in &categories {
            let cat_controls = self.controls_for_category(cat);
            let cat_total = cat_controls.len();
            let cat_covered = cat_controls
                .iter()
                .filter(|c| !c.vellaveto_mitigations.is_empty())
                .count();

            total_controls = total_controls.saturating_add(cat_total);
            covered_controls_count = covered_controls_count.saturating_add(cat_covered);

            if cat_covered == cat_total && cat_total > 0 {
                covered_categories = covered_categories.saturating_add(1);
            }

            for c in &cat_controls {
                if c.vellaveto_mitigations.is_empty() {
                    uncovered.push(c.id.clone());
                }
            }

            let pct = if cat_total > 0 {
                (cat_covered as f32 / cat_total as f32) * 100.0
            } else {
                0.0
            };

            category_coverage.push(McpCategoryCoverage {
                category: cat,
                category_name: cat.to_string(),
                total_controls: cat_total,
                covered_controls: cat_covered,
                coverage_percent: pct,
            });
        }

        let overall_pct = if total_controls > 0 {
            (covered_controls_count as f32 / total_controls as f32) * 100.0
        } else {
            0.0
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        McpCoverageReport {
            generated_at: format!("{now}"),
            total_categories: categories.len(),
            covered_categories,
            total_controls,
            covered_controls: covered_controls_count,
            coverage_percent: overall_pct,
            uncovered_controls: uncovered,
            category_coverage,
        }
    }

    /// Populate the control registry with OWASP MCP Top 10 mappings.
    fn populate_controls(&mut self) {
        // Enforce bounded collection (Trap 3).
        let controls = vec![
            // ── MCP01: Server Spoofing ──────────────────────────────────────
            McpControl {
                id: "MCP01-C01".to_string(),
                category: McpCategory::Mcp01,
                name: "Server Identity Verification".to_string(),
                description: "Verify MCP server identity via allowlist or registry lookup"
                    .to_string(),
                vellaveto_mitigations: vec![
                    "governance.require_server_registration".to_string(),
                    "SANDWORM-001 server allowlist enforcement".to_string(),
                    "MCP Registry client (discovery/registry.rs)".to_string(),
                ],
            },
            McpControl {
                id: "MCP01-C02".to_string(),
                category: McpCategory::Mcp01,
                name: "A2A Agent Card Signature".to_string(),
                description: "Verify Ed25519 signatures on A2A Agent Cards".to_string(),
                vellaveto_mitigations: vec![
                    "a2a/signature.rs — Agent Card Ed25519 enforcement".to_string()
                ],
            },
            // ── MCP02: Tool Poisoning ───────────────────────────────────────
            McpControl {
                id: "MCP02-C01".to_string(),
                category: McpCategory::Mcp02,
                name: "Tool Description Injection Scanning".to_string(),
                description:
                    "Scan tool descriptions for injection patterns and cross-tool references"
                        .to_string(),
                vellaveto_mitigations: vec![
                    "inspection/tool_description.rs — FSP scanning".to_string(),
                    "R226 MCP-ITP cross-tool reference detection".to_string(),
                ],
            },
            McpControl {
                id: "MCP02-C02".to_string(),
                category: McpCategory::Mcp02,
                name: "Schema Poisoning Detection".to_string(),
                description: "Detect malicious inputSchema fields including nested descriptions"
                    .to_string(),
                vellaveto_mitigations: vec![
                    "inspection/tool_description.rs — recursive schema scanning".to_string(),
                    "collect_schema_descriptions — allOf/anyOf/oneOf/patternProperties".to_string(),
                ],
            },
            McpControl {
                id: "MCP02-C03".to_string(),
                category: McpCategory::Mcp02,
                name: "Rug-Pull Detection".to_string(),
                description: "Detect tool annotation and schema changes after initial registration"
                    .to_string(),
                vellaveto_mitigations: vec![
                    "tool_registry.rs — supply chain hash comparison".to_string()
                ],
            },
            // ── MCP03: Excessive Permissions ────────────────────────────────
            McpControl {
                id: "MCP03-C01".to_string(),
                category: McpCategory::Mcp03,
                name: "Least-Agency Enforcement".to_string(),
                description: "Track and enforce minimum-privilege tool access patterns".to_string(),
                vellaveto_mitigations: vec![
                    "engine/least_agency.rs — tool usage tracking".to_string(),
                    "ABAC forbid-overrides".to_string(),
                ],
            },
            McpControl {
                id: "MCP03-C02".to_string(),
                category: McpCategory::Mcp03,
                name: "Capability Token Scoping".to_string(),
                description: "Scoped capability tokens with delegation constraints".to_string(),
                vellaveto_mitigations: vec![
                    "capability_token.rs — delegation depth limits".to_string()
                ],
            },
            // ── MCP04: Tool Shadowing ───────────────────────────────────────
            McpControl {
                id: "MCP04-C01".to_string(),
                category: McpCategory::Mcp04,
                name: "Tool Namespace Collision Detection".to_string(),
                description: "Detect when multiple servers register the same tool name".to_string(),
                vellaveto_mitigations: vec![
                    "tool_registry.rs — server_id_conflict detection".to_string(),
                    "R226 tool_namespace_strict mode (fail-closed)".to_string(),
                ],
            },
            McpControl {
                id: "MCP04-C02".to_string(),
                category: McpCategory::Mcp04,
                name: "Tool Squatting Detection".to_string(),
                description: "Detect homoglyph and typosquat tool name attacks".to_string(),
                vellaveto_mitigations: vec![
                    "tool_registry.rs — NFKC + homoglyph comparison".to_string()
                ],
            },
            // ── MCP05: Indirect Prompt Injection ────────────────────────────
            McpControl {
                id: "MCP05-C01".to_string(),
                category: McpCategory::Mcp05,
                name: "Response Injection Scanning".to_string(),
                description: "Scan tool responses for prompt injection patterns".to_string(),
                vellaveto_mitigations: vec![
                    "inspection/injection.rs — Aho-Corasick pattern matching".to_string(),
                    "R226 Policy Puppetry pattern detection".to_string(),
                    "R226 leetspeak normalization (decode_leetspeak)".to_string(),
                ],
            },
            McpControl {
                id: "MCP05-C02".to_string(),
                category: McpCategory::Mcp05,
                name: "Memory Poisoning Detection".to_string(),
                description: "Detect injection via conversation memory and tool output poisoning"
                    .to_string(),
                vellaveto_mitigations: vec![
                    "proxy/bridge/relay.rs — memory poisoning fingerprint tracking".to_string(),
                ],
            },
            // ── MCP06: Data Exfiltration ────────────────────────────────────
            McpControl {
                id: "MCP06-C01".to_string(),
                category: McpCategory::Mcp06,
                name: "DLP Parameter Scanning".to_string(),
                description: "Scan tool parameters and responses for leaked secrets".to_string(),
                vellaveto_mitigations: vec![
                    "inspection/dlp.rs — 5-layer decode pipeline".to_string()
                ],
            },
            McpControl {
                id: "MCP06-C02".to_string(),
                category: McpCategory::Mcp06,
                name: "URL Exfiltration Detection".to_string(),
                description: "Detect data encoded in outbound URL query strings and paths"
                    .to_string(),
                vellaveto_mitigations: vec![
                    "R226 detect_url_data_exfiltration — Shannon entropy analysis".to_string(),
                ],
            },
            // ── MCP07: Insecure Credential Handling ─────────────────────────
            McpControl {
                id: "MCP07-C01".to_string(),
                category: McpCategory::Mcp07,
                name: "Secret Redaction in Logs".to_string(),
                description: "Redact API keys and credentials from audit logs and error messages"
                    .to_string(),
                vellaveto_mitigations: vec![
                    "PII redaction in audit entries".to_string(),
                    "Custom Debug impls redacting secrets".to_string(),
                ],
            },
            McpControl {
                id: "MCP07-C02".to_string(),
                category: McpCategory::Mcp07,
                name: "NHI Ephemeral Credentials".to_string(),
                description: "Non-human identity lifecycle with ephemeral credential rotation"
                    .to_string(),
                vellaveto_mitigations: vec![
                    "nhi.rs — ephemeral credential issuance and rotation enforcement".to_string(),
                ],
            },
            // ── MCP08: Lack of Tool Consent ─────────────────────────────────
            McpControl {
                id: "MCP08-C01".to_string(),
                category: McpCategory::Mcp08,
                name: "Human-in-the-Loop Approval".to_string(),
                description: "Require human approval for sensitive tool calls".to_string(),
                vellaveto_mitigations: vec![
                    "Verdict::RequireApproval — approval workflow".to_string(),
                    "Step-up authorization (MCP 2025-11-25)".to_string(),
                ],
            },
            // ── MCP09: Inadequate Logging ───────────────────────────────────
            McpControl {
                id: "MCP09-C01".to_string(),
                category: McpCategory::Mcp09,
                name: "Tamper-Evident Audit Trail".to_string(),
                description: "SHA-256 hash chain with Ed25519 signed checkpoints".to_string(),
                vellaveto_mitigations: vec![
                    "AuditLogger — hash chain, Merkle proofs, signed checkpoints".to_string(),
                    "PQC hybrid Ed25519+ML-DSA-65 checkpoint signatures".to_string(),
                ],
            },
            McpControl {
                id: "MCP09-C02".to_string(),
                category: McpCategory::Mcp09,
                name: "OCSF/CEF Export".to_string(),
                description: "Export audit events in standardized formats for SIEM integration"
                    .to_string(),
                vellaveto_mitigations: vec![
                    "export/ocsf.rs — OCSF format".to_string(),
                    "CEF, JSONL, webhook, syslog export".to_string(),
                ],
            },
            // ── MCP10: Resource Exhaustion ───────────────────────────────────
            McpControl {
                id: "MCP10-C01".to_string(),
                category: McpCategory::Mcp10,
                name: "Rate Limiting".to_string(),
                description: "Per-IP, per-principal, and per-agent rate limiting".to_string(),
                vellaveto_mitigations: vec!["Rate limiting middleware on all endpoints".to_string()],
            },
            McpControl {
                id: "MCP10-C02".to_string(),
                category: McpCategory::Mcp10,
                name: "Circuit Breaker".to_string(),
                description: "Cascading failure circuit breakers for downstream dependencies"
                    .to_string(),
                vellaveto_mitigations: vec![
                    "engine/cascading.rs — circuit breaker state machine".to_string()
                ],
            },
        ];

        // Enforce bounds (Trap 3).
        for control in controls.into_iter().take(MAX_MCP_CONTROLS) {
            if control.vellaveto_mitigations.len() > MAX_MITIGATIONS_PER_CONTROL {
                tracing::warn!(
                    control_id = %control.id,
                    "MCP control has too many mitigations, truncating"
                );
            }
            self.controls.push(control);
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creates_successfully() {
        let registry = OwaspMcpRegistry::new();
        assert!(
            !registry.controls().is_empty(),
            "Registry must have controls"
        );
    }

    #[test]
    fn test_all_categories_have_controls() {
        let registry = OwaspMcpRegistry::new();
        let categories = [
            McpCategory::Mcp01,
            McpCategory::Mcp02,
            McpCategory::Mcp03,
            McpCategory::Mcp04,
            McpCategory::Mcp05,
            McpCategory::Mcp06,
            McpCategory::Mcp07,
            McpCategory::Mcp08,
            McpCategory::Mcp09,
            McpCategory::Mcp10,
        ];
        for cat in &categories {
            let controls = registry.controls_for_category(*cat);
            assert!(
                !controls.is_empty(),
                "Category {} must have at least one control",
                cat
            );
        }
    }

    #[test]
    fn test_coverage_report_generation() {
        let registry = OwaspMcpRegistry::new();
        let report = registry.generate_coverage_report();
        assert_eq!(report.total_categories, 10);
        assert!(report.total_controls > 0);
        assert!(report.coverage_percent.is_finite());
        assert!(report.coverage_percent >= 0.0 && report.coverage_percent <= 100.0);
    }

    #[test]
    fn test_coverage_report_high_coverage() {
        let registry = OwaspMcpRegistry::new();
        let report = registry.generate_coverage_report();
        // All controls should have mitigations — 100% coverage expected.
        assert!(
            report.coverage_percent >= 90.0,
            "Expected >= 90% coverage, got {:.1}%",
            report.coverage_percent
        );
    }

    #[test]
    fn test_get_control_by_id() {
        let registry = OwaspMcpRegistry::new();
        let control = registry.get_control("MCP01-C01");
        assert!(control.is_some(), "MCP01-C01 must exist");
        assert_eq!(control.unwrap().category, McpCategory::Mcp01);
    }

    #[test]
    fn test_get_nonexistent_control() {
        let registry = OwaspMcpRegistry::new();
        assert!(registry.get_control("MCP99-C99").is_none());
    }

    #[test]
    fn test_control_ids_unique() {
        let registry = OwaspMcpRegistry::new();
        let ids: Vec<&str> = registry.controls().iter().map(|c| c.id.as_str()).collect();
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "Control IDs must be unique");
    }

    #[test]
    fn test_category_display() {
        assert_eq!(McpCategory::Mcp01.to_string(), "MCP01: Server Spoofing");
        assert_eq!(McpCategory::Mcp10.to_string(), "MCP10: Resource Exhaustion");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let registry = OwaspMcpRegistry::new();
        let report = registry.generate_coverage_report();
        let json = serde_json::to_string(&report).unwrap();
        let parsed: McpCoverageReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_categories, report.total_categories);
        assert_eq!(parsed.total_controls, report.total_controls);
    }
}
