// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Policy linting and best-practices engine.
//!
//! Provides static analysis of policy sets to detect misconfigurations,
//! overlapping rules, and security anti-patterns before policies are loaded
//! into the evaluation engine.
//!
//! # Lint Rules
//!
//! | ID   | Severity | Description |
//! |------|----------|-------------|
//! | L001 | Error    | Empty policy ID |
//! | L002 | Error    | Empty policy name |
//! | L003 | Warning  | Wildcard-only policy (overly broad) |
//! | L004 | Warning  | Allow without path or network rules (matches everything) |
//! | L005 | Warning  | Overlapping path rules between policies |
//! | L006 | Info     | Deny policy with unused path/network rules |
//! | L007 | Warning  | Blocked path is prefix of allowed path (dead rule) |
//! | L008 | Warning  | Empty allowed_domains with non-empty blocked_domains |
//! | L009 | Error    | Duplicate policy IDs |
//! | L010 | Warning  | Priority collision (non-deterministic ordering) |
//! | L011 | Info     | Large policy set (>500 may impact latency) |
//! | L012 | Warning  | Conditional with no conditions |

use std::collections::{HashMap, HashSet};
use vellaveto_types::{Policy, PolicyType};

/// Maximum number of policies before emitting L011.
const LARGE_POLICY_SET_THRESHOLD: usize = 500;

/// Severity level for lint findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LintSeverity {
    Info,
    Warning,
    Error,
}

/// A single lint finding.
#[derive(Debug, Clone)]
pub struct LintFinding {
    pub rule_id: String,
    pub severity: LintSeverity,
    pub policy_id: String,
    pub message: String,
    pub suggestion: Option<String>,
}

/// Result of linting a policy set.
#[derive(Debug, Clone)]
pub struct LintReport {
    pub findings: Vec<LintFinding>,
    pub policies_checked: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
}

impl LintReport {
    /// Returns true if no Error-level findings were emitted.
    pub fn is_ok(&self) -> bool {
        self.error_count == 0
    }
}

/// Policy linting engine.
///
/// Performs static analysis of policy sets to detect misconfigurations,
/// shadowed rules, and security anti-patterns.
pub struct PolicyLinter {
    // No state needed — pure analysis.
}

impl PolicyLinter {
    /// Create a new policy linter.
    pub fn new() -> Self {
        Self {}
    }

    /// Lint a set of policies and return a report.
    pub fn lint(&self, policies: &[Policy]) -> LintReport {
        let mut findings = Vec::new();

        // Per-policy rules
        for policy in policies {
            findings.extend(self.lint_single(policy));
        }

        // Cross-policy rules
        self.check_duplicate_ids(policies, &mut findings);
        self.check_priority_collisions(policies, &mut findings);
        self.check_overlapping_paths(policies, &mut findings);
        self.check_large_policy_set(policies, &mut findings);

        let error_count = findings
            .iter()
            .filter(|f| f.severity == LintSeverity::Error)
            .count();
        let warning_count = findings
            .iter()
            .filter(|f| f.severity == LintSeverity::Warning)
            .count();
        let info_count = findings
            .iter()
            .filter(|f| f.severity == LintSeverity::Info)
            .count();

        LintReport {
            findings,
            policies_checked: policies.len(),
            error_count,
            warning_count,
            info_count,
        }
    }

    /// Lint a single policy (subset of rules that apply to one policy).
    pub fn lint_single(&self, policy: &Policy) -> Vec<LintFinding> {
        let mut findings = Vec::new();

        self.check_empty_id(policy, &mut findings);
        self.check_empty_name(policy, &mut findings);
        self.check_wildcard_only(policy, &mut findings);
        self.check_allow_without_rules(policy, &mut findings);
        self.check_deny_unused_rules(policy, &mut findings);
        self.check_blocked_prefix_of_allowed(policy, &mut findings);
        self.check_empty_allowed_with_blocked_domains(policy, &mut findings);
        self.check_conditional_no_conditions(policy, &mut findings);

        findings
    }

    // ───────────────────────────────────────────────
    // Single-policy rules
    // ───────────────────────────────────────────────

    /// L001: Policy ID must not be empty.
    fn check_empty_id(&self, policy: &Policy, findings: &mut Vec<LintFinding>) {
        if policy.id.trim().is_empty() {
            findings.push(LintFinding {
                rule_id: "L001".to_string(),
                severity: LintSeverity::Error,
                policy_id: policy.id.clone(),
                message: "Policy ID is empty".to_string(),
                suggestion: Some(
                    "Set a unique policy ID in the format 'tool:function' or 'tool:*'".to_string(),
                ),
            });
        }
    }

    /// L002: Policy name must not be empty.
    fn check_empty_name(&self, policy: &Policy, findings: &mut Vec<LintFinding>) {
        if policy.name.trim().is_empty() {
            findings.push(LintFinding {
                rule_id: "L002".to_string(),
                severity: LintSeverity::Error,
                policy_id: policy.id.clone(),
                message: "Policy name is empty".to_string(),
                suggestion: Some(
                    "Set a descriptive name for the policy (e.g. 'Allow file reads')".to_string(),
                ),
            });
        }
    }

    /// L003: Wildcard-only policy ID is overly broad.
    fn check_wildcard_only(&self, policy: &Policy, findings: &mut Vec<LintFinding>) {
        let trimmed = policy.id.trim();
        if trimmed == "*" || trimmed == "*:*" {
            findings.push(LintFinding {
                rule_id: "L003".to_string(),
                severity: LintSeverity::Warning,
                policy_id: policy.id.clone(),
                message: format!(
                    "Policy '{}' uses a wildcard-only ID that matches all tools",
                    policy.id
                ),
                suggestion: Some(
                    "Use a more specific tool pattern (e.g. 'file_system:*') to limit scope"
                        .to_string(),
                ),
            });
        }
    }

    /// L004: Allow policy with no path_rules and no network_rules matches everything.
    fn check_allow_without_rules(&self, policy: &Policy, findings: &mut Vec<LintFinding>) {
        if !matches!(policy.policy_type, PolicyType::Allow) {
            return;
        }
        if policy.path_rules.is_none() && policy.network_rules.is_none() {
            findings.push(LintFinding {
                rule_id: "L004".to_string(),
                severity: LintSeverity::Warning,
                policy_id: policy.id.clone(),
                message: format!(
                    "Allow policy '{}' has no path_rules or network_rules — matches all paths and domains",
                    policy.id
                ),
                suggestion: Some(
                    "Add path_rules or network_rules to restrict what this policy allows".to_string(),
                ),
            });
        }
    }

    /// L006: Deny policy with path_rules or network_rules (those rules are unused).
    fn check_deny_unused_rules(&self, policy: &Policy, findings: &mut Vec<LintFinding>) {
        if !matches!(policy.policy_type, PolicyType::Deny) {
            return;
        }
        let has_path_rules = policy
            .path_rules
            .as_ref()
            .is_some_and(|pr| !pr.allowed.is_empty() || !pr.blocked.is_empty());
        let has_network_rules = policy
            .network_rules
            .as_ref()
            .is_some_and(|nr| !nr.allowed_domains.is_empty() || !nr.blocked_domains.is_empty());
        if has_path_rules || has_network_rules {
            findings.push(LintFinding {
                rule_id: "L006".to_string(),
                severity: LintSeverity::Info,
                policy_id: policy.id.clone(),
                message: format!(
                    "Deny policy '{}' has path_rules or network_rules that will not be evaluated (Deny blocks unconditionally)",
                    policy.id
                ),
                suggestion: Some(
                    "Remove path_rules/network_rules from Deny policies, or change policy_type to Conditional".to_string(),
                ),
            });
        }
    }

    /// L007: In PathRules, a blocked pattern is a prefix of an allowed pattern (allowed is dead).
    fn check_blocked_prefix_of_allowed(&self, policy: &Policy, findings: &mut Vec<LintFinding>) {
        let path_rules = match &policy.path_rules {
            Some(pr) => pr,
            None => return,
        };
        for blocked in &path_rules.blocked {
            for allowed in &path_rules.allowed {
                if is_prefix_pattern(blocked, allowed) {
                    findings.push(LintFinding {
                        rule_id: "L007".to_string(),
                        severity: LintSeverity::Warning,
                        policy_id: policy.id.clone(),
                        message: format!(
                            "Blocked pattern '{}' is a prefix of allowed pattern '{}' — the allowed pattern is unreachable",
                            blocked, allowed
                        ),
                        suggestion: Some(
                            "Remove the unreachable allowed pattern or restructure the rules".to_string(),
                        ),
                    });
                }
            }
        }
    }

    /// L008: Empty allowed_domains with non-empty blocked_domains.
    fn check_empty_allowed_with_blocked_domains(
        &self,
        policy: &Policy,
        findings: &mut Vec<LintFinding>,
    ) {
        let network_rules = match &policy.network_rules {
            Some(nr) => nr,
            None => return,
        };
        if network_rules.allowed_domains.is_empty() && !network_rules.blocked_domains.is_empty() {
            findings.push(LintFinding {
                rule_id: "L008".to_string(),
                severity: LintSeverity::Warning,
                policy_id: policy.id.clone(),
                message: format!(
                    "Policy '{}' has blocked_domains but no allowed_domains — blocked_domains has no effect when the allowlist is empty",
                    policy.id
                ),
                suggestion: Some(
                    "Add allowed_domains to define which domains are permitted, or remove blocked_domains".to_string(),
                ),
            });
        }
    }

    /// L012: Conditional policy type with empty or missing conditions.
    fn check_conditional_no_conditions(&self, policy: &Policy, findings: &mut Vec<LintFinding>) {
        let conditions = match &policy.policy_type {
            PolicyType::Conditional { conditions } => conditions,
            _ => return,
        };
        let is_empty = conditions.is_null()
            || (conditions.is_object() && conditions.as_object().is_none_or(|m| m.is_empty()))
            || (conditions.is_array() && conditions.as_array().is_none_or(|a| a.is_empty()));
        if is_empty {
            findings.push(LintFinding {
                rule_id: "L012".to_string(),
                severity: LintSeverity::Warning,
                policy_id: policy.id.clone(),
                message: format!(
                    "Conditional policy '{}' has empty or null conditions — it will not match any context",
                    policy.id
                ),
                suggestion: Some(
                    "Add conditions (e.g. parameter_constraints, time_window) or change policy_type to Allow/Deny".to_string(),
                ),
            });
        }
    }

    // ───────────────────────────────────────────────
    // Cross-policy rules
    // ───────────────────────────────────────────────

    /// L009: Duplicate policy IDs.
    fn check_duplicate_ids(&self, policies: &[Policy], findings: &mut Vec<LintFinding>) {
        let mut seen: HashMap<&str, usize> = HashMap::new();
        for (i, policy) in policies.iter().enumerate() {
            if let Some(&first_idx) = seen.get(policy.id.as_str()) {
                findings.push(LintFinding {
                    rule_id: "L009".to_string(),
                    severity: LintSeverity::Error,
                    policy_id: policy.id.clone(),
                    message: format!(
                        "Duplicate policy ID '{}' (first seen at index {}, duplicate at index {})",
                        policy.id, first_idx, i
                    ),
                    suggestion: Some("Each policy must have a unique ID".to_string()),
                });
            } else {
                seen.insert(&policy.id, i);
            }
        }
    }

    /// L010: Priority collision — two or more policies with the same priority.
    fn check_priority_collisions(&self, policies: &[Policy], findings: &mut Vec<LintFinding>) {
        let mut priority_groups: HashMap<i32, Vec<&str>> = HashMap::new();
        for policy in policies {
            priority_groups
                .entry(policy.priority)
                .or_default()
                .push(&policy.id);
        }
        for (priority, ids) in &priority_groups {
            if ids.len() > 1 {
                // Report once per collision group, referencing the first policy ID.
                findings.push(LintFinding {
                    rule_id: "L010".to_string(),
                    severity: LintSeverity::Warning,
                    policy_id: ids[0].to_string(),
                    message: format!(
                        "Priority {} is shared by {} policies: {} — evaluation order may be non-deterministic",
                        priority,
                        ids.len(),
                        ids.join(", "),
                    ),
                    suggestion: Some(
                        "Assign unique priorities to each policy for deterministic evaluation".to_string(),
                    ),
                });
            }
        }
    }

    /// L005: Overlapping path rules between policies on the same tool pattern.
    ///
    /// Detects cases where two Allow policies on the same (or overlapping) tool
    /// pattern have path_rules whose allowed patterns overlap, which may cause
    /// one policy to shadow the other.
    fn check_overlapping_paths(&self, policies: &[Policy], findings: &mut Vec<LintFinding>) {
        // Group policies by their tool pattern (the part before ':')
        let mut tool_groups: HashMap<&str, Vec<&Policy>> = HashMap::new();
        for policy in policies {
            let tool_part = policy.id.split(':').next().unwrap_or(&policy.id);
            tool_groups.entry(tool_part).or_default().push(policy);
        }

        for group in tool_groups.values() {
            if group.len() < 2 {
                continue;
            }
            // Check all pairs
            let mut reported: HashSet<(usize, usize)> = HashSet::new();
            for (i, p1) in group.iter().enumerate() {
                let pr1 = match &p1.path_rules {
                    Some(pr) if !pr.allowed.is_empty() => pr,
                    _ => continue,
                };
                for (j, p2) in group.iter().enumerate().skip(i + 1) {
                    if reported.contains(&(i, j)) {
                        continue;
                    }
                    let pr2 = match &p2.path_rules {
                        Some(pr) if !pr.allowed.is_empty() => pr,
                        _ => continue,
                    };
                    // Check if any allowed pattern from p1 overlaps with p2
                    for a1 in &pr1.allowed {
                        for a2 in &pr2.allowed {
                            if patterns_overlap(a1, a2) {
                                reported.insert((i, j));
                                findings.push(LintFinding {
                                    rule_id: "L005".to_string(),
                                    severity: LintSeverity::Warning,
                                    policy_id: p1.id.clone(),
                                    message: format!(
                                        "Policy '{}' path '{}' overlaps with policy '{}' path '{}' — higher-priority policy shadows the other",
                                        p1.id, a1, p2.id, a2
                                    ),
                                    suggestion: Some(
                                        "Ensure overlapping policies have distinct priorities or non-overlapping paths".to_string(),
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// L011: Large policy set (>500 policies).
    fn check_large_policy_set(&self, policies: &[Policy], findings: &mut Vec<LintFinding>) {
        if policies.len() > LARGE_POLICY_SET_THRESHOLD {
            findings.push(LintFinding {
                rule_id: "L011".to_string(),
                severity: LintSeverity::Info,
                policy_id: String::new(),
                message: format!(
                    "Policy set contains {} policies (threshold: {}) — evaluation latency may be impacted",
                    policies.len(),
                    LARGE_POLICY_SET_THRESHOLD,
                ),
                suggestion: Some(
                    "Consider consolidating policies or using more specific tool patterns for faster matching".to_string(),
                ),
            });
        }
    }
}

impl Default for PolicyLinter {
    fn default() -> Self {
        Self::new()
    }
}

// ───────────────────────────────────────────────────
// Helper functions
// ───────────────────────────────────────────────────

/// Check if `prefix` is a glob/path prefix of `candidate`.
///
/// A pattern is considered a prefix if:
/// - `candidate` starts with `prefix` (exact prefix match), or
/// - `prefix` ends with `/**` and the base of `prefix` is a prefix of `candidate`, or
/// - `prefix` ends with `/*` and the base of `prefix` is a directory prefix of `candidate`
fn is_prefix_pattern(prefix: &str, candidate: &str) -> bool {
    // Exact prefix (e.g. "/home" blocks "/home/user")
    if candidate.starts_with(prefix) && candidate.len() > prefix.len() {
        return true;
    }

    // /foo/** blocks /foo/bar/baz
    if let Some(base) = prefix.strip_suffix("/**") {
        if candidate.starts_with(base) {
            return true;
        }
    }

    // /foo/* blocks /foo/bar
    if let Some(base) = prefix.strip_suffix("/*") {
        if candidate.starts_with(base) {
            return true;
        }
    }

    false
}

/// Check if two glob patterns potentially overlap in the paths they match.
///
/// This is a conservative approximation — it may report false positives
/// but should not miss true overlaps. Two patterns overlap if:
/// - They are identical
/// - One is a prefix of the other
/// - Both match the same directory tree (e.g. `/home/*` and `/home/user/*`)
fn patterns_overlap(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    // One is a prefix of the other
    if is_prefix_pattern(a, b) || is_prefix_pattern(b, a) {
        return true;
    }
    // Both patterns start with the same concrete prefix up to the first wildcard
    let a_concrete = concrete_prefix(a);
    let b_concrete = concrete_prefix(b);
    if !a_concrete.is_empty() && !b_concrete.is_empty() {
        // If one concrete prefix starts with the other, they may overlap
        if a_concrete.starts_with(b_concrete) || b_concrete.starts_with(a_concrete) {
            return true;
        }
    }
    false
}

/// Extract the concrete (non-wildcard) prefix of a glob pattern.
///
/// Returns the portion of the pattern before the first `*`, `?`, or `[`.
fn concrete_prefix(pattern: &str) -> &str {
    let end = pattern.find(['*', '?', '[']).unwrap_or(pattern.len());
    &pattern[..end]
}

// ═══════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vellaveto_types::{NetworkRules, PathRules};

    /// Helper to create an Allow policy with optional path/network rules.
    fn make_allow_policy(
        id: &str,
        name: &str,
        priority: i32,
        path_rules: Option<PathRules>,
        network_rules: Option<NetworkRules>,
    ) -> Policy {
        Policy {
            id: id.to_string(),
            name: name.to_string(),
            policy_type: PolicyType::Allow,
            priority,
            path_rules,
            network_rules,
        }
    }

    /// Helper to create a Deny policy.
    fn make_deny_policy(id: &str, name: &str, priority: i32) -> Policy {
        Policy {
            id: id.to_string(),
            name: name.to_string(),
            policy_type: PolicyType::Deny,
            priority,
            path_rules: None,
            network_rules: None,
        }
    }

    /// Helper to create a Conditional policy.
    fn make_conditional_policy(
        id: &str,
        name: &str,
        priority: i32,
        conditions: serde_json::Value,
    ) -> Policy {
        Policy {
            id: id.to_string(),
            name: name.to_string(),
            policy_type: PolicyType::Conditional { conditions },
            priority,
            path_rules: None,
            network_rules: None,
        }
    }

    // ───────────────────────────────────────────────
    // L001: Empty policy ID
    // ───────────────────────────────────────────────

    #[test]
    fn test_lint_l001_empty_id() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy("", "Test", 10, None, None);
        let findings = linter.lint_single(&policy);
        assert!(findings.iter().any(|f| f.rule_id == "L001"));
    }

    #[test]
    fn test_lint_l001_whitespace_only_id() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy("   ", "Test", 10, None, None);
        let findings = linter.lint_single(&policy);
        assert!(findings.iter().any(|f| f.rule_id == "L001"));
    }

    #[test]
    fn test_lint_l001_valid_id_no_finding() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy("file:read", "Test", 10, None, None);
        let findings = linter.lint_single(&policy);
        assert!(!findings.iter().any(|f| f.rule_id == "L001"));
    }

    // ───────────────────────────────────────────────
    // L002: Empty policy name
    // ───────────────────────────────────────────────

    #[test]
    fn test_lint_l002_empty_name() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy("test:read", "", 10, None, None);
        let findings = linter.lint_single(&policy);
        assert!(findings.iter().any(|f| f.rule_id == "L002"));
    }

    #[test]
    fn test_lint_l002_whitespace_only_name() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy("test:read", "  \t ", 10, None, None);
        let findings = linter.lint_single(&policy);
        assert!(findings.iter().any(|f| f.rule_id == "L002"));
    }

    // ───────────────────────────────────────────────
    // L003: Wildcard-only policy
    // ───────────────────────────────────────────────

    #[test]
    fn test_lint_l003_star_only() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy("*", "All tools", 10, None, None);
        let findings = linter.lint_single(&policy);
        assert!(findings.iter().any(|f| f.rule_id == "L003"));
    }

    #[test]
    fn test_lint_l003_star_colon_star() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy("*:*", "All tools", 10, None, None);
        let findings = linter.lint_single(&policy);
        assert!(findings.iter().any(|f| f.rule_id == "L003"));
    }

    #[test]
    fn test_lint_l003_partial_wildcard_no_finding() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy("file:*", "File tools", 10, None, None);
        let findings = linter.lint_single(&policy);
        assert!(!findings.iter().any(|f| f.rule_id == "L003"));
    }

    // ───────────────────────────────────────────────
    // L004: Allow without path or network rules
    // ───────────────────────────────────────────────

    #[test]
    fn test_lint_l004_allow_no_rules() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy("file:read", "Allow reads", 10, None, None);
        let findings = linter.lint_single(&policy);
        assert!(findings.iter().any(|f| f.rule_id == "L004"));
    }

    #[test]
    fn test_lint_l004_allow_with_path_rules_no_finding() {
        let linter = PolicyLinter::new();
        let pr = PathRules {
            allowed: vec!["/home/**".to_string()],
            blocked: vec![],
        };
        let policy = make_allow_policy("file:read", "Allow reads", 10, Some(pr), None);
        let findings = linter.lint_single(&policy);
        assert!(!findings.iter().any(|f| f.rule_id == "L004"));
    }

    #[test]
    fn test_lint_l004_deny_no_rules_no_finding() {
        let linter = PolicyLinter::new();
        let policy = make_deny_policy("bash:*", "Block bash", 100);
        let findings = linter.lint_single(&policy);
        assert!(!findings.iter().any(|f| f.rule_id == "L004"));
    }

    // ───────────────────────────────────────────────
    // L005: Overlapping path rules
    // ───────────────────────────────────────────────

    #[test]
    fn test_lint_l005_overlapping_paths() {
        let linter = PolicyLinter::new();
        let p1 = make_allow_policy(
            "file:read",
            "P1",
            10,
            Some(PathRules {
                allowed: vec!["/home/**".to_string()],
                blocked: vec![],
            }),
            None,
        );
        let p2 = make_allow_policy(
            "file:write",
            "P2",
            20,
            Some(PathRules {
                allowed: vec!["/home/user/**".to_string()],
                blocked: vec![],
            }),
            None,
        );
        let report = linter.lint(&[p1, p2]);
        assert!(report.findings.iter().any(|f| f.rule_id == "L005"));
    }

    #[test]
    fn test_lint_l005_non_overlapping_paths_no_finding() {
        let linter = PolicyLinter::new();
        let p1 = make_allow_policy(
            "file:read",
            "P1",
            10,
            Some(PathRules {
                allowed: vec!["/home/**".to_string()],
                blocked: vec![],
            }),
            None,
        );
        let p2 = make_allow_policy(
            "network:fetch",
            "P2",
            20,
            Some(PathRules {
                allowed: vec!["/var/log/**".to_string()],
                blocked: vec![],
            }),
            None,
        );
        let report = linter.lint(&[p1, p2]);
        assert!(!report.findings.iter().any(|f| f.rule_id == "L005"));
    }

    // ───────────────────────────────────────────────
    // L006: Deny with unused rules
    // ───────────────────────────────────────────────

    #[test]
    fn test_lint_l006_deny_with_path_rules() {
        let linter = PolicyLinter::new();
        let policy = Policy {
            id: "bash:*".to_string(),
            name: "Block bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: Some(PathRules {
                allowed: vec!["/tmp/**".to_string()],
                blocked: vec![],
            }),
            network_rules: None,
        };
        let findings = linter.lint_single(&policy);
        assert!(findings.iter().any(|f| f.rule_id == "L006"));
    }

    #[test]
    fn test_lint_l006_deny_without_rules_no_finding() {
        let linter = PolicyLinter::new();
        let policy = make_deny_policy("bash:*", "Block bash", 100);
        let findings = linter.lint_single(&policy);
        assert!(!findings.iter().any(|f| f.rule_id == "L006"));
    }

    #[test]
    fn test_lint_l006_deny_with_empty_rules_no_finding() {
        let linter = PolicyLinter::new();
        let policy = Policy {
            id: "bash:*".to_string(),
            name: "Block bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: Some(PathRules {
                allowed: vec![],
                blocked: vec![],
            }),
            network_rules: None,
        };
        let findings = linter.lint_single(&policy);
        assert!(!findings.iter().any(|f| f.rule_id == "L006"));
    }

    // ───────────────────────────────────────────────
    // L007: Blocked path prefix of allowed path
    // ───────────────────────────────────────────────

    #[test]
    fn test_lint_l007_blocked_prefix_of_allowed() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy(
            "file:read",
            "Read files",
            10,
            Some(PathRules {
                allowed: vec!["/etc/config/**".to_string()],
                blocked: vec!["/etc/**".to_string()],
            }),
            None,
        );
        let findings = linter.lint_single(&policy);
        assert!(findings.iter().any(|f| f.rule_id == "L007"));
    }

    #[test]
    fn test_lint_l007_no_prefix_no_finding() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy(
            "file:read",
            "Read files",
            10,
            Some(PathRules {
                allowed: vec!["/home/**".to_string()],
                blocked: vec!["/etc/**".to_string()],
            }),
            None,
        );
        let findings = linter.lint_single(&policy);
        assert!(!findings.iter().any(|f| f.rule_id == "L007"));
    }

    // ───────────────────────────────────────────────
    // L008: Empty allowed_domains with blocked_domains
    // ───────────────────────────────────────────────

    #[test]
    fn test_lint_l008_empty_allowed_with_blocked() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy(
            "http:fetch",
            "Fetch",
            10,
            None,
            Some(NetworkRules {
                allowed_domains: vec![],
                blocked_domains: vec!["evil.com".to_string()],
                ip_rules: None,
            }),
        );
        let findings = linter.lint_single(&policy);
        assert!(findings.iter().any(|f| f.rule_id == "L008"));
    }

    #[test]
    fn test_lint_l008_both_populated_no_finding() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy(
            "http:fetch",
            "Fetch",
            10,
            None,
            Some(NetworkRules {
                allowed_domains: vec!["example.com".to_string()],
                blocked_domains: vec!["evil.com".to_string()],
                ip_rules: None,
            }),
        );
        let findings = linter.lint_single(&policy);
        assert!(!findings.iter().any(|f| f.rule_id == "L008"));
    }

    // ───────────────────────────────────────────────
    // L009: Duplicate policy IDs
    // ───────────────────────────────────────────────

    #[test]
    fn test_lint_l009_duplicate_ids() {
        let linter = PolicyLinter::new();
        let p1 = make_allow_policy("file:read", "P1", 10, None, None);
        let p2 = make_deny_policy("file:read", "P2", 20);
        let report = linter.lint(&[p1, p2]);
        assert!(report.findings.iter().any(|f| f.rule_id == "L009"));
        assert!(report.error_count >= 1);
    }

    #[test]
    fn test_lint_l009_unique_ids_no_finding() {
        let linter = PolicyLinter::new();
        let p1 = make_allow_policy("file:read", "P1", 10, None, None);
        let p2 = make_deny_policy("file:write", "P2", 20);
        let report = linter.lint(&[p1, p2]);
        assert!(!report.findings.iter().any(|f| f.rule_id == "L009"));
    }

    // ───────────────────────────────────────────────
    // L010: Priority collision
    // ───────────────────────────────────────────────

    #[test]
    fn test_lint_l010_priority_collision() {
        let linter = PolicyLinter::new();
        let p1 = make_allow_policy("file:read", "P1", 50, None, None);
        let p2 = make_deny_policy("bash:exec", "P2", 50);
        let report = linter.lint(&[p1, p2]);
        assert!(report.findings.iter().any(|f| f.rule_id == "L010"));
    }

    #[test]
    fn test_lint_l010_unique_priorities_no_finding() {
        let linter = PolicyLinter::new();
        let p1 = make_allow_policy("file:read", "P1", 10, None, None);
        let p2 = make_deny_policy("bash:exec", "P2", 20);
        let report = linter.lint(&[p1, p2]);
        assert!(!report.findings.iter().any(|f| f.rule_id == "L010"));
    }

    // ───────────────────────────────────────────────
    // L011: Large policy set
    // ───────────────────────────────────────────────

    #[test]
    fn test_lint_l011_large_policy_set() {
        let linter = PolicyLinter::new();
        let policies: Vec<Policy> = (0..501)
            .map(|i| make_deny_policy(&format!("tool{}:fn", i), &format!("Policy {}", i), i))
            .collect();
        let report = linter.lint(&policies);
        assert!(report.findings.iter().any(|f| f.rule_id == "L011"));
    }

    #[test]
    fn test_lint_l011_small_policy_set_no_finding() {
        let linter = PolicyLinter::new();
        let policies: Vec<Policy> = (0..10)
            .map(|i| make_deny_policy(&format!("tool{}:fn", i), &format!("Policy {}", i), i))
            .collect();
        let report = linter.lint(&policies);
        assert!(!report.findings.iter().any(|f| f.rule_id == "L011"));
    }

    // ───────────────────────────────────────────────
    // L012: Conditional with no conditions
    // ───────────────────────────────────────────────

    #[test]
    fn test_lint_l012_conditional_null_conditions() {
        let linter = PolicyLinter::new();
        let policy = make_conditional_policy("test:fn", "Test", 10, json!(null));
        let findings = linter.lint_single(&policy);
        assert!(findings.iter().any(|f| f.rule_id == "L012"));
    }

    #[test]
    fn test_lint_l012_conditional_empty_object() {
        let linter = PolicyLinter::new();
        let policy = make_conditional_policy("test:fn", "Test", 10, json!({}));
        let findings = linter.lint_single(&policy);
        assert!(findings.iter().any(|f| f.rule_id == "L012"));
    }

    #[test]
    fn test_lint_l012_conditional_empty_array() {
        let linter = PolicyLinter::new();
        let policy = make_conditional_policy("test:fn", "Test", 10, json!([]));
        let findings = linter.lint_single(&policy);
        assert!(findings.iter().any(|f| f.rule_id == "L012"));
    }

    #[test]
    fn test_lint_l012_conditional_with_conditions_no_finding() {
        let linter = PolicyLinter::new();
        let policy = make_conditional_policy(
            "test:fn",
            "Test",
            10,
            json!({ "parameter_constraints": [{ "param": "mode", "op": "eq", "value": "safe" }] }),
        );
        let findings = linter.lint_single(&policy);
        assert!(!findings.iter().any(|f| f.rule_id == "L012"));
    }

    // ───────────────────────────────────────────────
    // Report summary counts
    // ───────────────────────────────────────────────

    #[test]
    fn test_lint_report_counts() {
        let linter = PolicyLinter::new();
        // L001 (Error) + L003 (Warning) + L004 (Warning) from one policy
        let policy = make_allow_policy("*", "", 10, None, None);
        let report = linter.lint(&[policy]);
        // L001 (empty name -> Error), L002 actually since name is empty
        // L003 (wildcard -> Warning), L004 (allow no rules -> Warning)
        assert!(report.error_count >= 1); // L002
        assert!(report.warning_count >= 1); // L003, L004
        assert_eq!(report.policies_checked, 1, "should check exactly 1 policy");
    }

    #[test]
    fn test_lint_report_is_ok_with_errors() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy("", "Test", 10, None, None);
        let report = linter.lint(&[policy]);
        assert!(!report.is_ok(), "report with errors should not be ok");
    }

    #[test]
    fn test_lint_report_is_ok_without_errors() {
        let linter = PolicyLinter::new();
        let policy = make_deny_policy("bash:exec", "Block bash", 100);
        let report = linter.lint(&[policy]);
        assert!(report.is_ok(), "report without errors should be ok");
    }

    #[test]
    fn test_lint_empty_policy_set() {
        let linter = PolicyLinter::new();
        let report = linter.lint(&[]);
        assert_eq!(report.policies_checked, 0);
        assert_eq!(report.error_count, 0);
        assert_eq!(report.warning_count, 0);
        assert_eq!(report.info_count, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_lint_default_constructor() {
        let linter = PolicyLinter::default();
        let report = linter.lint(&[]);
        assert!(report.is_ok());
    }

    // ───────────────────────────────────────────────
    // Helper function tests
    // ───────────────────────────────────────────────

    #[test]
    fn test_is_prefix_pattern_exact() {
        assert!(is_prefix_pattern("/home", "/home/user"));
        assert!(!is_prefix_pattern("/home/user", "/home"));
    }

    #[test]
    fn test_is_prefix_pattern_glob_double_star() {
        assert!(is_prefix_pattern("/etc/**", "/etc/config/file.toml"));
    }

    #[test]
    fn test_is_prefix_pattern_glob_single_star() {
        assert!(is_prefix_pattern("/var/*", "/var/log/syslog"));
    }

    #[test]
    fn test_patterns_overlap_identical() {
        assert!(patterns_overlap("/home/**", "/home/**"));
    }

    #[test]
    fn test_patterns_overlap_prefix() {
        assert!(patterns_overlap("/home/**", "/home/user/**"));
    }

    #[test]
    fn test_patterns_overlap_disjoint() {
        assert!(!patterns_overlap("/home/**", "/var/**"));
    }

    #[test]
    fn test_concrete_prefix_extraction() {
        assert_eq!(concrete_prefix("/home/user/*"), "/home/user/");
        assert_eq!(concrete_prefix("**"), "");
        assert_eq!(concrete_prefix("/exact/path"), "/exact/path");
    }

    // ───────────────────────────────────────────────
    // Edge cases
    // ───────────────────────────────────────────────

    #[test]
    fn test_lint_l009_triple_duplicate() {
        let linter = PolicyLinter::new();
        let p1 = make_deny_policy("dup:id", "P1", 10);
        let p2 = make_deny_policy("dup:id", "P2", 20);
        let p3 = make_deny_policy("dup:id", "P3", 30);
        let report = linter.lint(&[p1, p2, p3]);
        let dup_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == "L009")
            .collect();
        assert_eq!(
            dup_findings.len(),
            2,
            "should report 2 duplicates for 3 identical IDs"
        );
    }

    #[test]
    fn test_lint_l010_three_way_collision() {
        let linter = PolicyLinter::new();
        let p1 = make_deny_policy("a:fn", "A", 50);
        let p2 = make_deny_policy("b:fn", "B", 50);
        let p3 = make_deny_policy("c:fn", "C", 50);
        let report = linter.lint(&[p1, p2, p3]);
        let collision_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == "L010")
            .collect();
        assert_eq!(
            collision_findings.len(),
            1,
            "should report one collision group"
        );
        assert!(
            collision_findings[0].message.contains("3 policies"),
            "message should mention 3 policies"
        );
    }

    #[test]
    fn test_lint_finding_has_suggestion() {
        let linter = PolicyLinter::new();
        let policy = make_allow_policy("", "Empty ID", 10, None, None);
        let findings = linter.lint_single(&policy);
        let l001 = findings.iter().find(|f| f.rule_id == "L001");
        assert!(l001.is_some());
        assert!(l001.is_some_and(|f| f.suggestion.is_some()));
    }
}
