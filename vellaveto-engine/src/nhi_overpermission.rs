// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Non-Human Identity (NHI) overpermission detection.
//!
//! Detects agents with overly broad OAuth scopes, tool permissions,
//! or capability delegations relative to their declared purpose.
//! Addresses the OAuth delegation chain vulnerability (Salesloft-Drift
//! breach pattern) and the 144:1 NHI-to-human ratio problem.

use vellaveto_types::TrustTier;

/// An overpermission finding.
#[derive(Debug, Clone)]
pub struct OverpermissionFinding {
    pub finding_type: OverpermissionType,
    pub agent_id: String,
    pub confidence: u32,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverpermissionType {
    /// Agent has more OAuth scopes than needed for its declared tools.
    ExcessiveOAuthScopes,
    /// Agent can access tools it never uses.
    UnusedToolAccess,
    /// Agent trust tier is higher than its behavioral history warrants.
    TrustTierInflation,
    /// Delegation chain grants broader access than the delegator has.
    DelegationEscalation,
    /// Agent has no declared purpose/scope (ambient authority).
    AmbientAuthority,
}

/// Detected OAuth scope.
#[derive(Debug, Clone)]
pub struct AgentScope {
    pub agent_id: String,
    pub declared_scopes: Vec<String>,
    pub tools_used: Vec<String>,
    pub trust_tier: TrustTier,
    pub delegation_depth: u32,
}

/// Check an agent's permissions for overpermission indicators.
pub fn check_overpermission(scope: &AgentScope) -> Vec<OverpermissionFinding> {
    let mut findings = Vec::new();

    // Check for ambient authority (no declared scopes)
    if scope.declared_scopes.is_empty() && !scope.tools_used.is_empty() {
        findings.push(OverpermissionFinding {
            finding_type: OverpermissionType::AmbientAuthority,
            agent_id: scope.agent_id.clone(),
            confidence: 70,
            description: format!(
                "Agent '{}' uses {} tools but has no declared scopes",
                &scope.agent_id[..scope.agent_id.len().min(32)],
                scope.tools_used.len()
            ),
        });
    }

    // Check for excessive scopes relative to tools used
    if !scope.declared_scopes.is_empty() && !scope.tools_used.is_empty() {
        let scope_count = scope.declared_scopes.len();
        let tool_count = scope.tools_used.len();
        // If scopes >> tools, the agent has more access than it needs
        if scope_count > tool_count * 3 && scope_count > 5 {
            findings.push(OverpermissionFinding {
                finding_type: OverpermissionType::ExcessiveOAuthScopes,
                agent_id: scope.agent_id.clone(),
                confidence: 60,
                description: format!(
                    "{scope_count} scopes for {tool_count} tools ({:.0}x ratio)",
                    scope_count as f64 / tool_count.max(1) as f64
                ),
            });
        }
    }

    // Check for trust tier inflation
    if scope.trust_tier.rank() >= TrustTier::High.rank() && scope.delegation_depth > 0 {
        // Delegated agents should have lower trust than direct agents
        findings.push(OverpermissionFinding {
            finding_type: OverpermissionType::TrustTierInflation,
            agent_id: scope.agent_id.clone(),
            confidence: 55,
            description: format!(
                "Delegated agent (depth {}) has {:?} trust — expected lower",
                scope.delegation_depth, scope.trust_tier
            ),
        });
    }

    // Check for wide scopes that suggest admin/root access
    let admin_scopes = ["admin", "root", "write:all", "read:all", "*", "full_access"];
    for scope_name in &scope.declared_scopes {
        let lower = scope_name.to_lowercase();
        if admin_scopes.iter().any(|a| lower.contains(a)) {
            findings.push(OverpermissionFinding {
                finding_type: OverpermissionType::ExcessiveOAuthScopes,
                agent_id: scope.agent_id.clone(),
                confidence: 80,
                description: format!("Admin-level scope detected: '{scope_name}'"),
            });
            break;
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ambient_authority_detected() {
        let scope = AgentScope {
            agent_id: "agent-1".to_string(),
            declared_scopes: Vec::new(),
            tools_used: vec!["read_file".to_string(), "write_file".to_string()],
            trust_tier: TrustTier::Medium,
            delegation_depth: 0,
        };
        let findings = check_overpermission(&scope);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == OverpermissionType::AmbientAuthority));
    }

    #[test]
    fn test_excessive_scopes_detected() {
        let scope = AgentScope {
            agent_id: "agent-2".to_string(),
            declared_scopes: (0..20).map(|i| format!("scope:{i}")).collect(),
            tools_used: vec!["read_file".to_string()],
            trust_tier: TrustTier::Medium,
            delegation_depth: 0,
        };
        let findings = check_overpermission(&scope);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == OverpermissionType::ExcessiveOAuthScopes));
    }

    #[test]
    fn test_admin_scope_flagged() {
        let scope = AgentScope {
            agent_id: "agent-3".to_string(),
            declared_scopes: vec!["admin:full_access".to_string()],
            tools_used: vec!["read_file".to_string()],
            trust_tier: TrustTier::Medium,
            delegation_depth: 0,
        };
        let findings = check_overpermission(&scope);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == OverpermissionType::ExcessiveOAuthScopes));
    }

    #[test]
    fn test_trust_inflation_for_delegated_agent() {
        let scope = AgentScope {
            agent_id: "sub-agent".to_string(),
            declared_scopes: vec!["read".to_string()],
            tools_used: vec!["read_file".to_string()],
            trust_tier: TrustTier::High,
            delegation_depth: 2,
        };
        let findings = check_overpermission(&scope);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == OverpermissionType::TrustTierInflation));
    }

    #[test]
    fn test_properly_scoped_agent_clean() {
        let scope = AgentScope {
            agent_id: "good-agent".to_string(),
            declared_scopes: vec!["read:files".to_string(), "write:tmp".to_string()],
            tools_used: vec!["read_file".to_string(), "write_file".to_string()],
            trust_tier: TrustTier::Medium,
            delegation_depth: 0,
        };
        let findings = check_overpermission(&scope);
        assert!(findings.is_empty());
    }
}
