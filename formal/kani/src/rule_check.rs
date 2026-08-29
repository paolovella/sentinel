// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Rule checking fail-closed verification extracted from
//! `vellaveto-engine/src/rule_check.rs`.
//!
//! Decision predicates abstracted to pure boolean functions. Pattern matching
//! is abstracted to boolean parameters (`matches: bool`) since glob/regex
//! compilation is in third-party code (globset).
//!
//! # Verified Properties (K41-K45)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K41 | No target_paths + allowlist configured → Deny |
//! | K42 | Blocked pattern match → Deny even if also in allowed |
//! | K43 | IDNA normalization failure → Deny |
//! | K44 | IP rules configured + no resolved IPs → Deny |
//! | K45 | block_private + private IP → Deny |
//!
//! # Production Correspondence
//!
//! - `check_path_rules_decision` ↔ `vellaveto-engine/src/rule_check.rs` check_path_rules
//! - `check_network_rules_decision` ↔ `vellaveto-engine/src/rule_check.rs` check_network_rules
//! - `check_ip_rules_decision` ↔ `vellaveto-engine/src/rule_check.rs` check_ip_rules
//!
//! The path predicate's correspondence is checked behaviourally by
//! `vellaveto-engine/src/kani_rule_check_differential.rs`, which derives these
//! booleans from real compiled policies rather than enumerating the free
//! product (most combinations are not realisable). Before 2026-08-30 nothing
//! checked it — see PARITY-HAND-2 in formal/ASSUMPTION_REGISTRY.md.
//! The network and IP predicates are still unbound.

/// Path rule decision predicate.
///
/// Parameters abstract the production logic:
/// - `has_allowed_paths`: allowlist is configured (non-empty)
/// - `has_blocked_paths`: blocklist is configured (non-empty)
/// - `target_paths_empty`: action has no target paths
/// - `any_path_blocked`: at least one target path matches a block pattern
/// - `all_paths_allowed`: every target path matches an allow pattern
///
/// Returns true (Deny) or false (pass).
pub fn check_path_rules_decision(
    has_allowed_paths: bool,
    has_blocked_paths: bool,
    target_paths_empty: bool,
    any_path_blocked: bool,
    all_paths_allowed: bool,
) -> bool {
    // If allowlist is configured but action has no paths → Deny
    if has_allowed_paths && target_paths_empty {
        return true; // Deny
    }

    // Blocked before allowed: if any path matches a block pattern → Deny
    if has_blocked_paths && any_path_blocked {
        return true; // Deny
    }

    // If allowlist exists, all paths must be in it
    if has_allowed_paths && !target_paths_empty && !all_paths_allowed {
        return true; // Deny
    }

    false // Pass
}

/// Network rule decision predicate.
///
/// Parameters:
/// - `has_allowed_domains`: allowlist configured
/// - `has_blocked_domains`: blocklist configured
/// - `target_domains_empty`: action has no target domains
/// - `any_domain_blocked`: at least one domain matches a block pattern
/// - `all_domains_allowed`: every domain matches an allow pattern
/// - `idna_normalization_failed`: IDNA normalization returned an error
///
/// Returns true (Deny) or false (pass).
pub fn check_network_rules_decision(
    has_allowed_domains: bool,
    has_blocked_domains: bool,
    target_domains_empty: bool,
    any_domain_blocked: bool,
    all_domains_allowed: bool,
    idna_normalization_failed: bool,
) -> bool {
    // IDNA failure → Deny (fail-closed)
    if idna_normalization_failed {
        return true; // Deny
    }

    // Block takes priority over allow
    if has_blocked_domains && any_domain_blocked {
        return true; // Deny
    }

    // If allowlist exists but no domains → Deny
    if has_allowed_domains && target_domains_empty {
        return true; // Deny
    }

    // Allowlist check
    if has_allowed_domains && !target_domains_empty && !all_domains_allowed {
        return true; // Deny
    }

    false // Pass
}

/// IP rule decision predicate.
///
/// Parameters:
/// - `ip_rules_configured`: IpRules is present in the policy
/// - `resolved_ips_empty`: action has no resolved IPs
/// - `block_private`: block_private flag is set
/// - `any_ip_private`: at least one resolved IP is private/reserved
/// - `any_ip_in_blocked_cidr`: at least one IP matches a blocked CIDR
/// - `has_allowed_cidrs`: allowed_cidrs is non-empty
/// - `all_ips_in_allowed_cidrs`: every IP matches an allowed CIDR
///
/// Returns true (Deny) or false (pass).
pub fn check_ip_rules_decision(
    ip_rules_configured: bool,
    resolved_ips_empty: bool,
    block_private: bool,
    any_ip_private: bool,
    any_ip_in_blocked_cidr: bool,
    has_allowed_cidrs: bool,
    all_ips_in_allowed_cidrs: bool,
) -> bool {
    if !ip_rules_configured {
        return false; // No IP rules → pass
    }

    // No resolved IPs when IP rules exist → Deny (fail-closed)
    if resolved_ips_empty {
        return true; // Deny
    }

    // block_private + any private IP → Deny
    if block_private && any_ip_private {
        return true; // Deny
    }

    // Blocked CIDR match → Deny
    if any_ip_in_blocked_cidr {
        return true; // Deny
    }

    // Allowed CIDR check
    if has_allowed_cidrs && !all_ips_in_allowed_cidrs {
        return true; // Deny
    }

    false // Pass
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_allowlist_no_paths_deny() {
        assert!(check_path_rules_decision(true, false, true, false, false));
    }

    #[test]
    fn test_path_blocked_before_allowed() {
        // Even if all_paths_allowed = true, blocked still denies
        assert!(check_path_rules_decision(true, true, false, true, true));
    }

    #[test]
    fn test_path_no_rules_pass() {
        assert!(!check_path_rules_decision(false, false, true, false, false));
    }

    #[test]
    fn test_network_idna_fail_deny() {
        assert!(check_network_rules_decision(
            false, false, false, false, false, true
        ));
    }

    #[test]
    fn test_ip_no_resolved_deny() {
        assert!(check_ip_rules_decision(
            true, true, false, false, false, false, false
        ));
    }

    #[test]
    fn test_ip_private_blocked() {
        assert!(check_ip_rules_decision(
            true, false, true, true, false, false, false
        ));
    }

    #[test]
    fn test_ip_no_rules_pass() {
        assert!(!check_ip_rules_decision(
            false, false, false, false, false, false, false
        ));
    }
}
