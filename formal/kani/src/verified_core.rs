// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified core verdict computation — extraction from
//! `vellaveto-engine/src/verified_core.rs`.
//!
//! The algorithm is intended to be identical, but nothing checks that against
//! production. The unit tests in this crate assert hardcoded vectors against
//! this crate's own copy, and there is no CI diff check. Treat any proof here
//! as constraining this copy only, under PARITY-HAND-2 in
//! formal/ASSUMPTION_REGISTRY.md. `path.rs` and `ip.rs` show the shape a real
//! binding takes.

/// The result of the core verdict computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictKind {
    Allow,
    Deny,
    RequireApproval,
}

impl VerdictKind {
    #[inline]
    pub fn is_deny(self) -> bool {
        matches!(self, VerdictKind::Deny)
    }

    #[inline]
    pub fn is_allow(self) -> bool {
        matches!(self, VerdictKind::Allow)
    }
}

/// A pre-resolved policy match with all verdict-relevant information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMatch {
    pub matched: bool,
    pub is_deny: bool,
    pub is_conditional: bool,
    pub priority: u32,
    pub rule_override_deny: bool,
    pub context_deny: bool,
    pub require_approval: bool,
    pub condition_fired: bool,
    pub condition_verdict: VerdictKind,
    pub on_no_match_continue: bool,
    pub all_constraints_skipped: bool,
}

/// Outcome of verdict computation for a single policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictOutcome {
    Decided(VerdictKind),
    Continue,
}

/// Compute the verdict for a single resolved policy match.
///
/// Verbatim from `vellaveto-engine/src/verified_core.rs:141-188`.
#[inline]
pub fn compute_single_verdict(rm: &ResolvedMatch) -> VerdictOutcome {
    if !rm.matched {
        return VerdictOutcome::Continue;
    }

    if rm.rule_override_deny {
        return VerdictOutcome::Decided(VerdictKind::Deny);
    }

    if rm.context_deny {
        return VerdictOutcome::Decided(VerdictKind::Deny);
    }

    if rm.is_deny {
        return VerdictOutcome::Decided(VerdictKind::Deny);
    }

    if rm.is_conditional {
        if rm.require_approval {
            return VerdictOutcome::Decided(VerdictKind::RequireApproval);
        }

        if rm.all_constraints_skipped {
            if rm.on_no_match_continue {
                return VerdictOutcome::Continue;
            }
            return VerdictOutcome::Decided(VerdictKind::Deny);
        }

        if rm.condition_fired {
            return VerdictOutcome::Decided(rm.condition_verdict);
        }

        if rm.on_no_match_continue {
            return VerdictOutcome::Continue;
        }
        return VerdictOutcome::Decided(VerdictKind::Allow);
    }

    VerdictOutcome::Decided(VerdictKind::Allow)
}

/// Compute the final verdict from a sequence of resolved policy matches.
///
/// Verbatim from `vellaveto-engine/src/verified_core.rs:206-217`.
pub fn compute_verdict(resolved: &[ResolvedMatch]) -> VerdictKind {
    for rm in resolved {
        match compute_single_verdict(rm) {
            VerdictOutcome::Decided(kind) => return kind,
            VerdictOutcome::Continue => continue,
        }
    }
    VerdictKind::Deny
}

/// Sort comparator for policies: priority descending, deny-first at equal priority.
///
/// Simplified extraction from `vellaveto-engine/src/lib.rs:331-346` (`sort_policies`).
/// **Known omission:** production uses a 3rd ID tiebreaker for deterministic ordering
/// when priority and deny/allow are equal. This extraction omits the ID tiebreaker
/// because `ResolvedMatch` does not carry a policy ID field. The omission does not
/// affect V6/V7 safety (priority + deny-first are sufficient) but means sort order
/// may differ from production when priorities and types are equal.
pub fn sort_resolved_matches(matches: &mut [ResolvedMatch]) {
    matches.sort_by(|a, b| {
        let pri = b.priority.cmp(&a.priority);
        if pri != std::cmp::Ordering::Equal {
            return pri;
        }
        // Deny-first at equal priority: Deny policies before Allow
        let a_deny = a.is_deny;
        let b_deny = b.is_deny;
        b_deny.cmp(&a_deny)
    });
}

/// Check the sorted invariant: priority descending, deny-first at equal priority.
pub fn is_sorted(matches: &[ResolvedMatch]) -> bool {
    for i in 1..matches.len() {
        if matches[i].priority > matches[i - 1].priority {
            return false;
        }
        if matches[i].priority == matches[i - 1].priority
            && matches[i].is_deny
            && !matches[i - 1].is_deny
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_policy(priority: u32) -> ResolvedMatch {
        ResolvedMatch {
            matched: true,
            is_deny: false,
            is_conditional: false,
            priority,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: false,
            condition_verdict: VerdictKind::Deny,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        }
    }

    fn deny_policy(priority: u32) -> ResolvedMatch {
        ResolvedMatch {
            matched: true,
            is_deny: true,
            is_conditional: false,
            priority,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: false,
            condition_verdict: VerdictKind::Deny,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        }
    }

    #[test]
    fn test_production_parity_v1_empty_deny() {
        assert_eq!(compute_verdict(&[]), VerdictKind::Deny);
    }

    #[test]
    fn test_production_parity_v3_allow() {
        assert_eq!(compute_verdict(&[allow_policy(100)]), VerdictKind::Allow);
    }

    #[test]
    fn test_production_parity_deny() {
        assert_eq!(compute_verdict(&[deny_policy(100)]), VerdictKind::Deny);
    }

    #[test]
    fn test_sort_produces_sorted() {
        let mut policies = vec![allow_policy(50), deny_policy(100), allow_policy(100)];
        sort_resolved_matches(&mut policies);
        assert!(is_sorted(&policies));
        assert_eq!(policies[0].priority, 100);
        assert!(policies[0].is_deny);
    }
}
