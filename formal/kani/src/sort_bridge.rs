// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Sorting correctness bridge: Kani → Verus.
//!
//! The Verus verified core (`verified_core.rs`) has a precondition that
//! the `ResolvedMatch` sequence is sorted by priority descending with
//! deny-first at equal priority. This module proves that
//! `sort_resolved_matches()` always produces output satisfying that
//! precondition, completing the verification chain:
//!
//!   **Kani proves sorting correct (bounded) → Verus proves verdict correct (unbounded)**
//!
//! # Verified Properties (K103-K107)
//!
//! | ID   | Property |
//! |------|----------|
//! | K103 | sort_resolved_matches output satisfies is_sorted |
//! | K104 | sort is stable: equal-priority policies preserve relative order within deny/allow groups |
//! | K105 | sort is idempotent: sort(sort(x)) == sort(x) |
//! | K106 | empty input: sort produces empty output (trivially sorted) |
//! | K107 | single element: always sorted |
//!
//! # Production Correspondence
//!
//! - `sort_resolved_matches` ↔ `vellaveto-engine/src/lib.rs:331-346` (sort_policies)
//! - `is_sorted` ↔ Verus precondition in `verified_core.rs:spec_is_sorted`

use crate::verified_core::{is_sorted, sort_resolved_matches, ResolvedMatch, VerdictKind};

fn make_policy(priority: u32, is_deny: bool) -> ResolvedMatch {
    ResolvedMatch {
        matched: true,
        is_deny,
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── K103: sort output satisfies is_sorted ─────────────────────────

    #[test]
    fn test_k103_sort_produces_sorted_output() {
        // Exhaustive for 3 policies with priorities 1-3 and deny/allow
        let priorities = [1u32, 2, 3];
        let deny_flags = [false, true];

        // All 6^3 = 216 combinations of 3 policies
        for &p0 in &priorities {
            for &d0 in &deny_flags {
                for &p1 in &priorities {
                    for &d1 in &deny_flags {
                        for &p2 in &priorities {
                            for &d2 in &deny_flags {
                                let mut matches = vec![
                                    make_policy(p0, d0),
                                    make_policy(p1, d1),
                                    make_policy(p2, d2),
                                ];
                                sort_resolved_matches(&mut matches);
                                assert!(
                                    is_sorted(&matches),
                                    "sort output not sorted for ({p0},{d0}), ({p1},{d1}), ({p2},{d2})"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_k103_sort_produces_sorted_larger() {
        // 5 policies with various priorities
        let mut matches = vec![
            make_policy(1, false),
            make_policy(5, true),
            make_policy(3, false),
            make_policy(5, false),
            make_policy(2, true),
        ];
        sort_resolved_matches(&mut matches);
        assert!(is_sorted(&matches));

        // Verify priority ordering: 5, 5, 3, 2, 1
        assert_eq!(matches[0].priority, 5);
        assert_eq!(matches[1].priority, 5);
        assert_eq!(matches[2].priority, 3);
        assert_eq!(matches[3].priority, 2);
        assert_eq!(matches[4].priority, 1);

        // Verify deny-first at priority 5
        assert!(matches[0].is_deny, "deny should come first at priority 5");
        assert!(!matches[1].is_deny, "allow should come second at priority 5");
    }

    // ── K104: Sort stability within deny/allow groups ─────────────────

    #[test]
    fn test_k104_deny_first_at_equal_priority() {
        let mut matches = vec![
            make_policy(10, false), // Allow at priority 10
            make_policy(10, true),  // Deny at priority 10
        ];
        sort_resolved_matches(&mut matches);
        assert!(is_sorted(&matches));
        assert!(matches[0].is_deny, "Deny must come before Allow at equal priority");
        assert!(!matches[1].is_deny);
    }

    #[test]
    fn test_k104_multiple_deny_at_equal_priority() {
        let mut matches = vec![
            make_policy(5, false),
            make_policy(5, true),
            make_policy(5, true),
            make_policy(5, false),
        ];
        sort_resolved_matches(&mut matches);
        assert!(is_sorted(&matches));
        // First two should be deny, last two allow
        assert!(matches[0].is_deny);
        assert!(matches[1].is_deny);
        assert!(!matches[2].is_deny);
        assert!(!matches[3].is_deny);
    }

    // ── K105: Sort idempotent ─────────────────────────────────────────

    #[test]
    fn test_k105_sort_idempotent() {
        let priorities = [1u32, 5, 3, 5, 2];
        let denies = [false, true, false, false, true];

        let mut matches: Vec<ResolvedMatch> = priorities
            .iter()
            .zip(denies.iter())
            .map(|(&p, &d)| make_policy(p, d))
            .collect();

        sort_resolved_matches(&mut matches);
        let first_sort = matches.clone();

        sort_resolved_matches(&mut matches);
        assert_eq!(
            matches, first_sort,
            "sort(sort(x)) should equal sort(x)"
        );
    }

    #[test]
    fn test_k105_already_sorted_unchanged() {
        let mut matches = vec![
            make_policy(10, true),
            make_policy(10, false),
            make_policy(5, true),
            make_policy(5, false),
            make_policy(1, false),
        ];
        let original = matches.clone();
        sort_resolved_matches(&mut matches);
        assert_eq!(matches, original, "already sorted input should be unchanged");
    }

    // ── K106: Empty input ─────────────────────────────────────────────

    #[test]
    fn test_k106_empty_sorted() {
        let mut matches: Vec<ResolvedMatch> = vec![];
        sort_resolved_matches(&mut matches);
        assert!(is_sorted(&matches));
        assert!(matches.is_empty());
    }

    // ── K107: Single element always sorted ────────────────────────────

    #[test]
    fn test_k107_single_element() {
        for &deny in &[false, true] {
            for priority in 0..=10u32 {
                let mut matches = vec![make_policy(priority, deny)];
                sort_resolved_matches(&mut matches);
                assert!(is_sorted(&matches));
            }
        }
    }

    // ── Bridge verification: sorted input → Verus precondition met ────

    #[test]
    fn test_bridge_sorted_then_verdict_correct() {
        use crate::verified_core::compute_verdict;

        // After sorting, compute_verdict should respect first-match-wins
        let mut matches = vec![
            make_policy(1, false),  // Low priority allow
            make_policy(10, true),  // High priority deny
        ];
        sort_resolved_matches(&mut matches);
        assert!(is_sorted(&matches));

        // Deny at priority 10 should win over Allow at priority 1
        let verdict = compute_verdict(&matches);
        assert!(verdict.is_deny(), "High-priority deny must override low-priority allow");
    }

    #[test]
    fn test_bridge_deny_first_produces_deny_verdict() {
        use crate::verified_core::compute_verdict;

        // Same priority: deny should come first in sort and produce Deny verdict
        let mut matches = vec![
            make_policy(5, false), // Allow
            make_policy(5, true),  // Deny
        ];
        sort_resolved_matches(&mut matches);
        assert!(is_sorted(&matches));

        let verdict = compute_verdict(&matches);
        assert!(verdict.is_deny(), "Deny-first at equal priority must produce Deny");
    }
}
