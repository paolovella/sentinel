// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified constraint-evaluation kernel.
//!
//! This module extracts the pure fail-closed decision logic from
//! `constraint_eval.rs` so it can be proved unbounded in Verus and used by
//! the production wrapper without pulling Rust collection internals into the
//! proof boundary.
//!
//! # Verification Properties
//!
//! | ID | Property | Meaning |
//! |----|----------|---------|
//! | ENG-CON-1 | All-skipped detection | `total_constraints > 0 && !any_evaluated` iff all constraints were skipped |
//! | ENG-CON-2 | Forbidden precedence | Any forbidden parameter presence forces `Deny` |
//! | ENG-CON-3 | Require-approval precedence | `require_approval` forces `RequireApproval` unless already denied |
//! | ENG-CON-4 | No-match handling | `on_no_match_continue` only yields `Continue` on the no-match path |
//! | ENG-CON-5 | Unknown-only conditions | Non-empty condition payload with no known key is fail-closed |

/// Final decision produced by the pure constraint-evaluation kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintVerdict {
    Allow,
    Deny,
    RequireApproval,
    Continue,
}

/// Verdict that can be produced by a fired constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedConstraintVerdict {
    Allow,
    Deny,
    RequireApproval,
}

impl From<MatchedConstraintVerdict> for ConstraintVerdict {
    fn from(value: MatchedConstraintVerdict) -> Self {
        match value {
            MatchedConstraintVerdict::Allow => Self::Allow,
            MatchedConstraintVerdict::Deny => Self::Deny,
            MatchedConstraintVerdict::RequireApproval => Self::RequireApproval,
        }
    }
}

/// Return true when every configured constraint was skipped.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn all_constraints_skipped(total_constraints: usize, any_evaluated: bool) -> bool {
    total_constraints > 0 && !any_evaluated
}

/// Return true when a condition payload contains at least one known top-level key.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn has_known_condition_key(
    has_require_approval: bool,
    has_forbidden_parameters: bool,
    has_required_parameters: bool,
    has_parameter_constraints: bool,
    has_context_conditions: bool,
    has_on_no_match: bool,
) -> bool {
    has_require_approval
        || has_forbidden_parameters
        || has_required_parameters
        || has_parameter_constraints
        || has_context_conditions
        || has_on_no_match
}

/// Return true when a non-empty condition payload has no recognized condition key.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn unrecognized_condition_payload(
    has_condition_payload: bool,
    has_known_condition_key: bool,
) -> bool {
    has_condition_payload && !has_known_condition_key
}

/// Return true when at least one forbidden parameter is present.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub fn has_forbidden_parameter(forbidden_parameters_present: &[bool]) -> bool {
    forbidden_parameters_present.iter().any(|&present| present)
}

/// Verdict for the "all constraints skipped" path.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn skipped_constraints_verdict(on_no_match_continue: bool) -> ConstraintVerdict {
    if on_no_match_continue {
        ConstraintVerdict::Continue
    } else {
        ConstraintVerdict::Deny
    }
}

/// Verdict for the "no constraint fired" path.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn no_match_verdict(on_no_match_continue: bool) -> ConstraintVerdict {
    if on_no_match_continue {
        ConstraintVerdict::Continue
    } else {
        ConstraintVerdict::Allow
    }
}

/// Compute the pure verdict for conditional constraint evaluation.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn conditional_verdict(
    require_approval: bool,
    all_constraints_skipped: bool,
    on_no_match_continue: bool,
    any_forbidden_present: bool,
    condition_fired: bool,
    condition_verdict: MatchedConstraintVerdict,
) -> ConstraintVerdict {
    if any_forbidden_present {
        return ConstraintVerdict::Deny;
    }

    if require_approval {
        return ConstraintVerdict::RequireApproval;
    }

    if all_constraints_skipped {
        return skipped_constraints_verdict(on_no_match_continue);
    }

    if condition_fired {
        return match condition_verdict {
            MatchedConstraintVerdict::Allow => ConstraintVerdict::Allow,
            MatchedConstraintVerdict::Deny => ConstraintVerdict::Deny,
            MatchedConstraintVerdict::RequireApproval => ConstraintVerdict::RequireApproval,
        };
    }

    no_match_verdict(on_no_match_continue)
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_constraint_eval.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function. Symbol parity cannot see this:
    //! `check-verus-parity.sh` greps for names.
    //!
    //! MIXED: every boolean predicate is enumerated TOTALLY, and
    //! `conditional_verdict` is enumerated across all 2⁵ flag combinations
    //! crossed with all three `MatchedConstraintVerdict` values — 96 cases,
    //! the whole domain it distinguishes. `all_constraints_skipped` carries a
    //! `usize` count and uses a boundary set around zero, the only value the
    //! spec treats specially. `has_forbidden_parameter` takes a slice, so it
    //! is bounded: every flag vector of length 0..=4.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_all_constraints_skipped(total_constraints: usize, any_evaluated: bool) -> bool {
        total_constraints > 0 && !any_evaluated
    }

    fn spec_has_known_condition_key(
        has_require_approval: bool,
        has_forbidden_parameters: bool,
        has_required_parameters: bool,
        has_parameter_constraints: bool,
        has_context_conditions: bool,
        has_on_no_match: bool,
    ) -> bool {
        has_require_approval
            || has_forbidden_parameters
            || has_required_parameters
            || has_parameter_constraints
            || has_context_conditions
            || has_on_no_match
    }

    fn spec_unrecognized_condition_payload(
        has_condition_payload: bool,
        has_known_condition_key: bool,
    ) -> bool {
        has_condition_payload && !has_known_condition_key
    }

    fn spec_has_forbidden_parameter(flags: &[bool]) -> bool {
        let mut i = 0usize;
        while i < flags.len() {
            if flags[i] {
                return true;
            }
            i += 1;
        }
        false
    }

    fn spec_skipped_constraints_verdict(on_no_match_continue: bool) -> ConstraintVerdict {
        if on_no_match_continue {
            ConstraintVerdict::Continue
        } else {
            ConstraintVerdict::Deny
        }
    }

    fn spec_no_match_verdict(on_no_match_continue: bool) -> ConstraintVerdict {
        if on_no_match_continue {
            ConstraintVerdict::Continue
        } else {
            ConstraintVerdict::Allow
        }
    }

    fn spec_matched_constraint_verdict(
        condition_verdict: MatchedConstraintVerdict,
    ) -> ConstraintVerdict {
        match condition_verdict {
            MatchedConstraintVerdict::Allow => ConstraintVerdict::Allow,
            MatchedConstraintVerdict::Deny => ConstraintVerdict::Deny,
            MatchedConstraintVerdict::RequireApproval => ConstraintVerdict::RequireApproval,
        }
    }

    fn spec_conditional_verdict(
        require_approval: bool,
        all_constraints_skipped: bool,
        on_no_match_continue: bool,
        any_forbidden_present: bool,
        condition_fired: bool,
        condition_verdict: MatchedConstraintVerdict,
    ) -> ConstraintVerdict {
        if any_forbidden_present {
            ConstraintVerdict::Deny
        } else if require_approval {
            ConstraintVerdict::RequireApproval
        } else if all_constraints_skipped {
            spec_skipped_constraints_verdict(on_no_match_continue)
        } else if condition_fired {
            spec_matched_constraint_verdict(condition_verdict)
        } else {
            spec_no_match_verdict(on_no_match_continue)
        }
    }

    const MATCHED: [MatchedConstraintVerdict; 3] = [
        MatchedConstraintVerdict::Allow,
        MatchedConstraintVerdict::Deny,
        MatchedConstraintVerdict::RequireApproval,
    ];

    #[test]
    fn test_predicates_match_verus_spec_total_domain() {
        for bits in 0u8..64 {
            let f = |i: u8| bits & (1 << i) != 0;
            let (a, b, c, d, e, g) = (f(0), f(1), f(2), f(3), f(4), f(5));
            assert_eq!(
                has_known_condition_key(a, b, c, d, e, g),
                spec_has_known_condition_key(a, b, c, d, e, g),
                "PARITY-HAND-1: has_known_condition_key disagrees at bits {bits:#08b}"
            );
            assert_eq!(
                unrecognized_condition_payload(a, b),
                spec_unrecognized_condition_payload(a, b),
                "PARITY-HAND-1: unrecognized_condition_payload disagrees at ({a}, {b})"
            );
            assert_eq!(
                skipped_constraints_verdict(a),
                spec_skipped_constraints_verdict(a),
                "PARITY-HAND-1: skipped_constraints_verdict disagrees at ({a})"
            );
            assert_eq!(
                no_match_verdict(a),
                spec_no_match_verdict(a),
                "PARITY-HAND-1: no_match_verdict disagrees at ({a})"
            );
        }

        for total in [0usize, 1, 2, 64, usize::MAX] {
            for any_evaluated in [false, true] {
                assert_eq!(
                    all_constraints_skipped(total, any_evaluated),
                    spec_all_constraints_skipped(total, any_evaluated),
                    "PARITY-HAND-1: all_constraints_skipped disagrees at ({total}, \
                     {any_evaluated})"
                );
            }
        }
    }

    #[test]
    fn test_conditional_verdict_matches_verus_spec_total_domain() {
        let mut checked = 0usize;
        for bits in 0u8..32 {
            let f = |i: u8| bits & (1 << i) != 0;
            let (ra, acs, onmc, afp, cf) = (f(0), f(1), f(2), f(3), f(4));
            for condition_verdict in MATCHED {
                assert_eq!(
                    conditional_verdict(ra, acs, onmc, afp, cf, condition_verdict),
                    spec_conditional_verdict(ra, acs, onmc, afp, cf, condition_verdict),
                    "PARITY-HAND-1: conditional_verdict disagrees at bits {bits:#07b} \
                     with {condition_verdict:?}"
                );
                // The kernel names this `spec_matched_constraint_verdict`;
                // production expresses it as the `From` impl, so that is what
                // gets bound here.
                assert_eq!(
                    ConstraintVerdict::from(condition_verdict),
                    spec_matched_constraint_verdict(condition_verdict),
                    "PARITY-HAND-1: From<MatchedConstraintVerdict> disagrees at \
                     {condition_verdict:?}"
                );
                checked += 1;
            }
        }
        assert_eq!(
            checked, 96,
            "total domain is 2^5 x 3; enumeration collapsed"
        );
    }

    #[test]
    fn test_has_forbidden_parameter_matches_verus_spec_bounded_exhaustive() {
        let mut all: Vec<Vec<bool>> = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..4 {
            let mut next = Vec::new();
            for prefix in &frontier {
                for flag in [false, true] {
                    let mut candidate: Vec<bool> = prefix.clone();
                    candidate.push(flag);
                    next.push(candidate);
                }
            }
            all.extend(next.iter().cloned());
            frontier = next;
        }
        assert_eq!(all.len(), 31, "enumeration size changed; recount");
        for flags in &all {
            assert_eq!(
                has_forbidden_parameter(flags),
                spec_has_forbidden_parameter(flags),
                "PARITY-HAND-1: has_forbidden_parameter disagrees for {flags:?}"
            );
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // A forbidden parameter denies ahead of everything else, including an
        // approval requirement.
        assert_eq!(
            spec_conditional_verdict(
                true,
                false,
                true,
                true,
                false,
                MatchedConstraintVerdict::Allow
            ),
            ConstraintVerdict::Deny
        );
        // Skipped constraints fail closed unless the policy opts into continue.
        assert_eq!(
            spec_skipped_constraints_verdict(false),
            ConstraintVerdict::Deny
        );
        // No constraint firing is an implicit allow, which is the asymmetry
        // between the two no-match paths.
        assert_eq!(spec_no_match_verdict(false), ConstraintVerdict::Allow);
        // Zero constraints is not "all skipped".
        assert!(!spec_all_constraints_skipped(0, false));
        assert!(spec_all_constraints_skipped(1, false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_constraints_skipped_detected() {
        assert!(all_constraints_skipped(3, false));
        assert!(!all_constraints_skipped(0, false));
        assert!(!all_constraints_skipped(3, true));
    }

    #[test]
    fn test_known_condition_key_detection() {
        assert!(has_known_condition_key(
            false, true, false, false, false, false
        ));
        assert!(has_known_condition_key(
            false, false, false, false, false, true
        ));
        assert!(!has_known_condition_key(
            false, false, false, false, false, false
        ));
    }

    #[test]
    fn test_unrecognized_condition_payload_detected() {
        assert!(unrecognized_condition_payload(true, false));
        assert!(!unrecognized_condition_payload(false, false));
        assert!(!unrecognized_condition_payload(true, true));
    }

    #[test]
    fn test_forbidden_parameter_detected() {
        assert!(has_forbidden_parameter(&[false, true, false]));
        assert!(!has_forbidden_parameter(&[false, false]));
    }

    #[test]
    fn test_skipped_constraints_continue() {
        assert_eq!(
            skipped_constraints_verdict(true),
            ConstraintVerdict::Continue
        );
        assert_eq!(skipped_constraints_verdict(false), ConstraintVerdict::Deny);
    }

    #[test]
    fn test_no_match_verdict() {
        assert_eq!(no_match_verdict(true), ConstraintVerdict::Continue);
        assert_eq!(no_match_verdict(false), ConstraintVerdict::Allow);
    }

    #[test]
    fn test_conditional_verdict_precedence() {
        assert_eq!(
            conditional_verdict(
                false,
                false,
                false,
                true,
                true,
                MatchedConstraintVerdict::Allow,
            ),
            ConstraintVerdict::Deny
        );
        assert_eq!(
            conditional_verdict(
                true,
                false,
                false,
                false,
                true,
                MatchedConstraintVerdict::Allow,
            ),
            ConstraintVerdict::RequireApproval
        );
    }

    #[test]
    fn test_conditional_verdict_paths() {
        assert_eq!(
            conditional_verdict(
                false,
                true,
                true,
                false,
                false,
                MatchedConstraintVerdict::Deny,
            ),
            ConstraintVerdict::Continue
        );
        assert_eq!(
            conditional_verdict(
                false,
                true,
                false,
                false,
                false,
                MatchedConstraintVerdict::Deny,
            ),
            ConstraintVerdict::Deny
        );
        assert_eq!(
            conditional_verdict(
                false,
                false,
                false,
                false,
                true,
                MatchedConstraintVerdict::RequireApproval,
            ),
            ConstraintVerdict::RequireApproval
        );
        assert_eq!(
            conditional_verdict(
                false,
                false,
                true,
                false,
                false,
                MatchedConstraintVerdict::Deny,
            ),
            ConstraintVerdict::Continue
        );
        assert_eq!(
            conditional_verdict(
                false,
                false,
                false,
                false,
                false,
                MatchedConstraintVerdict::Deny,
            ),
            ConstraintVerdict::Allow
        );
    }
}
