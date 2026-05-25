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
