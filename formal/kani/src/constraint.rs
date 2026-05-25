// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Constraint evaluation fail-closed verification extracted from
//! `vellaveto-engine/src/constraint_eval.rs`.
//!
//! Pure predicates for the `all_constraints_skipped` detection,
//! unknown-only condition payload detection, forbidden parameter matching,
//! and require_approval propagation.
//!
//! # Verified Properties (K53-K55)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K53 | All constraints skipped → all_constraints_skipped == true |
//! | K54 | Forbidden parameter match → Deny |
//! | K55 | require_approval == true → RequireApproval verdict |
//! | K55A | Non-empty condition payload with no known key → fail-closed |
//!
//! # Production Correspondence
//!
//! - `detect_all_skipped` ↔ `vellaveto-engine/src/constraint_eval.rs:113-169`
//! - `unrecognized_condition_payload` ↔ `vellaveto-engine/src/policy_compile.rs`
//! - `check_forbidden_params` ↔ `vellaveto-engine/src/constraint_eval.rs:62-83`

/// Represents the evaluation state of a single constraint.
#[derive(Debug, Clone, Copy)]
pub struct ConstraintEval {
    /// Whether the constraint's parameter was present or on_missing != "skip"
    pub was_evaluated: bool,
}

/// Detect if all constraints were skipped (all parameters missing with on_missing="skip").
///
/// Verbatim from production `evaluate_compiled_conditions_core` logic.
pub fn detect_all_skipped(constraints: &[ConstraintEval]) -> bool {
    if constraints.is_empty() {
        return false; // No constraints = not "all skipped"
    }
    !constraints.iter().any(|c| c.was_evaluated)
}

/// Detect whether a condition object has at least one recognized top-level key.
pub fn has_known_condition_key(
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

/// Detect a non-empty condition payload that contains no known condition keys.
pub fn unrecognized_condition_payload(
    has_condition_payload: bool,
    has_known_condition_key: bool,
) -> bool {
    has_condition_payload && !has_known_condition_key
}

/// Decision when all constraints are skipped.
///
/// Returns the appropriate verdict based on on_no_match_continue flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintVerdict {
    Deny,
    Allow,
    RequireApproval,
    Continue, // Skip to next policy
}

/// Determine the verdict when all constraints were skipped.
pub fn verdict_all_skipped(on_no_match_continue: bool) -> ConstraintVerdict {
    if on_no_match_continue {
        ConstraintVerdict::Continue
    } else {
        ConstraintVerdict::Deny // Fail-closed
    }
}

/// Check if any forbidden parameter is present.
///
/// Returns true if a forbidden parameter is found (should produce Deny).
pub fn check_forbidden_params(
    forbidden_params: &[bool], // Whether each forbidden parameter is present
) -> bool {
    forbidden_params.iter().any(|&present| present)
}

/// Determine verdict for a conditional policy given evaluation results.
///
/// This combines the full constraint evaluation outcome.
pub fn conditional_verdict(
    require_approval: bool,
    all_constraints_skipped: bool,
    on_no_match_continue: bool,
    any_forbidden_present: bool,
    condition_fired: bool,
    condition_allows: bool,
) -> ConstraintVerdict {
    // Forbidden parameters checked first
    if any_forbidden_present {
        return ConstraintVerdict::Deny;
    }

    // Require approval propagation
    if require_approval {
        return ConstraintVerdict::RequireApproval;
    }

    // All constraints skipped
    if all_constraints_skipped {
        return verdict_all_skipped(on_no_match_continue);
    }

    // Condition evaluation result
    if condition_fired {
        if condition_allows {
            return ConstraintVerdict::Allow;
        } else {
            return ConstraintVerdict::Deny;
        }
    }

    // No condition fired, continue or allow
    if on_no_match_continue {
        ConstraintVerdict::Continue
    } else {
        ConstraintVerdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_skipped_detected() {
        let constraints = vec![
            ConstraintEval {
                was_evaluated: false,
            },
            ConstraintEval {
                was_evaluated: false,
            },
        ];
        assert!(detect_all_skipped(&constraints));
    }

    #[test]
    fn test_not_all_skipped() {
        let constraints = vec![
            ConstraintEval {
                was_evaluated: false,
            },
            ConstraintEval {
                was_evaluated: true,
            },
        ];
        assert!(!detect_all_skipped(&constraints));
    }

    #[test]
    fn test_empty_not_skipped() {
        assert!(!detect_all_skipped(&[]));
    }

    #[test]
    fn test_known_condition_key_detected() {
        assert!(has_known_condition_key(false, false, true, false, false, false));
        assert!(!has_known_condition_key(false, false, false, false, false, false));
    }

    #[test]
    fn test_unrecognized_condition_payload_detected() {
        assert!(unrecognized_condition_payload(true, false));
        assert!(!unrecognized_condition_payload(false, false));
        assert!(!unrecognized_condition_payload(true, true));
    }

    #[test]
    fn test_forbidden_param_deny() {
        assert!(check_forbidden_params(&[false, true, false]));
    }

    #[test]
    fn test_no_forbidden_pass() {
        assert!(!check_forbidden_params(&[false, false]));
    }

    #[test]
    fn test_require_approval_propagated() {
        let v = conditional_verdict(true, false, false, false, false, false);
        assert_eq!(v, ConstraintVerdict::RequireApproval);
    }

    #[test]
    fn test_all_skipped_deny() {
        let v = conditional_verdict(false, true, false, false, false, false);
        assert_eq!(v, ConstraintVerdict::Deny);
    }

    #[test]
    fn test_all_skipped_continue() {
        let v = conditional_verdict(false, true, true, false, false, false);
        assert_eq!(v, ConstraintVerdict::Continue);
    }
}
