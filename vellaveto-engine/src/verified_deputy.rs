// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified confused-deputy delegation guards.
//!
//! This module extracts the pure predicates from `deputy.rs` so the runtime
//! delegation chain and validation boundaries can be mirrored in Verus.

/// Return the next delegation depth using the runtime saturating increment.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn next_delegation_depth(current_depth: u8) -> u8 {
    current_depth.saturating_add(1)
}

/// Return true when a delegation depth stays within the configured limit.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_depth_within_limit(new_depth: u8, max_depth: u8) -> bool {
    new_depth <= max_depth
}

/// Return true when a chained delegation comes from the currently delegated
/// principal for the session.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn redelegation_chain_principal_valid(
    parent_has_delegate: bool,
    normalized_from_matches_parent_delegate: bool,
) -> bool {
    !parent_has_delegate || normalized_from_matches_parent_delegate
}

/// Return true when a requested child tool stays within the parent's granted
/// tool set, unless the parent has unrestricted delegation scope.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn redelegation_tool_allowed(
    parent_has_unrestricted_tools: bool,
    parent_allows_requested_tool: bool,
) -> bool {
    parent_has_unrestricted_tools || parent_allows_requested_tool
}

/// Return true when the claimed principal matches the stored delegate.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegated_principal_matches(normalized_claimed_matches_delegate: bool) -> bool {
    normalized_claimed_matches_delegate
}

/// Return true when the requested tool is allowed under the current delegation
/// context.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegated_tool_allowed(
    allowed_tools_empty: bool,
    requested_tool_found: bool,
) -> bool {
    allowed_tools_empty || requested_tool_found
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_deputy.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function. Symbol parity cannot see this:
    //! `check-verus-parity.sh` greps for names.
    //!
    //! MIXED: the four allowance predicates are enumerated TOTALLY over their
    //! booleans. The depth functions carry `u8` operands, which is small
    //! enough to enumerate completely — all 256 depths and all 256×256 limit
    //! pairs.
    //!
    //! The kernel states the depth saturation over unbounded `nat` with a
    //! literal 255 ceiling; production works in `u8` where that ceiling is
    //! `u8::MAX`, so the transcription uses `u8::MAX` and the two agree by
    //! construction rather than by coincidence.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    /// The kernel states this over unbounded `nat` with a literal 255 ceiling,
    /// where `current_depth >= 255` is a genuine comparison. Transcribed into
    /// `u8` the `>` half is unreachable, so it collapses to `==`. The collapse
    /// is a property of the domain change, not a liberty taken with the spec.
    fn spec_next_delegation_depth(current_depth: u8) -> u8 {
        if current_depth == u8::MAX {
            u8::MAX
        } else {
            current_depth + 1
        }
    }

    fn spec_delegation_depth_within_limit(new_depth: u8, max_depth: u8) -> bool {
        new_depth <= max_depth
    }

    fn spec_redelegation_chain_principal_valid(
        parent_has_delegate: bool,
        normalized_from_matches_parent_delegate: bool,
    ) -> bool {
        !parent_has_delegate || normalized_from_matches_parent_delegate
    }

    fn spec_redelegation_tool_allowed(
        parent_has_unrestricted_tools: bool,
        parent_allows_requested_tool: bool,
    ) -> bool {
        parent_has_unrestricted_tools || parent_allows_requested_tool
    }

    fn spec_delegated_principal_matches(normalized_claimed_matches_delegate: bool) -> bool {
        normalized_claimed_matches_delegate
    }

    fn spec_delegated_tool_allowed(allowed_tools_empty: bool, requested_tool_found: bool) -> bool {
        allowed_tools_empty || requested_tool_found
    }

    #[test]
    fn test_depth_functions_match_verus_spec_total_domain() {
        for current in 0u8..=u8::MAX {
            assert_eq!(
                next_delegation_depth(current),
                spec_next_delegation_depth(current),
                "PARITY-HAND-1: next_delegation_depth disagrees at {current}"
            );
            for max in 0u8..=u8::MAX {
                assert_eq!(
                    delegation_depth_within_limit(current, max),
                    spec_delegation_depth_within_limit(current, max),
                    "PARITY-HAND-1: delegation_depth_within_limit disagrees at ({current}, {max})"
                );
            }
        }
    }

    #[test]
    fn test_allowance_predicates_match_verus_spec_total_domain() {
        for a in [false, true] {
            assert_eq!(
                delegated_principal_matches(a),
                spec_delegated_principal_matches(a),
                "PARITY-HAND-1: delegated_principal_matches disagrees at ({a})"
            );
            for b in [false, true] {
                assert_eq!(
                    redelegation_chain_principal_valid(a, b),
                    spec_redelegation_chain_principal_valid(a, b),
                    "PARITY-HAND-1: redelegation_chain_principal_valid disagrees at ({a}, {b})"
                );
                assert_eq!(
                    redelegation_tool_allowed(a, b),
                    spec_redelegation_tool_allowed(a, b),
                    "PARITY-HAND-1: redelegation_tool_allowed disagrees at ({a}, {b})"
                );
                assert_eq!(
                    delegated_tool_allowed(a, b),
                    spec_delegated_tool_allowed(a, b),
                    "PARITY-HAND-1: delegated_tool_allowed disagrees at ({a}, {b})"
                );
            }
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Depth must saturate, not wrap back to zero and grant fresh budget.
        assert_eq!(spec_next_delegation_depth(u8::MAX), u8::MAX);
        assert_eq!(spec_next_delegation_depth(0), 1);
        // A re-delegation must originate from the parent's delegate.
        assert!(!spec_redelegation_chain_principal_valid(true, false));
        assert!(spec_redelegation_chain_principal_valid(false, false));
        // A restricted parent must actually allow the requested tool.
        assert!(!spec_redelegation_tool_allowed(false, false));
        assert!(!spec_delegated_tool_allowed(false, false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_delegation_depth_saturates() {
        assert_eq!(next_delegation_depth(0), 1);
        assert_eq!(next_delegation_depth(u8::MAX), u8::MAX);
    }

    #[test]
    fn test_delegation_depth_within_limit_is_strict() {
        assert!(delegation_depth_within_limit(1, 1));
        assert!(!delegation_depth_within_limit(2, 1));
    }

    #[test]
    fn test_redelegation_chain_principal_valid_requires_parent_delegate_match() {
        assert!(redelegation_chain_principal_valid(false, false));
        assert!(redelegation_chain_principal_valid(true, true));
        assert!(!redelegation_chain_principal_valid(true, false));
    }

    #[test]
    fn test_redelegation_tool_allowed_respects_parent_scope() {
        assert!(redelegation_tool_allowed(true, false));
        assert!(redelegation_tool_allowed(false, true));
        assert!(!redelegation_tool_allowed(false, false));
    }

    #[test]
    fn test_delegated_principal_and_tool_checks_are_identities() {
        assert!(delegated_principal_matches(true));
        assert!(!delegated_principal_matches(false));
        assert!(delegated_tool_allowed(true, false));
        assert!(delegated_tool_allowed(false, true));
        assert!(!delegated_tool_allowed(false, false));
    }
}
