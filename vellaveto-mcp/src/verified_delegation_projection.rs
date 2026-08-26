// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified projection of deputy delegation state into engine evaluation
//! context.
//!
//! The relay currently only has deputy-validated delegation depth, not the
//! full multi-hop path. It therefore projects active delegation into a
//! synthetic fail-closed call-chain shape whose only trusted semantic is its
//! length.

/// Return the synthetic call-chain length that should be exposed to the engine.
///
/// Active delegation preserves the deputy-reported depth. Direct requests or
/// sessions without an active delegation context project to an empty chain.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn projected_call_chain_len(
    has_active_delegation: bool,
    delegation_depth: u8,
) -> usize {
    if has_active_delegation {
        delegation_depth as usize
    } else {
        0
    }
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_delegation_projection.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function. Symbol parity cannot see this:
    //! `check-verus-parity.sh` greps for names.
    //!
    //! TOTAL discharge: one boolean and a `u8`, so all 512 inhabitants of the
    //! domain are enumerated.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_projected_call_chain_len(has_active_delegation: bool, delegation_depth: u8) -> usize {
        if has_active_delegation {
            delegation_depth as usize
        } else {
            0
        }
    }

    #[test]
    fn test_production_matches_verus_spec_total_domain() {
        let mut checked = 0usize;
        for has_active_delegation in [false, true] {
            for delegation_depth in 0u8..=u8::MAX {
                assert_eq!(
                    projected_call_chain_len(has_active_delegation, delegation_depth),
                    spec_projected_call_chain_len(has_active_delegation, delegation_depth),
                    "PARITY-HAND-1: projected_call_chain_len disagrees at \
                     ({has_active_delegation}, {delegation_depth})"
                );
                checked += 1;
            }
        }
        assert_eq!(
            checked, 512,
            "total domain is 2 x 256; enumeration collapsed"
        );
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Without an active delegation the projected chain is empty, whatever
        // depth the token claims.
        assert_eq!(spec_projected_call_chain_len(false, 7), 0);
        assert_eq!(spec_projected_call_chain_len(true, 7), 7);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_projected_call_chain_len_is_zero_without_active_delegation() {
        assert_eq!(projected_call_chain_len(false, 0), 0);
        assert_eq!(projected_call_chain_len(false, 3), 0);
    }

    #[test]
    fn test_projected_call_chain_len_preserves_active_depth() {
        assert_eq!(projected_call_chain_len(true, 0), 0);
        assert_eq!(projected_call_chain_len(true, 1), 1);
        assert_eq!(projected_call_chain_len(true, 3), 3);
        assert_eq!(
            projected_call_chain_len(true, u8::MAX),
            usize::from(u8::MAX)
        );
    }
}
