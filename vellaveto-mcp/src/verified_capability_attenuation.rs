// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability attenuation arithmetic kernel.
//!
//! This module extracts the delegation depth decrement and expiry clamp from
//! `capability_token.rs` so they can be proved in Verus without pulling chrono,
//! UUID generation, signing, or string normalization into the proof boundary.

/// Return the child token's remaining delegation depth, or `None` if the
/// parent can no longer delegate.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn attenuated_remaining_depth(parent_remaining_depth: u8) -> Option<u8> {
    if parent_remaining_depth == 0 {
        None
    } else {
        Some(parent_remaining_depth - 1)
    }
}

/// Return the child token's expiry time in Unix seconds.
///
/// The child expiry is the earlier of the parent's expiry and the requested
/// `now + ttl_secs` window. Returns `None` if the parent is already expired,
/// the requested TTL exceeds policy, or the requested expiry overflows `u64`.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) fn attenuated_expiry_epoch(
    parent_expires_at_epoch: u64,
    now_epoch: u64,
    ttl_secs: u64,
    max_ttl_secs: u64,
) -> Option<u64> {
    if ttl_secs > max_ttl_secs || now_epoch >= parent_expires_at_epoch {
        return None;
    }

    let requested_expires = now_epoch.checked_add(ttl_secs)?;
    Some(requested_expires.min(parent_expires_at_epoch))
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_capability_attenuation.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the function this crate ships, which is the step that carries the proof
    //! to production. Symbol parity cannot see this: `check-verus-parity.sh`
    //! greps for names.
    //!
    //! MIXED: the depth function is discharged TOTALLY — `u8` has 256
    //! inhabitants and all are enumerated. The expiry function takes four
    //! `u64`s, so it uses a boundary set built around the overflow edge,
    //! the parent-expiry clamp, and the ttl limit.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_can_attenuate_depth(parent_remaining_depth: u8) -> bool {
        parent_remaining_depth > 0
    }

    fn spec_attenuated_remaining_depth_value(parent_remaining_depth: u8) -> u8 {
        if parent_remaining_depth == 0 {
            0
        } else {
            parent_remaining_depth - 1
        }
    }

    fn spec_can_attenuate_expiry(
        parent_expires_at_epoch: u128,
        now_epoch: u128,
        ttl_secs: u128,
        max_ttl_secs: u128,
    ) -> bool {
        ttl_secs <= max_ttl_secs
            && now_epoch < parent_expires_at_epoch
            && now_epoch + ttl_secs <= u128::from(u64::MAX)
    }

    fn spec_attenuated_expiry_epoch_value(
        parent_expires_at_epoch: u128,
        now_epoch: u128,
        ttl_secs: u128,
    ) -> u128 {
        if now_epoch + ttl_secs <= parent_expires_at_epoch {
            now_epoch + ttl_secs
        } else {
            parent_expires_at_epoch
        }
    }

    #[test]
    fn test_attenuated_remaining_depth_matches_verus_spec_total_domain() {
        for depth in 0u8..=u8::MAX {
            let shipped = attenuated_remaining_depth(depth);
            let expected = if spec_can_attenuate_depth(depth) {
                Some(spec_attenuated_remaining_depth_value(depth))
            } else {
                None
            };
            assert_eq!(
                shipped, expected,
                "PARITY-HAND-1: attenuated_remaining_depth disagrees at {depth}"
            );
        }
    }

    #[test]
    fn test_attenuated_expiry_epoch_matches_verus_spec_at_boundaries() {
        // Chosen around the three places the spec can change its mind: the ttl
        // limit, the parent-expiry clamp, and u64 overflow on now + ttl.
        let values = [0u64, 1, 2, 100, 1_000, u64::MAX - 1, u64::MAX];
        let mut checked = 0usize;
        for &parent_expires in &values {
            for &now in &values {
                for &ttl in &values {
                    for &max_ttl in &values {
                        let shipped = attenuated_expiry_epoch(parent_expires, now, ttl, max_ttl);
                        let expected = if spec_can_attenuate_expiry(
                            u128::from(parent_expires),
                            u128::from(now),
                            u128::from(ttl),
                            u128::from(max_ttl),
                        ) {
                            let value = spec_attenuated_expiry_epoch_value(
                                u128::from(parent_expires),
                                u128::from(now),
                                u128::from(ttl),
                            );
                            Some(u64::try_from(value).expect("clamped below u64::MAX by guard"))
                        } else {
                            None
                        };
                        assert_eq!(
                            shipped, expected,
                            "PARITY-HAND-1: attenuated_expiry_epoch disagrees at \
                             ({parent_expires}, {now}, {ttl}, {max_ttl})"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 7usize.pow(4), "enumeration collapsed");
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Depth must run out rather than wrapping.
        assert!(!spec_can_attenuate_depth(0));
        // An already-expired parent cannot be attenuated.
        assert!(!spec_can_attenuate_expiry(10, 10, 1, 100));
        // A ttl above the cap is refused.
        assert!(!spec_can_attenuate_expiry(1_000, 1, 200, 100));
        // now + ttl must not overflow u64.
        assert!(!spec_can_attenuate_expiry(
            u128::from(u64::MAX),
            u128::from(u64::MAX),
            1,
            u128::from(u64::MAX)
        ));
        // The child expiry never exceeds the parent's.
        assert_eq!(spec_attenuated_expiry_epoch_value(100, 10, 500), 100);
    }
}

#[cfg(test)]
mod verus_chain_composition_differential {
    //! Differential binding for `PARITY-HAND-1`, composition kernel
    //! `formal/verus/verified_capability_chain.rs` (CAP-CHAIN-1..6).
    //!
    //! Like `verified_audit_integrity`, this kernel models no new function. It
    //! composes the depth and expiry primitives this module already binds, then
    //! proves properties of an n-step delegation chain. The failure the
    //! per-primitive bindings cannot catch is the composition reasoning about a
    //! *different* primitive than the one that ships, so the binding iterates
    //! the shipped functions and checks each lemma against the result.
    //!
    //! `spec_delegation_step_valid` composes rules
    //! `verified_capability_identity` already binds — child issuer equals
    //! parent holder, no self-delegation — so those are checked through the
    //! shipped predicates rather than restated.
    //!
    //! BOUNDED: chain lengths 0..=64 from every `u8` starting depth (all 256),
    //! and expiry chains over a boundary set around the clamp and overflow
    //! edges.

    use super::*;
    use crate::verified_capability_identity::{
        delegated_child_issuer_valid, delegation_holder_distinct,
    };

    /// Transcription of `spec_depth_after_n_steps`.
    fn spec_depth_after_n_steps(n: u32, initial_depth: u8) -> u8 {
        let mut depth = initial_depth;
        for _ in 0..n {
            if depth == 0 {
                return 0;
            }
            depth -= 1;
        }
        depth
    }

    /// Transcription of `spec_delegation_step_valid`, over the abstract
    /// principal identities the kernel uses.
    fn spec_delegation_step_valid(
        parent_remaining_depth: u8,
        parent_holder: u32,
        child_issuer: u32,
        child_holder: u32,
    ) -> bool {
        parent_remaining_depth > 0 && child_issuer == parent_holder && child_holder != child_issuer
    }

    /// Iterate the *shipped* depth primitive n times.
    fn shipped_depth_after_n_steps(n: u32, initial_depth: u8) -> u8 {
        let mut depth = initial_depth;
        for _ in 0..n {
            match attenuated_remaining_depth(depth) {
                Some(next) => depth = next,
                None => return 0,
            }
        }
        depth
    }

    /// CAP-CHAIN-1: after n steps from a depth of at least n, the remaining
    /// depth is exactly `initial_depth - n`. Checked against the shipped
    /// primitive, not just the transcription.
    #[test]
    fn test_chain_depth_exact_matches_iterating_the_shipped_primitive() {
        for initial in 0u8..=u8::MAX {
            for n in 0u32..=64 {
                let shipped = shipped_depth_after_n_steps(n, initial);
                assert_eq!(
                    shipped,
                    spec_depth_after_n_steps(n, initial),
                    "PARITY-HAND-1: chain depth diverges after {n} steps from {initial}"
                );
                if u32::from(initial) >= n {
                    assert_eq!(
                        u32::from(shipped),
                        u32::from(initial) - n,
                        "CAP-CHAIN-1: {n} steps from {initial} did not leave initial - n"
                    );
                }
            }
        }
    }

    /// CAP-CHAIN-2/3: the chain depth is monotone decreasing, and every step
    /// with depth remaining strictly reduces it. A step that failed to reduce
    /// would make the delegation budget unbounded.
    #[test]
    fn test_each_step_strictly_reduces_until_exhausted() {
        for initial in 0u8..=u8::MAX {
            let mut previous = initial;
            for step in 1u32..=64 {
                let current = shipped_depth_after_n_steps(step, initial);
                assert!(
                    current <= previous,
                    "CAP-CHAIN-2: depth rose from {previous} to {current} at step {step}"
                );
                if previous > 0 {
                    assert_eq!(
                        current,
                        previous - 1,
                        "CAP-CHAIN-3: step {step} from depth {previous} did not reduce by one"
                    );
                } else {
                    assert_eq!(current, 0, "CAP-CHAIN-4: exhausted depth did not stay zero");
                }
                previous = current;
            }
        }
    }

    /// CAP-CHAIN-5/6: depth is exhausted after exactly `initial` steps, and no
    /// further delegation is possible past that point.
    #[test]
    fn test_exhaustion_is_terminal() {
        for initial in 0u8..=64 {
            let at_exhaustion = shipped_depth_after_n_steps(u32::from(initial), initial);
            assert_eq!(
                at_exhaustion, 0,
                "CAP-CHAIN-5: depth {initial} was not exhausted after {initial} steps"
            );
            assert_eq!(
                attenuated_remaining_depth(at_exhaustion),
                None,
                "CAP-CHAIN-6: a further delegation was permitted after exhaustion"
            );
            assert!(
                !spec_delegation_step_valid(at_exhaustion, 1, 1, 2),
                "CAP-CHAIN-6: the step predicate permits delegation at zero depth"
            );
        }
    }

    /// The step predicate's identity rules are the ones
    /// `verified_capability_identity` binds, so check the composition agrees
    /// with those shipped predicates rather than restating them.
    #[test]
    fn test_step_identity_rules_agree_with_the_shipped_predicates() {
        for depth in [0u8, 1, 2, u8::MAX] {
            for parent_holder in 0u32..3 {
                for child_issuer in 0u32..3 {
                    for child_holder in 0u32..3 {
                        let composed = spec_delegation_step_valid(
                            depth,
                            parent_holder,
                            child_issuer,
                            child_holder,
                        );
                        // Production expresses the same two rules as booleans.
                        let issuer_ok =
                            delegated_child_issuer_valid(true, child_issuer == parent_holder);
                        let holder_ok = delegation_holder_distinct(child_holder == child_issuer);
                        assert_eq!(
                            composed,
                            depth > 0 && issuer_ok && holder_ok,
                            "PARITY-HAND-1: the chain step predicate disagrees with the shipped \
                             identity rules at ({depth}, {parent_holder}, {child_issuer}, \
                             {child_holder})"
                        );
                    }
                }
            }
        }
    }

    /// CAP-CHAIN expiry: a child's expiry never exceeds its parent's, so the
    /// bound holds transitively along a chain.
    #[test]
    fn test_expiry_never_exceeds_the_root_along_a_chain() {
        let roots = [1u64, 2, 100, 1_000, u64::MAX];
        let ttls = [0u64, 1, 50, 10_000, u64::MAX];
        for &root_expiry in &roots {
            for &ttl in &ttls {
                let mut parent = root_expiry;
                for step in 0..8 {
                    let Some(child) = attenuated_expiry_epoch(parent, 0, ttl, u64::MAX) else {
                        break;
                    };
                    assert!(
                        child <= parent,
                        "CAP-CHAIN: step {step} produced a child expiry {child} above its \
                         parent {parent}"
                    );
                    assert!(
                        child <= root_expiry,
                        "CAP-CHAIN: step {step} produced an expiry {child} above the root \
                         {root_expiry}"
                    );
                    parent = child;
                }
            }
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Zero depth admits no step, whatever the identities.
        assert!(!spec_delegation_step_valid(0, 1, 1, 2));
        // The child's issuer must be the parent's holder.
        assert!(!spec_delegation_step_valid(1, 1, 2, 3));
        // Self-delegation is refused.
        assert!(!spec_delegation_step_valid(1, 1, 1, 1));
        // A well-formed step is accepted.
        assert!(spec_delegation_step_valid(1, 1, 1, 2));
        // Depth zero propagates rather than wrapping.
        assert_eq!(spec_depth_after_n_steps(10, 0), 0);
        assert_eq!(spec_depth_after_n_steps(3, 5), 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attenuated_remaining_depth_decrements() {
        assert_eq!(attenuated_remaining_depth(0), None);
        assert_eq!(attenuated_remaining_depth(1), Some(0));
        assert_eq!(attenuated_remaining_depth(5), Some(4));
    }

    #[test]
    fn test_attenuated_expiry_epoch_clamps_to_parent() {
        assert_eq!(
            attenuated_expiry_epoch(1_000, 100, 950, 10_000),
            Some(1_000)
        );
    }

    #[test]
    fn test_attenuated_expiry_epoch_uses_requested_window() {
        assert_eq!(attenuated_expiry_epoch(1_000, 100, 200, 10_000), Some(300));
    }

    #[test]
    fn test_attenuated_expiry_epoch_rejects_expired_parent() {
        assert_eq!(attenuated_expiry_epoch(100, 100, 1, 10_000), None);
        assert_eq!(attenuated_expiry_epoch(100, 101, 1, 10_000), None);
    }

    #[test]
    fn test_attenuated_expiry_epoch_rejects_excessive_ttl() {
        assert_eq!(attenuated_expiry_epoch(1_000, 100, 401, 400), None);
    }

    #[test]
    fn test_attenuated_expiry_epoch_rejects_overflow() {
        assert_eq!(
            attenuated_expiry_epoch(u64::MAX, u64::MAX - 5, 10, 20),
            None
        );
    }
}
