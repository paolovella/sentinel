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
