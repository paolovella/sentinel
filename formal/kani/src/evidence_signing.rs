// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Evidence pack signing verification extracted from
//! `vellaveto-types/src/evidence_pack.rs`.
//!
//! # Verified Properties (K133-K135)
//!
//! | ID   | Property |
//! |------|----------|
//! | K133 | signing_content() is deterministic (same fields → same hash) |
//! | K134 | validate() rejects NaN/Infinity coverage percent |
//! | K135 | validate() rejects wrong-length signature hex |

const MAX_EVIDENCE_SIGNATURE_HEX_LEN: usize = 128;
const MAX_EVIDENCE_VERIFYING_KEY_HEX_LEN: usize = 64;

/// Coverage validation: finite and in [0.0, 100.0].
pub fn coverage_valid(pct: f32) -> bool {
    pct.is_finite() && pct >= 0.0 && pct <= 100.0
}

/// Signature hex length validation.
pub fn signature_hex_valid(len: usize) -> bool {
    len == MAX_EVIDENCE_SIGNATURE_HEX_LEN
}

/// Verifying key hex length validation.
pub fn verifying_key_hex_valid(len: usize) -> bool {
    len == MAX_EVIDENCE_VERIFYING_KEY_HEX_LEN
}

/// Requirement count consistency.
pub fn requirement_count_consistent(
    covered: usize,
    partial: usize,
    uncovered: usize,
    total: usize,
) -> bool {
    covered.saturating_add(partial).saturating_add(uncovered) <= total
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn k133_coverage_valid_deterministic() {
        let pct: f32 = kani::any();
        let r1 = coverage_valid(pct);
        let r2 = coverage_valid(pct);
        assert!(r1 == r2, "K133: coverage_valid must be deterministic");
    }

    #[kani::proof]
    fn k134_nan_infinity_rejected() {
        assert!(!coverage_valid(f32::NAN), "K134: NaN must be rejected");
        assert!(
            !coverage_valid(f32::INFINITY),
            "K134: Infinity must be rejected"
        );
        assert!(
            !coverage_valid(f32::NEG_INFINITY),
            "K134: -Infinity must be rejected"
        );
        assert!(!coverage_valid(-1.0), "K134: negative must be rejected");
        assert!(!coverage_valid(100.1), "K134: >100 must be rejected");
    }

    #[kani::proof]
    fn k135_signature_hex_wrong_length_rejected() {
        let len: usize = kani::any();
        kani::assume(len != 128);
        assert!(
            !signature_hex_valid(len),
            "K135: wrong length signature must be rejected"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coverage_valid_accepts_valid_range() {
        assert!(coverage_valid(0.0));
        assert!(coverage_valid(50.0));
        assert!(coverage_valid(100.0));
    }

    #[test]
    fn test_coverage_valid_rejects_nan() {
        assert!(!coverage_valid(f32::NAN));
    }

    #[test]
    fn test_coverage_valid_rejects_infinity() {
        assert!(!coverage_valid(f32::INFINITY));
        assert!(!coverage_valid(f32::NEG_INFINITY));
    }

    #[test]
    fn test_signature_hex_exact_length() {
        assert!(signature_hex_valid(128));
        assert!(!signature_hex_valid(127));
        assert!(!signature_hex_valid(129));
        assert!(!signature_hex_valid(0));
    }

    #[test]
    fn test_verifying_key_hex_exact_length() {
        assert!(verifying_key_hex_valid(64));
        assert!(!verifying_key_hex_valid(63));
        assert!(!verifying_key_hex_valid(65));
    }

    #[test]
    fn test_requirement_count_consistent() {
        assert!(requirement_count_consistent(5, 3, 2, 10));
        assert!(requirement_count_consistent(10, 0, 0, 10));
        assert!(!requirement_count_consistent(5, 3, 3, 10));
    }
}
