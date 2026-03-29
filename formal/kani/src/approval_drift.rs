// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Approval lineage drift verification extracted from
//! `vellaveto-approval/src/lib.rs:330-360` and
//! `vellaveto-mcp/src/proxy/bridge/relay.rs:2941-3014`.
//!
//! # Verified Properties (K140)
//!
//! | ID   | Property |
//! |------|----------|
//! | K140 | Trust downgrade → drift detected; no downgrade → no drift (from trust) |

/// Trust downgrade detection: current rank < approval rank means drift.
pub fn trust_downgraded(approval_rank: u32, current_rank: u32) -> bool {
    current_rank < approval_rank
}

/// Taint accumulation detection: more taint now than at approval time.
pub fn taint_accumulated(approval_taint: usize, current_taint: usize) -> bool {
    current_taint > approval_taint
}

/// Combined drift detection.
pub fn drift_detected(
    trust_down: bool,
    taint_up: bool,
    store_error: bool,
) -> bool {
    trust_down || taint_up || store_error
}

/// Fail-closed decision: drift_detected → Block (never Forward).
pub fn decision_is_block(drift: bool) -> bool {
    drift
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn k140_trust_downgrade_detected() {
        let approval_rank: u32 = kani::any();
        let current_rank: u32 = kani::any();
        kani::assume(current_rank < approval_rank);
        assert!(
            trust_downgraded(approval_rank, current_rank),
            "K140: trust downgrade must be detected"
        );
    }

    #[kani::proof]
    fn k140_no_downgrade_no_drift_from_trust() {
        let approval_rank: u32 = kani::any();
        let current_rank: u32 = kani::any();
        kani::assume(current_rank >= approval_rank);
        assert!(
            !trust_downgraded(approval_rank, current_rank),
            "K140: no downgrade must not flag trust drift"
        );
    }

    #[kani::proof]
    fn k140_store_error_implies_drift() {
        let store_error = true;
        assert!(
            drift_detected(false, false, store_error),
            "K140: store error must set drift_detected (fail-closed)"
        );
    }

    #[kani::proof]
    fn k140_drift_implies_block() {
        let trust_down: bool = kani::any();
        let taint_up: bool = kani::any();
        let store_error: bool = kani::any();
        kani::assume(trust_down || taint_up || store_error);
        let drift = drift_detected(trust_down, taint_up, store_error);
        assert!(
            decision_is_block(drift),
            "K140: drift detected must produce Block decision"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_downgrade_detected() {
        assert!(trust_downgraded(5, 3)); // rank 3 < rank 5 → downgrade
        assert!(!trust_downgraded(3, 5)); // rank 5 >= rank 3 → no downgrade
        assert!(!trust_downgraded(5, 5)); // equal → no downgrade
    }

    #[test]
    fn test_taint_accumulated() {
        assert!(taint_accumulated(2, 5)); // 5 > 2 → taint grew
        assert!(!taint_accumulated(5, 2)); // 2 <= 5 → no growth
        assert!(!taint_accumulated(3, 3)); // equal → no growth
    }

    #[test]
    fn test_drift_detected_any_cause() {
        assert!(drift_detected(true, false, false)); // trust down
        assert!(drift_detected(false, true, false)); // taint up
        assert!(drift_detected(false, false, true)); // store error
        assert!(!drift_detected(false, false, false)); // none
    }

    #[test]
    fn test_decision_is_block_when_drift() {
        assert!(decision_is_block(true));
        assert!(!decision_is_block(false));
    }
}
