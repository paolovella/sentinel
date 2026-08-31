// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! The restriction gate driven by behavioural sequence analysis.
//!
//! Production counterpart of `formal/verus/verified_sequence_analysis.rs`.
//! The kernel proves that anomaly detection is monotonic, that tracked
//! confidence only rises, that a restriction requires an anomaly at or above a
//! threshold, and that warm-up never suppresses taint. Those properties had no
//! production home: the threshold existed only as a bare `70` at one relay
//! call site whose result was discarded, and the warm-up count existed only as
//! a `SequenceConfig` field. Neither was named, and no gate was built from
//! them.
//!
//! Confidence is `u32` here because that is what `SequenceAnomaly.confidence`
//! and `SequenceTracker::max_confidence()` are. The kernel modelled it as `u8`,
//! which was an arbitrary narrowing rather than a claim about the value; the
//! kernel now matches.

/// Calls that must be observed before anomaly detection activates.
///
/// Warm-up suppresses *detection*, never taint: a tainted source read during
/// warm-up is still recorded and still restricts. That separation is SEQ-4.
pub const WARMUP_CALLS: u32 = 3;

/// Confidence at or above which a detected anomaly restricts the session scope.
///
/// The emitted confidences are 60 (diversity spike), 80, 85 (novel tool after
/// taint) and 90 (privilege escalation), so this threshold admits everything
/// except the diversity spike alone.
pub const RESTRICTION_THRESHOLD: u32 = 70;

/// Distinct new tools permitted after the first taint before flagging.
pub const MAX_NEW_TOOLS: u32 = 2;

/// The highest confidence any detector may emit.
pub const MAX_CONFIDENCE: u32 = 100;

/// Fold a new detection into the session's anomaly state.
///
/// Monotonic: once an anomaly has been seen, later clean calls do not clear it.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn update_anomaly_detected(current: bool, new_detection: bool) -> bool {
    current || new_detection
}

/// Fold a new confidence into the session's tracked confidence.
///
/// Max-tracking: the session is judged by its worst observation, so a later
/// low-confidence call cannot talk the session back down below a restriction.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn update_confidence(current: u32, new_confidence: u32) -> u32 {
    if new_confidence > current {
        new_confidence
    } else {
        current
    }
}

/// Whether the session scope should be restricted.
///
/// Requires both an anomaly and a confidence at or above the threshold — a
/// high number with no detection behind it never restricts.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn should_restrict(anomaly_detected: bool, anomaly_confidence: u32) -> bool {
    anomaly_detected && anomaly_confidence >= RESTRICTION_THRESHOLD
}

/// Whether enough calls have been seen for detection to activate.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn warmup_complete(call_count: u32) -> bool {
    call_count >= WARMUP_CALLS
}

/// Whether taint restricts, given warm-up state.
///
/// SEQ-4: the answer does not depend on `call_count`. Taint fires during
/// warm-up exactly as it does after it. The parameter is present so the
/// independence is visible at the call site rather than assumed.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn is_taint_restricted(taint_active: bool, _call_count: u32) -> bool {
    taint_active
}

/// Whether another distinct tool may be introduced after taint.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn new_tool_budget_available(new_tools_after_taint: u32, max_new_tools: u32) -> bool {
    new_tools_after_taint <= max_new_tools
}

/// Count one more distinct tool seen after taint.
#[inline]
#[must_use]
pub const fn increment_new_tools(current: u32) -> u32 {
    current.saturating_add(1)
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`), kernel
    //! `formal/verus/verified_sequence_analysis.rs`.
    //!
    //! This kernel was the second of the two recorded under `MODEL-SHAPE-1/2`:
    //! it proved properties of a restriction gate production had not built.
    //! The gate now exists in this module and drives the relay, so the specs
    //! have counterparts to compare against.
    //!
    //! Confidence widened from `u8` to `u32` on the kernel side to match
    //! `SequenceAnomaly.confidence`, which is what the gate is fed.

    use super::*;

    /// Transcription of `spec_update_anomaly_detected`.
    fn spec_update_anomaly_detected(current: bool, new_detection: bool) -> bool {
        current || new_detection
    }

    /// Transcription of `spec_update_confidence`.
    fn spec_update_confidence(current: u32, new_confidence: u32) -> u32 {
        if new_confidence > current {
            new_confidence
        } else {
            current
        }
    }

    /// Transcription of `spec_should_restrict`.
    fn spec_should_restrict(anomaly_detected: bool, anomaly_confidence: u32) -> bool {
        anomaly_detected && anomaly_confidence >= RESTRICTION_THRESHOLD
    }

    /// Transcription of `spec_warmup_complete`.
    fn spec_warmup_complete(call_count: u32) -> bool {
        call_count >= WARMUP_CALLS
    }

    /// Transcription of `check_new_tool_budget`.
    fn spec_check_new_tool_budget(new_tools_after_taint: u32, max_new_tools: u32) -> bool {
        new_tools_after_taint <= max_new_tools
    }

    /// SEQ-1, TOTAL over 2².
    #[test]
    fn test_anomaly_update_matches_verus_spec_total_domain() {
        for current in [false, true] {
            for detection in [false, true] {
                assert_eq!(
                    update_anomaly_detected(current, detection),
                    spec_update_anomaly_detected(current, detection),
                    "PARITY-HAND-1: anomaly update disagrees at ({current}, {detection})"
                );
                if current {
                    assert!(
                        update_anomaly_detected(current, detection),
                        "SEQ-1: a detected anomaly was cleared"
                    );
                }
            }
        }
    }

    /// SEQ-2, TOTAL over every confidence pair in range.
    #[test]
    fn test_confidence_update_matches_verus_spec_and_only_rises() {
        let mut checked = 0usize;
        for current in 0..=MAX_CONFIDENCE {
            for new in 0..=MAX_CONFIDENCE {
                let got = update_confidence(current, new);
                assert_eq!(
                    got,
                    spec_update_confidence(current, new),
                    "PARITY-HAND-1: confidence update disagrees at ({current}, {new})"
                );
                assert!(got >= current, "SEQ-2: tracked confidence fell");
                checked += 1;
            }
        }
        assert_eq!(checked, 101 * 101, "enumeration collapsed");
    }

    /// SEQ-3 and SEQ-6, TOTAL over the emitted confidence range.
    #[test]
    fn test_should_restrict_matches_verus_spec_total_domain() {
        for detected in [false, true] {
            for confidence in 0..=MAX_CONFIDENCE {
                let got = should_restrict(detected, confidence);
                assert_eq!(
                    got,
                    spec_should_restrict(detected, confidence),
                    "PARITY-HAND-1: restriction gate disagrees at ({detected}, {confidence})"
                );
                if got {
                    assert!(detected, "SEQ-3: restriction without an anomaly");
                    assert!(
                        confidence >= RESTRICTION_THRESHOLD,
                        "SEQ-3: restriction below the threshold"
                    );
                }
            }
        }
    }

    /// The confidences the detectors actually emit, against the gate.
    /// `lemma_high_confidence_triggers_restriction` names these four.
    #[test]
    fn test_emitted_confidences_land_on_the_expected_side_of_the_threshold() {
        assert!(
            should_restrict(true, 90),
            "privilege escalation must restrict"
        );
        assert!(
            should_restrict(true, 85),
            "novel tool after taint must restrict"
        );
        assert!(should_restrict(true, 80), "read-to-act must restrict");
        assert!(
            !should_restrict(true, 60),
            "a diversity spike alone must not restrict"
        );
        assert!(!should_restrict(false, 100), "no anomaly, no restriction");
    }

    /// SEQ-4: warm-up gates detection, never taint.
    #[test]
    fn test_warmup_matches_verus_spec_and_does_not_suppress_taint() {
        for call_count in 0u32..12 {
            assert_eq!(
                warmup_complete(call_count),
                spec_warmup_complete(call_count),
                "PARITY-HAND-1: warm-up disagrees at {call_count}"
            );
            for taint_active in [false, true] {
                assert_eq!(
                    is_taint_restricted(taint_active, call_count),
                    taint_active,
                    "SEQ-4: taint restriction depended on warm-up at {call_count}"
                );
            }
        }
    }

    /// SEQ-5.
    #[test]
    fn test_new_tool_budget_matches_verus_spec() {
        for new_tools in 0u32..12 {
            for max in 0u32..12 {
                assert_eq!(
                    new_tool_budget_available(new_tools, max),
                    spec_check_new_tool_budget(new_tools, max),
                    "PARITY-HAND-1: new-tool budget disagrees at ({new_tools}, {max})"
                );
            }
        }
    }

    /// `increment_new_tools` must saturate, not wrap. A wrapping counter
    /// resets the budget and defeats the gate.
    #[test]
    fn test_increment_saturates_at_the_ceiling() {
        assert_eq!(increment_new_tools(0), 1);
        assert_eq!(increment_new_tools(u32::MAX - 1), u32::MAX);
        assert_eq!(
            increment_new_tools(u32::MAX),
            u32::MAX,
            "the new-tool counter wrapped"
        );
    }

    /// The constants are the ones the kernel proves against.
    #[test]
    fn test_constants_match_the_kernel() {
        assert_eq!(RESTRICTION_THRESHOLD, 70);
        assert_eq!(WARMUP_CALLS, 3);
        assert_eq!(MAX_NEW_TOOLS, 2);
        assert_eq!(MAX_CONFIDENCE, 100);
    }

    /// The gate drives the shipped `SequenceConfig` defaults.
    #[test]
    fn test_sequence_config_default_uses_the_verified_constants() {
        let config = crate::sequence::SequenceConfig::default();
        assert_eq!(config.warmup_calls, WARMUP_CALLS);
        assert_eq!(config.max_new_tools_after_taint, MAX_NEW_TOOLS);
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        assert!(!spec_should_restrict(true, RESTRICTION_THRESHOLD - 1));
        assert!(spec_should_restrict(true, RESTRICTION_THRESHOLD));
        assert!(!spec_should_restrict(false, MAX_CONFIDENCE));
        assert!(!spec_warmup_complete(WARMUP_CALLS - 1));
        assert!(spec_warmup_complete(WARMUP_CALLS));
        assert_eq!(spec_update_confidence(50, 10), 50);
        assert_eq!(spec_update_confidence(10, 50), 50);
    }
}
