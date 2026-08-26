// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Fixed-point entropy decision helpers.
//!
//! These helpers are the security decision boundary for collusion entropy
//! alerts. Raw `f64` entropy values remain available for telemetry and
//! evidence, but alert gating uses millibit scores to keep the comparison
//! semantics centralized and deterministic.

pub(crate) use crate::verified_entropy_gate::{
    entropy_alert_severity, is_high_entropy_millibits, EntropyAlertLevel,
};

pub(crate) use crate::verified_entropy_fixed_point::{
    entropy_observation_millibits, entropy_threshold_millibits,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verified_entropy_gate::{entropy_alert_level, high_severity_entropy_threshold};

    #[test]
    fn test_entropy_threshold_millibits_rounds_down() {
        assert_eq!(entropy_threshold_millibits(6.5), 6500);
        assert_eq!(entropy_threshold_millibits(6.9999), 6999);
    }

    #[test]
    fn test_entropy_observation_millibits_rounds_up() {
        assert_eq!(entropy_observation_millibits(6.5), 6500);
        assert_eq!(entropy_observation_millibits(6.4991), 6500);
    }

    #[test]
    fn test_is_high_entropy_millibits_uses_fixed_point_boundary() {
        let threshold = entropy_threshold_millibits(6.5);
        assert!(is_high_entropy_millibits(
            entropy_observation_millibits(6.5),
            threshold,
        ));
        assert!(!is_high_entropy_millibits(
            entropy_observation_millibits(6.498),
            threshold,
        ));
    }

    #[test]
    fn test_entropy_alert_helpers_delegate_to_verified_kernel() {
        assert_eq!(high_severity_entropy_threshold(3), 6);
        assert_eq!(
            entropy_alert_severity(3, 3),
            Some(EntropyAlertLevel::Medium)
        );
        assert_eq!(entropy_alert_level(6, 3), EntropyAlertLevel::High);
    }
}
