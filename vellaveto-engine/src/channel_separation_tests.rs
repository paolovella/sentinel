// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Phase 6.4A: Channel separation test matrix.
//!
//! Tests the engine-level components: contagion source tainting, sequence
//! analysis, and trust lattice flow checks. Config-level tests (source trust
//! resolution, intent scope, sink classification) are in vellaveto-config.

#[cfg(test)]
mod tests {
    use crate::contagion::{ContagionMode, ContagionTaintType, ContagionTracker};
    use crate::sequence::{AnomalyAction, AnomalyType, SequenceConfig, SequenceTracker};
    use vellaveto_types::provenance::{check_flow_admissibility, FlowVerdict, SinkClass};
    use vellaveto_types::TrustTier;

    /// Scenario 1: Source-class taint blocks privileged sink.
    #[test]
    fn test_source_taint_blocks_write_after_untrusted_fetch() {
        let mut contagion = ContagionTracker::new(ContagionMode::SessionPersistent);
        // Untrusted source auto-taints
        contagion.record_source_response("fetch_url", TrustTier::Untrusted);
        // FilesystemWrite requires Medium — Untrusted < Medium → blocked
        assert!(contagion.should_block_privileged_sink(SinkClass::FilesystemWrite));
        // Flow lattice confirms
        let v = check_flow_admissibility(
            contagion.effective_trust_floor(),
            SinkClass::FilesystemWrite,
            false,
            1,
        );
        assert!(matches!(
            v,
            FlowVerdict::Denied { .. } | FlowVerdict::Gated { .. }
        ));
    }

    /// Scenario 2: Verified source does NOT taint.
    #[test]
    fn test_verified_source_no_taint() {
        let mut contagion = ContagionTracker::new(ContagionMode::SessionPersistent);
        contagion.record_source_response("internal_api", TrustTier::Verified);
        assert!(!contagion.was_ever_tainted());
        assert!(!contagion.should_block_privileged_sink(SinkClass::CodeExecution));
    }

    /// Scenario 3: Unknown source auto-taints with Low floor.
    #[test]
    fn test_unknown_source_taints_with_low_floor() {
        let mut contagion = ContagionTracker::new(ContagionMode::SessionPersistent);
        contagion.record_source_response("some_tool", TrustTier::Unknown);
        assert!(contagion.was_ever_tainted());
        assert_eq!(contagion.effective_trust_floor(), TrustTier::Low);
        // NetworkEgress requires Medium — Low < Medium → blocked
        assert!(contagion.should_block_privileged_sink(SinkClass::NetworkEgress));
    }

    /// Scenario 4: Detection-based taint stacks with source-class taint.
    #[test]
    fn test_detection_and_source_taint_stack() {
        let mut contagion = ContagionTracker::new(ContagionMode::SessionPersistent);
        // Source taint: Untrusted floor
        contagion.record_source_response("fetch_url", TrustTier::Untrusted);
        // Detection taint: Quarantined floor (stricter)
        contagion.record_taint("fetch_url", ContagionTaintType::InjectionDetected);
        // Effective floor is the strictest = Quarantined
        assert_eq!(contagion.effective_trust_floor(), TrustTier::Quarantined);
    }

    /// Scenario 5: Sequence detector catches read→exfil after source taint.
    #[test]
    fn test_sequence_read_exfil_with_source_taint() {
        let mut seq = SequenceTracker::new(SequenceConfig {
            warmup_calls: 2,
            anomaly_action: AnomalyAction::Block,
            ..SequenceConfig::default()
        });
        seq.record_and_analyze("warmup", SinkClass::ReadOnly, false, 100);
        seq.record_and_analyze("fetch_url", SinkClass::ReadOnly, true, 1000);
        let anomalies = seq.record_and_analyze("http_post", SinkClass::NetworkEgress, false, 2000);
        assert!(anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::ReadThenExfil));
    }

    /// Scenario 6: Privilege escalation after taint caught by sequence.
    #[test]
    fn test_sequence_privilege_escalation_after_source_taint() {
        let mut seq = SequenceTracker::new(SequenceConfig {
            warmup_calls: 2,
            anomaly_action: AnomalyAction::Block,
            ..SequenceConfig::default()
        });
        seq.record_and_analyze("list_files", SinkClass::ReadOnly, false, 100);
        seq.record_and_analyze("fetch_url", SinkClass::ReadOnly, true, 1000);
        let anomalies =
            seq.record_and_analyze("execute_cmd", SinkClass::CodeExecution, false, 2000);
        assert!(anomalies.iter().any(|a| {
            a.anomaly_type == AnomalyType::PrivilegeEscalationAfterTaint
                || a.anomaly_type == AnomalyType::NovelToolAfterUntrustedContent
        }));
    }

    /// Scenario 7: Clean session with no untrusted sources — nothing fires.
    #[test]
    fn test_clean_session_no_restrictions() {
        let mut contagion = ContagionTracker::new(ContagionMode::SessionPersistent);
        let mut seq = SequenceTracker::new(SequenceConfig::default());

        // Only verified sources
        contagion.record_source_response("internal_api", TrustTier::Verified);
        contagion.record_source_response("internal_db", TrustTier::High);

        assert!(!contagion.was_ever_tainted());
        assert!(!contagion.should_block_privileged_sink(SinkClass::PolicyMutation));

        let anomalies = seq.record_and_analyze("any_tool", SinkClass::CodeExecution, false, 1000);
        assert!(anomalies.is_empty());
    }

    /// Scenario 8: Three-layer composition — source taint + flow lattice + sequence.
    #[test]
    fn test_three_layer_composition() {
        let mut contagion = ContagionTracker::new(ContagionMode::SessionPersistent);
        let mut seq = SequenceTracker::new(SequenceConfig {
            warmup_calls: 1,
            anomaly_action: AnomalyAction::Block,
            ..SequenceConfig::default()
        });

        // Layer 1: Source-class taint fires
        contagion.record_source_response("fetch_url", TrustTier::Untrusted);
        assert!(contagion.was_ever_tainted());

        // Layer 2: Flow lattice blocks privileged sink
        let floor = contagion.effective_trust_floor();
        let flow = check_flow_admissibility(floor, SinkClass::CodeExecution, false, 1);
        assert!(matches!(flow, FlowVerdict::Denied { .. }));

        // Layer 3: Sequence analysis also catches it
        seq.record_and_analyze("fetch_url", SinkClass::ReadOnly, true, 100);
        let anomalies = seq.record_and_analyze("execute_cmd", SinkClass::CodeExecution, false, 500);
        assert!(anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::PrivilegeEscalationAfterTaint));

        // All three layers independently block the same attack
    }
}
