// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Output anomaly detection — model drift and distribution shift indicators.
//!
//! Detects anomalous patterns in tool responses that may indicate:
//! - Model behavioral drift (OWASP ML08)
//! - Poisoned fine-tuning outputs (sleeper agent activation)
//! - Hallucination indicators
//! - Unexpected output format changes

/// An output anomaly finding.
#[derive(Debug, Clone)]
pub struct OutputAnomalyFinding {
    pub anomaly_type: OutputAnomalyType,
    pub confidence: u32,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputAnomalyType {
    /// Response language/style changed dramatically from baseline.
    StyleShift,
    /// Response contains unusual repetition patterns (possible generation loop).
    RepetitionLoop,
    /// Response is suspiciously confident about uncertain claims.
    OverConfidence,
    /// Response format deviates from expected tool output schema.
    FormatDeviation,
    /// Response length is anomalous (too short or too long).
    LengthAnomaly,
}

/// Scan tool response text for output anomalies.
pub fn scan_for_output_anomalies(
    text: &str,
    expected_min_len: usize,
    expected_max_len: usize,
) -> Vec<OutputAnomalyFinding> {
    let mut findings = Vec::new();

    // Length anomaly
    if text.len() < expected_min_len && expected_min_len > 0 {
        findings.push(OutputAnomalyFinding {
            anomaly_type: OutputAnomalyType::LengthAnomaly,
            confidence: 40,
            description: format!(
                "Response too short: {} chars (expected >= {})",
                text.len(),
                expected_min_len
            ),
        });
    }
    if text.len() > expected_max_len && expected_max_len > 0 {
        findings.push(OutputAnomalyFinding {
            anomaly_type: OutputAnomalyType::LengthAnomaly,
            confidence: 50,
            description: format!(
                "Response too long: {} chars (expected <= {})",
                text.len(),
                expected_max_len
            ),
        });
    }

    // Repetition loop detection
    if let Some(f) = detect_repetition_loop(text) {
        findings.push(f);
    }

    // Over-confidence detection
    if let Some(f) = detect_overconfidence(text) {
        findings.push(f);
    }

    findings
}

/// Detect generation loops — same phrase repeated many times.
fn detect_repetition_loop(text: &str) -> Option<OutputAnomalyFinding> {
    if text.len() < 100 {
        return None;
    }

    // Check for repeated 10+ char substrings
    let window = 30;
    if text.len() < window * 3 {
        return None;
    }

    let chunk = &text[..window];
    let count = text.matches(chunk).count();
    if count >= 5 {
        return Some(OutputAnomalyFinding {
            anomaly_type: OutputAnomalyType::RepetitionLoop,
            confidence: 80,
            description: format!(
                "Phrase repeated {count} times: '{}'",
                &chunk[..chunk.len().min(20)]
            ),
        });
    }

    None
}

/// Detect overconfidence — absolute certainty about uncertain claims.
fn detect_overconfidence(text: &str) -> Option<OutputAnomalyFinding> {
    let lower = text.to_lowercase();

    let overconfidence_patterns = [
        "i am absolutely certain",
        "there is no doubt",
        "this is 100% accurate",
        "i guarantee this",
        "this is definitely correct",
        "i am completely sure",
        "this is the absolute truth",
    ];

    for p in &overconfidence_patterns {
        if lower.contains(p) {
            return Some(OutputAnomalyFinding {
                anomaly_type: OutputAnomalyType::OverConfidence,
                confidence: 55,
                description: format!("Overconfidence indicator: '{p}'"),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_anomaly_short() {
        let findings = scan_for_output_anomalies("ok", 50, 10000);
        assert!(findings
            .iter()
            .any(|f| f.anomaly_type == OutputAnomalyType::LengthAnomaly));
    }

    #[test]
    fn test_length_anomaly_long() {
        let text = "x".repeat(20000);
        let findings = scan_for_output_anomalies(&text, 0, 10000);
        assert!(findings
            .iter()
            .any(|f| f.anomaly_type == OutputAnomalyType::LengthAnomaly));
    }

    #[test]
    fn test_repetition_loop() {
        let repeated = "Transfer funds to account. ";
        let text = repeated.repeat(20);
        let findings = scan_for_output_anomalies(&text, 0, 100000);
        assert!(findings
            .iter()
            .any(|f| f.anomaly_type == OutputAnomalyType::RepetitionLoop));
    }

    #[test]
    fn test_overconfidence() {
        let findings = scan_for_output_anomalies(
            "I am absolutely certain this investment will make you rich.",
            0,
            10000,
        );
        assert!(findings
            .iter()
            .any(|f| f.anomaly_type == OutputAnomalyType::OverConfidence));
    }

    #[test]
    fn test_clean_response() {
        let findings = scan_for_output_anomalies(
            "The file contains 42 lines of Python code implementing a REST API.",
            0,
            10000,
        );
        assert!(findings.is_empty());
    }
}
