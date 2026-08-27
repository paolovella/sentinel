// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Cross-call DLP state tracking (Phase 71).
//!
//! Detects secrets split across multiple tool calls within the same session.
//! Each tracked field maintains an overlap buffer of the previous call's tail,
//! which is prepended to the current call's value before scanning. This catches
//! secrets like `AKIA...` where the first half arrives in call N and the
//! second half in call N+1.
//!
//! # Memory Budget
//!
//! - Each field buffer: up to `OVERLAP_BUFFER_SIZE` bytes (default 150)
//! - Max tracked fields: `MAX_TRACKED_FIELDS` (default 256)
//! - Max total buffer bytes: `MAX_TOTAL_BUFFER_BYTES` (default 38,400)
//!
//! # Fail-Closed Behavior
//!
//! At capacity, new fields are scanned without overlap (per-call DLP still runs).
//! A warning is logged but the scan is not skipped.

use std::collections::{HashMap, VecDeque};

use super::dlp::{self, DlpFinding};
use super::verified_cross_call_dlp;
use super::verified_dlp_core;

/// Default overlap buffer size per field (bytes).
/// Covers the longest known secret prefix (AWS key: 20 chars) plus encoding margin.
pub const DEFAULT_OVERLAP_BUFFER_SIZE: usize = 150;

/// Maximum number of fields tracked simultaneously per session.
pub const MAX_TRACKED_FIELDS: usize = 256;

/// Maximum total buffer bytes across all tracked fields (256 × 150 = 38,400).
pub const MAX_TOTAL_BUFFER_BYTES: usize = MAX_TRACKED_FIELDS * DEFAULT_OVERLAP_BUFFER_SIZE;

/// Cross-call DLP tracker for a single session.
///
/// Maintains overlap buffers keyed by field path (e.g., `"arguments.content"`).
/// Thread-safety: this struct is NOT `Sync` — it is owned by a single session
/// and accessed sequentially within that session's request pipeline.
pub struct CrossCallDlpTracker {
    /// Field path → tail bytes from the previous call.
    buffers: HashMap<String, VecDeque<u8>>,
    /// Total bytes currently stored across all buffers.
    total_bytes: usize,
    /// Configured overlap buffer size per field.
    overlap_size: usize,
    /// Maximum number of fields to track.
    max_fields: usize,
}

impl CrossCallDlpTracker {
    /// Create a new tracker with default settings.
    pub fn new() -> Self {
        Self {
            buffers: HashMap::with_capacity(64),
            total_bytes: 0,
            overlap_size: DEFAULT_OVERLAP_BUFFER_SIZE,
            max_fields: MAX_TRACKED_FIELDS,
        }
    }

    /// Create a tracker with custom overlap size and field limit.
    ///
    /// `overlap_size` is clamped to `[32, 512]`.
    /// `max_fields` is clamped to `[1, 1024]`.
    pub fn with_config(overlap_size: usize, max_fields: usize) -> Self {
        let overlap_size = overlap_size.clamp(32, 512);
        let max_fields = max_fields.clamp(1, 1024);
        Self {
            buffers: HashMap::with_capacity(max_fields.min(64)),
            total_bytes: 0,
            overlap_size,
            max_fields,
        }
    }

    /// Scan a field value with overlap from the previous call.
    ///
    /// 1. Prepends the previous overlap buffer (if any) to `current_value`.
    /// 2. Runs DLP scan on the combined string.
    /// 3. Updates the overlap buffer with the tail of `current_value`.
    /// 4. Returns any DLP findings from the **overlap region** only
    ///    (findings in the non-overlap portion are caught by per-call DLP).
    ///
    /// At field capacity, new fields skip overlap tracking but still return
    /// findings from per-call scanning (handled by the caller).
    pub fn scan_with_overlap(&mut self, field_path: &str, current_value: &str) -> Vec<DlpFinding> {
        // Fast path: empty value — nothing to scan or buffer
        if current_value.is_empty() {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let field_exists = self.buffers.contains_key(field_path);

        // Retrieve previous overlap buffer for this field
        let previous_tail = self
            .buffers
            .get(field_path)
            .map(|buf| buf.iter().copied().collect::<Vec<u8>>());

        // If we have previous overlap, build the combined string and scan
        if let Some(ref tail_bytes) = previous_tail {
            if !tail_bytes.is_empty() {
                // Build combined: previous_tail + current_value
                if let Ok(tail_str) = std::str::from_utf8(tail_bytes) {
                    let combined = format!("{tail_str}{current_value}");
                    let overlap_len = tail_str.len();

                    // Scan the combined string
                    let combined_findings =
                        dlp::scan_text_for_secrets(&combined, &format!("{field_path}(cross-call)"));

                    // Only report findings that span the overlap boundary.
                    // Findings entirely within current_value will be caught
                    // by the per-call DLP scan.
                    for finding in combined_findings {
                        // The finding location contains "(cross-call)" suffix,
                        // so we know it came from the overlap scan.
                        // We include all findings from the combined scan since
                        // the overlap region may contain partial matches that
                        // only become complete with the new data.
                        //
                        // De-duplication with per-call findings happens at the
                        // caller level (same pattern+field = skip).
                        let _ = overlap_len; // used conceptually; all cross-call findings reported
                        findings.push(finding);
                    }
                }
            }
        }

        // SECURITY (R237-MCP-4): Before updating the buffer, check if this is a new field
        // that would exceed capacity. If so, add a synthetic finding so the caller can
        // deny the request rather than silently losing cross-call DLP coverage.
        if verified_cross_call_dlp::should_emit_capacity_exhausted_finding(
            field_exists,
            self.buffers.len(),
            self.max_fields,
        ) {
            findings.push(DlpFinding {
                pattern_name: "cross_call_dlp_capacity_exhausted".to_string(),
                location: format!("{field_path}(capacity-exceeded)"),
            });
        }

        // Update the overlap buffer with the tail of current_value
        self.update_buffer(field_path, current_value, field_exists);

        findings
    }

    /// Update the overlap buffer for a field with the tail of the given value.
    ///
    /// Uses verified_dlp_core functions for buffer arithmetic (D1-D5).
    fn update_buffer(&mut self, field_path: &str, value: &str, field_exists: bool) {
        let value_bytes = value.as_bytes();
        let new_buffer_bytes = value_bytes.len().min(self.overlap_size);
        let max_total_bytes = self.max_fields.saturating_mul(self.overlap_size);

        if !verified_cross_call_dlp::should_update_buffer(
            field_exists,
            self.buffers.len(),
            self.max_fields,
            self.total_bytes,
            new_buffer_bytes,
            max_total_bytes,
        ) {
            tracing::warn!(
                field_path = %field_path,
                tracked_fields = self.buffers.len(),
                max_fields = self.max_fields,
                "Cross-call DLP: field capacity reached, skipping overlap tracking for new field"
            );
            return;
        }

        // D3/D5: Update total bytes using verified core (saturating arithmetic)
        let old_buf_len = self.buffers.get(field_path).map(|b| b.len()).unwrap_or(0);

        // D1/D2: Extract tail at valid UTF-8 boundary using verified core
        let (start, end) = verified_dlp_core::extract_tail(value_bytes, self.overlap_size);
        let tail = &value_bytes[start..end];

        let mut buf = VecDeque::with_capacity(tail.len());
        buf.extend(tail);

        self.total_bytes =
            verified_dlp_core::update_total_bytes(self.total_bytes, old_buf_len, buf.len());
        self.buffers.insert(field_path.to_string(), buf);
    }

    /// Clear all buffers (call on session end).
    pub fn clear_all(&mut self) {
        self.buffers.clear();
        self.total_bytes = 0;
    }

    /// Number of fields currently tracked.
    pub fn tracked_fields(&self) -> usize {
        self.buffers.len()
    }

    /// Total bytes stored across all buffers.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

impl Default for CrossCallDlpTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`), kernel
    //! `formal/verus/verified_cross_call_split.rs`.
    //!
    //! **Property discharge.** The kernel's lemmas are about *coverage*, not
    //! about an algorithm this module equals: combined length is the sum,
    //! the tail survives as a prefix, the current value survives as a suffix,
    //! and any byte range spanning the junction is a substring of the combined
    //! string. Together those are the security claim — a secret split across
    //! two calls appears whole in what gets scanned.
    //!
    //! One thing the kernel does **not** require: that findings be filtered to
    //! those spanning the junction. `spec_spans_junction` appears only as a
    //! *hypothesis* of `lemma_junction_range_is_substring`, never as an
    //! obligation. Production reports every finding from the combined scan and
    //! says so at the `let _ = overlap_len` line — a superset, which is the
    //! safe direction for a detector. That is a deliberate difference, not
    //! drift.

    use super::*;

    /// Transcription of `spec_combined`.
    fn spec_combined(tail: &[u8], current: &[u8]) -> Vec<u8> {
        let mut out = tail.to_vec();
        out.extend_from_slice(current);
        out
    }

    /// Transcription of `spec_spans_junction`.
    fn spec_spans_junction(start: usize, len: usize, tail_len: usize, combined_len: usize) -> bool {
        start < tail_len && start + len > tail_len && start + len <= combined_len
    }

    /// Transcription of `spec_is_substring_at`.
    fn spec_is_substring_at(s: &[u8], t: &[u8], pos: usize) -> bool {
        pos + s.len() <= t.len() && t[pos..pos + s.len()] == *s
    }

    /// The concatenation production actually performs, in
    /// `scan_with_overlap`: `format!("{tail_str}{current_value}")`.
    fn shipped_combined(tail: &str, current: &str) -> String {
        format!("{tail}{current}")
    }

    const PIECES: [&str; 6] = ["", "a", "ab", "AKIA", "secret-", "0123456789"];

    /// CC-SPLIT-1: combined length is the sum of the parts.
    #[test]
    fn test_combined_length_matches_the_lemma() {
        for tail in PIECES {
            for current in PIECES {
                let shipped = shipped_combined(tail, current);
                assert_eq!(
                    shipped.len(),
                    tail.len() + current.len(),
                    "PARITY-HAND-1 (CC-SPLIT-1): combined length is not the sum for \
                     {tail:?} + {current:?}"
                );
                assert_eq!(
                    shipped.as_bytes(),
                    spec_combined(tail.as_bytes(), current.as_bytes()).as_slice(),
                    "PARITY-HAND-1: shipped concatenation disagrees with spec_combined"
                );
            }
        }
    }

    /// CC-SPLIT-2/3: the tail survives as a prefix, the current value as a
    /// suffix. If either failed, a secret straddling the boundary would be
    /// corrupted before the scanner ever saw it.
    #[test]
    fn test_both_parts_survive_the_join() {
        for tail in PIECES {
            for current in PIECES {
                let combined = shipped_combined(tail, current);
                assert_eq!(
                    &combined.as_bytes()[..tail.len()],
                    tail.as_bytes(),
                    "PARITY-HAND-1 (CC-SPLIT-2): tail is not the prefix of combined"
                );
                assert_eq!(
                    &combined.as_bytes()[tail.len()..],
                    current.as_bytes(),
                    "PARITY-HAND-1 (CC-SPLIT-3): current is not the suffix of combined"
                );
            }
        }
    }

    /// CC-SPLIT-4: any range spanning the junction is a substring of combined.
    /// This is the lemma that makes cross-call detection sound.
    #[test]
    fn test_junction_spanning_ranges_are_substrings_of_combined() {
        let mut checked = 0usize;
        for tail in PIECES {
            for current in PIECES {
                let combined = shipped_combined(tail, current);
                let (tail_len, combined_len) = (tail.len(), combined.len());
                for start in 0..=combined_len {
                    for len in 0..=(combined_len - start) {
                        if !spec_spans_junction(start, len, tail_len, combined_len) {
                            continue;
                        }
                        let slice = &combined.as_bytes()[start..start + len];
                        assert!(
                            spec_is_substring_at(slice, combined.as_bytes(), start),
                            "PARITY-HAND-1 (CC-SPLIT-4): a junction-spanning range \
                             [{start}, {len}) is not a substring of combined for \
                             {tail:?} + {current:?}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked > 50, "junction enumeration collapsed to {checked}");
    }

    /// The security claim end to end: a secret split across two calls is found
    /// by the overlap scan, and is *not* found by scanning either half alone.
    #[test]
    fn test_split_secret_is_detected_only_across_the_junction() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let (first, second) = secret.split_at(9);

        let mut tracker = CrossCallDlpTracker::new();
        let first_findings = tracker.scan_with_overlap("field", first);
        assert!(
            first_findings.is_empty(),
            "PARITY-HAND-1: the first half alone should not trip the scanner"
        );

        let second_findings = tracker.scan_with_overlap("field", second);
        assert!(
            !second_findings.is_empty(),
            "PARITY-HAND-1 (CC-SPLIT-4): a secret split across two calls was not detected \
             by the overlap scan — the coverage the kernel proves did not reach production"
        );
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // A range entirely inside either half does not span the junction.
        assert!(!spec_spans_junction(0, 2, 4, 10));
        assert!(!spec_spans_junction(5, 3, 4, 10));
        // One that crosses it does.
        assert!(spec_spans_junction(3, 3, 4, 10));
        // A range running past the end is not a junction range.
        assert!(!spec_spans_junction(3, 20, 4, 10));
        // Substring check is position-sensitive.
        assert!(spec_is_substring_at(b"bc", b"abcd", 1));
        assert!(!spec_is_substring_at(b"bc", b"abcd", 2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_aws_key_detected() {
        // AWS access key split across two calls
        let mut tracker = CrossCallDlpTracker::new();
        let part1 = "Here is some data: AKIA";
        let part2 = "IOSFODNN7EXAMPLE and more text";

        // First call: stores overlap buffer
        let findings1 = tracker.scan_with_overlap("arguments.content", part1);
        // May or may not find partial — the key is incomplete

        // Second call: overlap should combine to form full key
        let findings2 = tracker.scan_with_overlap("arguments.content", part2);

        // The combined string "...AKIA" + "IOSFODNN7EXAMPLE..." should trigger AWS key detection
        // Either findings1 or findings2 should detect it, or the per-call scan catches it
        let all_findings: Vec<_> = findings1.into_iter().chain(findings2).collect();
        let has_aws = all_findings
            .iter()
            .any(|f| f.pattern_name.contains("aws") || f.location.contains("cross-call"));
        // The cross-call scan combines the tail of part1 with part2,
        // forming "...AKIA" + "IOSFODNN7EXAMPLE..." which matches the AWS pattern
        assert!(
            has_aws,
            "Expected AWS key detection from cross-call overlap, got: {all_findings:?}"
        );
    }

    #[test]
    fn test_split_jwt_detected() {
        // JWT split across two calls: header.payload in call1, .signature in call2
        let mut tracker = CrossCallDlpTracker::new();
        let jwt_header_payload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        let jwt_signature = ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let _ = tracker.scan_with_overlap("result.text", jwt_header_payload);
        let findings2 = tracker.scan_with_overlap("result.text", jwt_signature);

        // The combined string should trigger JWT detection
        let has_jwt = findings2
            .iter()
            .any(|f| f.pattern_name.contains("jwt") || f.location.contains("cross-call"));
        assert!(
            has_jwt,
            "Expected JWT detection from cross-call overlap, got: {findings2:?}"
        );
    }

    #[test]
    fn test_no_false_positive_normal_text() {
        let mut tracker = CrossCallDlpTracker::new();
        let text1 = "Hello, this is a normal message about the weather today.";
        let text2 = "The temperature is 72 degrees and sunny.";

        let findings1 = tracker.scan_with_overlap("args.msg", text1);
        let findings2 = tracker.scan_with_overlap("args.msg", text2);

        assert!(findings1.is_empty(), "No secrets in normal text");
        assert!(findings2.is_empty(), "No secrets in normal text");
    }

    #[test]
    fn test_buffer_capacity_enforcement() {
        let mut tracker = CrossCallDlpTracker::with_config(150, 4);

        // Fill to capacity
        for i in 0..4 {
            tracker.scan_with_overlap(&format!("field_{i}"), "some value");
        }
        assert_eq!(tracker.tracked_fields(), 4);

        // Fifth field should be rejected (no overlap tracking)
        tracker.scan_with_overlap("field_overflow", "some value");
        assert_eq!(
            tracker.tracked_fields(),
            4,
            "Should not track beyond max_fields"
        );
    }

    #[test]
    fn test_buffer_cleanup_on_session_end() {
        let mut tracker = CrossCallDlpTracker::new();
        tracker.scan_with_overlap("field_a", "some data");
        tracker.scan_with_overlap("field_b", "other data");
        assert!(tracker.tracked_fields() > 0);
        assert!(tracker.total_bytes() > 0);

        tracker.clear_all();
        assert_eq!(tracker.tracked_fields(), 0);
        assert_eq!(tracker.total_bytes(), 0);
    }

    #[test]
    fn test_overlap_size_bounds() {
        // Below minimum: clamped to 32
        let tracker = CrossCallDlpTracker::with_config(10, 256);
        assert_eq!(tracker.overlap_size, 32);

        // Above maximum: clamped to 512
        let tracker = CrossCallDlpTracker::with_config(1000, 256);
        assert_eq!(tracker.overlap_size, 512);

        // Within bounds: used as-is
        let tracker = CrossCallDlpTracker::with_config(200, 256);
        assert_eq!(tracker.overlap_size, 200);
    }

    #[test]
    fn test_base64_encoded_split() {
        // A base64-encoded secret split at the boundary
        let mut tracker = CrossCallDlpTracker::new();
        // Simulating a private key header split
        let part1 = "data before -----BEGIN RSA PRIVATE";
        let part2 = " KEY-----\nMIIEowIBAAKCAQEA";

        let _ = tracker.scan_with_overlap("content", part1);
        let findings2 = tracker.scan_with_overlap("content", part2);

        let has_key = findings2
            .iter()
            .any(|f| f.pattern_name.contains("private_key") || f.location.contains("cross-call"));
        assert!(
            has_key,
            "Expected private key detection from cross-call overlap, got: {findings2:?}"
        );
    }

    #[test]
    fn test_field_eviction_at_capacity() {
        // When at capacity, existing fields can still be updated
        let mut tracker = CrossCallDlpTracker::with_config(150, 2);

        tracker.scan_with_overlap("field_a", "value_a");
        tracker.scan_with_overlap("field_b", "value_b");
        assert_eq!(tracker.tracked_fields(), 2);

        // Existing field update should work
        tracker.scan_with_overlap("field_a", "updated_a");
        assert_eq!(tracker.tracked_fields(), 2);

        // New field should be rejected
        tracker.scan_with_overlap("field_c", "value_c");
        assert_eq!(tracker.tracked_fields(), 2);
    }

    #[test]
    fn test_config_cross_call_disabled() {
        // When tracker is not created (disabled at config level),
        // there is no cross-call scanning. This test verifies the
        // tracker itself works when created with minimal config.
        let mut tracker = CrossCallDlpTracker::with_config(32, 1);
        let findings = tracker.scan_with_overlap("field", "safe text");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_config_validation_bounds() {
        // max_fields clamped
        let tracker = CrossCallDlpTracker::with_config(150, 0);
        assert_eq!(tracker.max_fields, 1);

        let tracker = CrossCallDlpTracker::with_config(150, 2000);
        assert_eq!(tracker.max_fields, 1024);
    }

    #[test]
    fn test_empty_value_no_panic() {
        let mut tracker = CrossCallDlpTracker::new();
        let findings = tracker.scan_with_overlap("field", "");
        assert!(findings.is_empty());
        assert_eq!(tracker.tracked_fields(), 0);
    }

    #[test]
    fn test_multibyte_utf8_boundary() {
        // Ensure overlap buffer doesn't split multi-byte UTF-8 characters
        let mut tracker = CrossCallDlpTracker::with_config(32, 256);
        // String with multibyte chars at the tail
        let text = "Hello world! 日本語テスト";
        tracker.scan_with_overlap("field", text);

        // Should not panic and buffer should be valid UTF-8
        if let Some(buf) = tracker.buffers.get("field") {
            let bytes: Vec<u8> = buf.iter().copied().collect();
            assert!(
                std::str::from_utf8(&bytes).is_ok(),
                "Buffer must contain valid UTF-8"
            );
        }
    }

    #[test]
    fn test_r237_mcp4_capacity_exhaustion_produces_finding() {
        // SECURITY (R237-MCP-4): When field capacity is reached, new fields
        // must produce a synthetic DlpFinding to force a deny.
        let max_fields = 3;
        let mut tracker = CrossCallDlpTracker::with_config(32, max_fields);

        // Fill to capacity
        for i in 0..max_fields {
            let findings = tracker.scan_with_overlap(&format!("field-{i}"), "benign data");
            assert!(findings.is_empty());
        }

        // Next new field should produce a capacity-exhausted finding
        let findings = tracker.scan_with_overlap("overflow-field", "more data");
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "cross_call_dlp_capacity_exhausted"),
            "Expected capacity exhaustion finding, got: {findings:?}"
        );
    }

    #[test]
    fn test_r237_mcp4_existing_field_at_capacity_no_finding() {
        // An existing tracked field should NOT produce a capacity finding.
        let max_fields = 2;
        let mut tracker = CrossCallDlpTracker::with_config(32, max_fields);

        tracker.scan_with_overlap("field-a", "data1");
        tracker.scan_with_overlap("field-b", "data2");

        // Re-scanning an existing field should not trigger capacity alert
        let findings = tracker.scan_with_overlap("field-a", "data3");
        assert!(
            !findings
                .iter()
                .any(|f| f.pattern_name == "cross_call_dlp_capacity_exhausted"),
            "Existing field should not trigger capacity exhaustion"
        );
    }
}
