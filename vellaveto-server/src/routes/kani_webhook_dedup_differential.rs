// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Differential binding for `PARITY-HAND-2` — webhook idempotency.
//!
//! `formal/kani/src/webhook_dedup.rs` reduces `WebhookDedup::check_or_insert`
//! to three boolean predicates and proves K138 (a second call with the same ID
//! returns false) and K139 (empty, oversized and dangerous IDs are rejected).
//!
//! What rides on it: this is billing webhook replay protection. A duplicate
//! that reads as first-occurrence is a re-processed payment event; a malformed
//! ID that reads as valid is an unvalidated key in the dedup map. Production
//! treats malformed IDs as duplicates precisely so they are never processed —
//! fail-closed — and the model has to agree about that or K139 describes a
//! different rejection rule than the one running.

#[cfg(test)]
// Suppressed rather than satisfied: linting the extraction would edit the copy
// the Kani proofs run against.
#[allow(clippy::manual_range_contains, dead_code, unused_imports)]
mod extracted {
    include!(concat!(
        env!("OUT_DIR"),
        "/kani_webhook_dedup_extraction.rs"
    ));
}

#[cfg(test)]
mod kani_parity_differential_webhook_dedup {
    use super::extracted;
    use crate::routes::billing::WebhookDedup;
    use std::time::Duration;

    /// Long TTL: every repeat within a test is "within TTL", which is the
    /// window K138 is about.
    fn tracker() -> WebhookDedup {
        WebhookDedup::new(Duration::from_secs(3600))
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/webhook_dedup.rs was not found, so this binding \
             compared nothing"
        );
    }

    /// The model's length bound must be production's, not merely equal to
    /// another copy of the same literal. Pinned on both sides so raising one
    /// cannot move both at once.
    #[test]
    fn test_length_bound_matches_production() {
        assert!(
            extracted::event_id_valid(512, false, false),
            "the model rejects a 512-byte id, which production accepts"
        );
        assert!(
            !extracted::event_id_valid(513, false, false),
            "the model accepts a 513-byte id, which production rejects"
        );
        // Production's bound, exercised through the real function.
        let dedup = tracker();
        assert!(dedup.check_or_insert(&"a".repeat(512)));
        assert!(!dedup.check_or_insert(&"b".repeat(513)));
    }

    /// K139 and the whole validation predicate, over every id shape production
    /// distinguishes, on a fresh tracker so `already_seen` is false.
    #[test]
    fn test_validation_matches_production() {
        let dangerous = "evt\u{0000}id";
        let cases: Vec<(String, &str)> = vec![
            (String::new(), "empty"),
            ("e".to_string(), "single char"),
            ("evt_normal_id".to_string(), "ordinary"),
            ("a".repeat(512), "at the length bound"),
            ("a".repeat(513), "one over the bound"),
            ("a".repeat(4096), "far over the bound"),
            (dangerous.to_string(), "embedded NUL"),
            ("evt\nid".to_string(), "newline"),
            ("evt\u{202e}id".to_string(), "bidi override"),
        ];

        for (id, label) in &cases {
            let dedup = tracker();
            let production_first = dedup.check_or_insert(id);

            let id_valid = extracted::event_id_valid(
                id.len(),
                id.is_empty(),
                vellaveto_types::has_dangerous_chars(id),
            );
            let model_first = extracted::check_or_insert_result(id_valid, false, false);

            assert_eq!(
                production_first, model_first,
                "PARITY-HAND-2: production and the Kani model disagree on the first \
                 occurrence of a {label} id (production={production_first}, \
                 model={model_first}) — K139 describes a different rejection rule \
                 than the one running"
            );
        }
        assert_eq!(cases.len(), 9, "case list shrank; recount before trusting");
    }

    /// K138: a valid id seen twice within the TTL is a duplicate the second
    /// time, in both.
    #[test]
    fn test_duplicate_detection_matches_production() {
        for id in ["evt_1", "evt_two", &"c".repeat(512)] {
            let dedup = tracker();
            let first = dedup.check_or_insert(id);
            let second = dedup.check_or_insert(id);

            assert_eq!(
                first,
                extracted::check_or_insert_result(true, false, false),
                "first occurrence of {id:?} disagrees"
            );
            assert_eq!(
                second,
                extracted::check_or_insert_result(true, true, true),
                "K138: second occurrence of {id:?} disagrees — a replayed billing \
                 webhook would be processed twice"
            );
            assert!(first, "a fresh valid id must be a first occurrence");
            assert!(!second, "K138: the same id twice must be a duplicate");
        }
    }

    /// A malformed id is rejected on *every* call, never becoming a
    /// first-occurrence, and is not inserted into the map either.
    #[test]
    fn test_malformed_ids_are_rejected_every_time() {
        let dedup = tracker();
        for _ in 0..3 {
            assert!(
                !dedup.check_or_insert(""),
                "an empty id was accepted on some call"
            );
            assert!(
                !dedup.check_or_insert(&"a".repeat(513)),
                "an oversized id was accepted on some call"
            );
        }
        assert!(
            !extracted::check_or_insert_result(false, false, false),
            "the model treats an invalid id as a first occurrence"
        );
    }

    /// TOTAL over the model's own domains: 2^3 for the combined result and
    /// 2^2 for duplicate detection.
    #[test]
    fn test_model_predicates_are_internally_total() {
        for id_valid in [false, true] {
            for already_seen in [false, true] {
                for within_ttl in [false, true] {
                    let got = extracted::check_or_insert_result(id_valid, already_seen, within_ttl);
                    let expected = id_valid && !(already_seen && within_ttl);
                    assert_eq!(
                        got, expected,
                        "check_or_insert_result disagrees with its own spec at \
                         ({id_valid}, {already_seen}, {within_ttl})"
                    );
                }
            }
        }
        for already_seen in [false, true] {
            for within_ttl in [false, true] {
                assert_eq!(
                    extracted::is_duplicate(already_seen, within_ttl),
                    already_seen && within_ttl
                );
            }
        }
    }
}
