// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Differential binding for `PARITY-HAND-2` — PII placeholder tokens.
//!
//! `formal/kani/src/sanitizer.rs` models `QuerySanitizer::sanitize`. Until
//! 2026-08-30 it built `[PII_{CAT}_{SEQ:06}]` from a monotonic counter and K70
//! proved *that* design's uniqueness — the arrangement production removed in
//! R242-SHLD-1 because a guessable placeholder can be probed as a
//! desanitization oracle. Production draws a random `u64` and formats it
//! `{:016X}`. See `KANI-SANITIZER-DRIFT-1`.
//!
//! This binding is what would have caught it: the model's token construction is
//! compared against the exact `format!` production uses, and the round-trip is
//! exercised through the real `QuerySanitizer`.
//!
//! What cannot be compared, and why: production's token *value* is random, so
//! there is no token generation to compare against. Uniqueness there does not
//! come from the value being predictable — it comes from the redraw loop, which
//! `token_is_fresh` models. What is comparable is the **encoding**: given the
//! same category and value, the two must produce the same placeholder text.

#[cfg(test)]
// Suppressed rather than satisfied: linting the extraction would edit the copy
// the Kani proofs run against.
#[allow(
    clippy::manual_range_contains,
    clippy::manual_unwrap_or_default,
    dead_code,
    unused_imports
)]
mod extracted {
    include!(concat!(env!("OUT_DIR"), "/kani_sanitizer_extraction.rs"));
}

#[cfg(test)]
mod kani_parity_differential_sanitizer {
    use super::extracted;

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/sanitizer.rs was not found, so this binding compared nothing"
        );
    }

    /// The model's token must be byte-identical to what production's `format!`
    /// produces for the same category and value.
    ///
    /// This is the assertion that was missing. The model said
    /// `[PII_EMAIL_000007]`; production says `[PII_EMAIL_0000000000000007]`.
    #[test]
    fn test_token_encoding_matches_production_format() {
        const CATEGORIES: [(u8, &str); 4] = [(0, "email"), (1, "ssn"), (2, "cc"), (3, "phone")];
        const VALUES: [u64; 10] = [
            0,
            1,
            7,
            15,
            16,
            255,
            0xDEAD_BEEF,
            1_234_567,
            u64::MAX / 2,
            u64::MAX,
        ];

        for (cat_index, cat_name) in CATEGORIES {
            for value in VALUES {
                // Exactly the expression in QuerySanitizer::sanitize.
                let production = format!("[PII_{}_{:016X}]", cat_name.to_uppercase(), value);
                let model = extracted::make_token(cat_index, value);
                assert_eq!(
                    model, production,
                    "PARITY-HAND-2: the Kani sanitizer model builds a different \
                     placeholder than production for category {cat_name} value {value} \
                     — K69/K70 describe tokens that never appear in sanitized output"
                );
            }
        }
    }

    /// Fixed width is what makes a placeholder unambiguous to find and replace.
    /// A variable-width token could be a prefix of another.
    #[test]
    fn test_token_width_is_constant_in_both() {
        let widths: std::collections::HashSet<usize> = [0u64, 1, 255, u64::MAX / 3, u64::MAX]
            .into_iter()
            .map(|v| extracted::make_token(0, v).len())
            .collect();
        assert_eq!(
            widths.len(),
            1,
            "the model's placeholder width varies with the value, so one token \
             could be a prefix of another"
        );
        assert_eq!(
            format!("[PII_{}_{:016X}]", "EMAIL", 0u64).len(),
            *widths.iter().next().expect("one width"),
            "the model and production placeholders are different lengths"
        );
    }

    /// The hex rendering itself, against `{:016X}`, over the values a
    /// nibble-by-nibble renderer is most likely to get wrong.
    #[test]
    fn test_hex_rendering_matches_the_format_macro() {
        for value in [
            0u64,
            1,
            9,
            10,
            15,
            16,
            0x0F,
            0xF0,
            0xABCD_EF01_2345_6789,
            u64::MAX,
        ] {
            let rendered = extracted::render_sixteen_hex_digits(value);
            let as_str = std::str::from_utf8(&rendered).expect("hex digits are ASCII");
            assert_eq!(
                as_str,
                format!("{value:016X}"),
                "PARITY-HAND-2: hex rendering disagrees with {{:016X}} for {value}"
            );
            assert!(
                as_str
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)),
                "rendered {as_str:?} is not uppercase hex"
            );
        }
    }

    /// R242-SHLD-1: uniqueness comes from the redraw loop, not from the value.
    /// A candidate already in the mapping table must never be accepted.
    #[test]
    fn test_freshness_check_models_the_redraw_loop() {
        assert!(
            extracted::token_is_fresh(false),
            "an unused candidate must be accepted"
        );
        assert!(
            !extracted::token_is_fresh(true),
            "R242-SHLD-1: a candidate already in the mapping table was accepted, \
             which would map two PII values to one placeholder"
        );
    }

    /// The round-trip through the real sanitizer: PII in, placeholder out,
    /// original restored. K69 stated against production rather than the model.
    #[test]
    fn test_roundtrip_through_the_real_sanitizer() {
        use crate::sanitizer::QuerySanitizer;
        use vellaveto_audit::PiiScanner;

        let sanitizer = QuerySanitizer::new(PiiScanner::default());
        let input = "contact user@example.com about it";

        let sanitized = sanitizer.sanitize(input).expect("sanitize succeeds");
        assert!(
            !sanitized.contains("user@example.com"),
            "K69: the original PII survived sanitization"
        );
        assert!(
            sanitized.contains("[PII_"),
            "K69: no placeholder was inserted"
        );

        let restored = sanitizer
            .desanitize(&sanitized)
            .expect("desanitize succeeds");
        assert_eq!(
            restored, input,
            "K69: the round-trip did not restore the original text"
        );
    }

    /// A placeholder produced by production must be one the model would
    /// recognise as a token, or the two disagree about what a token looks like.
    #[test]
    fn test_production_placeholders_are_recognised_by_the_model() {
        use crate::sanitizer::QuerySanitizer;
        use vellaveto_audit::PiiScanner;

        let sanitizer = QuerySanitizer::new(PiiScanner::default());
        let sanitized = sanitizer
            .sanitize("mail user@example.com now")
            .expect("sanitize succeeds");

        assert!(
            extracted::contains_token_prefix(&sanitized),
            "the model does not recognise production's placeholder as a token: \
             {sanitized:?}"
        );
    }
}
