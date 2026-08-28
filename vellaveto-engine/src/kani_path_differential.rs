// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Differential binding for `PARITY-HAND-2` — path normalization.
//!
//! `formal/kani/src/path.rs` opens by saying it is a "verbatim extraction from
//! `vellaveto-engine/src/path.rs`", that "the algorithm is identical", and that
//! "this correspondence is verified by CI". The registry records that last
//! claim as false: the Kani job's "Verify extracted code correspondence" step
//! runs `cargo test --lib` **inside `formal/kani`**, where the assertions are
//! hardcoded vectors checked against Kani's own copy, and "Verify extraction
//! sync" is `check-kani-parity.sh`, which greps for symbol names. Neither
//! compares the two implementations. `formal/kani` is excluded from the
//! workspace and does not depend on the production crates, so nothing could.
//!
//! This module closes that. It compiles the extracted source directly, in this
//! crate's test build, and compares it against production over an enumerated
//! corpus. Every Kani proof about path normalization reaches shipped behaviour
//! through this comparison and no longer through a comment.
//!
//! Two differences are declared by the extraction itself and are not drift:
//! the error type (`PathError` vs `EngineError::PathNormalization`) and the
//! removal of `tracing::warn!`. So the comparison is: **the `Ok` values must be
//! equal, and the two must agree on whether the input is an error at all.**

// The extracted file is compiled verbatim by `include!` rather than copied: a
// copy would be a third implementation to keep in step, which is exactly what
// this binding exists to avoid. The `include!` must be the first thing in the
// module because the extracted file opens with `//!` inner docs, and it refers
// to `crate::PathError`, which `lib.rs` supplies under `#[cfg(test)]`.
//
// If the extraction stops compiling here, that is a finding, not an
// inconvenience: it means the file no longer stands on its own as the thing the
// Kani proofs run against.
#[cfg(test)]
// Lints are suppressed rather than satisfied. Clippy's suggestions here
// (`manual_range_contains` on the hex-nibble helpers, unused items) are about
// the extracted file, and "fixing" them would edit the copy the Kani proofs run
// against so that it no longer matches what was extracted — which is the exact
// drift this module exists to detect. The extraction is compiled as written or
// not at all.
#[allow(
    clippy::manual_range_contains,
    clippy::implicit_saturating_sub,
    dead_code,
    unused_imports
)]
mod extracted {
    include!(concat!(env!("OUT_DIR"), "/kani_path_extraction.rs"));
}

#[cfg(test)]
mod kani_parity_differential {
    use super::extracted;
    use crate::path::{normalize_path, normalize_path_bounded};

    /// Inputs chosen against what the normalizer is supposed to defend:
    /// traversal, encoded traversal, double and triple encoding, null bytes,
    /// backslash normalization, redundant separators, and the shapes that sit
    /// on a boundary the algorithm branches at.
    const CORPUS: &[&str] = &[
        "",
        "/",
        ".",
        "..",
        "/..",
        "/../..",
        "a",
        "/a",
        "a/b",
        "/a/b",
        "/a/./b",
        "/a/../b",
        "/a/b/..",
        "/a/b/../..",
        "/a/b/../../..",
        "./a",
        "../a",
        "a/../../b",
        "//a//b//",
        "/a//",
        "///",
        "\\a\\b",
        "a\\..\\b",
        "/a\\../b",
        "%2e%2e",
        "%2e%2e/",
        "/%2e%2e/b",
        "%2E%2E/b",
        "%252e%252e",
        "%25252e%25252e",
        "/a/%2e%2e/b",
        "%2f",
        "%2F",
        "/a%2fb",
        "%5c",
        "/a%5c..%5cb",
        "%00",
        "/a%00b",
        "a\0b",
        "/a/b/c/d/e/f/g",
        "/../../../../etc/passwd",
        "....//....//",
        "..;/",
        "%",
        "%2",
        "%zz",
        "%2g",
        "a%",
        "/a/%",
        "  /a/b  ",
        "/a b/c",
        "/é/ü",
        "/a\u{202e}b",
        "/a\u{200b}b",
    ];

    /// The production rejection reason for an input, if it rejects at all.
    ///
    /// The extraction declares exactly one difference in its error handling —
    /// the type — so the *reason* is comparable and is compared. Without it
    /// the binding cannot see a rejection moving from one branch to another:
    /// deleting the null-byte check on the raw input is invisible if the check
    /// inside the decode loop still rejects, because both still return `Err`.
    /// That mutation survived until the reason was included.
    fn shipped_reason(raw: &str, max_iterations: u32) -> Option<String> {
        match normalize_path_bounded(raw, max_iterations) {
            Ok(_) => None,
            Err(crate::error::EngineError::PathNormalization { reason }) => Some(reason),
            Err(other) => panic!(
                "PARITY-HAND-2: path normalization returned an unexpected error kind \
                 for {raw:?}: {other:?}"
            ),
        }
    }

    /// Report shape: the two must agree on the `Ok` value, on whether the input
    /// errors, and on *why*. Only the error type differs, by declared design.
    fn compare(raw: &str, max_iterations: u32) {
        let shipped = normalize_path_bounded(raw, max_iterations);
        let extracted = extracted::normalize_path_bounded(raw, max_iterations);

        match (&shipped, &extracted) {
            (Ok(a), Ok(b)) => assert_eq!(
                a, b,
                "PARITY-HAND-2: the Kani extraction and production normalize {raw:?} \
                 differently at max_iterations={max_iterations} \
                 (production {a:?}, extracted {b:?}) — every Kani path proof is \
                 about a function that is not the one running"
            ),
            (Err(_), Err(extracted_err)) => {
                let production_reason =
                    shipped_reason(raw, max_iterations).expect("shipped errored on this input");
                assert_eq!(
                    production_reason, extracted_err.reason,
                    "PARITY-HAND-2: both reject {raw:?} at \
                     max_iterations={max_iterations} but for different reasons \
                     (production {production_reason:?}, extracted {:?}) — a check has \
                     moved between branches in one copy and not the other",
                    extracted_err.reason
                );
            }
            (Ok(a), Err(e)) => panic!(
                "PARITY-HAND-2: production accepted {raw:?} as {a:?} but the Kani \
                 extraction rejected it ({e:?}) — the proofs are stricter than the code"
            ),
            (Err(e), Ok(b)) => panic!(
                "PARITY-HAND-2: production rejected {raw:?} ({e:?}) but the Kani \
                 extraction accepted it as {b:?} — the proofs are weaker than the code, \
                 which is the direction that hides a bypass"
            ),
        }
    }

    #[test]
    fn test_kani_path_extraction_matches_production_on_the_corpus() {
        for raw in CORPUS {
            compare(raw, crate::path::DEFAULT_MAX_PATH_DECODE_ITERATIONS);
        }
        assert!(CORPUS.len() >= 50, "corpus shrank; recount before trusting");
    }

    /// The iteration limit is the fail-closed bound. Walk it from 0 upward
    /// against inputs that need increasing numbers of decode passes, so an
    /// off-by-one in either copy is caught rather than averaged away.
    #[test]
    fn test_kani_path_extraction_matches_production_across_the_iteration_bound() {
        let nested = [
            "/a/b".to_string(),
            "/%2e%2e/b".to_string(),
            "/%252e%252e/b".to_string(),
            "/%25252e%25252e/b".to_string(),
            "/%2525252e%2525252e/b".to_string(),
        ];
        for raw in &nested {
            for max_iterations in 0u32..8 {
                compare(raw, max_iterations);
            }
        }
    }

    /// A path built to sit exactly on the default limit, and one past it.
    #[test]
    fn test_kani_path_extraction_agrees_at_the_default_limit() {
        // Each `25` prefix costs one decode pass.
        for depth in 0usize..24 {
            let encoded = format!("/{}2e2e/b", "%25".repeat(depth));
            compare(&encoded, crate::path::DEFAULT_MAX_PATH_DECODE_ITERATIONS);
        }
    }

    /// The unbounded entry point, which is what production callers use.
    #[test]
    fn test_kani_path_extraction_matches_production_unbounded_entry_point() {
        for raw in CORPUS {
            let shipped = normalize_path(raw);
            let extracted = extracted::normalize_path(raw);
            match (&shipped, &extracted) {
                (Ok(a), Ok(b)) => assert_eq!(a, b, "PARITY-HAND-2: disagreement on {raw:?}"),
                (Err(_), Err(_)) => {}
                _ => panic!(
                    "PARITY-HAND-2: production and the Kani extraction disagree on whether \
                     {raw:?} is an error"
                ),
            }
        }
    }

    /// The constant the proofs bound their loops with must be the shipped one.
    /// If the extraction drifts here, every Kani path proof is about a
    /// different fail-closed threshold than the one that runs.
    #[test]
    fn test_decode_iteration_constant_matches() {
        assert_eq!(
            extracted::DEFAULT_MAX_PATH_DECODE_ITERATIONS,
            crate::path::DEFAULT_MAX_PATH_DECODE_ITERATIONS,
            "PARITY-HAND-2: the Kani extraction bounds decoding at a different \
             iteration count than production"
        );
        // Pinned literally, so raising production's constant cannot move both
        // sides of the comparison at once and escape unnoticed.
        assert_eq!(crate::path::DEFAULT_MAX_PATH_DECODE_ITERATIONS, 20);
    }

    /// The build script degrades to a stub when the extraction is absent, so
    /// every test above would pass vacuously against nothing. Assert it is
    /// really there. A skipped binding that reports success is the failure
    /// mode this whole assumption family exists to remove.
    // The constant is generated by build.rs and is `false` when the extraction
    // is missing, so the assertion is not constant in the way clippy means.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/path.rs was not found, so PARITY-HAND-2 was not \
             discharged by this run — the comparison ran against nothing"
        );
    }

    /// The comparison must be able to fail. If the corpus never reaches a
    /// distinguishing input, agreement is meaningless.
    #[test]
    fn test_corpus_exercises_both_outcomes() {
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for raw in CORPUS {
            if normalize_path(raw).is_ok() {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        assert!(
            accepted > 0 && rejected > 0,
            "corpus is one-sided (accepted {accepted}, rejected {rejected}); it cannot \
             distinguish a permissive extraction from a strict one"
        );
    }
}
