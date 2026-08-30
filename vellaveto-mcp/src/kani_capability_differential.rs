// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Differential binding for `PARITY-HAND-2` — capability delegation.
//!
//! The largest extraction in the crate, carrying K36-K41: subset reflexivity,
//! no-escalation, pattern subset correctness, wildcard matching, and path
//! normalization with no `..` surviving.
//!
//! It duplicates predicates that **already have production mirrors bound to
//! Verus** under `PARITY-HAND-1` — `verified_capability_pattern`,
//! `_glob`, `_literal`, `_domain`, `_path` and `_glob_subset`. So this binding
//! closes **six triangles at once**: for each predicate, Verus proves the
//! mirror, and this shows the Kani copy is the same function.
//!
//! What rides on it: monotonic attenuation. A delegated capability must never
//! exceed its parent's. Every predicate here is part of deciding that, and the
//! campaign has already found one case (`KANI-LEET-DRIFT-1`) where a duplicated
//! table drifted into claiming a defence production does not have.

#[cfg(test)]
// Suppressed rather than satisfied: linting the extraction would edit the copy
// the Kani proofs run against.
#[allow(
    clippy::manual_range_contains,
    clippy::manual_unwrap_or_default,
    clippy::needless_range_loop,
    dead_code,
    unused_imports
)]
mod extracted {
    include!(concat!(env!("OUT_DIR"), "/kani_capability_extraction.rs"));
}

#[cfg(test)]
mod kani_parity_differential_capability {
    use super::extracted;
    use crate::{
        verified_capability_domain, verified_capability_glob, verified_capability_glob_subset,
        verified_capability_literal, verified_capability_path, verified_capability_pattern,
    };

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/capability.rs was not found, so this binding compared nothing"
        );
    }

    /// TOTAL over all 256 bytes: the case fold, and the case-insensitive byte
    /// comparison built on it.
    ///
    /// The fold is where a `A..=Z` → `A..<Z` off-by-one hides — that exact
    /// mutation passed the old symbol-name guard and all 1,950 crate tests
    /// under `PARITY-HAND-1`, which is what started this campaign.
    #[test]
    fn test_case_fold_matches_production_total_domain() {
        for byte in 0u8..=255 {
            assert_eq!(
                extracted::ascii_fold_byte(byte),
                verified_capability_glob::ascii_fold_byte(byte),
                "PARITY-HAND-2: case fold disagrees for byte {byte:#04x}"
            );
        }
        let mut checked = 0usize;
        for left in 0u8..=255 {
            for right in 0u8..=255 {
                assert_eq!(
                    extracted::byte_eq_ignore_ascii_case(left, right),
                    verified_capability_glob::byte_eq_ignore_ascii_case(left, right),
                    "PARITY-HAND-2: case-insensitive byte comparison disagrees at \
                     ({left:#04x}, {right:#04x})"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 256 * 256, "enumeration collapsed");
    }

    /// Metacharacter detection over an alphabet that includes both
    /// metacharacters, their neighbours, and strings that contain neither.
    #[test]
    fn test_metacharacter_detection_matches_production() {
        const PATTERNS: [&str; 12] = [
            "",
            "*",
            "?",
            "**",
            "??",
            "a",
            "ab",
            "a*b",
            "a?b",
            "a)b",
            "a(b",
            "file_read",
        ];
        for pattern in PATTERNS {
            assert_eq!(
                extracted::has_glob_metacharacters(pattern),
                verified_capability_pattern::has_glob_metacharacters(pattern),
                "PARITY-HAND-2: metacharacter detection disagrees for {pattern:?}"
            );
        }
    }

    /// TOTAL over 2³: the routing guard that decides whether a pattern pair
    /// takes the fast path or the exact subset check.
    #[test]
    fn test_pattern_subset_guard_matches_production_total_domain() {
        for wildcard in [false, true] {
            for equal in [false, true] {
                for meta in [false, true] {
                    assert_eq!(
                        extracted::pattern_subset_guard(wildcard, equal, meta),
                        verified_capability_pattern::pattern_subset_guard(wildcard, equal, meta),
                        "PARITY-HAND-2: subset guard disagrees at ({wildcard}, {equal}, {meta})"
                    );
                }
            }
        }
    }

    /// TOTAL over 2²: the literal-child fast path.
    #[test]
    fn test_literal_child_subset_matches_production_total_domain() {
        for meta in [false, true] {
            for matches in [false, true] {
                assert_eq!(
                    extracted::literal_child_pattern_subset(meta, matches),
                    verified_capability_literal::literal_child_pattern_subset(meta, matches),
                    "PARITY-HAND-2: literal-child subset disagrees at ({meta}, {matches})"
                );
            }
        }
    }

    /// TOTAL over 2³ and 2⁴: the two domain-capability gates.
    ///
    /// `normalized_domain_pattern_subset` is where a wildcard parent decides
    /// whether a child domain is covered — the difference between `*.evil.com`
    /// being contained by `*.com` and not.
    #[test]
    fn test_domain_gates_match_production_total_domain() {
        for has_wildcard_prefix in [false, true] {
            for has_other_meta in [false, true] {
                for suffix_empty in [false, true] {
                    assert_eq!(
                        extracted::domain_pattern_shape_valid(
                            has_wildcard_prefix,
                            has_other_meta,
                            suffix_empty
                        ),
                        verified_capability_domain::domain_pattern_shape_valid(
                            has_wildcard_prefix,
                            has_other_meta,
                            suffix_empty
                        ),
                        "PARITY-HAND-2: domain shape validity disagrees at \
                         ({has_wildcard_prefix}, {has_other_meta}, {suffix_empty})"
                    );
                }
            }
        }

        let mut checked = 0usize;
        for parent_wild in [false, true] {
            for child_wild in [false, true] {
                for suffix_match in [false, true] {
                    for exact_equal in [false, true] {
                        assert_eq!(
                            extracted::normalized_domain_pattern_subset(
                                parent_wild,
                                child_wild,
                                suffix_match,
                                exact_equal
                            ),
                            verified_capability_domain::normalized_domain_pattern_subset(
                                parent_wild,
                                child_wild,
                                suffix_match,
                                exact_equal
                            ),
                            "PARITY-HAND-2: domain subset disagrees at ({parent_wild}, \
                             {child_wild}, {suffix_match}, {exact_equal}) — a child \
                             domain grant could exceed its parent"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 16, "enumeration collapsed");
    }

    /// K41: path depth tracking, including the fail-closed case above root.
    ///
    /// `..` at depth 0 must return `None`, not wrap or clamp — that is what
    /// stops a grant path escaping its root.
    #[test]
    fn test_path_depth_matches_production_total_domain() {
        for depth in [0usize, 1, 2, 10, usize::MAX - 1, usize::MAX] {
            for empty_or_dot in [false, true] {
                for dotdot in [false, true] {
                    assert_eq!(
                        extracted::path_component_next_depth(depth, empty_or_dot, dotdot),
                        verified_capability_path::path_component_next_depth(
                            depth,
                            empty_or_dot,
                            dotdot
                        ),
                        "PARITY-HAND-2: path depth disagrees at ({depth}, \
                         {empty_or_dot}, {dotdot})"
                    );
                }
            }
        }
        // K41 stated: `..` above root fails closed.
        assert_eq!(
            extracted::path_component_next_depth(0, false, true),
            None,
            "K41: `..` at depth 0 did not fail closed, so a grant path can escape \
             its root"
        );
        // And depth cannot overflow silently.
        assert_eq!(
            extracted::path_component_next_depth(usize::MAX, false, false),
            None,
            "depth increment overflowed instead of failing closed"
        );
    }

    /// The glob matcher, over the alphabet chosen for the `PARITY-HAND-1`
    /// binding: metacharacters, case-fold boundaries, and the characters
    /// immediately outside `A..=Z` in both directions.
    #[test]
    fn test_glob_matching_matches_production() {
        const ALPHABET: &[u8] = b"*?@AZ[az";
        let mut strings: Vec<Vec<u8>> = vec![Vec::new()];
        let mut frontier: Vec<Vec<u8>> = vec![Vec::new()];
        for _ in 0..2 {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &symbol in ALPHABET {
                    let mut candidate = prefix.clone();
                    candidate.push(symbol);
                    next.push(candidate);
                }
            }
            strings.extend(next.iter().cloned());
            frontier = next;
        }

        let mut checked = 0usize;
        for pattern in &strings {
            let Ok(pattern_str) = core::str::from_utf8(pattern) else {
                continue;
            };
            for value in &strings {
                let Ok(value_str) = core::str::from_utf8(value) else {
                    continue;
                };
                // The model's byte matcher against production's str matcher.
                assert_eq!(
                    extracted::glob_match(pattern, value),
                    verified_capability_glob::literal_child_matches_parent_glob(
                        pattern_str,
                        value_str
                    ),
                    "PARITY-HAND-2: glob matching disagrees for pattern \
                     {pattern_str:?} value {value_str:?}"
                );
                checked += 1;
            }
        }
        assert_eq!(strings.len(), 73, "enumeration size changed; recount");
        assert_eq!(checked, 73 * 73, "not every pair was compared");
    }

    /// The exact language-subset checker, on pattern pairs where containment
    /// actually differs.
    #[test]
    fn test_glob_subset_matches_production() {
        const PATTERNS: [&str; 10] = ["*", "a", "A", "a*", "a?", "?b", "ab", "AB", "a*b", "*b*"];
        for parent in PATTERNS {
            for child in PATTERNS {
                assert_eq!(
                    extracted::glob_pattern_subset(parent, child),
                    verified_capability_glob_subset::glob_pattern_subset(parent, child),
                    "PARITY-HAND-2: glob subset disagrees for parent {parent:?} \
                     child {child:?} — a delegated pattern could admit values its \
                     parent does not"
                );
            }
        }
    }

    /// The comparisons must reach both answers, or agreement proves nothing.
    #[test]
    fn test_enumerations_reach_both_answers() {
        assert!(extracted::glob_match(b"*", b"anything"));
        assert!(!extracted::glob_match(b"a", b"b"));
        assert!(extracted::glob_pattern_subset("*", "a"));
        assert!(!extracted::glob_pattern_subset("a", "*"));
        assert_ne!(
            extracted::ascii_fold_byte(b'A'),
            b'A',
            "the fold must actually change something"
        );
    }
}
