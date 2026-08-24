// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability parent-glob matcher for literal child patterns.
//!
//! This module extracts the literal-child branch from
//! `capability_token.rs::grant_is_subset()` so the parent-glob containment
//! decision can be mirrored in Verus without changing the broader runtime
//! matcher used for action coverage.

const ASCII_CASE_OFFSET: u8 = b'a' - b'A';

#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn ascii_fold_byte(byte: u8) -> u8 {
    if byte >= b'A' && byte <= b'Z' {
        byte + ASCII_CASE_OFFSET
    } else {
        byte
    }
}

#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn byte_eq_ignore_ascii_case(left: u8, right: u8) -> bool {
    ascii_fold_byte(left) == ascii_fold_byte(right)
}

fn literal_child_matches_parent_glob_from(parent_pattern: &[u8], child_literal: &[u8]) -> bool {
    match parent_pattern.split_first() {
        None => child_literal.is_empty(),
        Some((&b'*', tail)) => {
            literal_child_matches_parent_glob_from(tail, child_literal)
                || child_literal.split_first().is_some_and(|(_, child_tail)| {
                    literal_child_matches_parent_glob_from(parent_pattern, child_tail)
                })
        }
        Some((&b'?', tail)) => child_literal.split_first().is_some_and(|(_, child_tail)| {
            literal_child_matches_parent_glob_from(tail, child_tail)
        }),
        Some((&pattern_head, tail)) => {
            child_literal
                .split_first()
                .is_some_and(|(&child_head, child_tail)| {
                    byte_eq_ignore_ascii_case(pattern_head, child_head)
                        && literal_child_matches_parent_glob_from(tail, child_tail)
                })
        }
    }
}

/// Return true when the parent glob pattern matches the literal child value
/// under the case-insensitive `*`/`?` rules used by capability delegation.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) fn literal_child_matches_parent_glob(parent_pattern: &str, child_literal: &str) -> bool {
    literal_child_matches_parent_glob_from(parent_pattern.as_bytes(), child_literal.as_bytes())
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! `formal/verus/verified_capability_glob.rs` proves that its executable
    //! function equals `spec_literal_child_matches_parent_glob`. That proof
    //! reaches shipped behaviour only if the function in *this* module computes
    //! the same thing — and the two are structurally different implementations
    //! (the kernel is index-based over `Vec<u8>` with an explicit `decreases`;
    //! this module is slice-based with `split_first()`), so no textual check can
    //! establish it.
    //!
    //! `check-verus-parity.sh` greps for symbol names and cannot see behaviour:
    //! it reported "ALL CHECKS PASSED" against a tree where the body below had
    //! been replaced with `return true`. The module-level test suite is also not
    //! sufficient on its own — changing the case-fold range from `A..=Z` to
    //! `A..<Z` passed all 1,950 crate tests while the kernel went on proving
    //! case-insensitivity universally.
    //!
    //! So the oracle here transcribes the Verus **spec** function directly and
    //! the two are compared over an exhaustively enumerated input space. Keep
    //! this transcription in step with the kernel; it is the discharge of the
    //! assumption, and if it drifts the assumption silently returns.

    use super::literal_child_matches_parent_glob;

    const STAR: u8 = 0x2a;
    const QUESTION: u8 = 0x3f;
    const ASCII_CASE_OFFSET: u8 = 0x20;
    const ASCII_A_UPPER: u8 = b'A';
    const ASCII_Z_UPPER: u8 = b'Z';

    /// Transcription of `spec_ascii_fold_byte`.
    ///
    /// `const` so the comparison keeps the spec's literal `A <= b && b <= Z`
    /// shape; the `RangeInclusive::contains` form clippy suggests for non-const
    /// code would obscure the line-by-line correspondence this module exists to
    /// make checkable.
    const fn spec_ascii_fold_byte(byte: u8) -> u8 {
        if ASCII_A_UPPER <= byte && byte <= ASCII_Z_UPPER {
            byte + ASCII_CASE_OFFSET
        } else {
            byte
        }
    }

    /// Transcription of `spec_byte_eq_ignore_ascii_case`.
    const fn spec_byte_eq_ignore_ascii_case(left: u8, right: u8) -> bool {
        spec_ascii_fold_byte(left) == spec_ascii_fold_byte(right)
    }

    /// Transcription of `spec_literal_child_matches_parent_glob_from`.
    ///
    /// Deliberately index-based and shaped exactly like the Verus spec so the
    /// correspondence can be checked by reading the two side by side.
    fn spec_matches_from(
        parent_pattern: &[u8],
        pattern_start: usize,
        child_literal: &[u8],
        child_start: usize,
    ) -> bool {
        if pattern_start >= parent_pattern.len() {
            child_start >= child_literal.len()
        } else if parent_pattern[pattern_start] == STAR {
            spec_matches_from(
                parent_pattern,
                pattern_start + 1,
                child_literal,
                child_start,
            ) || (child_start < child_literal.len()
                && spec_matches_from(
                    parent_pattern,
                    pattern_start,
                    child_literal,
                    child_start + 1,
                ))
        } else {
            child_start < child_literal.len()
                && (parent_pattern[pattern_start] == QUESTION
                    || spec_byte_eq_ignore_ascii_case(
                        parent_pattern[pattern_start],
                        child_literal[child_start],
                    ))
                && spec_matches_from(
                    parent_pattern,
                    pattern_start + 1,
                    child_literal,
                    child_start + 1,
                )
        }
    }

    /// Alphabet chosen so the enumeration reaches every branch and every
    /// boundary the kernel's proof depends on:
    ///
    /// - `*` and `?` drive the two metacharacter branches
    /// - `A`/`a` and `Z`/`z` drive case folding, with `Z` present specifically
    ///   because an `A..<Z` off-by-one is otherwise invisible to the suite
    /// - `@` (0x40) and `[` (0x5B) sit immediately outside `A..=Z`, so widening
    ///   the fold range in either direction is caught
    const ALPHABET: &[u8] = &[STAR, QUESTION, b'@', b'A', b'Z', b'[', b'a', b'z'];
    const MAX_LEN: usize = 3;

    /// Every string over `ALPHABET` of length `0..=MAX_LEN`.
    fn enumerate_strings() -> Vec<Vec<u8>> {
        let mut out = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..MAX_LEN {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &symbol in ALPHABET {
                    let mut candidate = prefix.clone();
                    candidate.push(symbol);
                    next.push(candidate);
                }
            }
            out.extend(next.iter().cloned());
            frontier = next;
        }
        out
    }

    #[test]
    fn test_production_matches_verus_spec_bounded_exhaustive() {
        let strings = enumerate_strings();
        let mut checked = 0usize;

        for parent in &strings {
            // Only well-formed UTF-8 reaches the public entry point.
            let Ok(parent_str) = core::str::from_utf8(parent) else {
                continue;
            };
            for child in &strings {
                let Ok(child_str) = core::str::from_utf8(child) else {
                    continue;
                };

                let shipped = literal_child_matches_parent_glob(parent_str, child_str);
                let proven = spec_matches_from(parent, 0, child, 0);

                assert_eq!(
                    shipped, proven,
                    "PARITY-HAND-1 violated: shipped matcher disagrees with the \
                     Verus spec for parent={parent_str:?} child={child_str:?} \
                     (shipped={shipped}, spec={proven})"
                );
                checked += 1;
            }
        }

        // Guards against the enumeration silently collapsing to nothing, which
        // would make this test pass vacuously — the exact failure mode the
        // guard self-test exists to prevent.
        assert_eq!(
            strings.len(),
            585,
            "enumeration size changed; recount before trusting the result"
        );
        assert_eq!(checked, 585 * 585, "not every pair was compared");
    }

    #[test]
    fn test_spec_oracle_disagrees_with_a_deliberately_wrong_matcher() {
        // The differential test above is only meaningful if the oracle can
        // actually reject something. This pins that it does, for each of the
        // three mutations that defeated check-verus-parity.sh.
        assert!(spec_matches_from(b"A", 0, b"a", 0), "fold must cover A");
        assert!(spec_matches_from(b"Z", 0, b"z", 0), "fold must cover Z");
        assert!(
            !spec_matches_from(b"?", 0, b"", 0),
            "'?' must consume exactly one byte"
        );
        assert!(
            !spec_matches_from(b"[", 0, b"{", 0),
            "fold must not extend past Z"
        );
        assert!(
            !spec_matches_from(b"@", 0, b"`", 0),
            "fold must not extend below A"
        );
        assert!(
            !spec_matches_from(b"A", 0, b"z", 0),
            "distinct letters must not match"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascii_fold_byte_lowers_ascii_uppercase() {
        assert_eq!(ascii_fold_byte(b'F'), b'f');
        assert_eq!(ascii_fold_byte(b'f'), b'f');
        assert_eq!(ascii_fold_byte(b'_'), b'_');
    }

    #[test]
    fn test_byte_eq_ignore_ascii_case_is_case_insensitive() {
        assert!(byte_eq_ignore_ascii_case(b'F', b'f'));
        assert!(byte_eq_ignore_ascii_case(b'o', b'O'));
        assert!(!byte_eq_ignore_ascii_case(b'f', b'x'));
    }

    #[test]
    fn test_literal_child_matches_parent_glob_accepts_case_insensitive_literal() {
        assert!(literal_child_matches_parent_glob("FILE_READ", "file_read"));
    }

    #[test]
    fn test_literal_child_matches_parent_glob_accepts_question_mark() {
        assert!(literal_child_matches_parent_glob("fi?", "fix"));
        assert!(!literal_child_matches_parent_glob("fi?", "fi"));
    }

    #[test]
    fn test_literal_child_matches_parent_glob_accepts_star_backtracking() {
        assert!(literal_child_matches_parent_glob("a*b*c", "axbyc"));
        assert!(!literal_child_matches_parent_glob("a*b*c", "axbyd"));
    }

    #[test]
    fn test_literal_child_matches_parent_glob_accepts_empty_star_match() {
        assert!(literal_child_matches_parent_glob("file_*", "file_"));
    }
}
