// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability pattern attenuation guard.
//!
//! This module extracts the conservative child-glob rejection rule from
//! `capability_token.rs::grant_is_subset()`. It does not attempt to prove full
//! glob-language containment; it only formalizes the fail-closed guard that
//! rejects non-identical child patterns containing `*` or `?`.

/// Return true when the pattern contains glob metacharacters used by capability
/// delegation (`*` or `?`).
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) fn has_glob_metacharacters(pattern: &str) -> bool {
    pattern.as_bytes().iter().any(|b| *b == b'*' || *b == b'?')
}

/// Return true when the child pattern is allowed to continue through the
/// delegation subset check.
///
/// This guard encodes the conservative fix for non-identical child glob
/// patterns:
/// - wildcard parent: always allowed to continue
/// - exact case-insensitive equality: always allowed to continue
/// - otherwise, child patterns containing `*` or `?` are rejected
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn pattern_subset_guard(
    parent_is_wildcard: bool,
    parent_equals_child_ignore_ascii_case: bool,
    child_has_metacharacters: bool,
) -> bool {
    parent_is_wildcard || parent_equals_child_ignore_ascii_case || !child_has_metacharacters
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for the kernel in
    //! `formal/verus/verified_capability_pattern.rs`. The transcriptions below restate that
    //! `spec` and assert it agrees with the function this crate actually ships,
    //! which is the step that carries the proof to production. Symbol-level
    //! parity cannot do this: `check-verus-parity.sh` greps for names and
    //! reported success against a tree with a security check replaced by
    //! `return true`.
    //!
    //! MIXED: `pattern_subset_guard` gets a TOTAL discharge over its
    //! three booleans. `has_glob_metacharacters` is string-domain and gets a
    //! bounded-exhaustive one over an alphabet holding both metacharacters and
    //! their nearest non-metacharacter neighbours by byte value.
    //!
    //! Keep each transcription in step with the kernel. If it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_pattern_subset_guard(
        parent_is_wildcard: bool,
        parent_equals_child_ignore_ascii_case: bool,
        child_has_metacharacters: bool,
    ) -> bool {
        parent_is_wildcard || parent_equals_child_ignore_ascii_case || !child_has_metacharacters
    }

    fn spec_has_glob_metacharacters_from(pattern: &[u8], start: usize) -> bool {
        if start >= pattern.len() {
            false
        } else {
            pattern[start] == 0x2a
                || pattern[start] == 0x3f
                || spec_has_glob_metacharacters_from(pattern, start + 1)
        }
    }

    #[test]
    fn test_pattern_subset_guard_matches_verus_spec_total_domain() {
        let mut checked = 0usize;
        for parent_is_wildcard in [false, true] {
            for equal in [false, true] {
                for child_meta in [false, true] {
                    assert_eq!(
                        pattern_subset_guard(parent_is_wildcard, equal, child_meta),
                        spec_pattern_subset_guard(parent_is_wildcard, equal, child_meta),
                        "PARITY-HAND-1: pattern_subset_guard disagrees at \
                         ({parent_is_wildcard}, {equal}, {child_meta})"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 8, "total domain is 2^3; enumeration collapsed");
    }

    #[test]
    fn test_has_glob_metacharacters_matches_verus_spec_bounded_exhaustive() {
        // 0x29/0x2b bracket `*` (0x2a) and 0x3e/0x40 bracket `?` (0x3f), so
        // widening or narrowing the metacharacter set is caught.
        const ALPHABET: &[u8] = &[0x29, 0x2a, 0x2b, 0x3e, 0x3f, 0x40, b'a'];
        const MAX_LEN: usize = 3;

        let mut frontier = vec![Vec::new()];
        let mut all: Vec<Vec<u8>> = vec![Vec::new()];
        for _ in 0..MAX_LEN {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &symbol in ALPHABET {
                    let mut candidate = prefix.clone();
                    candidate.push(symbol);
                    next.push(candidate);
                }
            }
            all.extend(next.iter().cloned());
            frontier = next;
        }

        let mut checked = 0usize;
        for bytes in &all {
            let Ok(as_str) = core::str::from_utf8(bytes) else {
                continue;
            };
            assert_eq!(
                has_glob_metacharacters(as_str),
                spec_has_glob_metacharacters_from(bytes, 0),
                "PARITY-HAND-1: has_glob_metacharacters disagrees for {as_str:?}"
            );
            checked += 1;
        }
        assert_eq!(all.len(), 400, "enumeration size changed; recount");
        assert_eq!(checked, 400, "not every candidate was compared");
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        assert!(!spec_pattern_subset_guard(false, false, true));
        assert!(spec_has_glob_metacharacters_from(b"a*", 0));
        assert!(spec_has_glob_metacharacters_from(b"a?", 0));
        assert!(!spec_has_glob_metacharacters_from(b"a+", 0));
        assert!(!spec_has_glob_metacharacters_from(b"a@", 0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_glob_metacharacters() {
        assert!(has_glob_metacharacters("fi*"));
        assert!(has_glob_metacharacters("fi?"));
        assert!(!has_glob_metacharacters("file_read"));
    }

    #[test]
    fn test_pattern_subset_guard_rejects_non_identical_child_glob() {
        assert!(!pattern_subset_guard(false, false, true));
    }

    #[test]
    fn test_pattern_subset_guard_allows_wildcard_parent() {
        assert!(pattern_subset_guard(true, false, true));
    }

    #[test]
    fn test_pattern_subset_guard_allows_identical_pattern() {
        assert!(pattern_subset_guard(false, true, true));
    }

    #[test]
    fn test_pattern_subset_guard_allows_literal_child_fallthrough() {
        assert!(pattern_subset_guard(false, false, false));
    }
}
