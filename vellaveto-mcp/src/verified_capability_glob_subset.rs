// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability parent-glob/child-glob subset kernel.
//!
//! This module closes the remaining delegation gap in
//! `capability_token.rs::grant_is_subset()` by deciding whether the full child
//! glob language is contained within the parent glob language for the
//! case-insensitive `*`/`?` matcher used by capability delegation.
//!
//! The implementation determinizes each glob pattern into a compact NFA state
//! set and explores the reachable product graph over a finite set of
//! representative bytes. That alphabet is exact for this matcher because
//! transitions only distinguish:
//! - literal bytes present in either pattern, after ASCII folding
//! - all remaining bytes, which are behaviorally equivalent

use std::collections::{HashSet, VecDeque};

use crate::verified_capability_glob::{ascii_fold_byte, byte_eq_ignore_ascii_case};

const STAR: u8 = b'*';
const QUESTION: u8 = b'?';

#[derive(Clone, PartialEq, Eq, Hash)]
struct PatternStateSet {
    bits: Vec<u64>,
}

impl PatternStateSet {
    fn new(state_count: usize) -> Self {
        Self {
            bits: vec![0; state_count.div_ceil(64)],
        }
    }

    fn set(&mut self, index: usize) {
        self.bits[index / 64] |= 1u64 << (index % 64);
    }

    fn contains(&self, index: usize) -> bool {
        (self.bits[index / 64] & (1u64 << (index % 64))) != 0
    }

    fn apply_star_epsilon_closure(&mut self, pattern: &[u8]) {
        for (index, &token) in pattern.iter().enumerate() {
            if self.contains(index) && token == STAR {
                self.set(index + 1);
            }
        }
    }

    fn start(pattern: &[u8]) -> Self {
        let mut state_set = Self::new(pattern.len() + 1);
        state_set.set(0);
        state_set.apply_star_epsilon_closure(pattern);
        state_set
    }

    fn transition(&self, pattern: &[u8], input: u8) -> Self {
        let mut next = Self::new(pattern.len() + 1);

        for (index, &token) in pattern.iter().enumerate() {
            if !self.contains(index) {
                continue;
            }

            if token == STAR {
                next.set(index);
            } else if token == QUESTION || byte_eq_ignore_ascii_case(token, input) {
                next.set(index + 1);
            }
        }

        next.apply_star_epsilon_closure(pattern);
        next
    }

    fn accepts(&self, pattern: &[u8]) -> bool {
        self.contains(pattern.len())
    }
}

/// Return true when the product-automaton state just reached is a witness that
/// the child language is *not* contained in the parent language: the child
/// accepts here and the parent does not.
///
/// Named counterpart of `spec_glob_subset_accepting_counterexample`.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn accepting_counterexample(parent_accepts: bool, child_accepts: bool) -> bool {
    child_accepts && !parent_accepts
}

/// Return true when the representative alphabet still needs a byte standing in
/// for "every character neither pattern mentions".
///
/// Below a full 256-class alphabet such a byte exists and the transition
/// relation cannot distinguish it from any other unmentioned byte; at 256 there
/// is nothing left to represent.
///
/// Named counterpart of `spec_representative_other_byte_needed`.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn representative_other_byte_needed(literal_class_count: usize) -> bool {
    literal_class_count < 256
}

/// Route a parent/child pattern pair to the branch that decides containment.
///
/// Named counterpart of `spec_glob_subset_fast_path`. The wildcard and
/// case-insensitive-equality parents are immediate; a child with no
/// metacharacters is a literal and is decided by the literal matcher;
/// everything else needs the exact language-subset check.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn glob_subset_fast_path(
    parent_is_wildcard: bool,
    parent_equals_child_ignore_ascii_case: bool,
    child_has_metacharacters: bool,
    literal_child_subset: bool,
    exact_child_glob_subset: bool,
) -> bool {
    if parent_is_wildcard || parent_equals_child_ignore_ascii_case {
        true
    } else if !child_has_metacharacters {
        literal_child_subset
    } else {
        exact_child_glob_subset
    }
}

fn collect_representative_bytes(parent_pattern: &[u8], child_pattern: &[u8]) -> Vec<u8> {
    let mut seen = [false; 256];
    let mut representatives = Vec::new();

    for &byte in parent_pattern.iter().chain(child_pattern.iter()) {
        if byte == STAR || byte == QUESTION {
            continue;
        }

        let folded = ascii_fold_byte(byte);
        if !seen[folded as usize] {
            seen[folded as usize] = true;
            representatives.push(folded);
        }
    }

    if representative_other_byte_needed(representatives.len()) {
        if let Some(other) = (u8::MIN..=u8::MAX).find(|byte| !seen[*byte as usize]) {
            representatives.push(other);
        }
    }

    representatives
}

/// Return true when every value matched by `child_pattern` is also matched by
/// `parent_pattern` under the case-insensitive `*`/`?` capability glob rules.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) fn glob_pattern_subset(parent_pattern: &str, child_pattern: &str) -> bool {
    let parent = parent_pattern.as_bytes();
    let child = child_pattern.as_bytes();
    let representatives = collect_representative_bytes(parent, child);

    let start = (
        PatternStateSet::start(parent),
        PatternStateSet::start(child),
    );
    let mut queue = VecDeque::from([start.clone()]);
    let mut visited = HashSet::from([start]);

    while let Some((parent_states, child_states)) = queue.pop_front() {
        if accepting_counterexample(parent_states.accepts(parent), child_states.accepts(child)) {
            return false;
        }

        for &input in &representatives {
            let next_parent = parent_states.transition(parent, input);
            let next_child = child_states.transition(child, input);
            let next = (next_parent.clone(), next_child.clone());

            if visited.insert(next) {
                queue.push_back((next_parent, next_child));
            }
        }
    }

    true
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`), kernel
    //! `formal/verus/verified_capability_glob_subset.rs`.
    //!
    //! The kernel proves three executable functions equal their specs. All
    //! three had been inline in this module and in `capability_token.rs`, so
    //! nothing linked the proof to what shipped; they are now named, called on
    //! the shipped path, and compared against transcriptions of the specs over
    //! their **total** input domains (2² and 2⁵ booleans, and the byte-class
    //! count across the 256 boundary).
    //!
    //! Scope note: the routing test below computes the two expensive booleans
    //! by calling the same sub-matchers production calls, so a mutation *inside*
    //! `literal_child_matches_parent_glob` or `glob_pattern_subset` is not
    //! caught here. That is deliberate — those functions are bound by their own
    //! kernels (`verified_capability_glob`, and the counterexample predicate
    //! above). This binding is about the routing between them.

    use super::{
        accepting_counterexample, glob_pattern_subset, glob_subset_fast_path,
        representative_other_byte_needed,
    };

    /// Transcription of `spec_glob_subset_accepting_counterexample`.
    fn spec_accepting_counterexample(parent_accepts: bool, child_accepts: bool) -> bool {
        child_accepts && !parent_accepts
    }

    /// Transcription of `spec_glob_subset_fast_path`.
    fn spec_fast_path(
        parent_is_wildcard: bool,
        parent_equals_child_ignore_ascii_case: bool,
        child_has_metacharacters: bool,
        literal_child_subset: bool,
        exact_child_glob_subset: bool,
    ) -> bool {
        if parent_is_wildcard || parent_equals_child_ignore_ascii_case {
            true
        } else if !child_has_metacharacters {
            literal_child_subset
        } else {
            exact_child_glob_subset
        }
    }

    /// Transcription of `spec_representative_other_byte_needed`.
    fn spec_other_byte_needed(literal_class_count: usize) -> bool {
        literal_class_count < 256
    }

    /// TOTAL over 2² inputs.
    #[test]
    fn test_accepting_counterexample_matches_verus_spec_total_domain() {
        for parent_accepts in [false, true] {
            for child_accepts in [false, true] {
                assert_eq!(
                    accepting_counterexample(parent_accepts, child_accepts),
                    spec_accepting_counterexample(parent_accepts, child_accepts),
                    "PARITY-HAND-1: counterexample predicate disagrees at \
                     (parent={parent_accepts}, child={child_accepts})"
                );
            }
        }
        // The two ensures clauses the kernel attaches: a counterexample implies
        // the child accepted and the parent did not.
        for parent_accepts in [false, true] {
            for child_accepts in [false, true] {
                if accepting_counterexample(parent_accepts, child_accepts) {
                    assert!(
                        child_accepts,
                        "PARITY-HAND-1: witness without child acceptance"
                    );
                    assert!(
                        !parent_accepts,
                        "PARITY-HAND-1: witness with parent acceptance"
                    );
                }
            }
        }
    }

    /// TOTAL over 2⁵ inputs.
    #[test]
    fn test_fast_path_matches_verus_spec_total_domain() {
        let mut checked = 0usize;
        for wildcard in [false, true] {
            for equal in [false, true] {
                for meta in [false, true] {
                    for literal in [false, true] {
                        for exact in [false, true] {
                            assert_eq!(
                                glob_subset_fast_path(wildcard, equal, meta, literal, exact),
                                spec_fast_path(wildcard, equal, meta, literal, exact),
                                "PARITY-HAND-1: fast-path routing disagrees at \
                                 ({wildcard}, {equal}, {meta}, {literal}, {exact})"
                            );
                            checked += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 32, "enumeration collapsed");
    }

    /// Covers the 256 boundary in both directions.
    #[test]
    fn test_other_byte_needed_matches_verus_spec_across_the_boundary() {
        for count in 0..=300usize {
            assert_eq!(
                representative_other_byte_needed(count),
                spec_other_byte_needed(count),
                "PARITY-HAND-1: representative-byte predicate disagrees at {count}"
            );
        }
        assert!(representative_other_byte_needed(255));
        assert!(!representative_other_byte_needed(256));
    }

    /// The shipped routing in `capability_token::pattern_is_subset` must equal
    /// the kernel's routing over real pattern pairs.
    #[test]
    fn test_shipped_routing_matches_verus_spec() {
        use crate::{
            capability_token::pattern_is_subset, verified_capability_glob,
            verified_capability_pattern,
        };

        const PATTERNS: [&str; 10] = ["*", "a", "A", "a*", "a?", "?b", "ab", "AB", "a*b", "*b*"];

        let mut checked = 0usize;
        for parent in PATTERNS {
            for child in PATTERNS {
                let wildcard = parent == "*";
                let equal = parent.eq_ignore_ascii_case(child);
                let meta = verified_capability_pattern::has_glob_metacharacters(child);
                let literal = !meta
                    && verified_capability_glob::literal_child_matches_parent_glob(parent, child);
                let exact = meta && glob_pattern_subset(parent, child);

                assert_eq!(
                    pattern_is_subset(parent, child),
                    spec_fast_path(wildcard, equal, meta, literal, exact),
                    "PARITY-HAND-1: shipped routing disagrees for parent={parent:?} \
                     child={child:?}"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 100, "pattern enumeration collapsed");
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // A wildcard parent admits everything.
        assert!(spec_fast_path(true, false, true, false, false));
        // A non-wildcard, non-equal, literal child defers to the literal result.
        assert!(!spec_fast_path(false, false, false, false, true));
        assert!(spec_fast_path(false, false, false, true, false));
        // A glob child defers to the exact checker, not the literal one.
        assert!(!spec_fast_path(false, false, true, true, false));
        assert!(spec_fast_path(false, false, true, false, true));
        // Only child-accepts-and-parent-rejects is a counterexample.
        assert!(!spec_accepting_counterexample(true, true));
        assert!(spec_accepting_counterexample(false, true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enumerate_values(alphabet: &[u8], max_len: usize) -> Vec<String> {
        fn recurse(current: &mut Vec<u8>, out: &mut Vec<String>, alphabet: &[u8], max_len: usize) {
            out.push(String::from_utf8(current.clone()).expect("alphabet is ASCII"));
            if current.len() == max_len {
                return;
            }

            for &byte in alphabet {
                current.push(byte);
                recurse(current, out, alphabet, max_len);
                current.pop();
            }
        }

        let mut values = Vec::new();
        recurse(&mut Vec::new(), &mut values, alphabet, max_len);
        values
    }

    fn brute_force_subset(parent_pattern: &str, child_pattern: &str, max_len: usize) -> bool {
        enumerate_values(b"ab_", max_len).into_iter().all(|value| {
            !crate::verified_capability_glob::literal_child_matches_parent_glob(
                child_pattern,
                &value,
            ) || crate::verified_capability_glob::literal_child_matches_parent_glob(
                parent_pattern,
                &value,
            )
        })
    }

    #[test]
    fn test_glob_pattern_subset_accepts_narrower_child_star_prefix() {
        assert!(glob_pattern_subset("file_*", "file_read*"));
    }

    #[test]
    fn test_glob_pattern_subset_accepts_narrower_child_question_branch() {
        assert!(glob_pattern_subset("report_*", "report_??"));
    }

    #[test]
    fn test_glob_pattern_subset_rejects_broader_child_star() {
        assert!(!glob_pattern_subset("fi?", "fi*"));
    }

    #[test]
    fn test_glob_pattern_subset_is_case_insensitive() {
        assert!(glob_pattern_subset("FILE_*", "file_read*"));
    }

    #[test]
    fn test_glob_pattern_subset_matches_small_bruteforce_oracle() {
        let patterns = [
            "", "*", "?", "a", "A", "a*", "*a", "a?", "?a", "ab*", "a*b", "a?b",
        ];

        for parent in patterns {
            for child in patterns {
                assert_eq!(
                    glob_pattern_subset(parent, child),
                    brute_force_subset(parent, child, 4),
                    "subset mismatch for parent={parent:?} child={child:?}"
                );
            }
        }
    }
}
