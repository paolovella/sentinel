// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Capability delegation verification extracted from
//! `vellaveto-mcp/src/capability_token.rs`.
//!
//! Pure functions for grant subset checking, runtime glob-match modeling, path
//! normalization for grants. These enforce monotonic attenuation:
//! a delegated capability can never exceed its parent's permissions.
//!
//! # Verified Properties (K36-K40)
//!
//! | ID  | Property | Bridge |
//! |-----|----------|--------|
//! | K36 | grant_is_subset reflexive | S11 |
//! | K37 | No escalation (child grants ⊆ parent grants) | S11 |
//! | K38 | pattern_is_subset correctness | S11 |
//! | K39 | glob_match("*", any) == true | — |
//! | K40 | normalize_path_for_grant: no ".." in output | S11 |
//! | K41 | path_component_next_depth fails closed above root | S11 |
//!
//! # Production Correspondence
//!
//! - `pattern_matches` (metachar branch) ↔ `verified_capability_glob::literal_child_matches_parent_glob`
//! - `pattern_is_subset` ↔ `vellaveto-mcp/src/capability_token.rs:610-630`
//! - `domain_pattern_shape_valid` ↔ `vellaveto-mcp/src/verified_capability_domain.rs`
//! - `normalized_domain_pattern_subset` ↔ `vellaveto-mcp/src/verified_capability_domain.rs`
//! - `path_component_next_depth` ↔ `vellaveto-mcp/src/verified_capability_path.rs`
//! - `normalize_path_for_grant` ↔ `vellaveto-mcp/src/verified_capability_path.rs`
//! - `grant_is_subset` ↔ `vellaveto-mcp/src/capability_token.rs:598-696`

use std::collections::{HashSet, VecDeque};

const ASCII_CASE_OFFSET: u8 = b'a' - b'A';
const STAR: u8 = b'*';
const QUESTION: u8 = b'?';

/// Return true when the pattern contains capability delegation metacharacters.
pub fn has_glob_metacharacters(pattern: &str) -> bool {
    pattern.as_bytes().iter().any(|b| *b == b'*' || *b == b'?')
}

pub fn ascii_fold_byte(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        byte + ASCII_CASE_OFFSET
    } else {
        byte
    }
}

pub fn byte_eq_ignore_ascii_case(left: u8, right: u8) -> bool {
    ascii_fold_byte(left) == ascii_fold_byte(right)
}

/// Literal-only fast path from production `pattern_matches`.
pub fn literal_pattern_matches(
    pattern_has_metacharacters: bool,
    pattern_equals_value_ignore_ascii_case: bool,
) -> bool {
    !pattern_has_metacharacters && pattern_equals_value_ignore_ascii_case
}

/// Conservative child-glob guard from production `grant_is_subset`.
pub fn pattern_subset_guard(
    parent_is_wildcard: bool,
    parent_equals_child_ignore_ascii_case: bool,
    child_has_metacharacters: bool,
) -> bool {
    parent_is_wildcard || parent_equals_child_ignore_ascii_case || !child_has_metacharacters
}

/// Literal-child subset fast path from production `grant_is_subset`.
pub fn literal_child_pattern_subset(
    child_has_metacharacters: bool,
    parent_matches_child_literal: bool,
) -> bool {
    !child_has_metacharacters && parent_matches_child_literal
}

/// Restriction-shape and invocation attenuation gate from production
/// `grant_is_subset`.
pub fn grant_restrictions_attenuated(
    parent_has_allowed_paths: bool,
    child_has_allowed_paths: bool,
    parent_has_allowed_domains: bool,
    child_has_allowed_domains: bool,
    parent_max_invocations: u32,
    child_max_invocations: u32,
) -> bool {
    (!parent_has_allowed_paths || child_has_allowed_paths)
        && (!parent_has_allowed_domains || child_has_allowed_domains)
        && (parent_max_invocations == 0
            || (child_max_invocations > 0 && child_max_invocations <= parent_max_invocations))
}

/// Restriction coverage gate from production `grant_covers_action`.
pub fn grant_restrictions_cover_action(
    grant_has_allowed_paths: bool,
    action_has_target_paths: bool,
    all_target_paths_covered: bool,
    grant_has_allowed_domains: bool,
    action_has_target_domains: bool,
    all_target_domains_covered: bool,
) -> bool {
    (!grant_has_allowed_paths || (action_has_target_paths && all_target_paths_covered))
        && (!grant_has_allowed_domains || (action_has_target_domains && all_target_domains_covered))
}

/// Capability-domain shape gate from production `verified_capability_domain`.
pub fn domain_pattern_shape_valid(
    has_wildcard_prefix: bool,
    has_other_metacharacters: bool,
    suffix_is_empty: bool,
) -> bool {
    !has_other_metacharacters && (!has_wildcard_prefix || !suffix_is_empty)
}

/// Capability-domain subset gate on already normalized inputs.
pub fn normalized_domain_pattern_subset(
    parent_is_wildcard: bool,
    child_is_wildcard: bool,
    child_matches_parent_suffix: bool,
    exact_patterns_equal: bool,
) -> bool {
    if parent_is_wildcard {
        child_matches_parent_suffix
    } else {
        !child_is_wildcard && exact_patterns_equal
    }
}

/// First-match selection kernel from production `check_grant_coverage`.
pub fn next_covering_grant_index(
    selected_index: Option<usize>,
    current_index: usize,
    current_grant_covers: bool,
) -> Option<usize> {
    match selected_index {
        Some(existing_index) => Some(existing_index),
        None => {
            if current_grant_covers {
                Some(current_index)
            } else {
                None
            }
        }
    }
}

/// Fail-closed depth transition from production capability path normalization.
pub fn path_component_next_depth(
    current_depth: usize,
    component_is_empty_or_dot: bool,
    component_is_dotdot: bool,
) -> Option<usize> {
    if component_is_empty_or_dot {
        Some(current_depth)
    } else if component_is_dotdot {
        if current_depth == 0 {
            None
        } else {
            Some(current_depth - 1)
        }
    } else {
        current_depth.checked_add(1)
    }
}

/// Glob match on byte slices. Case-insensitive, supports `*` and `?`.
///
/// This remains the bounded-model witness for the runtime metachar matcher now
/// routed through `verified_capability_glob::literal_child_matches_parent_glob`.
pub fn glob_match(pattern: &[u8], value: &[u8]) -> bool {
    if pattern.len() == 1 && pattern[0] == b'*' {
        return true;
    }

    let mut pi = 0;
    let mut vi = 0;
    let mut star_pi = usize::MAX;
    let mut star_vi = 0;

    while vi < value.len() {
        // KANI-GLOB-ORDER-1: the star branch must be tested BEFORE literal
        // equality. Production's matcher treats a `*` in the pattern as a
        // wildcard unconditionally; testing equality first consumed a literal
        // `*` in the *value* against the pattern's star, so `("*?", "*")`
        // matched in production and not here. See
        // formal/ASSUMPTION_REGISTRY.md.
        if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_vi = vi;
            pi += 1;
        } else if pi < pattern.len()
            && (pattern[pi] == b'?' || pattern[pi].eq_ignore_ascii_case(&value[vi]))
        {
            pi += 1;
            vi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_vi += 1;
            vi = star_vi;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

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
        for index in 0..pattern.len() {
            if self.contains(index) && pattern[index] == STAR {
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

        for index in 0..pattern.len() {
            if !self.contains(index) {
                continue;
            }

            let token = pattern[index];
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

    if let Some(other) = (u8::MIN..=u8::MAX).find(|byte| !seen[*byte as usize]) {
        representatives.push(other);
    }

    representatives
}

pub fn glob_pattern_subset(parent_pattern: &str, child_pattern: &str) -> bool {
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
        if child_states.accepts(child) && !parent_states.accepts(parent) {
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

/// Check if `child` pattern is a subset of `parent` pattern.
///
/// Verbatim from production `pattern_is_subset`.
pub fn pattern_is_subset(parent: &str, child: &str) -> bool {
    let parent_is_wildcard = parent == "*";
    let parent_equals_child_ignore_ascii_case = parent.eq_ignore_ascii_case(child);
    let child_has_metacharacters = has_glob_metacharacters(child);

    if pattern_subset_guard(
        parent_is_wildcard,
        parent_equals_child_ignore_ascii_case,
        child_has_metacharacters,
    ) {
        if parent_is_wildcard || parent_equals_child_ignore_ascii_case {
            return true;
        }

        return literal_child_pattern_subset(
            child_has_metacharacters,
            pattern_matches(parent, child),
        );
    }

    glob_pattern_subset(parent, child)
}

/// Pattern matching helper (delegates to glob_match for glob patterns,
/// otherwise case-insensitive equality).
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pattern_has_metacharacters = has_glob_metacharacters(pattern);
    if literal_pattern_matches(
        pattern_has_metacharacters,
        pattern.eq_ignore_ascii_case(value),
    ) {
        return true;
    }
    if !pattern_has_metacharacters {
        return false;
    }
    glob_match(pattern.as_bytes(), value.as_bytes())
}

/// Normalize a path for grant comparison. Returns None on malformed input
/// (null bytes, above-root traversal).
///
/// Verbatim from production `normalize_path_for_grant`.
pub fn normalize_path_for_grant(path: &str) -> Option<String> {
    if path.contains('\0') {
        return None; // Null byte injection — fail-closed
    }
    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        let next_depth = path_component_next_depth(
            components.len(),
            component.is_empty() || component == ".",
            component == "..",
        )?;
        match next_depth.cmp(&components.len()) {
            std::cmp::Ordering::Less => {
                components.pop();
            }
            std::cmp::Ordering::Equal => {}
            std::cmp::Ordering::Greater => {
                components.push(component);
            }
        }
    }
    let normalized = if path.starts_with('/') {
        format!("/{}", components.join("/"))
    } else {
        components.join("/")
    };
    Some(normalized)
}

/// Kani-friendly byte-level grant path normalizer using fixed-size arrays.
///
/// Implements the same algorithm as [`normalize_path_for_grant`]:
/// 1. Reject null bytes
/// 2. Split on `/`, process components (skip empty/`.`, fail-closed on `..` above root)
/// 3. Preserve `/` prefix for absolute paths
///
/// Avoids Vec/String heap operations that create SAT formulas too large for CBMC.
/// Production correspondence verified by unit tests below.
pub fn normalize_path_for_grant_kani(input: &[u8]) -> Option<([u8; 16], usize)> {
    // Reject null bytes
    let mut i = 0;
    while i < input.len() {
        if input[i] == 0 {
            return None;
        }
        i += 1;
    }

    let has_root = !input.is_empty() && input[0] == b'/';

    // Component resolution matching path_component_next_depth logic:
    // - empty or "." → skip (depth unchanged)
    // - ".." at depth 0 → None (fail-closed, above-root traversal)
    // - ".." at depth > 0 → pop (depth -= 1)
    // - other → push (depth += 1)
    let mut comp_starts = [0usize; 8];
    let mut comp_lens = [0usize; 8];
    let mut depth = 0usize;

    let mut pos = 0;
    while pos < input.len() {
        let start = pos;
        while pos < input.len() && input[pos] != b'/' {
            pos += 1;
        }
        let clen = pos - start;

        let is_empty_or_dot = clen == 0 || (clen == 1 && input[start] == b'.');
        let is_dotdot = clen == 2 && input[start] == b'.' && input[start + 1] == b'.';

        if is_dotdot {
            if depth == 0 {
                return None; // fail-closed: above-root traversal
            }
            depth -= 1;
        } else if !is_empty_or_dot && depth < 8 {
            comp_starts[depth] = start;
            comp_lens[depth] = clen;
            depth += 1;
        }

        // Skip the '/' delimiter
        if pos < input.len() {
            pos += 1;
        }
    }

    // Build output
    let mut out = [0u8; 16];
    let mut out_len = 0;

    if has_root && out_len < 16 {
        out[out_len] = b'/';
        out_len += 1;
    }

    let mut ci = 0;
    while ci < depth {
        if ci > 0 && out_len < 16 {
            out[out_len] = b'/';
            out_len += 1;
        }
        let mut j = 0;
        while j < comp_lens[ci] && out_len < 16 {
            out[out_len] = input[comp_starts[ci] + j];
            out_len += 1;
            j += 1;
        }
        ci += 1;
    }

    if out_len == 0 {
        return None; // Empty result
    }

    Some((out, out_len))
}

/// A capability grant for verification.
pub struct CapabilityGrant {
    pub tool_pattern: String,
    pub function_pattern: String,
    pub allowed_paths: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub max_invocations: u32,
}

/// Check if `new_grant` is a subset of `parent_grant`.
///
/// Verbatim from production `grant_is_subset`.
pub fn grant_is_subset(new_grant: &CapabilityGrant, parent_grant: &CapabilityGrant) -> bool {
    if !pattern_is_subset(&parent_grant.tool_pattern, &new_grant.tool_pattern) {
        return false;
    }
    if !pattern_is_subset(&parent_grant.function_pattern, &new_grant.function_pattern) {
        return false;
    }
    if !grant_restrictions_attenuated(
        !parent_grant.allowed_paths.is_empty(),
        !new_grant.allowed_paths.is_empty(),
        !parent_grant.allowed_domains.is_empty(),
        !new_grant.allowed_domains.is_empty(),
        parent_grant.max_invocations,
        new_grant.max_invocations,
    ) {
        return false;
    }

    // If parent has path restrictions, child MUST also have non-empty path restrictions.
    if !parent_grant.allowed_paths.is_empty() {
        for path in &new_grant.allowed_paths {
            let normalized = match normalize_path_for_grant(path) {
                Some(n) => n,
                None => return false,
            };
            let covered = parent_grant.allowed_paths.iter().any(|pp| {
                let parent_normalized = match normalize_path_for_grant(pp) {
                    Some(n) => n,
                    None => return false,
                };
                if parent_normalized.is_empty() {
                    return false;
                }
                pattern_matches(&parent_normalized, &normalized)
            });
            if !covered {
                return false;
            }
        }
    }
    // Same check for domains.
    if !parent_grant.allowed_domains.is_empty() {
        for domain in &new_grant.allowed_domains {
            let covered = parent_grant
                .allowed_domains
                .iter()
                .any(|pd| pattern_matches(pd, domain));
            if !covered {
                return false;
            }
        }
    }
    true
}

/// Simplified action for capability coverage checking.
pub struct ActionRef<'a> {
    pub tool: &'a str,
    pub function: &'a str,
    pub target_paths: &'a [String],
    pub target_domains: &'a [String],
}

/// Check if a grant covers a specific action.
///
/// Verbatim from production `grant_covers_action` in
/// `vellaveto-mcp/src/capability_token.rs:485-537`.
///
/// Fail-closed: if grant has path/domain restrictions and action has none,
/// the grant does NOT cover the action.
pub fn grant_covers_action(grant: &CapabilityGrant, action: &ActionRef<'_>) -> bool {
    // Check tool pattern
    if !pattern_matches(&grant.tool_pattern, action.tool) {
        return false;
    }
    // Check function pattern
    if !pattern_matches(&grant.function_pattern, action.function) {
        return false;
    }
    // Check path constraints (if any)
    // SECURITY (FIND-R57-CAP-001): Fail-closed when grant requires path restrictions
    // but the action provides no target_paths.
    let grant_has_allowed_paths = !grant.allowed_paths.is_empty();
    let action_has_target_paths = !action.target_paths.is_empty();
    let all_target_paths_covered = if grant_has_allowed_paths && action_has_target_paths {
        let all_covered = action.target_paths.iter().all(|path| {
            // Fail-closed: if normalization fails, deny the grant
            let normalized = match normalize_path_for_grant(path) {
                Some(n) => n,
                None => return false,
            };
            grant
                .allowed_paths
                .iter()
                .any(|pattern| pattern_matches(pattern, &normalized))
        });
        all_covered
    } else {
        false
    };
    // Check domain constraints (if any)
    // SECURITY (FIND-R57-CAP-001): Fail-closed when grant requires domain restrictions
    // but the action provides no target_domains.
    let grant_has_allowed_domains = !grant.allowed_domains.is_empty();
    let action_has_target_domains = !action.target_domains.is_empty();
    let all_target_domains_covered = if grant_has_allowed_domains && action_has_target_domains {
        let all_covered = action.target_domains.iter().all(|domain| {
            grant
                .allowed_domains
                .iter()
                .any(|pattern| pattern_matches(pattern, domain))
        });
        all_covered
    } else {
        false
    };
    if !grant_restrictions_cover_action(
        grant_has_allowed_paths,
        action_has_target_paths,
        all_target_paths_covered,
        grant_has_allowed_domains,
        action_has_target_domains,
        all_target_domains_covered,
    ) {
        return false;
    }
    true
}

pub fn check_grant_coverage(grants: &[CapabilityGrant], action: &ActionRef<'_>) -> Option<usize> {
    let mut selected_index = None;
    for (i, grant) in grants.iter().enumerate() {
        selected_index =
            next_covering_grant_index(selected_index, i, grant_covers_action(grant, action));
    }
    selected_index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match(b"*", b"anything"));
        assert!(glob_match(b"*", b""));
        assert!(glob_match(b"*", b"*?"));
        assert!(glob_match(b"fi*", b"file.txt"));
        assert!(!glob_match(b"fi*", b"Foo"));
    }

    #[test]
    fn test_glob_match_question() {
        assert!(glob_match(b"f?le", b"file"));
        assert!(!glob_match(b"f?le", b"fiile"));
    }

    #[test]
    fn test_pattern_is_subset() {
        assert!(pattern_is_subset("*", "anything"));
        assert!(pattern_is_subset("fi*", "file"));
        assert!(pattern_is_subset("file_*", "file_read*"));
        assert!(!pattern_is_subset("fi?", "fi*"));
        assert!(pattern_is_subset("file", "file"));
    }

    #[test]
    fn test_literal_pattern_fast_path() {
        assert!(literal_pattern_matches(false, true));
        assert!(!literal_pattern_matches(false, false));
        assert!(!literal_pattern_matches(true, true));
    }

    #[test]
    fn test_pattern_subset_guard() {
        assert!(pattern_subset_guard(true, false, true));
        assert!(pattern_subset_guard(false, true, true));
        assert!(pattern_subset_guard(false, false, false));
        assert!(!pattern_subset_guard(false, false, true));
    }

    #[test]
    fn test_glob_pattern_subset() {
        assert!(glob_pattern_subset("file_*", "file_read*"));
        assert!(glob_pattern_subset("report_*", "report_??"));
        assert!(!glob_pattern_subset("fi?", "fi*"));
    }

    #[test]
    fn test_literal_child_pattern_subset() {
        assert!(literal_child_pattern_subset(false, true));
        assert!(!literal_child_pattern_subset(false, false));
        assert!(!literal_child_pattern_subset(true, true));
    }

    #[test]
    fn test_normalize_path_no_traversal() {
        assert_eq!(
            normalize_path_for_grant("/a/b/c"),
            Some("/a/b/c".to_string())
        );
        assert_eq!(normalize_path_for_grant("/a/../b"), Some("/b".to_string()));
        assert_eq!(normalize_path_for_grant("/../etc/passwd"), None); // above root
        assert_eq!(normalize_path_for_grant("/a/\0/b"), None); // null byte
    }

    #[test]
    fn test_grant_is_subset_reflexive() {
        let g = CapabilityGrant {
            tool_pattern: "read*".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec!["/home/*".to_string()],
            allowed_domains: vec!["*.example.com".to_string()],
            max_invocations: 10,
        };
        assert!(grant_is_subset(&g, &g));
    }

    #[test]
    fn test_grant_covers_matching_action() {
        let g = CapabilityGrant {
            tool_pattern: "read*".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec!["/home/*".to_string()],
            allowed_domains: vec![],
            max_invocations: 10,
        };
        let action = ActionRef {
            tool: "read_file",
            function: "execute",
            target_paths: &["/home/user/file.txt".to_string()],
            target_domains: &[],
        };
        assert!(grant_covers_action(&g, &action));
    }

    #[test]
    fn test_grant_rejects_wrong_tool() {
        let g = CapabilityGrant {
            tool_pattern: "read*".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        };
        let action = ActionRef {
            tool: "write_file",
            function: "execute",
            target_paths: &[],
            target_domains: &[],
        };
        assert!(!grant_covers_action(&g, &action));
    }

    #[test]
    fn test_grant_fail_closed_empty_paths() {
        // Grant requires paths but action provides none → fail-closed
        let g = CapabilityGrant {
            tool_pattern: "*".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec!["/safe/*".to_string()],
            allowed_domains: vec![],
            max_invocations: 0,
        };
        let action = ActionRef {
            tool: "read",
            function: "exec",
            target_paths: &[],
            target_domains: &[],
        };
        assert!(!grant_covers_action(&g, &action));
    }

    #[test]
    fn test_grant_fail_closed_empty_domains() {
        // Grant requires domains but action provides none → fail-closed
        let g = CapabilityGrant {
            tool_pattern: "*".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec!["*.example.com".to_string()],
            max_invocations: 0,
        };
        let action = ActionRef {
            tool: "fetch",
            function: "get",
            target_paths: &[],
            target_domains: &[],
        };
        assert!(!grant_covers_action(&g, &action));
    }

    #[test]
    fn test_grant_restrictions_cover_action_gate() {
        assert!(!grant_restrictions_cover_action(
            true, false, false, false, false, false
        ));
        assert!(!grant_restrictions_cover_action(
            true, true, false, false, false, false
        ));
        assert!(!grant_restrictions_cover_action(
            false, false, false, true, false, false
        ));
        assert!(!grant_restrictions_cover_action(
            false, false, false, true, true, false
        ));
        assert!(grant_restrictions_cover_action(
            true, true, true, true, true, true
        ));
    }

    #[test]
    fn test_domain_pattern_shape_valid() {
        assert!(domain_pattern_shape_valid(false, false, false));
        assert!(domain_pattern_shape_valid(true, false, false));
        assert!(!domain_pattern_shape_valid(true, false, true));
        assert!(!domain_pattern_shape_valid(false, true, false));
    }

    #[test]
    fn test_normalized_domain_pattern_subset() {
        assert!(normalized_domain_pattern_subset(true, false, true, false));
        assert!(normalized_domain_pattern_subset(true, true, true, false));
        assert!(normalized_domain_pattern_subset(false, false, false, true));
        assert!(!normalized_domain_pattern_subset(false, true, true, true));
        assert!(!normalized_domain_pattern_subset(true, false, false, true));
    }

    #[test]
    fn test_next_covering_grant_index() {
        assert_eq!(next_covering_grant_index(None, 2, false), None);
        assert_eq!(next_covering_grant_index(None, 2, true), Some(2));
        assert_eq!(next_covering_grant_index(Some(1), 2, false), Some(1));
        assert_eq!(next_covering_grant_index(Some(1), 2, true), Some(1));
    }

    #[test]
    fn test_path_component_next_depth() {
        assert_eq!(path_component_next_depth(2, true, false), Some(2));
        assert_eq!(path_component_next_depth(0, false, true), None);
        assert_eq!(path_component_next_depth(2, false, true), Some(1));
        assert_eq!(path_component_next_depth(2, false, false), Some(3));
    }

    #[test]
    fn test_check_grant_coverage_returns_first_match() {
        let grants = vec![
            CapabilityGrant {
                tool_pattern: "file_*".to_string(),
                function_pattern: "*".to_string(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 0,
            },
            CapabilityGrant {
                tool_pattern: "*".to_string(),
                function_pattern: "*".to_string(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 0,
            },
        ];
        let action = ActionRef {
            tool: "file_system",
            function: "write_file",
            target_paths: &[],
            target_domains: &[],
        };
        assert_eq!(check_grant_coverage(&grants, &action), Some(0));
    }

    #[test]
    fn test_grant_escalation_blocked() {
        let parent = CapabilityGrant {
            tool_pattern: "read*".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec!["/home/*".to_string()],
            allowed_domains: vec![],
            max_invocations: 10,
        };
        // Child tries to add broader tool pattern — should fail
        let child = CapabilityGrant {
            tool_pattern: "*".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec!["/home/user".to_string()],
            allowed_domains: vec![],
            max_invocations: 5,
        };
        assert!(!grant_is_subset(&child, &parent));
    }

    #[test]
    fn test_kani_grant_normalizer_parity() {
        let cases: &[(&[u8], Option<&str>)] = &[
            (b"/a/b/c", Some("/a/b/c")),
            (b"/a/../b", Some("/b")),
            (b"/a/./b", Some("/a/b")),
            (b"/../etc", None), // above root → fail-closed
            (b"..", None),      // above root → fail-closed
            (b"../a", None),    // above root → fail-closed
            (b"/", Some("/")),
            (b"/.", Some("/")),
            (b"a/b", Some("a/b")),
            (b"/a\x00/b", None), // null byte
        ];
        for &(input, expected) in cases {
            let result = normalize_path_for_grant_kani(input);
            let input_str = std::str::from_utf8(input).ok();
            match (result, expected) {
                (Some((buf, len)), Some(exp)) => {
                    assert_eq!(
                        &buf[..len],
                        exp.as_bytes(),
                        "kani grant normalizer mismatch for {:?}",
                        input_str
                    );
                    if let Some(s) = input_str {
                        assert_eq!(
                            normalize_path_for_grant(s).as_deref(),
                            Some(exp),
                            "production grant normalizer mismatch for {:?}",
                            s
                        );
                    }
                }
                (None, None) => {
                    if let Some(s) = input_str {
                        assert!(
                            normalize_path_for_grant(s).is_none(),
                            "production should also return None for {:?}",
                            s
                        );
                    }
                }
                (Some((buf, len)), None) => {
                    panic!(
                        "kani grant normalizer should return None for {:?}, got {:?}",
                        input_str,
                        std::str::from_utf8(&buf[..len])
                    );
                }
                (None, Some(exp)) => {
                    panic!(
                        "kani grant normalizer returned None for {:?}, expected {:?}",
                        input_str, exp
                    );
                }
            }
        }
    }
}
