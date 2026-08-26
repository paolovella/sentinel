// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability domain normalization and containment kernel.
//!
//! This module extracts capability-domain matching and subset checks from
//! `capability_token.rs` so `allowed_domains` no longer route through the
//! generic glob matcher. The runtime boundary is deliberately fail-closed:
//! malformed patterns, malformed domains, or unsupported metacharacter shapes
//! all deny rather than widening authority.

use std::borrow::Cow;

/// Return true when a domain pattern shape is supported by the capability
/// domain matcher.
///
/// Supported shapes are exact domains (`example.com`) and a single leading
/// wildcard label (`*.example.com`). Any other glob metacharacter placement is
/// rejected fail-closed.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn domain_pattern_shape_valid(
    has_wildcard_prefix: bool,
    has_other_metacharacters: bool,
    suffix_is_empty: bool,
) -> bool {
    !has_other_metacharacters && (!has_wildcard_prefix || !suffix_is_empty)
}

/// Return true when a normalized candidate domain is exactly the suffix or is
/// a subdomain of it with an explicit `.` boundary.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn normalized_domain_suffix_matches(
    candidate_equals_suffix: bool,
    candidate_has_suffix_with_dot_boundary: bool,
) -> bool {
    candidate_equals_suffix || candidate_has_suffix_with_dot_boundary
}

/// Return true when a normalized domain is accepted by a normalized pattern.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn normalized_domain_pattern_matches(
    pattern_is_wildcard: bool,
    wildcard_suffix_match: bool,
    exact_match: bool,
) -> bool {
    if pattern_is_wildcard {
        wildcard_suffix_match
    } else {
        exact_match
    }
}

/// Return true when the normalized child pattern is contained by the
/// normalized parent pattern.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn normalized_domain_pattern_subset(
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

fn normalize_domain_candidate<'a>(s: &'a str, allow_wildcard_prefix: bool) -> Option<Cow<'a, str>> {
    let stripped = s.trim_end_matches('.');
    if stripped.is_empty() {
        return None;
    }

    let has_wildcard_prefix = allow_wildcard_prefix && stripped.starts_with("*.");
    let idna_input = if has_wildcard_prefix {
        stripped.strip_prefix("*.")?
    } else {
        stripped
    };
    let has_other_metacharacters = idna_input.bytes().any(|b| b == b'*' || b == b'?')
        || (!has_wildcard_prefix && stripped.bytes().any(|b| b == b'*' || b == b'?'));

    if !domain_pattern_shape_valid(
        has_wildcard_prefix,
        has_other_metacharacters,
        idna_input.is_empty(),
    ) {
        return None;
    }

    let prefix = if has_wildcard_prefix { "*." } else { "" };
    let is_ascii_lower = idna_input.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_'
    });

    if idna_input.is_ascii()
        && !idna_input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        return None;
    }

    if is_ascii_lower && stripped == s {
        return Some(Cow::Borrowed(s));
    }

    if is_ascii_lower {
        return Some(Cow::Owned(format!("{prefix}{idna_input}")));
    }

    match idna::domain_to_ascii(idna_input) {
        Ok(ascii) => Some(Cow::Owned(format!(
            "{prefix}{}",
            ascii.to_ascii_lowercase()
        ))),
        Err(_) if idna_input.is_ascii() => {
            if idna_input
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
            {
                Some(Cow::Owned(format!(
                    "{prefix}{}",
                    idna_input.to_ascii_lowercase()
                )))
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

#[inline]
fn split_normalized_domain_pattern(pattern: &str) -> Option<(bool, &str)> {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if suffix.is_empty() {
            None
        } else {
            Some((true, suffix))
        }
    } else if pattern.bytes().any(|b| b == b'*' || b == b'?') {
        None
    } else {
        Some((false, pattern))
    }
}

#[inline]
fn normalized_domain_matches_suffix(candidate: &str, suffix: &str) -> bool {
    let candidate_equals_suffix = candidate == suffix;
    let candidate_has_suffix_with_dot_boundary = candidate.len() > suffix.len()
        && candidate.ends_with(suffix)
        && candidate.as_bytes()[candidate.len() - suffix.len() - 1] == b'.';
    normalized_domain_suffix_matches(
        candidate_equals_suffix,
        candidate_has_suffix_with_dot_boundary,
    )
}

#[inline]
fn normalize_domain_pattern_for_match(pattern: &str) -> Option<Cow<'_, str>> {
    normalize_domain_candidate(pattern, true)
}

#[inline]
fn normalize_domain_for_match(domain: &str) -> Option<Cow<'_, str>> {
    normalize_domain_candidate(domain, false)
}

/// Return true when the capability domain pattern covers the target domain.
#[must_use = "security decisions must not be discarded"]
pub(crate) fn domain_matches_pattern(pattern: &str, domain: &str) -> bool {
    let normalized_domain = match normalize_domain_for_match(domain) {
        Some(domain) => domain,
        None => return false,
    };
    let normalized_pattern = match normalize_domain_pattern_for_match(pattern) {
        Some(pattern) => pattern,
        None => return false,
    };
    let Some((pattern_is_wildcard, suffix)) =
        split_normalized_domain_pattern(normalized_pattern.as_ref())
    else {
        return false;
    };

    let exact_match = normalized_domain.as_ref() == suffix;
    let wildcard_suffix_match =
        normalized_domain_matches_suffix(normalized_domain.as_ref(), suffix);
    normalized_domain_pattern_matches(pattern_is_wildcard, wildcard_suffix_match, exact_match)
}

/// Return true when the child domain pattern is contained by the parent domain
/// pattern.
#[must_use = "security decisions must not be discarded"]
pub(crate) fn domain_pattern_is_subset(parent_pattern: &str, child_pattern: &str) -> bool {
    let normalized_parent = match normalize_domain_pattern_for_match(parent_pattern) {
        Some(pattern) => pattern,
        None => return false,
    };
    let normalized_child = match normalize_domain_pattern_for_match(child_pattern) {
        Some(pattern) => pattern,
        None => return false,
    };

    let Some((parent_is_wildcard, parent_suffix)) =
        split_normalized_domain_pattern(normalized_parent.as_ref())
    else {
        return false;
    };
    let Some((child_is_wildcard, child_suffix)) =
        split_normalized_domain_pattern(normalized_child.as_ref())
    else {
        return false;
    };

    let exact_patterns_equal = parent_suffix == child_suffix;
    let child_matches_parent_suffix = normalized_domain_matches_suffix(child_suffix, parent_suffix);
    normalized_domain_pattern_subset(
        parent_is_wildcard,
        child_is_wildcard,
        child_matches_parent_suffix,
        exact_patterns_equal,
    )
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_capability_domain.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the function this crate ships, which is the step that carries the proof
    //! to production. Symbol parity cannot see this: `check-verus-parity.sh`
    //! greps for names.
    //!
    //! TOTAL discharge for all four predicates: they range over 3, 2, 3 and 4
    //! booleans respectively, so every combination is enumerated.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_domain_pattern_shape_valid(
        has_wildcard_prefix: bool,
        has_other_metacharacters: bool,
        suffix_is_empty: bool,
    ) -> bool {
        !has_other_metacharacters && (!has_wildcard_prefix || !suffix_is_empty)
    }

    fn spec_normalized_domain_suffix_matches(
        candidate_equals_suffix: bool,
        candidate_has_suffix_with_dot_boundary: bool,
    ) -> bool {
        candidate_equals_suffix || candidate_has_suffix_with_dot_boundary
    }

    fn spec_normalized_domain_pattern_matches(
        pattern_is_wildcard: bool,
        wildcard_suffix_match: bool,
        exact_match: bool,
    ) -> bool {
        if pattern_is_wildcard {
            wildcard_suffix_match
        } else {
            exact_match
        }
    }

    fn spec_normalized_domain_pattern_subset(
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

    #[test]
    fn test_production_matches_verus_spec_total_domain() {
        for bits in 0u8..16 {
            let f = |i: u8| bits & (1 << i) != 0;
            let (a, b, c, d) = (f(0), f(1), f(2), f(3));

            assert_eq!(
                domain_pattern_shape_valid(a, b, c),
                spec_domain_pattern_shape_valid(a, b, c),
                "PARITY-HAND-1: domain_pattern_shape_valid disagrees at ({a}, {b}, {c})"
            );
            assert_eq!(
                normalized_domain_suffix_matches(a, b),
                spec_normalized_domain_suffix_matches(a, b),
                "PARITY-HAND-1: normalized_domain_suffix_matches disagrees at ({a}, {b})"
            );
            assert_eq!(
                normalized_domain_pattern_matches(a, b, c),
                spec_normalized_domain_pattern_matches(a, b, c),
                "PARITY-HAND-1: normalized_domain_pattern_matches disagrees at ({a}, {b}, {c})"
            );
            assert_eq!(
                normalized_domain_pattern_subset(a, b, c, d),
                spec_normalized_domain_pattern_subset(a, b, c, d),
                "PARITY-HAND-1: normalized_domain_pattern_subset disagrees at \
                 ({a}, {b}, {c}, {d})"
            );
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // A wildcard pattern with an empty suffix is `*.` and must be refused.
        assert!(!spec_domain_pattern_shape_valid(true, false, true));
        // Any other metacharacter placement is refused regardless.
        assert!(!spec_domain_pattern_shape_valid(false, true, false));
        // A wildcard child must never be contained by an exact parent.
        assert!(!spec_normalized_domain_pattern_subset(
            false, true, true, true
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_pattern_shape_valid_accepts_exact_and_prefix_wildcard() {
        assert!(domain_pattern_shape_valid(false, false, false));
        assert!(domain_pattern_shape_valid(true, false, false));
    }

    #[test]
    fn test_domain_pattern_shape_valid_rejects_bad_shapes() {
        assert!(!domain_pattern_shape_valid(true, false, true));
        assert!(!domain_pattern_shape_valid(false, true, false));
        assert!(!domain_pattern_shape_valid(true, true, false));
    }

    #[test]
    fn test_normalized_domain_suffix_matches_requires_dot_boundary() {
        assert!(normalized_domain_suffix_matches(true, false));
        assert!(normalized_domain_suffix_matches(false, true));
        assert!(!normalized_domain_suffix_matches(false, false));
    }

    #[test]
    fn test_normalize_domain_pattern_for_match_rejects_unsupported_metacharacters() {
        assert!(normalize_domain_pattern_for_match("api.*.example.com").is_none());
        assert!(normalize_domain_pattern_for_match("api?.example.com").is_none());
        assert!(normalize_domain_pattern_for_match("*example.com").is_none());
    }

    #[test]
    fn test_normalize_domain_pattern_for_match_normalizes_case_trailing_dot_and_idna() {
        let normalized = normalize_domain_pattern_for_match("*.MÜNCHEN.DE.").unwrap();
        assert_eq!(normalized.as_ref(), "*.xn--mnchen-3ya.de");
    }

    #[test]
    fn test_domain_matches_pattern_accepts_exact_and_wildcard_domains() {
        assert!(domain_matches_pattern(
            "api.example.com",
            "API.EXAMPLE.COM."
        ));
        assert!(domain_matches_pattern("*.example.com", "api.example.com"));
        assert!(domain_matches_pattern("*.example.com", "example.com"));
        assert!(!domain_matches_pattern(
            "*.example.com",
            "example.com.evil.com"
        ));
    }

    #[test]
    fn test_domain_matches_pattern_rejects_malformed_inputs() {
        assert!(!domain_matches_pattern(
            "api?.example.com",
            "api.example.com"
        ));
        assert!(!domain_matches_pattern(
            "*.example.com",
            "api.example.com:443"
        ));
        assert!(!domain_matches_pattern("*.example.com", "api example.com"));
    }

    #[test]
    fn test_domain_pattern_is_subset_accepts_exact_and_narrower_wildcards() {
        assert!(domain_pattern_is_subset("*.example.com", "api.example.com"));
        assert!(domain_pattern_is_subset(
            "*.example.com",
            "*.api.example.com"
        ));
        assert!(domain_pattern_is_subset(
            "api.example.com",
            "API.EXAMPLE.COM."
        ));
    }

    #[test]
    fn test_domain_pattern_is_subset_rejects_expanding_or_malformed_children() {
        assert!(!domain_pattern_is_subset(
            "api.example.com",
            "*.api.example.com"
        ));
        assert!(!domain_pattern_is_subset("*.example.com", "evil.com"));
        assert!(!domain_pattern_is_subset(
            "*.example.com",
            "api?.example.com"
        ));
    }
}
