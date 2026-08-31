// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! IDNA domain normalization verification extracted from
//! `vellaveto-engine/src/domain.rs`.
//!
//! The production function `normalize_domain_for_match` calls the third-party
//! `idna::domain_to_ascii` crate. We abstract that call as a symbolic
//! `Result<String, ()>` so Kani can explore all success/failure paths of
//! our wrapper WITHOUT verifying the idna crate internals (which are in
//! the trust boundary).
//!
//! # Verified Properties (K61-K63)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K61 | IDNA failure on non-ASCII → None (fail-closed) |
//! | K62 | IDNA failure on ASCII domain → lowercase fallback (never None for valid ASCII) |
//! | K63 | Wildcard prefix preserved through IDNA normalization |
//!
//! # Production Correspondence
//!
//! - `normalize_domain_for_match` ↔ `vellaveto-engine/src/domain.rs:237-325`
//!
//! That correspondence is checked behaviourally by the
//! `kani_parity_differential_domain` module in
//! `vellaveto-engine/src/domain.rs`, which supplies the real `idna` result
//! for each input and requires the two wrappers to agree. Before 2026-08-28
//! nothing checked it — see PARITY-HAND-2 in
//! formal/ASSUMPTION_REGISTRY.md.

/// Normalize a domain for matching.
///
/// Abstracted from production `normalize_domain_for_match`.
/// The `idna_result` parameter replaces the `idna::domain_to_ascii` call,
/// allowing Kani to explore both success and failure paths.
pub fn normalize_domain_for_match(s: &str, idna_result: Result<String, ()>) -> Option<String> {
    // Strip trailing dots first
    let stripped = s.trim_end_matches('.');

    // Check if the domain is already pure ASCII lowercase
    let is_ascii_lower = stripped.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'*'
    });

    if is_ascii_lower && stripped == s {
        // Already normalized, no IDNA needed
        return Some(s.to_string());
    }

    if is_ascii_lower {
        // Just needed trailing dot removal
        return Some(stripped.to_string());
    }

    // Strip wildcard prefix before IDNA normalization
    let (wildcard_prefix, idna_input) = if let Some(rest) = stripped.strip_prefix("*.") {
        ("*.", rest)
    } else {
        ("", stripped)
    };

    // Reject ASCII inputs with non-domain characters BEFORE IDNA
    if idna_input.is_ascii()
        && !idna_input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        return None;
    }

    // Apply IDNA normalization (abstracted as parameter)
    match idna_result {
        Ok(ascii) => {
            if wildcard_prefix.is_empty() {
                Some(ascii)
            } else {
                let mut normalized = String::with_capacity(wildcard_prefix.len() + ascii.len());
                normalized.push_str(wildcard_prefix);
                normalized.push_str(&ascii);
                Some(normalized)
            }
        }
        Err(()) => {
            // ASCII fallback for edge cases
            if idna_input.is_ascii() {
                if idna_input
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
                {
                    let lowered_ascii = idna_input.to_ascii_lowercase();
                    let mut lowered =
                        String::with_capacity(wildcard_prefix.len() + lowered_ascii.len());
                    lowered.push_str(wildcard_prefix);
                    lowered.push_str(&lowered_ascii);
                    Some(lowered)
                } else {
                    None
                }
            } else {
                // Non-ASCII domain that fails IDNA — truly invalid
                None
            }
        }
    }
}

/// Check if a string contains only ASCII domain characters.
pub fn is_valid_ascii_domain(s: &str) -> bool {
    s.is_ascii()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_already_normalized() {
        assert_eq!(
            normalize_domain_for_match("example.com", Ok(String::new())),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_trailing_dot_stripped() {
        assert_eq!(
            normalize_domain_for_match("example.com.", Ok(String::new())),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_idna_success() {
        // Non-ASCII domain with successful IDNA
        assert_eq!(
            normalize_domain_for_match("münchen.de", Ok("xn--mnchen-3ya.de".to_string())),
            Some("xn--mnchen-3ya.de".to_string())
        );
    }

    #[test]
    fn test_idna_failure_non_ascii() {
        // Non-ASCII domain where IDNA fails → None (fail-closed)
        assert_eq!(normalize_domain_for_match("münchen.de", Err(())), None);
    }

    #[test]
    fn test_idna_failure_ascii_fallback() {
        // ASCII domain where IDNA fails → lowercase fallback
        assert_eq!(
            normalize_domain_for_match("EXAMPLE.COM", Err(())),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_wildcard_preserved() {
        assert_eq!(
            normalize_domain_for_match("*.münchen.de", Ok("xn--mnchen-3ya.de".to_string())),
            Some("*.xn--mnchen-3ya.de".to_string())
        );
    }

    #[test]
    fn test_invalid_ascii_chars_rejected() {
        assert_eq!(
            normalize_domain_for_match("exam ple.com", Ok(String::new())),
            None
        );
    }
}
