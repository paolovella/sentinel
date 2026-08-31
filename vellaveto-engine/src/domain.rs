// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Domain extraction, matching, and validation utilities.
//!
//! This module provides functions for working with domains in URLs and patterns:
//! - Extracting domains from URLs (with security hardening against bypass attacks)
//! - Matching domains against patterns (including wildcard patterns)
//! - Validating domain patterns for policy configuration
//! - IDNA normalization for internationalized domain names

use std::borrow::Cow;

/// Validate a domain pattern for policy configuration.
///
/// Checks RFC 1035 compliance:
/// - Domain labels must be 1-63 characters
/// - Total domain length must be <= 253 characters
/// - Labels can only contain alphanumeric characters and hyphens
/// - Labels cannot start or end with a hyphen
/// - Wildcards are only allowed as a prefix (`*.domain.com`)
pub fn validate_domain_pattern(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("Domain pattern cannot be empty".to_string());
    }

    // Strip wildcard prefix if present
    let domain = if let Some(rest) = pattern.strip_prefix("*.") {
        if rest.is_empty() {
            return Err("Domain pattern '*.' has no domain after wildcard".to_string());
        }
        rest
    } else if pattern.contains('*') {
        return Err(format!(
            "Wildcard '*' is only allowed as a prefix '*.domain', found in '{pattern}'"
        ));
    } else {
        pattern
    };

    // Check total length (max 253 for a fully qualified domain name)
    if domain.len() > 253 {
        // SECURITY (R33-003): Use safe truncation to avoid panics on UTF-8 boundaries.
        // Even though domains should be ASCII, malformed inputs could contain multi-byte chars.
        let truncated: String = domain.chars().take(40).collect();
        return Err(format!(
            "Domain '{}' exceeds maximum length of 253 characters ({} chars)",
            truncated,
            domain.len()
        ));
    }

    // Validate each label
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(format!(
                "Domain '{pattern}' contains an empty label (consecutive dots or trailing dot)"
            ));
        }
        if label.len() > 63 {
            // SECURITY (R33-003): Use safe truncation to avoid panics on UTF-8 boundaries.
            let truncated: String = label.chars().take(20).collect();
            return Err(format!(
                "Label '{truncated}...' in domain '{pattern}' exceeds maximum length of 63 characters"
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "Label '{label}' in domain '{pattern}' has leading or trailing hyphen"
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!(
                "Label '{label}' in domain '{pattern}' contains invalid characters (only alphanumeric and hyphen allowed)"
            ));
        }
    }

    Ok(())
}

/// Extract the domain from a URL string.
///
/// Strips scheme, port, path, query, and fragment.
///
/// # Security
///
/// This function is hardened against various bypass attacks:
/// - Backslash normalization (WHATWG URL Standard)
/// - Percent-encoded `@` symbols in authority
/// - Fragment delimiters misused in authority
/// - IPv6 bracket handling
/// - Trailing dot normalization
pub fn extract_domain(url: &str) -> String {
    let without_scheme = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        url
    };

    // SECURITY (R22-ENG-5): Normalize backslashes to forward slashes BEFORE
    // splitting on path separator. Per the WHATWG URL Standard, `\` is treated
    // as a path separator in "special" schemes (http, https, ftp, etc.).
    // Without this, "http://evil.com\@legit.com/path" splits on '/' but the
    // `\@legit.com/path` remains in the authority portion, and after rfind('@')
    // we extract "legit.com/path" — completely wrong domain.
    let normalized = without_scheme.replace('\\', "/");
    let without_scheme = normalized.as_str();

    // Fix #8: Extract the authority portion FIRST (before the first '/', '?', or '#'),
    // then search for '@' only within the authority. This prevents
    // ?email=user@safe.com in query params from being mistaken for userinfo.
    // SECURITY (R27-ENG-1): Per RFC 3986 §3.2 and WHATWG URL Standard, the authority
    // is terminated by '/', '?', or '#' — whichever comes first. Previously only '/'
    // was checked, so URLs like "http://evil.com#@legit.com" extracted "legit.com"
    // instead of "evil.com" (the fragment '#' was not treated as an authority delimiter,
    // causing rfind('@') to find the '@' after '#' and return the wrong domain).
    let authority_raw = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);

    // Fix #30: Percent-decode the authority BEFORE searching for '@'.
    // Without this, "http://evil.com%40blocked.com/path" extracts authority
    // "evil.com%40blocked.com" — rfind('@') misses the encoded %40, and the
    // domain becomes "evil.com@blocked.com" instead of "blocked.com".
    // A standards-compliant parser decoding first would see userinfo="evil.com",
    // host="blocked.com", so we must decode before splitting on '@'.
    // SECURITY (FIND-R49-008): Strict UTF-8 decode instead of lossy.
    // On invalid UTF-8 after percent-decoding, fail-closed by returning
    // the raw authority as-is (lowercased) — no userinfo stripping attempted
    // on data we cannot safely parse.
    let decoded_authority = match percent_encoding::percent_decode_str(authority_raw).decode_utf8()
    {
        Ok(decoded) => decoded,
        Err(_) => {
            return authority_raw.to_lowercase();
        }
    };
    // SECURITY (R37-ENG-1): Strip userinfo FIRST on the decoded authority,
    // BEFORE backslash normalization. A %2F in userinfo (e.g., "evil.com%2F@legit.com")
    // decodes to '/' which would cause a wrong split if we split on '/' first.
    // Per RFC 3986, only unencoded '/' terminates the authority; the '@' delimiter
    // takes precedence for separating userinfo from host.
    let without_userinfo = if let Some(at_pos) = decoded_authority.rfind('@') {
        &decoded_authority[at_pos + 1..]
    } else {
        &*decoded_authority
    };
    // SECURITY (R26-ENG-4): Apply backslash normalization on the host portion only.
    // Input like "http://evil.com%5C@legit.com" has the host portion as "legit.com"
    // (after userinfo stripping). For host-only cases like "http://host%5Cpath",
    // the decoded backslash becomes '/' per WHATWG, splitting host from path.
    let host_normalized = without_userinfo.replace('\\', "/");
    let without_userinfo = host_normalized
        .split('/')
        .next()
        .unwrap_or(&host_normalized);

    // Strip query and fragment (shouldn't normally be in authority, but defensive)
    let host_port = without_userinfo;
    let host_port = host_port.split('?').next().unwrap_or(host_port);
    let host_port = host_port.split('#').next().unwrap_or(host_port);

    // Strip port
    let host = if let Some(bracket_end) = host_port.find(']') {
        // SECURITY (R31-ENG-5): Strip IPv6 brackets for consistent domain matching.
        // Without this, extract_domain("http://[::1]:8080/path") returns "[::1]",
        // which doesn't match a blocked domain pattern "::1".
        let start = if host_port.starts_with('[') { 1 } else { 0 };
        &host_port[start..bracket_end]
    } else if let Some(pos) = host_port.rfind(':') {
        // Only strip if what follows looks like a port number
        if host_port[pos + 1..].chars().all(|c| c.is_ascii_digit()) {
            &host_port[..pos]
        } else {
            host_port
        }
    } else {
        host_port
    };

    // SECURITY (R38-ENG-2): The host is already a substring of decoded_authority
    // (which was percent-decoded at line 3866-3867). A second percent-decode here
    // would cause double-decode: %2525 → %25 → %, enabling domain mismatch bypass.
    // Fix #33: Strip trailing dot (DNS FQDN notation) to prevent bypass.
    // "evil.com." and "evil.com" must resolve to the same domain.
    // Single allocation: lowercase first, then strip trailing dots in-place.
    let mut result = host.to_lowercase();
    while result.ends_with('.') {
        result.pop();
    }
    result
}

/// Match a domain against a pattern like `*.example.com` or `example.com`.
///
/// Both domain and pattern are normalized (lowercase, IDNA, strip trailing dots).
/// Returns `false` (fail-closed) if either domain or pattern fails IDNA normalization.
pub fn match_domain_pattern(domain: &str, pattern: &str) -> bool {
    // Normalize domain and pattern with IDNA.
    // Fail-closed: if normalization fails, treat as non-matching.
    let dom = match normalize_domain_for_match(domain) {
        Some(d) => d,
        None => return false,
    };
    let pat = match normalize_domain_for_match(pattern) {
        Some(p) => p,
        None => return false,
    };

    if let Some(suffix) = pat.strip_prefix("*.") {
        // Wildcard: domain must end with .suffix or be exactly suffix.
        // Use byte-level check to avoid format!() allocation.
        dom == suffix
            || (dom.len() > suffix.len()
                && dom.ends_with(suffix)
                && dom.as_bytes()[dom.len() - suffix.len() - 1] == b'.')
    } else {
        dom == pat
    }
}

/// Normalize a domain for matching: lowercase, strip trailing dots, apply IDNA.
///
/// SECURITY (R18-DOMAIN-1): Applies IDNA (Internationalized Domain Names in
/// Applications) normalization to convert Unicode domains to ASCII Punycode.
/// This prevents bypass attacks using internationalized domain names that
/// visually resemble blocked domains but differ in encoding.
///
/// Returns `None` if IDNA conversion fails (invalid domain) — callers should
/// treat this as fail-closed (non-matching).
pub(crate) fn normalize_domain_for_match(s: &str) -> Option<Cow<'_, str>> {
    // Strip trailing dots first
    let stripped = s.trim_end_matches('.');

    // Check if the domain is already pure ASCII lowercase
    let is_ascii_lower = stripped.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'*'
    });

    if is_ascii_lower && stripped == s {
        // Already normalized, no IDNA needed
        return Some(Cow::Borrowed(s));
    }

    if is_ascii_lower {
        // Just needed trailing dot removal
        return Some(Cow::Owned(stripped.to_string()));
    }

    // SECURITY (R25-ENG-5): Strip wildcard prefix before IDNA normalization.
    // IDNA rejects "*" as an invalid label, so "*.münchen.de" would fail
    // normalization and the pattern would never match — effectively allowing
    // the internationalized domain to bypass wildcard blocking.
    let (wildcard_prefix, idna_input) = if let Some(rest) = stripped.strip_prefix("*.") {
        ("*.", rest)
    } else {
        ("", stripped)
    };

    // SECURITY (R39-ENG-3): Reject ASCII inputs with non-domain characters BEFORE
    // IDNA processing. Some IDNA implementations accept whitespace, colons, slashes,
    // null bytes, etc. without error, creating a fail-open path where malformed domains
    // bypass blocklists. Valid domain characters: alphanumeric, hyphen, dot, underscore
    // (underscore for SRV records), and non-ASCII (handled by IDNA normalization).
    if idna_input.is_ascii()
        && !idna_input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        tracing::debug!(domain = s, "Domain contains invalid ASCII characters");
        return None;
    }

    // Apply IDNA normalization for internationalized domains
    // This converts Unicode to Punycode (e.g., "münchen.de" -> "xn--mnchen-3ya.de")
    match idna::domain_to_ascii(idna_input) {
        Ok(ascii) => {
            if wildcard_prefix.is_empty() {
                Some(Cow::Owned(ascii))
            } else {
                Some(Cow::Owned(format!("{wildcard_prefix}{ascii}")))
            }
        }
        Err(_) => {
            // SECURITY (R27-ENG-2): When IDNA normalization fails for a pure-ASCII
            // domain (e.g., underscores in SRV records like "_sip._tcp.evil.com"),
            // fall back to ASCII lowercase. Without this fallback, IDNA failure
            // returns None → match_domain_pattern returns false → blocked patterns
            // don't match → the domain passes through (fail-OPEN for blocking).
            if idna_input.is_ascii() {
                // SECURITY (R39-ENG-3): Only fall back for legitimate IDNA edge cases
                // (e.g., underscores in SRV records). Reject ASCII strings containing
                // whitespace, colons, or other non-domain characters to prevent
                // malformed domains from bypassing blocklists.
                if idna_input
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
                {
                    let lowered = format!("{}{}", wildcard_prefix, idna_input.to_ascii_lowercase());
                    tracing::debug!(
                        domain = s,
                        "IDNA normalization failed but domain is ASCII — using lowercase fallback"
                    );
                    Some(Cow::Owned(lowered))
                } else {
                    tracing::debug!(
                        domain = s,
                        "IDNA normalization failed: non-domain ASCII characters"
                    );
                    None
                }
            } else {
                // Non-ASCII domain that fails IDNA — truly invalid
                tracing::debug!(domain = s, "IDNA normalization failed for non-ASCII domain");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_domain_pattern_valid() {
        assert!(validate_domain_pattern("example.com").is_ok());
        assert!(validate_domain_pattern("sub.example.com").is_ok());
        assert!(validate_domain_pattern("*.example.com").is_ok());
        assert!(validate_domain_pattern("a-b.example.com").is_ok());
    }

    #[test]
    fn test_validate_domain_pattern_empty() {
        assert!(validate_domain_pattern("").is_err());
    }

    #[test]
    fn test_validate_domain_pattern_invalid_wildcard() {
        assert!(validate_domain_pattern("example.*.com").is_err());
        assert!(validate_domain_pattern("*example.com").is_err());
        assert!(validate_domain_pattern("*.").is_err());
    }

    #[test]
    fn test_validate_domain_pattern_invalid_label() {
        assert!(validate_domain_pattern("-example.com").is_err());
        assert!(validate_domain_pattern("example-.com").is_err());
        assert!(validate_domain_pattern("exam ple.com").is_err());
    }

    #[test]
    fn test_extract_domain_simple() {
        assert_eq!(extract_domain("https://example.com/path"), "example.com");
        assert_eq!(
            extract_domain("http://example.com:8080/path"),
            "example.com"
        );
        assert_eq!(extract_domain("example.com"), "example.com");
    }

    #[test]
    fn test_extract_domain_userinfo() {
        assert_eq!(
            extract_domain("https://user@example.com/path"),
            "example.com"
        );
        assert_eq!(
            extract_domain("https://user:pass@example.com/path"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_domain_ipv6() {
        assert_eq!(extract_domain("http://[::1]:8080/path"), "::1");
        assert_eq!(extract_domain("http://[2001:db8::1]/path"), "2001:db8::1");
    }

    #[test]
    fn test_extract_domain_trailing_dot() {
        assert_eq!(extract_domain("https://example.com./path"), "example.com");
    }

    #[test]
    fn test_match_domain_pattern_exact() {
        assert!(match_domain_pattern("example.com", "example.com"));
        assert!(!match_domain_pattern("example.com", "other.com"));
    }

    #[test]
    fn test_match_domain_pattern_wildcard() {
        assert!(match_domain_pattern("sub.example.com", "*.example.com"));
        assert!(match_domain_pattern("example.com", "*.example.com"));
        assert!(!match_domain_pattern(
            "example.com.evil.com",
            "*.example.com"
        ));
    }

    #[test]
    fn test_match_domain_pattern_case_insensitive() {
        assert!(match_domain_pattern("EXAMPLE.COM", "example.com"));
        assert!(match_domain_pattern("example.com", "EXAMPLE.COM"));
    }

    #[test]
    fn test_normalize_domain_for_match_idna() {
        // German domain with umlaut
        let norm = normalize_domain_for_match("münchen.de");
        assert!(norm.is_some());
        assert_eq!(norm.unwrap().as_ref(), "xn--mnchen-3ya.de");
    }

    #[test]
    fn test_normalize_domain_for_match_trailing_dot() {
        let norm = normalize_domain_for_match("example.com.");
        assert!(norm.is_some());
        assert_eq!(norm.unwrap().as_ref(), "example.com");
    }

    #[test]
    fn test_extract_domain_encoded_at() {
        // Percent-encoded @ in authority should be decoded
        assert_eq!(
            extract_domain("http://evil.com%40blocked.com/path"),
            "blocked.com"
        );
    }

    #[test]
    fn test_extract_domain_backslash_normalization() {
        // Backslash should be treated as path separator per WHATWG
        assert_eq!(
            extract_domain("http://evil.com\\@legit.com/path"),
            "evil.com"
        );
    }

    // ════════════════════════════════════════════════════════
    // FIND-046: Domain homoglyph / confusable tests
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_match_domain_cyrillic_homoglyph_does_not_match_latin() {
        // Cyrillic "о" (U+043E) looks like Latin "o" but is different
        // "gооgle.com" with Cyrillic "о" should NOT match "google.com"
        let cyrillic_o = "g\u{043E}\u{043E}gle.com";
        assert!(
            !match_domain_pattern(cyrillic_o, "google.com"),
            "Cyrillic homoglyph domain should not match Latin domain (normalized to different punycode)"
        );
    }

    #[test]
    fn test_match_domain_cyrillic_homoglyph_normalizes_consistently() {
        // Both sides with Cyrillic should match each other
        let cyrillic_o = "g\u{043E}\u{043E}gle.com";
        assert!(
            match_domain_pattern(cyrillic_o, cyrillic_o),
            "Identical Cyrillic domains should match"
        );
    }

    #[test]
    fn test_match_domain_zero_width_characters_in_domain() {
        // Zero-width space (U+200B) in a domain should be handled by IDNA
        // IDNA should either strip it or reject it (fail-closed)
        let zwsp = "evil\u{200B}.com";
        let result = normalize_domain_for_match(zwsp);
        // Acceptable: either normalizes to "evil.com" or fails (None)
        // What's NOT acceptable: it normalizes to something that bypasses blocklists
        if let Some(normalized) = &result {
            // If it normalizes, it should match evil.com
            assert!(
                match_domain_pattern(zwsp, "evil.com") || normalized.contains("xn--"),
                "Zero-width domain should either match evil.com or become punycode, got: {normalized}"
            );
        }
        // If result is None, that's also fine (fail-closed)
    }

    #[test]
    fn test_match_domain_fullwidth_latin_characters() {
        // Fullwidth Latin 'e' (U+FF45) should be handled by IDNA normalization
        let fullwidth_e = "\u{FF45}xample.com";
        let result = normalize_domain_for_match(fullwidth_e);
        // IDNA may normalize to "example.com" or reject it
        if let Some(normalized) = &result {
            // If normalized, verify it maps to punycode or the ASCII equivalent
            assert!(
                normalized.as_ref() == "example.com" || normalized.contains("xn--"),
                "Fullwidth should normalize to example.com or punycode, got: {normalized}"
            );
        }
        // None is also acceptable (fail-closed)
    }

    #[test]
    fn test_match_domain_mixed_script_fails_closed() {
        // Mixed Latin + Cyrillic in same label — IDNA should reject or normalize to punycode
        let mixed = "g\u{043E}ogle.com"; // Cyrillic "о" + Latin "o"
        let result = normalize_domain_for_match(mixed);
        // Must NOT match "google.com" — that would be a security bypass
        assert!(
            !match_domain_pattern(mixed, "google.com"),
            "Mixed-script domain must not match pure ASCII equivalent"
        );
        // Either normalize to punycode (different from google.com) or reject
        if let Some(normalized) = &result {
            assert_ne!(
                normalized.as_ref(),
                "google.com",
                "Mixed-script must not silently normalize to ASCII lookalike"
            );
        }
    }

    #[test]
    fn test_match_domain_combining_character_diacritics() {
        // "a" + combining acute accent (U+0301) = "á"
        let combining = "ex\u{0301}mple.com";
        let result = normalize_domain_for_match(combining);
        // Should NOT match "example.com" — the diacritic changes the domain
        assert!(
            !match_domain_pattern(combining, "example.com"),
            "Domain with combining diacritics should not match plain ASCII"
        );
        // If normalized, should be punycode
        if let Some(normalized) = &result {
            assert!(
                normalized.contains("xn--") || normalized.as_ref() != "example.com",
                "Combining diacritics should produce different normalized form"
            );
        }
    }

    #[test]
    fn test_normalize_domain_for_match_rejects_invalid_ascii() {
        // Domains with spaces, colons, etc. should be rejected
        assert!(normalize_domain_for_match("evil .com").is_none());
        assert!(normalize_domain_for_match("evil:com").is_none());
        assert!(normalize_domain_for_match("evil\ncom").is_none());
    }
}

#[cfg(test)]
// Suppressed rather than satisfied: linting the extraction would edit the copy
// the Kani proofs run against. See `kani_path_differential`.
#[allow(clippy::manual_range_contains, dead_code, unused_imports)]
mod kani_domain_extraction {
    include!(concat!(env!("OUT_DIR"), "/kani_domain_extraction.rs"));
}

#[cfg(test)]
mod kani_parity_differential_domain {
    //! Differential binding for `PARITY-HAND-2` — domain normalization.
    //!
    //! `formal/kani/src/domain.rs` abstracts the third-party `idna` call as a
    //! symbolic `Result<String, ()>` parameter, so K61-K63 explore every
    //! success/failure path of the wrapper without verifying the crate's
    //! internals — which is the right boundary to draw, and is declared.
    //!
    //! What was never checked is whether the *wrapper* the proofs explore is
    //! the wrapper that runs. This binding supplies the real `idna` result for
    //! each input and requires the two to produce the same normalized domain.
    //!
    //! What rides on it: `normalize_domain_for_match` decides whether a domain
    //! matches a blocklist pattern. R27-ENG-2 and R39-ENG-3 both record
    //! fail-open bypasses in exactly this function — an IDNA failure returning
    //! `None` means a blocked pattern does not match and the domain passes. So
    //! a proof about a wrapper that is not this one is worth very little.

    use super::kani_domain_extraction as extracted;
    use super::normalize_domain_for_match;

    /// Inputs spanning what the function branches on: pure ASCII, trailing
    /// dots, wildcards, internationalized labels, the SRV underscore case that
    /// R27-ENG-2 is about, and the malformed-ASCII shapes R39-ENG-3 rejects.
    const CORPUS: &[&str] = &[
        "",
        ".",
        "example.com",
        "EXAMPLE.COM",
        "Example.Com",
        "example.com.",
        "example.com..",
        "*.example.com",
        "*.EXAMPLE.COM",
        "*.example.com.",
        "*",
        "*.",
        "sub.example.com",
        "a.b.c.d.example.com",
        "_sip._tcp.example.com",
        "_sip._tcp.EXAMPLE.com",
        "*._sip.example.com",
        "xn--mnchen-3ya.de",
        "münchen.de",
        "MÜNCHEN.de",
        "*.münchen.de",
        "münchen.de.",
        "日本.jp",
        "*.日本.jp",
        "exa mple.com",
        "example.com:8080",
        "example.com/path",
        "example\0.com",
        "example..com",
        "-example.com",
        "example-.com",
        "example.com-",
        "127.0.0.1",
        "[::1]",
        "example_underscore.com",
        "ex%41mple.com",
        "example.com\u{200b}",
        "exam\u{202e}ple.com",
    ];

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/domain.rs was not found, so this binding compared nothing"
        );
    }

    /// Feed the extraction the same IDNA answer production gets, and require
    /// the wrappers to agree.
    ///
    /// The extraction is given the IDNA result for the string production would
    /// hand to IDNA — after trailing dots and the wildcard prefix are stripped
    /// — because that stripping is part of the wrapper, and getting it wrong is
    /// exactly the R25-ENG-5 bypass the wildcard handling exists to close.
    #[test]
    fn test_domain_normalization_matches_production() {
        for raw in CORPUS {
            let stripped = raw.trim_end_matches('.');
            let idna_input = stripped.strip_prefix("*.").unwrap_or(stripped);
            let idna_result = idna::domain_to_ascii(idna_input).map_err(|_| ());

            let production = normalize_domain_for_match(raw).map(|c| c.into_owned());
            let model = extracted::normalize_domain_for_match(raw, idna_result);

            assert_eq!(
                production, model,
                "PARITY-HAND-2: production and the Kani domain model normalize \
                 {raw:?} differently (production {production:?}, model {model:?}) \
                 — K61-K63 are about a wrapper that is not the one deciding \
                 whether a domain matches a blocklist pattern"
            );
        }
        assert!(CORPUS.len() >= 35, "corpus shrank; recount before trusting");
    }

    /// K61-K63 restated against the pair, so the named properties are checked
    /// on production and not only on the model.
    #[test]
    fn test_named_properties_hold_on_production() {
        // K63: a wildcard prefix survives normalization of an IDN.
        let wildcard = normalize_domain_for_match("*.münchen.de")
            .expect("an internationalized wildcard must normalize, not vanish");
        assert!(
            wildcard.starts_with("*."),
            "K63: the wildcard prefix was lost, so *.münchen.de would never match \
             and the R25-ENG-5 bypass is back"
        );

        // K62: a valid ASCII domain never normalizes to None, even when IDNA
        // rejects it — the R27-ENG-2 fail-open.
        for ascii in ["_sip._tcp.example.com", "example.com", "a-b.example.com"] {
            assert!(
                normalize_domain_for_match(ascii).is_some(),
                "K62: {ascii:?} normalized to None; a blocked pattern would not \
                 match it and the domain would pass"
            );
        }

        // K61 / R39-ENG-3: malformed ASCII is rejected rather than smuggled
        // through as a domain.
        for malformed in ["exa mple.com", "example.com:8080", "example.com/path"] {
            assert!(
                normalize_domain_for_match(malformed).is_none(),
                "R39-ENG-3: {malformed:?} was accepted as a domain"
            );
        }
    }

    /// The corpus must reach both outcomes, or agreement is vacuous.
    #[test]
    fn test_corpus_reaches_both_outcomes() {
        let mut some = 0usize;
        let mut none = 0usize;
        for raw in CORPUS {
            if normalize_domain_for_match(raw).is_some() {
                some += 1;
            } else {
                none += 1;
            }
        }
        assert!(
            some > 0 && none > 0,
            "corpus is one-sided (Some {some}, None {none}); it cannot distinguish \
             a wrapper that accepts everything"
        );
    }
}
