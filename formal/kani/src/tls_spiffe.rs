// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! TLS SPIFFE workload identity verification.
//!
//! Extracts and verifies security-critical functions from
//! `vellaveto-tls/src/lib.rs` — SPIFFE identity parsing, hex digit
//! conversion, percent-decode UTF-8 integrity, and PQ KEX policy.
//!
//! # Verified Properties (K113-K120)
//!
//! | ID   | Property |
//! |------|----------|
//! | K113 | hex_digit: 0-9,a-f,A-F → Some(0-15), else None |
//! | K114 | hex_digit exhaustive: all 256 byte values correct |
//! | K115 | SPIFFE parse: non-spiffe URI → None |
//! | K116 | SPIFFE parse: empty trust domain → None |
//! | K117 | SPIFFE parse: uppercase/special chars in domain → None |
//! | K118 | SPIFFE parse: path traversal /../ → None |
//! | K119 | SPIFFE parse: valid URI → Some with correct fields |
//! | K120 | percent_decode: no percent → Ok(None), invalid UTF-8 → Err |
//!
//! # Production Correspondence
//!
//! - hex_digit ↔ vellaveto-tls/src/lib.rs:96-103
//! - SpiffeIdentity::parse ↔ vellaveto-tls/src/lib.rs:109-198
//! - percent_decode_workload_path ↔ vellaveto-tls/src/lib.rs:69-94

/// Hex digit conversion — verbatim from vellaveto-tls/src/lib.rs:96-103.
pub fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode a path — verbatim from vellaveto-tls/src/lib.rs:69-94.
pub fn percent_decode_workload_path(path: &str) -> Result<Option<String>, ()> {
    if !path.contains('%') {
        return Ok(None);
    }
    let mut decoded_bytes: Vec<u8> = Vec::with_capacity(path.len());
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                decoded_bytes.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        decoded_bytes.push(bytes[i]);
        i += 1;
    }
    let decoded = std::str::from_utf8(&decoded_bytes).map_err(|_| ())?;
    if decoded == path {
        Ok(None)
    } else {
        Ok(Some(decoded.to_string()))
    }
}

/// SPIFFE identity — simplified from vellaveto-tls/src/lib.rs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeIdentity {
    pub spiffe_id: String,
    pub trust_domain: String,
    pub workload_path: String,
}

impl SpiffeIdentity {
    /// Parse a SPIFFE URI — verbatim logic from vellaveto-tls/src/lib.rs:109-198.
    pub fn parse(uri: &str) -> Option<Self> {
        if !uri.starts_with("spiffe://") {
            return None;
        }

        let without_scheme = &uri[9..];
        let (trust_domain, workload_path) = if let Some(slash_pos) = without_scheme.find('/') {
            (
                without_scheme[..slash_pos].to_string(),
                without_scheme[slash_pos..].to_string(),
            )
        } else {
            (without_scheme.to_string(), String::new())
        };

        if trust_domain.is_empty() {
            return None;
        }
        if !trust_domain
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        {
            return None;
        }
        if trust_domain.starts_with('.')
            || trust_domain.starts_with('-')
            || trust_domain.ends_with('.')
            || trust_domain.ends_with('-')
        {
            return None;
        }

        if !workload_path.is_empty() {
            let decoded_path = match percent_decode_workload_path(&workload_path) {
                Ok(d) => d,
                Err(()) => return None,
            };
            let check_path = decoded_path.as_deref().unwrap_or(&workload_path);
            if check_path.contains("/../") || check_path.ends_with("/..") || check_path == "/.." {
                return None;
            }
            for c in check_path.chars() {
                if c == '\0' || c.is_control() {
                    return None;
                }
                if matches!(c,
                    '\u{00AD}' | '\u{200B}'..='\u{200F}' |
                    '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' |
                    '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' |
                    '\u{E0001}'..='\u{E007F}'
                ) {
                    return None;
                }
            }
        }

        Some(SpiffeIdentity {
            spiffe_id: uri.to_string(),
            trust_domain,
            workload_path,
        })
    }
}

/// Check if a path contains traversal sequences.
/// Byte-level extraction from SpiffeIdentity::parse() lines 155-157,
/// avoiding String::contains() for CBMC tractability.
pub fn path_has_traversal(path: &[u8]) -> bool {
    if path.len() < 3 {
        return false;
    }
    // Check for "/.." at end
    if path.len() >= 3
        && path[path.len() - 3] == b'/'
        && path[path.len() - 2] == b'.'
        && path[path.len() - 1] == b'.'
    {
        return true;
    }
    // Check for "/../" anywhere
    let mut i: usize = 0;
    while i + 3 < path.len() {
        if path[i] == b'/'
            && path[i + 1] == b'.'
            && path[i + 2] == b'.'
            && path[i + 3] == b'/'
        {
            return true;
        }
        i += 1;
    }
    false
}

/// PQ KEX policy enum — from vellaveto-tls/src/lib.rs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqKexPolicy {
    ClassicalOnly,
    HybridPreferred,
    HybridRequiredWhenSupported,
}

/// Check if a named group is PQ or hybrid.
pub fn is_pq_or_hybrid(name: &str) -> bool {
    matches!(
        name,
        "X25519Kyber768Draft00" | "X25519MLKEM768" | "SecP256r1MLKEM768" |
        "X25519Kyber768" | "SecP256r1Kyber768"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── K113: hex_digit correctness ─────────────────────────────────

    #[test]
    fn test_k113_hex_digit_digits() {
        for b in b'0'..=b'9' {
            assert_eq!(hex_digit(b), Some(b - b'0'));
        }
    }

    #[test]
    fn test_k113_hex_digit_lowercase() {
        for (i, b) in (b'a'..=b'f').enumerate() {
            assert_eq!(hex_digit(b), Some(10 + i as u8));
        }
    }

    #[test]
    fn test_k113_hex_digit_uppercase() {
        for (i, b) in (b'A'..=b'F').enumerate() {
            assert_eq!(hex_digit(b), Some(10 + i as u8));
        }
    }

    #[test]
    fn test_k113_hex_digit_non_hex() {
        assert_eq!(hex_digit(b'g'), None);
        assert_eq!(hex_digit(b'G'), None);
        assert_eq!(hex_digit(b' '), None);
        assert_eq!(hex_digit(b'\0'), None);
        assert_eq!(hex_digit(b'z'), None);
    }

    // ── K114: hex_digit exhaustive (all 256 bytes) ──────────────────

    #[test]
    fn test_k114_hex_digit_exhaustive() {
        let mut valid_count = 0;
        for b in 0u8..=255 {
            match hex_digit(b) {
                Some(v) => {
                    assert!(v <= 15, "hex_digit({b}) = {v} > 15");
                    valid_count += 1;
                }
                None => {}
            }
        }
        // Exactly 22 hex digits: 0-9 (10) + a-f (6) + A-F (6)
        assert_eq!(valid_count, 22);
    }

    // ── K115: Non-SPIFFE URI → None ─────────────────────────────────

    #[test]
    fn test_k115_non_spiffe_rejected() {
        assert_eq!(SpiffeIdentity::parse("https://example.com"), None);
        assert_eq!(SpiffeIdentity::parse("http://example.com"), None);
        assert_eq!(SpiffeIdentity::parse("spiffe:/missing-slash"), None);
        assert_eq!(SpiffeIdentity::parse(""), None);
        assert_eq!(SpiffeIdentity::parse("SPIFFE://domain/path"), None);
    }

    // ── K116: Empty trust domain → None ─────────────────────────────

    #[test]
    fn test_k116_empty_domain() {
        assert_eq!(SpiffeIdentity::parse("spiffe:///workload"), None);
        assert_eq!(SpiffeIdentity::parse("spiffe://"), None);
    }

    // ── K117: Invalid domain chars → None ───────────────────────────

    #[test]
    fn test_k117_invalid_domain_chars() {
        assert_eq!(SpiffeIdentity::parse("spiffe://DOMAIN/path"), None);
        assert_eq!(SpiffeIdentity::parse("spiffe://do main/path"), None);
        assert_eq!(SpiffeIdentity::parse("spiffe://dom@in/path"), None);
        assert_eq!(SpiffeIdentity::parse("spiffe://dom_ain/path"), None);
        assert_eq!(SpiffeIdentity::parse("spiffe://.domain/path"), None);
        assert_eq!(SpiffeIdentity::parse("spiffe://-domain/path"), None);
        assert_eq!(SpiffeIdentity::parse("spiffe://domain./path"), None);
        assert_eq!(SpiffeIdentity::parse("spiffe://domain-/path"), None);
    }

    // ── K118: Path traversal → None ─────────────────────────────────

    #[test]
    fn test_k118_path_traversal() {
        assert_eq!(SpiffeIdentity::parse("spiffe://domain/../secret"), None);
        assert_eq!(SpiffeIdentity::parse("spiffe://domain/a/../../b"), None);
        assert_eq!(SpiffeIdentity::parse("spiffe://domain/.."), None);
        // Percent-encoded traversal: %2e = '.', %2f = '/'
        assert_eq!(SpiffeIdentity::parse("spiffe://domain/%2e%2e/%2e%2e/secret"), None);
    }

    // ── K119: Valid SPIFFE URI → Some with correct fields ───────────

    #[test]
    fn test_k119_valid_parse() {
        let id = SpiffeIdentity::parse("spiffe://cluster.local/workload/api").unwrap();
        assert_eq!(id.trust_domain, "cluster.local");
        assert_eq!(id.workload_path, "/workload/api");
        assert_eq!(id.spiffe_id, "spiffe://cluster.local/workload/api");
    }

    #[test]
    fn test_k119_domain_only() {
        let id = SpiffeIdentity::parse("spiffe://example.com").unwrap();
        assert_eq!(id.trust_domain, "example.com");
        assert_eq!(id.workload_path, "");
    }

    #[test]
    fn test_k119_domain_with_numbers() {
        let id = SpiffeIdentity::parse("spiffe://k8s-cluster-01.prod/ns/default").unwrap();
        assert_eq!(id.trust_domain, "k8s-cluster-01.prod");
    }

    // ── K120: Percent decode behavior ───────────────────────────────

    #[test]
    fn test_k120_no_percent_returns_none() {
        assert_eq!(percent_decode_workload_path("/simple/path"), Ok(None));
    }

    #[test]
    fn test_k120_valid_percent_decode() {
        let result = percent_decode_workload_path("/path%20with%20spaces");
        assert_eq!(result, Ok(Some("/path with spaces".to_string())));
    }

    #[test]
    fn test_k120_invalid_utf8_returns_err() {
        // %80 is a continuation byte — not valid UTF-8 start
        let result = percent_decode_workload_path("/path%80bad");
        assert!(result.is_err(), "Invalid UTF-8 percent-decode must fail");
    }

    #[test]
    fn test_k120_soft_hyphen_decodes_but_parse_rejects() {
        // %C2%AD = U+00AD (soft hyphen) — valid UTF-8 but Unicode format char
        let result = percent_decode_workload_path("/path%C2%AD");
        assert!(result.is_ok()); // Decoding itself succeeds
        // But SpiffeIdentity::parse should reject it
        assert_eq!(
            SpiffeIdentity::parse("spiffe://domain/path%C2%AD"),
            None,
            "Percent-encoded format chars must be rejected"
        );
    }

    // ── PQ KEX policy ───────────────────────────────────────────────

    #[test]
    fn test_pq_kex_identification() {
        assert!(is_pq_or_hybrid("X25519Kyber768Draft00"));
        assert!(is_pq_or_hybrid("X25519MLKEM768"));
        assert!(is_pq_or_hybrid("SecP256r1MLKEM768"));
        assert!(!is_pq_or_hybrid("X25519"));
        assert!(!is_pq_or_hybrid("secp256r1"));
        assert!(!is_pq_or_hybrid("secp384r1"));
        assert!(!is_pq_or_hybrid(""));
    }
}
