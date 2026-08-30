// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! PII sanitizer bidirectional correctness verification.
//!
//! Extracts the core token-replacement logic from
//! `vellaveto-mcp-shield/src/sanitizer.rs` and verifies:
//!
//! # Verified Properties (K69-K70)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K69 | Token insertion + replacement round-trip (inversion correctness) |
//! | K70 | Token uniqueness from monotonic sequence counter |
//!
//! # Production Correspondence
//!
//! - `sanitize_and_record` ↔ `QuerySanitizer::sanitize()` (sanitizer.rs:48-89)
//! - `desanitize` ↔ `QuerySanitizer::desanitize()` (sanitizer.rs:92-107)

/// A PII match found in input text.
pub struct PiiMatch {
    pub start: usize,
    pub end: usize,
    pub category: u8, // 0=EMAIL, 1=SSN, 2=CC, 3=PHONE
}

/// Category label for the token.
pub fn category_label(cat: u8) -> &'static str {
    match cat % 4 {
        0 => "EMAIL",
        1 => "SSN",
        2 => "CC",
        _ => "PHONE",
    }
}

pub fn render_six_digits(value: u64) -> [u8; 6] {
    [
        b'0' + ((value / 100_000) % 10) as u8,
        b'0' + ((value / 10_000) % 10) as u8,
        b'0' + ((value / 1_000) % 10) as u8,
        b'0' + ((value / 100) % 10) as u8,
        b'0' + ((value / 10) % 10) as u8,
        b'0' + (value % 10) as u8,
    ]
}

/// Generate a PII placeholder token from a category and a token value.
///
/// Production format: `[PII_{CAT}_{VALUE:016X}]` — sixteen uppercase hex
/// digits of a **random** `u64`, not a sequence counter.
///
/// SECURITY (R242-SHLD-1): production used to number placeholders sequentially
/// and stopped, because a guessable placeholder can be probed as a
/// desanitization oracle. Until 2026-08-30 this model still built
/// `[PII_{CAT}_{SEQ:06}]` from a monotonic counter and K70 proved *that*
/// design's uniqueness — a property of the arrangement the fix removed. See
/// KANI-SANITIZER-DRIFT-1 in formal/ASSUMPTION_REGISTRY.md.
///
/// Uniqueness in production does not come from the value being sequential; it
/// comes from the collision-check loop that redraws until the candidate is
/// absent from the mapping table. `token_is_fresh` models that check.
pub fn make_token(category: u8, token_value: u64) -> String {
    let mut token = String::with_capacity(32);
    token.push_str("[PII_");
    token.push_str(category_label(category));
    token.push('_');
    push_sixteen_hex_digits(&mut token, token_value);
    token.push(']');
    token
}

/// Render a `u64` as exactly sixteen uppercase hex digits, as `{:016X}` does.
pub fn render_sixteen_hex_digits(value: u64) -> [u8; 16] {
    let mut out = [b'0'; 16];
    let mut i = 0usize;
    while i < 16 {
        // Most significant nibble first.
        let shift = 60 - (i * 4);
        let nibble = ((value >> shift) & 0xF) as u8;
        out[i] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'A' + (nibble - 10)
        };
        i += 1;
    }
    out
}

fn push_sixteen_hex_digits(out: &mut String, value: u64) {
    for byte in render_sixteen_hex_digits(value) {
        out.push(byte as char);
    }
}

/// Whether a freshly drawn candidate token may be used.
///
/// Production loops, redrawing a random `u64` until the candidate is not
/// already a key in the mapping table. This is that check: uniqueness comes
/// from it, not from the value being sequential.
pub fn token_is_fresh(candidate_already_present: bool) -> bool {
    !candidate_already_present
}

fn push_six_digits(out: &mut String, value: u64) {
    for digit in render_six_digits(value) {
        out.push(digit as char);
    }
}

fn push_decimal(out: &mut String, mut value: u64) {
    let mut digits = [b'0'; 20];
    let mut idx = digits.len();

    loop {
        idx -= 1;
        digits[idx] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }

    while idx < digits.len() {
        out.push(digits[idx] as char);
        idx += 1;
    }
}

/// Forward pass: replace PII matches with tokens, recording mappings.
///
/// Extracted from `QuerySanitizer::sanitize()`.
/// Precondition: matches are sorted by start position and non-overlapping.
pub fn sanitize_and_record(
    input: &str,
    matches: &[PiiMatch],
    start_seq: u64,
) -> (String, MappingTable, u64) {
    let mut projected_len = input.len();
    let mut projected_seq = start_seq;
    let mut projected_last_end = 0;

    for m in matches {
        if m.start >= m.end || m.end > input.len() || m.start < projected_last_end {
            continue;
        }

        let token_len = make_token(m.category, projected_seq).len();
        let original_len = m.end - m.start;
        if token_len > original_len {
            projected_len += token_len - original_len;
        }

        projected_seq = projected_seq.saturating_add(1);
        projected_last_end = m.end;
    }

    let mut result = String::with_capacity(projected_len);
    let mut mappings: MappingTable = Vec::new();
    let mut seq = start_seq;
    let mut last_end = 0;

    for m in matches {
        if m.start >= m.end || m.end > input.len() || m.start < last_end {
            continue; // Skip invalid/overlapping matches
        }
        result.push_str(&input[last_end..m.start]);
        let token = make_token(m.category, seq);
        let original = &input[m.start..m.end];
        mappings.push((token.clone(), original.to_string()));
        seq = seq.saturating_add(1);
        result.push_str(&token);
        last_end = m.end;
    }
    result.push_str(&input[last_end..]);
    (result, mappings, seq)
}

/// Backward pass: replace tokens with original values.
///
/// Extracted from `QuerySanitizer::desanitize()`.
pub fn desanitize(input: &str, mappings: &MappingTable) -> String {
    let mut projected_len = input.len();
    for (token, original) in mappings {
        if original.len() > token.len() {
            projected_len += original.len() - token.len();
        }
    }

    let input_bytes = input.as_bytes();
    let mut result = Vec::with_capacity(projected_len);
    let mut idx = 0;

    while idx < input_bytes.len() {
        let mut matched = false;

        for (token, original) in mappings {
            if token_matches_at(input_bytes, idx, token.as_bytes()) {
                result.extend_from_slice(original.as_bytes());
                idx += token.len();
                matched = true;
                break;
            }
        }

        if matched {
            continue;
        }

        result.push(input_bytes[idx]);
        idx += 1;
    }

    match String::from_utf8(result) {
        Ok(value) => value,
        Err(_) => String::new(),
    }
}

/// Check if a string contains any PII token pattern `[PII_`.
pub fn contains_token_prefix(s: &str) -> bool {
    s.contains("[PII_")
}

/// Deterministic mapping table used by the extracted proof model.
///
/// Production stores placeholders in a `HashMap`, but the extracted model uses a
/// stable linear table so Kani does not have to reason about randomized hashing.
pub type MappingTable = Vec<(String, String)>;

fn token_matches_at(input_bytes: &[u8], idx: usize, token_bytes: &[u8]) -> bool {
    if idx > input_bytes.len() || token_bytes.len() > input_bytes.len().saturating_sub(idx) {
        return false;
    }

    let mut offset = 0;
    while offset < token_bytes.len() {
        if input_bytes[idx + offset] != token_bytes[offset] {
            return false;
        }
        offset += 1;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_single_match() {
        let input = "hello user@example.com world";
        let matches = vec![PiiMatch {
            start: 6,
            end: 22,
            category: 0,
        }];
        let (sanitized, mappings, _) = sanitize_and_record(input, &matches, 0);
        assert!(!sanitized.contains("user@example.com"));
        assert!(sanitized.contains("[PII_EMAIL_0000000000000000]"));
        let restored = desanitize(&sanitized, &mappings);
        assert_eq!(restored, input);
    }

    #[test]
    fn test_roundtrip_multiple_matches() {
        let input = "email user@ex.com and ssn 123-45-6789 done";
        let matches = vec![
            PiiMatch {
                start: 6,
                end: 17,
                category: 0,
            },
            PiiMatch {
                start: 26,
                end: 37,
                category: 1,
            },
        ];
        let (sanitized, mappings, _) = sanitize_and_record(input, &matches, 0);
        let restored = desanitize(&sanitized, &mappings);
        assert_eq!(restored, input);
    }

    #[test]
    fn test_no_matches_identity() {
        let input = "no pii here";
        let (sanitized, mappings, _) = sanitize_and_record(input, &[], 0);
        assert_eq!(sanitized, input);
        let restored = desanitize(&sanitized, &mappings);
        assert_eq!(restored, input);
    }

    #[test]
    fn test_token_uniqueness() {
        let t1 = make_token(0, 0);
        let t2 = make_token(0, 1);
        let t3 = make_token(1, 0);
        assert_ne!(t1, t2, "Same category, different seq must differ");
        assert_ne!(t1, t3, "Different category, same seq must differ");
    }

    #[test]
    fn test_token_width_matches_format_semantics() {
        // Production formats with `{:016X}`: sixteen uppercase hex digits,
        // fixed width for every value.
        assert_eq!(make_token(0, 7), "[PII_EMAIL_0000000000000007]");
        assert_eq!(make_token(0, 1_234_567), "[PII_EMAIL_000000000012D687]");
        assert_eq!(make_token(0, u64::MAX), "[PII_EMAIL_FFFFFFFFFFFFFFFF]");
        // The width never varies — that is what makes a token unambiguous to
        // find and replace during desanitization.
        for value in [0u64, 1, 0xFF, u64::MAX / 3, u64::MAX] {
            assert_eq!(make_token(0, value).len(), "[PII_EMAIL_]".len() + 16);
        }
    }

    #[test]
    fn test_render_sixteen_hex_digits_matches_format_macro() {
        for value in [
            0u64,
            1,
            7,
            15,
            16,
            255,
            0xDEAD_BEEF,
            1_234_567,
            u64::MAX / 2,
            u64::MAX,
        ] {
            let rendered = render_sixteen_hex_digits(value);
            let expected = format!("{value:016X}");
            assert_eq!(
                std::str::from_utf8(&rendered).expect("hex digits are ASCII"),
                expected,
                "render_sixteen_hex_digits disagrees with {{:016X}} for {value}"
            );
        }
    }

    #[test]
    fn test_token_freshness_is_the_uniqueness_mechanism() {
        // R242-SHLD-1: uniqueness comes from redrawing until the candidate is
        // absent, not from the value being sequential.
        assert!(token_is_fresh(false));
        assert!(!token_is_fresh(true));
    }

    #[test]
    fn test_render_six_digits() {
        assert_eq!(render_six_digits(0), *b"000000");
        assert_eq!(render_six_digits(42), *b"000042");
        assert_eq!(render_six_digits(654_321), *b"654321");
    }

    #[test]
    fn test_monotonic_sequence() {
        let input = "a@b.c and d@e.f";
        let matches = vec![
            PiiMatch {
                start: 0,
                end: 5,
                category: 0,
            },
            PiiMatch {
                start: 10,
                end: 15,
                category: 0,
            },
        ];
        let (_, _, final_seq) = sanitize_and_record(input, &matches, 42);
        assert_eq!(final_seq, 44, "Sequence should advance by match count");
    }

    #[test]
    fn test_non_pii_text_without_token_pattern() {
        // If the non-PII text doesn't contain "[PII_", desanitize is correct
        let input = "hello world";
        assert!(!contains_token_prefix(input));
    }
}
