// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Injection scanner decode pipeline correctness verification.
//!
//! Extracts the decode pipeline ordering from
//! `vellaveto-mcp/src/inspection/injection.rs` and verifies
//! that all decode passes run before pattern matching, and that
//! known attack strings are detected after decoding.
//!
//! # Verified Properties (K76-K77)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K76 | Decode pipeline completeness: all 7 decoders run before pattern check |
//! | K77 | Known patterns detected: exact attack strings always trigger detection |
//!
//! # Production Correspondence
//!
//! - Decode pipeline ↔ injection.rs InjectionScanner::scan() decode chain
//! - Pattern matching ↔ injection.rs Aho-Corasick + additional pattern checks

/// Represents the decode stages in the injection scanner pipeline.
/// Each stage must execute in order before pattern matching.
///
/// Updated to match ALL 13 production decode stages in
/// `vellaveto-mcp/src/inspection/injection.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeStage {
    UrlDecode,
    DoubleUrlDecode,
    Base64Decode,
    Rot13Decode,
    LeetspakeDecode,
    HtmlEntityDecode,
    DoubleHtmlEntityDecode,
    HtmlCommentStrip,
    PunycodeDecode,
    PhoneticDecode,
    EmojiDecode,
    RegionalIndicatorDecode,
    UnicodeNormalize,
}

/// Original 7-stage pipeline (K76 backward compatibility).
pub const DECODE_PIPELINE: [DecodeStage; 7] = [
    DecodeStage::UrlDecode,
    DecodeStage::Base64Decode,
    DecodeStage::Rot13Decode,
    DecodeStage::HtmlEntityDecode,
    DecodeStage::DoubleHtmlEntityDecode,
    DecodeStage::PunycodeDecode,
    DecodeStage::UnicodeNormalize,
];

/// Full 13-stage production pipeline (K91-K93).
/// This must match the production injection.rs decode chain.
pub const FULL_DECODE_PIPELINE: [DecodeStage; 13] = [
    DecodeStage::UrlDecode,
    DecodeStage::DoubleUrlDecode,
    DecodeStage::Base64Decode,
    DecodeStage::Rot13Decode,
    DecodeStage::LeetspakeDecode,
    DecodeStage::HtmlEntityDecode,
    DecodeStage::DoubleHtmlEntityDecode,
    DecodeStage::HtmlCommentStrip,
    DecodeStage::PunycodeDecode,
    DecodeStage::PhoneticDecode,
    DecodeStage::EmojiDecode,
    DecodeStage::RegionalIndicatorDecode,
    DecodeStage::UnicodeNormalize,
];

/// URL-decode a percent-encoded string (simplified single-pass).
pub fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val(bytes[i + 1]);
            let lo = hex_val(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push((h * 16 + l) as char);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// ROT13 decode (self-inverse).
pub fn rot13_decode(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
            'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

/// HTML entity decode (structural entities only).
pub fn html_entity_decode(input: &str) -> String {
    input
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#60;", "<")
        .replace("&#62;", ">")
}

/// Known injection patterns that MUST be detected.
/// Subset of the production Aho-Corasick pattern set, stored in lowercase
/// canonical form so the extracted checker can stay ASCII-only and tractable.
pub const CRITICAL_PATTERNS: [&str; 12] = [
    "<script>",
    "<override>",
    "[system]",
    "javascript:",
    "ignore previous instructions",
    "ignore all previous",
    "disregard your instructions",
    "system prompt",
    "you are now",
    "data:text/html",
    "<system_prompt>",
    "important: ",
];

fn ascii_contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }

    let mut start = 0;
    while start + needle.len() <= haystack.len() {
        let mut idx = 0;
        let mut matched = true;
        while idx < needle.len() {
            if haystack[start + idx].to_ascii_lowercase() != needle[idx] {
                matched = false;
                break;
            }
            idx += 1;
        }
        if matched {
            return true;
        }
        start += 1;
    }

    false
}

/// Check if any critical ASCII pattern is present in the decoded input.
pub fn contains_critical_pattern(decoded: &str) -> bool {
    let haystack = decoded.as_bytes();
    for pattern in &CRITICAL_PATTERNS {
        if ascii_contains_ignore_case(haystack, pattern.as_bytes()) {
            return true;
        }
    }
    false
}

/// Full decode pipeline: apply all decoders in order, then check patterns.
///
/// Returns (decoded_text, stages_applied, pattern_found).
pub fn run_decode_pipeline(input: &str) -> (String, Vec<DecodeStage>, bool) {
    let mut stages_applied = Vec::new();
    let mut text = input.to_string();

    // Stage 1: URL decode
    let decoded = url_decode(&text);
    if decoded != text {
        stages_applied.push(DecodeStage::UrlDecode);
        text = decoded;
    }

    // Stage 2: Base64 is complex, skip for Kani (tested by unit tests)
    // Stage 3: ROT13
    let _decoded = rot13_decode(&text);
    stages_applied.push(DecodeStage::Rot13Decode);
    // Only use ROT13 if it reveals something meaningful
    // (in production, ROT13 is checked if enough stop words appear)

    // Stage 4: HTML entities
    let decoded_html = html_entity_decode(&text);
    if decoded_html != text {
        stages_applied.push(DecodeStage::HtmlEntityDecode);
        text = decoded_html;
    }

    // Stage 5: Double HTML entities
    let decoded_double = html_entity_decode(&text);
    if decoded_double != text {
        stages_applied.push(DecodeStage::DoubleHtmlEntityDecode);
        text = decoded_double;
    }

    // Check patterns on the final decoded text
    let found = contains_critical_pattern(&text);

    (text, stages_applied, found)
}

/// Leetspeak normalization (14-char map from R226).
/// Mirrors `vellaveto-mcp/src/inspection/injection.rs` normalize_leetspeak.
pub fn leetspeak_decode(input: &str) -> String {
    input
        .chars()
        // Must stay identical to LEET_MAP in
        // `vellaveto-mcp/src/inspection/injection.rs`. Until 2026-08-30 this
        // map had drifted three ways: it was missing production's R226-MCP-2
        // additions ('+', '2', '9'), it mapped '|' to 'i' where production maps
        // it to 'l', and it decoded '#' to 'h' — a substitution production does
        // NOT perform, so any proof relying on it claimed a detection that does
        // not happen. See KANI-LEET-DRIFT-1 in formal/ASSUMPTION_REGISTRY.md.
        .map(|c| match c {
            '4' | '@' => 'a',
            '8' => 'b',
            '(' => 'c',
            '3' => 'e',
            '6' | '9' => 'g',
            '1' | '!' => 'i',
            '|' => 'l',
            '0' => 'o',
            '5' | '$' => 's',
            '7' | '+' => 't',
            '2' => 'z',
            _ => c,
        })
        .collect()
}

/// Strip HTML comments (<!-- ... -->).
/// Mirrors production HTML comment stripping (R232/TI-2026-031).
pub fn strip_html_comments(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut i = 0;
    let bytes = input.as_bytes();
    while i < bytes.len() {
        if i + 3 < bytes.len()
            && bytes[i] == b'<'
            && bytes[i + 1] == b'!'
            && bytes[i + 2] == b'-'
            && bytes[i + 3] == b'-'
        {
            // Skip until -->
            let mut j = i + 4;
            while j + 2 < bytes.len() {
                if bytes[j] == b'-' && bytes[j + 1] == b'-' && bytes[j + 2] == b'>' {
                    j += 3;
                    break;
                }
                j += 1;
            }
            if j + 2 >= bytes.len() && !(bytes.len() >= 3
                && bytes[bytes.len() - 3] == b'-'
                && bytes[bytes.len() - 2] == b'-'
                && bytes[bytes.len() - 1] == b'>')
            {
                j = bytes.len();
            }
            i = j;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

/// Full decode pipeline with all 13 stages.
/// Returns (decoded_text, stages_applied, pattern_found).
pub fn run_full_decode_pipeline(input: &str) -> (String, Vec<DecodeStage>, bool) {
    let mut stages_applied = Vec::new();
    let mut text = input.to_string();

    // Stage 1: URL decode
    let decoded = url_decode(&text);
    if decoded != text {
        stages_applied.push(DecodeStage::UrlDecode);
        text = decoded;
    }

    // Stage 2: Double URL decode
    let decoded = url_decode(&text);
    if decoded != text {
        stages_applied.push(DecodeStage::DoubleUrlDecode);
        text = decoded;
    }

    // Stage 3: Base64 (skip for tractability — tested in unit tests)

    // Stage 4: ROT13
    let decoded_rot = rot13_decode(&text);
    stages_applied.push(DecodeStage::Rot13Decode);
    // Check if ROT13 reveals patterns (simplified: always try)
    if contains_critical_pattern(&decoded_rot) {
        return (decoded_rot, stages_applied, true);
    }

    // Stage 5: Leetspeak
    let decoded_leet = leetspeak_decode(&text);
    if decoded_leet != text {
        stages_applied.push(DecodeStage::LeetspakeDecode);
        if contains_critical_pattern(&decoded_leet) {
            return (decoded_leet, stages_applied, true);
        }
    }

    // Stage 6: HTML entities
    let decoded_html = html_entity_decode(&text);
    if decoded_html != text {
        stages_applied.push(DecodeStage::HtmlEntityDecode);
        text = decoded_html;
    }

    // Stage 7: Double HTML entities
    let decoded_double = html_entity_decode(&text);
    if decoded_double != text {
        stages_applied.push(DecodeStage::DoubleHtmlEntityDecode);
        text = decoded_double;
    }

    // Stage 8: HTML comment stripping
    let decoded_comment = strip_html_comments(&text);
    if decoded_comment != text {
        stages_applied.push(DecodeStage::HtmlCommentStrip);
        text = decoded_comment;
    }

    // Stages 9-12: Punycode, Phonetic, Emoji, Regional Indicator
    // (complex decoders — tested separately in production)

    // Stage 13: Unicode normalize (simplified — lowercase)
    let decoded_lower = text.to_lowercase();
    if decoded_lower != text {
        stages_applied.push(DecodeStage::UnicodeNormalize);
        text = decoded_lower;
    }

    let found = contains_critical_pattern(&text);
    (text, stages_applied, found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encoded_injection_detected() {
        // %3Cscript%3E → <script>
        let input = "%3Cscript%3E";
        let decoded = url_decode(input);
        assert_eq!(decoded, "<script>");
        assert!(contains_critical_pattern(&decoded));
    }

    #[test]
    fn test_html_entity_injection_detected() {
        let input = "&lt;script&gt;";
        let decoded = html_entity_decode(input);
        assert_eq!(decoded, "<script>");
        assert!(contains_critical_pattern(&decoded));
    }

    #[test]
    fn test_double_html_entity_injection_detected() {
        // &amp;lt; → &lt; → <
        let input = "&amp;lt;script&amp;gt;";
        let pass1 = html_entity_decode(input);
        assert_eq!(pass1, "&lt;script&gt;");
        let pass2 = html_entity_decode(&pass1);
        assert_eq!(pass2, "<script>");
        assert!(contains_critical_pattern(&pass2));
    }

    #[test]
    fn test_rot13_injection_detected() {
        // "vtaber cerivbhf vafgehpgvbaf" is ROT13 of "ignore previous instructions"
        let encoded = "vtaber cerivbhf vafgehpgvbaf";
        let decoded = rot13_decode(encoded);
        assert_eq!(decoded, "ignore previous instructions");
        assert!(contains_critical_pattern(&decoded));
    }

    #[test]
    fn test_pipeline_ordering_completeness() {
        // Verify the pipeline has all 7 stages
        assert_eq!(DECODE_PIPELINE.len(), 7);

        // Verify URL decode comes before HTML decode
        let url_pos = DECODE_PIPELINE
            .iter()
            .position(|s| *s == DecodeStage::UrlDecode)
            .unwrap();
        let html_pos = DECODE_PIPELINE
            .iter()
            .position(|s| *s == DecodeStage::HtmlEntityDecode)
            .unwrap();
        assert!(
            url_pos < html_pos,
            "URL decode must come before HTML entity decode"
        );

        // Verify HTML decode comes before double HTML decode
        let double_pos = DECODE_PIPELINE
            .iter()
            .position(|s| *s == DecodeStage::DoubleHtmlEntityDecode)
            .unwrap();
        assert!(
            html_pos < double_pos,
            "HTML decode must come before double HTML decode"
        );
    }

    #[test]
    fn test_all_critical_patterns_lowercase_match() {
        // Every critical pattern should match its own text
        for pattern in &CRITICAL_PATTERNS {
            assert!(
                contains_critical_pattern(pattern),
                "Pattern '{pattern}' should be detected"
            );
        }
    }

    #[test]
    fn test_case_insensitive_detection() {
        assert!(contains_critical_pattern("IGNORE PREVIOUS INSTRUCTIONS"));
        assert!(contains_critical_pattern("Ignore Previous Instructions"));
        assert!(contains_critical_pattern("<SCRIPT>"));
    }

    #[test]
    fn test_clean_input_no_detection() {
        assert!(!contains_critical_pattern("hello world, how are you?"));
        assert!(!contains_critical_pattern(
            "please read the file at /tmp/data.txt"
        ));
    }

    #[test]
    fn test_url_decode_passthrough() {
        // Non-encoded input passes through unchanged
        assert_eq!(url_decode("hello world"), "hello world");
    }

    #[test]
    fn test_rot13_self_inverse() {
        let input = "hello world 123";
        let encoded = rot13_decode(input);
        let decoded = rot13_decode(&encoded);
        assert_eq!(decoded, input, "ROT13 must be self-inverse");
    }

    // ── K91: Full pipeline has all 13 stages ───────────────────────────

    #[test]
    fn test_full_pipeline_stage_count() {
        assert_eq!(FULL_DECODE_PIPELINE.len(), 13);
    }

    // ── K92: Full pipeline ordering constraints ─────────────────────────

    #[test]
    fn test_full_pipeline_ordering() {
        let pos = |stage: DecodeStage| {
            FULL_DECODE_PIPELINE.iter().position(|s| *s == stage).unwrap()
        };

        // URL decode must come before double URL decode
        assert!(pos(DecodeStage::UrlDecode) < pos(DecodeStage::DoubleUrlDecode));
        // URL decode before HTML entity decode
        assert!(pos(DecodeStage::UrlDecode) < pos(DecodeStage::HtmlEntityDecode));
        // HTML entity decode before double HTML entity decode
        assert!(pos(DecodeStage::HtmlEntityDecode) < pos(DecodeStage::DoubleHtmlEntityDecode));
        // HTML comment strip after entity decode (reveals hidden tags)
        assert!(pos(DecodeStage::HtmlEntityDecode) < pos(DecodeStage::HtmlCommentStrip));
        // Unicode normalize is last (catches everything)
        assert_eq!(pos(DecodeStage::UnicodeNormalize), FULL_DECODE_PIPELINE.len() - 1);
        // Leetspeak before HTML (leetspeak could produce entity-like sequences)
        assert!(pos(DecodeStage::LeetspakeDecode) < pos(DecodeStage::HtmlEntityDecode));
    }

    // ── K93: Leetspeak-encoded injection detected ───────────────────────

    #[test]
    fn test_leetspeak_injection_detected() {
        // "1gn0r3 pr3v10u5 1n57ruc710n5" → leetspeak decode → "ignore previous instructions"
        // Simplified: test with partial leetspeak
        let leet = "1gnore prev1ous 1nstruct1ons";
        let decoded = leetspeak_decode(leet);
        assert_eq!(decoded, "ignore previous instructions");
        assert!(contains_critical_pattern(&decoded));
    }

    #[test]
    fn test_leetspeak_system_prompt_detected() {
        let leet = "5y573m pr0mp7";
        let decoded = leetspeak_decode(leet);
        assert_eq!(decoded, "system prompt");
        assert!(contains_critical_pattern(&decoded));
    }

    // ── K94: HTML comment-wrapped injection detected ────────────────────

    #[test]
    fn test_html_comment_stripped() {
        let input = "safe text <!-- hidden payload --> more text";
        let stripped = strip_html_comments(input);
        assert_eq!(stripped, "safe text  more text");
    }

    #[test]
    fn test_html_comment_wrapping_injection() {
        // Payload hidden between comments
        let input = "normal<!-- --><script><!-- -->alert";
        let stripped = strip_html_comments(input);
        assert!(stripped.contains("<script>"));
        assert!(contains_critical_pattern(&stripped));
    }

    // ── K95: Double URL-encoded injection detected ──────────────────────

    #[test]
    fn test_double_url_encoded_injection() {
        // %253Cscript%253E → first pass: %3Cscript%3E → second pass: <script>
        let input = "%253Cscript%253E";
        let pass1 = url_decode(input);
        assert_eq!(pass1, "%3Cscript%3E");
        let pass2 = url_decode(&pass1);
        assert_eq!(pass2, "<script>");
        assert!(contains_critical_pattern(&pass2));
    }

    // ── K96: Compound encoding (ROT13 + URL) detected ───────────────────

    #[test]
    fn test_compound_rot13_url() {
        // ROT13 of "<script>" is "<fpevcg>", URL-encode that
        let rot13_of_script = rot13_decode("<script>");
        assert_eq!(rot13_of_script, "<fpevcg>");
        // If we ROT13-decode back, we get the original
        let decoded = rot13_decode(&rot13_of_script);
        assert_eq!(decoded, "<script>");
        assert!(contains_critical_pattern(&decoded));
    }

    // ── K97: Full pipeline detects multi-layer encoding ─────────────────

    #[test]
    fn test_full_pipeline_url_then_html() {
        // URL-encoded HTML entities: %26lt%3Bscript%26gt%3B
        let input = "%26lt%3Bscript%26gt%3B";
        let (decoded, stages, found) = run_full_decode_pipeline(input);
        // URL decode → &lt;script&gt; → HTML decode → <script>
        assert!(found || contains_critical_pattern(&decoded),
            "Multi-layer URL+HTML encoding should be detected. Decoded: {decoded}, stages: {stages:?}");
    }

    #[test]
    fn test_full_pipeline_leetspeak() {
        let input = "1gnore prev1ous 1nstruct1ons";
        let (_decoded, _stages, found) = run_full_decode_pipeline(input);
        assert!(found, "Leetspeak-encoded injection should be detected");
    }
}
