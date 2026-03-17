// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Multi-modal injection indicator detection.
//!
//! Detects suspicious embedded media in tool responses that could carry
//! steganographic prompt injection payloads. Based on research showing
//! 24.3% attack success rate via image-embedded instructions across
//! GPT-4V, Claude, and LLaVA.
//!
//! This module does NOT decode images — it detects indicators that
//! suggest an image/audio/video payload is being used as an injection vector.

use serde_json::Value;

/// Maximum data URI length to scan.
const MAX_DATA_URI_LEN: usize = 10_000_000; // 10MB

/// A multi-modal injection indicator finding.
#[derive(Debug, Clone)]
pub struct MultimodalFinding {
    pub indicator_type: MultimodalIndicatorType,
    pub confidence: u32,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultimodalIndicatorType {
    /// Base64-encoded image in tool response (potential steganographic carrier).
    EmbeddedImage,
    /// Data URI with executable MIME type.
    ExecutableDataUri,
    /// Suspiciously large base64 blob (potential hidden payload).
    OversizedBlob,
    /// SVG with embedded scripts or foreignObject elements.
    SvgInjection,
    /// Audio/video data URI (potential multi-modal injection carrier).
    EmbeddedMedia,
}

/// Scan a tool response for multi-modal injection indicators.
pub fn scan_for_multimodal_indicators(text: &str) -> Vec<MultimodalFinding> {
    let mut findings = Vec::new();

    // Check for data URIs
    let mut search_from = 0;
    while let Some(pos) = text[search_from..].find("data:") {
        if findings.len() >= 50 {
            break;
        }
        let abs_pos = search_from + pos;
        let rest = &text[abs_pos..text.len().min(abs_pos + MAX_DATA_URI_LEN)];

        if let Some(f) = analyze_data_uri(rest) {
            findings.push(f);
        }
        search_from = abs_pos + 5;
    }

    // Check for base64-encoded blobs outside data URIs
    if let Some(f) = detect_large_base64_blob(text) {
        findings.push(f);
    }

    findings
}

/// Analyze a data: URI for injection indicators.
fn analyze_data_uri(uri: &str) -> Option<MultimodalFinding> {
    // Extract MIME type
    let after_data = &uri[5..]; // skip "data:"
    let mime_end = after_data.find([';', ','])?;
    let mime = &after_data[..mime_end];

    // Check for executable MIME types
    let executable_mimes = [
        "text/html",
        "text/javascript",
        "application/javascript",
        "application/x-javascript",
        "text/xml",
        "application/xml",
    ];
    if executable_mimes.iter().any(|m| mime.starts_with(m)) {
        return Some(MultimodalFinding {
            indicator_type: MultimodalIndicatorType::ExecutableDataUri,
            confidence: 90,
            description: format!("Executable data URI: {}", &mime[..mime.len().min(40)]),
        });
    }

    // Check for SVG (can contain script elements)
    if mime.starts_with("image/svg") {
        // Try to find script indicators in the base64 content
        if let Some(comma_pos) = after_data.find(',') {
            let encoded = &after_data[comma_pos + 1..after_data.len().min(comma_pos + 10000)];
            // Basic check: SVG data URIs are suspicious by default
            return Some(MultimodalFinding {
                indicator_type: MultimodalIndicatorType::SvgInjection,
                confidence: 70,
                description: format!("SVG data URI ({} bytes encoded)", encoded.len()),
            });
        }
    }

    // Check for image data URIs (potential steganographic carriers)
    if mime.starts_with("image/") {
        if let Some(comma_pos) = after_data.find(',') {
            let encoded_len = after_data[comma_pos + 1..]
                .find(['"', '\'', ')'])
                .unwrap_or(after_data.len() - comma_pos - 1);
            if encoded_len > 100_000 {
                // Large images are more suspicious as stego carriers
                return Some(MultimodalFinding {
                    indicator_type: MultimodalIndicatorType::EmbeddedImage,
                    confidence: 50,
                    description: format!(
                        "Large embedded image ({} bytes): {}",
                        encoded_len,
                        &mime[..mime.len().min(30)]
                    ),
                });
            }
        }
        return Some(MultimodalFinding {
            indicator_type: MultimodalIndicatorType::EmbeddedImage,
            confidence: 30,
            description: format!("Embedded image data URI: {}", &mime[..mime.len().min(30)]),
        });
    }

    // Audio/video
    if mime.starts_with("audio/") || mime.starts_with("video/") {
        return Some(MultimodalFinding {
            indicator_type: MultimodalIndicatorType::EmbeddedMedia,
            confidence: 40,
            description: format!("Embedded media data URI: {}", &mime[..mime.len().min(30)]),
        });
    }

    None
}

/// Detect suspiciously large base64-encoded blobs.
fn detect_large_base64_blob(text: &str) -> Option<MultimodalFinding> {
    // Look for long stretches of base64 characters (A-Z, a-z, 0-9, +, /, =)
    let mut max_b64_run = 0_usize;
    let mut current_run = 0_usize;

    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=' {
            current_run += 1;
            if current_run > max_b64_run {
                max_b64_run = current_run;
            }
        } else {
            current_run = 0;
        }
    }

    // A base64 blob > 50KB that's NOT in a data: URI is suspicious
    if max_b64_run > 50_000 && !text.contains("data:") {
        return Some(MultimodalFinding {
            indicator_type: MultimodalIndicatorType::OversizedBlob,
            confidence: 55,
            description: format!(
                "Large base64 blob ({max_b64_run} chars) without data URI wrapper"
            ),
        });
    }
    None
}

/// Scan JSON response for multi-modal indicators.
pub fn scan_json_for_multimodal(value: &Value) -> Vec<MultimodalFinding> {
    let mut all_text = String::new();
    collect_strings(value, &mut all_text, 0);
    scan_for_multimodal_indicators(&all_text)
}

fn collect_strings(value: &Value, out: &mut String, depth: usize) {
    if depth > 10 || out.len() > MAX_DATA_URI_LEN {
        return;
    }
    match value {
        Value::String(s) => {
            out.push_str(s);
            out.push('\n');
        }
        Value::Array(arr) => arr.iter().for_each(|i| collect_strings(i, out, depth + 1)),
        Value::Object(obj) => obj
            .values()
            .for_each(|v| collect_strings(v, out, depth + 1)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_executable_data_uri() {
        let text = r#"<img src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">"#;
        let findings = scan_for_multimodal_indicators(text);
        assert!(findings
            .iter()
            .any(|f| f.indicator_type == MultimodalIndicatorType::ExecutableDataUri));
    }

    #[test]
    fn test_detect_svg_injection() {
        let text = r#"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjwvc3ZnPg=="#;
        let findings = scan_for_multimodal_indicators(text);
        assert!(findings
            .iter()
            .any(|f| f.indicator_type == MultimodalIndicatorType::SvgInjection));
    }

    #[test]
    fn test_detect_embedded_image() {
        let text = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA";
        let findings = scan_for_multimodal_indicators(text);
        assert!(findings
            .iter()
            .any(|f| f.indicator_type == MultimodalIndicatorType::EmbeddedImage));
    }

    #[test]
    fn test_detect_embedded_audio() {
        let text = "data:audio/wav;base64,UklGRiAAAA";
        let findings = scan_for_multimodal_indicators(text);
        assert!(findings
            .iter()
            .any(|f| f.indicator_type == MultimodalIndicatorType::EmbeddedMedia));
    }

    #[test]
    fn test_clean_text_no_findings() {
        let text = "This is a normal tool response with no media content.";
        let findings = scan_for_multimodal_indicators(text);
        assert!(findings.is_empty());
    }
}
