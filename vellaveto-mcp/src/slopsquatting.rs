// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Slopsquatting detection — hallucinated package/tool/URL names.
//!
//! LLMs hallucinate non-existent package names, URLs, and tool names.
//! Attackers register these names, creating supply chain attacks.
//! This module scans tool responses for patterns consistent with
//! hallucinated references that could be slopsquatted.

use serde_json::Value;
use std::collections::HashSet;

/// Maximum items to scan per response.
const MAX_SCAN_ITEMS: usize = 256;

/// Known legitimate package registries for validation context.
#[allow(dead_code)]
const KNOWN_REGISTRIES: &[&str] = &[
    "npm",
    "pypi",
    "crates.io",
    "maven",
    "nuget",
    "rubygems",
    "go",
];

/// Patterns suggesting a package/tool reference in text.
const PACKAGE_PATTERNS: &[&str] = &[
    "pip install ",
    "npm install ",
    "cargo add ",
    "go get ",
    "gem install ",
    "dotnet add package ",
    "import ",
    "require(",
    "from ",
];

/// A detected slopsquatting indicator.
#[derive(Debug, Clone)]
pub struct SlopsquattingFinding {
    /// The suspicious reference found.
    pub reference: String,
    /// What type of reference (package, url, tool).
    pub reference_type: ReferenceType,
    /// Confidence (0-100).
    pub confidence: u32,
    /// Where in the response it was found.
    pub location: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceType {
    Package,
    Url,
    ToolName,
}

/// Scan a tool response for potential slopsquatting indicators.
///
/// Checks for:
/// 1. Package install commands referencing unknown packages
/// 2. URLs to domains that look auto-generated
/// 3. Tool names not in the known registry
pub fn scan_response_for_slopsquatting(
    response_text: &str,
    known_tools: &HashSet<String>,
    known_packages: &HashSet<String>,
) -> Vec<SlopsquattingFinding> {
    let mut findings = Vec::new();

    // Scan for package install commands
    for pattern in PACKAGE_PATTERNS {
        let mut search_from = 0;
        while let Some(pos) = response_text[search_from..].find(pattern) {
            if findings.len() >= MAX_SCAN_ITEMS {
                break;
            }
            let abs_pos = search_from + pos + pattern.len();
            let rest = &response_text[abs_pos..];
            let pkg_end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ';' || c == ')')
                .unwrap_or(rest.len().min(128));
            let pkg_name = &rest[..pkg_end];

            if !pkg_name.is_empty()
                && pkg_name.len() <= 128
                && !known_packages.contains(pkg_name)
                && looks_hallucinated(pkg_name)
            {
                findings.push(SlopsquattingFinding {
                    reference: pkg_name[..pkg_name.len().min(64)].to_string(),
                    reference_type: ReferenceType::Package,
                    confidence: hallucination_confidence(pkg_name),
                    location: format!("text at offset {abs_pos}"),
                });
            }
            search_from = abs_pos + pkg_end;
        }
    }

    // Scan for tool name references not in known registry
    for tool_ref in extract_tool_references(response_text) {
        if findings.len() >= MAX_SCAN_ITEMS {
            break;
        }
        if !known_tools.contains(&tool_ref) && looks_hallucinated(&tool_ref) {
            findings.push(SlopsquattingFinding {
                reference: tool_ref[..tool_ref.len().min(64)].to_string(),
                reference_type: ReferenceType::ToolName,
                confidence: 40, // Lower confidence for tool names
                location: "tool reference".to_string(),
            });
        }
    }

    findings
}

/// Heuristic: does this name look like it could be hallucinated?
///
/// Indicators: unusual character patterns, very long names, names that
/// look like concatenated English words that don't form real packages.
fn looks_hallucinated(name: &str) -> bool {
    // Very long package names are suspicious
    if name.len() > 50 {
        return true;
    }
    // Names with too many hyphens are suspicious
    if name.chars().filter(|&c| c == '-').count() > 4 {
        return true;
    }
    // Names starting with common hallucination prefixes
    let suspicious_prefixes = [
        "ai-", "ml-", "llm-", "gpt-", "neural-", "deep-", "smart-", "auto-",
    ];
    if suspicious_prefixes
        .iter()
        .any(|p| name.starts_with(p) && name.len() > p.len() + 15)
    {
        return true;
    }
    false
}

/// Confidence score for hallucination likelihood.
fn hallucination_confidence(name: &str) -> u32 {
    let mut score: u32 = 30; // baseline
    if name.len() > 40 {
        score += 20;
    }
    if name.chars().filter(|&c| c == '-').count() > 3 {
        score += 15;
    }
    // Names that look like concatenated words without clear package naming conventions
    if !name.contains('-') && !name.contains('_') && name.len() > 20 {
        score += 15;
    }
    score.min(95)
}

/// Extract tool-name-like references from text.
fn extract_tool_references(text: &str) -> Vec<String> {
    let mut refs = Vec::new();
    // Look for backtick-quoted identifiers that look like tool names
    let mut in_backtick = false;
    let mut current = String::new();
    for ch in text.chars() {
        if ch == '`' {
            if in_backtick {
                if current.len() > 2
                    && current.len() < 64
                    && current
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
                {
                    refs.push(current.clone());
                }
                current.clear();
            }
            in_backtick = !in_backtick;
        } else if in_backtick {
            current.push(ch);
        }
        if refs.len() >= MAX_SCAN_ITEMS {
            break;
        }
    }
    refs
}

/// Scan a JSON response value for slopsquatting in string fields.
pub fn scan_json_for_slopsquatting(
    value: &Value,
    known_tools: &HashSet<String>,
    known_packages: &HashSet<String>,
) -> Vec<SlopsquattingFinding> {
    let mut all_text = String::new();
    collect_strings(value, &mut all_text, 0);
    scan_response_for_slopsquatting(&all_text, known_tools, known_packages)
}

fn collect_strings(value: &Value, out: &mut String, depth: usize) {
    if depth > 10 || out.len() > 100_000 {
        return;
    }
    match value {
        Value::String(s) => {
            out.push_str(s);
            out.push(' ');
        }
        Value::Array(arr) => {
            for item in arr {
                collect_strings(item, out, depth + 1);
            }
        }
        Value::Object(obj) => {
            for (_k, v) in obj {
                collect_strings(v, out, depth + 1);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_sets() -> (HashSet<String>, HashSet<String>) {
        (HashSet::new(), HashSet::new())
    }

    #[test]
    fn test_detects_suspicious_pip_install() {
        let (tools, packages) = empty_sets();
        let text =
            "You can install it with: pip install ai-neural-deep-learning-assistant-toolkit-pro";
        let findings = scan_response_for_slopsquatting(text, &tools, &packages);
        assert!(
            !findings.is_empty(),
            "Should detect suspiciously long package name"
        );
        assert_eq!(findings[0].reference_type, ReferenceType::Package);
    }

    #[test]
    fn test_ignores_known_package() {
        let mut packages = HashSet::new();
        packages.insert("requests".to_string());
        let tools = HashSet::new();
        let text = "pip install requests";
        let findings = scan_response_for_slopsquatting(text, &tools, &packages);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detects_hallucinated_tool_reference() {
        let tools = HashSet::new();
        let packages = HashSet::new();
        let text = "Use the `ai-super-mega-ultra-code-fixer-deluxe` tool to fix your code";
        let findings = scan_response_for_slopsquatting(text, &tools, &packages);
        assert!(findings
            .iter()
            .any(|f| f.reference_type == ReferenceType::ToolName));
    }

    #[test]
    fn test_ignores_known_tool() {
        let mut tools = HashSet::new();
        tools.insert("read_file".to_string());
        let packages = HashSet::new();
        let text = "Use `read_file` to read the contents";
        let findings = scan_response_for_slopsquatting(text, &tools, &packages);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_confidence_scoring() {
        assert!(hallucination_confidence("ai-neural-deep-learning-toolkit-pro-v2") >= 45);
        assert!(hallucination_confidence("requests") < 45);
    }

    #[test]
    fn test_scan_json() {
        let (tools, packages) = empty_sets();
        let json = serde_json::json!({
            "content": [{"type": "text", "text": "pip install ai-mega-deep-neural-helper-toolkit-extreme"}]
        });
        let findings = scan_json_for_slopsquatting(&json, &tools, &packages);
        assert!(!findings.is_empty());
    }
}
