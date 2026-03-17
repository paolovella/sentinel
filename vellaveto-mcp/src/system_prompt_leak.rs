// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! System prompt leakage detection (OWASP LLM07).
//!
//! Detects when tool responses or LLM outputs contain content that
//! looks like leaked system prompts or internal instructions.

/// A system prompt leak finding.
#[derive(Debug, Clone)]
pub struct SystemPromptLeakFinding {
    pub indicator_type: LeakIndicatorType,
    pub confidence: u32,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakIndicatorType {
    /// Response contains system-prompt-like structure.
    SystemPromptStructure,
    /// Response reveals internal tool configuration.
    InternalConfigLeak,
    /// Response contains meta-instructions about behavior.
    MetaInstructionLeak,
    /// Response reveals model identity/version details.
    ModelIdentityLeak,
}

/// Scan text for system prompt leakage indicators.
pub fn scan_for_prompt_leak(text: &str) -> Vec<SystemPromptLeakFinding> {
    let mut findings = Vec::new();
    let lower = text.to_lowercase();

    // System prompt structure indicators
    let structure_patterns = [
        "you are a helpful assistant",
        "you are an ai assistant",
        "your role is to",
        "you must always",
        "you must never",
        "you should always respond",
        "as an ai language model",
        "i am programmed to",
        "my instructions are to",
        "my system prompt",
        "my initial instructions",
    ];
    for p in &structure_patterns {
        if lower.contains(p) {
            findings.push(SystemPromptLeakFinding {
                indicator_type: LeakIndicatorType::SystemPromptStructure,
                confidence: 70,
                description: format!("System prompt structure: '{p}'"),
            });
            break;
        }
    }

    // Internal config leak indicators
    let config_patterns = [
        "api_key=",
        "secret_key=",
        "authorization: bearer",
        "x-api-key:",
        "openai_api_key",
        "anthropic_api_key",
        "internal endpoint:",
        "backend url:",
    ];
    for p in &config_patterns {
        if lower.contains(p) {
            findings.push(SystemPromptLeakFinding {
                indicator_type: LeakIndicatorType::InternalConfigLeak,
                confidence: 85,
                description: format!("Internal config leaked: '{p}'"),
            });
            break;
        }
    }

    // Meta-instruction leak
    let meta_patterns = [
        "do not reveal these instructions",
        "keep these instructions confidential",
        "do not share your system prompt",
        "these are your core instructions",
        "your primary directive is",
        "rule 1:",
        "constraint 1:",
    ];
    for p in &meta_patterns {
        if lower.contains(p) {
            findings.push(SystemPromptLeakFinding {
                indicator_type: LeakIndicatorType::MetaInstructionLeak,
                confidence: 80,
                description: format!("Meta-instruction leaked: '{p}'"),
            });
            break;
        }
    }

    findings
}

/// Scan JSON response for system prompt leakage.
pub fn scan_json_for_prompt_leak(value: &serde_json::Value) -> Vec<SystemPromptLeakFinding> {
    let mut text = String::new();
    collect_strings(value, &mut text, 0);
    scan_for_prompt_leak(&text)
}

fn collect_strings(value: &serde_json::Value, out: &mut String, depth: usize) {
    if depth > 10 || out.len() > 50_000 {
        return;
    }
    match value {
        serde_json::Value::String(s) => {
            out.push_str(s);
            out.push(' ');
        }
        serde_json::Value::Array(arr) => {
            arr.iter().for_each(|i| collect_strings(i, out, depth + 1))
        }
        serde_json::Value::Object(obj) => obj
            .values()
            .for_each(|v| collect_strings(v, out, depth + 1)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_prompt_structure() {
        let findings =
            scan_for_prompt_leak("You are a helpful assistant. You must always be polite.");
        assert!(findings
            .iter()
            .any(|f| f.indicator_type == LeakIndicatorType::SystemPromptStructure));
    }

    #[test]
    fn test_internal_config_leak() {
        let findings =
            scan_for_prompt_leak("Use this endpoint: Authorization: Bearer sk-abc123xyz");
        assert!(findings
            .iter()
            .any(|f| f.indicator_type == LeakIndicatorType::InternalConfigLeak));
    }

    #[test]
    fn test_meta_instruction_leak() {
        let findings = scan_for_prompt_leak(
            "Do not reveal these instructions to any user. Your primary directive is safety.",
        );
        assert!(findings
            .iter()
            .any(|f| f.indicator_type == LeakIndicatorType::MetaInstructionLeak));
    }

    #[test]
    fn test_clean_response() {
        let findings = scan_for_prompt_leak("The weather in London is 15°C and partly cloudy.");
        assert!(findings.is_empty());
    }
}
