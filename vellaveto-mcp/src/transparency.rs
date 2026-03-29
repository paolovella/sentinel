// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! EU AI Act Article 50 Runtime Transparency.
//!
//! Art 50(1) requires AI-mediated output to be marked so that recipients
//! know they are interacting with an AI system. Art 14 requires human
//! oversight for high-risk tools.
//!
//! This module provides two runtime features:
//! 1. **Transparency marking** — Injects `_meta.vellaveto_ai_mediated: true`
//!    into tool-call responses before forwarding to the agent.
//! 2. **Human oversight matching** — Checks whether a tool name matches
//!    configurable glob patterns for human oversight.

/// Check if a tool name matches any human oversight glob patterns.
///
/// Returns `true` if the tool matches at least one pattern. An empty
/// pattern list always returns `false`.
///
/// Patterns use simple glob matching: `*` matches any sequence of
/// characters, `?` matches a single character.
pub fn requires_human_oversight(tool: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }
    for pattern in patterns {
        if glob_match(pattern, tool) {
            return true;
        }
    }
    false
}

/// Inject transparency marking into a JSON-RPC response.
///
/// Adds `result._meta.vellaveto_ai_mediated = true` if the message
/// contains a `result` field (i.e., it's a successful response).
/// Error responses are not modified.
pub fn mark_ai_mediated(msg: &mut serde_json::Value) {
    if let Some(result) = msg.get_mut("result") {
        if let Some(obj) = result.as_object_mut() {
            let meta = obj.entry("_meta").or_insert_with(|| serde_json::json!({}));
            if let Some(meta_obj) = meta.as_object_mut() {
                meta_obj.insert(
                    "vellaveto_ai_mediated".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
        }
    }
}

/// Inject a structured decision explanation into a JSON-RPC response.
///
/// Adds `result._meta.vellaveto_decision_explanation` when a trace is available
/// and verbosity is not `None`. Same `result._meta` pattern as `mark_ai_mediated`.
///
/// `is_admin`: when false, `Full` verbosity is downgraded to `Summary` to prevent
/// leaking internal policy structure (names, priorities, constraint details) to
/// unauthorized agents.
pub fn inject_decision_explanation(
    msg: &mut serde_json::Value,
    trace: Option<&vellaveto_types::EvaluationTrace>,
    verbosity: vellaveto_types::ExplanationVerbosity,
    is_admin: bool,
) {
    use vellaveto_types::ExplanationVerbosity;

    let trace = match trace {
        Some(t) => t,
        None => return,
    };

    if verbosity == ExplanationVerbosity::None {
        return;
    }

    // SECURITY: Downgrade Full → Summary for non-admin callers to prevent
    // leaking policy names, types, priorities, and constraint details.
    let effective_verbosity = if verbosity == ExplanationVerbosity::Full && !is_admin {
        tracing::debug!("transparency: downgrading Full verbosity to Summary for non-admin caller");
        ExplanationVerbosity::Summary
    } else {
        verbosity
    };

    let explanation = match effective_verbosity {
        ExplanationVerbosity::Summary => vellaveto_types::VerdictExplanation::summary(trace),
        ExplanationVerbosity::Full => vellaveto_types::VerdictExplanation::full(trace),
        ExplanationVerbosity::None => return, // already handled above
    };

    // SECURITY (FIND-R182-005): Bound serialized explanation size. With many
    // policies, Full verbosity can produce multi-MB explanations inflating every
    // proxied response. Fall back to Summary if Full exceeds the cap.
    const MAX_EXPLANATION_SIZE: usize = 65_536; // 64 KiB

    if let Some(result) = msg.get_mut("result") {
        if let Some(obj) = result.as_object_mut() {
            let meta = obj.entry("_meta").or_insert_with(|| serde_json::json!({}));
            if let Some(meta_obj) = meta.as_object_mut() {
                if let Ok(explanation_value) = serde_json::to_value(&explanation) {
                    // SECURITY (IMP-R182-006): unwrap_or(usize::MAX) instead of 0
                    // so serialization failure triggers the fallback (fail-closed).
                    let size = serde_json::to_string(&explanation_value)
                        .map(|s| s.len())
                        .unwrap_or(usize::MAX);
                    if size <= MAX_EXPLANATION_SIZE {
                        meta_obj.insert(
                            "vellaveto_decision_explanation".to_string(),
                            explanation_value,
                        );
                    } else {
                        tracing::warn!(
                            size = size,
                            max = MAX_EXPLANATION_SIZE,
                            "Decision explanation too large, falling back to summary"
                        );
                        let summary = vellaveto_types::VerdictExplanation::summary(trace);
                        if let Ok(summary_value) = serde_json::to_value(&summary) {
                            // SECURITY (IMP-R182-007): Also bound the Summary fallback.
                            let summary_size = serde_json::to_string(&summary_value)
                                .map(|s| s.len())
                                .unwrap_or(usize::MAX);
                            if summary_size <= MAX_EXPLANATION_SIZE {
                                meta_obj.insert(
                                    "vellaveto_decision_explanation".to_string(),
                                    summary_value,
                                );
                            } else {
                                tracing::warn!(
                                    size = summary_size,
                                    max = MAX_EXPLANATION_SIZE,
                                    "Summary explanation also too large, omitting entirely"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Simple glob matching supporting `*` and `?`.
///
/// Delegates to the shared implementation in `crate::util`.
fn glob_match(pattern: &str, text: &str) -> bool {
    crate::util::glob_match(pattern, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mark_ai_mediated_adds_meta() {
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": "hello"}
        });
        mark_ai_mediated(&mut msg);
        assert_eq!(
            msg["result"]["_meta"]["vellaveto_ai_mediated"],
            serde_json::Value::Bool(true)
        );
    }

    #[test]
    fn test_mark_ai_mediated_preserves_existing_meta() {
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": "hello",
                "_meta": {"existing_key": "value"}
            }
        });
        mark_ai_mediated(&mut msg);
        assert_eq!(
            msg["result"]["_meta"]["vellaveto_ai_mediated"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            msg["result"]["_meta"]["existing_key"],
            serde_json::Value::String("value".to_string())
        );
    }

    #[test]
    fn test_mark_ai_mediated_no_result() {
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32600, "message": "Invalid Request"}
        });
        let original = msg.clone();
        mark_ai_mediated(&mut msg);
        assert_eq!(msg, original, "error responses should not be modified");
    }

    #[test]
    fn test_mark_ai_mediated_null_result() {
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": null
        });
        let original = msg.clone();
        mark_ai_mediated(&mut msg);
        assert_eq!(msg, original, "null result should not be modified");
    }

    #[test]
    fn test_requires_human_oversight_glob_match() {
        let patterns = vec!["shell_*".to_string()];
        assert!(requires_human_oversight("shell_exec", &patterns));
        assert!(requires_human_oversight("shell_run", &patterns));
    }

    #[test]
    fn test_requires_human_oversight_no_match() {
        let patterns = vec!["shell_*".to_string()];
        assert!(!requires_human_oversight("read_file", &patterns));
        assert!(!requires_human_oversight("http_get", &patterns));
    }

    #[test]
    fn test_requires_human_oversight_empty_patterns() {
        assert!(!requires_human_oversight("shell_exec", &[]));
    }

    #[test]
    fn test_requires_human_oversight_multiple_patterns() {
        let patterns = vec![
            "shell_*".to_string(),
            "exec_*".to_string(),
            "sudo".to_string(),
        ];
        assert!(requires_human_oversight("shell_exec", &patterns));
        assert!(requires_human_oversight("exec_command", &patterns));
        assert!(requires_human_oversight("sudo", &patterns));
        assert!(!requires_human_oversight("read_file", &patterns));
    }

    #[test]
    fn test_requires_human_oversight_question_mark() {
        let patterns = vec!["db_?".to_string()];
        assert!(requires_human_oversight("db_a", &patterns));
        assert!(!requires_human_oversight("db_ab", &patterns));
        assert!(!requires_human_oversight("db_", &patterns));
    }

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("he*", "hello"));
        assert!(glob_match("*lo", "hello"));
        assert!(glob_match("h*o", "hello"));
    }

    // ═══════════════════════════════════════════════════
    // PHASE 24: Decision Explanation Injection Tests
    // ═══════════════════════════════════════════════════

    fn make_test_trace() -> vellaveto_types::EvaluationTrace {
        vellaveto_types::EvaluationTrace {
            action_summary: vellaveto_types::ActionSummary {
                tool: "read_file".to_string(),
                function: "execute".to_string(),
                param_count: 1,
                param_keys: vec!["path".to_string()],
            },
            policies_checked: 3,
            policies_matched: 1,
            matches: vec![vellaveto_types::PolicyMatch {
                policy_id: "p1".to_string(),
                policy_name: "Allow reads".to_string(),
                policy_type: "Allow".to_string(),
                priority: 100,
                tool_matched: true,
                constraint_results: vec![],
                verdict_contribution: Some(vellaveto_types::Verdict::Allow),
            }],
            verdict: vellaveto_types::Verdict::Allow,
            duration_us: 42,
        }
    }

    #[test]
    fn test_inject_decision_explanation_summary() {
        let trace = make_test_trace();
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": "hello"}
        });
        inject_decision_explanation(
            &mut msg,
            Some(&trace),
            vellaveto_types::ExplanationVerbosity::Summary,
            true, // is_admin
        );
        let explanation = &msg["result"]["_meta"]["vellaveto_decision_explanation"];
        assert_eq!(explanation["verdict"], "Allow");
        assert_eq!(explanation["policies_checked"], 3);
        assert!(explanation.get("policy_details").is_none());
    }

    #[test]
    fn test_inject_decision_explanation_full() {
        let trace = make_test_trace();
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": "data"}
        });
        inject_decision_explanation(
            &mut msg,
            Some(&trace),
            vellaveto_types::ExplanationVerbosity::Full,
            true, // is_admin
        );
        let explanation = &msg["result"]["_meta"]["vellaveto_decision_explanation"];
        assert_eq!(explanation["verdict"], "Allow");
        let details = explanation["policy_details"].as_array().unwrap();
        assert_eq!(details.len(), 1);
        assert_eq!(details[0]["policy_id"], "p1");
    }

    #[test]
    fn test_inject_decision_explanation_full_non_admin_downgrades_to_summary() {
        let trace = make_test_trace();
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": "data"}
        });
        inject_decision_explanation(
            &mut msg,
            Some(&trace),
            vellaveto_types::ExplanationVerbosity::Full,
            false, // NOT admin — should downgrade to Summary
        );
        let explanation = &msg["result"]["_meta"]["vellaveto_decision_explanation"];
        assert_eq!(explanation["verdict"], "Allow");
        // Summary does not include policy_details
        assert!(
            explanation.get("policy_details").is_none(),
            "non-admin Full should be downgraded to Summary (no policy_details)"
        );
    }

    #[test]
    fn test_inject_decision_explanation_none_verbosity() {
        let trace = make_test_trace();
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": "data"}
        });
        let original = msg.clone();
        inject_decision_explanation(
            &mut msg,
            Some(&trace),
            vellaveto_types::ExplanationVerbosity::None,
            true,
        );
        assert_eq!(
            msg, original,
            "None verbosity should not modify the message"
        );
    }

    #[test]
    fn test_inject_decision_explanation_no_trace() {
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": "data"}
        });
        let original = msg.clone();
        inject_decision_explanation(
            &mut msg,
            None,
            vellaveto_types::ExplanationVerbosity::Summary,
            true,
        );
        assert_eq!(msg, original, "No trace should not modify the message");
    }

    #[test]
    fn test_inject_decision_explanation_error_response_unchanged() {
        let trace = make_test_trace();
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32600, "message": "Invalid Request"}
        });
        let original = msg.clone();
        inject_decision_explanation(
            &mut msg,
            Some(&trace),
            vellaveto_types::ExplanationVerbosity::Full,
            true,
        );
        assert_eq!(msg, original, "Error responses should not be modified");
    }

    #[test]
    fn test_inject_decision_explanation_preserves_existing_meta() {
        let trace = make_test_trace();
        let mut msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": "data",
                "_meta": {"vellaveto_ai_mediated": true}
            }
        });
        inject_decision_explanation(
            &mut msg,
            Some(&trace),
            vellaveto_types::ExplanationVerbosity::Summary,
            true,
        );
        // Both keys should be present
        assert_eq!(
            msg["result"]["_meta"]["vellaveto_ai_mediated"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            msg["result"]["_meta"]["vellaveto_decision_explanation"]["verdict"],
            "Allow"
        );
    }
}
