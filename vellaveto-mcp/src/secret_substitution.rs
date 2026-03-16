// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Phase 2: Secret substitution engine.
//!
//! Replaces secrets with placeholders before tool call parameters reach the
//! model, then restores real values at execution time. This ensures the LLM
//! never sees actual API keys, tokens, or credentials — only placeholders.
//!
//! The substitution is bidirectional:
//! - **Outbound (before model):** real secret → placeholder
//! - **Inbound (before execution):** placeholder → real secret

use serde_json::Value;
use vellaveto_config::SecretSubstitution;

/// Maximum length of a resolved secret value (defense-in-depth).
const MAX_SECRET_VALUE_LEN: usize = 8192;

/// Runtime secret substitution engine.
pub struct SecretSubstitutionEngine {
    /// Resolved substitutions (env vars read at init time).
    entries: Vec<ResolvedEntry>,
}

struct ResolvedEntry {
    config: SecretSubstitution,
    /// The actual secret value resolved from the environment variable.
    /// None if the env var is not set (skip this entry silently).
    secret_value: Option<String>,
}

impl SecretSubstitutionEngine {
    /// Create a new engine from config, resolving environment variables.
    ///
    /// Entries whose env vars are not set are silently skipped at runtime.
    /// This allows config to be committed without requiring all secrets
    /// to be present in every environment.
    pub fn new(configs: &[SecretSubstitution]) -> Self {
        let entries = configs
            .iter()
            .map(|config| {
                let secret_value = std::env::var(&config.env_var).ok().and_then(|v| {
                    if v.is_empty() || v.len() > MAX_SECRET_VALUE_LEN {
                        None
                    } else {
                        Some(v)
                    }
                });
                ResolvedEntry {
                    config: config.clone(),
                    secret_value,
                }
            })
            .collect();
        Self { entries }
    }

    /// Returns true if any substitutions are configured with resolved secrets.
    pub fn has_active_entries(&self) -> bool {
        self.entries.iter().any(|e| e.secret_value.is_some())
    }

    /// Substitute secrets with placeholders in tool call parameters (outbound).
    ///
    /// Called before parameters are visible to the model. Modifies `params`
    /// in place, replacing any occurrence of a resolved secret value with
    /// its configured placeholder.
    pub fn substitute_outbound(&self, tool_name: &str, params: &mut Value) {
        for entry in &self.entries {
            let secret = match &entry.secret_value {
                Some(s) => s,
                None => continue,
            };
            if !tool_matches(&entry.config.tool_patterns, tool_name) {
                continue;
            }
            if entry.config.param_paths.is_empty() {
                // Scan all string values
                replace_in_value(params, secret, &entry.config.placeholder);
            } else {
                // Only scan specified paths
                for path in &entry.config.param_paths {
                    if let Some(val) = get_param_by_path_mut(params, path) {
                        if let Some(s) = val.as_str() {
                            if s.contains(secret.as_str()) {
                                *val = Value::String(
                                    s.replace(secret.as_str(), &entry.config.placeholder),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Restore secrets from placeholders in tool call parameters (inbound).
    ///
    /// Called before parameters are forwarded to the tool server for execution.
    /// Replaces placeholders back to real secret values.
    pub fn restore_inbound(&self, tool_name: &str, params: &mut Value) {
        for entry in &self.entries {
            let secret = match &entry.secret_value {
                Some(s) => s,
                None => continue,
            };
            if !tool_matches(&entry.config.tool_patterns, tool_name) {
                continue;
            }
            if entry.config.param_paths.is_empty() {
                replace_in_value(params, &entry.config.placeholder, secret);
            } else {
                for path in &entry.config.param_paths {
                    if let Some(val) = get_param_by_path_mut(params, path) {
                        if let Some(s) = val.as_str() {
                            if s.contains(entry.config.placeholder.as_str()) {
                                *val = Value::String(
                                    s.replace(entry.config.placeholder.as_str(), secret),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Replace all occurrences of `find` with `replace` in all string values.
fn replace_in_value(value: &mut Value, find: &str, replace: &str) {
    match value {
        Value::String(s) => {
            if s.contains(find) {
                *s = s.replace(find, replace);
            }
        }
        Value::Object(obj) => {
            for (_key, child) in obj.iter_mut() {
                replace_in_value(child, find, replace);
            }
        }
        Value::Array(arr) => {
            for child in arr.iter_mut() {
                replace_in_value(child, find, replace);
            }
        }
        _ => {}
    }
}

/// Get a mutable reference to a parameter by dot-delimited path.
fn get_param_by_path_mut<'a>(value: &'a mut Value, path: &str) -> Option<&'a mut Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get_mut(segment)?;
    }
    Some(current)
}

/// Check if a tool name matches any of the given patterns (empty = all match).
fn tool_matches(patterns: &[String], tool_name: &str) -> bool {
    if patterns.is_empty() {
        return true;
    }
    patterns.iter().any(|pattern| {
        if pattern == "*" {
            return true;
        }
        if let Some(star_pos) = pattern.find('*') {
            let prefix = &pattern[..star_pos];
            let suffix = &pattern[star_pos + 1..];
            tool_name.starts_with(prefix) && tool_name.ends_with(suffix)
        } else {
            pattern == tool_name
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_engine_with_secret(
        name: &str,
        placeholder: &str,
        secret: &str,
        tool_patterns: Vec<String>,
        param_paths: Vec<String>,
    ) -> SecretSubstitutionEngine {
        let entry = ResolvedEntry {
            config: SecretSubstitution {
                name: name.to_string(),
                env_var: "TEST_SECRET".to_string(),
                placeholder: placeholder.to_string(),
                tool_patterns,
                param_paths,
            },
            secret_value: Some(secret.to_string()),
        };
        SecretSubstitutionEngine {
            entries: vec![entry],
        }
    }

    #[test]
    fn test_substitute_outbound_all_params() {
        let engine = make_engine_with_secret(
            "API_KEY",
            "{{API_KEY}}",
            "sk-secret-12345",
            Vec::new(),
            Vec::new(),
        );
        let mut params = json!({"token": "sk-secret-12345", "name": "test"});
        engine.substitute_outbound("any_tool", &mut params);
        assert_eq!(params["token"], "{{API_KEY}}");
        assert_eq!(params["name"], "test"); // unchanged
    }

    #[test]
    fn test_restore_inbound_all_params() {
        let engine = make_engine_with_secret(
            "API_KEY",
            "{{API_KEY}}",
            "sk-secret-12345",
            Vec::new(),
            Vec::new(),
        );
        let mut params = json!({"token": "{{API_KEY}}", "name": "test"});
        engine.restore_inbound("any_tool", &mut params);
        assert_eq!(params["token"], "sk-secret-12345");
        assert_eq!(params["name"], "test");
    }

    #[test]
    fn test_substitute_specific_param_paths() {
        let engine = make_engine_with_secret(
            "TOKEN",
            "{{TOKEN}}",
            "real-token",
            Vec::new(),
            vec!["auth.token".to_string()],
        );
        let mut params = json!({
            "auth": {"token": "real-token"},
            "data": "real-token"
        });
        engine.substitute_outbound("tool", &mut params);
        assert_eq!(params["auth"]["token"], "{{TOKEN}}");
        // data is NOT in param_paths, so it should NOT be substituted
        assert_eq!(params["data"], "real-token");
    }

    #[test]
    fn test_substitute_tool_pattern_filtering() {
        let engine = make_engine_with_secret(
            "GH",
            "{{GH}}",
            "ghp_secret",
            vec!["github_*".to_string()],
            Vec::new(),
        );
        let mut params1 = json!({"token": "ghp_secret"});
        engine.substitute_outbound("github_create_pr", &mut params1);
        assert_eq!(params1["token"], "{{GH}}"); // matches github_*

        let mut params2 = json!({"token": "ghp_secret"});
        engine.substitute_outbound("slack_post", &mut params2);
        assert_eq!(params2["token"], "ghp_secret"); // doesn't match github_*
    }

    #[test]
    fn test_roundtrip_substitution() {
        let engine = make_engine_with_secret(
            "KEY",
            "{{KEY}}",
            "my-secret-key",
            Vec::new(),
            Vec::new(),
        );
        let original = json!({"token": "Bearer my-secret-key", "count": 42});
        let mut params = original.clone();

        engine.substitute_outbound("tool", &mut params);
        assert_eq!(params["token"], "Bearer {{KEY}}");

        engine.restore_inbound("tool", &mut params);
        assert_eq!(params, original);
    }

    #[test]
    fn test_no_secret_resolved_skips() {
        let engine = SecretSubstitutionEngine {
            entries: vec![ResolvedEntry {
                config: SecretSubstitution {
                    name: "MISSING".to_string(),
                    env_var: "NONEXISTENT_VAR_12345".to_string(),
                    placeholder: "{{MISSING}}".to_string(),
                    tool_patterns: Vec::new(),
                    param_paths: Vec::new(),
                },
                secret_value: None,
            }],
        };
        let mut params = json!({"data": "hello"});
        engine.substitute_outbound("tool", &mut params);
        assert_eq!(params["data"], "hello"); // no change
    }

    #[test]
    fn test_nested_value_substitution() {
        let engine = make_engine_with_secret(
            "KEY",
            "{{KEY}}",
            "secret",
            Vec::new(),
            Vec::new(),
        );
        let mut params = json!({
            "nested": {"deep": {"value": "prefix-secret-suffix"}},
            "array": ["secret", "other"]
        });
        engine.substitute_outbound("tool", &mut params);
        assert_eq!(params["nested"]["deep"]["value"], "prefix-{{KEY}}-suffix");
        assert_eq!(params["array"][0], "{{KEY}}");
        assert_eq!(params["array"][1], "other");
    }
}
