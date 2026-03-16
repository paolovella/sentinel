// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Phase 2: Declarative policy templates.
//!
//! Operators can declare high-level intent (e.g., "block credential access")
//! and have it expand into the underlying policy rules. This is simpler than
//! writing full Conditional policies with parameter constraints.
//!
//! # TOML Example
//!
//! ```toml
//! [[policy_templates]]
//! template = "block_paths"
//! name = "Block credentials"
//! paths = ["/home/*/.aws/**", "/home/*/.ssh/**", "**/.env"]
//! priority = 300
//!
//! [[policy_templates]]
//! template = "block_domains"
//! name = "Block exfil"
//! domains = ["pastebin.com", "webhook.site", "*.ngrok.io"]
//! priority = 275
//!
//! [[policy_templates]]
//! template = "block_commands"
//! name = "Block dangerous commands"
//! patterns = ["rm\\s+-rf\\s+/", "curl.*\\|.*sh", "chmod\\s+-R\\s+777"]
//! priority = 250
//! ```

use serde::{Deserialize, Serialize};

/// A policy template declaration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyTemplate {
    /// Template type: "block_paths", "block_domains", "block_commands",
    /// "require_approval_paths", "allow_paths".
    pub template: String,
    /// Human-readable policy name.
    pub name: String,
    /// Priority (higher = evaluated first).
    #[serde(default = "default_template_priority")]
    pub priority: i32,
    /// Path patterns (for block_paths, require_approval_paths, allow_paths).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Domain patterns (for block_domains).
    #[serde(default)]
    pub domains: Vec<String>,
    /// Regex patterns (for block_commands).
    #[serde(default)]
    pub patterns: Vec<String>,
}

fn default_template_priority() -> i32 {
    100
}

/// Maximum number of policy templates.
pub const MAX_POLICY_TEMPLATES: usize = 128;

/// Maximum entries per template list.
const MAX_TEMPLATE_ENTRIES: usize = 256;

impl PolicyTemplate {
    /// Validate template bounds and content.
    pub fn validate(&self) -> Result<(), String> {
        let valid_templates = [
            "block_paths",
            "block_domains",
            "block_commands",
            "require_approval_paths",
            "allow_paths",
        ];
        if !valid_templates.contains(&self.template.as_str()) {
            return Err(format!(
                "unknown template type '{}' (valid: {})",
                self.template,
                valid_templates.join(", ")
            ));
        }
        if self.name.is_empty() || self.name.len() > 256 {
            return Err("policy_templates[].name must be 1-256 chars".to_string());
        }
        if vellaveto_types::has_dangerous_chars(&self.name) {
            return Err("policy_templates[].name contains dangerous characters".to_string());
        }
        for list in [&self.paths, &self.domains, &self.patterns] {
            if list.len() > MAX_TEMPLATE_ENTRIES {
                return Err(format!(
                    "policy_templates[].entries exceeds {MAX_TEMPLATE_ENTRIES}"
                ));
            }
            for (i, entry) in list.iter().enumerate() {
                if entry.is_empty() {
                    return Err(format!("policy_templates[].entry[{i}] is empty"));
                }
                if entry.len() > 512 {
                    return Err(format!(
                        "policy_templates[].entry[{i}] length {} exceeds 512",
                        entry.len()
                    ));
                }
            }
        }
        // Validate that the right lists are populated for the template type
        match self.template.as_str() {
            "block_paths" | "require_approval_paths" | "allow_paths" => {
                if self.paths.is_empty() {
                    return Err(format!(
                        "template '{}' requires non-empty 'paths'",
                        self.template
                    ));
                }
            }
            "block_domains" => {
                if self.domains.is_empty() {
                    return Err("template 'block_domains' requires non-empty 'domains'".to_string());
                }
            }
            "block_commands" => {
                if self.patterns.is_empty() {
                    return Err(
                        "template 'block_commands' requires non-empty 'patterns'".to_string()
                    );
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Expand this template into policy rule JSON.
    ///
    /// Returns a `serde_json::Value` that can be deserialized into a `PolicyRule`.
    pub fn expand(&self) -> serde_json::Value {
        match self.template.as_str() {
            "block_paths" => self.expand_path_policy("deny"),
            "require_approval_paths" => self.expand_path_policy("require_approval"),
            "allow_paths" => {
                serde_json::json!({
                    "name": self.name,
                    "tool_pattern": "*",
                    "function_pattern": "*",
                    "priority": self.priority,
                    "id": format!("*:*:tpl-{}", slug(&self.name)),
                    "policy_type": "Allow"
                })
            }
            "block_domains" => {
                let constraints: Vec<serde_json::Value> = self
                    .domains
                    .iter()
                    .map(|d| {
                        serde_json::json!({
                            "param": "*",
                            "op": "regex",
                            "pattern": regex_escape_domain(d),
                            "on_match": "deny",
                            "on_missing": "skip"
                        })
                    })
                    .collect();
                serde_json::json!({
                    "name": self.name,
                    "tool_pattern": "*",
                    "function_pattern": "*",
                    "priority": self.priority,
                    "id": format!("*:*:tpl-{}", slug(&self.name)),
                    "policy_type": {
                        "Conditional": {
                            "conditions": {
                                "on_no_match": "continue",
                                "parameter_constraints": constraints
                            }
                        }
                    }
                })
            }
            "block_commands" => {
                let constraints: Vec<serde_json::Value> = self
                    .patterns
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "param": "*",
                            "op": "regex",
                            "pattern": p,
                            "on_match": "deny",
                            "on_missing": "skip"
                        })
                    })
                    .collect();
                serde_json::json!({
                    "name": self.name,
                    "tool_pattern": "*",
                    "function_pattern": "*",
                    "priority": self.priority,
                    "id": format!("*:*:tpl-{}", slug(&self.name)),
                    "policy_type": {
                        "Conditional": {
                            "conditions": {
                                "on_no_match": "continue",
                                "parameter_constraints": constraints
                            }
                        }
                    }
                })
            }
            _ => serde_json::json!(null),
        }
    }

    fn expand_path_policy(&self, on_match: &str) -> serde_json::Value {
        let constraints: Vec<serde_json::Value> = self
            .paths
            .iter()
            .map(|p| {
                serde_json::json!({
                    "param": "*",
                    "op": "glob",
                    "pattern": p,
                    "on_match": on_match,
                    "on_missing": "skip"
                })
            })
            .collect();
        serde_json::json!({
            "name": self.name,
            "tool_pattern": "*",
            "function_pattern": "*",
            "priority": self.priority,
            "id": format!("*:*:tpl-{}", slug(&self.name)),
            "policy_type": {
                "Conditional": {
                    "conditions": {
                        "on_no_match": "continue",
                        "parameter_constraints": constraints
                    }
                }
            }
        })
    }
}

/// Convert a name to a URL-safe slug for policy IDs.
fn slug(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// Escape a domain pattern for use in a regex constraint.
/// Converts `*.example.com` to `.*\.example\.com` etc.
fn regex_escape_domain(domain: &str) -> String {
    if let Some(rest) = domain.strip_prefix("*.") {
        format!("{}\\.", rest.replace('.', "\\."))
    } else {
        domain.replace('.', "\\.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_paths_template_expand() {
        let tpl = PolicyTemplate {
            template: "block_paths".to_string(),
            name: "Block credentials".to_string(),
            priority: 300,
            paths: vec!["/home/*/.aws/**".to_string(), "**/.env".to_string()],
            domains: Vec::new(),
            patterns: Vec::new(),
        };
        assert!(tpl.validate().is_ok());
        let expanded = tpl.expand();
        assert_eq!(expanded["name"], "Block credentials");
        assert_eq!(expanded["priority"], 300);
        let constraints =
            &expanded["policy_type"]["Conditional"]["conditions"]["parameter_constraints"];
        assert_eq!(constraints.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_block_domains_template_expand() {
        let tpl = PolicyTemplate {
            template: "block_domains".to_string(),
            name: "Block exfil".to_string(),
            priority: 275,
            paths: Vec::new(),
            domains: vec!["pastebin.com".to_string(), "*.ngrok.io".to_string()],
            patterns: Vec::new(),
        };
        assert!(tpl.validate().is_ok());
        let expanded = tpl.expand();
        let constraints =
            &expanded["policy_type"]["Conditional"]["conditions"]["parameter_constraints"];
        assert_eq!(constraints.as_array().unwrap().len(), 2);
        // Check regex escaping
        assert_eq!(constraints[0]["pattern"], "pastebin\\.com");
    }

    #[test]
    fn test_block_commands_template_expand() {
        let tpl = PolicyTemplate {
            template: "block_commands".to_string(),
            name: "Block dangerous".to_string(),
            priority: 250,
            paths: Vec::new(),
            domains: Vec::new(),
            patterns: vec!["rm\\s+-rf\\s+/".to_string()],
        };
        assert!(tpl.validate().is_ok());
        let expanded = tpl.expand();
        let constraints =
            &expanded["policy_type"]["Conditional"]["conditions"]["parameter_constraints"];
        assert_eq!(constraints[0]["op"], "regex");
    }

    #[test]
    fn test_invalid_template_type_rejected() {
        let tpl = PolicyTemplate {
            template: "invalid".to_string(),
            name: "test".to_string(),
            priority: 100,
            paths: Vec::new(),
            domains: Vec::new(),
            patterns: Vec::new(),
        };
        assert!(tpl.validate().unwrap_err().contains("unknown template"));
    }

    #[test]
    fn test_block_paths_requires_paths() {
        let tpl = PolicyTemplate {
            template: "block_paths".to_string(),
            name: "Empty".to_string(),
            priority: 100,
            paths: Vec::new(),
            domains: Vec::new(),
            patterns: Vec::new(),
        };
        assert!(tpl.validate().unwrap_err().contains("requires non-empty"));
    }

    #[test]
    fn test_slug_generation() {
        assert_eq!(slug("Block Credential Files"), "block-credential-files");
        assert_eq!(slug("test_123"), "test-123");
    }
}
