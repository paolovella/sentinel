// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Agent goal drift detection (OWASP ASI01 — Goal Hijacking).
//!
//! Tracks the declared objective of an agent session and detects when
//! tool call patterns diverge from the stated goal — indicating possible
//! goal hijacking via prompt injection or context manipulation.

use std::collections::HashMap;

/// Maximum tracked categories per session.
const MAX_CATEGORIES: usize = 50;

/// A goal drift finding.
#[derive(Debug, Clone)]
pub struct GoalDriftFinding {
    pub drift_type: GoalDriftType,
    pub confidence: u32,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoalDriftType {
    /// Tools used don't match the declared goal category.
    CategoryMismatch,
    /// Sudden shift in tool usage pattern mid-session.
    MidSessionShift,
    /// Agent is performing actions unrelated to any stated goal.
    UnrelatedActions,
}

/// Tool categories for goal alignment checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolCategory {
    FileRead,
    FileWrite,
    CodeExecution,
    NetworkAccess,
    DatabaseAccess,
    SystemAdmin,
    Communication,
    Search,
    Unknown,
}

/// Tracks goal alignment per session.
pub struct GoalDriftTracker {
    /// Declared goal categories for the session.
    declared_categories: Vec<ToolCategory>,
    /// Actual tool categories used.
    used_categories: HashMap<ToolCategory, u32>,
    /// Total calls.
    total_calls: u32,
    /// Whether a goal was declared.
    goal_declared: bool,
}

impl GoalDriftTracker {
    pub fn new() -> Self {
        Self {
            declared_categories: Vec::new(),
            used_categories: HashMap::new(),
            total_calls: 0,
            goal_declared: false,
        }
    }

    /// Declare the session's goal categories.
    pub fn declare_goal(&mut self, categories: Vec<ToolCategory>) {
        self.declared_categories = categories;
        self.goal_declared = true;
    }

    /// Record a tool call and check for goal drift.
    pub fn record_and_check(&mut self, tool_name: &str) -> Vec<GoalDriftFinding> {
        let category = categorize_tool(tool_name);
        self.total_calls = self.total_calls.saturating_add(1);

        if self.used_categories.len() < MAX_CATEGORIES {
            *self.used_categories.entry(category).or_insert(0) = self
                .used_categories
                .get(&category)
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
        }

        let mut findings = Vec::new();

        if !self.goal_declared || self.total_calls < 3 {
            return findings;
        }

        // Check category mismatch
        if !self.declared_categories.contains(&category)
            && category != ToolCategory::Unknown
            && !self.declared_categories.is_empty()
        {
            findings.push(GoalDriftFinding {
                drift_type: GoalDriftType::CategoryMismatch,
                confidence: 55,
                description: format!(
                    "Tool '{}' ({:?}) not in declared goal categories",
                    &tool_name[..tool_name.len().min(32)],
                    category
                ),
            });
        }

        // Check mid-session shift — if the last 3 calls are all in a new category
        if self.total_calls > 5 {
            let dominant = self
                .used_categories
                .iter()
                .max_by_key(|(_, &count)| count)
                .map(|(cat, _)| *cat);
            if let Some(dom) = dominant {
                if !self.declared_categories.contains(&dom) && !self.declared_categories.is_empty()
                {
                    let dom_ratio = self.used_categories.get(&dom).copied().unwrap_or(0) as f64
                        / self.total_calls as f64;
                    if dom_ratio > 0.6 {
                        findings.push(GoalDriftFinding {
                            drift_type: GoalDriftType::MidSessionShift,
                            confidence: 65,
                            description: format!(
                                "Session dominated by {:?} ({:.0}%) — not in declared goals",
                                dom,
                                dom_ratio * 100.0
                            ),
                        });
                    }
                }
            }
        }

        findings
    }
}

impl Default for GoalDriftTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Categorize a tool name into a high-level category.
pub fn categorize_tool(tool_name: &str) -> ToolCategory {
    let lower = tool_name.to_lowercase();
    if lower.contains("read") || lower.contains("list") || lower.contains("get_file") {
        ToolCategory::FileRead
    } else if lower.contains("write") || lower.contains("create") || lower.contains("delete") {
        ToolCategory::FileWrite
    } else if lower.contains("exec") || lower.contains("run") || lower.contains("shell") {
        ToolCategory::CodeExecution
    } else if lower.contains("http")
        || lower.contains("fetch")
        || lower.contains("curl")
        || lower.contains("request")
    {
        ToolCategory::NetworkAccess
    } else if lower.contains("sql")
        || lower.contains("query")
        || lower.contains("database")
        || lower.contains("db_")
    {
        ToolCategory::DatabaseAccess
    } else if lower.contains("admin")
        || lower.contains("config")
        || lower.contains("sudo")
        || lower.contains("chmod")
    {
        ToolCategory::SystemAdmin
    } else if lower.contains("send")
        || lower.contains("email")
        || lower.contains("message")
        || lower.contains("notify")
    {
        ToolCategory::Communication
    } else if lower.contains("search") || lower.contains("find") || lower.contains("grep") {
        ToolCategory::Search
    } else {
        ToolCategory::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_drift_without_goal() {
        let mut tracker = GoalDriftTracker::new();
        let findings = tracker.record_and_check("execute_command");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_category_mismatch() {
        let mut tracker = GoalDriftTracker::new();
        tracker.declare_goal(vec![ToolCategory::FileRead, ToolCategory::Search]);
        tracker.record_and_check("read_file");
        tracker.record_and_check("search_code");
        let findings = tracker.record_and_check("execute_command");
        assert!(findings
            .iter()
            .any(|f| f.drift_type == GoalDriftType::CategoryMismatch));
    }

    #[test]
    fn test_no_drift_matching_goal() {
        let mut tracker = GoalDriftTracker::new();
        tracker.declare_goal(vec![ToolCategory::FileRead]);
        tracker.record_and_check("read_file");
        tracker.record_and_check("list_directory");
        let findings = tracker.record_and_check("get_file_contents");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_categorize_tool() {
        assert_eq!(categorize_tool("read_file"), ToolCategory::FileRead);
        assert_eq!(
            categorize_tool("execute_command"),
            ToolCategory::CodeExecution
        );
        assert_eq!(categorize_tool("http_request"), ToolCategory::NetworkAccess);
        assert_eq!(categorize_tool("sql_query"), ToolCategory::DatabaseAccess);
        assert_eq!(categorize_tool("send_email"), ToolCategory::Communication);
    }
}
