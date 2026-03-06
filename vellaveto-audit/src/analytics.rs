// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

// vellaveto-audit/src/analytics.rs
//
// Phase 68: Runtime Analytics & Insights API
//
// Processes audit entries into aggregated insights: summary statistics,
// time-series trends, and per-policy effectiveness metrics.

use crate::types::AuditEntry;
use chrono::{DateTime, Datelike, FixedOffset, NaiveDate, Timelike};
use serde::Serialize;
use std::collections::HashMap;
use vellaveto_types::Verdict;

/// Time bucket for trend analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeBucket {
    Hour,
    Day,
    Week,
}

/// Summary analytics for a time period.
#[derive(Debug, Clone, Serialize)]
pub struct AnalyticsSummary {
    pub total_evaluations: u64,
    pub allow_count: u64,
    pub deny_count: u64,
    pub approval_count: u64,
    /// Deny rate as a fraction of total evaluations (0.0–1.0).
    /// Returns 0.0 when total_evaluations is zero (avoids NaN/division-by-zero).
    pub deny_rate: f64,
    pub unique_tools: usize,
    pub unique_agents: usize,
    pub top_denied_tools: Vec<(String, u64)>,
    pub top_allowed_tools: Vec<(String, u64)>,
    pub top_deny_reasons: Vec<(String, u64)>,
    pub evaluations_per_tool: HashMap<String, u64>,
}

/// A time-series data point.
#[derive(Debug, Clone, Serialize)]
pub struct TrendPoint {
    /// ISO 8601 bucket start timestamp.
    pub timestamp: String,
    pub allow_count: u64,
    pub deny_count: u64,
    pub approval_count: u64,
    pub total: u64,
}

/// Trend analysis result.
#[derive(Debug, Clone, Serialize)]
pub struct TrendAnalysis {
    /// Bucket granularity: "hour", "day", or "week".
    pub bucket: String,
    pub points: Vec<TrendPoint>,
    pub total_evaluations: u64,
}

/// Per-policy effectiveness metrics.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyMetrics {
    pub policy_id: String,
    pub times_matched: u64,
    pub allow_verdicts: u64,
    pub deny_verdicts: u64,
    pub approval_verdicts: u64,
    pub last_matched: Option<String>,
}

/// Policy analytics result.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyAnalytics {
    pub policies: Vec<PolicyMetrics>,
    /// Policy IDs from the input set that never appeared in any entry's
    /// `matched_policy` metadata field.
    pub never_matched: Vec<String>,
    pub total_evaluations: u64,
}

/// Stateless analytics engine that processes `AuditEntry` slices
/// into aggregated insights.
pub struct AnalyticsEngine;

/// Maximum number of items returned in "top N" lists.
const TOP_N: usize = 10;

impl AnalyticsEngine {
    /// Compute summary analytics from audit entries.
    ///
    /// Extracts tool names from `entry.action.tool`, agent IDs from
    /// `entry.metadata["agent_id"]` (if present), and deny reasons from
    /// the `Verdict::Deny` variant.
    /// SECURITY (R229-AUD-6): Maximum distinct keys in analytics HashMaps.
    /// Prevents memory exhaustion when processing entries with attacker-controlled
    /// tool names, deny reasons, or agent IDs.
    const MAX_DISTINCT_KEYS: usize = 10_000;

    pub fn summarize(entries: &[AuditEntry]) -> AnalyticsSummary {
        let mut allow_count: u64 = 0;
        let mut deny_count: u64 = 0;
        let mut approval_count: u64 = 0;

        let mut tools: HashMap<String, u64> = HashMap::new();
        let mut denied_tools: HashMap<String, u64> = HashMap::new();
        let mut allowed_tools: HashMap<String, u64> = HashMap::new();
        let mut deny_reasons: HashMap<String, u64> = HashMap::new();
        let mut agents: HashMap<String, ()> = HashMap::new();

        for entry in entries {
            // Verdict classification
            match &entry.verdict {
                Verdict::Allow => {
                    allow_count = allow_count.saturating_add(1);
                    if allowed_tools.contains_key(&entry.action.tool)
                        || allowed_tools.len() < Self::MAX_DISTINCT_KEYS
                    {
                        *allowed_tools.entry(entry.action.tool.clone()).or_insert(0) =
                            allowed_tools
                                .get(&entry.action.tool)
                                .copied()
                                .unwrap_or(0)
                                .saturating_add(1);
                    }
                }
                Verdict::Deny { reason } => {
                    deny_count = deny_count.saturating_add(1);
                    if denied_tools.contains_key(&entry.action.tool)
                        || denied_tools.len() < Self::MAX_DISTINCT_KEYS
                    {
                        *denied_tools.entry(entry.action.tool.clone()).or_insert(0) = denied_tools
                            .get(&entry.action.tool)
                            .copied()
                            .unwrap_or(0)
                            .saturating_add(1);
                    }
                    if deny_reasons.contains_key(reason)
                        || deny_reasons.len() < Self::MAX_DISTINCT_KEYS
                    {
                        *deny_reasons.entry(reason.clone()).or_insert(0) = deny_reasons
                            .get(reason)
                            .copied()
                            .unwrap_or(0)
                            .saturating_add(1);
                    }
                }
                Verdict::RequireApproval { .. } => {
                    approval_count = approval_count.saturating_add(1);
                }
                // Fail-closed: unknown future variants count as deny
                _ => {
                    deny_count = deny_count.saturating_add(1);
                    if denied_tools.contains_key(&entry.action.tool)
                        || denied_tools.len() < Self::MAX_DISTINCT_KEYS
                    {
                        *denied_tools.entry(entry.action.tool.clone()).or_insert(0) = denied_tools
                            .get(&entry.action.tool)
                            .copied()
                            .unwrap_or(0)
                            .saturating_add(1);
                    }
                }
            }

            // Per-tool evaluation counts
            // SECURITY (R229-AUD-6): Only insert new keys if under capacity.
            if tools.contains_key(&entry.action.tool) || tools.len() < Self::MAX_DISTINCT_KEYS {
                *tools.entry(entry.action.tool.clone()).or_insert(0) = tools
                    .get(&entry.action.tool)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(1);
            }

            // Agent extraction from metadata
            if let Some(agent_id) = entry.metadata.get("agent_id").and_then(|v| v.as_str()) {
                if agents.len() < Self::MAX_DISTINCT_KEYS {
                    agents.entry(agent_id.to_string()).or_insert(());
                }
            }
        }

        let total_evaluations = allow_count
            .saturating_add(deny_count)
            .saturating_add(approval_count);

        let deny_rate = if total_evaluations == 0 {
            0.0
        } else {
            deny_count as f64 / total_evaluations as f64
        };

        AnalyticsSummary {
            total_evaluations,
            allow_count,
            deny_count,
            approval_count,
            deny_rate,
            unique_tools: tools.len(),
            unique_agents: agents.len(),
            top_denied_tools: top_n_by_count(denied_tools),
            top_allowed_tools: top_n_by_count(allowed_tools),
            top_deny_reasons: top_n_by_count(deny_reasons),
            evaluations_per_tool: tools,
        }
    }

    /// Compute time-series trends from audit entries.
    ///
    /// Groups entries by timestamp bucket (hour, day, or week) and returns
    /// data points sorted by timestamp ascending. Invalid timestamps fall
    /// back to the Unix epoch.
    pub fn trends(entries: &[AuditEntry], bucket: TimeBucket) -> TrendAnalysis {
        let bucket_label = match bucket {
            TimeBucket::Hour => "hour",
            TimeBucket::Day => "day",
            TimeBucket::Week => "week",
        };

        let mut buckets: HashMap<String, (u64, u64, u64)> = HashMap::new();

        for entry in entries {
            let ts = parse_timestamp(&entry.timestamp);
            let key = bucket_key(ts, bucket);

            let counts = buckets.entry(key).or_insert((0, 0, 0));
            match &entry.verdict {
                Verdict::Allow => counts.0 = counts.0.saturating_add(1),
                Verdict::Deny { .. } => counts.1 = counts.1.saturating_add(1),
                Verdict::RequireApproval { .. } => counts.2 = counts.2.saturating_add(1),
                // Fail-closed: unknown future variants count as deny
                _ => counts.1 = counts.1.saturating_add(1),
            }
        }

        let mut points: Vec<TrendPoint> = buckets
            .into_iter()
            .map(|(ts, (allow, deny, approval))| TrendPoint {
                timestamp: ts,
                allow_count: allow,
                deny_count: deny,
                approval_count: approval,
                total: allow.saturating_add(deny).saturating_add(approval),
            })
            .collect();

        // Sort by timestamp ascending (ISO 8601 strings sort lexicographically)
        points.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        let total_evaluations = points
            .iter()
            .fold(0u64, |acc, p| acc.saturating_add(p.total));

        TrendAnalysis {
            bucket: bucket_label.to_string(),
            points,
            total_evaluations,
        }
    }

    /// Compute per-policy metrics from audit entries and a set of known policy IDs.
    ///
    /// Reads `entry.metadata["matched_policy"]` to determine which policy matched
    /// each entry. Policy IDs from `policy_ids` that never appear in any entry's
    /// metadata are reported in `never_matched`.
    pub fn policy_analytics(entries: &[AuditEntry], policy_ids: &[String]) -> PolicyAnalytics {
        let mut metrics_map: HashMap<String, PolicyMetrics> = HashMap::new();

        let total_evaluations = entries.len() as u64;

        for entry in entries {
            if let Some(pid) = entry
                .metadata
                .get("matched_policy")
                .and_then(|v| v.as_str())
            {
                let m = metrics_map
                    .entry(pid.to_string())
                    .or_insert_with(|| PolicyMetrics {
                        policy_id: pid.to_string(),
                        times_matched: 0,
                        allow_verdicts: 0,
                        deny_verdicts: 0,
                        approval_verdicts: 0,
                        last_matched: None,
                    });

                m.times_matched = m.times_matched.saturating_add(1);
                match &entry.verdict {
                    Verdict::Allow => m.allow_verdicts = m.allow_verdicts.saturating_add(1),
                    Verdict::Deny { .. } => m.deny_verdicts = m.deny_verdicts.saturating_add(1),
                    Verdict::RequireApproval { .. } => {
                        m.approval_verdicts = m.approval_verdicts.saturating_add(1)
                    }
                    // Fail-closed: unknown future variants count as deny
                    _ => m.deny_verdicts = m.deny_verdicts.saturating_add(1),
                }

                // Track last matched timestamp (lexicographic max of ISO 8601 works)
                let ts = entry.timestamp.clone();
                if let Some(ref existing) = m.last_matched {
                    if ts > *existing {
                        m.last_matched = Some(ts);
                    }
                } else {
                    m.last_matched = Some(ts);
                }
            }
        }

        // Determine which known policy IDs were never matched
        let never_matched: Vec<String> = policy_ids
            .iter()
            .filter(|pid| !metrics_map.contains_key(pid.as_str()))
            .cloned()
            .collect();

        // Build final sorted list of policy metrics
        let mut policies: Vec<PolicyMetrics> = metrics_map.into_values().collect();
        policies.sort_by(|a, b| b.times_matched.cmp(&a.times_matched));

        PolicyAnalytics {
            policies,
            never_matched,
            total_evaluations,
        }
    }
}

/// Extract the top N entries from a count map, sorted by count descending.
fn top_n_by_count(map: HashMap<String, u64>) -> Vec<(String, u64)> {
    let mut entries: Vec<(String, u64)> = map.into_iter().collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    entries.truncate(TOP_N);
    entries
}

/// Parse an ISO 8601 / RFC 3339 timestamp string into a `DateTime<FixedOffset>`.
/// Falls back to the Unix epoch if parsing fails.
fn parse_timestamp(ts: &str) -> DateTime<FixedOffset> {
    DateTime::parse_from_rfc3339(ts).unwrap_or_else(|_| {
        DateTime::parse_from_rfc3339("1970-01-01T00:00:00Z").unwrap_or_else(|_| {
            // This is a compile-time-known valid string; the double fallback
            // ensures we never panic even under adversarial conditions.
            DateTime::<FixedOffset>::from(DateTime::UNIX_EPOCH)
        })
    })
}

/// Compute the bucket key string for a given timestamp and granularity.
fn bucket_key(dt: DateTime<FixedOffset>, bucket: TimeBucket) -> String {
    match bucket {
        TimeBucket::Hour => {
            format!(
                "{:04}-{:02}-{:02}T{:02}:00:00Z",
                dt.year(),
                dt.month(),
                dt.day(),
                dt.hour()
            )
        }
        TimeBucket::Day => {
            format!(
                "{:04}-{:02}-{:02}T00:00:00Z",
                dt.year(),
                dt.month(),
                dt.day()
            )
        }
        TimeBucket::Week => {
            // ISO week: find the Monday of the entry's ISO week
            let iso_week = dt.iso_week();
            let monday =
                NaiveDate::from_isoywd_opt(iso_week.year(), iso_week.week(), chrono::Weekday::Mon)
                    .unwrap_or_else(|| NaiveDate::from_ymd_opt(1970, 1, 1).unwrap_or_default());
            format!(
                "{:04}-{:02}-{:02}T00:00:00Z",
                monday.year(),
                monday.month(),
                monday.day()
            )
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vellaveto_types::Action;

    /// Helper: create an AuditEntry with the given tool, verdict, and timestamp.
    fn make_entry(tool: &str, verdict: Verdict, timestamp: &str) -> AuditEntry {
        make_entry_with_metadata(tool, verdict, timestamp, json!({}))
    }

    /// Helper: create an AuditEntry with metadata.
    fn make_entry_with_metadata(
        tool: &str,
        verdict: Verdict,
        timestamp: &str,
        metadata: serde_json::Value,
    ) -> AuditEntry {
        AuditEntry {
            id: uuid::Uuid::new_v4().to_string(),
            action: Action::new(tool.to_string(), "invoke".to_string(), json!({})),
            verdict,
            timestamp: timestamp.to_string(),
            metadata,
            sequence: 0,
            entry_hash: None,
            prev_hash: None,
            commitment: None,
            tenant_id: None,
        }
    }

    // ── summarize tests ──────────────────────────────────────────────────────

    #[test]
    fn test_summarize_empty_entries_returns_zeroes() {
        let summary = AnalyticsEngine::summarize(&[]);
        assert_eq!(summary.total_evaluations, 0);
        assert_eq!(summary.allow_count, 0);
        assert_eq!(summary.deny_count, 0);
        assert_eq!(summary.approval_count, 0);
        assert_eq!(summary.deny_rate, 0.0);
        assert_eq!(summary.unique_tools, 0);
        assert_eq!(summary.unique_agents, 0);
        assert!(summary.top_denied_tools.is_empty());
        assert!(summary.top_allowed_tools.is_empty());
        assert!(summary.top_deny_reasons.is_empty());
        assert!(summary.evaluations_per_tool.is_empty());
    }

    #[test]
    fn test_summarize_mixed_verdicts_correct_counts() {
        let entries = vec![
            make_entry("fs", Verdict::Allow, "2026-02-01T00:00:00Z"),
            make_entry("fs", Verdict::Allow, "2026-02-01T01:00:00Z"),
            make_entry(
                "net",
                Verdict::Deny {
                    reason: "blocked".into(),
                },
                "2026-02-01T02:00:00Z",
            ),
            make_entry(
                "db",
                Verdict::RequireApproval {
                    reason: "needs approval".into(),
                },
                "2026-02-01T03:00:00Z",
            ),
        ];
        let summary = AnalyticsEngine::summarize(&entries);
        assert_eq!(summary.total_evaluations, 4);
        assert_eq!(summary.allow_count, 2);
        assert_eq!(summary.deny_count, 1);
        assert_eq!(summary.approval_count, 1);
        assert!((summary.deny_rate - 0.25).abs() < 1e-9);
    }

    #[test]
    fn test_summarize_deny_rate_all_denied() {
        let entries = vec![
            make_entry(
                "t",
                Verdict::Deny { reason: "r".into() },
                "2026-01-01T00:00:00Z",
            ),
            make_entry(
                "t",
                Verdict::Deny { reason: "r".into() },
                "2026-01-01T01:00:00Z",
            ),
        ];
        let summary = AnalyticsEngine::summarize(&entries);
        assert!((summary.deny_rate - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_summarize_top_denied_tools_ordering() {
        let mut entries = Vec::new();
        // "dangerous" denied 5 times, "risky" denied 3 times, "edge" denied 1 time
        for _ in 0..5 {
            entries.push(make_entry(
                "dangerous",
                Verdict::Deny {
                    reason: "policy".into(),
                },
                "2026-01-01T00:00:00Z",
            ));
        }
        for _ in 0..3 {
            entries.push(make_entry(
                "risky",
                Verdict::Deny {
                    reason: "policy".into(),
                },
                "2026-01-01T00:00:00Z",
            ));
        }
        entries.push(make_entry(
            "edge",
            Verdict::Deny {
                reason: "policy".into(),
            },
            "2026-01-01T00:00:00Z",
        ));

        let summary = AnalyticsEngine::summarize(&entries);
        assert_eq!(summary.top_denied_tools.len(), 3);
        assert_eq!(summary.top_denied_tools[0].0, "dangerous");
        assert_eq!(summary.top_denied_tools[0].1, 5);
        assert_eq!(summary.top_denied_tools[1].0, "risky");
        assert_eq!(summary.top_denied_tools[1].1, 3);
        assert_eq!(summary.top_denied_tools[2].0, "edge");
        assert_eq!(summary.top_denied_tools[2].1, 1);
    }

    #[test]
    fn test_summarize_unique_agents_from_metadata() {
        let entries = vec![
            make_entry_with_metadata(
                "t",
                Verdict::Allow,
                "2026-01-01T00:00:00Z",
                json!({"agent_id": "agent-1"}),
            ),
            make_entry_with_metadata(
                "t",
                Verdict::Allow,
                "2026-01-01T01:00:00Z",
                json!({"agent_id": "agent-2"}),
            ),
            make_entry_with_metadata(
                "t",
                Verdict::Allow,
                "2026-01-01T02:00:00Z",
                json!({"agent_id": "agent-1"}),
            ),
            // No agent_id in metadata
            make_entry("t", Verdict::Allow, "2026-01-01T03:00:00Z"),
        ];
        let summary = AnalyticsEngine::summarize(&entries);
        assert_eq!(summary.unique_agents, 2);
    }

    #[test]
    fn test_summarize_deny_reason_aggregation() {
        let entries = vec![
            make_entry(
                "t",
                Verdict::Deny {
                    reason: "path blocked".into(),
                },
                "2026-01-01T00:00:00Z",
            ),
            make_entry(
                "t",
                Verdict::Deny {
                    reason: "path blocked".into(),
                },
                "2026-01-01T01:00:00Z",
            ),
            make_entry(
                "t",
                Verdict::Deny {
                    reason: "domain blocked".into(),
                },
                "2026-01-01T02:00:00Z",
            ),
        ];
        let summary = AnalyticsEngine::summarize(&entries);
        assert_eq!(summary.top_deny_reasons.len(), 2);
        assert_eq!(summary.top_deny_reasons[0].0, "path blocked");
        assert_eq!(summary.top_deny_reasons[0].1, 2);
        assert_eq!(summary.top_deny_reasons[1].0, "domain blocked");
        assert_eq!(summary.top_deny_reasons[1].1, 1);
    }

    #[test]
    fn test_summarize_evaluations_per_tool() {
        let entries = vec![
            make_entry("fs", Verdict::Allow, "2026-01-01T00:00:00Z"),
            make_entry("fs", Verdict::Allow, "2026-01-01T01:00:00Z"),
            make_entry("net", Verdict::Allow, "2026-01-01T02:00:00Z"),
        ];
        let summary = AnalyticsEngine::summarize(&entries);
        assert_eq!(summary.evaluations_per_tool.get("fs"), Some(&2));
        assert_eq!(summary.evaluations_per_tool.get("net"), Some(&1));
        assert_eq!(summary.unique_tools, 2);
    }

    #[test]
    fn test_summarize_top_n_capped_at_10() {
        let mut entries = Vec::new();
        // Create 15 distinct tools each denied once
        for i in 0..15 {
            entries.push(make_entry(
                &format!("tool_{:02}", i),
                Verdict::Deny {
                    reason: "blocked".into(),
                },
                "2026-01-01T00:00:00Z",
            ));
        }
        let summary = AnalyticsEngine::summarize(&entries);
        assert_eq!(summary.top_denied_tools.len(), 10);
    }

    // ── trends tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_trends_empty_entries() {
        let analysis = AnalyticsEngine::trends(&[], TimeBucket::Hour);
        assert_eq!(analysis.bucket, "hour");
        assert!(analysis.points.is_empty());
        assert_eq!(analysis.total_evaluations, 0);
    }

    #[test]
    fn test_trends_hour_bucketing() {
        let entries = vec![
            make_entry("t", Verdict::Allow, "2026-02-01T10:15:00Z"),
            make_entry("t", Verdict::Allow, "2026-02-01T10:45:00Z"),
            make_entry(
                "t",
                Verdict::Deny { reason: "r".into() },
                "2026-02-01T11:05:00Z",
            ),
        ];
        let analysis = AnalyticsEngine::trends(&entries, TimeBucket::Hour);
        assert_eq!(analysis.bucket, "hour");
        assert_eq!(analysis.points.len(), 2);
        // First bucket: 10:00
        assert_eq!(analysis.points[0].timestamp, "2026-02-01T10:00:00Z");
        assert_eq!(analysis.points[0].allow_count, 2);
        assert_eq!(analysis.points[0].deny_count, 0);
        assert_eq!(analysis.points[0].total, 2);
        // Second bucket: 11:00
        assert_eq!(analysis.points[1].timestamp, "2026-02-01T11:00:00Z");
        assert_eq!(analysis.points[1].deny_count, 1);
        assert_eq!(analysis.points[1].total, 1);
    }

    #[test]
    fn test_trends_day_bucketing() {
        let entries = vec![
            make_entry("t", Verdict::Allow, "2026-02-01T10:00:00Z"),
            make_entry("t", Verdict::Allow, "2026-02-01T22:00:00Z"),
            make_entry("t", Verdict::Allow, "2026-02-02T05:00:00Z"),
        ];
        let analysis = AnalyticsEngine::trends(&entries, TimeBucket::Day);
        assert_eq!(analysis.bucket, "day");
        assert_eq!(analysis.points.len(), 2);
        assert_eq!(analysis.points[0].timestamp, "2026-02-01T00:00:00Z");
        assert_eq!(analysis.points[0].total, 2);
        assert_eq!(analysis.points[1].timestamp, "2026-02-02T00:00:00Z");
        assert_eq!(analysis.points[1].total, 1);
    }

    #[test]
    fn test_trends_week_bucketing() {
        // 2026-02-02 is a Monday (ISO week 6)
        // 2026-02-09 is a Monday (ISO week 7)
        let entries = vec![
            make_entry("t", Verdict::Allow, "2026-02-03T12:00:00Z"), // Tue week 6
            make_entry("t", Verdict::Allow, "2026-02-05T12:00:00Z"), // Thu week 6
            make_entry("t", Verdict::Allow, "2026-02-10T12:00:00Z"), // Tue week 7
        ];
        let analysis = AnalyticsEngine::trends(&entries, TimeBucket::Week);
        assert_eq!(analysis.bucket, "week");
        assert_eq!(analysis.points.len(), 2);
        // Week 6 starts on Monday 2026-02-02
        assert_eq!(analysis.points[0].timestamp, "2026-02-02T00:00:00Z");
        assert_eq!(analysis.points[0].total, 2);
        // Week 7 starts on Monday 2026-02-09
        assert_eq!(analysis.points[1].timestamp, "2026-02-09T00:00:00Z");
        assert_eq!(analysis.points[1].total, 1);
    }

    #[test]
    fn test_trends_invalid_timestamp_falls_back_to_epoch() {
        let entries = vec![make_entry("t", Verdict::Allow, "not-a-date")];
        let analysis = AnalyticsEngine::trends(&entries, TimeBucket::Day);
        assert_eq!(analysis.points.len(), 1);
        assert_eq!(analysis.points[0].timestamp, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_trends_sorted_ascending() {
        let entries = vec![
            make_entry("t", Verdict::Allow, "2026-03-01T00:00:00Z"),
            make_entry("t", Verdict::Allow, "2026-01-01T00:00:00Z"),
            make_entry("t", Verdict::Allow, "2026-02-01T00:00:00Z"),
        ];
        let analysis = AnalyticsEngine::trends(&entries, TimeBucket::Day);
        assert_eq!(analysis.points.len(), 3);
        assert!(analysis.points[0].timestamp < analysis.points[1].timestamp);
        assert!(analysis.points[1].timestamp < analysis.points[2].timestamp);
    }

    // ── policy_analytics tests ───────────────────────────────────────────────

    #[test]
    fn test_policy_analytics_empty_entries() {
        let result = AnalyticsEngine::policy_analytics(&[], &["p1".into(), "p2".into()]);
        assert_eq!(result.total_evaluations, 0);
        assert!(result.policies.is_empty());
        assert_eq!(result.never_matched.len(), 2);
    }

    #[test]
    fn test_policy_analytics_never_matched_policies() {
        let entries = vec![make_entry_with_metadata(
            "t",
            Verdict::Allow,
            "2026-01-01T00:00:00Z",
            json!({"matched_policy": "p1"}),
        )];
        let result =
            AnalyticsEngine::policy_analytics(&entries, &["p1".into(), "p2".into(), "p3".into()]);
        assert_eq!(
            result.never_matched,
            vec!["p2".to_string(), "p3".to_string()]
        );
        assert_eq!(result.policies.len(), 1);
        assert_eq!(result.policies[0].policy_id, "p1");
        assert_eq!(result.policies[0].times_matched, 1);
    }

    #[test]
    fn test_policy_analytics_verdict_breakdown() {
        let entries = vec![
            make_entry_with_metadata(
                "t",
                Verdict::Allow,
                "2026-01-01T00:00:00Z",
                json!({"matched_policy": "p1"}),
            ),
            make_entry_with_metadata(
                "t",
                Verdict::Deny { reason: "r".into() },
                "2026-01-01T01:00:00Z",
                json!({"matched_policy": "p1"}),
            ),
            make_entry_with_metadata(
                "t",
                Verdict::RequireApproval { reason: "r".into() },
                "2026-01-01T02:00:00Z",
                json!({"matched_policy": "p1"}),
            ),
        ];
        let result = AnalyticsEngine::policy_analytics(&entries, &["p1".into()]);
        assert_eq!(result.policies[0].times_matched, 3);
        assert_eq!(result.policies[0].allow_verdicts, 1);
        assert_eq!(result.policies[0].deny_verdicts, 1);
        assert_eq!(result.policies[0].approval_verdicts, 1);
    }

    #[test]
    fn test_policy_analytics_last_matched_timestamp() {
        let entries = vec![
            make_entry_with_metadata(
                "t",
                Verdict::Allow,
                "2026-01-01T00:00:00Z",
                json!({"matched_policy": "p1"}),
            ),
            make_entry_with_metadata(
                "t",
                Verdict::Allow,
                "2026-03-15T12:00:00Z",
                json!({"matched_policy": "p1"}),
            ),
            make_entry_with_metadata(
                "t",
                Verdict::Allow,
                "2026-02-01T00:00:00Z",
                json!({"matched_policy": "p1"}),
            ),
        ];
        let result = AnalyticsEngine::policy_analytics(&entries, &["p1".into()]);
        assert_eq!(
            result.policies[0].last_matched,
            Some("2026-03-15T12:00:00Z".to_string())
        );
    }

    #[test]
    fn test_policy_analytics_entries_without_matched_policy() {
        let entries = vec![
            make_entry("t", Verdict::Allow, "2026-01-01T00:00:00Z"),
            make_entry_with_metadata(
                "t",
                Verdict::Allow,
                "2026-01-01T01:00:00Z",
                json!({"matched_policy": "p1"}),
            ),
        ];
        let result = AnalyticsEngine::policy_analytics(&entries, &["p1".into()]);
        assert_eq!(result.total_evaluations, 2);
        assert_eq!(result.policies.len(), 1);
        assert_eq!(result.policies[0].times_matched, 1);
    }

    // ── Performance / large dataset test ─────────────────────────────────────

    #[test]
    fn test_summarize_large_dataset_1000_entries() {
        let mut entries = Vec::with_capacity(1000);
        for i in 0..1000u64 {
            let tool = format!("tool_{}", i % 20);
            let verdict = match i % 3 {
                0 => Verdict::Allow,
                1 => Verdict::Deny {
                    reason: format!("reason_{}", i % 5),
                },
                _ => Verdict::RequireApproval {
                    reason: "approval needed".into(),
                },
            };
            let ts = format!("2026-02-{:02}T{:02}:00:00Z", (i % 28) + 1, i % 24);
            entries.push(make_entry_with_metadata(
                &tool,
                verdict,
                &ts,
                json!({"agent_id": format!("agent_{}", i % 10)}),
            ));
        }

        let summary = AnalyticsEngine::summarize(&entries);
        assert_eq!(summary.total_evaluations, 1000);
        // i%3==0 → 334 (0,3,6,...,999), i%3==1 → 333, i%3==2 → 333
        assert_eq!(summary.allow_count, 334);
        assert_eq!(summary.deny_count, 333);
        assert_eq!(summary.approval_count, 333);
        assert_eq!(summary.unique_tools, 20);
        assert_eq!(summary.unique_agents, 10);
        assert!(summary.top_denied_tools.len() <= 10);
        assert!(summary.top_deny_reasons.len() <= 5);
    }

    #[test]
    fn test_trends_large_dataset_1000_entries() {
        let mut entries = Vec::with_capacity(1000);
        for i in 0..1000u64 {
            let ts = format!("2026-02-{:02}T{:02}:00:00Z", (i % 28) + 1, i % 24);
            entries.push(make_entry("t", Verdict::Allow, &ts));
        }
        let analysis = AnalyticsEngine::trends(&entries, TimeBucket::Hour);
        assert_eq!(analysis.total_evaluations, 1000);
        // Each (day, hour) pair should have entries
        assert!(!analysis.points.is_empty());
        // Verify sorted
        for w in analysis.points.windows(2) {
            assert!(w[0].timestamp <= w[1].timestamp);
        }
    }
}
