// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Audit log export formatters for SIEM integration.
//!
//! Supports three formats:
//! - **CEF** (Common Event Format): Standardized format used by ArcSight, Splunk, and
//!   most SIEM platforms. Each entry becomes one line in CEF format.
//! - **JSON Lines**: One JSON object per line (`.jsonl` / `.ndjson`), compatible with
//!   Elasticsearch, Datadog, and generic log pipelines.
//! - **OCSF** (Open Cybersecurity Schema Framework): Structured event format compatible
//!   with AWS Security Lake, Datadog, and Splunk. Maps audit entries to OCSF v1.3
//!   Authorization events (class_uid 3002).

pub mod ocsf;

use crate::AuditEntry;
use vellaveto_types::Verdict;

/// Export format for audit entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// Common Event Format (CEF) — standard SIEM interchange format.
    Cef,
    /// JSON Lines (one JSON object per line) — ndjson format.
    JsonLines,
    /// OCSF (Open Cybersecurity Schema Framework) v1.3 — structured event format
    /// compatible with AWS Security Lake, Datadog, and Splunk.
    Ocsf,
}

impl ExportFormat {
    /// Parse a format name from a string.
    ///
    /// Accepts case-insensitive: `"cef"`, `"jsonl"`, `"json_lines"`, `"jsonlines"`,
    /// `"ocsf"`.
    /// Returns `None` for unrecognized formats.
    pub fn parse_format(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "cef" => Some(Self::Cef),
            "jsonl" | "json_lines" | "jsonlines" => Some(Self::JsonLines),
            "ocsf" => Some(Self::Ocsf),
            _ => None,
        }
    }
}

/// Convert an AuditEntry to CEF (Common Event Format) string.
///
/// Format: `CEF:0|Vellaveto|MCP Firewall|1.0|{signatureId}|{name}|{severity}|extensions`
///
/// CEF severity mapping:
/// - `Allow` -> 1 (Low)
/// - `RequireApproval` -> 5 (Medium)
/// - `Deny` -> 8 (High)
pub fn to_cef(entry: &AuditEntry) -> String {
    let verdict_str = match &entry.verdict {
        Verdict::Allow => "Allow",
        Verdict::Deny { .. } => "Deny",
        Verdict::RequireApproval { .. } => "RequireApproval",
        // Handle future variants - treat as unknown
        _ => "Unknown",
    };

    let severity = match &entry.verdict {
        Verdict::Allow => 1,
        Verdict::RequireApproval { .. } => 5,
        Verdict::Deny { .. } => 8,
        // Handle future variants - treat as high severity (fail-closed)
        _ => 8,
    };

    let tool_function_raw = format!(
        "{}:{}",
        cef_escape(&entry.action.tool),
        cef_escape(&entry.action.function)
    );
    // SECURITY (R36-SUP-5): CEF header name field (position 6) could exceed
    // reasonable SIEM parser limits with very long tool/function names. Cap at
    // 500 bytes with char-boundary-aware truncation.
    let tool_function = if tool_function_raw.len() > 500 {
        let mut end = 500;
        while end > 0 && !tool_function_raw.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &tool_function_raw[..end])
    } else {
        tool_function_raw
    };

    // SECURITY (R35-SUP-2): CEF spec limits extension values to 1023 bytes.
    // Truncate escaped values by byte count (not char count) to prevent
    // multi-byte UTF-8 strings from exceeding the limit. Cap at 1000 bytes
    // to leave headroom for the key= prefix.
    const CEF_EXT_MAX_BYTES: usize = 1000;

    // SECURITY (R24-SUP-3): Include deny reason in CEF output for SIEM
    // analysts to understand why a tool call was blocked.
    let reason_ext = match &entry.verdict {
        Verdict::Deny { reason } => {
            let escaped = cef_escape_ext(reason);
            let truncated = truncate_bytes(&escaped, CEF_EXT_MAX_BYTES);
            format!(" cs2={truncated} cs2Label=denyReason")
        }
        Verdict::RequireApproval { reason, .. } => {
            let escaped = cef_escape_ext(reason);
            let truncated = truncate_bytes(&escaped, CEF_EXT_MAX_BYTES);
            format!(" cs2={truncated} cs2Label=approvalReason")
        }
        Verdict::Allow => String::new(),
        // Handle future variants - no reason available
        _ => String::new(),
    };

    // SECURITY (R226-AUD-5): CEF timestamps require timezone information per
    // CEF specification. Append 'Z' if timestamp has no timezone indicator
    // (Z, +HH:MM, -HH:MM) to ensure SIEM parsers interpret as UTC.
    let ts = &entry.timestamp;
    let has_tz = ts.ends_with('Z')
        || ts.ends_with('z')
        || ts.len() >= 6
            && (ts.as_bytes()[ts.len() - 6] == b'+' || ts.as_bytes()[ts.len() - 6] == b'-')
        || ts.len() >= 5
            && (ts.as_bytes()[ts.len() - 5] == b'+' || ts.as_bytes()[ts.len() - 5] == b'-');
    let ts_with_tz = if has_tz {
        ts.clone()
    } else {
        format!("{}Z", ts)
    };
    let rt_escaped = cef_escape_ext(&ts_with_tz);
    let rt_val = truncate_bytes(&rt_escaped, CEF_EXT_MAX_BYTES);
    let cs1_escaped = cef_escape_ext(&entry.id);
    let cs1_val = truncate_bytes(&cs1_escaped, CEF_EXT_MAX_BYTES);

    format!(
        "CEF:0|Vellaveto|MCP Firewall|1.0|{}|{}|{}|rt={} cs1={} cs1Label=entryId{}",
        cef_escape(verdict_str),
        tool_function,
        severity,
        rt_val,
        cs1_val,
        reason_ext,
    )
}

/// Escape special characters for CEF header fields.
///
/// Per the CEF specification, the following characters must be escaped in
/// header values (pipe-delimited fields): backslash, pipe, newline, carriage return.
fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        // SECURITY (R15-SIEM-2): Unicode line separators can inject fake CEF entries
        .replace(['\u{2028}', '\u{2029}'], "\\n")
        // SECURITY (R29-SUP-2): Control chars that break SIEM parsers
        .replace('\0', "\\0")
        .replace('\x0B', "\\v")
        .replace('\x0C', "\\f")
        .replace('\u{0085}', "\\n")
}

/// Truncate a string to at most `max_bytes` bytes, respecting UTF-8 character boundaries.
///
/// SECURITY (R35-SUP-2): The CEF spec limits extension values to 1023 bytes. Truncating
/// by character count is incorrect for multi-byte UTF-8 strings (e.g., 200 emoji characters
/// = 800 bytes, but 300 emoji = 1200 bytes which exceeds the CEF limit). This function
/// finds the last valid UTF-8 character boundary at or before `max_bytes`.
fn truncate_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Escape special characters for CEF extension values (key=value pairs).
///
/// Per the CEF specification, extension values must escape: backslash,
/// equals sign, newline, carriage return. We also escape pipes as a
/// defense-in-depth measure — while the CEF spec does not require pipe
/// escaping in extensions, unescaped pipes confuse many SIEM parsers
/// and can break field boundary detection.
fn cef_escape_ext(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        // SECURITY (R25-SUP-1): Escape pipes in extensions to prevent parser confusion.
        // Many SIEMs split on unescaped pipes regardless of position, allowing
        // attacker-controlled extension values to inject fake header fields.
        .replace('|', "\\|")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        // SECURITY (R15-SIEM-2): Unicode line separators can inject fake CEF entries
        .replace(['\u{2028}', '\u{2029}'], "\\n")
        // SECURITY (R29-SUP-2): Control chars that break SIEM parsers
        .replace('\0', "\\0")
        .replace('\x0B', "\\v")
        .replace('\x0C', "\\f")
        .replace('\u{0085}', "\\n")
}

/// Convert an AuditEntry to JSON Lines format (one JSON object per line).
///
/// Uses compact serialization (no pretty-print) with a trailing newline.
/// If serialization fails (which should not happen for a valid AuditEntry),
/// returns an empty string rather than panicking.
pub fn to_json_lines(entry: &AuditEntry) -> String {
    match serde_json::to_string(entry) {
        Ok(json) => format!("{json}\n"),
        Err(e) => {
            // GAP-Q04: Log serialization failures instead of silently returning empty.
            tracing::warn!(
                entry_id = %entry.id,
                error = %e,
                "Failed to serialize audit entry to JSON Lines"
            );
            format!(
                "{}\n",
                serde_json::json!({
                    "error": "serialization_failed",
                    "entry_id": entry.id
                })
            )
        }
    }
}

/// Format a batch of entries in the requested format.
///
/// Returns a single string with all entries formatted and newline-separated.
pub fn format_entries(entries: &[AuditEntry], format: ExportFormat) -> String {
    let mut output = String::new();
    for entry in entries {
        match format {
            ExportFormat::Cef => {
                output.push_str(&to_cef(entry));
                output.push('\n');
            }
            ExportFormat::JsonLines => {
                output.push_str(&to_json_lines(entry));
            }
            ExportFormat::Ocsf => {
                let event = ocsf::audit_entry_to_ocsf(entry);
                match ocsf::to_json(&event) {
                    Ok(json) => {
                        output.push_str(&json);
                        output.push('\n');
                    }
                    Err(e) => {
                        tracing::warn!(
                            entry_id = %entry.id,
                            error = %e,
                            "Failed to serialize audit entry to OCSF"
                        );
                        output.push_str(&format!(
                            "{}\n",
                            serde_json::json!({
                                "error": "ocsf_serialization_failed",
                                "entry_id": entry.id
                            })
                        ));
                    }
                }
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_types::Action;

    /// Helper to create a test AuditEntry with the given verdict.
    fn make_entry(tool: &str, function: &str, verdict: Verdict) -> AuditEntry {
        AuditEntry {
            id: "test-entry-001".to_string(),
            action: Action::new(tool, function, serde_json::json!({"path": "/tmp/test"})),
            verdict,
            timestamp: "2026-02-04T12:00:00Z".to_string(),
            metadata: serde_json::json!({"source": "test"}),
            sequence: 0,
            entry_hash: Some("abc123".to_string()),
            prev_hash: None,
            commitment: None,
            tenant_id: None,
        }
    }

    #[test]
    fn test_cef_format_allow_verdict() {
        let entry = make_entry("read_file", "execute", Verdict::Allow);
        let cef = to_cef(&entry);

        assert!(cef.starts_with("CEF:0|Vellaveto|MCP Firewall|1.0|"));
        assert!(cef.contains("|Allow|"));
        assert!(cef.contains("read_file:execute"));
        assert!(cef.contains("|1|")); // severity 1 for Allow
        assert!(cef.contains("rt=2026-02-04T12:00:00Z"));
        assert!(cef.contains("cs1=test-entry-001"));
        assert!(cef.contains("cs1Label=entryId"));
    }

    #[test]
    fn test_cef_format_deny_verdict() {
        let entry = make_entry(
            "bash",
            "exec",
            Verdict::Deny {
                reason: "blocked by policy".to_string(),
            },
        );
        let cef = to_cef(&entry);

        assert!(cef.contains("|Deny|"));
        assert!(cef.contains("bash:exec"));
        assert!(cef.contains("|8|")); // severity 8 for Deny
    }

    #[test]
    fn test_cef_deny_includes_reason() {
        // R24-SUP-3: CEF output must include deny reason for SIEM analysts
        let entry = make_entry(
            "bash",
            "exec",
            Verdict::Deny {
                reason: "blocked by policy X".to_string(),
            },
        );
        let cef = to_cef(&entry);
        assert!(
            cef.contains("cs2=blocked by policy X"),
            "CEF should include deny reason, got: {}",
            cef
        );
        assert!(
            cef.contains("cs2Label=denyReason"),
            "CEF should label deny reason, got: {}",
            cef
        );
    }

    #[test]
    fn test_cef_allow_has_no_reason() {
        let entry = make_entry("t", "f", Verdict::Allow);
        let cef = to_cef(&entry);
        assert!(
            !cef.contains("cs2="),
            "Allow verdict should have no reason field, got: {}",
            cef
        );
    }

    #[test]
    fn test_cef_severity_mapping() {
        // Allow -> severity 1
        let allow_entry = make_entry("t", "f", Verdict::Allow);
        let allow_cef = to_cef(&allow_entry);
        assert!(
            allow_cef.contains("|1|"),
            "Allow should have severity 1, got: {}",
            allow_cef
        );

        // RequireApproval -> severity 5
        let approval_entry = make_entry(
            "t",
            "f",
            Verdict::RequireApproval {
                reason: "needs review".to_string(),
            },
        );
        let approval_cef = to_cef(&approval_entry);
        assert!(
            approval_cef.contains("|5|"),
            "RequireApproval should have severity 5, got: {}",
            approval_cef
        );

        // Deny -> severity 8
        let deny_entry = make_entry(
            "t",
            "f",
            Verdict::Deny {
                reason: "denied".to_string(),
            },
        );
        let deny_cef = to_cef(&deny_entry);
        assert!(
            deny_cef.contains("|8|"),
            "Deny should have severity 8, got: {}",
            deny_cef
        );
    }

    #[test]
    fn test_json_lines_format() {
        let entry = make_entry("read_file", "execute", Verdict::Allow);
        let jsonl = to_json_lines(&entry);

        // Must end with exactly one newline
        assert!(jsonl.ends_with('\n'));
        assert!(!jsonl.ends_with("\n\n"));

        // Must be valid JSON when trimmed
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.trim()).expect("JSON Lines output must be valid JSON");

        // Spot-check key fields
        assert_eq!(parsed["id"], "test-entry-001");
        assert_eq!(parsed["action"]["tool"], "read_file");
        assert_eq!(parsed["action"]["function"], "execute");
        assert_eq!(parsed["verdict"], "Allow");
        assert_eq!(parsed["timestamp"], "2026-02-04T12:00:00Z");
    }

    #[test]
    fn test_format_entries_batch() {
        let entries = vec![
            make_entry("tool_a", "func_a", Verdict::Allow),
            make_entry(
                "tool_b",
                "func_b",
                Verdict::Deny {
                    reason: "blocked".to_string(),
                },
            ),
        ];

        // CEF batch
        let cef_output = format_entries(&entries, ExportFormat::Cef);
        let cef_lines: Vec<&str> = cef_output.trim_end().split('\n').collect();
        assert_eq!(cef_lines.len(), 2, "Should have 2 CEF lines");
        assert!(cef_lines[0].contains("tool_a:func_a"));
        assert!(cef_lines[1].contains("tool_b:func_b"));

        // JSONL batch
        let jsonl_output = format_entries(&entries, ExportFormat::JsonLines);
        let jsonl_lines: Vec<&str> = jsonl_output.trim_end().split('\n').collect();
        assert_eq!(jsonl_lines.len(), 2, "Should have 2 JSONL lines");
        // Each line must be valid JSON
        for line in &jsonl_lines {
            let _: serde_json::Value =
                serde_json::from_str(line).expect("Each JSONL line must be valid JSON");
        }

        // OCSF batch
        let ocsf_output = format_entries(&entries, ExportFormat::Ocsf);
        let ocsf_lines: Vec<&str> = ocsf_output.trim_end().split('\n').collect();
        assert_eq!(ocsf_lines.len(), 2, "Should have 2 OCSF lines");
        // Each line must be valid JSON with OCSF fields
        for line in &ocsf_lines {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("Each OCSF line must be valid JSON");
            assert_eq!(parsed["class_uid"], 3002, "OCSF class_uid must be 3002");
            assert_eq!(parsed["category_uid"], 3, "OCSF category_uid must be 3");
        }
        // First entry (Allow) should have activity_id 1
        let first: serde_json::Value = serde_json::from_str(ocsf_lines[0]).unwrap();
        assert_eq!(first["activity_id"], 1);
        // Second entry (Deny) should have activity_id 2
        let second: serde_json::Value = serde_json::from_str(ocsf_lines[1]).unwrap();
        assert_eq!(second["activity_id"], 2);

        // Empty batch
        let empty_cef = format_entries(&[], ExportFormat::Cef);
        assert!(empty_cef.is_empty());
        let empty_jsonl = format_entries(&[], ExportFormat::JsonLines);
        assert!(empty_jsonl.is_empty());
        let empty_ocsf = format_entries(&[], ExportFormat::Ocsf);
        assert!(empty_ocsf.is_empty());
    }

    #[test]
    fn test_cef_escape_special_chars() {
        // Backslash
        assert_eq!(cef_escape("a\\b"), "a\\\\b");
        // Pipe
        assert_eq!(cef_escape("a|b"), "a\\|b");
        // Newline
        assert_eq!(cef_escape("a\nb"), "a\\nb");
        // Carriage return
        assert_eq!(cef_escape("a\rb"), "a\\rb");
        // Multiple special chars
        assert_eq!(cef_escape("a\\|b\nc\rd"), "a\\\\\\|b\\nc\\rd");
        // No special chars
        assert_eq!(cef_escape("normal text"), "normal text");
        // Empty string
        assert_eq!(cef_escape(""), "");
    }

    #[test]
    fn test_export_format_from_str() {
        assert_eq!(ExportFormat::parse_format("cef"), Some(ExportFormat::Cef));
        assert_eq!(ExportFormat::parse_format("CEF"), Some(ExportFormat::Cef));
        assert_eq!(ExportFormat::parse_format("Cef"), Some(ExportFormat::Cef));
        assert_eq!(
            ExportFormat::parse_format("jsonl"),
            Some(ExportFormat::JsonLines)
        );
        assert_eq!(
            ExportFormat::parse_format("json_lines"),
            Some(ExportFormat::JsonLines)
        );
        assert_eq!(
            ExportFormat::parse_format("jsonlines"),
            Some(ExportFormat::JsonLines)
        );
        assert_eq!(
            ExportFormat::parse_format("JSONL"),
            Some(ExportFormat::JsonLines)
        );
        assert_eq!(ExportFormat::parse_format("ocsf"), Some(ExportFormat::Ocsf));
        assert_eq!(ExportFormat::parse_format("OCSF"), Some(ExportFormat::Ocsf));
        assert_eq!(ExportFormat::parse_format("xml"), None);
        assert_eq!(ExportFormat::parse_format(""), None);
    }

    #[test]
    fn test_cef_entry_with_special_chars_in_fields() {
        // Tool name with pipe character (should be escaped)
        let entry = make_entry("tool|with|pipes", "func\\with\\backslash", Verdict::Allow);
        let cef = to_cef(&entry);
        // Verify the output doesn't break CEF format (extra unescaped pipes)
        assert!(cef.contains("tool\\|with\\|pipes"));
        assert!(cef.contains("func\\\\with\\\\backslash"));
        // The CEF header should still have exactly 7 pipe-delimited fields
        // (unescaped pipes count)
        let unescaped_pipes = cef
            .chars()
            .zip(cef.chars().skip(1).chain(std::iter::once('\0')))
            .filter(|&(prev, cur)| cur == '|' && prev != '\\')
            .count()
            // Also count pipes at position 0 if present
            + if cef.starts_with('|') { 1 } else { 0 };
        // CEF:0|vendor|product|version|sigId|name|severity|extensions
        // That's 7 unescaped pipes
        assert!(
            unescaped_pipes >= 7,
            "CEF should have at least 7 unescaped pipes, got {}",
            unescaped_pipes
        );
    }

    // ── Adversarial Tests: CEF Extension Escaping ──

    #[test]
    fn test_cef_ext_escape_equals_sign() {
        // CEF extension values must escape '=' to prevent injection
        assert_eq!(cef_escape_ext("key=value"), "key\\=value");
        assert_eq!(cef_escape_ext("a=b=c"), "a\\=b\\=c");
    }

    #[test]
    fn test_cef_ext_escape_backslash_and_newline() {
        assert_eq!(cef_escape_ext("a\\b"), "a\\\\b");
        assert_eq!(cef_escape_ext("a\nb"), "a\\nb");
        assert_eq!(cef_escape_ext("a\rb"), "a\\rb");
    }

    #[test]
    fn test_cef_ext_escapes_pipe() {
        // SECURITY (R25-SUP-1): Pipes are now escaped in extensions too,
        // to prevent SIEM parser confusion from attacker-controlled values.
        assert_eq!(cef_escape_ext("a|b"), "a\\|b");
    }

    #[test]
    fn test_cef_escape_unicode_line_separators() {
        // U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR
        // These could inject fake CEF lines if not escaped
        assert_eq!(cef_escape("before\u{2028}after"), "before\\nafter");
        assert_eq!(cef_escape("before\u{2029}after"), "before\\nafter");
        assert_eq!(cef_escape_ext("val\u{2028}ue"), "val\\nue");
        assert_eq!(cef_escape_ext("val\u{2029}ue"), "val\\nue");
    }

    #[test]
    fn test_cef_header_does_not_escape_equals() {
        // Header escaping should NOT escape '=' (only needed in extensions)
        assert_eq!(cef_escape("a=b"), "a=b");
    }

    #[test]
    fn test_cef_entry_with_equals_in_id() {
        // Entry ID with '=' should be escaped in extensions
        let entry = make_entry("tool", "func", Verdict::Allow);
        let mut entry_with_eq = entry;
        entry_with_eq.id = "entry=id=test".to_string();
        let cef = to_cef(&entry_with_eq);
        assert!(
            cef.contains("cs1=entry\\=id\\=test"),
            "Equals signs in extension values must be escaped: {}",
            cef
        );
    }

    // ── R35-SUP-2: Byte-aware CEF extension truncation ──

    #[test]
    fn test_r35_sup_2_truncate_bytes_ascii() {
        // ASCII: 1 byte per character, straightforward truncation
        let s = "a".repeat(1500);
        let t = truncate_bytes(&s, 1000);
        assert_eq!(t.len(), 1000);
        assert!(std::str::from_utf8(t.as_bytes()).is_ok());
    }

    #[test]
    fn test_r35_sup_2_cef_multibyte_truncation() {
        // 300 emoji characters = 1200 bytes in UTF-8, should be truncated
        let emoji_str = "\u{1F600}".repeat(300); // U+1F600 = 4 bytes each
        assert_eq!(emoji_str.len(), 1200);
        let truncated = truncate_bytes(&emoji_str, 1000);
        assert!(truncated.len() <= 1000);
        // Must be on a valid UTF-8 boundary (250 * 4 = 1000)
        assert_eq!(truncated.len(), 1000);
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
    }

    #[test]
    fn test_r35_sup_2_truncate_bytes_boundary() {
        // 2-byte chars: truncation at an odd byte must back up
        let s = "\u{00E9}".repeat(600); // e-acute = 2 bytes each, total 1200
        let t = truncate_bytes(&s, 1001); // 1001 is mid-character
        assert!(t.len() <= 1001);
        assert!(t.len() == 1000); // backs up to 500 * 2
        assert!(std::str::from_utf8(t.as_bytes()).is_ok());
    }

    #[test]
    fn test_r35_sup_2_truncate_bytes_no_truncation_needed() {
        let s = "short";
        let t = truncate_bytes(s, 1000);
        assert_eq!(t, "short");
    }

    #[test]
    fn test_r35_sup_2_cef_deny_reason_truncated() {
        // A very long deny reason should be truncated in the CEF output
        let long_reason = "x".repeat(2000);
        let entry = make_entry(
            "tool",
            "func",
            Verdict::Deny {
                reason: long_reason,
            },
        );
        let cef = to_cef(&entry);
        // The cs2= value should be present but truncated
        assert!(cef.contains("cs2="));
        assert!(cef.contains("cs2Label=denyReason"));
        // The full CEF line should be reasonable size (well under 4K)
        // Each extension value capped at 1000 bytes
        let cs2_start = cef.find("cs2=").unwrap() + 4;
        let cs2_end = cef[cs2_start..].find(" cs2Label").unwrap();
        let cs2_value = &cef[cs2_start..cs2_start + cs2_end];
        assert!(
            cs2_value.len() <= 1000,
            "CEF extension value should be <= 1000 bytes, got {}",
            cs2_value.len()
        );
    }

    #[test]
    fn test_r35_sup_2_cef_multibyte_deny_reason_truncated() {
        // Deny reason with 4-byte emoji chars that exceeds CEF limit
        let long_reason = "\u{1F600}".repeat(300); // 1200 bytes
        let entry = make_entry(
            "tool",
            "func",
            Verdict::Deny {
                reason: long_reason,
            },
        );
        let cef = to_cef(&entry);
        assert!(cef.contains("cs2="));
        // Extract the cs2 value and verify it's valid UTF-8 and within limit
        let cs2_start = cef.find("cs2=").unwrap() + 4;
        let cs2_end = cef[cs2_start..].find(" cs2Label").unwrap();
        let cs2_value = &cef[cs2_start..cs2_start + cs2_end];
        assert!(
            cs2_value.len() <= 1000,
            "Multi-byte CEF extension value should be <= 1000 bytes, got {}",
            cs2_value.len()
        );
        // Must be valid UTF-8 (no mid-character truncation)
        assert!(
            std::str::from_utf8(cs2_value.as_bytes()).is_ok(),
            "Truncated CEF value must be valid UTF-8"
        );
    }

    // ── R36-SUP-5: CEF header name field length-bounded ──

    #[test]
    fn test_r36_sup_5_cef_header_name_truncated() {
        // Tool and function names that produce a name field > 500 bytes
        let long_tool = "a".repeat(300);
        let long_func = "b".repeat(300);
        let entry = make_entry(&long_tool, &long_func, Verdict::Allow);
        let cef = to_cef(&entry);

        // Extract the name field (position 5, 0-indexed) from the CEF header.
        // CEF:0|vendor|product|version|sigId|name|severity|extensions
        // Split on unescaped pipes to find the name field.
        let parts: Vec<&str> = cef.splitn(8, '|').collect();
        assert!(
            parts.len() >= 7,
            "CEF should have at least 7 pipe-delimited fields"
        );
        let name_field = parts[5];
        // The name field should be truncated to ~503 bytes (500 + "...")
        assert!(
            name_field.len() <= 503,
            "CEF name field should be <= 503 bytes (500 + '...'), got {}",
            name_field.len()
        );
        assert!(
            name_field.ends_with("..."),
            "Truncated CEF name field should end with '...', got: {}",
            &name_field[name_field.len().saturating_sub(10)..]
        );
    }

    #[test]
    fn test_r36_sup_5_cef_header_name_short_not_truncated() {
        // Normal-length tool/function names should not be truncated
        let entry = make_entry("read_file", "execute", Verdict::Allow);
        let cef = to_cef(&entry);
        let parts: Vec<&str> = cef.splitn(8, '|').collect();
        let name_field = parts[5];
        assert_eq!(name_field, "read_file:execute");
        assert!(
            !name_field.ends_with("..."),
            "Short name should not be truncated"
        );
    }

    #[test]
    fn test_r36_sup_5_cef_header_name_multibyte_boundary() {
        // Tool name with multi-byte UTF-8 chars near the 500-byte boundary
        // Each emoji is 4 bytes. 125 emoji = 500 bytes exactly for tool name alone.
        let emoji_tool = "\u{1F600}".repeat(125); // 500 bytes
        let entry = make_entry(&emoji_tool, "f", Verdict::Allow);
        let cef = to_cef(&entry);
        // The tool:function = 500+1+1 = 502 bytes, within 500 after escaping
        // Actually the escaped form is the same since emoji don't need CEF escaping.
        // tool_function = emoji(500 bytes) + ":" + "f" = 502 bytes > 500, so truncated
        let parts: Vec<&str> = cef.splitn(8, '|').collect();
        let name_field = parts[5];
        assert!(
            name_field.len() <= 503,
            "Multi-byte name field should be <= 503 bytes, got {}",
            name_field.len()
        );
        // Must be valid UTF-8
        assert!(
            std::str::from_utf8(name_field.as_bytes()).is_ok(),
            "Truncated name field must be valid UTF-8"
        );
    }

    /// R226-AUD-5: CEF timestamp without timezone gets Z appended.
    #[test]
    fn test_r226_cef_timestamp_without_timezone_gets_z() {
        let mut entry = make_entry("tool", "fn", Verdict::Allow);
        entry.timestamp = "2026-02-26T14:30:00".to_string(); // No timezone
        let cef = to_cef(&entry);
        assert!(
            cef.contains("rt=2026-02-26T14:30:00Z"),
            "Timestamp without TZ must get Z appended, got: {}",
            cef
        );
    }

    /// R226-AUD-5: CEF timestamp with Z is left unchanged.
    #[test]
    fn test_r226_cef_timestamp_with_z_unchanged() {
        let entry = make_entry("tool", "fn", Verdict::Allow);
        let cef = to_cef(&entry);
        assert!(
            cef.contains("rt=2026-02-04T12:00:00Z"),
            "Timestamp with Z must be preserved, got: {}",
            cef
        );
    }

    /// R226-AUD-5: CEF timestamp with offset is left unchanged.
    #[test]
    fn test_r226_cef_timestamp_with_offset_unchanged() {
        let mut entry = make_entry("tool", "fn", Verdict::Allow);
        entry.timestamp = "2026-02-26T14:30:00+05:30".to_string();
        let cef = to_cef(&entry);
        assert!(
            cef.contains("rt=2026-02-26T14:30:00+05:30"),
            "Timestamp with offset must be preserved, got: {}",
            cef
        );
    }
}
