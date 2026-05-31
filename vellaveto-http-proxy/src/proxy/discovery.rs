// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Transport discovery and negotiation endpoint.
//!
//! Implements `GET /.well-known/mcp-transport` (RFC 8615) for MCP June 2026
//! spec compliance. Advertises available transports, SDK tier, and supported
//! protocol versions.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use vellaveto_config::TransportConfig;
use vellaveto_types::{SdkCapabilities, SdkTier, TransportEndpoint, TransportProtocol};

use super::ProxyState;

/// Vellaveto's declared SDK tier.
///
/// Vellaveto provides multi-transport support, advanced threat detection,
/// compliance evidence, and protocol extensions — qualifying as Extended.
pub const VELLAVETO_SDK_TIER: SdkTier = SdkTier::Extended;

/// Build SDK capabilities for the current Vellaveto instance.
pub fn build_sdk_capabilities() -> SdkCapabilities {
    let versions = vellaveto_config::StreamableHttpConfig::default()
        .supported_protocol_versions()
        .into_iter()
        .map(String::from)
        .collect();
    build_sdk_capabilities_with_versions(versions)
}

fn build_sdk_capabilities_with_versions(supported_versions: Vec<String>) -> SdkCapabilities {
    SdkCapabilities {
        tier: VELLAVETO_SDK_TIER,
        capabilities: vec![
            "policy-evaluation".to_string(),
            "audit-logging".to_string(),
            "dlp-scanning".to_string(),
            "injection-detection".to_string(),
            "multi-transport".to_string(),
            "threat-detection".to_string(),
            "compliance-evidence".to_string(),
            "protocol-extensions".to_string(),
            "human-approval".to_string(),
            "oauth-validation".to_string(),
            "transport-negotiation".to_string(),
            "backward-compatibility".to_string(),
        ],
        supported_versions,
    }
}

/// Build the list of available transport endpoints for the discovery response.
pub fn build_transport_endpoints(state: &ProxyState) -> Vec<TransportEndpoint> {
    let restricted = &state.transport_config.restricted_transports;
    let versions: Vec<String> = state
        .streamable_http
        .supported_protocol_versions()
        .into_iter()
        .map(String::from)
        .collect();

    let mut endpoints = Vec::new();

    // HTTP is always available (primary transport).
    if !restricted.contains(&TransportProtocol::Http) {
        let base = format!("http://{}/mcp", state.bind_addr);
        endpoints.push(TransportEndpoint {
            protocol: TransportProtocol::Http,
            url: base,
            available: true,
            protocol_versions: versions.clone(),
        });
    }

    // WebSocket is always available alongside HTTP.
    if !restricted.contains(&TransportProtocol::WebSocket) {
        let ws_url = format!("ws://{}/mcp/ws", state.bind_addr);
        endpoints.push(TransportEndpoint {
            protocol: TransportProtocol::WebSocket,
            url: ws_url,
            available: true,
            protocol_versions: versions.clone(),
        });
    }

    // gRPC is available only when a gRPC port is configured.
    if !restricted.contains(&TransportProtocol::Grpc) {
        if let Some(grpc_port) = state.grpc_port {
            let grpc_url = format!("http://{}:{}", state.bind_addr.ip(), grpc_port);
            endpoints.push(TransportEndpoint {
                protocol: TransportProtocol::Grpc,
                url: grpc_url,
                available: true,
                protocol_versions: versions,
            });
        }
    }

    endpoints
}

/// Discovery response returned by `GET /.well-known/mcp-transport`.
#[derive(Debug, Serialize)]
pub struct TransportDiscoveryResponse {
    /// Available transport endpoints.
    pub transports: Vec<TransportEndpoint>,
    /// SDK capabilities and tier.
    pub sdk: SdkCapabilities,
    /// Supported protocol versions (highest first).
    pub protocol_versions: Vec<String>,
}

/// Handler for `GET /.well-known/mcp-transport`.
///
/// Returns a JSON discovery document describing available transports,
/// SDK tier, and supported protocol versions. Returns 404 when
/// `transport.discovery_enabled` is false.
pub async fn handle_transport_discovery(State(state): State<ProxyState>) -> Response {
    if !state.transport_config.discovery_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let transports = build_transport_endpoints(&state);
    let protocol_versions: Vec<String> = state
        .streamable_http
        .supported_protocol_versions()
        .into_iter()
        .map(String::from)
        .collect();

    let sdk = if state.transport_config.advertise_capabilities {
        build_sdk_capabilities_with_versions(protocol_versions.clone())
    } else {
        SdkCapabilities {
            tier: VELLAVETO_SDK_TIER,
            capabilities: Vec::new(),
            supported_versions: Vec::new(),
        }
    };

    let response = TransportDiscoveryResponse {
        transports,
        sdk,
        protocol_versions,
    };

    Json(response).into_response()
}

/// Maximum entries in a parsed transport preference list (FIND-R42-002).
/// There are only 4 protocol variants, so more than 4 is redundant.
const MAX_TRANSPORT_PREFERENCES: usize = 4;

/// Parse the `mcp-transport-preference` header value into an ordered list
/// of `TransportProtocol` values. Unknown values are silently ignored.
///
/// SECURITY (FIND-R42-002): Deduplicates and caps at `MAX_TRANSPORT_PREFERENCES`
/// to prevent DoS via headers with hundreds of comma-separated entries.
pub fn parse_transport_preference(header: &str) -> Vec<TransportProtocol> {
    let mut seen = std::collections::HashSet::new();
    header
        .split(',')
        .filter_map(|s| match s.trim().to_lowercase().as_str() {
            "grpc" => Some(TransportProtocol::Grpc),
            "websocket" | "ws" => Some(TransportProtocol::WebSocket),
            "http" | "sse" => Some(TransportProtocol::Http),
            "stdio" => Some(TransportProtocol::Stdio),
            _ => None,
        })
        .filter(|proto| seen.insert(*proto))
        .take(MAX_TRANSPORT_PREFERENCES)
        .collect()
}

/// Negotiate the best available transport given client preferences,
/// available endpoints, and restricted transports.
///
/// Pure logic — no I/O, no async. Returns the first preferred endpoint
/// that is both available and not restricted.
pub fn negotiate_transport(
    preferences: &[TransportProtocol],
    available: &[TransportEndpoint],
    restricted: &[TransportProtocol],
) -> Option<TransportEndpoint> {
    for pref in preferences {
        if restricted.contains(pref) {
            continue;
        }
        if let Some(endpoint) = available
            .iter()
            .find(|e| e.protocol == *pref && e.available)
        {
            return Some(endpoint.clone());
        }
    }
    None
}

/// Resolve transport priority order for a given tool name (Phase 29).
///
/// Resolution order (first match wins):
/// 1. Per-tool override from `config.transport_overrides` (glob match)
/// 2. Client preference from `mcp-transport-preference` header
/// 3. `config.upstream_priorities`
/// 4. Default: `[Grpc, WebSocket, Http]` (Stdio only if `stdio_fallback_enabled`)
///
/// Restricted transports are filtered out in all cases.
pub fn resolve_transport_priority(
    tool_name: &str,
    client_preference: Option<&[TransportProtocol]>,
    config: &TransportConfig,
) -> Vec<TransportProtocol> {
    let restricted = &config.restricted_transports;

    // 1. Per-tool override (glob match).
    // SECURITY (FIND-R41-013): Sort keys lexicographically for deterministic
    // matching when multiple glob patterns overlap.
    let mut sorted_overrides: Vec<_> = config.transport_overrides.iter().collect();
    sorted_overrides.sort_by_key(|(glob, _)| glob.as_str());
    for (glob_pattern, protos) in sorted_overrides {
        if glob_matches(glob_pattern, tool_name) {
            return filter_restricted(protos, restricted, config.stdio_fallback_enabled);
        }
    }

    // 2. Client preference.
    if let Some(prefs) = client_preference {
        if !prefs.is_empty() {
            return filter_restricted(prefs, restricted, config.stdio_fallback_enabled);
        }
    }

    // 3. Config upstream_priorities.
    if !config.upstream_priorities.is_empty() {
        return filter_restricted(
            &config.upstream_priorities,
            restricted,
            config.stdio_fallback_enabled,
        );
    }

    // 4. Default order.
    let mut defaults = vec![
        TransportProtocol::Grpc,
        TransportProtocol::WebSocket,
        TransportProtocol::Http,
    ];
    if config.stdio_fallback_enabled {
        defaults.push(TransportProtocol::Stdio);
    }
    filter_restricted(&defaults, restricted, config.stdio_fallback_enabled)
}

/// Filter out restricted transports and stdio (unless enabled).
fn filter_restricted(
    protos: &[TransportProtocol],
    restricted: &[TransportProtocol],
    stdio_enabled: bool,
) -> Vec<TransportProtocol> {
    protos
        .iter()
        .copied()
        .filter(|p| !restricted.contains(p))
        .filter(|p| *p != TransportProtocol::Stdio || stdio_enabled)
        .collect()
}

/// Simple glob matching for tool name patterns.
///
/// Supports `*` (match any characters) and `?` (match single character).
/// Used for `transport_overrides` keys.
///
/// SECURITY (FIND-R41-012): Uses iterative DP (O(M*N)) instead of recursive
/// backtracking which had exponential worst-case complexity O(2^m).
fn glob_matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let m = p.len();
    let n = t.len();

    if m == 0 {
        return n == 0;
    }

    // dp[i][j] = true if pattern[0..i] matches text[0..j].
    // Rolling two rows: prev_row = dp[i-1], curr_row = dp[i].
    let mut prev_row = vec![false; n + 1];
    prev_row[0] = true; // Empty pattern matches empty text.

    let mut all_stars = true;

    for i in 1..=m {
        let mut curr_row = vec![false; n + 1];
        all_stars = all_stars && p[i - 1] == '*';
        curr_row[0] = all_stars; // All-star prefix matches empty text.

        for j in 1..=n {
            match p[i - 1] {
                '*' => {
                    // '*' matches zero chars (curr_row[j-1]) or one+ chars (prev_row[j]).
                    curr_row[j] = curr_row[j - 1] || prev_row[j];
                }
                '?' => {
                    // '?' matches exactly one character.
                    curr_row[j] = prev_row[j - 1];
                }
                c => {
                    // Literal match.
                    curr_row[j] = prev_row[j - 1] && t[j - 1] == c;
                }
            }
        }

        prev_row = curr_row;
    }

    prev_row[n]
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use std::collections::HashMap;

    fn default_config() -> TransportConfig {
        TransportConfig::default()
    }

    #[test]
    fn test_resolve_transport_priority_default_order() {
        let config = default_config();
        let result = resolve_transport_priority("any_tool", None, &config);
        assert_eq!(
            result,
            vec![
                TransportProtocol::Grpc,
                TransportProtocol::WebSocket,
                TransportProtocol::Http,
            ]
        );
    }

    #[test]
    fn test_resolve_transport_priority_config_priorities() {
        let config = TransportConfig {
            upstream_priorities: vec![TransportProtocol::Http, TransportProtocol::Grpc],
            ..default_config()
        };
        let result = resolve_transport_priority("any_tool", None, &config);
        assert_eq!(
            result,
            vec![TransportProtocol::Http, TransportProtocol::Grpc]
        );
    }

    #[test]
    fn test_resolve_transport_priority_client_preference() {
        let config = TransportConfig {
            upstream_priorities: vec![TransportProtocol::Http],
            ..default_config()
        };
        let prefs = vec![TransportProtocol::WebSocket, TransportProtocol::Http];
        let result = resolve_transport_priority("any_tool", Some(&prefs), &config);
        // Client preference takes precedence over config.
        assert_eq!(
            result,
            vec![TransportProtocol::WebSocket, TransportProtocol::Http]
        );
    }

    #[test]
    fn test_resolve_transport_priority_per_tool_override() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "fs_*".to_string(),
            vec![TransportProtocol::Http, TransportProtocol::WebSocket],
        );
        let config = TransportConfig {
            transport_overrides: overrides,
            upstream_priorities: vec![TransportProtocol::Grpc],
            ..default_config()
        };
        let prefs = vec![TransportProtocol::Grpc];
        // Per-tool override takes highest precedence.
        let result = resolve_transport_priority("fs_read", Some(&prefs), &config);
        assert_eq!(
            result,
            vec![TransportProtocol::Http, TransportProtocol::WebSocket]
        );
    }

    #[test]
    fn test_resolve_transport_priority_per_tool_no_match() {
        let mut overrides = HashMap::new();
        overrides.insert("fs_*".to_string(), vec![TransportProtocol::Http]);
        let config = TransportConfig {
            transport_overrides: overrides,
            ..default_config()
        };
        // Tool doesn't match the glob, so falls through to default.
        let result = resolve_transport_priority("db_query", None, &config);
        assert_eq!(
            result,
            vec![
                TransportProtocol::Grpc,
                TransportProtocol::WebSocket,
                TransportProtocol::Http,
            ]
        );
    }

    #[test]
    fn test_resolve_transport_priority_restricted_filtered() {
        let config = TransportConfig {
            restricted_transports: vec![TransportProtocol::Grpc],
            ..default_config()
        };
        let result = resolve_transport_priority("any_tool", None, &config);
        assert!(!result.contains(&TransportProtocol::Grpc));
        assert_eq!(
            result,
            vec![TransportProtocol::WebSocket, TransportProtocol::Http]
        );
    }

    #[test]
    fn test_resolve_transport_priority_stdio_only_when_enabled() {
        let config = TransportConfig {
            stdio_fallback_enabled: true,
            stdio_command: Some("/usr/bin/mcp".to_string()),
            ..default_config()
        };
        let result = resolve_transport_priority("any_tool", None, &config);
        assert!(result.contains(&TransportProtocol::Stdio));

        // Without stdio enabled, Stdio should not appear.
        let config2 = default_config();
        let result2 = resolve_transport_priority("any_tool", None, &config2);
        assert!(!result2.contains(&TransportProtocol::Stdio));
    }

    #[test]
    fn test_resolve_transport_priority_empty_client_preference() {
        let config = TransportConfig {
            upstream_priorities: vec![TransportProtocol::Http],
            ..default_config()
        };
        // Empty preference should fall through to config.upstream_priorities.
        let result = resolve_transport_priority("any_tool", Some(&[]), &config);
        assert_eq!(result, vec![TransportProtocol::Http]);
    }

    #[test]
    fn test_glob_matches_basic() {
        assert!(glob_matches("fs_*", "fs_read"));
        assert!(glob_matches("fs_*", "fs_"));
        assert!(!glob_matches("fs_*", "db_read"));
        assert!(glob_matches("*", "anything"));
        assert!(glob_matches("?s_read", "fs_read"));
        assert!(!glob_matches("?s_read", "ffs_read"));
        assert!(glob_matches("exact", "exact"));
        assert!(!glob_matches("exact", "exactx"));
    }

    // ═══════════════════════════════════════════════════════
    // Adversarial audit tests (FIND-R41-012, FIND-R41-013)
    // ═══════════════════════════════════════════════════════

    /// FIND-R41-012: Verify DP-based glob matching completes in bounded time
    /// for patterns that would cause exponential backtracking in a recursive
    /// implementation. Must complete in under 10ms.
    #[test]
    fn test_glob_matches_no_exponential_backtracking() {
        // Pattern with many wildcards that causes O(2^m) in recursive impl.
        let pattern = "*a*a*a*a*a*a*a*a*a*a*b";
        let text = "a".repeat(100); // 100 'a's, no 'b' → must return false.

        let start = std::time::Instant::now();
        let result = glob_matches(pattern, &text);
        let elapsed = start.elapsed();

        assert!(!result, "should not match (no 'b' in text)");
        assert!(
            elapsed.as_millis() < 10,
            "glob match took {}ms — DP should be O(M*N), not exponential",
            elapsed.as_millis()
        );
    }

    /// FIND-R41-012: Extreme pattern (256 chars of alternating *a) + long text.
    #[test]
    fn test_glob_matches_max_length_pattern_bounded() {
        // 128 '*a' pairs = 256 chars (MAX_GLOB_KEY_LEN).
        let pattern = "*a".repeat(128);
        let text = "a".repeat(200);

        let start = std::time::Instant::now();
        let result = glob_matches(&pattern, &text);
        let elapsed = start.elapsed();

        assert!(result, "128 '*a' should match 200 'a's");
        assert!(
            elapsed.as_millis() < 100,
            "glob match took {}ms — must complete in bounded time",
            elapsed.as_millis()
        );
    }

    /// FIND-R41-012: Empty pattern and text edge cases.
    #[test]
    fn test_glob_matches_edge_cases() {
        assert!(glob_matches("", ""));
        assert!(!glob_matches("", "a"));
        assert!(!glob_matches("a", ""));
        assert!(glob_matches("*", ""));
        assert!(glob_matches("**", ""));
        assert!(glob_matches("***", "abc"));
        assert!(glob_matches("?", "x"));
        assert!(!glob_matches("?", ""));
        assert!(!glob_matches("??", "x"));
    }

    /// FIND-R41-013: Verify overlapping globs are resolved deterministically
    /// (lexicographic order of pattern keys).
    #[test]
    fn test_resolve_transport_priority_overlapping_globs_deterministic() {
        let mut overrides = HashMap::new();
        overrides.insert("*_query".to_string(), vec![TransportProtocol::Grpc]);
        overrides.insert("fs_*".to_string(), vec![TransportProtocol::Http]);

        let config = TransportConfig {
            transport_overrides: overrides,
            ..default_config()
        };

        // "fs_query" matches both "fs_*" and "*_query".
        // Lexicographically, "*_query" < "fs_*", so gRPC should win.
        let result = resolve_transport_priority("fs_query", None, &config);
        assert_eq!(
            result,
            vec![TransportProtocol::Grpc],
            "lexicographically first glob (*_query) should take precedence"
        );

        // Run 10x to confirm determinism (would catch HashMap iteration flakiness).
        for _ in 0..10 {
            let r = resolve_transport_priority("fs_query", None, &config);
            assert_eq!(r, vec![TransportProtocol::Grpc]);
        }
    }

    /// FIND-R41-013: Non-overlapping globs should still work correctly.
    #[test]
    fn test_resolve_transport_priority_non_overlapping_globs() {
        let mut overrides = HashMap::new();
        overrides.insert("db_*".to_string(), vec![TransportProtocol::WebSocket]);
        overrides.insert("fs_*".to_string(), vec![TransportProtocol::Http]);

        let config = TransportConfig {
            transport_overrides: overrides,
            ..default_config()
        };

        assert_eq!(
            resolve_transport_priority("fs_read", None, &config),
            vec![TransportProtocol::Http]
        );
        assert_eq!(
            resolve_transport_priority("db_query", None, &config),
            vec![TransportProtocol::WebSocket]
        );
        // Non-matching falls through to default.
        assert_eq!(
            resolve_transport_priority("net_call", None, &config),
            vec![
                TransportProtocol::Grpc,
                TransportProtocol::WebSocket,
                TransportProtocol::Http,
            ]
        );
    }

    // ═══════════════════════════════════════════════════════
    // Adversarial audit tests (FIND-R42-002)
    // ═══════════════════════════════════════════════════════

    /// FIND-R42-002: parse_transport_preference deduplicates entries.
    #[test]
    fn test_parse_transport_preference_dedup() {
        let result = parse_transport_preference("http,http,grpc,http,grpc");
        assert_eq!(
            result,
            vec![TransportProtocol::Http, TransportProtocol::Grpc]
        );
    }

    /// FIND-R42-002: parse_transport_preference caps at MAX_TRANSPORT_PREFERENCES.
    #[test]
    fn test_parse_transport_preference_capped() {
        // Even with 1000 entries, result is capped.
        let header = std::iter::repeat_n("http,grpc,websocket,stdio", 250)
            .collect::<Vec<_>>()
            .join(",");
        let result = parse_transport_preference(&header);
        assert!(result.len() <= MAX_TRANSPORT_PREFERENCES);
        assert_eq!(result.len(), 4); // All 4 unique protocols, exactly.
    }

    /// FIND-R42-002: parse_transport_preference handles aliases correctly.
    #[test]
    fn test_parse_transport_preference_aliases_dedup() {
        // "ws" and "websocket" should both map to WebSocket and be deduped.
        let result = parse_transport_preference("ws,websocket,http,sse");
        assert_eq!(
            result,
            vec![TransportProtocol::WebSocket, TransportProtocol::Http]
        );
    }
}
