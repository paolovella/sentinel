// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Integration tests for the topology discovery pipeline.
//!
//! Verifies the full flow: topology construction → guard wiring →
//! engine pre-filter → policy evaluation, with both static and
//! dynamic topology scenarios.

use std::sync::Arc;

use serde_json::json;
use vellaveto_discovery::guard::TopologyGuard;
use vellaveto_discovery::topology::*;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

/// Build a simple topology with two servers.
fn make_topology() -> TopologyGraph {
    TopologyGraph::from_static(vec![
        StaticServerDecl {
            name: "fs".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "read_file".to_string(),
                    description: "Read a file from disk".to_string(),
                    input_schema: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
                },
                StaticToolDecl {
                    name: "write_file".to_string(),
                    description: "Write content to a file".to_string(),
                    input_schema: json!({"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}),
                },
            ],
            resources: vec![],
        },
        StaticServerDecl {
            name: "web".to_string(),
            tools: vec![StaticToolDecl {
                name: "fetch_url".to_string(),
                description: "Fetch content from a URL".to_string(),
                input_schema: json!({"type": "object", "properties": {"url": {"type": "string"}}}),
            }],
            resources: vec![],
        },
    ])
    .unwrap()
}

fn make_action(tool: &str, function: &str) -> Action {
    Action {
        tool: tool.to_string(),
        function: function.to_string(),
        parameters: json!({}),
        target_paths: vec![],
        target_domains: vec![],
        resolved_ips: vec![],
    }
}

#[cfg(feature = "discovery")]
mod with_discovery_feature {
    use super::*;

    #[test]
    fn test_engine_allows_known_tool_qualified() {
        let topology = make_topology();
        let guard = Arc::new(TopologyGuard::new());
        guard.update(topology);

        let policies = vec![Policy {
            id: "*:*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        }];

        let mut engine = PolicyEngine::with_policies(false, &policies).unwrap();
        engine.set_topology_guard(guard);

        // Qualified name — should pass topology check and be allowed by policy
        let action = make_action("fs::read_file", "");
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "Known qualified tool should be allowed, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_engine_allows_known_tool_unqualified() {
        let topology = make_topology();
        let guard = Arc::new(TopologyGuard::new());
        guard.update(topology);

        let policies = vec![Policy {
            id: "*:*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        }];

        let mut engine = PolicyEngine::with_policies(false, &policies).unwrap();
        engine.set_topology_guard(guard);

        // Unqualified unique name — should resolve and be allowed
        let action = make_action("fetch_url", "");
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "Known unqualified tool should be allowed, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_engine_denies_unknown_tool() {
        let topology = make_topology();
        let guard = Arc::new(TopologyGuard::new());
        guard.update(topology);

        let policies = vec![Policy {
            id: "*:*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        }];

        let mut engine = PolicyEngine::with_policies(false, &policies).unwrap();
        engine.set_topology_guard(guard);

        // Unknown tool — should be denied by topology guard
        let action = make_action("nonexistent_tool", "");
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        match &verdict {
            Verdict::Deny { reason } => {
                assert!(
                    reason.contains("not found in topology"),
                    "Expected topology denial reason, got: {}",
                    reason
                );
            }
            _ => panic!("Unknown tool should be denied, got: {:?}", verdict),
        }
    }

    #[test]
    fn test_engine_denies_unknown_with_suggestion() {
        let topology = make_topology();
        let guard = Arc::new(TopologyGuard::new());
        guard.update(topology);

        let policies = vec![Policy {
            id: "*:*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        }];

        let mut engine = PolicyEngine::with_policies(false, &policies).unwrap();
        engine.set_topology_guard(guard);

        // Typo in tool name — should suggest closest match
        let action = make_action("read_fil", "");
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        match &verdict {
            Verdict::Deny { reason } => {
                assert!(
                    reason.contains("did you mean"),
                    "Expected suggestion in denial reason, got: {}",
                    reason
                );
            }
            _ => panic!("Typo tool should be denied, got: {:?}", verdict),
        }
    }

    #[test]
    fn test_engine_bypasses_when_no_topology_loaded() {
        let guard = Arc::new(TopologyGuard::new());
        // No topology loaded — guard should bypass

        let policies = vec![Policy {
            id: "*:*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        }];

        let mut engine = PolicyEngine::with_policies(false, &policies).unwrap();
        engine.set_topology_guard(guard);

        let action = make_action("any_tool", "");
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        // With no topology loaded, guard bypasses → falls through to policy engine
        assert!(
            matches!(verdict, Verdict::Allow),
            "Should bypass topology when no graph loaded, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_engine_hot_swap_topology() {
        let guard = Arc::new(TopologyGuard::new());

        let policies = vec![Policy {
            id: "*:*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        }];

        let mut engine = PolicyEngine::with_policies(false, &policies).unwrap();
        engine.set_topology_guard(Arc::clone(&guard));

        // Initially no topology — tool passes through
        let action = make_action("fs::read_file", "");
        let v1 = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(v1, Verdict::Allow));

        // Load topology — tool is now known
        guard.update(make_topology());
        let v2 = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(v2, Verdict::Allow));

        // Unknown tool — now denied
        let unknown = make_action("unknown_tool", "");
        let v3 = engine.evaluate_action(&unknown, &policies).unwrap();
        assert!(matches!(v3, Verdict::Deny { .. }));

        // Clear topology — back to bypass
        guard.clear();
        let v4 = engine.evaluate_action(&unknown, &policies).unwrap();
        assert!(matches!(v4, Verdict::Allow));
    }

    #[test]
    fn test_topology_diff_after_update() {
        let v1 = make_topology();
        let v2 = TopologyGraph::from_static(vec![
            StaticServerDecl {
                name: "fs".to_string(),
                tools: vec![
                    StaticToolDecl {
                        name: "read_file".to_string(),
                        description: "Read a file from disk".to_string(),
                        input_schema: json!({"type": "object"}),
                    },
                    StaticToolDecl {
                        name: "write_file".to_string(),
                        description: "Write content to a file".to_string(),
                        input_schema: json!({"type": "object"}),
                    },
                    StaticToolDecl {
                        name: "delete_file".to_string(),
                        description: "Delete a file".to_string(),
                        input_schema: json!({"type": "object"}),
                    },
                ],
                resources: vec![],
            },
            StaticServerDecl {
                name: "web".to_string(),
                tools: vec![StaticToolDecl {
                    name: "fetch_url".to_string(),
                    description: "Fetch content from a URL".to_string(),
                    input_schema: json!({"type": "object"}),
                }],
                resources: vec![],
            },
        ])
        .unwrap();

        let diff = v1.diff(&v2);
        assert!(!diff.is_empty());
        assert_eq!(diff.added_tools.len(), 1);
        assert_eq!(diff.added_tools[0].qualified, "fs::delete_file");
        assert!(!diff.has_removals());
    }

    #[test]
    fn test_topology_config_validation() {
        use vellaveto_config::TopologyConfig;

        // Valid default
        let config = TopologyConfig::default();
        assert!(config.validate().is_ok());

        // Invalid: NaN threshold
        let bad = TopologyConfig {
            inference_threshold: f32::NAN,
            ..Default::default()
        };
        assert!(bad.validate().is_err());

        // Invalid: unknown fallback mode
        let bad = TopologyConfig {
            fallback_mode: "panic".to_string(),
            ..Default::default()
        };
        assert!(bad.validate().is_err());

        // Invalid: zero recrawl interval
        let bad = TopologyConfig {
            recrawl_interval_secs: 0,
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_topology_serialization_roundtrip() {
        let original = make_topology();
        let json = original.to_json().unwrap();
        let restored = TopologyGraph::from_json(&json).unwrap();

        assert_eq!(original.node_count(), restored.node_count());
        assert_eq!(original.server_count(), restored.server_count());
        assert_eq!(original.tool_names(), restored.tool_names());
        assert_eq!(original.fingerprint(), restored.fingerprint());
    }

    #[test]
    fn test_full_pipeline_guard_to_engine() {
        // Complete pipeline test: static topology → guard → engine → verdict

        // Step 1: Build topology from server declarations
        let topology = make_topology();
        assert_eq!(topology.server_count(), 2);
        assert_eq!(topology.tool_names().len(), 3);

        // Step 2: Capture fingerprint before transferring topology to guard
        let fingerprint_hex = topology.fingerprint_hex();

        // Step 3: Create guard and load topology
        let guard = Arc::new(TopologyGuard::new());
        guard.update(topology);

        // Step 4: Wire guard into engine
        let policies = vec![
            Policy {
                id: "fs:write_file".to_string(),
                name: "Deny file writes".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*:*".to_string(),
                name: "Allow everything else".to_string(),
                policy_type: PolicyType::Allow,
                priority: 1,
                path_rules: None,
                network_rules: None,
            },
        ];

        let mut engine = PolicyEngine::with_policies(false, &policies).unwrap();
        engine.set_topology_guard(Arc::clone(&guard));

        // Step 4: Verify verdicts

        // Known tool, allowed by policy (read_file matches *:* allow)
        let read = make_action("fs::read_file", "");
        assert!(matches!(
            engine.evaluate_action(&read, &policies).unwrap(),
            Verdict::Allow
        ));

        // Known tool, denied by policy (fs:write_file deny at priority 100)
        let write = make_action("fs", "write_file");
        let write_verdict = engine.evaluate_action(&write, &policies).unwrap();
        assert!(
            matches!(write_verdict, Verdict::Deny { .. }),
            "write_file should be denied by policy, got: {:?}",
            write_verdict
        );

        // Unknown tool — denied by topology guard before policy evaluation
        let unknown = make_action("database::drop_table", "");
        match engine.evaluate_action(&unknown, &policies).unwrap() {
            Verdict::Deny { reason } => {
                assert!(
                    reason.contains("not found in topology"),
                    "Expected topology-based denial, got: {}",
                    reason
                );
            }
            other => panic!("Unknown tool should be denied, got: {:?}", other),
        }

        // Step 6: Verify fingerprint consistency
        let topology2 = make_topology();
        assert_eq!(fingerprint_hex, topology2.fingerprint_hex());
    }
}

// Tests that work without the discovery feature (no topology guard)
#[cfg(not(feature = "discovery"))]
mod without_discovery_feature {
    use super::*;

    #[test]
    fn test_engine_works_without_topology() {
        let policies = vec![Policy {
            id: "*:*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        }];

        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = make_action("any_tool", "any_function");
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }
}
