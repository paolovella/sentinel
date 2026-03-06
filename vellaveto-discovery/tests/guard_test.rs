// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Tests for TopologyGuard — pre-policy filter.

use vellaveto_discovery::guard::*;
use vellaveto_discovery::topology::*;

fn make_test_topology() -> TopologyGraph {
    TopologyGraph::from_static(vec![
        StaticServerDecl {
            name: "fs".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "read_file".to_string(),
                    description: "Read a file".to_string(),
                    input_schema: serde_json::json!({}),
                },
                StaticToolDecl {
                    name: "write_file".to_string(),
                    description: "Write a file".to_string(),
                    input_schema: serde_json::json!({}),
                },
            ],
            resources: vec![],
        },
        StaticServerDecl {
            name: "git".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "commit".to_string(),
                    description: "Commit changes".to_string(),
                    input_schema: serde_json::json!({}),
                },
                StaticToolDecl {
                    name: "read_file".to_string(),
                    description: "Read file from git".to_string(),
                    input_schema: serde_json::json!({}),
                },
            ],
            resources: vec![],
        },
    ])
    .unwrap()
}

#[test]
fn test_guard_known_qualified() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    match guard.check("fs::read_file") {
        TopologyVerdict::Known { server, tool, .. } => {
            assert_eq!(server, "fs");
            assert_eq!(tool, "read_file");
        }
        other => panic!("Expected Known, got {:?}", other),
    }
}

#[test]
fn test_guard_known_unqualified() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    // "commit" is unique across servers
    match guard.check("commit") {
        TopologyVerdict::Known { server, tool, .. } => {
            assert_eq!(server, "git");
            assert_eq!(tool, "commit");
        }
        other => panic!("Expected Known, got {:?}", other),
    }
}

#[test]
fn test_guard_unknown() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    match guard.check("nonexistent_tool") {
        TopologyVerdict::Unknown {
            requested_tool,
            available_tools,
            ..
        } => {
            assert_eq!(requested_tool, "nonexistent_tool");
            assert!(!available_tools.is_empty());
        }
        other => panic!("Expected Unknown, got {:?}", other),
    }
}

#[test]
fn test_guard_unknown_with_suggestion() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    match guard.check("read_fil") {
        TopologyVerdict::Unknown { suggestion, .. } => {
            // Should suggest something close to "read_file"
            assert!(suggestion.is_some(), "Expected a suggestion");
        }
        other => panic!("Expected Unknown, got {:?}", other),
    }
}

#[test]
fn test_guard_ambiguous() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    // "read_file" exists on both "fs" and "git"
    match guard.check("read_file") {
        TopologyVerdict::Ambiguous {
            requested_tool,
            matches,
        } => {
            assert_eq!(requested_tool, "read_file");
            assert_eq!(matches.len(), 2);
            assert!(matches.contains(&"fs::read_file".to_string()));
            assert!(matches.contains(&"git::read_file".to_string()));
        }
        other => panic!("Expected Ambiguous, got {:?}", other),
    }
}

#[test]
fn test_guard_bypassed() {
    let guard = TopologyGuard::new();
    // No topology loaded
    match guard.check("any_tool") {
        TopologyVerdict::Bypassed => {}
        other => panic!("Expected Bypassed, got {:?}", other),
    }
}

#[test]
fn test_guard_load_and_check() {
    let guard = TopologyGuard::new();
    assert!(matches!(guard.check("commit"), TopologyVerdict::Bypassed));

    guard.load(make_test_topology());
    assert!(matches!(
        guard.check("commit"),
        TopologyVerdict::Known { .. }
    ));
}

#[test]
fn test_guard_update_hotswap() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    // "commit" is known
    assert!(matches!(
        guard.check("commit"),
        TopologyVerdict::Known { .. }
    ));

    // Update with a topology that doesn't have git
    let new_topology = TopologyGraph::from_static(vec![StaticServerDecl {
        name: "fs".to_string(),
        tools: vec![StaticToolDecl {
            name: "read_file".to_string(),
            description: "Read a file".to_string(),
            input_schema: serde_json::json!({}),
        }],
        resources: vec![],
    }])
    .unwrap();

    guard.update(new_topology);

    // "commit" should now be unknown
    assert!(matches!(
        guard.check("commit"),
        TopologyVerdict::Unknown { .. }
    ));

    // "read_file" should now be Known (unique)
    assert!(matches!(
        guard.check("read_file"),
        TopologyVerdict::Known { .. }
    ));
}

#[test]
fn test_guard_clear() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());
    assert!(matches!(
        guard.check("commit"),
        TopologyVerdict::Known { .. }
    ));

    guard.clear();
    assert!(matches!(guard.check("commit"), TopologyVerdict::Bypassed));
}

#[test]
fn test_guard_concurrent_reads() {
    use std::sync::Arc;

    let guard = Arc::new(TopologyGuard::new());
    guard.load(make_test_topology());

    let handles: Vec<_> = (0..100)
        .map(|_| {
            let g = Arc::clone(&guard);
            std::thread::spawn(move || {
                let result = g.check("commit");
                assert!(matches!(result, TopologyVerdict::Known { .. }));
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_guard_update_during_reads() {
    use std::sync::Arc;

    let guard = Arc::new(TopologyGuard::new());
    guard.load(make_test_topology());

    let handles: Vec<_> = (0..50)
        .map(|i| {
            let g = Arc::clone(&guard);
            std::thread::spawn(move || {
                if i % 10 == 0 {
                    // Writer: update topology
                    let new_topo = TopologyGraph::from_static(vec![StaticServerDecl {
                        name: "fs".to_string(),
                        tools: vec![StaticToolDecl {
                            name: "read_file".to_string(),
                            description: "Read".to_string(),
                            input_schema: serde_json::json!({}),
                        }],
                        resources: vec![],
                    }])
                    .unwrap();
                    g.update(new_topo);
                } else {
                    // Reader: just check, should not panic
                    let _result = g.check("read_file");
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_guard_current() {
    let guard = TopologyGuard::new();
    assert!(guard.current().is_none());

    guard.load(make_test_topology());
    let current = guard.current();
    assert!(current.is_some());
    assert!(current.unwrap().node_count() > 0);
}

#[test]
fn test_guard_default() {
    let guard = TopologyGuard::default();
    assert!(matches!(guard.check("any"), TopologyVerdict::Bypassed));
}

#[test]
fn test_guard_debug() {
    let guard = TopologyGuard::new();
    let debug = format!("{:?}", guard);
    assert!(debug.contains("TopologyGuard"));
    assert!(debug.contains("loaded"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// upsert_server() tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_guard_upsert_server_into_empty() {
    let guard = TopologyGuard::new();
    assert!(matches!(guard.check("tool_a"), TopologyVerdict::Bypassed));

    let decl = StaticServerDecl {
        name: "alpha".to_string(),
        tools: vec![StaticToolDecl {
            name: "tool_a".to_string(),
            description: "A tool".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
        }],
        resources: vec![],
    };
    guard.upsert_server(decl).unwrap();

    assert!(matches!(
        guard.check("tool_a"),
        TopologyVerdict::Known { .. }
    ));
}

#[test]
fn test_guard_upsert_server_new_server() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    // Existing tool should be known (ambiguous since both fs and git have read_file)
    assert!(matches!(
        guard.check("commit"),
        TopologyVerdict::Known { .. }
    ));

    // New server's tool should be unknown
    assert!(matches!(
        guard.check("new_tool"),
        TopologyVerdict::Unknown { .. }
    ));

    // Upsert a new server
    let decl = StaticServerDecl {
        name: "new_server".to_string(),
        tools: vec![StaticToolDecl {
            name: "new_tool".to_string(),
            description: "A new tool".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
        }],
        resources: vec![],
    };
    guard.upsert_server(decl).unwrap();

    // Both old and new tools should be known
    assert!(matches!(
        guard.check("commit"),
        TopologyVerdict::Known { .. }
    ));
    assert!(matches!(
        guard.check("new_tool"),
        TopologyVerdict::Known { .. }
    ));
}

#[test]
fn test_guard_upsert_server_replace_existing() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    // Verify fs server has write_file (unique to fs)
    assert!(matches!(
        guard.check("write_file"),
        TopologyVerdict::Known { .. }
    ));

    // Replace fs server with different tools
    let decl = StaticServerDecl {
        name: "fs".to_string(),
        tools: vec![StaticToolDecl {
            name: "new_fs_tool".to_string(),
            description: "Replaced tool".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
        }],
        resources: vec![],
    };
    guard.upsert_server(decl).unwrap();

    // Old fs tool should be gone, new one should be known
    assert!(matches!(
        guard.check("write_file"),
        TopologyVerdict::Unknown { .. }
    ));
    assert!(matches!(
        guard.check("new_fs_tool"),
        TopologyVerdict::Known { .. }
    ));
    // Git server preserved
    assert!(matches!(
        guard.check("commit"),
        TopologyVerdict::Known { .. }
    ));
}

#[test]
fn test_guard_upsert_server_preserves_other_servers() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    let before = guard.current().unwrap();
    let before_count = before.server_count();

    // Add a third server
    let decl = StaticServerDecl {
        name: "third".to_string(),
        tools: vec![StaticToolDecl {
            name: "third_tool".to_string(),
            description: "Third tool".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
        }],
        resources: vec![],
    };
    guard.upsert_server(decl).unwrap();

    let after = guard.current().unwrap();
    assert_eq!(after.server_count(), before_count + 1);

    // All original tools still work
    assert!(matches!(
        guard.check("write_file"),
        TopologyVerdict::Known { .. }
    ));
    assert!(matches!(
        guard.check("commit"),
        TopologyVerdict::Known { .. }
    ));
    assert!(matches!(
        guard.check("third_tool"),
        TopologyVerdict::Known { .. }
    ));
}
