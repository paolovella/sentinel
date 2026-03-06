// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Tests for TopologyGraph construction, querying, and serialization.

use vellaveto_discovery::topology::*;

fn make_fs_server() -> StaticServerDecl {
    StaticServerDecl {
        name: "fs".to_string(),
        tools: vec![
            StaticToolDecl {
                name: "read_file".to_string(),
                description: "Read a file from the filesystem".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "file_path": { "type": "string" }
                    }
                }),
            },
            StaticToolDecl {
                name: "write_file".to_string(),
                description: "Write content to a file".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "file_path": { "type": "string" },
                        "content": { "type": "string" }
                    }
                }),
            },
            StaticToolDecl {
                name: "search".to_string(),
                description: "Search for files matching a pattern".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "pattern": { "type": "string" }
                    }
                }),
            },
        ],
        resources: vec![StaticResourceDecl {
            uri_template: "file:///{path}".to_string(),
            name: "file".to_string(),
            mime_type: Some("application/octet-stream".to_string()),
        }],
    }
}

fn make_git_server() -> StaticServerDecl {
    StaticServerDecl {
        name: "git".to_string(),
        tools: vec![
            StaticToolDecl {
                name: "commit".to_string(),
                description: "Commit changes to a repository".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "message": { "type": "string" }
                    }
                }),
            },
            StaticToolDecl {
                name: "search".to_string(),
                description: "Search git history".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" }
                    }
                }),
            },
        ],
        resources: vec![],
    }
}

fn make_web_server() -> StaticServerDecl {
    StaticServerDecl {
        name: "web".to_string(),
        tools: vec![
            StaticToolDecl {
                name: "fetch".to_string(),
                description: "Fetch a URL".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" }
                    }
                }),
            },
            StaticToolDecl {
                name: "post".to_string(),
                description: "POST to a URL".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" },
                        "body": { "type": "string" }
                    }
                }),
            },
        ],
        resources: vec![],
    }
}

#[test]
fn test_from_static_single_server() {
    let graph = TopologyGraph::from_static(vec![make_fs_server()]).unwrap();
    assert_eq!(graph.server_count(), 1);
    // 1 server + 3 tools + 1 resource = 5 nodes
    assert_eq!(graph.node_count(), 5);
}

#[test]
fn test_from_static_multi_server() {
    let graph =
        TopologyGraph::from_static(vec![make_fs_server(), make_git_server(), make_web_server()])
            .unwrap();
    assert_eq!(graph.server_count(), 3);
    // fs: 1+3+1=5, git: 1+2=3, web: 1+2=3 → 11 nodes
    assert_eq!(graph.node_count(), 11);
}

#[test]
fn test_find_tool_qualified() {
    let graph = TopologyGraph::from_static(vec![make_fs_server()]).unwrap();
    let tool = graph.find_tool("fs::read_file");
    assert!(tool.is_some());
    assert!(tool.unwrap().is_tool());
}

#[test]
fn test_find_tool_qualified_missing() {
    let graph = TopologyGraph::from_static(vec![make_fs_server()]).unwrap();
    assert!(graph.find_tool("fs::nonexistent").is_none());
}

#[test]
fn test_find_tool_qualified_returns_none_for_server() {
    let graph = TopologyGraph::from_static(vec![make_fs_server()]).unwrap();
    // "fs" is a server node, not a tool
    assert!(graph.find_tool("fs").is_none());
}

#[test]
fn test_find_tool_unqualified_unique() {
    let graph = TopologyGraph::from_static(vec![make_fs_server()]).unwrap();
    let matches = graph.find_tool_unqualified("read_file");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].0, "fs::read_file");
}

#[test]
fn test_find_tool_unqualified_ambiguous() {
    let graph = TopologyGraph::from_static(vec![make_fs_server(), make_git_server()]).unwrap();
    let matches = graph.find_tool_unqualified("search");
    assert_eq!(matches.len(), 2);
    // Sorted by qualified name
    assert_eq!(matches[0].0, "fs::search");
    assert_eq!(matches[1].0, "git::search");
}

#[test]
fn test_find_tool_unqualified_not_found() {
    let graph = TopologyGraph::from_static(vec![make_fs_server()]).unwrap();
    let matches = graph.find_tool_unqualified("nonexistent");
    assert!(matches.is_empty());
}

#[test]
fn test_server_tools() {
    let graph = TopologyGraph::from_static(vec![make_fs_server(), make_git_server()]).unwrap();
    let tools = graph.server_tools("fs");
    assert_eq!(tools.len(), 3);
    // All should be Tool nodes
    assert!(tools.iter().all(|t| t.is_tool()));
}

#[test]
fn test_server_tools_missing_server() {
    let graph = TopologyGraph::from_static(vec![make_fs_server()]).unwrap();
    let tools = graph.server_tools("nonexistent");
    assert!(tools.is_empty());
}

#[test]
fn test_node_count() {
    let graph = TopologyGraph::from_static(vec![make_fs_server(), make_git_server()]).unwrap();
    // fs: 1+3+1=5, git: 1+2=3 → 8
    assert_eq!(graph.node_count(), 8);
}

#[test]
fn test_edge_count() {
    let graph = TopologyGraph::from_static(vec![make_fs_server()]).unwrap();
    // 3 tools + 1 resource = 4 Owns edges
    assert_eq!(graph.edge_count(), 4);
}

#[test]
fn test_empty_topology() {
    let graph = TopologyGraph::from_static(vec![]).unwrap();
    assert_eq!(graph.node_count(), 0);
    assert_eq!(graph.edge_count(), 0);
    assert_eq!(graph.server_count(), 0);
    assert!(graph.find_tool("any::tool").is_none());
    assert!(graph.find_tool_unqualified("tool").is_empty());
    assert!(graph.server_tools("any").is_empty());
    assert!(graph.tool_names().is_empty());
}

#[test]
fn test_tool_names() {
    let graph = TopologyGraph::from_static(vec![make_fs_server()]).unwrap();
    let names = graph.tool_names();
    assert_eq!(names.len(), 3);
    assert!(names.contains(&"fs::read_file".to_string()));
    assert!(names.contains(&"fs::write_file".to_string()));
    assert!(names.contains(&"fs::search".to_string()));
}

#[test]
fn test_server_names() {
    let graph = TopologyGraph::from_static(vec![make_fs_server(), make_git_server()]).unwrap();
    let names = graph.server_names();
    assert_eq!(names, vec!["fs", "git"]);
}

#[test]
fn test_downstream_no_dataflow() {
    let graph = TopologyGraph::from_static(vec![make_fs_server()]).unwrap();
    let downstream = graph.downstream("fs::read_file");
    assert!(downstream.is_empty());
}

#[test]
fn test_upstream_no_dataflow() {
    let graph = TopologyGraph::from_static(vec![make_fs_server()]).unwrap();
    let upstream = graph.upstream("fs::write_file");
    assert!(upstream.is_empty());
}

#[test]
fn test_duplicate_server_name_rejected() {
    let server1 = make_fs_server();
    let server2 = make_fs_server(); // same name
    let result = TopologyGraph::from_static(vec![server1, server2]);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Duplicate server name"));
}

#[test]
fn test_empty_server_name_rejected() {
    let server = StaticServerDecl {
        name: String::new(),
        tools: vec![],
        resources: vec![],
    };
    let result = TopologyGraph::from_static(vec![server]);
    assert!(result.is_err());
}

#[test]
fn test_empty_tool_name_rejected() {
    let server = StaticServerDecl {
        name: "test".to_string(),
        tools: vec![StaticToolDecl {
            name: String::new(),
            description: "empty name".to_string(),
            input_schema: serde_json::json!({}),
        }],
        resources: vec![],
    };
    let result = TopologyGraph::from_static(vec![server]);
    assert!(result.is_err());
}

#[test]
fn test_qualified_name_uniqueness() {
    let graph =
        TopologyGraph::from_static(vec![make_fs_server(), make_git_server(), make_web_server()])
            .unwrap();
    let names = graph.tool_names();
    let unique: std::collections::HashSet<&String> = names.iter().collect();
    assert_eq!(names.len(), unique.len(), "All tool names must be unique");
}

#[test]
fn test_resource_names() {
    let graph = TopologyGraph::from_static(vec![make_fs_server()]).unwrap();
    let resources = graph.resource_names();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0], "fs::file");
}

#[test]
fn test_server_resources() {
    let graph = TopologyGraph::from_static(vec![make_fs_server()]).unwrap();
    let resources = graph.server_resources("fs");
    assert_eq!(resources.len(), 1);
    assert!(resources[0].is_resource());
}

#[test]
fn test_debug_format() {
    let graph = TopologyGraph::from_static(vec![make_fs_server()]).unwrap();
    let debug = format!("{:?}", graph);
    assert!(debug.contains("TopologyGraph"));
    assert!(debug.contains("node_count"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// to_static() round-trip tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_to_static_roundtrip_single_server() {
    let original = vec![make_fs_server()];
    let graph = TopologyGraph::from_static(original.clone()).unwrap();
    let reconstituted = graph.to_static();

    assert_eq!(reconstituted.len(), 1);
    assert_eq!(reconstituted[0].name, "fs");
    assert_eq!(reconstituted[0].tools.len(), original[0].tools.len());
    assert_eq!(
        reconstituted[0].resources.len(),
        original[0].resources.len()
    );
}

#[test]
fn test_to_static_roundtrip_multi_server() {
    let original = vec![
        make_fs_server(),
        StaticServerDecl {
            name: "web".to_string(),
            tools: vec![StaticToolDecl {
                name: "fetch_url".to_string(),
                description: "Fetch a URL".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            }],
            resources: vec![],
        },
    ];
    let graph = TopologyGraph::from_static(original).unwrap();
    let reconstituted = graph.to_static();

    assert_eq!(reconstituted.len(), 2);
    // Sorted by server name
    let fs = reconstituted.iter().find(|s| s.name == "fs").unwrap();
    let web = reconstituted.iter().find(|s| s.name == "web").unwrap();
    assert_eq!(fs.tools.len(), 3); // read_file, write_file, list_directory
    assert_eq!(web.tools.len(), 1);
}

#[test]
fn test_to_static_empty_topology() {
    let graph = TopologyGraph::empty();
    let decls = graph.to_static();
    assert!(decls.is_empty());
}

#[test]
fn test_to_static_preserves_tool_data() {
    let original = StaticServerDecl {
        name: "test".to_string(),
        tools: vec![StaticToolDecl {
            name: "my_tool".to_string(),
            description: "A test tool with specific schema".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {"x": {"type": "integer"}},
                "required": ["x"]
            }),
        }],
        resources: vec![StaticResourceDecl {
            uri_template: "file:///data".to_string(),
            name: "data".to_string(),
            mime_type: Some("application/json".to_string()),
        }],
    };
    let graph = TopologyGraph::from_static(vec![original]).unwrap();
    let decls = graph.to_static();

    assert_eq!(decls[0].tools[0].name, "my_tool");
    assert_eq!(
        decls[0].tools[0].description,
        "A test tool with specific schema"
    );
    assert_eq!(
        decls[0].tools[0].input_schema["properties"]["x"]["type"],
        "integer"
    );
    assert_eq!(decls[0].resources[0].name, "data");
    assert_eq!(
        decls[0].resources[0].mime_type.as_deref(),
        Some("application/json")
    );
}

#[test]
fn test_to_static_rebuild_produces_same_fingerprint() {
    let original = vec![make_fs_server()];
    let graph1 = TopologyGraph::from_static(original.clone()).unwrap();
    let decls = graph1.to_static();
    let graph2 = TopologyGraph::from_static(decls).unwrap();

    // Fingerprints should match since content is the same
    assert_eq!(graph1.fingerprint(), graph2.fingerprint());
}
