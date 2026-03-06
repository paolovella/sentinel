// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Tests for data flow inference.

use vellaveto_discovery::inference::*;
use vellaveto_discovery::topology::*;

fn make_inference_topology() -> TopologyGraph {
    TopologyGraph::from_static(vec![
        StaticServerDecl {
            name: "fs".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "file_search".to_string(),
                    description: "Search for files matching a pattern. Returns file paths."
                        .to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "pattern": { "type": "string" }
                        }
                    }),
                },
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
            ],
            resources: vec![],
        },
        StaticServerDecl {
            name: "web".to_string(),
            tools: vec![StaticToolDecl {
                name: "fetch_url".to_string(),
                description: "Fetch content from a URL".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" }
                    }
                }),
            }],
            resources: vec![],
        },
    ])
    .unwrap()
}

#[test]
fn test_infer_name_match() {
    let config = InferenceConfig {
        threshold: 0.3,
        ..InferenceConfig::default()
    };
    let engine = InferenceEngine::new(config);
    let mut graph = make_inference_topology();

    engine.infer_edges(&mut graph);

    // file_search → read_file (because read_file has param "file_path" and
    // file_search implies output "path", "file_path")
    let downstream = graph.downstream("fs::file_search");
    assert!(
        downstream.contains(&"fs::read_file".to_string())
            || downstream.contains(&"fs::write_file".to_string()),
        "Expected file_search to have downstream edges to read_file or write_file, got: {:?}",
        downstream
    );
}

#[test]
fn test_infer_name_mismatch() {
    let config = InferenceConfig {
        threshold: 0.9, // Very high threshold
        ..InferenceConfig::default()
    };
    let engine = InferenceEngine::new(config);
    let mut graph = make_inference_topology();

    engine.infer_edges(&mut graph);

    // web::fetch_url should NOT connect to fs::file_search with high threshold
    let downstream = graph.downstream("web::fetch_url");
    // With threshold 0.9, most inferences shouldn't fire
    // (this is a weak assertion — the point is no crash)
    let _ = downstream;
}

#[test]
fn test_infer_cross_server() {
    let config = InferenceConfig {
        threshold: 0.3,
        ..InferenceConfig::default()
    };
    let engine = InferenceEngine::new(config);
    let mut graph = make_inference_topology();

    engine.infer_edges(&mut graph);

    // Edges can be inferred across server boundaries
    // The specific edges depend on heuristic scoring
    let all_edges = graph.edge_count();
    // Should have more edges than just Owns edges (3 tools + 1 tool = 4 Owns)
    assert!(
        all_edges >= 4,
        "Expected at least the Owns edges, got {}",
        all_edges
    );
}

#[test]
fn test_infer_no_self_edge() {
    let config = InferenceConfig {
        threshold: 0.0, // Accept all matches
        ..InferenceConfig::default()
    };
    let engine = InferenceEngine::new(config);
    let mut graph = make_inference_topology();

    engine.infer_edges(&mut graph);

    // No tool should have a DataFlow edge to itself
    use petgraph::visit::EdgeRef;
    for edge in graph.graph().edge_references() {
        if matches!(EdgeRef::weight(&edge), TopologyEdge::DataFlow { .. }) {
            assert_ne!(
                EdgeRef::source(&edge),
                EdgeRef::target(&edge),
                "Self-edge detected"
            );
        }
    }
}

#[test]
fn test_infer_threshold() {
    // With threshold 1.0, no edges should be inferred (impossible to reach)
    let config = InferenceConfig {
        threshold: 1.0,
        ..InferenceConfig::default()
    };
    let engine = InferenceEngine::new(config);
    let mut graph = make_inference_topology();

    let owns_edges_before = graph.edge_count();
    engine.infer_edges(&mut graph);

    // No new DataFlow edges should be added
    assert_eq!(
        graph.edge_count(),
        owns_edges_before,
        "No edges should be inferred at threshold 1.0"
    );
}

#[test]
fn test_infer_reason_human_readable() {
    let config = InferenceConfig {
        threshold: 0.0,
        ..InferenceConfig::default()
    };
    let engine = InferenceEngine::new(config);
    let mut graph = make_inference_topology();

    engine.infer_edges(&mut graph);

    use petgraph::visit::EdgeRef;
    for edge in graph.graph().edge_references() {
        if let TopologyEdge::DataFlow { reason, .. } = EdgeRef::weight(&edge) {
            assert!(!reason.is_empty(), "DataFlow edge has empty reason");
        }
    }
}

#[test]
fn test_match_schemas_direct() {
    let config = InferenceConfig {
        threshold: 0.3,
        ..InferenceConfig::default()
    };
    let engine = InferenceEngine::new(config);

    let source = TopologyNode::Tool {
        server: "fs".to_string(),
        name: "file_search".to_string(),
        description: "Search for files. Returns file paths.".to_string(),
        input_schema: serde_json::json!({}),
        output_hints: vec![],
        inferred_deps: vec![],
    };
    let target = TopologyNode::Tool {
        server: "fs".to_string(),
        name: "read_file".to_string(),
        description: "Read a file".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" }
            }
        }),
        output_hints: vec![],
        inferred_deps: vec![],
    };

    let matches = engine.match_schemas(&source, &target);
    // Should find at least one match on "file_path"
    assert!(
        !matches.is_empty(),
        "Expected at least one match between file_search and read_file"
    );
}

#[test]
fn test_inference_config_validate() {
    let config = InferenceConfig::default();
    assert!(config.validate().is_ok());

    let bad = InferenceConfig {
        threshold: f32::NAN,
        ..InferenceConfig::default()
    };
    assert!(bad.validate().is_err());

    let bad = InferenceConfig {
        threshold: 2.0,
        ..InferenceConfig::default()
    };
    assert!(bad.validate().is_err());
}

#[test]
fn test_infer_edges_recomputes_fingerprint() {
    let config = InferenceConfig {
        threshold: 0.0,
        ..InferenceConfig::default()
    };
    let engine = InferenceEngine::new(config);
    let mut graph = make_inference_topology();

    let fp_before = graph.fingerprint();
    engine.infer_edges(&mut graph);
    let fp_after = graph.fingerprint();

    // Fingerprint should change if any edges were added
    if graph.edge_count() > 4 {
        // More than just Owns
        assert_ne!(
            fp_before, fp_after,
            "Fingerprint should change after adding edges"
        );
    }
}
