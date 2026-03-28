// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! JSON serialization and topology operations.
//!
//! Supports serialization/deserialization for caching, Foundation consumption,
//! and topology merging/filtering.

use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

use crate::topology::{
    StaticResourceDecl, StaticServerDecl, StaticToolDecl, TopologyEdge, TopologyGraph, TopologyNode,
};
use crate::DiscoveryError;

/// Serializable representation of the full topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologySnapshot {
    /// All nodes in the graph.
    pub nodes: Vec<TopologyNode>,
    /// Edges as (source_qualified, target_qualified, edge).
    pub edges: Vec<SerializedEdge>,
    /// When this snapshot was created.
    pub crawled_at_epoch_secs: u64,
    /// SHA-256 fingerprint (hex).
    pub fingerprint: String,
}

/// A serialized edge with source and target qualified names.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SerializedEdge {
    /// Source node qualified name.
    pub source: String,
    /// Target node qualified name.
    pub target: String,
    /// The edge data.
    pub edge: TopologyEdge,
}

impl TopologyGraph {
    /// Serialize the full topology to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let snapshot = self.to_snapshot();
        serde_json::to_string_pretty(&snapshot)
    }

    /// Deserialize from JSON (for caching/loading).
    pub fn from_json(json: &str) -> Result<Self, crate::error::DiscoveryError> {
        let snapshot: TopologySnapshot =
            serde_json::from_str(json).map_err(crate::error::DiscoveryError::SerializationError)?;
        Self::from_snapshot(snapshot)
    }

    /// Convert to a serializable snapshot.
    pub fn to_snapshot(&self) -> TopologySnapshot {
        let nodes: Vec<TopologyNode> = self
            .graph()
            .node_indices()
            .map(|idx| self.graph()[idx].clone())
            .collect();

        let edges: Vec<SerializedEdge> = self
            .graph()
            .edge_references()
            .map(|e| {
                let source = self.graph()[EdgeRef::source(&e)].qualified_name();
                let target = self.graph()[EdgeRef::target(&e)].qualified_name();
                SerializedEdge {
                    source,
                    target,
                    edge: EdgeRef::weight(&e).clone(),
                }
            })
            .collect();

        // SECURITY (R240-P3-DISC-2): Log clock anomaly instead of silent 0.
        let epoch_secs = self
            .crawled_at()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "SystemTime before UNIX_EPOCH in snapshot — using 0");
                0
            });

        TopologySnapshot {
            nodes,
            edges,
            crawled_at_epoch_secs: epoch_secs,
            fingerprint: self.fingerprint_hex(),
        }
    }

    /// Reconstruct a topology from a snapshot.
    pub fn from_snapshot(snapshot: TopologySnapshot) -> Result<Self, crate::error::DiscoveryError> {
        // SECURITY (R231-DISC-4): Bound edge count from untrusted snapshots to prevent
        // OOM from crafted JSON with millions of edges between valid nodes.
        const MAX_SNAPSHOT_EDGES: usize = 100_000;
        if snapshot.edges.len() > MAX_SNAPSHOT_EDGES {
            return Err(crate::error::DiscoveryError::ValidationError(format!(
                "Snapshot edge count {} exceeds maximum {}",
                snapshot.edges.len(),
                MAX_SNAPSHOT_EDGES
            )));
        }

        // SECURITY (R256-DISC-2): Validate edge source/target qualified names for length
        // and dangerous characters. Without this, crafted snapshot JSON can inject control
        // characters via source/target that propagate into graph node lookups and logs.
        const MAX_EDGE_QUALIFIED_NAME_LEN: usize = 4096;
        for edge in &snapshot.edges {
            if edge.source.len() > MAX_EDGE_QUALIFIED_NAME_LEN {
                return Err(crate::error::DiscoveryError::ValidationError(format!(
                    "Edge source length {} exceeds max {MAX_EDGE_QUALIFIED_NAME_LEN}",
                    edge.source.len()
                )));
            }
            if vellaveto_types::has_dangerous_chars(&edge.source) {
                return Err(crate::error::DiscoveryError::ValidationError(
                    "Edge source contains dangerous characters".to_string(),
                ));
            }
            if edge.target.len() > MAX_EDGE_QUALIFIED_NAME_LEN {
                return Err(crate::error::DiscoveryError::ValidationError(format!(
                    "Edge target length {} exceeds max {MAX_EDGE_QUALIFIED_NAME_LEN}",
                    edge.target.len()
                )));
            }
            if vellaveto_types::has_dangerous_chars(&edge.target) {
                return Err(crate::error::DiscoveryError::ValidationError(
                    "Edge target contains dangerous characters".to_string(),
                ));
            }
        }

        // SECURITY (R239-DISC-1): Validate DataFlow edge confidence for NaN/Infinity/range.
        // SECURITY (R239-DISC-2): Validate edge string fields for dangerous chars and length.
        const MAX_EDGE_STRING_LEN: usize = 1024;
        for edge in &snapshot.edges {
            match &edge.edge {
                TopologyEdge::DataFlow {
                    confidence,
                    from_field,
                    to_param,
                    reason,
                    ..
                } => {
                    if !confidence.is_finite() || *confidence < 0.0 || *confidence > 1.0 {
                        return Err(crate::error::DiscoveryError::ValidationError(format!(
                            "DataFlow edge confidence {confidence} is not in [0.0, 1.0]"
                        )));
                    }
                    for (label, value) in [
                        ("from_field", from_field.as_str()),
                        ("to_param", to_param.as_str()),
                        ("reason", reason.as_str()),
                    ] {
                        if value.len() > MAX_EDGE_STRING_LEN {
                            let len = value.len();
                            return Err(crate::error::DiscoveryError::ValidationError(format!(
                                "DataFlow edge {label} length {len} exceeds max {MAX_EDGE_STRING_LEN}"
                            )));
                        }
                        if vellaveto_types::has_dangerous_chars(value) {
                            return Err(crate::error::DiscoveryError::ValidationError(format!(
                                "DataFlow edge {label} contains dangerous characters"
                            )));
                        }
                    }
                }
                TopologyEdge::Consumes { param } => {
                    if param.len() > MAX_EDGE_STRING_LEN {
                        return Err(crate::error::DiscoveryError::ValidationError(format!(
                            "Consumes edge param length {} exceeds max {MAX_EDGE_STRING_LEN}",
                            param.len()
                        )));
                    }
                    if vellaveto_types::has_dangerous_chars(param) {
                        return Err(crate::error::DiscoveryError::ValidationError(
                            "Consumes edge param contains dangerous characters".to_string(),
                        ));
                    }
                }
                TopologyEdge::Owns => {}
            }
        }

        // SECURITY (R239-DISC-4): Bound node count and validate node string fields
        // for dangerous characters and length. Unbounded node count allows OOM from
        // crafted JSON with millions of nodes.
        const MAX_SNAPSHOT_NODES: usize = 100_000;
        // SECURITY (R240-DISC-1): Aligned with topology.rs MAX_TOOL_DESCRIPTION_LEN (4096).
        // Previously 1024, which rejected valid descriptions that the topology itself accepts.
        const MAX_NODE_STRING_LEN: usize = 4096;
        if snapshot.nodes.len() > MAX_SNAPSHOT_NODES {
            let count = snapshot.nodes.len();
            return Err(crate::error::DiscoveryError::ValidationError(format!(
                "Snapshot node count {count} exceeds maximum {MAX_SNAPSHOT_NODES}"
            )));
        }
        for node in &snapshot.nodes {
            let strings_to_check: Vec<(&str, &str)> = match node {
                // SECURITY (R241-DISC-3): Also validate server version field.
                TopologyNode::Server { name, version, .. } => {
                    let mut v = vec![("server.name", name.as_str())];
                    if let Some(ver) = version {
                        v.push(("server.version", ver.as_str()));
                    }
                    v
                }
                TopologyNode::Tool {
                    server,
                    name,
                    description,
                    output_hints,
                    inferred_deps,
                    ..
                } => {
                    let mut v = vec![
                        ("tool.server", server.as_str()),
                        ("tool.name", name.as_str()),
                        ("tool.description", description.as_str()),
                    ];
                    // SECURITY (R241-DISC-4): Validate output_hints and inferred_deps.
                    const MAX_HINTS_PER_TOOL: usize = 100;
                    if output_hints.len() > MAX_HINTS_PER_TOOL {
                        return Err(crate::error::DiscoveryError::ValidationError(format!(
                            "tool.output_hints count {} exceeds max {MAX_HINTS_PER_TOOL}",
                            output_hints.len()
                        )));
                    }
                    if inferred_deps.len() > MAX_HINTS_PER_TOOL {
                        return Err(crate::error::DiscoveryError::ValidationError(format!(
                            "tool.inferred_deps count {} exceeds max {MAX_HINTS_PER_TOOL}",
                            inferred_deps.len()
                        )));
                    }
                    for hint in output_hints {
                        v.push(("tool.output_hint", hint.as_str()));
                    }
                    for dep in inferred_deps {
                        v.push(("tool.inferred_dep", dep.as_str()));
                    }
                    v
                }
                TopologyNode::Resource {
                    server,
                    uri_template,
                    name,
                    mime_type,
                } => {
                    let mut v = vec![
                        ("resource.server", server.as_str()),
                        ("resource.uri_template", uri_template.as_str()),
                        ("resource.name", name.as_str()),
                    ];
                    if let Some(mt) = mime_type {
                        v.push(("resource.mime_type", mt.as_str()));
                    }
                    v
                }
            };
            for (label, value) in strings_to_check {
                if value.len() > MAX_NODE_STRING_LEN {
                    let len = value.len();
                    return Err(crate::error::DiscoveryError::ValidationError(format!(
                        "Node {label} length {len} exceeds max {MAX_NODE_STRING_LEN}"
                    )));
                }
                if vellaveto_types::has_dangerous_chars(value) {
                    return Err(crate::error::DiscoveryError::ValidationError(format!(
                        "Node {label} contains dangerous characters"
                    )));
                }
            }
        }

        // Build static server declarations from nodes
        let mut servers: HashMap<String, StaticServerDecl> = HashMap::new();

        for node in &snapshot.nodes {
            match node {
                TopologyNode::Server { name, .. } => {
                    servers
                        .entry(name.clone())
                        .or_insert_with(|| StaticServerDecl {
                            name: name.clone(),
                            tools: Vec::new(),
                            resources: Vec::new(),
                        });
                }
                TopologyNode::Tool {
                    server,
                    name,
                    description,
                    input_schema,
                    ..
                } => {
                    servers
                        .entry(server.clone())
                        .or_insert_with(|| StaticServerDecl {
                            name: server.clone(),
                            tools: Vec::new(),
                            resources: Vec::new(),
                        })
                        .tools
                        .push(StaticToolDecl {
                            name: name.clone(),
                            description: description.clone(),
                            input_schema: input_schema.clone(),
                        });
                }
                TopologyNode::Resource {
                    server,
                    uri_template,
                    name,
                    mime_type,
                } => {
                    servers
                        .entry(server.clone())
                        .or_insert_with(|| StaticServerDecl {
                            name: server.clone(),
                            tools: Vec::new(),
                            resources: Vec::new(),
                        })
                        .resources
                        .push(StaticResourceDecl {
                            uri_template: uri_template.clone(),
                            name: name.clone(),
                            mime_type: mime_type.clone(),
                        });
                }
            }
        }

        let server_list: Vec<StaticServerDecl> = servers.into_values().collect();
        let mut graph = TopologyGraph::from_static(server_list)?;

        // Re-add non-Owns edges
        let index = graph.name_index().clone();
        for edge in &snapshot.edges {
            if matches!(edge.edge, TopologyEdge::Owns) {
                continue; // Already created by from_static
            }
            if let (Some(&src), Some(&tgt)) = (index.get(&edge.source), index.get(&edge.target)) {
                graph.graph_mut().add_edge(src, tgt, edge.edge.clone());
            }
        }

        // SECURITY (R240-DISC-3): Use checked_add to prevent panic on crafted
        // crawled_at_epoch_secs (e.g., u64::MAX). The `+` operator on SystemTime
        // calls expect() which panics on overflow.
        let crawled_at = SystemTime::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(
                snapshot.crawled_at_epoch_secs,
            ))
            .ok_or_else(|| {
                DiscoveryError::ValidationError(
                    "crawled_at_epoch_secs overflows SystemTime".to_string(),
                )
            })?;
        graph.set_crawled_at(crawled_at);
        graph.recompute_fingerprint();

        // SECURITY (R241-DISC-1): Verify snapshot fingerprint if provided.
        // A non-empty fingerprint that doesn't match the recomputed value indicates
        // the snapshot was tampered with after export.
        if !snapshot.fingerprint.is_empty() && snapshot.fingerprint != graph.fingerprint_hex() {
            return Err(DiscoveryError::ValidationError(format!(
                "Snapshot fingerprint mismatch: claimed '{}', computed '{}'",
                snapshot.fingerprint,
                graph.fingerprint_hex()
            )));
        }

        Ok(graph)
    }

    /// Export tools matching a capability keyword.
    ///
    /// Searches tool names and descriptions for the keyword.
    pub fn tools_matching_capability(&self, keyword: &str) -> Vec<String> {
        let keyword_lower = keyword.to_lowercase();
        let mut results = Vec::new();

        for (qualified, idx) in self.name_index() {
            if let TopologyNode::Tool {
                name, description, ..
            } = &self.graph()[*idx]
            {
                if name.to_lowercase().contains(&keyword_lower)
                    || description.to_lowercase().contains(&keyword_lower)
                {
                    results.push(qualified.clone());
                }
            }
        }

        results.sort();
        results
    }

    /// Export the graph as an adjacency list.
    ///
    /// Returns vec of (source_qualified, vec of (target_qualified, edge_type_string)).
    pub fn to_adjacency_list(&self) -> Vec<(String, Vec<(String, String)>)> {
        let mut adj: HashMap<String, Vec<(String, String)>> = HashMap::new();

        for edge_ref in self.graph().edge_references() {
            let source = self.graph()[EdgeRef::source(&edge_ref)].qualified_name();
            let target = self.graph()[EdgeRef::target(&edge_ref)].qualified_name();
            let edge_type = match EdgeRef::weight(&edge_ref) {
                TopologyEdge::Owns => "Owns".to_string(),
                TopologyEdge::DataFlow { confidence, .. } => {
                    format!("DataFlow(conf={confidence:.2})")
                }
                TopologyEdge::Consumes { param } => format!("Consumes({param})"),
            };

            adj.entry(source).or_default().push((target, edge_type));
        }

        let mut result: Vec<(String, Vec<(String, String)>)> = adj.into_iter().collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, edges) in &mut result {
            edges.sort();
        }
        result
    }

    /// Merge two topologies.
    ///
    /// Deduplicates by qualified tool name, keeps the newer version on conflict.
    pub fn merge(&self, other: &TopologyGraph) -> Result<Self, crate::error::DiscoveryError> {
        let mut servers: HashMap<String, StaticServerDecl> = HashMap::new();

        // Collect from self
        collect_servers(self, &mut servers);
        // Collect from other (overwrites on conflict — newer wins)
        collect_servers(other, &mut servers);

        let server_list: Vec<StaticServerDecl> = servers.into_values().collect();
        TopologyGraph::from_static(server_list)
    }

    /// Filter topology to only include tools from specified servers.
    pub fn filter_servers(&self, allowed: &[&str]) -> Result<Self, crate::error::DiscoveryError> {
        let allowed_set: std::collections::HashSet<&str> = allowed.iter().copied().collect();

        let mut servers = Vec::new();
        for server_name in self.server_names() {
            if !allowed_set.contains(server_name.as_str()) {
                continue;
            }

            let tools: Vec<StaticToolDecl> = self
                .server_tools(&server_name)
                .into_iter()
                .filter_map(|node| {
                    if let TopologyNode::Tool {
                        name,
                        description,
                        input_schema,
                        ..
                    } = node
                    {
                        Some(StaticToolDecl {
                            name: name.clone(),
                            description: description.clone(),
                            input_schema: input_schema.clone(),
                        })
                    } else {
                        None
                    }
                })
                .collect();

            let resources: Vec<StaticResourceDecl> = self
                .server_resources(&server_name)
                .into_iter()
                .filter_map(|node| {
                    if let TopologyNode::Resource {
                        uri_template,
                        name,
                        mime_type,
                        ..
                    } = node
                    {
                        Some(StaticResourceDecl {
                            uri_template: uri_template.clone(),
                            name: name.clone(),
                            mime_type: mime_type.clone(),
                        })
                    } else {
                        None
                    }
                })
                .collect();

            servers.push(StaticServerDecl {
                name: server_name,
                tools,
                resources,
            });
        }

        TopologyGraph::from_static(servers)
    }
}

/// Collect server declarations from a topology into a map.
fn collect_servers(graph: &TopologyGraph, servers: &mut HashMap<String, StaticServerDecl>) {
    for server_name in graph.server_names() {
        let tools: Vec<StaticToolDecl> = graph
            .server_tools(&server_name)
            .into_iter()
            .filter_map(|node| {
                if let TopologyNode::Tool {
                    name,
                    description,
                    input_schema,
                    ..
                } = node
                {
                    Some(StaticToolDecl {
                        name: name.clone(),
                        description: description.clone(),
                        input_schema: input_schema.clone(),
                    })
                } else {
                    None
                }
            })
            .collect();

        let resources: Vec<StaticResourceDecl> = graph
            .server_resources(&server_name)
            .into_iter()
            .filter_map(|node| {
                if let TopologyNode::Resource {
                    uri_template,
                    name,
                    mime_type,
                    ..
                } = node
                {
                    Some(StaticResourceDecl {
                        uri_template: uri_template.clone(),
                        name: name.clone(),
                        mime_type: mime_type.clone(),
                    })
                } else {
                    None
                }
            })
            .collect();

        servers.insert(
            server_name.clone(),
            StaticServerDecl {
                name: server_name,
                tools,
                resources,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::{StaticResourceDecl, StaticServerDecl, StaticToolDecl, TopologyGraph};

    fn make_simple_topology() -> TopologyGraph {
        TopologyGraph::from_static(vec![StaticServerDecl {
            name: "fs".to_string(),
            tools: vec![StaticToolDecl {
                name: "read_file".to_string(),
                description: "Read a file from disk".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"}
                    }
                }),
            }],
            resources: vec![StaticResourceDecl {
                uri_template: "file:///{path}".to_string(),
                name: "file_resource".to_string(),
                mime_type: Some("text/plain".to_string()),
            }],
        }])
        .unwrap()
    }

    #[test]
    fn test_from_json_malformed_json_returns_error() {
        let result = TopologyGraph::from_json("this is not valid json {{{");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_json_empty_object_returns_error() {
        let result = TopologyGraph::from_json("{}");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_json_missing_fields_returns_error() {
        // Valid JSON but missing required fields
        let result = TopologyGraph::from_json(r#"{"nodes": []}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_json_unknown_fields_rejected() {
        // deny_unknown_fields on TopologySnapshot should reject extra fields
        let json = r#"{
            "nodes": [],
            "edges": [],
            "crawled_at_epoch_secs": 0,
            "fingerprint": "00",
            "extra_field": "should be rejected"
        }"#;
        let result = TopologyGraph::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_snapshot_oversized_edges_rejected() {
        // Manually construct a snapshot with too many edges (> MAX_SNAPSHOT_EDGES = 100_000)
        let snapshot = TopologySnapshot {
            nodes: vec![],
            edges: (0..100_001)
                .map(|i| SerializedEdge {
                    source: format!("s{i}"),
                    target: format!("t{i}"),
                    edge: crate::topology::TopologyEdge::Owns,
                })
                .collect(),
            crawled_at_epoch_secs: 0,
            fingerprint: String::new(),
        };
        let result = TopologyGraph::from_snapshot(snapshot);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("exceeds maximum"));
    }

    #[test]
    fn test_fingerprint_preserved_after_json_roundtrip() {
        let original = make_simple_topology();
        let original_fp = original.fingerprint_hex();

        let json = original.to_json().unwrap();
        let restored = TopologyGraph::from_json(&json).unwrap();

        // After round-trip, fingerprint should match (recomputed from same data)
        assert_eq!(
            original_fp,
            restored.fingerprint_hex(),
            "Fingerprint should be stable across JSON round-trip"
        );
    }

    #[test]
    fn test_snapshot_roundtrip_preserves_resources() {
        let graph = make_simple_topology();
        let snapshot = graph.to_snapshot();
        let restored = TopologyGraph::from_snapshot(snapshot).unwrap();

        let resource_names = restored.resource_names();
        assert!(resource_names.contains(&"fs::file_resource".to_string()));
    }

    #[test]
    fn test_tools_matching_capability_case_insensitive() {
        let graph = make_simple_topology();
        // "READ" in uppercase should still match "read_file"
        let matches = graph.tools_matching_capability("READ");
        assert!(
            matches.contains(&"fs::read_file".to_string()),
            "Case-insensitive search should find read_file, got: {matches:?}",
        );
    }

    #[test]
    fn test_tools_matching_capability_matches_description() {
        let graph = make_simple_topology();
        // "disk" appears in description "Read a file from disk"
        let matches = graph.tools_matching_capability("disk");
        assert!(
            matches.contains(&"fs::read_file".to_string()),
            "Should match on description keyword 'disk', got: {matches:?}",
        );
    }

    #[test]
    fn test_tools_matching_capability_empty_keyword() {
        let graph = make_simple_topology();
        // Empty string should match everything (every name/description contains "")
        let matches = graph.tools_matching_capability("");
        assert!(!matches.is_empty(), "Empty keyword should match all tools");
    }

    #[test]
    fn test_adjacency_list_sorted() {
        let graph = TopologyGraph::from_static(vec![
            StaticServerDecl {
                name: "beta".to_string(),
                tools: vec![StaticToolDecl {
                    name: "tool_b".to_string(),
                    description: "B".to_string(),
                    input_schema: serde_json::json!({}),
                }],
                resources: vec![],
            },
            StaticServerDecl {
                name: "alpha".to_string(),
                tools: vec![StaticToolDecl {
                    name: "tool_a".to_string(),
                    description: "A".to_string(),
                    input_schema: serde_json::json!({}),
                }],
                resources: vec![],
            },
        ])
        .unwrap();

        let adj = graph.to_adjacency_list();
        // Verify outer list is sorted by source name
        let sources: Vec<&str> = adj.iter().map(|(s, _)| s.as_str()).collect();
        let mut sorted_sources = sources.clone();
        sorted_sources.sort();
        assert_eq!(sources, sorted_sources, "Adjacency list should be sorted");
    }

    #[test]
    fn test_merge_preserves_both_servers_tools() {
        let t1 = TopologyGraph::from_static(vec![StaticServerDecl {
            name: "s1".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "t1".to_string(),
                    description: "Tool 1".to_string(),
                    input_schema: serde_json::json!({}),
                },
                StaticToolDecl {
                    name: "t2".to_string(),
                    description: "Tool 2".to_string(),
                    input_schema: serde_json::json!({}),
                },
            ],
            resources: vec![],
        }])
        .unwrap();

        let t2 = TopologyGraph::from_static(vec![StaticServerDecl {
            name: "s2".to_string(),
            tools: vec![StaticToolDecl {
                name: "t3".to_string(),
                description: "Tool 3".to_string(),
                input_schema: serde_json::json!({}),
            }],
            resources: vec![],
        }])
        .unwrap();

        let merged = t1.merge(&t2).unwrap();
        assert_eq!(merged.server_count(), 2);
        assert!(merged.find_tool("s1::t1").is_some());
        assert!(merged.find_tool("s1::t2").is_some());
        assert!(merged.find_tool("s2::t3").is_some());
    }

    #[test]
    fn test_filter_servers_none_allowed() {
        let graph = make_simple_topology();
        let filtered = graph.filter_servers(&[]).unwrap();
        assert_eq!(filtered.server_count(), 0);
        assert_eq!(filtered.node_count(), 0);
    }

    #[test]
    fn test_filter_servers_nonexistent_name() {
        let graph = make_simple_topology();
        let filtered = graph.filter_servers(&["nonexistent"]).unwrap();
        assert_eq!(filtered.server_count(), 0);
    }

    #[test]
    fn test_snapshot_dataflow_edges_roundtrip() {
        // Build a topology, add DataFlow edges, serialize, and restore
        let mut graph = TopologyGraph::from_static(vec![StaticServerDecl {
            name: "srv".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "producer".to_string(),
                    description: "Produces data".to_string(),
                    input_schema: serde_json::json!({}),
                },
                StaticToolDecl {
                    name: "consumer".to_string(),
                    description: "Consumes data".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "data": {"type": "string"}
                        }
                    }),
                },
            ],
            resources: vec![],
        }])
        .unwrap();

        // Manually add a DataFlow edge via inference engine
        let engine = crate::inference::InferenceEngine::new(crate::inference::InferenceConfig {
            threshold: 0.0,
            ..crate::inference::InferenceConfig::default()
        });
        engine.infer_edges(&mut graph);

        let initial_edge_count = graph.edge_count();
        let json = graph.to_json().unwrap();
        let restored = TopologyGraph::from_json(&json).unwrap();

        assert_eq!(
            initial_edge_count,
            restored.edge_count(),
            "Edge count should be preserved across roundtrip"
        );
    }
}
