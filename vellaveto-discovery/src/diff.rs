// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Topology diffing — compare two snapshots.
//!
//! Detects added, removed, and modified tools/servers/resources between
//! two topology snapshots.

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use crate::topology::{TopologyEdge, TopologyGraph, TopologyNode};
use petgraph::visit::EdgeRef;

/// A qualified tool reference (server::tool).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub struct QualifiedTool {
    /// The server name.
    pub server: String,
    /// The tool name.
    pub tool: String,
    /// The qualified name ("server::tool").
    pub qualified: String,
}

/// A modification to a tool's schema or description.
#[derive(Debug, Clone, Serialize)]
pub struct ToolModification {
    /// The qualified tool name.
    pub qualified: String,
    /// Whether the description changed.
    pub description_changed: bool,
    /// Whether the input schema changed.
    pub schema_changed: bool,
    /// Human-readable summary of the change.
    pub summary: String,
}

/// The difference between two topology snapshots.
#[derive(Debug, Clone, Serialize)]
pub struct TopologyDiff {
    /// Servers that were added.
    pub added_servers: Vec<String>,
    /// Servers that were removed.
    pub removed_servers: Vec<String>,
    /// Tools that were added.
    pub added_tools: Vec<QualifiedTool>,
    /// Tools that were removed.
    pub removed_tools: Vec<QualifiedTool>,
    /// Tools that were modified (description or schema changed).
    pub modified_tools: Vec<ToolModification>,
    /// Resources that were added.
    pub added_resources: Vec<String>,
    /// Resources that were removed.
    pub removed_resources: Vec<String>,
    /// SECURITY (R231-DISC-6): DataFlow edges that were added.
    pub added_data_flow_edges: Vec<(String, String)>,
    /// DataFlow edges that were removed.
    pub removed_data_flow_edges: Vec<(String, String)>,
    /// When this diff was computed.
    pub timestamp: SystemTime,
}

impl TopologyDiff {
    /// Returns true if there are no changes.
    pub fn is_empty(&self) -> bool {
        self.added_servers.is_empty()
            && self.removed_servers.is_empty()
            && self.added_tools.is_empty()
            && self.removed_tools.is_empty()
            && self.modified_tools.is_empty()
            && self.added_resources.is_empty()
            && self.removed_resources.is_empty()
            && self.added_data_flow_edges.is_empty()
            && self.removed_data_flow_edges.is_empty()
    }

    /// Returns true if any tools or servers were removed.
    pub fn has_removals(&self) -> bool {
        !self.removed_servers.is_empty()
            || !self.removed_tools.is_empty()
            || !self.removed_resources.is_empty()
    }

    /// Returns true if any tool schemas changed.
    pub fn has_schema_changes(&self) -> bool {
        self.modified_tools.iter().any(|m| m.schema_changed)
    }

    /// Human-readable one-line summary.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();

        if !self.added_servers.is_empty() {
            parts.push(format!("+{} servers", self.added_servers.len()));
        }
        if !self.removed_servers.is_empty() {
            parts.push(format!("-{} servers", self.removed_servers.len()));
        }
        if !self.added_tools.is_empty() {
            parts.push(format!("+{} tools", self.added_tools.len()));
        }
        if !self.removed_tools.is_empty() {
            parts.push(format!("-{} tools", self.removed_tools.len()));
        }
        if !self.modified_tools.is_empty() {
            parts.push(format!("~{} tools", self.modified_tools.len()));
        }
        if !self.added_resources.is_empty() {
            parts.push(format!("+{} resources", self.added_resources.len()));
        }
        if !self.removed_resources.is_empty() {
            parts.push(format!("-{} resources", self.removed_resources.len()));
        }
        if !self.added_data_flow_edges.is_empty() {
            parts.push(format!("+{} data flows", self.added_data_flow_edges.len()));
        }
        if !self.removed_data_flow_edges.is_empty() {
            parts.push(format!(
                "-{} data flows",
                self.removed_data_flow_edges.len()
            ));
        }

        if parts.is_empty() {
            "no changes".to_string()
        } else {
            parts.join(", ")
        }
    }
}

impl TopologyGraph {
    /// Compute the diff between this (older) topology and a newer one.
    pub fn diff(&self, newer: &TopologyGraph) -> TopologyDiff {
        let old_servers: HashSet<String> = self.server_names().into_iter().collect();
        let new_servers: HashSet<String> = newer.server_names().into_iter().collect();

        let added_servers: Vec<String> = new_servers.difference(&old_servers).cloned().collect();
        let removed_servers: Vec<String> = old_servers.difference(&new_servers).cloned().collect();

        let old_tools: HashSet<String> = self.tool_names().into_iter().collect();
        let new_tools: HashSet<String> = newer.tool_names().into_iter().collect();

        let added_tools: Vec<QualifiedTool> = new_tools
            .difference(&old_tools)
            .map(|q| qualified_from_str(q))
            .collect();
        let removed_tools: Vec<QualifiedTool> = old_tools
            .difference(&new_tools)
            .map(|q| qualified_from_str(q))
            .collect();

        // Check for modifications (same qualified name, different content)
        let common_tools: HashSet<&String> = old_tools.intersection(&new_tools).collect();
        let mut modified_tools = Vec::new();

        let old_tool_map = build_tool_map(self);
        let new_tool_map = build_tool_map(newer);

        for qualified in common_tools {
            if let (Some(old_node), Some(new_node)) = (
                old_tool_map.get(qualified.as_str()),
                new_tool_map.get(qualified.as_str()),
            ) {
                let desc_changed = old_node.0 != new_node.0;
                let schema_changed = old_node.1 != new_node.1;

                if desc_changed || schema_changed {
                    let mut changes = Vec::new();
                    if desc_changed {
                        changes.push("description");
                    }
                    if schema_changed {
                        changes.push("schema");
                    }
                    modified_tools.push(ToolModification {
                        qualified: qualified.clone(),
                        description_changed: desc_changed,
                        schema_changed,
                        summary: format!("{}: {} changed", qualified, changes.join(" and ")),
                    });
                }
            }
        }

        // Resources
        let old_resources: HashSet<String> = self.resource_names().into_iter().collect();
        let new_resources: HashSet<String> = newer.resource_names().into_iter().collect();

        let added_resources: Vec<String> =
            new_resources.difference(&old_resources).cloned().collect();
        let removed_resources: Vec<String> =
            old_resources.difference(&new_resources).cloned().collect();

        // SECURITY (R231-DISC-6): Track DataFlow edge changes.
        let old_data_flows = collect_data_flow_edges(self);
        let new_data_flows = collect_data_flow_edges(newer);
        let added_data_flow_edges: Vec<(String, String)> = new_data_flows
            .difference(&old_data_flows)
            .cloned()
            .collect();
        let removed_data_flow_edges: Vec<(String, String)> = old_data_flows
            .difference(&new_data_flows)
            .cloned()
            .collect();

        TopologyDiff {
            added_servers,
            removed_servers,
            added_tools,
            removed_tools,
            modified_tools,
            added_resources,
            removed_resources,
            added_data_flow_edges,
            removed_data_flow_edges,
            timestamp: SystemTime::now(),
        }
    }

    /// All qualified resource names in the topology.
    pub fn resource_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .name_index()
            .iter()
            .filter(|(_, idx)| self.graph()[**idx].is_resource())
            .map(|(name, _)| name.clone())
            .collect();
        names.sort();
        names
    }
}

/// Build a map of qualified_name → (description, schema_json) for diffing.
fn build_tool_map(graph: &TopologyGraph) -> HashMap<&str, (&str, &serde_json::Value)> {
    let mut map = HashMap::new();
    for (name, idx) in graph.name_index() {
        if let TopologyNode::Tool {
            description,
            input_schema,
            ..
        } = &graph.graph()[*idx]
        {
            map.insert(name.as_str(), (description.as_str(), input_schema));
        }
    }
    map
}

/// Collect all DataFlow edges as (source_qualified, target_qualified) pairs.
fn collect_data_flow_edges(graph: &TopologyGraph) -> HashSet<(String, String)> {
    let reverse_index: HashMap<petgraph::graph::NodeIndex, &str> = graph
        .name_index()
        .iter()
        .map(|(name, idx)| (*idx, name.as_str()))
        .collect();
    let mut edges = HashSet::new();
    for edge in graph.graph().edge_references() {
        if matches!(edge.weight(), TopologyEdge::DataFlow { .. }) {
            if let (Some(&src), Some(&tgt)) = (
                reverse_index.get(&edge.source()),
                reverse_index.get(&edge.target()),
            ) {
                edges.insert((src.to_string(), tgt.to_string()));
            }
        }
    }
    edges
}

/// Parse a qualified name "server::tool" into a QualifiedTool.
fn qualified_from_str(s: &str) -> QualifiedTool {
    let parts: Vec<&str> = s.splitn(2, "::").collect();
    if parts.len() == 2 {
        QualifiedTool {
            server: parts[0].to_string(),
            tool: parts[1].to_string(),
            qualified: s.to_string(),
        }
    } else {
        QualifiedTool {
            server: String::new(),
            tool: s.to_string(),
            qualified: s.to_string(),
        }
    }
}
