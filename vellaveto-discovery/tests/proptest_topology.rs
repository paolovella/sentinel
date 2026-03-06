// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Property-based tests for topology invariants.

use proptest::prelude::*;
use vellaveto_discovery::topology::*;

/// Generate a random valid server name.
fn arb_server_name() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{1,10}".prop_map(|s| s)
}

/// Generate a random valid tool name.
fn arb_tool_name() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{1,15}".prop_map(|s| s)
}

/// Generate a StaticToolDecl.
fn arb_tool_decl() -> impl Strategy<Value = StaticToolDecl> {
    (arb_tool_name(), "[a-zA-Z ]{5,30}").prop_map(|(name, desc)| StaticToolDecl {
        name,
        description: desc,
        input_schema: serde_json::json!({"type": "object"}),
    })
}

/// Generate a StaticServerDecl with 1-5 tools.
fn arb_server_decl() -> impl Strategy<Value = StaticServerDecl> {
    (
        arb_server_name(),
        prop::collection::vec(arb_tool_decl(), 1..5),
    )
        .prop_map(|(name, tools)| {
            // Deduplicate tool names
            let mut seen = std::collections::HashSet::new();
            let unique_tools: Vec<StaticToolDecl> = tools
                .into_iter()
                .filter(|t| seen.insert(t.name.clone()))
                .collect();
            StaticServerDecl {
                name,
                tools: unique_tools,
                resources: vec![],
            }
        })
}

/// Generate 1-4 servers with unique names.
fn arb_servers() -> impl Strategy<Value = Vec<StaticServerDecl>> {
    prop::collection::vec(arb_server_decl(), 1..4).prop_map(|servers| {
        let mut seen = std::collections::HashSet::new();
        servers
            .into_iter()
            .filter(|s| seen.insert(s.name.clone()))
            .collect()
    })
}

proptest! {
    #[test]
    fn prop_all_tools_reachable_from_server(servers in arb_servers()) {
        let graph = TopologyGraph::from_static(servers).unwrap();

        // Every tool node should be reachable from its server
        for tool_name in graph.tool_names() {
            let parts: Vec<&str> = tool_name.splitn(2, "::").collect();
            if parts.len() == 2 {
                let server_name = parts[0];
                let tool_simple_name = parts[1];
                let server_tools = graph.server_tools(server_name);
                let found = server_tools.iter().any(|t| t.name() == tool_simple_name);
                prop_assert!(found, "Tool {} not reachable from server {}", tool_name, server_name);
            }
        }
    }

    #[test]
    fn prop_qualified_name_unique(servers in arb_servers()) {
        let graph = TopologyGraph::from_static(servers).unwrap();
        let names = graph.tool_names();
        let unique: std::collections::HashSet<&String> = names.iter().collect();
        prop_assert_eq!(names.len(), unique.len(), "Qualified names must be unique");
    }

    #[test]
    fn prop_node_count_matches_components(servers in arb_servers()) {
        let graph = TopologyGraph::from_static(servers.clone()).unwrap();

        let expected_servers = servers.len();
        let expected_tools: usize = servers.iter().map(|s| s.tools.len()).sum();
        let expected_resources: usize = servers.iter().map(|s| s.resources.len()).sum();
        let expected_total = expected_servers + expected_tools + expected_resources;

        prop_assert_eq!(graph.node_count(), expected_total);
    }

    #[test]
    fn prop_owns_edge_count_matches(servers in arb_servers()) {
        let graph = TopologyGraph::from_static(servers.clone()).unwrap();

        let expected_edges: usize = servers.iter().map(|s| s.tools.len() + s.resources.len()).sum();
        prop_assert_eq!(graph.edge_count(), expected_edges, "Owns edges should equal tools + resources");
    }

    #[test]
    fn prop_fingerprint_is_32_bytes(servers in arb_servers()) {
        let graph = TopologyGraph::from_static(servers).unwrap();
        prop_assert_eq!(graph.fingerprint().len(), 32);
        prop_assert_eq!(graph.fingerprint_hex().len(), 64);
    }
}
