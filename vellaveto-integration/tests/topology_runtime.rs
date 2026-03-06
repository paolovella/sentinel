// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Integration tests for topology runtime wiring.
//!
//! Verifies the end-to-end flow: StaticProbe → TopologyCrawler → TopologyGuard
//! with incremental updates via upsert_server.

use std::sync::Arc;

use serde_json::json;
use vellaveto_discovery::crawler::{McpServerProbe, StaticProbe};
use vellaveto_discovery::guard::{TopologyGuard, TopologyVerdict};
use vellaveto_discovery::topology::{StaticServerDecl, StaticToolDecl, TopologyGraph};
use vellaveto_discovery::{CrawlConfig, TopologyCrawler};

fn make_server(name: &str, tools: Vec<(&str, &str)>) -> StaticServerDecl {
    StaticServerDecl {
        name: name.to_string(),
        tools: tools
            .into_iter()
            .map(|(n, d)| StaticToolDecl {
                name: n.to_string(),
                description: d.to_string(),
                input_schema: json!({"type": "object"}),
            })
            .collect(),
        resources: vec![],
    }
}

/// End-to-end: populate StaticProbe, crawl via TopologyCrawler, verify guard.
#[tokio::test]
async fn test_probe_crawl_guard_pipeline() {
    // 1. Create a static probe with two servers
    let probe = Arc::new(StaticProbe::new(vec![
        make_server(
            "fs",
            vec![("read_file", "Read a file"), ("write_file", "Write a file")],
        ),
        make_server("web", vec![("fetch_url", "Fetch a URL")]),
    ]));

    // 2. Create crawler
    let crawler = TopologyCrawler::new(
        Arc::clone(&probe) as Arc<dyn McpServerProbe>,
        CrawlConfig::default(),
    );

    // 3. Crawl
    let result = crawler.crawl().await.unwrap();
    assert_eq!(result.servers_crawled, 2);
    assert_eq!(result.tools_found, 3);

    // 4. Load into guard
    let guard = TopologyGuard::new();
    guard.update(result.topology);

    // 5. Verify lookups
    assert!(
        matches!(guard.check("read_file"), TopologyVerdict::Known { server, .. } if server == "fs")
    );
    assert!(
        matches!(guard.check("fetch_url"), TopologyVerdict::Known { server, .. } if server == "web")
    );
    assert!(matches!(
        guard.check("nonexistent"),
        TopologyVerdict::Unknown { .. }
    ));
}

/// Incremental update: upsert a server via the guard after initial crawl.
#[tokio::test]
async fn test_incremental_upsert_after_crawl() {
    // Initial crawl
    let probe = Arc::new(StaticProbe::new(vec![make_server(
        "fs",
        vec![("read_file", "Read a file")],
    )]));
    let crawler = TopologyCrawler::new(
        Arc::clone(&probe) as Arc<dyn McpServerProbe>,
        CrawlConfig::default(),
    );
    let result = crawler.crawl().await.unwrap();

    let guard = Arc::new(TopologyGuard::new());
    guard.update(result.topology);

    // Verify initial state
    assert!(matches!(
        guard.check("read_file"),
        TopologyVerdict::Known { .. }
    ));
    assert!(matches!(
        guard.check("new_tool"),
        TopologyVerdict::Unknown { .. }
    ));

    // Upsert a new server (simulating relay intercept)
    let decl = make_server("relay_server", vec![("new_tool", "A new tool")]);
    guard.upsert_server(decl).unwrap();

    // Both old and new tools should be known
    assert!(matches!(
        guard.check("read_file"),
        TopologyVerdict::Known { .. }
    ));
    assert!(matches!(
        guard.check("new_tool"),
        TopologyVerdict::Known { .. }
    ));
}

/// Verify that StaticProbe updates are reflected in subsequent crawls.
#[tokio::test]
async fn test_probe_upsert_affects_next_crawl() {
    let probe = Arc::new(StaticProbe::new(vec![make_server(
        "initial",
        vec![("tool_a", "Tool A")],
    )]));

    // First crawl
    let crawler = TopologyCrawler::new(
        Arc::clone(&probe) as Arc<dyn McpServerProbe>,
        CrawlConfig::default(),
    );
    let result1 = crawler.crawl().await.unwrap();
    assert_eq!(result1.servers_crawled, 1);
    assert_eq!(result1.tools_found, 1);

    // Add a server to the probe
    probe.upsert_server(make_server("dynamic", vec![("tool_b", "Tool B")]));

    // Second crawl should see the new server
    let result2 = crawler.crawl().await.unwrap();
    assert_eq!(result2.servers_crawled, 2);
    assert_eq!(result2.tools_found, 2);
}

/// Verify to_static round-trip preserves graph equality.
#[tokio::test]
async fn test_to_static_preserves_graph_content() {
    let probe = Arc::new(StaticProbe::new(vec![
        make_server("alpha", vec![("tool_1", "Desc 1"), ("tool_2", "Desc 2")]),
        make_server("beta", vec![("tool_3", "Desc 3")]),
    ]));

    let crawler = TopologyCrawler::new(
        Arc::clone(&probe) as Arc<dyn McpServerProbe>,
        CrawlConfig::default(),
    );
    let result = crawler.crawl().await.unwrap();

    // Round-trip through to_static → from_static
    let decls = result.topology.to_static();
    let rebuilt = TopologyGraph::from_static(decls).unwrap();

    assert_eq!(rebuilt.server_count(), result.topology.server_count());
    assert_eq!(rebuilt.tool_names(), result.topology.tool_names());
    assert_eq!(rebuilt.fingerprint(), result.topology.fingerprint());
}

/// Guard check returns Known for qualified and unqualified names after crawl.
#[tokio::test]
async fn test_guard_check_qualified_and_unqualified() {
    let probe = Arc::new(StaticProbe::new(vec![make_server(
        "server_a",
        vec![("unique_tool", "A unique tool")],
    )]));
    let crawler = TopologyCrawler::new(
        Arc::clone(&probe) as Arc<dyn McpServerProbe>,
        CrawlConfig::default(),
    );
    let result = crawler.crawl().await.unwrap();

    let guard = TopologyGuard::new();
    guard.update(result.topology);

    // Qualified lookup
    assert!(matches!(
        guard.check("server_a::unique_tool"),
        TopologyVerdict::Known { server, tool, .. } if server == "server_a" && tool == "unique_tool"
    ));

    // Unqualified lookup
    assert!(matches!(
        guard.check("unique_tool"),
        TopologyVerdict::Known { server, tool, .. } if server == "server_a" && tool == "unique_tool"
    ));
}
