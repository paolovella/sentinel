// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Tests for `StaticProbe` — in-memory `McpServerProbe` implementation.

use serde_json::json;
use vellaveto_discovery::crawler::{McpServerProbe, StaticProbe};
use vellaveto_discovery::topology::{StaticResourceDecl, StaticServerDecl, StaticToolDecl};

fn make_server(name: &str, tools: Vec<&str>) -> StaticServerDecl {
    StaticServerDecl {
        name: name.to_string(),
        tools: tools
            .into_iter()
            .map(|t| StaticToolDecl {
                name: t.to_string(),
                description: format!("{t} description"),
                input_schema: json!({"type": "object"}),
            })
            .collect(),
        resources: vec![],
    }
}

fn make_server_with_resources(
    name: &str,
    tools: Vec<&str>,
    resources: Vec<&str>,
) -> StaticServerDecl {
    StaticServerDecl {
        name: name.to_string(),
        tools: tools
            .into_iter()
            .map(|t| StaticToolDecl {
                name: t.to_string(),
                description: format!("{t} description"),
                input_schema: json!({"type": "object"}),
            })
            .collect(),
        resources: resources
            .into_iter()
            .map(|r| StaticResourceDecl {
                uri_template: format!("file:///{r}"),
                name: r.to_string(),
                mime_type: None,
            })
            .collect(),
    }
}

#[tokio::test]
async fn test_static_probe_new_empty() {
    let probe = StaticProbe::new(vec![]);
    assert_eq!(probe.server_count(), 0);
    let servers = probe.list_servers().await.unwrap();
    assert!(servers.is_empty());
}

#[tokio::test]
async fn test_static_probe_new_with_servers() {
    let probe = StaticProbe::new(vec![
        make_server("alpha", vec!["read_file", "write_file"]),
        make_server("beta", vec!["fetch_url"]),
    ]);
    assert_eq!(probe.server_count(), 2);

    let servers = probe.list_servers().await.unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0].id, "alpha");
    assert_eq!(servers[1].id, "beta");
}

#[tokio::test]
async fn test_static_probe_list_tools() {
    let probe = StaticProbe::new(vec![make_server("fs", vec!["read_file", "write_file"])]);

    let tools = probe.list_tools("fs").await.unwrap();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0].name, "read_file");
    assert_eq!(tools[1].name, "write_file");
}

#[tokio::test]
async fn test_static_probe_list_tools_not_found() {
    let probe = StaticProbe::new(vec![make_server("fs", vec!["read_file"])]);
    let err = probe.list_tools("nonexistent").await.unwrap_err();
    assert!(err.to_string().contains("nonexistent"));
}

#[tokio::test]
async fn test_static_probe_list_resources() {
    let probe = StaticProbe::new(vec![make_server_with_resources(
        "fs",
        vec![],
        vec!["config"],
    )]);

    let resources = probe.list_resources("fs").await.unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].name, "config");
}

#[tokio::test]
async fn test_static_probe_server_capabilities() {
    let probe = StaticProbe::new(vec![
        make_server("with_tools", vec!["tool1"]),
        make_server_with_resources("with_resources", vec![], vec!["res1"]),
        make_server("empty", vec![]),
    ]);

    let cap1 = probe.server_capabilities("with_tools").await.unwrap();
    assert!(cap1.tools);
    assert!(!cap1.resources);

    let cap2 = probe.server_capabilities("with_resources").await.unwrap();
    assert!(!cap2.tools);
    assert!(cap2.resources);

    let cap3 = probe.server_capabilities("empty").await.unwrap();
    assert!(!cap3.tools);
    assert!(!cap3.resources);
}

#[tokio::test]
async fn test_static_probe_upsert_new_server() {
    let probe = StaticProbe::new(vec![make_server("alpha", vec!["tool_a"])]);
    assert_eq!(probe.server_count(), 1);

    probe.upsert_server(make_server("beta", vec!["tool_b"]));
    assert_eq!(probe.server_count(), 2);

    let tools = probe.list_tools("beta").await.unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "tool_b");
}

#[tokio::test]
async fn test_static_probe_upsert_replace_existing() {
    let probe = StaticProbe::new(vec![make_server("alpha", vec!["old_tool"])]);

    // Replace alpha with new tools
    probe.upsert_server(make_server("alpha", vec!["new_tool_1", "new_tool_2"]));
    assert_eq!(probe.server_count(), 1);

    let tools = probe.list_tools("alpha").await.unwrap();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0].name, "new_tool_1");
    assert_eq!(tools[1].name, "new_tool_2");
}

#[tokio::test]
async fn test_static_probe_remove_server() {
    let probe = StaticProbe::new(vec![
        make_server("alpha", vec!["tool_a"]),
        make_server("beta", vec!["tool_b"]),
    ]);

    assert!(probe.remove_server("alpha"));
    assert_eq!(probe.server_count(), 1);

    // Alpha should be gone
    assert!(probe.list_tools("alpha").await.is_err());

    // Beta should still be there
    assert!(probe.list_tools("beta").await.is_ok());
}

#[tokio::test]
async fn test_static_probe_remove_nonexistent() {
    let probe = StaticProbe::new(vec![make_server("alpha", vec!["tool_a"])]);
    assert!(!probe.remove_server("nonexistent"));
    assert_eq!(probe.server_count(), 1);
}

#[test]
fn test_static_probe_debug() {
    let probe = StaticProbe::new(vec![make_server("x", vec!["y"])]);
    let debug = format!("{:?}", probe);
    assert!(debug.contains("StaticProbe"));
    assert!(debug.contains("server_count"));
}
