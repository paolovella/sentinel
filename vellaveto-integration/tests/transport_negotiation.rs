// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Integration tests for Phase 18: Transport negotiation and backward compatibility.
//!
//! Verifies that the transport discovery, negotiation, and protocol version
//! handling works correctly across supported MCP spec versions.

use vellaveto_types::{TransportEndpoint, TransportProtocol};

#[test]
fn test_backward_compat_no_transport_header() {
    // Clients that don't send the mcp-transport-preference header should
    // still work — HTTP is the implicit default.
    let prefs: Vec<TransportProtocol> =
        vellaveto_http_proxy::proxy::discovery::parse_transport_preference("");
    assert!(
        prefs.is_empty(),
        "Empty preference should result in empty list (HTTP implicit default)"
    );
}

#[test]
fn test_default_version_floor_excludes_2025_03_26() {
    // The firewall default floor is 2025-11-25, so older protocol versions
    // remain parseable only when policy explicitly lowers the floor.
    let caps = vellaveto_http_proxy::proxy::discovery::build_sdk_capabilities();
    assert!(
        !caps.supported_versions.contains(&"2025-03-26".to_string()),
        "2025-03-26 must not be advertised at the default version floor"
    );
}

#[test]
fn test_highest_supported_version_is_2026_07_28() {
    // The highest supported version must be 2026-07-28, with 2025-11-25
    // retained for the deprecation window.
    let caps = vellaveto_http_proxy::proxy::discovery::build_sdk_capabilities();
    assert!(
        caps.supported_versions.contains(&"2026-07-28".to_string()),
        "2026-07-28 must be in supported_versions"
    );
    assert!(
        caps.supported_versions.contains(&"2025-11-25".to_string()),
        "2025-11-25 must be in supported_versions"
    );
    // It should be the first (highest priority) entry.
    assert_eq!(
        caps.supported_versions[0], "2026-07-28",
        "2026-07-28 should be the first supported version"
    );
}

#[test]
fn test_transport_protocol_preference_order() {
    // Verify the natural ordering: Grpc < WebSocket < Http < Stdio
    assert!(TransportProtocol::Grpc < TransportProtocol::WebSocket);
    assert!(TransportProtocol::WebSocket < TransportProtocol::Http);
    assert!(TransportProtocol::Http < TransportProtocol::Stdio);
}

#[test]
fn test_discovery_response_structure() {
    // Verify SDK capabilities serialize to the expected shape.
    let caps = vellaveto_http_proxy::proxy::discovery::build_sdk_capabilities();
    let json = serde_json::to_value(&caps).unwrap();
    assert!(json.get("tier").is_some(), "Must have tier field");
    assert!(
        json.get("capabilities").is_some(),
        "Must have capabilities field"
    );
    assert!(
        json.get("supported_versions").is_some(),
        "Must have supported_versions field"
    );

    // Verify TransportEndpoint serializes correctly.
    let endpoint = TransportEndpoint {
        protocol: TransportProtocol::Http,
        url: "http://localhost:3001/mcp".to_string(),
        available: true,
        protocol_versions: vec!["2026-06".to_string()],
    };
    let endpoint_json = serde_json::to_value(&endpoint).unwrap();
    assert_eq!(endpoint_json["protocol"], "http");
    assert_eq!(endpoint_json["available"], true);
}
