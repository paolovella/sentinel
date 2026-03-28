// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Upstream forwarding for gRPC transport.
//!
//! Two modes:
//! - **gRPC-to-HTTP fallback**: Converts proto→JSON, sends via HTTP to the
//!   upstream URL, and converts the response back to proto. This lets gRPC
//!   clients work with existing HTTP MCP servers.
//! - **gRPC-to-gRPC**: When `upstream_grpc_url` is configured, forwards
//!   proto messages directly via a tonic client.

use std::sync::Arc;

use serde_json::Value;

use super::ProxyState;

/// SECURITY (FIND-R55-GRPC-008): Maximum response body size for gRPC-to-HTTP fallback.
/// Matches the smart_fallback chain's MAX_RESPONSE_BODY_BYTES (16 MB).
const MAX_GRPC_HTTP_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Errors from upstream forwarding.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("HTTP upstream request failed: {0}")]
    HttpError(String),

    #[error("HTTP upstream response is not valid JSON: {0}")]
    JsonError(String),

    #[error("gRPC upstream error: {0}")]
    GrpcError(String),

    #[error("upstream URL not configured")]
    NoUpstream,
}

/// Forwards JSON-RPC requests to the upstream MCP server.
///
/// Supports HTTP fallback mode (convert JSON, POST to upstream_url) and
/// native gRPC forwarding when an upstream gRPC URL is configured.
#[derive(Clone)]
pub struct UpstreamForwarder {
    state: Arc<ProxyState>,
}

impl UpstreamForwarder {
    pub fn new(state: Arc<ProxyState>) -> Self {
        Self { state }
    }

    /// Forward a JSON-RPC request (as `serde_json::Value`) to the upstream server.
    ///
    /// Currently uses HTTP fallback mode: serializes the JSON, POSTs to the
    /// upstream URL, and parses the response. This allows gRPC clients to
    /// work with any existing HTTP MCP server without modification.
    pub async fn forward_json(&self, json_req: &Value) -> Result<Value, UpstreamError> {
        self.forward_via_http(json_req).await
    }

    /// Forward via HTTP (gRPC-to-HTTP fallback).
    ///
    /// Optionally injects W3C Trace Context headers when `trace_ctx` is provided.
    async fn forward_via_http(&self, json_req: &Value) -> Result<Value, UpstreamError> {
        let body = serde_json::to_vec(json_req)
            .map_err(|e| UpstreamError::HttpError(format!("Failed to serialize request: {}", e)))?;

        // Phase 20: Use gateway default backend if configured
        let upstream_url = if let Some(ref gw) = self.state.gateway {
            gw.route("")
                .map(|d| d.upstream_url)
                .unwrap_or_else(|| self.state.upstream_url.clone())
        } else {
            self.state.upstream_url.clone()
        };

        // SECURITY (R255-PROXY-1): Enforce HTTPS for non-local upstream URLs.
        // Parity with fallback.rs and smart_fallback.rs.
        super::super::validate_upstream_url_scheme(&upstream_url)
            .map_err(UpstreamError::HttpError)?;

        let mut request_builder = self
            .state
            .http_client
            .post(&upstream_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json");

        // Phase 28: Inject trace context if available in the request
        // For gRPC-to-HTTP fallback, generate a fresh trace context
        let mut trace_ctx = vellaveto_audit::observability::TraceContext::default();
        trace_ctx.ensure_trace_id();
        if let Some(traceparent) = trace_ctx.to_traceparent() {
            request_builder = request_builder.header("traceparent", traceparent);
        }

        let response = request_builder
            .body(body)
            .send()
            .await
            .map_err(|e| UpstreamError::HttpError(format!("HTTP request failed: {}", e)))?;

        let status = response.status();

        // SECURITY (FIND-R55-GRPC-008): Bounded response body read.
        // Prevents OOM from oversized upstream responses. Fast-reject via
        // Content-Length, then chunked accumulation with size check.
        // SECURITY (R240-P3-PROXY-6): Compare in u64 space to avoid truncation on 32-bit.
        if let Some(len) = response.content_length() {
            if len > MAX_GRPC_HTTP_RESPONSE_BYTES as u64 {
                return Err(UpstreamError::HttpError(format!(
                    "response body too large: {} bytes (max {})",
                    len, MAX_GRPC_HTTP_RESPONSE_BYTES
                )));
            }
        }

        let capacity = std::cmp::min(
            response.content_length().unwrap_or(8192) as usize,
            MAX_GRPC_HTTP_RESPONSE_BYTES,
        );
        let mut response_body = Vec::with_capacity(capacity);
        let mut response_mut = response;
        while let Some(chunk) = response_mut.chunk().await.map_err(|e| {
            UpstreamError::HttpError(format!("Failed to read response chunk: {}", e))
        })? {
            if response_body.len().saturating_add(chunk.len()) > MAX_GRPC_HTTP_RESPONSE_BYTES {
                return Err(UpstreamError::HttpError(format!(
                    "response body too large: >{} bytes (max {})",
                    MAX_GRPC_HTTP_RESPONSE_BYTES, MAX_GRPC_HTTP_RESPONSE_BYTES
                )));
            }
            response_body.extend_from_slice(&chunk);
        }
        let response_bytes = bytes::Bytes::from(response_body);

        if !status.is_success() {
            // Try to parse error body as JSON, fall back to status code
            if let Ok(json_val) = serde_json::from_slice::<Value>(&response_bytes) {
                return Ok(json_val);
            }
            return Err(UpstreamError::HttpError(format!(
                "Upstream returned HTTP {}",
                status
            )));
        }

        serde_json::from_slice(&response_bytes).map_err(|e| {
            UpstreamError::JsonError(format!("Failed to parse upstream response: {}", e))
        })
    }
}
