// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! MCP protocol handling and proxy bridge for the Vellaveto tool firewall.
//!
//! Implements the MCP 2025-11-25 specification including tool call interception,
//! injection detection (Aho-Corasick + NFKC), DLP parameter scanning (5-layer decode),
//! tool squatting defense (ETDI), capability tokens, A2A signature enforcement,
//! semantic guardrails, and NHI identity lifecycle management. The proxy bridge
//! provides bidirectional stdio/HTTP/WebSocket/gRPC/SSE transport relay with
//! policy enforcement on every message.

#[cfg(feature = "a2a")]
pub mod a2a;
pub mod accountability;
pub mod agent_message;
// Note: `capability` is the MCP protocol capability parsing module (CIMD).
// `capability_token` is the delegation token crypto operations module.

pub mod a2a_integrity;
pub mod agent_trust;
pub mod attack_sim;
pub mod auth_level;
pub mod browser_agent_defense;
pub mod capability;
pub mod capability_token;
pub mod data_flow;
pub mod did_plc;
#[cfg(feature = "discovery")]
pub mod discovery;
pub mod divergence_attack;
pub mod elicitation;
pub mod escalation_detector;
pub mod etdi;
pub mod extension_registry;
pub mod extensions;
pub mod extractor;
pub mod fips;
pub mod framing;
pub mod goal_drift;
pub mod goal_tracking;
pub mod inspection;
pub mod jailbreak_patterns;
#[cfg(test)]
mod kani_capability_differential;
#[cfg(test)]
mod kani_task_differential;
pub mod mediation;
pub mod memory_query_poisoning;
pub mod memory_security;
pub mod memory_tracking;
pub mod multimodal_indicator;
pub mod nhi;
pub mod output_anomaly;
pub mod output_contracts;
pub mod output_security;
pub mod output_validation;
#[cfg(feature = "projector")]
pub mod projector;
pub mod prompt_template_injection;
pub mod proxy;
#[cfg(feature = "rag-defense")]
pub mod rag_defense;
pub mod rag_poisoning;
pub mod red_team;
pub mod rekor;
pub mod reputation;
pub mod rug_pull;
pub mod sampling_detector;
pub mod schema_poisoning;
pub mod secret_substitution;
pub mod security_context_mint;
#[cfg(feature = "semantic-detection")]
pub mod semantic_detection;
#[cfg(feature = "semantic-guardrails")]
pub mod semantic_guardrails;
pub mod server_fingerprint;
pub mod session_guard;
pub mod shadow_agent;
pub mod shadow_ai_discovery;
pub mod slopsquatting;
pub mod system_prompt_leak;
pub mod task_security;
pub mod task_state;
pub mod token_leakage;
pub mod token_security;
pub mod tool_description_audit;
pub mod tool_namespace;
pub mod tool_quota;
pub mod tool_registry;
pub mod transparency;
pub(crate) mod util;
pub(crate) mod verified_bridge_principal;
pub(crate) mod verified_capability_attenuation;
pub(crate) mod verified_capability_coverage;
pub(crate) mod verified_capability_domain;
pub(crate) mod verified_capability_glob;
pub(crate) mod verified_capability_glob_subset;
pub(crate) mod verified_capability_grant;
pub(crate) mod verified_capability_identity;
pub(crate) mod verified_capability_literal;
pub(crate) mod verified_capability_path;
pub(crate) mod verified_capability_pattern;
pub(crate) mod verified_capability_selection;
pub(crate) mod verified_capability_verification;
pub(crate) mod verified_delegation_projection;
pub(crate) mod verified_deputy_handoff;
pub(crate) mod verified_evaluation_context_projection;
pub(crate) mod verified_nhi_delegation;
pub(crate) mod verified_nhi_graph;
pub(crate) mod verified_transitive_revoke;
pub(crate) mod verified_warm_restart;
pub mod wire;
pub mod workflow_tracker;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, ValidationError};

#[derive(Error, Debug)]
pub enum McpError {
    #[error("Invalid request format: {0}")]
    InvalidRequest(String),
    #[error("Method not found: {0}")]
    MethodNotFound(String),
    #[error("Engine error: {0}")]
    Engine(#[from] vellaveto_engine::EngineError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Request too large: {0} bytes")]
    RequestTooLarge(usize),
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),
}

/// Maximum length for McpRequest.id to prevent unbounded allocation.
/// SECURITY (FIND-R55-MCP-010): Reject requests with IDs longer than this.
pub const MAX_REQUEST_ID_LENGTH: usize = 256;

// SECURITY (FIND-R55-MCP-001): deny_unknown_fields prevents attacker-injected
// fields from being silently accepted in deserialized MCP protocol messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpRequest {
    /// JSON-RPC protocol version (optional for backward compatibility).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jsonrpc: Option<String>,
    pub id: String,
    pub method: String,
    pub params: serde_json::Value,
}

// SECURITY (FIND-R55-MCP-001): deny_unknown_fields on MCP protocol messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpResponse {
    /// JSON-RPC protocol version (optional for backward compatibility).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jsonrpc: Option<String>,
    pub id: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<McpErrorResponse>,
}

// SECURITY (FIND-R55-MCP-001): deny_unknown_fields on MCP protocol messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpErrorResponse {
    pub code: i32,
    pub message: String,
}

/// MCP JSON-RPC server that evaluates tool-call actions against a policy engine.
///
/// Provides `evaluate_action`, `add_policy`, `list_policies`, and `remove_policy`
/// methods over a JSON-RPC transport. Policies are compiled on mutation using
/// the compile-first pattern to maintain engine consistency.
pub struct McpServer {
    /// The policy evaluation engine, behind RwLock so it can be recompiled
    /// when policies change at runtime.
    // SECURITY (R13-LEG-5): Without recompilation, the engine has empty
    // compiled_policies and silently falls back to the legacy path, which
    // bypasses path_rules, network_rules, and context_conditions.
    engine: RwLock<PolicyEngine>,
    /// Currently loaded policies that the engine evaluates against.
    policies: RwLock<Vec<Policy>>,
    /// Maximum allowed request body size in bytes (default: 1MB).
    max_request_size: usize,
    /// When true, unknown tools are denied by default (fail-closed).
    strict_mode: bool,
    /// Custom path decode iteration limit (None = default 20).
    max_path_decode_iterations: Option<u32>,
}

impl McpServer {
    pub fn new(strict_mode: bool) -> Self {
        Self {
            engine: RwLock::new(PolicyEngine::new(strict_mode)),
            policies: RwLock::new(Vec::new()),
            max_request_size: 1_000_000, // 1MB limit
            strict_mode,
            max_path_decode_iterations: None,
        }
    }

    /// Set the maximum percent-decoding iterations for path normalization.
    pub fn set_max_path_decode_iterations(&mut self, max: u32) {
        self.max_path_decode_iterations = Some(max);
    }

    /// Parse and dispatch a JSON-RPC request string, returning a JSON-RPC response string.
    ///
    /// Enforces maximum request size and request ID length before dispatching
    /// to the appropriate handler method.
    pub async fn handle_request(&self, request_data: &str) -> Result<String, McpError> {
        // Size protection
        if request_data.len() > self.max_request_size {
            return Err(McpError::RequestTooLarge(request_data.len()));
        }

        let request: McpRequest = serde_json::from_str(request_data)?;

        // SECURITY (FIND-R55-MCP-010): Reject requests with unbounded IDs to
        // prevent memory exhaustion and log injection via oversized request IDs.
        if request.id.len() > MAX_REQUEST_ID_LENGTH {
            return Err(McpError::InvalidRequest(format!(
                "Request ID exceeds maximum length of {MAX_REQUEST_ID_LENGTH} bytes"
            )));
        }

        let response = self.process_request(request).await;
        Ok(serde_json::to_string(&response)?)
    }

    /// Route an MCP request to the appropriate handler and wrap the result as a response.
    async fn process_request(&self, request: McpRequest) -> McpResponse {
        let result = match request.method.as_str() {
            "evaluate_action" => self.handle_evaluate_action(request.params).await,
            "add_policy" => self.handle_add_policy(request.params).await,
            "list_policies" => self.handle_list_policies().await,
            "remove_policy" => self.handle_remove_policy(request.params).await,
            _ => Err(McpError::MethodNotFound(request.method.clone())),
        };

        match result {
            Ok(value) => McpResponse {
                jsonrpc: None,
                id: request.id,
                result: Some(value),
                error: None,
            },
            Err(e) => McpResponse {
                jsonrpc: None,
                id: request.id,
                result: None,
                error: Some(McpErrorResponse {
                    code: self.error_code(&e),
                    message: e.to_string(),
                }),
            },
        }
    }

    /// Evaluate a tool-call action against all loaded policies and return the verdict.
    async fn handle_evaluate_action(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, McpError> {
        let action: Action = serde_json::from_value(params)?;

        // SECURITY (FIND-012): Validate deserialized action to reject null bytes,
        // control characters, and oversized fields before policy evaluation.
        // Matches the validation done in vellaveto-server/src/routes.rs.
        action.validate()?;

        let policies = self.policies.read().await;
        let engine = self.engine.read().await;
        let verdict = engine.evaluate_action(&action, &policies)?;
        Ok(serde_json::to_value(verdict)?)
    }

    /// Add a policy, recompile the engine, and return success.
    async fn handle_add_policy(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, McpError> {
        let policy: Policy = serde_json::from_value(params)?;

        // SECURITY (R18-MCP-1): Compile-first pattern.
        // Build candidate policy list and try to compile BEFORE committing.
        // This prevents leaving the policy list in an inconsistent state
        // if compilation fails.
        let mut policies = self.policies.write().await;
        let mut candidate = policies.clone();
        candidate.push(policy);
        PolicyEngine::sort_policies(&mut candidate);

        // Try to compile the candidate list
        let mut new_engine = match PolicyEngine::with_policies(self.strict_mode, &candidate) {
            Ok(engine) => engine,
            Err(errors) => {
                for e in &errors {
                    tracing::warn!("Policy compilation error: {}", e);
                }
                return Err(McpError::InvalidRequest(format!(
                    "Policy compilation failed: {}",
                    errors.first().map(|e| e.to_string()).unwrap_or_default()
                )));
            }
        };

        // Compilation succeeded — commit changes
        if let Some(max_iter) = self.max_path_decode_iterations {
            new_engine.set_max_path_decode_iterations(max_iter);
        }
        *policies = candidate;
        *self.engine.write().await = new_engine;

        Ok(serde_json::Value::Bool(true))
    }

    /// Return all currently loaded policies as a JSON array.
    async fn handle_list_policies(&self) -> Result<serde_json::Value, McpError> {
        let policies = self.policies.read().await;
        Ok(serde_json::to_value(&*policies)?)
    }

    /// Remove a policy by ID, recompile the engine, and return whether a policy was removed.
    async fn handle_remove_policy(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, McpError> {
        let policy_id: String = serde_json::from_value(params)?;

        // SECURITY (R18-MCP-1): Compile-first pattern.
        // Build candidate policy list and compile BEFORE committing.
        let mut policies = self.policies.write().await;
        let initial_len = policies.len();
        let candidate: Vec<Policy> = policies
            .iter()
            .filter(|p| p.id != policy_id)
            .cloned()
            .collect();
        let changed = candidate.len() < initial_len;

        if !changed {
            return Ok(serde_json::Value::Bool(false));
        }

        // Try to compile the candidate list
        let mut new_engine = match PolicyEngine::with_policies(self.strict_mode, &candidate) {
            Ok(engine) => engine,
            Err(errors) => {
                for e in &errors {
                    tracing::warn!("Policy compilation error: {}", e);
                }
                return Err(McpError::InvalidRequest(format!(
                    "Policy compilation failed after removal: {}",
                    errors.first().map(|e| e.to_string()).unwrap_or_default()
                )));
            }
        };

        // Compilation succeeded — commit changes
        if let Some(max_iter) = self.max_path_decode_iterations {
            new_engine.set_max_path_decode_iterations(max_iter);
        }
        *policies = candidate;
        *self.engine.write().await = new_engine;

        Ok(serde_json::Value::Bool(true))
    }

    fn error_code(&self, error: &McpError) -> i32 {
        use vellaveto_types::json_rpc;
        match error {
            McpError::InvalidRequest(_) => json_rpc::INVALID_REQUEST as i32,
            McpError::MethodNotFound(_) => json_rpc::METHOD_NOT_FOUND as i32,
            McpError::Validation(_) => json_rpc::INVALID_PARAMS as i32,
            McpError::RequestTooLarge(_) => json_rpc::SERVER_ERROR as i32,
            _ => json_rpc::INTERNAL_ERROR as i32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_mcp_evaluate_action() {
        let server = McpServer::new(false);

        // Add a test policy
        let add_request = json!({
            "id": "test_add",
            "method": "add_policy",
            "params": {
                "id": "bash:*",
                "name": "Block bash",
                "policy_type": "Deny",
                "priority": 100
            }
        });

        let response = server
            .handle_request(&serde_json::to_string(&add_request).unwrap())
            .await
            .unwrap();
        assert!(response.contains("\"result\":true"));

        // Test action evaluation
        let eval_request = json!({
            "id": "test_eval",
            "method": "evaluate_action",
            "params": {
                "tool": "bash",
                "function": "execute",
                "parameters": {}
            }
        });

        let response = server
            .handle_request(&serde_json::to_string(&eval_request).unwrap())
            .await
            .unwrap();
        assert!(response.contains("Deny"));
    }

    #[tokio::test]
    async fn test_mcp_request_size_protection() {
        let server = McpServer::new(false);
        let large_request = "A".repeat(2_000_000); // 2MB request

        let result = server.handle_request(&large_request).await;
        assert!(matches!(result, Err(McpError::RequestTooLarge(_))));
    }

    #[tokio::test]
    async fn test_mcp_invalid_method() {
        let server = McpServer::new(false);
        let request = json!({
            "id": "test",
            "method": "nonexistent_method",
            "params": {}
        });

        let response = server
            .handle_request(&serde_json::to_string(&request).unwrap())
            .await
            .unwrap();
        assert!(response.contains("Method not found"));
    }
}
