// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! A2A protocol error types.
//!
//! Error types for A2A (Agent-to-Agent) protocol handling, following the
//! fail-closed design principle: all errors result in request denial.

use thiserror::Error;

/// Errors that can occur during A2A protocol handling.
#[derive(Debug, Error)]
pub enum A2aError {
    /// The A2A message could not be parsed or is malformed.
    #[error("Invalid A2A message: {0}")]
    InvalidMessage(String),

    /// Agent card could not be found at the expected well-known URL.
    #[error("Agent card not found at {url}")]
    AgentCardNotFound { url: String },

    /// Agent card validation failed (schema mismatch, missing fields, etc.).
    #[error("Agent card validation failed: {0}")]
    AgentCardInvalid(String),

    /// Request requires authentication that was not provided.
    #[error("Authentication required: {method}")]
    AuthenticationRequired { method: String },

    /// Provided authentication credentials were rejected.
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Requested task does not exist or has expired.
    #[error("Task not found: {task_id}")]
    TaskNotFound { task_id: String },

    /// The requested operation is not allowed on a task in its current state.
    #[error("Task operation not allowed: {operation} on task in state {state}")]
    TaskOperationNotAllowed { operation: String, state: String },

    /// The message exceeds the configured maximum size.
    #[error("Message too large: {size} bytes exceeds maximum {max} bytes")]
    MessageTooLarge { size: usize, max: usize },

    /// An error occurred while communicating with the upstream A2A server.
    #[error("Upstream error: {0}")]
    Upstream(String),

    /// The request was denied by policy evaluation.
    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    /// The request timed out waiting for a response.
    #[error("Request timeout")]
    Timeout,

    /// Injection attack detected in message content.
    #[error("Injection detected: {0}")]
    InjectionDetected(String),

    /// DLP policy violation detected in message content.
    #[error("DLP violation: {0}")]
    DlpViolation(String),

    /// Response from upstream exceeded maximum allowed size.
    #[error("Response too large: estimated {size} bytes exceeds maximum {max} bytes")]
    ResponseTooLarge { size: usize, max: usize },

    /// JSON-RPC batch requests are not allowed (security hardening).
    #[error("Batch requests are not allowed")]
    BatchNotAllowed,

    /// JSON serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// I/O error during communication.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Circuit breaker is open; upstream is unavailable.
    #[error("Circuit breaker open: upstream {upstream} is unavailable")]
    CircuitBreakerOpen { upstream: String },

    /// Shadow agent detected; request is blocked.
    #[error("Shadow agent detected: {0}")]
    ShadowAgentDetected(String),
}

impl A2aError {
    /// Returns the JSON-RPC error code for this error type.
    ///
    /// Error codes follow the JSON-RPC 2.0 specification. See
    /// [`vellaveto_types::json_rpc`] for the full list of codes.
    pub fn code(&self) -> i32 {
        use vellaveto_types::json_rpc;
        match self {
            A2aError::InvalidMessage(_) => json_rpc::INVALID_REQUEST as i32,
            A2aError::Serialization(_) => json_rpc::PARSE_ERROR as i32,
            A2aError::AuthenticationRequired { .. } => json_rpc::POLICY_DENIED as i32,
            A2aError::AuthenticationFailed(_) => json_rpc::APPROVAL_REQUIRED as i32,
            A2aError::PolicyDenied(_) => json_rpc::VALIDATION_ERROR as i32,
            A2aError::TaskNotFound { .. } => json_rpc::TASK_NOT_FOUND as i32,
            A2aError::TaskOperationNotAllowed { .. } => json_rpc::TASK_OPERATION_NOT_ALLOWED as i32,
            A2aError::MessageTooLarge { .. } => json_rpc::MESSAGE_TOO_LARGE as i32,
            A2aError::Timeout => json_rpc::TIMEOUT as i32,
            A2aError::InjectionDetected(_) => json_rpc::INJECTION_DETECTED as i32,
            A2aError::DlpViolation(_) => json_rpc::DLP_VIOLATION as i32,
            A2aError::ResponseTooLarge { .. } => json_rpc::MESSAGE_TOO_LARGE as i32,
            A2aError::BatchNotAllowed => json_rpc::BATCH_NOT_ALLOWED as i32,
            A2aError::CircuitBreakerOpen { .. } => json_rpc::CIRCUIT_BREAKER_OPEN as i32,
            A2aError::ShadowAgentDetected(_) => json_rpc::SHADOW_AGENT_DETECTED as i32,
            A2aError::AgentCardNotFound { .. } => json_rpc::AGENT_CARD_NOT_FOUND as i32,
            A2aError::AgentCardInvalid(_) => json_rpc::AGENT_CARD_INVALID as i32,
            A2aError::Upstream(_) => json_rpc::INTERNAL_ERROR as i32,
            A2aError::Io(_) => json_rpc::INTERNAL_ERROR as i32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = A2aError::InvalidMessage("missing method field".to_string());
        assert_eq!(err.to_string(), "Invalid A2A message: missing method field");

        let err = A2aError::MessageTooLarge {
            size: 20_000_000,
            max: 10_000_000,
        };
        assert!(err.to_string().contains("20000000"));
        assert!(err.to_string().contains("10000000"));
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(A2aError::InvalidMessage("".to_string()).code(), -32600);
        assert_eq!(
            A2aError::AuthenticationRequired {
                method: "bearer".to_string()
            }
            .code(),
            -32001
        );
        assert_eq!(A2aError::PolicyDenied("".to_string()).code(), -32003);
        assert_eq!(A2aError::Timeout.code(), -32007);
        assert_eq!(A2aError::BatchNotAllowed.code(), -32010);
    }

    #[test]
    fn test_error_from_serde_json() {
        let bad_json = "{ invalid json }";
        let serde_err: Result<serde_json::Value, _> = serde_json::from_str(bad_json);
        let a2a_err: A2aError = serde_err.unwrap_err().into();
        assert!(matches!(a2a_err, A2aError::Serialization(_)));
        assert_eq!(a2a_err.code(), -32700);
    }

    /// Verify JSON-RPC codes for all remaining A2aError variants not in test_error_codes.
    #[test]
    fn test_error_codes_exhaustive() {
        use vellaveto_types::json_rpc;

        assert_eq!(
            A2aError::TaskNotFound {
                task_id: "t1".to_string()
            }
            .code(),
            json_rpc::TASK_NOT_FOUND as i32
        );
        assert_eq!(
            A2aError::TaskOperationNotAllowed {
                operation: "cancel".to_string(),
                state: "completed".to_string()
            }
            .code(),
            json_rpc::TASK_OPERATION_NOT_ALLOWED as i32
        );
        assert_eq!(
            A2aError::InjectionDetected("xss".to_string()).code(),
            json_rpc::INJECTION_DETECTED as i32
        );
        assert_eq!(
            A2aError::DlpViolation("ssn found".to_string()).code(),
            json_rpc::DLP_VIOLATION as i32
        );
        assert_eq!(
            A2aError::ShadowAgentDetected("unregistered".to_string()).code(),
            json_rpc::SHADOW_AGENT_DETECTED as i32
        );
        assert_eq!(
            A2aError::MessageTooLarge { size: 100, max: 50 }.code(),
            json_rpc::MESSAGE_TOO_LARGE as i32
        );
        assert_eq!(
            A2aError::ResponseTooLarge { size: 100, max: 50 }.code(),
            json_rpc::MESSAGE_TOO_LARGE as i32
        );
        assert_eq!(
            A2aError::AgentCardNotFound {
                url: "https://a.com".to_string()
            }
            .code(),
            json_rpc::AGENT_CARD_NOT_FOUND as i32
        );
        assert_eq!(
            A2aError::AgentCardInvalid("bad".to_string()).code(),
            json_rpc::AGENT_CARD_INVALID as i32
        );
        assert_eq!(
            A2aError::CircuitBreakerOpen {
                upstream: "svc".to_string()
            }
            .code(),
            json_rpc::CIRCUIT_BREAKER_OPEN as i32
        );
        assert_eq!(
            A2aError::AuthenticationFailed("bad token".to_string()).code(),
            json_rpc::APPROVAL_REQUIRED as i32
        );
        assert_eq!(
            A2aError::Upstream("network fail".to_string()).code(),
            json_rpc::INTERNAL_ERROR as i32
        );
        let io_err = std::io::Error::other("test");
        assert_eq!(A2aError::Io(io_err).code(), json_rpc::INTERNAL_ERROR as i32);
    }

    /// Verify display strings for structured error variants.
    #[test]
    fn test_error_display_all_variants() {
        assert_eq!(
            A2aError::AgentCardNotFound {
                url: "https://x.com".to_string()
            }
            .to_string(),
            "Agent card not found at https://x.com"
        );
        assert_eq!(
            A2aError::AgentCardInvalid("missing name".to_string()).to_string(),
            "Agent card validation failed: missing name"
        );
        assert_eq!(
            A2aError::TaskNotFound {
                task_id: "abc-123".to_string()
            }
            .to_string(),
            "Task not found: abc-123"
        );
        assert_eq!(
            A2aError::TaskOperationNotAllowed {
                operation: "cancel".to_string(),
                state: "completed".to_string()
            }
            .to_string(),
            "Task operation not allowed: cancel on task in state completed"
        );
        assert_eq!(
            A2aError::ResponseTooLarge {
                size: 5000,
                max: 1000
            }
            .to_string(),
            "Response too large: estimated 5000 bytes exceeds maximum 1000 bytes"
        );
        assert_eq!(A2aError::Timeout.to_string(), "Request timeout");
        assert_eq!(
            A2aError::BatchNotAllowed.to_string(),
            "Batch requests are not allowed"
        );
        assert_eq!(
            A2aError::CircuitBreakerOpen {
                upstream: "agent-b".to_string()
            }
            .to_string(),
            "Circuit breaker open: upstream agent-b is unavailable"
        );
        assert_eq!(
            A2aError::ShadowAgentDetected("rogue".to_string()).to_string(),
            "Shadow agent detected: rogue"
        );
    }

    /// Verify From<io::Error> conversion.
    #[test]
    fn test_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let a2a_err: A2aError = io_err.into();
        assert!(matches!(a2a_err, A2aError::Io(_)));
        assert!(a2a_err.to_string().contains("refused"));
    }
}
