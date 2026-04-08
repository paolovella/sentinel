// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Open Policy Agent (OPA) integration for external policy evaluation.
//!
//! Provides async client for querying OPA for policy decisions,
//! with caching and fail-open/fail-closed modes.
//!
//! ## Security Warning
//!
//! The `fail_open` configuration option should be used with extreme caution.
//! When enabled, OPA unavailability results in ALLOW decisions, violating
//! the fail-closed security principle. See [`OpaClient::log_security_warnings`].

use lru::LruCache;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock, RwLock as StdRwLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use vellaveto_config::OpaConfig;

/// Fallback cache size for OPA decisions if configured size is zero.
const FALLBACK_CACHE_SIZE: usize = 1000;

/// Maximum serialized size for OPA input context JSON (1 MB).
const MAX_OPA_CONTEXT_SIZE: usize = 1_048_576;

/// SECURITY (FIND-R70-002): Maximum TTL for OPA cache (7 days) to prevent
/// `Instant::now() + Duration` overflow panic on extreme config values.
const MAX_OPA_CACHE_TTL_SECS: u64 = 7 * 24 * 3600;

/// Errors that can occur during OPA evaluation.
#[derive(Debug, Error)]
pub enum OpaError {
    #[error("OPA request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("OPA returned invalid response: {0}")]
    InvalidResponse(String),

    #[error("OPA endpoint not configured")]
    NotConfigured,

    #[error("OPA evaluation timed out after {0}ms")]
    Timeout(u64),

    #[error("OPA decision path not found: {0}")]
    DecisionNotFound(String),

    #[error("OPA endpoint must use https:// when require_https=true: {0}")]
    InsecureEndpoint(String),

    #[error("OPA context too large ({0} bytes, max {1})")]
    ContextTooLarge(usize, usize),

    #[error("OPA input validation failed: {0}")]
    ValidationFailed(String),
}

/// Cached OPA decision with TTL.
#[derive(Debug, Clone)]
struct CachedDecision {
    decision: OpaDecision,
    expires_at: Instant,
}

/// OPA policy decision result.
// SECURITY (R239-SRV-9): Reject unknown fields — OPA decision shape is well-defined.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaDecision {
    /// Whether the action is allowed.
    pub allow: bool,
    /// Optional reason for denial.
    #[serde(default)]
    pub reason: Option<String>,
    /// Additional metadata from OPA.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Input sent to OPA for evaluation.
#[derive(Debug, Serialize)]
pub struct OpaInput {
    /// The tool being called.
    pub tool: String,
    /// The function/action being performed.
    pub function: String,
    /// Parameters of the action.
    pub parameters: serde_json::Value,
    /// Principal (user/agent) making the request.
    pub principal: Option<String>,
    /// Session ID.
    pub session_id: Option<String>,
    /// Additional context.
    #[serde(flatten)]
    pub context: serde_json::Value,
}

impl OpaInput {
    /// Validate the OPA input, checking that the context JSON does not exceed
    /// the maximum allowed size.
    ///
    /// SECURITY: Unbounded context JSON can cause OOM or excessive network
    /// traffic to the OPA sidecar. This enforces a 1 MB cap on the serialized
    /// context payload.
    pub fn validate(&self) -> Result<(), OpaError> {
        // SECURITY (R239-SRV-2): Validate string fields for dangerous chars before
        // sending to OPA. These come from the evaluate request and are included in
        // the cache key — control chars could smuggle past key comparisons.
        if vellaveto_types::has_dangerous_chars(&self.tool) {
            return Err(OpaError::ValidationFailed(
                "tool contains control or format characters".to_string(),
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.function) {
            return Err(OpaError::ValidationFailed(
                "function contains control or format characters".to_string(),
            ));
        }
        if let Some(ref p) = self.principal {
            if vellaveto_types::has_dangerous_chars(p) {
                return Err(OpaError::ValidationFailed(
                    "principal contains control or format characters".to_string(),
                ));
            }
        }
        if let Some(ref s) = self.session_id {
            if vellaveto_types::has_dangerous_chars(s) {
                return Err(OpaError::ValidationFailed(
                    "session_id contains control or format characters".to_string(),
                ));
            }
        }
        let context_size = serde_json::to_string(&self.context)
            .map_err(|e| OpaError::ValidationFailed(format!("context serialization failed: {e}")))?
            .len();
        if context_size > MAX_OPA_CONTEXT_SIZE {
            return Err(OpaError::ContextTooLarge(
                context_size,
                MAX_OPA_CONTEXT_SIZE,
            ));
        }
        Ok(())
    }
}

/// OPA response wrapper.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpaResponse {
    result: serde_json::Value,
}

/// OPA client for policy evaluation.
pub struct OpaClient {
    config: OpaConfig,
    client: Client,
    cache: Arc<RwLock<LruCache<String, CachedDecision>>>,
}

fn runtime_client_slot() -> &'static StdRwLock<Option<Arc<OpaClient>>> {
    static SLOT: OnceLock<StdRwLock<Option<Arc<OpaClient>>>> = OnceLock::new();
    SLOT.get_or_init(|| StdRwLock::new(None))
}

/// Configure the process-wide runtime OPA client from policy config.
///
/// When OPA is disabled, this clears any previously configured runtime client.
/// Returns an error if the internal lock is poisoned (fail-closed).
pub fn configure_runtime_client(config: &OpaConfig) -> Result<(), OpaError> {
    let client = OpaClient::new(config)?.map(Arc::new);
    let slot = runtime_client_slot();
    let mut guard = slot.write().map_err(|_| {
        OpaError::InvalidResponse("OPA runtime client lock poisoned — cannot configure".to_string())
    })?;
    *guard = client;
    Ok(())
}

/// Get the current process-wide runtime OPA client, if configured.
///
/// Returns `None` if the lock is poisoned (fail-closed: no OPA client
/// means the caller falls back to deny-by-default behavior).
pub fn runtime_client() -> Option<Arc<OpaClient>> {
    let slot = runtime_client_slot();
    let guard = slot.read().ok()?;
    guard.clone()
}

impl OpaClient {
    /// Create a new OPA client from configuration.
    pub fn new(config: &OpaConfig) -> Result<Option<Self>, OpaError> {
        if !config.enabled {
            return Ok(None);
        }

        if config.endpoint.is_none() {
            return Err(OpaError::NotConfigured);
        }
        if config.require_https {
            let endpoint = config.endpoint.as_deref().unwrap_or_default().trim();
            if !endpoint.starts_with("https://") {
                return Err(OpaError::InsecureEndpoint(endpoint.to_string()));
            }
        }

        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()?;

        // IMP-008: Use configurable cache size with fallback
        let configured_size = if config.cache_size > 0 {
            config.cache_size
        } else {
            FALLBACK_CACHE_SIZE
        };
        let cache_size = NonZeroUsize::new(configured_size).unwrap_or(NonZeroUsize::MIN);
        let cache = Arc::new(RwLock::new(LruCache::new(cache_size)));

        let opa_client = OpaClient {
            config: config.clone(),
            client,
            cache,
        };

        // SEC-001: Log security warnings for dangerous configurations
        opa_client.log_security_warnings();

        Ok(Some(opa_client))
    }

    /// Log security warnings for potentially dangerous configurations.
    ///
    /// # Security Warning (SEC-001)
    ///
    /// When `fail_open = true`, OPA unavailability causes policy decisions to
    /// default to ALLOW. This violates the fail-closed security principle and
    /// can be exploited by attackers who cause OPA service disruption.
    ///
    /// This method logs a warning at startup so operators are aware of the risk.
    pub fn log_security_warnings(&self) {
        if self.config.fail_open {
            tracing::warn!(
                target: "vellaveto::security",
                "SECURITY WARNING: OPA fail_open=true is configured. \
                 Policy decisions will default to ALLOW when OPA is unreachable. \
                 This violates fail-closed security principles and may allow \
                 unauthorized actions during OPA outages. Consider using \
                 fail_open=false (the default) for production environments."
            );
        }

        if let Some(endpoint) = self.config.endpoint.as_deref() {
            let endpoint = endpoint.trim();
            if endpoint.starts_with("http://") && !self.config.require_https {
                tracing::warn!(
                    target: "vellaveto::security",
                    "SECURITY WARNING: OPA endpoint uses plaintext HTTP ({}). \
                     Policy input and decision traffic are unencrypted. \
                     Prefer https:// and set opa.require_https=true in production.",
                    endpoint
                );
            }

            if let Ok(parsed) = reqwest::Url::parse(endpoint) {
                let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
                let is_loopback_host = host == "localhost"
                    || host == "127.0.0.1"
                    || host == "::1"
                    || host == "0.0.0.0";
                if !is_loopback_host && self.config.headers.is_empty() {
                    tracing::warn!(
                        target: "vellaveto::security",
                        "SECURITY WARNING: OPA endpoint '{}' has no configured auth headers. \
                         Ensure OPA API authentication/authorization is enforced to prevent \
                         unauthorized policy decision requests.",
                        endpoint
                    );
                }
            }
        }
    }

    /// Evaluate a policy decision via OPA.
    pub async fn evaluate(&self, input: &OpaInput) -> Result<OpaDecision, OpaError> {
        // SECURITY: Validate input before sending to OPA.
        input.validate()?;

        let cache_key = self.cache_key(input);

        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.peek(&cache_key) {
                if cached.expires_at > Instant::now() {
                    return Ok(cached.decision.clone());
                }
            }
        }

        // Query OPA
        let decision = self.query_opa(input).await?;

        // Update cache
        if self.config.cache_ttl_secs > 0 {
            let mut cache = self.cache.write().await;
            cache.put(
                cache_key,
                CachedDecision {
                    decision: decision.clone(),
                    // SECURITY (FIND-R70-002): Cap TTL to prevent Instant overflow.
                    expires_at: Instant::now()
                        + Duration::from_secs(
                            self.config.cache_ttl_secs.min(MAX_OPA_CACHE_TTL_SECS),
                        ),
                },
            );
        }

        Ok(decision)
    }

    /// Query OPA endpoint directly with retry logic (GAP-002).
    ///
    /// Implements exponential backoff for transient failures (connection errors,
    /// timeouts, 5xx responses). Retries are configurable via `max_retries` and
    /// `retry_backoff_ms` in OpaConfig.
    async fn query_opa(&self, input: &OpaInput) -> Result<OpaDecision, OpaError> {
        let endpoint = self
            .config
            .endpoint
            .as_ref()
            .ok_or(OpaError::NotConfigured)?;

        let url = self.build_query_url(endpoint);
        let body = serde_json::json!({ "input": input });
        let headers = self.build_request_headers();

        let mut last_error: Option<OpaError> = None;
        let mut backoff_ms = self.config.retry_backoff_ms;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                tracing::debug!(
                    target: "vellaveto::opa",
                    attempt = attempt,
                    backoff_ms = backoff_ms,
                    "Retrying OPA request after backoff"
                );
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = backoff_ms.saturating_mul(2); // Exponential backoff
            }

            let result = self
                .client
                .post(&url)
                .headers(headers.clone())
                .json(&body)
                .send()
                .await;

            match result {
                Ok(response) => {
                    let status = response.status();

                    // 5xx errors are retryable
                    if status.is_server_error() {
                        last_error = Some(OpaError::InvalidResponse(format!(
                            "OPA returned status {status}"
                        )));
                        continue;
                    }

                    // 4xx errors are not retryable
                    if !status.is_success() {
                        return Err(OpaError::InvalidResponse(format!(
                            "OPA returned status {status}"
                        )));
                    }

                    // SECURITY (R241-SRV-4): Bound OPA response body before deserialization
                    // to prevent OOM from a malicious OPA sidecar filling the LRU cache.
                    let body = response.bytes().await?;
                    if body.len() > MAX_OPA_CONTEXT_SIZE {
                        return Err(OpaError::InvalidResponse(format!(
                            "OPA response too large ({} bytes, max {})",
                            body.len(),
                            MAX_OPA_CONTEXT_SIZE
                        )));
                    }
                    let opa_response: OpaResponse = serde_json::from_slice(&body)
                        .map_err(|e| OpaError::InvalidResponse(e.to_string()))?;
                    return self.parse_decision(opa_response.result);
                }
                Err(e) => {
                    // Timeouts and connection errors are retryable
                    let error = if e.is_timeout() {
                        OpaError::Timeout(self.config.timeout_ms)
                    } else if e.is_connect() {
                        OpaError::Request(e)
                    } else {
                        // Other errors (e.g., invalid URL) are not retryable
                        return Err(OpaError::Request(e));
                    };
                    last_error = Some(error);
                }
            }
        }

        // All retries exhausted
        Err(last_error.unwrap_or(OpaError::NotConfigured))
    }

    /// Build the OPA query URL from endpoint config.
    ///
    /// Supports both:
    /// - base endpoint (e.g. `http://opa:8181`) + decision path
    /// - full data endpoint (e.g. `http://opa:8181/v1/data/vellaveto/allow`)
    fn build_query_url(&self, endpoint: &str) -> String {
        let endpoint = endpoint.trim_end_matches('/');
        if endpoint.contains("/v1/data/") || endpoint.ends_with("/v1/data") {
            endpoint.to_string()
        } else {
            let decision_path = self.config.decision_path.trim_start_matches('/');
            format!("{endpoint}/v1/data/{decision_path}")
        }
    }

    /// Build HTTP headers for OPA requests from config.
    ///
    /// Invalid header names/values are skipped with a warning.
    fn build_request_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in &self.config.headers {
            let parsed_name = match HeaderName::from_bytes(name.as_bytes()) {
                Ok(n) => n,
                Err(_) => {
                    tracing::warn!("Skipping invalid OPA header name: '{}'", name);
                    continue;
                }
            };
            let parsed_value = match HeaderValue::from_str(value) {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!("Skipping invalid OPA header value for '{}'", name);
                    continue;
                }
            };
            headers.insert(parsed_name, parsed_value);
        }
        headers
    }

    /// Parse OPA result into a decision.
    fn parse_decision(&self, result: serde_json::Value) -> Result<OpaDecision, OpaError> {
        // Handle both boolean results and structured results
        match result {
            serde_json::Value::Bool(allow) => Ok(OpaDecision {
                allow,
                reason: None,
                metadata: serde_json::Value::Null,
            }),
            serde_json::Value::Object(obj) => {
                let allow = obj.get("allow").and_then(|v| v.as_bool()).unwrap_or(false);
                let reason = obj.get("reason").and_then(|v| v.as_str()).map(String::from);
                Ok(OpaDecision {
                    allow,
                    reason,
                    metadata: serde_json::Value::Object(obj),
                })
            }
            serde_json::Value::Null => {
                // Decision path not found
                Err(OpaError::DecisionNotFound(
                    self.config.decision_path.clone(),
                ))
            }
            _ => Err(OpaError::InvalidResponse(
                "Unexpected result type from OPA".to_string(),
            )),
        }
    }

    /// Generate cache key for an input.
    ///
    /// Includes request parameters and context to prevent cross-request cache
    /// reuse where one allowed decision could be replayed for different inputs.
    fn cache_key(&self, input: &OpaInput) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.tool.as_bytes());
        hasher.update([0x1f]);
        hasher.update(input.function.as_bytes());
        hasher.update([0x1f]);
        hasher.update(input.principal.as_deref().unwrap_or("").as_bytes());
        hasher.update([0x1f]);
        hasher.update(input.session_id.as_deref().unwrap_or("").as_bytes());
        hasher.update([0x1f]);

        match serde_json::to_vec(&input.parameters) {
            Ok(bytes) => hasher.update(&bytes),
            Err(_) => hasher.update(b"<serde-json-error:parameters>"),
        }
        hasher.update([0x1f]);

        match serde_json::to_vec(&input.context) {
            Ok(bytes) => hasher.update(&bytes),
            Err(_) => hasher.update(b"<serde-json-error:context>"),
        }

        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Check if fail-open mode is enabled.
    pub fn fail_open(&self) -> bool {
        self.config.fail_open
    }

    /// Clear the decision cache.
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opa_client_disabled() {
        let config = OpaConfig {
            enabled: false,
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap();
        assert!(client.is_none());
    }

    #[test]
    fn test_opa_client_no_endpoint() {
        let config = OpaConfig {
            enabled: true,
            endpoint: None,
            ..Default::default()
        };
        let result = OpaClient::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_opa_client_require_https_rejects_http_endpoint() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            require_https: true,
            ..Default::default()
        };
        let result = OpaClient::new(&config);
        assert!(matches!(result, Err(OpaError::InsecureEndpoint(_))));
    }

    #[test]
    fn test_opa_client_require_https_accepts_https_endpoint() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("https://opa.example.com/v1/data/vellaveto/allow".to_string()),
            require_https: true,
            ..Default::default()
        };
        let result = OpaClient::new(&config);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_parse_decision_bool() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "vellaveto/allow".to_string(),
            require_https: false, // Allow HTTP for localhost testing
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap().unwrap();

        let decision = client
            .parse_decision(serde_json::Value::Bool(true))
            .unwrap();
        assert!(decision.allow);
        assert!(decision.reason.is_none());
    }

    #[test]
    fn test_parse_decision_object() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "vellaveto/allow".to_string(),
            require_https: false, // Allow HTTP for localhost testing
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap().unwrap();

        let result = serde_json::json!({
            "allow": false,
            "reason": "Policy violation"
        });
        let decision = client.parse_decision(result).unwrap();
        assert!(!decision.allow);
        assert_eq!(decision.reason, Some("Policy violation".to_string()));
    }

    #[test]
    fn test_parse_decision_null() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "vellaveto/allow".to_string(),
            require_https: false, // Allow HTTP for localhost testing
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap().unwrap();

        let result = client.parse_decision(serde_json::Value::Null);
        assert!(result.is_err());
    }

    #[test]
    fn test_opa_response_deny_unknown_fields() {
        let result: Result<OpaResponse, _> =
            serde_json::from_str(r#"{"result":true,"unexpected":1}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_cache_key_is_stable_and_input_sensitive() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "vellaveto/allow".to_string(),
            require_https: false, // Allow HTTP for localhost testing
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap().unwrap();

        let input = OpaInput {
            tool: "filesystem".to_string(),
            function: "read".to_string(),
            parameters: serde_json::json!({"path": "/tmp/file.txt"}),
            principal: Some("user1".to_string()),
            session_id: Some("sess123".to_string()),
            context: serde_json::json!({"tenant": "acme"}),
        };
        let key1 = client.cache_key(&input);
        let key2 = client.cache_key(&input);
        assert_eq!(key1, key2, "cache key must be deterministic");

        let changed_params = OpaInput {
            parameters: serde_json::json!({"path": "/etc/shadow"}),
            ..input
        };
        let key3 = client.cache_key(&changed_params);
        assert_ne!(key1, key3, "cache key must change when parameters change");
    }

    #[test]
    fn test_build_request_headers_filters_invalid_entries() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("x-api-key".to_string(), "secret".to_string());
        headers.insert("bad header".to_string(), "value".to_string());
        headers.insert("x-bad-value".to_string(), "line\nbreak".to_string());

        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "vellaveto/allow".to_string(),
            require_https: false, // Allow HTTP for localhost testing
            headers,
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap().unwrap();

        let request_headers = client.build_request_headers();
        assert_eq!(
            request_headers
                .get("x-api-key")
                .and_then(|v| v.to_str().ok()),
            Some("secret")
        );
        assert!(request_headers.get("bad header").is_none());
        assert!(request_headers.get("x-bad-value").is_none());
    }

    #[test]
    fn test_build_query_url_with_base_endpoint() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "vellaveto/allow".to_string(),
            require_https: false, // Allow HTTP for localhost testing
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap().unwrap();
        assert_eq!(
            client.build_query_url("http://localhost:8181"),
            "http://localhost:8181/v1/data/vellaveto/allow"
        );
    }

    #[test]
    fn test_build_query_url_with_full_data_endpoint() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://opa:8181/v1/data/vellaveto/allow".to_string()),
            decision_path: "result.allow".to_string(),
            require_https: false, // Allow HTTP for localhost/internal testing
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap().unwrap();
        assert_eq!(
            client.build_query_url("http://opa:8181/v1/data/vellaveto/allow"),
            "http://opa:8181/v1/data/vellaveto/allow"
        );
    }

    #[test]
    fn test_retry_config_defaults() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "vellaveto/allow".to_string(),
            ..Default::default()
        };

        // Verify default retry settings
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_backoff_ms, 50);
    }

    #[test]
    fn test_retry_config_custom() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "vellaveto/allow".to_string(),
            max_retries: 5,
            retry_backoff_ms: 100,
            ..Default::default()
        };

        assert_eq!(config.max_retries, 5);
        assert_eq!(config.retry_backoff_ms, 100);
    }

    #[test]
    fn test_retry_disabled() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "vellaveto/allow".to_string(),
            max_retries: 0,
            ..Default::default()
        };

        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn test_cache_size_default() {
        let config = OpaConfig::default();
        assert_eq!(config.cache_size, 1000);
    }

    #[test]
    fn test_cache_size_custom() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "vellaveto/allow".to_string(),
            cache_size: 5000,
            ..Default::default()
        };

        assert_eq!(config.cache_size, 5000);
    }

    #[test]
    fn test_opa_input_validate_small_context() {
        let input = OpaInput {
            tool: "filesystem".to_string(),
            function: "read".to_string(),
            parameters: serde_json::json!({}),
            principal: None,
            session_id: None,
            context: serde_json::json!({"tenant": "acme"}),
        };
        assert!(input.validate().is_ok());
    }

    #[test]
    fn test_opa_input_validate_context_too_large() {
        let large_string = "x".repeat(MAX_OPA_CONTEXT_SIZE + 1);
        let input = OpaInput {
            tool: "filesystem".to_string(),
            function: "read".to_string(),
            parameters: serde_json::json!({}),
            principal: None,
            session_id: None,
            context: serde_json::json!({"payload": large_string}),
        };
        let result = input.validate();
        assert!(result.is_err());
        match result {
            Err(OpaError::ContextTooLarge(size, max)) => {
                assert!(size > MAX_OPA_CONTEXT_SIZE);
                assert_eq!(max, MAX_OPA_CONTEXT_SIZE);
            }
            other => panic!("expected ContextTooLarge, got: {other:?}"),
        }
    }

    #[test]
    fn test_opa_input_validate_null_context() {
        let input = OpaInput {
            tool: "t".to_string(),
            function: "f".to_string(),
            parameters: serde_json::json!({}),
            principal: None,
            session_id: None,
            context: serde_json::Value::Null,
        };
        assert!(input.validate().is_ok());
    }

    // ── R239-SRV-2: OpaInput dangerous char validation tests ──────

    #[test]
    fn test_opa_input_validate_rejects_control_chars_in_tool() {
        let input = OpaInput {
            tool: "bash\x00".to_string(),
            function: "run".to_string(),
            parameters: serde_json::json!({}),
            principal: None,
            session_id: None,
            context: serde_json::Value::Null,
        };
        let err = input.validate().unwrap_err();
        assert!(err.to_string().contains("tool"));
    }

    #[test]
    fn test_opa_input_validate_rejects_control_chars_in_function() {
        let input = OpaInput {
            tool: "bash".to_string(),
            function: "run\n".to_string(),
            parameters: serde_json::json!({}),
            principal: None,
            session_id: None,
            context: serde_json::Value::Null,
        };
        let err = input.validate().unwrap_err();
        assert!(err.to_string().contains("function"));
    }

    #[test]
    fn test_opa_input_validate_rejects_control_chars_in_principal() {
        let input = OpaInput {
            tool: "bash".to_string(),
            function: "run".to_string(),
            parameters: serde_json::json!({}),
            principal: Some("admin\x7f".to_string()),
            session_id: None,
            context: serde_json::Value::Null,
        };
        let err = input.validate().unwrap_err();
        assert!(err.to_string().contains("principal"));
    }

    #[test]
    fn test_opa_input_validate_rejects_control_chars_in_session_id() {
        let input = OpaInput {
            tool: "bash".to_string(),
            function: "run".to_string(),
            parameters: serde_json::json!({}),
            principal: None,
            session_id: Some("sess\u{200B}ion".to_string()),
            context: serde_json::Value::Null,
        };
        let err = input.validate().unwrap_err();
        assert!(err.to_string().contains("session_id"));
    }

    #[test]
    fn test_opa_input_validate_accepts_clean_input() {
        let input = OpaInput {
            tool: "file_read".to_string(),
            function: "read".to_string(),
            parameters: serde_json::json!({"path": "/tmp/test"}),
            principal: Some("agent-1".to_string()),
            session_id: Some("sess-abc-123".to_string()),
            context: serde_json::json!({"source": "test"}),
        };
        assert!(input.validate().is_ok());
    }
}
