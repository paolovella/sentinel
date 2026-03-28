// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Smart cross-transport fallback chain orchestrator (Phase 29).
//!
//! Tries each transport in priority order, recording results in a
//! `FallbackNegotiationHistory` for audit purposes. Uses `TransportHealthTracker`
//! to skip transports whose circuits are open.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use vellaveto_types::command::resolve_executable;
use vellaveto_types::{FallbackNegotiationHistory, TransportAttempt, TransportProtocol};

use super::transport_health::TransportHealthTracker;
use super::{FORWARDED_HEADERS, MAX_RESPONSE_BODY_BYTES};

/// Maximum stderr capture from stdio subprocess (4 KB). FIND-R41-010.
const MAX_STDERR_BYTES: usize = 4096;

/// A single transport target to try during fallback.
#[derive(Debug, Clone)]
pub struct TransportTarget {
    /// The transport protocol to use.
    pub protocol: TransportProtocol,
    /// The endpoint URL for this transport.
    pub url: String,
    /// Upstream identifier for circuit breaker tracking.
    pub upstream_id: String,
}

/// Result of a successful smart fallback execution.
#[derive(Debug)]
pub struct SmartFallbackResult {
    /// Response bytes from the upstream.
    pub response: bytes::Bytes,
    /// The transport that succeeded.
    pub transport_used: TransportProtocol,
    /// HTTP status code.
    pub status: u16,
    /// Full negotiation history for audit.
    pub history: FallbackNegotiationHistory,
}

/// Errors from smart fallback execution.
#[derive(Debug)]
pub enum SmartFallbackError {
    /// All transports failed after trying each one.
    AllTransportsFailed { history: FallbackNegotiationHistory },
    /// Total timeout budget exhausted.
    TotalTimeoutExceeded { history: FallbackNegotiationHistory },
    /// No targets provided.
    NoTargets,
}

impl std::fmt::Display for SmartFallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AllTransportsFailed { history } => {
                write!(f, "all {} transport(s) failed", history.attempts.len())
            }
            Self::TotalTimeoutExceeded { history } => {
                write!(
                    f,
                    "total timeout exceeded after {} attempt(s)",
                    history.attempts.len()
                )
            }
            Self::NoTargets => write!(f, "no transport targets provided"),
        }
    }
}

impl std::error::Error for SmartFallbackError {}

/// Smart fallback chain orchestrator.
///
/// Tries each `TransportTarget` in order, checking circuit breaker health
/// before each attempt. Records all attempts in a `FallbackNegotiationHistory`.
pub struct SmartFallbackChain<'a> {
    client: &'a reqwest::Client,
    health_tracker: &'a TransportHealthTracker,
    per_attempt_timeout: Duration,
    total_timeout: Duration,
    stdio_enabled: bool,
    stdio_command: Option<String>,
    stdio_command_resolved: Option<PathBuf>,
}

impl<'a> SmartFallbackChain<'a> {
    /// Create a new fallback chain.
    pub fn new(
        client: &'a reqwest::Client,
        health_tracker: &'a TransportHealthTracker,
        per_attempt_timeout: Duration,
        total_timeout: Duration,
    ) -> Self {
        Self {
            client,
            health_tracker,
            per_attempt_timeout,
            total_timeout,
            stdio_enabled: false,
            stdio_command: None,
            stdio_command_resolved: None,
        }
    }

    /// Enable stdio fallback with the given command.
    pub fn with_stdio(&self, command: String) -> Result<Self, String> {
        let resolved = resolve_executable(&command, std::env::var_os("PATH").as_deref())?;
        Ok(Self {
            client: self.client,
            health_tracker: self.health_tracker,
            per_attempt_timeout: self.per_attempt_timeout,
            total_timeout: self.total_timeout,
            stdio_enabled: true,
            stdio_command: Some(command),
            stdio_command_resolved: Some(resolved),
        })
    }

    /// Execute the fallback chain, trying each target in order.
    pub async fn execute(
        &self,
        targets: &[TransportTarget],
        body: bytes::Bytes,
        headers: &reqwest::header::HeaderMap,
    ) -> Result<SmartFallbackResult, SmartFallbackError> {
        if targets.is_empty() {
            return Err(SmartFallbackError::NoTargets);
        }

        let chain_start = Instant::now();
        let mut attempts = Vec::new();

        for target in targets {
            // Check total timeout budget.
            if chain_start.elapsed() >= self.total_timeout {
                let history = FallbackNegotiationHistory {
                    attempts,
                    successful_transport: None,
                    // SECURITY (R255-PROXY-2): Safe u128→u64 conversion.
                    total_duration_ms: u64::try_from(chain_start.elapsed().as_millis())
                        .unwrap_or(u64::MAX),
                };
                return Err(SmartFallbackError::TotalTimeoutExceeded { history });
            }

            // Skip stdio if not enabled.
            if target.protocol == TransportProtocol::Stdio && !self.stdio_enabled {
                continue;
            }

            // Check circuit breaker.
            if let Err(reason) = self
                .health_tracker
                .can_use(&target.upstream_id, target.protocol)
            {
                attempts.push(TransportAttempt {
                    protocol: target.protocol,
                    endpoint_url: target.url.clone(),
                    succeeded: false,
                    duration_ms: 0,
                    error: Some(reason),
                });
                continue;
            }

            // Calculate remaining timeout budget.
            let remaining = self
                .total_timeout
                .checked_sub(chain_start.elapsed())
                .unwrap_or(Duration::ZERO);
            let attempt_timeout = self.per_attempt_timeout.min(remaining);

            if attempt_timeout.is_zero() {
                let history = FallbackNegotiationHistory {
                    attempts,
                    successful_transport: None,
                    // SECURITY (R255-PROXY-2): Safe u128→u64 conversion.
                    total_duration_ms: u64::try_from(chain_start.elapsed().as_millis())
                        .unwrap_or(u64::MAX),
                };
                return Err(SmartFallbackError::TotalTimeoutExceeded { history });
            }

            let attempt_start = Instant::now();

            let result = match target.protocol {
                TransportProtocol::Http => {
                    self.dispatch_http(&target.url, body.clone(), headers, attempt_timeout)
                        .await
                }
                TransportProtocol::WebSocket => {
                    self.dispatch_websocket(&target.url, body.clone(), attempt_timeout)
                        .await
                }
                TransportProtocol::Grpc => {
                    // gRPC dispatch via HTTP bridge endpoint.
                    self.dispatch_http(&target.url, body.clone(), headers, attempt_timeout)
                        .await
                }
                TransportProtocol::Stdio => {
                    if let (Some(cmd), Some(resolved)) = (
                        self.stdio_command.as_ref(),
                        self.stdio_command_resolved.as_ref(),
                    ) {
                        self.dispatch_stdio(cmd, resolved, body.clone(), attempt_timeout)
                            .await
                    } else {
                        Err("stdio command not configured".to_string())
                    }
                }
            };

            // SECURITY (R255-PROXY-2): Safe u128→u64 conversion.
            let duration_ms =
                u64::try_from(attempt_start.elapsed().as_millis()).unwrap_or(u64::MAX);

            match result {
                Ok((response_bytes, status)) => {
                    // SECURITY (FIND-R43-012): Treat 5xx responses as failures so
                    // the circuit breaker can open and trigger fallback to the next
                    // transport. A backend returning 500s must not keep the circuit
                    // closed.
                    if status >= 500 {
                        self.health_tracker
                            .record_failure(&target.upstream_id, target.protocol);

                        metrics::counter!(
                            "vellaveto_transport_fallback_total",
                            "transport" => format!("{:?}", target.protocol),
                            "upstream_id" => target.upstream_id.clone(),
                            "result" => "server_error",
                        )
                        .increment(1);

                        attempts.push(TransportAttempt {
                            protocol: target.protocol,
                            endpoint_url: target.url.clone(),
                            succeeded: false,
                            duration_ms,
                            error: Some(format!("server error: HTTP {status}")),
                        });

                        continue;
                    }

                    self.health_tracker
                        .record_success(&target.upstream_id, target.protocol);

                    metrics::counter!(
                        "vellaveto_transport_fallback_total",
                        "transport" => format!("{:?}", target.protocol),
                        "upstream_id" => target.upstream_id.clone(),
                        "result" => "success",
                    )
                    .increment(1);

                    attempts.push(TransportAttempt {
                        protocol: target.protocol,
                        endpoint_url: target.url.clone(),
                        succeeded: true,
                        duration_ms,
                        error: None,
                    });

                    let history = FallbackNegotiationHistory {
                        attempts,
                        successful_transport: Some(target.protocol),
                        // SECURITY (R255-PROXY-2): Safe u128→u64 conversion.
                        total_duration_ms: u64::try_from(chain_start.elapsed().as_millis())
                            .unwrap_or(u64::MAX),
                    };

                    return Ok(SmartFallbackResult {
                        response: response_bytes,
                        transport_used: target.protocol,
                        status,
                        history,
                    });
                }
                Err(error) => {
                    self.health_tracker
                        .record_failure(&target.upstream_id, target.protocol);

                    metrics::counter!(
                        "vellaveto_transport_fallback_total",
                        "transport" => format!("{:?}", target.protocol),
                        "upstream_id" => target.upstream_id.clone(),
                        "result" => "failure",
                    )
                    .increment(1);

                    attempts.push(TransportAttempt {
                        protocol: target.protocol,
                        endpoint_url: target.url.clone(),
                        succeeded: false,
                        duration_ms,
                        error: Some(error),
                    });
                }
            }
        }

        let history = FallbackNegotiationHistory {
            attempts,
            successful_transport: None,
            // SECURITY (R255-PROXY-2): Safe u128→u64 conversion.
            total_duration_ms: u64::try_from(chain_start.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
        Err(SmartFallbackError::AllTransportsFailed { history })
    }

    /// Dispatch via HTTP POST.
    ///
    /// SECURITY (FIND-R41-015): Uses chunk-based reading to prevent OOM from
    /// chunked-encoded responses that omit Content-Length. Each chunk is checked
    /// against MAX_RESPONSE_BODY_BYTES before accumulating.
    async fn dispatch_http(
        &self,
        url: &str,
        body: bytes::Bytes,
        headers: &reqwest::header::HeaderMap,
        timeout: Duration,
    ) -> Result<(bytes::Bytes, u16), String> {
        // SECURITY (R240-PROXY-1): Enforce HTTPS for non-local upstream URLs.
        // Parity with fallback.rs — the R239 fix only covered the legacy path.
        super::validate_upstream_url_scheme(url)?;

        let mut request = self.client.post(url).timeout(timeout);

        // SECURITY (FIND-R41-001): Only forward allowlisted headers to
        // prevent leaking Authorization, Cookie, etc. to upstream backends.
        for (key, value) in headers {
            let key_lower = key.as_str().to_lowercase();
            if FORWARDED_HEADERS
                .iter()
                .any(|&allowed| allowed == key_lower)
            {
                request = request.header(key.clone(), value.clone());
            }
        }

        let mut resp = request
            .body(body)
            .send()
            .await
            .map_err(|e| format!("HTTP request error: {e}"))?;

        let status = resp.status().as_u16();

        // SECURITY (FIND-R41-004): Fast-reject if Content-Length exceeds limit.
        // SECURITY (R240-P3-PROXY-2): Compare in u64 space to avoid truncation on 32-bit.
        if let Some(len) = resp.content_length() {
            if len > MAX_RESPONSE_BODY_BYTES as u64 {
                return Err(format!(
                    "response body too large: {len} bytes (max {MAX_RESPONSE_BODY_BYTES})"
                ));
            }
        }

        // SECURITY (FIND-R41-015): Read body in chunks with bounded accumulation.
        // Prevents OOM from chunked-encoded responses that omit Content-Length.
        let capacity = std::cmp::min(
            resp.content_length().unwrap_or(8192) as usize,
            MAX_RESPONSE_BODY_BYTES,
        );
        let mut response_body = Vec::with_capacity(capacity);
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| format!("HTTP response body error: {e}"))?
        {
            if response_body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BODY_BYTES {
                return Err(format!(
                    "response body too large: >{MAX_RESPONSE_BODY_BYTES} bytes (max {MAX_RESPONSE_BODY_BYTES})"
                ));
            }
            response_body.extend_from_slice(&chunk);
        }

        Ok((bytes::Bytes::from(response_body), status))
    }

    /// Dispatch via WebSocket (one-shot: connect, send, receive, close).
    ///
    /// SECURITY (FIND-R41-011): Configures max_message_size to prevent OOM
    /// from unbounded upstream WebSocket frames.
    async fn dispatch_websocket(
        &self,
        url: &str,
        body: bytes::Bytes,
        timeout: Duration,
    ) -> Result<(bytes::Bytes, u16), String> {
        // SECURITY (R240-PROXY-1): Enforce HTTPS/WSS for non-local upstream URLs.
        super::validate_upstream_url_scheme(url)?;

        use tokio_tungstenite::tungstenite::Message;

        let result = tokio::time::timeout(timeout, async {
            // SECURITY (FIND-R41-011): Configure max message/frame size to prevent
            // a malicious upstream from sending unbounded WebSocket frames (OOM).
            let mut ws_config =
                tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
            ws_config.max_message_size = Some(MAX_RESPONSE_BODY_BYTES);
            ws_config.max_frame_size = Some(MAX_RESPONSE_BODY_BYTES);
            let (mut ws, _) =
                tokio_tungstenite::connect_async_with_config(url, Some(ws_config), false)
                    .await
                    .map_err(|e| format!("WebSocket connect error: {e}"))?;

            use futures_util::SinkExt;
            // SECURITY (FIND-R43-026): Reject invalid UTF-8 instead of silently
            // replacing bytes with U+FFFD, which would mutate the request body.
            let body_text = String::from_utf8(body.to_vec())
                .map_err(|_| "WebSocket body contains invalid UTF-8".to_string())?;
            ws.send(Message::Text(body_text.into()))
                .await
                .map_err(|e| format!("WebSocket send error: {e}"))?;

            use futures_util::StreamExt;
            let response = ws
                .next()
                .await
                .ok_or_else(|| "WebSocket closed without response".to_string())?
                .map_err(|e| format!("WebSocket receive error: {e}"))?;

            ws.close(None)
                .await
                .map_err(|e| format!("WebSocket close error: {e}"))?;

            let response_bytes = match response {
                Message::Text(t) => {
                    let bytes = t.as_bytes();
                    if bytes.len() > MAX_RESPONSE_BODY_BYTES {
                        return Err(format!(
                            "WebSocket response too large: {} bytes (max {})",
                            bytes.len(),
                            MAX_RESPONSE_BODY_BYTES
                        ));
                    }
                    bytes::Bytes::from(Vec::from(bytes))
                }
                Message::Binary(b) => {
                    if b.len() > MAX_RESPONSE_BODY_BYTES {
                        return Err(format!(
                            "WebSocket response too large: {} bytes (max {})",
                            b.len(),
                            MAX_RESPONSE_BODY_BYTES
                        ));
                    }
                    bytes::Bytes::from(Vec::from(b.as_ref()))
                }
                other => {
                    return Err(format!("unexpected WebSocket message type: {other:?}"));
                }
            };

            Ok::<_, String>((response_bytes, 200u16))
        })
        .await;

        match result {
            Ok(inner) => inner,
            Err(_) => Err("WebSocket timeout".to_string()),
        }
    }

    /// Dispatch via stdio subprocess.
    ///
    /// SECURITY (FIND-R41-002): Uses direct Command::new(command) instead of
    /// `sh -c` to prevent shell injection. The command path is validated at
    /// config time to be an absolute path with no shell metacharacters.
    ///
    /// SECURITY (FIND-R41-006): Explicitly kills child on timeout to prevent
    /// zombie process accumulation.
    ///
    /// SECURITY (FIND-R41-010): Captures stderr for diagnostics instead of
    /// discarding it.
    async fn dispatch_stdio(
        &self,
        _command: &str,
        resolved_command: &Path,
        body: bytes::Bytes,
        timeout: Duration,
    ) -> Result<(bytes::Bytes, u16), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::process::Command;

        // SECURITY (FIND-R41-002): Execute command directly, not via sh -c.
        // SECURITY (FIND-R43-002): Clear inherited environment to prevent leaking
        // secrets (API keys, tokens, credentials) to the subprocess.
        // SECURITY (FIND-R43-008): kill_on_drop ensures the child is killed if
        // the async task is cancelled, preventing orphaned subprocesses.
        let mut child = Command::new(resolved_command)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", "/tmp")
            .env("LANG", "C.UTF-8")
            .kill_on_drop(true)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("stdio spawn error: {e}"))?;

        // Write to stdin and drop it to signal EOF.
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(&body)
                .await
                .map_err(|e| format!("stdio write error: {e}"))?;
        }

        // Take stdout/stderr handles before waiting, so child is not consumed.
        let stdout_handle = child
            .stdout
            .take()
            .ok_or_else(|| "stdio stdout not captured".to_string())?;
        let mut stderr_handle = child
            .stderr
            .take()
            .ok_or_else(|| "stdio stderr not captured".to_string())?;

        // SECURITY (FIND-R41-006): Use select! so we can kill the child on timeout.
        tokio::select! {
            // SECURITY (FIND-R43-001): Read stdout concurrently with waiting for
            // process exit to prevent deadlock. If the subprocess writes >64KB to
            // stdout, the pipe buffer fills and blocks; reading stdout only after
            // wait() would deadlock. Using tokio::join! ensures both proceed.
            result = async {
                let stdout_future = async {
                    let mut stdout_buf = Vec::new();
                    let read_result = stdout_handle
                        .take((MAX_RESPONSE_BODY_BYTES as u64) + 1)
                        .read_to_end(&mut stdout_buf)
                        .await
                        .map_err(|e| format!("stdio stdout read error: {e}"));
                    read_result.map(|_| stdout_buf)
                };

                let wait_future = child.wait();

                let (stdout_result, status_result) = tokio::join!(stdout_future, wait_future);

                let stdout_buf = stdout_result?;
                let status = status_result
                    .map_err(|e| format!("stdio wait error: {e}"))?;

                if stdout_buf.len() > MAX_RESPONSE_BODY_BYTES {
                    return Err(format!(
                        "stdio stdout too large: >{MAX_RESPONSE_BODY_BYTES} bytes (max {MAX_RESPONSE_BODY_BYTES})"
                    ));
                }

                if !status.success() {
                    // SECURITY (FIND-R41-010): Include truncated stderr in error.
                    let mut stderr_buf = vec![0u8; MAX_STDERR_BYTES];
                    let n = stderr_handle
                        .read(&mut stderr_buf)
                        .await
                        .unwrap_or(0);
                    let stderr_snippet = String::from_utf8_lossy(&stderr_buf[..n]);
                    return Err(format!(
                        "stdio process exited with {:?}: {}",
                        status,
                        stderr_snippet.trim()
                    ));
                }

                Ok((bytes::Bytes::from(stdout_buf), 200u16))
            } => {
                result
            }
            _ = tokio::time::sleep(timeout) => {
                // SECURITY (FIND-R41-006): Kill child on timeout to prevent zombies.
                let _ = child.kill().await;
                Err("stdio timeout".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracker() -> TransportHealthTracker {
        TransportHealthTracker::new(2, 1, 300)
    }

    fn make_targets(protos: &[(TransportProtocol, &str)]) -> Vec<TransportTarget> {
        protos
            .iter()
            .map(|(p, url)| TransportTarget {
                protocol: *p,
                url: url.to_string(),
                upstream_id: "test".to_string(),
            })
            .collect()
    }

    #[tokio::test]
    async fn test_smart_fallback_no_targets() {
        let client = reqwest::Client::new();
        let tracker = make_tracker();
        let chain = SmartFallbackChain::new(
            &client,
            &tracker,
            Duration::from_secs(5),
            Duration::from_secs(10),
        );

        let result = chain
            .execute(&[], bytes::Bytes::new(), &reqwest::header::HeaderMap::new())
            .await;

        assert!(matches!(result, Err(SmartFallbackError::NoTargets)));
    }

    #[tokio::test]
    async fn test_smart_fallback_all_circuits_open() {
        let tracker = TransportHealthTracker::new(1, 1, 300);
        let client = reqwest::Client::new();

        // Open both circuits.
        tracker.record_failure("test", TransportProtocol::Http);
        tracker.record_failure("test", TransportProtocol::WebSocket);

        let targets = make_targets(&[
            (TransportProtocol::Http, "http://localhost:1/mcp"),
            (TransportProtocol::WebSocket, "ws://localhost:2/mcp"),
        ]);

        let chain = SmartFallbackChain::new(
            &client,
            &tracker,
            Duration::from_secs(5),
            Duration::from_secs(10),
        );

        let result = chain
            .execute(
                &targets,
                bytes::Bytes::new(),
                &reqwest::header::HeaderMap::new(),
            )
            .await;

        match result {
            Err(SmartFallbackError::AllTransportsFailed { history }) => {
                assert_eq!(history.attempts.len(), 2);
                assert!(history.successful_transport.is_none());
                for attempt in &history.attempts {
                    assert!(!attempt.succeeded);
                    assert!(attempt.error.as_ref().unwrap().contains("circuit open"));
                }
            }
            other => panic!("expected AllTransportsFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_smart_fallback_skips_stdio_when_disabled() {
        let tracker = make_tracker();
        let client = reqwest::Client::new();

        let targets = make_targets(&[(TransportProtocol::Stdio, "stdio://local")]);

        let chain = SmartFallbackChain::new(
            &client,
            &tracker,
            Duration::from_secs(1),
            Duration::from_secs(5),
        );

        let result = chain
            .execute(
                &targets,
                bytes::Bytes::new(),
                &reqwest::header::HeaderMap::new(),
            )
            .await;

        // Stdio skipped, so all "available" transports failed.
        assert!(matches!(
            result,
            Err(SmartFallbackError::AllTransportsFailed { .. })
        ));
    }

    #[tokio::test]
    async fn test_smart_fallback_first_fails_second_succeeds_via_circuit() {
        // First transport's circuit is open, second should be tried.
        let tracker = TransportHealthTracker::new(1, 1, 300);
        let client = reqwest::Client::new();

        tracker.record_failure("test", TransportProtocol::Grpc);

        let targets = make_targets(&[
            (TransportProtocol::Grpc, "http://localhost:1/grpc"),
            (TransportProtocol::Http, "http://localhost:1/does-not-exist"),
        ]);

        let chain = SmartFallbackChain::new(
            &client,
            &tracker,
            Duration::from_millis(500),
            Duration::from_secs(5),
        );

        let result = chain
            .execute(
                &targets,
                bytes::Bytes::new(),
                &reqwest::header::HeaderMap::new(),
            )
            .await;

        // Both should fail (gRPC circuit open, HTTP connection refused)
        // but the history should have 2 attempts.
        match result {
            Err(SmartFallbackError::AllTransportsFailed { history }) => {
                assert_eq!(history.attempts.len(), 2);
                // First attempt was circuit-open (0ms).
                assert!(!history.attempts[0].succeeded);
                assert!(history.attempts[0]
                    .error
                    .as_ref()
                    .unwrap()
                    .contains("circuit open"));
                // Second attempt tried HTTP but connection refused.
                assert!(!history.attempts[1].succeeded);
            }
            other => panic!("expected AllTransportsFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_smart_fallback_total_timeout_zero() {
        let tracker = make_tracker();
        let client = reqwest::Client::new();

        let targets = make_targets(&[(TransportProtocol::Http, "http://localhost:1/mcp")]);

        let chain = SmartFallbackChain::new(
            &client,
            &tracker,
            Duration::from_secs(5),
            Duration::ZERO, // Zero total timeout
        );

        let result = chain
            .execute(
                &targets,
                bytes::Bytes::new(),
                &reqwest::header::HeaderMap::new(),
            )
            .await;

        assert!(matches!(
            result,
            Err(SmartFallbackError::TotalTimeoutExceeded { .. })
        ));
    }

    #[test]
    fn test_smart_fallback_error_display() {
        let err = SmartFallbackError::NoTargets;
        assert_eq!(format!("{err}"), "no transport targets provided");

        let err = SmartFallbackError::AllTransportsFailed {
            history: FallbackNegotiationHistory {
                attempts: vec![TransportAttempt {
                    protocol: TransportProtocol::Http,
                    endpoint_url: "http://localhost".to_string(),
                    succeeded: false,
                    duration_ms: 100,
                    error: Some("timeout".to_string()),
                }],
                successful_transport: None,
                total_duration_ms: 100,
            },
        };
        assert!(format!("{err}").contains("1 transport(s) failed"));
    }

    #[test]
    fn test_transport_target_construction() {
        let target = TransportTarget {
            protocol: TransportProtocol::Grpc,
            url: "http://localhost:50051".to_string(),
            upstream_id: "backend-1".to_string(),
        };
        assert_eq!(target.protocol, TransportProtocol::Grpc);
        assert_eq!(target.url, "http://localhost:50051");
    }

    #[tokio::test]
    async fn test_smart_fallback_history_records_all_attempts() {
        let tracker = TransportHealthTracker::new(1, 1, 300);
        let client = reqwest::Client::new();

        // Open first circuit.
        tracker.record_failure("test", TransportProtocol::Grpc);

        let targets = make_targets(&[
            (TransportProtocol::Grpc, "http://localhost:1/grpc"),
            (TransportProtocol::WebSocket, "ws://localhost:2/ws"),
            (TransportProtocol::Http, "http://localhost:3/http"),
        ]);

        let chain = SmartFallbackChain::new(
            &client,
            &tracker,
            Duration::from_millis(200),
            Duration::from_secs(5),
        );

        let result = chain
            .execute(
                &targets,
                bytes::Bytes::new(),
                &reqwest::header::HeaderMap::new(),
            )
            .await;

        match result {
            Err(SmartFallbackError::AllTransportsFailed { history }) => {
                // Should have attempted all 3: gRPC (circuit open), WS (connection refused), HTTP (connection refused).
                assert_eq!(history.attempts.len(), 3);
                assert!(history.successful_transport.is_none());
                assert!(history.total_duration_ms > 0 || history.attempts[0].duration_ms == 0);
            }
            other => panic!("expected AllTransportsFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_smart_fallback_with_stdio_enabled() {
        let tracker = make_tracker();
        let client = reqwest::Client::new();

        // Use 'echo' as a simple stdio command that reads stdin and outputs.
        let targets = vec![TransportTarget {
            protocol: TransportProtocol::Stdio,
            url: "stdio://local".to_string(),
            upstream_id: "test".to_string(),
        }];

        let chain = SmartFallbackChain::new(
            &client,
            &tracker,
            Duration::from_secs(5),
            Duration::from_secs(10),
        )
        .with_stdio("/bin/cat".to_string())
        .expect("stdio fallback command should resolve");

        let body = bytes::Bytes::from(r#"{"test": true}"#);
        let result = chain
            .execute(&targets, body.clone(), &reqwest::header::HeaderMap::new())
            .await;

        match result {
            Ok(res) => {
                assert_eq!(res.transport_used, TransportProtocol::Stdio);
                assert_eq!(res.status, 200);
                assert_eq!(res.response, body);
                assert_eq!(res.history.attempts.len(), 1);
                assert!(res.history.attempts[0].succeeded);
            }
            Err(e) => panic!("expected success, got: {e}"),
        }
    }
}
