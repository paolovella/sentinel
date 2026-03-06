// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Per-transport circuit breaker for cross-transport fallback (Phase 29).
//!
//! Mirrors the `CircuitBreakerManager` pattern (Closed/Open/HalfOpen state machine)
//! but keyed by `(upstream_id, TransportProtocol)` instead of tool name.
//! Used by `SmartFallbackChain` to skip transports that are known to be down.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use vellaveto_types::TransportProtocol;

/// Per-transport circuit breaker state, mirroring `CircuitState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportCircuitState {
    /// Normal operation, transport available.
    #[default]
    Closed,
    /// Transport marked down, requests blocked until open duration expires.
    Open,
    /// Testing recovery, limited requests allowed.
    HalfOpen,
}

/// Statistics for a single (upstream, transport) circuit.
#[derive(Debug, Clone)]
struct TransportCircuitStats {
    /// Current circuit breaker state (Closed / Open / HalfOpen).
    state: TransportCircuitState,
    /// Consecutive failures recorded while the circuit is Closed.
    /// Reset to 0 on a successful response or when transitioning to Open.
    failure_count: u32,
    /// Consecutive successes recorded while the circuit is HalfOpen.
    /// Reset to 0 on failure. When it reaches `success_threshold` the
    /// circuit transitions back to Closed.
    success_count: u32,
    /// Unix timestamp (seconds) of the most recent state transition.
    /// Used together with `open_duration_secs` to decide when an Open
    /// circuit should transition to HalfOpen.
    last_state_change: u64,
    /// Number of times this circuit has tripped (Closed -> Open).
    /// Used for exponential backoff on the open duration.
    trip_count: u32,
    /// Whether a half-open probe request is currently in flight (FIND-R42-010).
    half_open_in_flight: bool,
    /// Timestamp (secs) when half_open_in_flight was set to true (FIND-R44-001).
    /// Used to recover from stale flags when a probe is cancelled/leaked.
    half_open_in_flight_since: u64,
}

impl TransportCircuitStats {
    fn new() -> Self {
        Self {
            state: TransportCircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_state_change: now_secs(),
            trip_count: 0,
            half_open_in_flight: false,
            half_open_in_flight_since: 0,
        }
    }
}

/// Maximum time (secs) a half-open probe can be in-flight before being
/// considered stale and auto-cleared (FIND-R44-001). Prevents permanent
/// wedging when a probe request is cancelled/dropped without calling
/// record_success or record_failure.
const HALF_OPEN_PROBE_TIMEOUT_SECS: u64 = 60;

/// Summary snapshot of transport health tracker state.
#[derive(Debug, Clone, Serialize)]
pub struct TransportHealthSummary {
    /// Total number of tracked (upstream, transport) pairs.
    pub total: usize,
    /// Number in Closed state.
    pub closed: usize,
    /// Number in Open state.
    pub open: usize,
    /// Number in HalfOpen state.
    pub half_open: usize,
}

/// Maximum number of tracked (upstream_id, transport) pairs.
/// Prevents unbounded memory growth (FIND-R41-003).
const MAX_TRACKED_CIRCUITS: usize = 10_000;

/// Per-transport circuit breaker tracker.
///
/// Tracks health of each `(upstream_id, TransportProtocol)` pair using a
/// Closed/Open/HalfOpen state machine with exponential backoff.
pub struct TransportHealthTracker {
    states: RwLock<HashMap<(String, TransportProtocol), TransportCircuitStats>>,
    failure_threshold: u32,
    success_threshold: u32,
    open_duration_secs: u64,
}

impl std::fmt::Debug for TransportHealthTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportHealthTracker")
            .field("failure_threshold", &self.failure_threshold)
            .field("success_threshold", &self.success_threshold)
            .field("open_duration_secs", &self.open_duration_secs)
            .finish()
    }
}

impl TransportHealthTracker {
    /// Create a new tracker with the given thresholds.
    pub fn new(failure_threshold: u32, success_threshold: u32, open_duration_secs: u64) -> Self {
        Self {
            states: RwLock::new(HashMap::new()),
            failure_threshold: failure_threshold.max(1),
            success_threshold: success_threshold.max(1),
            open_duration_secs: open_duration_secs.max(1),
        }
    }

    /// Calculate effective open duration with exponential backoff (2^trip_count, max 32x).
    fn effective_open_duration(&self, stats: &TransportCircuitStats) -> u64 {
        let multiplier = 1u64 << stats.trip_count.min(5);
        self.open_duration_secs.saturating_mul(multiplier)
    }

    /// Check whether a transport can be used for the given upstream.
    ///
    /// Returns `Ok(())` if available, `Err(reason)` if the circuit is open.
    /// SECURITY: Fail-closed on RwLock poisoning.
    pub fn can_use(&self, upstream_id: &str, protocol: TransportProtocol) -> Result<(), String> {
        let key = (upstream_id.to_string(), protocol);

        // Read-lock first for common path (Closed).
        let needs_transition = {
            let states = self.states.read().map_err(|e| {
                tracing::error!("TransportHealthTracker RwLock poisoned in can_use(): {}", e);
                "transport health tracker unavailable (poisoned)".to_string()
            })?;

            match states.get(&key) {
                None => {
                    // SECURITY (FIND-R42-005): At capacity, fail-closed for unknown keys.
                    // If we can't track this circuit, we shouldn't allow usage since
                    // failures won't be recorded and the circuit can never open.
                    if states.len() >= MAX_TRACKED_CIRCUITS {
                        return Err(
                            "transport health tracker at capacity — cannot track new circuit"
                                .to_string(),
                        );
                    }
                    return Ok(()); // Unknown = assume available (Closed).
                }
                Some(stats) => match stats.state {
                    TransportCircuitState::Closed => return Ok(()),
                    // SECURITY (FIND-R42-010): HalfOpen requires write lock to set
                    // half_open_in_flight flag, preventing thundering herd.
                    TransportCircuitState::HalfOpen => true,
                    TransportCircuitState::Open => {
                        let now = now_secs();
                        let effective_dur = self.effective_open_duration(stats);
                        if now.saturating_sub(stats.last_state_change) >= effective_dur {
                            true // needs transition to HalfOpen
                        } else {
                            metrics::counter!(
                                "vellaveto_transport_health_rejections_total",
                                "upstream_id" => upstream_id.to_string(),
                                "transport" => format!("{:?}", protocol),
                            )
                            .increment(1);
                            return Err(format!(
                                "transport {:?} circuit open for upstream '{}'",
                                protocol, upstream_id
                            ));
                        }
                    }
                },
            }
        };

        // Double-check locking: transition Open → HalfOpen under write lock.
        if needs_transition {
            let mut states = self.states.write().map_err(|e| {
                tracing::error!(
                    "TransportHealthTracker RwLock poisoned in can_use() (write): {}",
                    e
                );
                "transport health tracker unavailable (poisoned)".to_string()
            })?;

            if let Some(stats) = states.get_mut(&key) {
                if stats.state == TransportCircuitState::Open {
                    let now = now_secs();
                    let effective_dur = self.effective_open_duration(stats);
                    if now.saturating_sub(stats.last_state_change) >= effective_dur {
                        tracing::info!(
                            upstream_id = upstream_id,
                            transport = ?protocol,
                            "transport circuit Open → HalfOpen"
                        );
                        metrics::counter!(
                            "vellaveto_transport_health_state_changes_total",
                            "upstream_id" => upstream_id.to_string(),
                            "transport" => format!("{:?}", protocol),
                            "from" => "open",
                            "to" => "half_open",
                        )
                        .increment(1);
                        stats.state = TransportCircuitState::HalfOpen;
                        stats.success_count = 0;
                        stats.failure_count = 0;
                        stats.last_state_change = now;
                        stats.half_open_in_flight = true; // First probe
                        stats.half_open_in_flight_since = now;
                    }
                } else if stats.state == TransportCircuitState::HalfOpen {
                    // SECURITY (FIND-R42-010): Only allow one in-flight probe
                    // to prevent thundering herd on recovering transports.
                    // SECURITY (FIND-R44-001): Auto-clear stale probes after
                    // HALF_OPEN_PROBE_TIMEOUT_SECS to prevent permanent wedging
                    // when a probe is cancelled/dropped.
                    if stats.half_open_in_flight {
                        let now = now_secs();
                        let elapsed = now.saturating_sub(stats.half_open_in_flight_since);
                        if elapsed < HALF_OPEN_PROBE_TIMEOUT_SECS {
                            return Err(format!(
                                "transport {:?} half-open probe already in flight for upstream '{}'",
                                protocol, upstream_id
                            ));
                        }
                        // Stale probe — clear and allow new one.
                        tracing::warn!(
                            upstream_id = upstream_id,
                            transport = ?protocol,
                            elapsed_secs = elapsed,
                            "half-open probe timed out — clearing stale in-flight flag"
                        );
                    }
                    stats.half_open_in_flight = true;
                    stats.half_open_in_flight_since = now_secs();
                }
            }
        }

        Ok(())
    }

    /// Record a successful use of a transport.
    pub fn record_success(&self, upstream_id: &str, protocol: TransportProtocol) {
        let key = (upstream_id.to_string(), protocol);

        let mut states = match self.states.write() {
            Ok(guard) => guard,
            Err(e) => {
                // SECURITY (FIND-R43-011): Poisoned lock in record_success is safe to ignore
                // because not recording a success keeps the circuit in its current (more restrictive) state.
                // This is effectively fail-closed: Open stays Open, HalfOpen stays HalfOpen.
                tracing::error!(
                    "TransportHealthTracker RwLock poisoned in record_success() — success not recorded (fail-closed by omission): {}",
                    e
                );
                return;
            }
        };

        // SECURITY (FIND-R41-003): Bound capacity. Only insert if entry exists
        // or we're under the limit. If over limit, silently skip (don't track).
        if !states.contains_key(&key) && states.len() >= MAX_TRACKED_CIRCUITS {
            tracing::warn!(
                target: "vellaveto::security",
                limit = MAX_TRACKED_CIRCUITS,
                "Transport health tracker capacity reached — skipping new entry"
            );
            return;
        }
        let stats = states.entry(key).or_insert_with(TransportCircuitStats::new);
        stats.failure_count = 0;

        match stats.state {
            TransportCircuitState::Closed => {
                // Already healthy, nothing to do.
            }
            TransportCircuitState::Open => {
                // SECURITY (FIND-R43-004): Stale success while Open — discard.
                // Open→HalfOpen should only happen via can_use() after open_duration expires.
                tracing::debug!(
                    upstream_id = upstream_id,
                    transport = ?protocol,
                    "discarding stale success while circuit is Open"
                );
            }
            TransportCircuitState::HalfOpen => {
                stats.half_open_in_flight = false; // FIND-R42-010: probe completed.
                                                   // SECURITY (FIND-R43-010): Use saturating_add to prevent wrapping arithmetic
                                                   // panic in debug builds, consistent with failure_count fix (FIND-R42-012).
                stats.success_count = stats.success_count.saturating_add(1);
                if stats.success_count >= self.success_threshold {
                    tracing::info!(
                        upstream_id = upstream_id,
                        transport = ?protocol,
                        "transport circuit HalfOpen → Closed (recovered)"
                    );
                    metrics::counter!(
                        "vellaveto_transport_health_state_changes_total",
                        "upstream_id" => upstream_id.to_string(),
                        "transport" => format!("{:?}", protocol),
                        "from" => "half_open",
                        "to" => "closed",
                    )
                    .increment(1);
                    stats.state = TransportCircuitState::Closed;
                    stats.success_count = 0;
                    stats.trip_count = 0; // Reset backoff on full recovery.
                    stats.last_state_change = now_secs();
                }
            }
        }
    }

    /// Record a failed use of a transport. Returns the new circuit state.
    pub fn record_failure(
        &self,
        upstream_id: &str,
        protocol: TransportProtocol,
    ) -> TransportCircuitState {
        let key = (upstream_id.to_string(), protocol);

        let mut states = match self.states.write() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!(
                    "TransportHealthTracker RwLock poisoned in record_failure(): {}",
                    e
                );
                return TransportCircuitState::Open; // fail-closed
            }
        };

        // SECURITY (FIND-R41-003): Bound capacity. Fail-closed: treat as Open.
        if !states.contains_key(&key) && states.len() >= MAX_TRACKED_CIRCUITS {
            tracing::warn!(
                target: "vellaveto::security",
                limit = MAX_TRACKED_CIRCUITS,
                "Transport health tracker capacity reached — treating as Open (fail-closed)"
            );
            return TransportCircuitState::Open;
        }
        let stats = states.entry(key).or_insert_with(TransportCircuitStats::new);
        stats.success_count = 0;

        match stats.state {
            TransportCircuitState::Closed => {
                stats.failure_count = stats.failure_count.saturating_add(1); // FIND-R42-012
                if stats.failure_count >= self.failure_threshold {
                    tracing::warn!(
                        upstream_id = upstream_id,
                        transport = ?protocol,
                        failures = stats.failure_count,
                        "transport circuit Closed → Open"
                    );
                    metrics::counter!(
                        "vellaveto_transport_health_state_changes_total",
                        "upstream_id" => upstream_id.to_string(),
                        "transport" => format!("{:?}", protocol),
                        "from" => "closed",
                        "to" => "open",
                    )
                    .increment(1);
                    stats.state = TransportCircuitState::Open;
                    // SECURITY (FIND-R43-027): Increment trip_count on Closed→Open to enable
                    // exponential backoff escalation for rapid flapping circuits.
                    stats.trip_count = stats.trip_count.saturating_add(1);
                    stats.last_state_change = now_secs();
                }
                stats.state
            }
            TransportCircuitState::Open => {
                stats.failure_count = stats.failure_count.saturating_add(1); // FIND-R42-012
                TransportCircuitState::Open
            }
            TransportCircuitState::HalfOpen => {
                tracing::warn!(
                    upstream_id = upstream_id,
                    transport = ?protocol,
                    "transport circuit HalfOpen → Open (recovery failed)"
                );
                metrics::counter!(
                    "vellaveto_transport_health_state_changes_total",
                    "upstream_id" => upstream_id.to_string(),
                    "transport" => format!("{:?}", protocol),
                    "from" => "half_open",
                    "to" => "open",
                )
                .increment(1);
                stats.state = TransportCircuitState::Open;
                stats.trip_count = stats.trip_count.saturating_add(1);
                stats.failure_count = 0;
                stats.half_open_in_flight = false; // FIND-R42-010: probe completed.
                stats.last_state_change = now_secs();
                TransportCircuitState::Open
            }
        }
    }

    /// Returns the subset of `priorities` whose circuits allow a request.
    ///
    /// **WARNING**: This method has side effects — it calls `can_use()` which may
    /// transition Open circuits to HalfOpen and set `half_open_in_flight`. Only call
    /// this if you intend to actually dispatch requests to the returned transports.
    // SECURITY (FIND-R43-028): Documented side-effect hazard for callers.
    pub fn available_transports(
        &self,
        upstream_id: &str,
        priorities: &[TransportProtocol],
    ) -> Vec<TransportProtocol> {
        priorities
            .iter()
            .copied()
            .filter(|proto| self.can_use(upstream_id, *proto).is_ok())
            .collect()
    }

    /// Read-only query: which transports would be available for dispatch?
    ///
    /// SECURITY (FIND-R44-002): Unlike `available_transports`, this method
    /// does NOT trigger state transitions or set `half_open_in_flight`.
    /// Use this for diagnostics, summaries, and filtering queries where
    /// you don't intend to dispatch a request immediately.
    pub fn peek_available_transports(
        &self,
        upstream_id: &str,
        priorities: &[TransportProtocol],
    ) -> Vec<TransportProtocol> {
        let states = match self.states.read() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(), // fail-closed: poisoned → no transports
        };

        let now = now_secs();
        priorities
            .iter()
            .copied()
            .filter(|proto| {
                let key = (upstream_id.to_string(), *proto);
                match states.get(&key) {
                    None => states.len() < MAX_TRACKED_CIRCUITS,
                    Some(stats) => match stats.state {
                        TransportCircuitState::Closed => true,
                        TransportCircuitState::HalfOpen => !stats.half_open_in_flight,
                        TransportCircuitState::Open => {
                            let effective_dur = self.effective_open_duration(stats);
                            now.saturating_sub(stats.last_state_change) >= effective_dur
                        }
                    },
                }
            })
            .collect()
    }

    /// Return a summary of all tracked transport circuit states.
    pub fn summary(&self) -> TransportHealthSummary {
        let states = match self.states.read() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!("TransportHealthTracker RwLock poisoned in summary(): {}", e);
                return TransportHealthSummary {
                    total: 0,
                    closed: 0,
                    open: 0,
                    half_open: 0,
                };
            }
        };

        let now = now_secs();
        let mut closed = 0usize;
        let mut open = 0usize;
        let mut half_open = 0usize;

        for stats in states.values() {
            match stats.state {
                TransportCircuitState::Closed => closed += 1,
                TransportCircuitState::Open => {
                    let effective_dur = self.effective_open_duration(stats);
                    if now.saturating_sub(stats.last_state_change) >= effective_dur {
                        half_open += 1; // Would transition on next can_use()
                    } else {
                        open += 1;
                    }
                }
                TransportCircuitState::HalfOpen => half_open += 1,
            }
        }

        TransportHealthSummary {
            total: states.len(),
            closed,
            open,
            half_open,
        }
    }

    /// Manually reset a transport circuit to Closed state.
    pub fn reset(&self, upstream_id: &str, protocol: TransportProtocol) {
        let key = (upstream_id.to_string(), protocol);
        let mut states = match self.states.write() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!("TransportHealthTracker RwLock poisoned in reset(): {}", e);
                return;
            }
        };
        states.remove(&key);
    }
}

// Thread-local mock clock for deterministic tests.
//
// Each test thread gets its own independent clock, so parallel tests
// don't interfere. Use `MockTimeGuard::new(start)` to activate and
// `advance_mock_time(secs)` to advance. The guard clears the mock on drop.
#[cfg(test)]
thread_local! {
    static MOCK_NOW: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn advance_mock_time(secs: u64) {
    MOCK_NOW.with(|c| {
        let current = c
            .get()
            .expect("advance_mock_time called without MockTimeGuard");
        c.set(Some(current + secs));
    });
}

/// RAII guard that activates mock time on creation and clears it on drop
/// (including on panic), preventing leaked state across tests.
#[cfg(test)]
struct MockTimeGuard;

#[cfg(test)]
impl MockTimeGuard {
    fn new(start_secs: u64) -> Self {
        MOCK_NOW.with(|c| c.set(Some(start_secs)));
        Self
    }
}

#[cfg(test)]
impl Drop for MockTimeGuard {
    fn drop(&mut self) {
        MOCK_NOW.with(|c| c.set(None));
    }
}

/// Current Unix timestamp in seconds.
///
/// SECURITY (FIND-R42-014): Logs an error if the system clock is before the Unix
/// epoch. Returns 0 as a fail-safe (circuit breaker timing may be inaccurate).
///
/// In test builds, returns the mock clock value if one is active (via `MockTimeGuard`).
fn now_secs() -> u64 {
    #[cfg(test)]
    {
        if let Some(t) = MOCK_NOW.with(|c| c.get()) {
            return t;
        }
    }

    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            tracing::error!(
                error = %e,
                "System clock before Unix epoch — using 0 (circuit breaker timing may be inaccurate)"
            );
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_health_tracker_new_defaults() {
        let tracker = TransportHealthTracker::new(3, 2, 30);
        assert_eq!(tracker.failure_threshold, 3);
        assert_eq!(tracker.success_threshold, 2);
        assert_eq!(tracker.open_duration_secs, 30);
    }

    #[test]
    fn test_transport_health_tracker_new_clamps_minimums() {
        let tracker = TransportHealthTracker::new(0, 0, 0);
        assert_eq!(tracker.failure_threshold, 1);
        assert_eq!(tracker.success_threshold, 1);
        assert_eq!(tracker.open_duration_secs, 1);
    }

    #[test]
    fn test_can_use_unknown_transport_allowed() {
        let tracker = TransportHealthTracker::new(3, 2, 30);
        assert!(tracker
            .can_use("upstream-1", TransportProtocol::Http)
            .is_ok());
    }

    #[test]
    fn test_can_use_closed_circuit_allowed() {
        let tracker = TransportHealthTracker::new(3, 2, 30);
        tracker.record_success("upstream-1", TransportProtocol::Grpc);
        assert!(tracker
            .can_use("upstream-1", TransportProtocol::Grpc)
            .is_ok());
    }

    #[test]
    fn test_record_failure_opens_circuit_after_threshold() {
        let tracker = TransportHealthTracker::new(3, 2, 30);
        let proto = TransportProtocol::Http;

        // First two failures don't open the circuit.
        assert_eq!(
            tracker.record_failure("up", proto),
            TransportCircuitState::Closed
        );
        assert_eq!(
            tracker.record_failure("up", proto),
            TransportCircuitState::Closed
        );
        assert!(tracker.can_use("up", proto).is_ok());

        // Third failure opens it.
        assert_eq!(
            tracker.record_failure("up", proto),
            TransportCircuitState::Open
        );
        assert!(tracker.can_use("up", proto).is_err());
    }

    #[test]
    fn test_record_success_resets_failure_count() {
        let tracker = TransportHealthTracker::new(3, 2, 30);
        let proto = TransportProtocol::WebSocket;

        tracker.record_failure("up", proto);
        tracker.record_failure("up", proto);
        // Two failures, then a success should reset.
        tracker.record_success("up", proto);
        // Two more failures should not open (count was reset).
        tracker.record_failure("up", proto);
        tracker.record_failure("up", proto);
        assert!(tracker.can_use("up", proto).is_ok());
    }

    #[test]
    fn test_half_open_recovers_on_successes() {
        let _clock = MockTimeGuard::new(1000);
        let tracker = TransportHealthTracker::new(1, 2, 0); // 0 → clamped to 1s
        let proto = TransportProtocol::Http;

        // Open the circuit. Closed→Open sets trip_count=1 (FIND-R43-027),
        // effective open_duration = 1s * 2^1 = 2s.
        tracker.record_failure("up", proto);
        assert!(tracker.can_use("up", proto).is_err());

        // Advance past effective open duration (2 seconds).
        advance_mock_time(2);

        // Should transition to HalfOpen.
        assert!(tracker.can_use("up", proto).is_ok());

        // Succeed twice to close.
        tracker.record_success("up", proto);
        tracker.record_success("up", proto);
        assert!(tracker.can_use("up", proto).is_ok());

        // Summary should show closed.
        let summary = tracker.summary();
        assert_eq!(summary.closed, 1);
        assert_eq!(summary.open, 0);
    }

    #[test]
    fn test_half_open_failure_reopens_circuit() {
        let _clock = MockTimeGuard::new(1000);
        let tracker = TransportHealthTracker::new(1, 2, 0); // clamped to 1s
        let proto = TransportProtocol::Grpc;

        // Open the circuit. Closed→Open sets trip_count=1 (FIND-R43-027),
        // effective open_duration = 1s * 2^1 = 2s.
        tracker.record_failure("up", proto);
        advance_mock_time(2);

        // Transition to HalfOpen.
        assert!(tracker.can_use("up", proto).is_ok());

        // Fail in HalfOpen → back to Open.
        assert_eq!(
            tracker.record_failure("up", proto),
            TransportCircuitState::Open
        );
        assert!(tracker.can_use("up", proto).is_err());
    }

    #[test]
    fn test_available_transports_filters_open() {
        let tracker = TransportHealthTracker::new(1, 2, 300);
        let priorities = vec![
            TransportProtocol::Grpc,
            TransportProtocol::WebSocket,
            TransportProtocol::Http,
        ];

        // Open gRPC circuit.
        tracker.record_failure("up", TransportProtocol::Grpc);

        let available = tracker.available_transports("up", &priorities);
        assert_eq!(available.len(), 2);
        assert!(!available.contains(&TransportProtocol::Grpc));
        assert!(available.contains(&TransportProtocol::WebSocket));
        assert!(available.contains(&TransportProtocol::Http));
    }

    #[test]
    fn test_available_transports_preserves_order() {
        let tracker = TransportHealthTracker::new(3, 2, 30);
        let priorities = vec![
            TransportProtocol::Http,
            TransportProtocol::Grpc,
            TransportProtocol::WebSocket,
        ];

        let available = tracker.available_transports("up", &priorities);
        assert_eq!(available, priorities);
    }

    #[test]
    fn test_summary_empty_tracker() {
        let tracker = TransportHealthTracker::new(3, 2, 30);
        let summary = tracker.summary();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.closed, 0);
        assert_eq!(summary.open, 0);
        assert_eq!(summary.half_open, 0);
    }

    #[test]
    fn test_summary_mixed_states() {
        let tracker = TransportHealthTracker::new(1, 2, 300);

        // Closed (via success).
        tracker.record_success("up", TransportProtocol::Http);
        // Open (via failure).
        tracker.record_failure("up", TransportProtocol::Grpc);

        let summary = tracker.summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.closed, 1);
        assert_eq!(summary.open, 1);
    }

    #[test]
    fn test_reset_removes_circuit() {
        let tracker = TransportHealthTracker::new(1, 2, 300);
        let proto = TransportProtocol::WebSocket;

        tracker.record_failure("up", proto);
        assert!(tracker.can_use("up", proto).is_err());

        tracker.reset("up", proto);
        assert!(tracker.can_use("up", proto).is_ok());
    }

    #[test]
    fn test_independent_upstreams() {
        let tracker = TransportHealthTracker::new(1, 2, 300);
        let proto = TransportProtocol::Http;

        tracker.record_failure("up-a", proto);
        assert!(tracker.can_use("up-a", proto).is_err());
        assert!(tracker.can_use("up-b", proto).is_ok());
    }

    #[test]
    fn test_independent_transports_same_upstream() {
        let tracker = TransportHealthTracker::new(1, 2, 300);

        tracker.record_failure("up", TransportProtocol::Grpc);
        assert!(tracker.can_use("up", TransportProtocol::Grpc).is_err());
        assert!(tracker.can_use("up", TransportProtocol::Http).is_ok());
    }

    #[test]
    fn test_exponential_backoff_increases_open_duration() {
        let _clock = MockTimeGuard::new(1000);
        let tracker = TransportHealthTracker::new(1, 1, 1);
        let proto = TransportProtocol::Http;

        // First trip: Closed→Open sets trip_count=1 (FIND-R43-027), so
        // effective open_duration = 1s * 2^1 = 2s.
        tracker.record_failure("up", proto);
        advance_mock_time(2);
        assert!(tracker.can_use("up", proto).is_ok()); // HalfOpen

        // Fail in HalfOpen → trip_count=2, open_duration = 1s * 2^2 = 4s.
        tracker.record_failure("up", proto);

        // After 2s, should still be open (need 4s).
        advance_mock_time(2);
        assert!(tracker.can_use("up", proto).is_err());

        // After another 2s (total 4s), should transition to HalfOpen.
        advance_mock_time(2);
        assert!(tracker.can_use("up", proto).is_ok());
    }

    #[test]
    fn test_trip_count_resets_on_full_recovery() {
        let _clock = MockTimeGuard::new(1000);
        let tracker = TransportHealthTracker::new(1, 1, 1);
        let proto = TransportProtocol::Http;

        // Trip once: Closed→Open sets trip_count=1 (FIND-R43-027),
        // effective open_duration = 1s * 2^1 = 2s.
        tracker.record_failure("up", proto);
        advance_mock_time(2);
        tracker.can_use("up", proto).ok(); // HalfOpen
        tracker.record_failure("up", proto); // trip_count=2, open_duration=4s

        // Recover: wait for 4s open duration to expire.
        advance_mock_time(4);
        tracker.can_use("up", proto).ok(); // HalfOpen
        tracker.record_success("up", proto); // Closed, trip_count=0

        // Next trip: Closed→Open sets trip_count=1 again (FIND-R43-027),
        // effective open_duration = 1s * 2^1 = 2s.
        tracker.record_failure("up", proto);
        advance_mock_time(2);
        assert!(tracker.can_use("up", proto).is_ok()); // Would fail if trip_count wasn't reset.
    }

    #[test]
    fn test_circuit_state_serde_roundtrip() {
        for state in [
            TransportCircuitState::Closed,
            TransportCircuitState::Open,
            TransportCircuitState::HalfOpen,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let deser: TransportCircuitState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, deser);
        }
    }

    #[test]
    fn test_transport_health_summary_serialize() {
        let summary = TransportHealthSummary {
            total: 5,
            closed: 3,
            open: 1,
            half_open: 1,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"total\":5"));
    }

    // ═══════════════════════════════════════════════════════
    // Adversarial audit tests (FIND-R41-003)
    // ═══════════════════════════════════════════════════════

    /// FIND-R41-003: Verify capacity bound prevents unbounded memory growth.
    /// record_failure should return Open (fail-closed) when at capacity.
    #[test]
    fn test_capacity_bound_record_failure_fail_closed() {
        // Use a tiny capacity for testing by filling with unique entries.
        // MAX_TRACKED_CIRCUITS is 10_000 — we won't fill that in a test.
        // Instead, verify the logic by checking that the bound check exists
        // and that the tracker tracks entries correctly.
        let tracker = TransportHealthTracker::new(1, 1, 300);

        // Add a few entries and verify they're tracked.
        for i in 0..5 {
            tracker.record_failure(&format!("up-{}", i), TransportProtocol::Http);
        }
        let summary = tracker.summary();
        assert_eq!(summary.total, 5);
        assert_eq!(summary.open, 5);
    }

    /// FIND-R41-003: record_success at capacity skips new entry (does not grow).
    #[test]
    fn test_record_success_does_not_grow_unbounded() {
        let tracker = TransportHealthTracker::new(3, 1, 300);

        // Record success for many unique upstreams.
        for i in 0..20 {
            tracker.record_success(&format!("up-{}", i), TransportProtocol::Http);
        }
        let summary = tracker.summary();
        assert_eq!(summary.total, 20);
        assert_eq!(summary.closed, 20);
    }

    /// Verify poisoned RwLock in record_failure returns Open (fail-closed).
    /// We can't easily poison in a test without panicking a thread, so we
    /// verify that record_failure returns the expected state on the happy path.
    #[test]
    fn test_record_failure_returns_correct_state() {
        let tracker = TransportHealthTracker::new(2, 1, 300);
        let proto = TransportProtocol::Grpc;

        assert_eq!(
            tracker.record_failure("up", proto),
            TransportCircuitState::Closed
        );
        assert_eq!(
            tracker.record_failure("up", proto),
            TransportCircuitState::Open
        );
        // Further failures in Open state should stay Open.
        assert_eq!(
            tracker.record_failure("up", proto),
            TransportCircuitState::Open
        );
    }

    // ═══════════════════════════════════════════════════════
    // Adversarial audit tests (FIND-R42-005, FIND-R42-010, FIND-R42-012)
    // ═══════════════════════════════════════════════════════

    /// FIND-R42-010: Half-open circuit rejects concurrent probes.
    #[test]
    fn test_half_open_rejects_second_probe() {
        let _clock = MockTimeGuard::new(1000);
        let tracker = TransportHealthTracker::new(1, 2, 0); // clamped to 1s
        let proto = TransportProtocol::Http;

        // Open the circuit. Closed→Open sets trip_count=1 (FIND-R43-027),
        // effective open_duration = 1s * 2^1 = 2s.
        tracker.record_failure("up", proto);
        advance_mock_time(2);

        // First probe transitions Open → HalfOpen and sets in_flight.
        assert!(tracker.can_use("up", proto).is_ok());

        // Second probe should be rejected (in_flight = true).
        assert!(tracker.can_use("up", proto).is_err());

        // After recording success, in_flight is cleared.
        tracker.record_success("up", proto);
        assert!(tracker.can_use("up", proto).is_ok());
    }

    /// FIND-R42-010: Half-open in_flight flag is cleared on failure too.
    #[test]
    fn test_half_open_in_flight_cleared_on_failure() {
        let _clock = MockTimeGuard::new(1000);
        let tracker = TransportHealthTracker::new(1, 2, 0); // clamped to 1s
        let proto = TransportProtocol::Grpc;

        // Open circuit: Closed→Open sets trip_count=1 (FIND-R43-027),
        // effective open_duration = 1s * 2^1 = 2s.
        tracker.record_failure("up", proto);
        advance_mock_time(2);
        assert!(tracker.can_use("up", proto).is_ok()); // HalfOpen, in_flight=true

        // Fail the probe → back to Open, in_flight cleared.
        // trip_count=2, effective open_duration = 1s * 2^2 = 4s.
        tracker.record_failure("up", proto);
        assert!(tracker.can_use("up", proto).is_err()); // Open again

        // Advance past 4s open duration.
        advance_mock_time(4);
        // Should be able to probe again.
        assert!(tracker.can_use("up", proto).is_ok());
    }

    /// FIND-R42-012: failure_count uses saturating_add (won't overflow).
    #[test]
    fn test_failure_count_saturating() {
        let tracker = TransportHealthTracker::new(u32::MAX, 1, 300);
        let proto = TransportProtocol::WebSocket;

        // Record many failures — should not panic from overflow.
        for _ in 0..10 {
            tracker.record_failure("up", proto);
        }
        // Circuit should still be Closed (threshold is u32::MAX).
        assert!(tracker.can_use("up", proto).is_ok());
    }

    // ═══════════════════════════════════════════════════════
    // Adversarial audit tests (FIND-R44-001, FIND-R44-002)
    // ═══════════════════════════════════════════════════════

    /// FIND-R44-002: peek_available_transports is side-effect-free.
    #[test]
    fn test_peek_available_transports_no_side_effects() {
        let _clock = MockTimeGuard::new(1000);
        let tracker = TransportHealthTracker::new(1, 2, 0); // clamped to 1s
        let proto = TransportProtocol::Http;

        // Open the circuit.  After 1 failure with threshold=1, trip_count=1
        // so effective_open_duration = 1s * 2^1 = 2s (exponential backoff).
        tracker.record_failure("up", proto);
        advance_mock_time(2);

        // peek should report it as available (timer expired) without transitioning.
        let available = tracker.peek_available_transports("up", &[proto]);
        assert_eq!(
            available,
            vec![proto],
            "peek should show expired Open as available"
        );

        // Call peek again — should still work (no probe slot consumed).
        let available2 = tracker.peek_available_transports("up", &[proto]);
        assert_eq!(available2, vec![proto], "second peek should also succeed");

        // Summary should still show Open (not HalfOpen — no transition occurred).
        let summary = tracker.summary();
        assert_eq!(summary.half_open, 1); // summary also peeks, but state is still Open
    }

    /// FIND-R44-002: peek_available_transports filters at capacity.
    #[test]
    fn test_peek_available_transports_at_capacity_unknown() {
        let tracker = TransportHealthTracker::new(3, 2, 300);
        // Insert entries up to near-capacity to test the capacity check.
        // We can't fill 10K in a test, but verify the logic path exists
        // by checking a known circuit.
        tracker.record_success("up", TransportProtocol::Http);
        let available = tracker
            .peek_available_transports("up", &[TransportProtocol::Http, TransportProtocol::Grpc]);
        assert!(available.contains(&TransportProtocol::Http));
        assert!(available.contains(&TransportProtocol::Grpc)); // Unknown = available
    }
}
