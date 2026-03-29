// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Stateful Session Reasoning Guards (Phase 23.5).
//!
//! Provides a formal session state machine (Init→Active→Suspicious→Locked→Ended)
//! with configurable transition rules, session-level policy conditions, and
//! integration with `WorkflowTracker` and `GoalTracker`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use thiserror::Error;

use crate::goal_tracking::GoalDriftAlert;
use crate::workflow_tracker::WorkflowAlert;

// ═══════════════════════════════════════════════════════════════════
// Session State Machine
// ═══════════════════════════════════════════════════════════════════

/// Session lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionState {
    /// Session just created, no actions yet.
    Init,
    /// Normal operation.
    Active,
    /// Anomalous behavior detected, monitoring closely.
    Suspicious,
    /// Session locked due to repeated violations.
    Locked,
    /// Session ended normally or forcibly.
    Ended,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionState::Init => write!(f, "Init"),
            SessionState::Active => write!(f, "Active"),
            SessionState::Suspicious => write!(f, "Suspicious"),
            SessionState::Locked => write!(f, "Locked"),
            SessionState::Ended => write!(f, "Ended"),
        }
    }
}

/// Severity of an anomaly signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalySeverity {
    /// Low — worth noting but not alarming.
    Low,
    /// Medium — potentially harmful, warrants closer monitoring.
    Medium,
    /// High — likely malicious, consider locking session.
    High,
    /// Critical — immediate lock recommended.
    Critical,
}

/// Events that trigger state transitions.
// SECURITY (FIND-R56-MCP-002): Custom Debug impl redacts admin_token in AdminUnlock.
#[derive(Clone, Serialize, Deserialize)]
pub enum SessionEvent {
    /// First action received (Init→Active).
    FirstAction,
    /// Normal action within policy (keeps Active).
    NormalAction,
    /// Anomaly detected from any source.
    AnomalyDetected {
        severity: AnomalySeverity,
        description: String,
    },
    /// Policy violation (deny verdict).
    PolicyViolation { reason: String },
    /// Multiple consecutive violations.
    RepeatedViolation { count: u32 },
    /// Cooldown period elapsed (Locked→Suspicious).
    CooldownElapsed,
    /// Admin unlock (Locked→Active).
    ///
    /// SECURITY (FIND-R46-007): The `admin_token` field MUST be verified against
    /// a configured admin credential. Without this, any caller can unlock any
    /// session, resetting violation counters to zero.
    AdminUnlock {
        /// Opaque admin credential token. The session guard verifies this
        /// against the configured `admin_unlock_token` before allowing the
        /// transition.
        admin_token: String,
    },
    /// Session timeout or explicit end.
    SessionEnd,
}

// SECURITY (FIND-R56-MCP-002): Custom Debug impl redacts admin_token in AdminUnlock
// variant to prevent credential leakage in logs and Debug output.
impl std::fmt::Debug for SessionEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionEvent::FirstAction => write!(f, "FirstAction"),
            SessionEvent::NormalAction => write!(f, "NormalAction"),
            SessionEvent::AnomalyDetected {
                severity,
                description,
            } => f
                .debug_struct("AnomalyDetected")
                .field("severity", severity)
                .field("description", description)
                .finish(),
            SessionEvent::PolicyViolation { reason } => f
                .debug_struct("PolicyViolation")
                .field("reason", reason)
                .finish(),
            SessionEvent::RepeatedViolation { count } => f
                .debug_struct("RepeatedViolation")
                .field("count", count)
                .finish(),
            SessionEvent::CooldownElapsed => write!(f, "CooldownElapsed"),
            SessionEvent::AdminUnlock { .. } => f
                .debug_struct("AdminUnlock")
                .field("admin_token", &"[REDACTED]")
                .finish(),
            SessionEvent::SessionEnd => write!(f, "SessionEnd"),
        }
    }
}

/// Result of a state transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionResult {
    /// State before transition.
    pub previous: SessionState,
    /// State after transition.
    pub current: SessionState,
    /// Action to take as a result.
    pub action: TransitionAction,
}

/// Action to take after a state transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionAction {
    /// No special action needed.
    None,
    /// Log a warning.
    Warn { message: String },
    /// Deny all further actions until state changes.
    DenyAll { reason: String },
    /// Emit audit event.
    AuditEvent { event_type: String },
}

/// Summary of a session's state and history.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSummary {
    /// Current session state.
    pub state: SessionState,
    /// Number of anomalies detected.
    pub anomaly_count: u32,
    /// Number of policy violations.
    pub violation_count: u32,
    /// Unix timestamp when session started.
    pub started_at: u64,
    /// Unix timestamp of last action.
    pub last_action_at: u64,
    /// State transition history: (from, to, timestamp).
    pub transitions: Vec<(SessionState, SessionState, u64)>,
}

/// Errors from session guard operations.
#[derive(Error, Debug)]
pub enum SessionGuardError {
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    #[error("Lock poisoned")]
    LockPoisoned,
}

// ═══════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════

/// Configuration for the session guard.
// SECURITY (FIND-R55-MCP-003): deny_unknown_fields prevents attacker-injected
// fields from being silently accepted in security-critical configuration.
// SECURITY (FIND-R56-MCP-002): Custom Debug impl redacts admin_unlock_token
// to prevent credential leakage in logs, error messages, and Debug output.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGuardConfig {
    /// Anomaly count before transitioning Active→Suspicious.
    #[serde(default = "default_suspicious_threshold")]
    pub suspicious_threshold: u32,
    /// Violation count before transitioning Suspicious→Locked.
    #[serde(default = "default_lock_threshold")]
    pub lock_threshold: u32,
    /// Cooldown period in seconds before Locked→Suspicious.
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u64,
    /// Maximum session duration in seconds (0 = unlimited).
    #[serde(default = "default_max_session_duration")]
    pub max_session_duration_secs: u64,
    /// Maximum number of tracked sessions (evict oldest when exceeded).
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// Admin unlock token. When set, `SessionEvent::AdminUnlock` events are
    /// only honored if the provided `admin_token` matches this value
    /// (constant-time comparison). When `None`, admin unlock is disabled
    /// entirely (fail-closed).
    ///
    /// SECURITY (FIND-R46-007): Without this, any caller can unlock any
    /// session, resetting violation counters to zero.
    #[serde(default)]
    pub admin_unlock_token: Option<String>,
}

// SECURITY (FIND-R56-MCP-002): Custom Debug impl redacts admin_unlock_token.
impl std::fmt::Debug for SessionGuardConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionGuardConfig")
            .field("suspicious_threshold", &self.suspicious_threshold)
            .field("lock_threshold", &self.lock_threshold)
            .field("cooldown_secs", &self.cooldown_secs)
            .field("max_session_duration_secs", &self.max_session_duration_secs)
            .field("max_sessions", &self.max_sessions)
            .field(
                "admin_unlock_token",
                &self.admin_unlock_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

fn default_suspicious_threshold() -> u32 {
    3
}
fn default_lock_threshold() -> u32 {
    5
}
fn default_cooldown_secs() -> u64 {
    300
}
fn default_max_session_duration() -> u64 {
    3600
}
fn default_max_sessions() -> usize {
    10000
}

impl Default for SessionGuardConfig {
    fn default() -> Self {
        Self {
            suspicious_threshold: default_suspicious_threshold(),
            lock_threshold: default_lock_threshold(),
            cooldown_secs: default_cooldown_secs(),
            max_session_duration_secs: default_max_session_duration(),
            max_sessions: default_max_sessions(),
            admin_unlock_token: None,
        }
    }
}

impl SessionGuardConfig {
    /// Validate the configuration, returning an error description on failure.
    ///
    /// # Security (FIND-R111-002)
    ///
    /// Zero thresholds bypass session guard protections:
    /// - `suspicious_threshold = 0` means the session immediately becomes Suspicious
    ///   on the very first action, which may prevent all legitimate use.
    /// - `lock_threshold = 0` means the session immediately locks, denying all
    ///   requests — effectively a DoS through misconfiguration.
    /// - `cooldown_secs = 0` allows instant unlock loops with no delay.
    /// - `max_sessions = 0` prevents any session from being created (fail-open DoS).
    ///
    /// All numeric thresholds must be at least 1.
    pub fn validate(&self) -> Result<(), String> {
        if self.suspicious_threshold == 0 {
            return Err(
                "suspicious_threshold must be at least 1 (zero bypasses anomaly accumulation)"
                    .to_string(),
            );
        }
        if self.lock_threshold == 0 {
            return Err(
                "lock_threshold must be at least 1 (zero causes immediate session lock)"
                    .to_string(),
            );
        }
        if self.cooldown_secs == 0 {
            return Err(
                "cooldown_secs must be at least 1 (zero allows instant unlock loops)".to_string(),
            );
        }
        if self.max_sessions == 0 {
            return Err(
                "max_sessions must be at least 1 (zero prevents all session creation)".to_string(),
            );
        }
        // Validate admin_unlock_token length and characters if present
        if let Some(ref token) = self.admin_unlock_token {
            if token.is_empty() {
                return Err("admin_unlock_token must not be empty when set".to_string());
            }
            const MAX_ADMIN_TOKEN_LEN: usize = 512;
            if token.len() > MAX_ADMIN_TOKEN_LEN {
                return Err(format!(
                    "admin_unlock_token too long: {} bytes (max {})",
                    token.len(),
                    MAX_ADMIN_TOKEN_LEN
                ));
            }
            // SECURITY (IMP-R188-006): Reject control/format chars in admin token
            // to prevent comparison issues with invisible characters.
            if vellaveto_types::has_dangerous_chars(token) {
                return Err("admin_unlock_token contains control or format characters".to_string());
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════
// Session Context (internal)
// ═══════════════════════════════════════════════════════════════════

/// Maximum number of transitions stored per session to prevent unbounded growth.
const MAX_TRANSITION_HISTORY: usize = 1000;

/// SECURITY (FIND-R174-002): Maximum session ID length to prevent HashMap key bloat.
const MAX_SESSION_ID_LEN: usize = 256;

/// SECURITY (FIND-R174-006): Maximum length for event description/reason strings
/// included in TransitionAction messages. Prevents unbounded string growth from
/// user-supplied SessionEvent fields.
const MAX_EVENT_FIELD_LEN: usize = 1024;

/// Truncate a string to `MAX_EVENT_FIELD_LEN` at a UTF-8 char boundary.
fn truncate_event_field(s: &str) -> &str {
    if s.len() <= MAX_EVENT_FIELD_LEN {
        return s;
    }
    let mut end = MAX_EVENT_FIELD_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// SECURITY (FIND-R73-007): Maximum recursion depth for compute_transition().
/// The Init catch-all arm recurses once to reprocess the event in Active state.
/// This guard prevents infinite recursion if a bug causes a state loop.
const MAX_COMPUTE_TRANSITION_DEPTH: u8 = 2;

/// SECURITY (FIND-R188-005): Maximum failed admin unlock attempts before
/// permanently ending the session. Prevents brute-force token guessing.
const MAX_FAILED_UNLOCK_ATTEMPTS: u32 = 5;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct SessionContext {
    state: SessionState,
    anomaly_count: u32,
    violation_count: u32,
    started_at: u64,
    last_action_at: u64,
    /// Timestamp when the session entered the Locked state (for cooldown validation).
    locked_at: Option<u64>,
    /// SECURITY (FIND-R188-005): Count of failed admin unlock attempts.
    failed_unlock_attempts: u32,
    transition_history: Vec<(SessionState, SessionState, u64)>,
}

impl SessionContext {
    fn new(now: u64) -> Self {
        Self {
            state: SessionState::Init,
            anomaly_count: 0,
            violation_count: 0,
            started_at: now,
            last_action_at: now,
            locked_at: None,
            failed_unlock_attempts: 0,
            transition_history: Vec::new(),
        }
    }

    fn record_transition(&mut self, from: SessionState, to: SessionState, now: u64) {
        self.state = to;
        self.last_action_at = now;
        if to == SessionState::Locked {
            self.locked_at = Some(now);
        }
        // Bound history to prevent unbounded memory growth (FIND-P23-S13)
        if self.transition_history.len() < MAX_TRANSITION_HISTORY {
            self.transition_history.push((from, to, now));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Session Backend Trait
// ═══════════════════════════════════════════════════════════════════

/// Durable persistence backend for session state.
///
/// Implementations store session contexts to a durable store (Redis, RocksDB,
/// filesystem) so that security-critical states (Locked, Suspicious) survive
/// process restarts via [`SessionGuard::warm_restart`].
///
/// All methods are synchronous and must be `Send + Sync`. Implementations
/// should be fast (< 5ms) since they are called within the SessionGuard
/// write lock. Failures are non-blocking — logged and ignored.
pub(crate) trait SessionBackend: Send + Sync {
    /// Persist a session context.
    fn store(&self, session_id: &str, ctx: &SessionContext) -> Result<(), String>;
    /// Remove a session from the durable store.
    #[allow(dead_code)]
    fn remove(&self, session_id: &str) -> Result<(), String>;
    /// Load all persisted sessions (for warm restart).
    fn load_all(&self) -> Result<Vec<(String, SessionContext)>, String>;
}

// ═══════════════════════════════════════════════════════════════════
// Session Guard
// ═══════════════════════════════════════════════════════════════════

/// Session guard with formal state machine and configurable transitions.
///
/// Optionally backed by a durable [`SessionBackend`] for persistence across
/// process restarts. When a backend is configured, every state transition
/// is written through to the backend. Backend failures are non-blocking
/// (logged, but the in-memory state remains authoritative).
pub struct SessionGuard {
    config: SessionGuardConfig,
    sessions: RwLock<HashMap<String, SessionContext>>,
    backend: Option<Box<dyn SessionBackend>>,
}

impl SessionGuard {
    /// Create a new session guard with the given configuration.
    pub fn new(config: SessionGuardConfig) -> Self {
        Self {
            config,
            sessions: RwLock::new(HashMap::new()),
            backend: None,
        }
    }

    /// Attach a durable persistence backend.
    ///
    /// When set, every state transition is written through to the backend.
    /// Backend failures are non-blocking (logged at warn level).
    #[allow(dead_code)]
    pub(crate) fn with_backend(mut self, backend: Box<dyn SessionBackend>) -> Self {
        self.backend = Some(backend);
        self
    }

    /// Get the current timestamp (Unix seconds).
    ///
    /// SECURITY (R253-GUARD-1): Returns a minimum of 1 second to prevent
    /// clock-rollback attacks. If the system clock is before Unix epoch,
    /// `unwrap_or_default()` returns 0, which causes `saturating_sub` in
    /// expiry checks to silently pass — allowing sessions to live forever.
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .max(1)
    }

    /// Process an event for a session, returning the transition result.
    pub fn process_event(
        &self,
        session_id: &str,
        event: SessionEvent,
    ) -> Result<TransitionResult, SessionGuardError> {
        self.process_event_at(session_id, event, Self::now())
    }

    /// Process an event at a specific timestamp (for testing).
    pub fn process_event_at(
        &self,
        session_id: &str,
        event: SessionEvent,
        now: u64,
    ) -> Result<TransitionResult, SessionGuardError> {
        // SECURITY (FIND-R174-002): Validate session_id before use as HashMap key.
        if session_id.is_empty() {
            return Err(SessionGuardError::SessionNotFound(
                "session_id must not be empty".to_string(),
            ));
        }
        if session_id.len() > MAX_SESSION_ID_LEN {
            return Err(SessionGuardError::SessionNotFound(format!(
                "session_id length {} exceeds maximum {}",
                session_id.len(),
                MAX_SESSION_ID_LEN
            )));
        }
        // IMP-R174-015: Use shared has_dangerous_chars() predicate for consistency.
        if vellaveto_types::has_dangerous_chars(session_id) {
            return Err(SessionGuardError::SessionNotFound(
                "session_id contains control or Unicode format characters".to_string(),
            ));
        }

        let mut sessions = self.sessions.write().map_err(|_| {
            // SECURITY (FIND-R220-009): Log write-lock poisoning at error level for operator
            // visibility, matching the parity established in should_deny (FIND-R218-004).
            tracing::error!(
                session_id = session_id,
                "SessionGuard write lock poisoned in process_event_at"
            );
            SessionGuardError::LockPoisoned
        })?;

        // Create session if it doesn't exist
        if !sessions.contains_key(session_id) {
            // Enforce max_sessions — evict oldest if at capacity.
            // SECURITY: Never evict Locked, Ended, or Suspicious sessions —
            // they carry security state that must be preserved (FIND-P23-S12).
            // SECURITY (FIND-R113-001): Also protect Suspicious sessions to
            // prevent state reset attacks where an attacker accumulates
            // violations near the lock threshold, then evicts to reset counters.
            if sessions.len() >= self.config.max_sessions {
                let evictable = sessions
                    .iter()
                    .filter(|(_, ctx)| {
                        !matches!(
                            ctx.state,
                            SessionState::Locked | SessionState::Ended | SessionState::Suspicious
                        )
                    })
                    .min_by_key(|(_, ctx)| ctx.last_action_at)
                    .map(|(k, _)| k.clone());
                if let Some(key) = evictable {
                    sessions.remove(&key);
                } else {
                    // SECURITY (FIND-R212-009): Fallback — evict oldest Suspicious
                    // session to prevent saturation DoS where an attacker fills all
                    // slots with Suspicious sessions (each needing only
                    // suspicious_threshold anomaly events).  Locked and Ended
                    // sessions are never evicted.
                    let suspicious_evictable = sessions
                        .iter()
                        .filter(|(_, ctx)| ctx.state == SessionState::Suspicious)
                        .min_by_key(|(_, ctx)| ctx.last_action_at)
                        .map(|(k, _)| k.clone());
                    if let Some(key) = suspicious_evictable {
                        tracing::warn!(
                            "Evicting oldest Suspicious session '{}' due to capacity pressure",
                            key
                        );
                        sessions.remove(&key);
                    } else {
                        // All sessions are Locked/Ended — cannot evict safely.
                        // Fail-closed: refuse to create new session.
                        return Err(SessionGuardError::SessionNotFound(format!(
                            "Session limit reached ({}) and no evictable sessions",
                            self.config.max_sessions
                        )));
                    }
                }
            }
            sessions.insert(session_id.to_string(), SessionContext::new(now));
        }

        let ctx = sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionGuardError::SessionNotFound(session_id.to_string()))?;

        // SECURITY (FIND-R188-001): Enforce max_session_duration_secs.
        // Previously this config was parsed and stored but never checked, allowing
        // sessions to run indefinitely regardless of the configured time-box.
        if self.config.max_session_duration_secs > 0
            && ctx.state != SessionState::Ended
            && now.saturating_sub(ctx.started_at) >= self.config.max_session_duration_secs
        {
            let previous = ctx.state;
            ctx.state = SessionState::Ended;
            ctx.record_transition(previous, SessionState::Ended, now);
            self.persist_session(session_id, ctx);
            return Ok(TransitionResult {
                previous,
                current: SessionState::Ended,
                action: TransitionAction::DenyAll {
                    reason: format!(
                        "Session duration exceeded ({} >= {} seconds)",
                        now.saturating_sub(ctx.started_at),
                        self.config.max_session_duration_secs
                    ),
                },
            });
        }

        let previous = ctx.state;
        let (new_state, action) = self.compute_transition(ctx, &event, now, 0);

        if new_state != previous {
            ctx.record_transition(previous, new_state, now);
        } else {
            ctx.last_action_at = now;
        }

        // Write-through to durable backend (non-blocking on failure).
        self.persist_session(session_id, ctx);

        Ok(TransitionResult {
            previous,
            current: new_state,
            action,
        })
    }

    /// Restore security-critical sessions from the durable backend.
    ///
    /// Called once at startup to recover Locked and Suspicious sessions that
    /// would otherwise be lost on process restart. Active and Init sessions
    /// are NOT restored (they are transient). Ended sessions are skipped
    /// (terminal, no further transitions possible).
    ///
    /// Returns the number of sessions restored, or an error if the backend
    /// is not configured or fails to load.
    pub fn warm_restart(&self) -> Result<usize, SessionGuardError> {
        let backend = self.backend.as_ref().ok_or_else(|| {
            SessionGuardError::SessionNotFound("no backend configured".to_string())
        })?;

        let persisted = backend
            .load_all()
            .map_err(|e| SessionGuardError::SessionNotFound(format!("backend load failed: {e}")))?;

        let mut sessions = self.sessions.write().map_err(|_| {
            tracing::error!("SessionGuard write lock poisoned during warm_restart");
            SessionGuardError::LockPoisoned
        })?;

        let mut restored = 0usize;
        for (id, ctx) in persisted {
            // Only restore security-critical states.
            if !matches!(ctx.state, SessionState::Locked | SessionState::Suspicious) {
                continue;
            }
            // Respect max_sessions bound.
            if sessions.len() >= self.config.max_sessions {
                tracing::warn!(
                    "warm_restart: hit max_sessions ({}) — stopping restoration",
                    self.config.max_sessions
                );
                break;
            }
            sessions.insert(id, ctx);
            restored = restored.saturating_add(1);
        }

        tracing::info!(
            "warm_restart: restored {} security-critical sessions",
            restored
        );
        Ok(restored)
    }

    /// Persist a session to the durable backend if configured.
    /// Failures are logged at warn level but never block the caller.
    fn persist_session(&self, session_id: &str, ctx: &SessionContext) {
        if let Some(ref backend) = self.backend {
            if let Err(e) = backend.store(session_id, ctx) {
                tracing::warn!(
                    session_id = session_id,
                    error = %e,
                    "Failed to persist session to backend (non-blocking)"
                );
            }
        }
    }

    fn compute_transition(
        &self,
        ctx: &mut SessionContext,
        event: &SessionEvent,
        now: u64,
        depth: u8,
    ) -> (SessionState, TransitionAction) {
        // SECURITY (FIND-R73-007): Guard against infinite recursion.
        if depth >= MAX_COMPUTE_TRANSITION_DEPTH {
            tracing::error!(
                target: "vellaveto::security",
                depth = depth,
                state = %ctx.state,
                "compute_transition recursion depth exceeded — fail-closed"
            );
            return (
                SessionState::Locked,
                TransitionAction::DenyAll {
                    reason: "Session state machine recursion depth exceeded — fail-closed"
                        .to_string(),
                },
            );
        }

        match (ctx.state, event) {
            // === Init state ===
            (SessionState::Init, SessionEvent::FirstAction) => (
                SessionState::Active,
                TransitionAction::AuditEvent {
                    event_type: "session_activated".to_string(),
                },
            ),
            (SessionState::Init, SessionEvent::SessionEnd) => (
                SessionState::Ended,
                TransitionAction::AuditEvent {
                    event_type: "session_ended".to_string(),
                },
            ),
            // Any other event in Init transitions to Active first
            (SessionState::Init, _) => {
                ctx.state = SessionState::Active;
                if ctx.transition_history.len() < MAX_TRANSITION_HISTORY {
                    ctx.transition_history
                        .push((SessionState::Init, SessionState::Active, now));
                }
                self.compute_transition(ctx, event, now, depth.saturating_add(1))
            }

            // === Active state ===
            (SessionState::Active, SessionEvent::NormalAction) => {
                (SessionState::Active, TransitionAction::None)
            }
            (
                SessionState::Active,
                SessionEvent::AnomalyDetected {
                    severity,
                    description,
                },
            ) => {
                ctx.anomaly_count = ctx.anomaly_count.saturating_add(1);
                // Critical severity → immediate Suspicious
                let immediate = matches!(severity, AnomalySeverity::Critical);
                // SECURITY (FIND-R174-006): Truncate user-supplied description.
                let desc = truncate_event_field(description);
                if immediate || ctx.anomaly_count >= self.config.suspicious_threshold {
                    (
                        SessionState::Suspicious,
                        TransitionAction::Warn {
                            message: format!(
                                "Session transitioning to Suspicious: {} (anomalies: {})",
                                desc, ctx.anomaly_count
                            ),
                        },
                    )
                } else {
                    (
                        SessionState::Active,
                        TransitionAction::Warn {
                            message: format!("Anomaly detected: {desc}"),
                        },
                    )
                }
            }
            (SessionState::Active, SessionEvent::PolicyViolation { reason }) => {
                ctx.violation_count = ctx.violation_count.saturating_add(1);
                ctx.anomaly_count = ctx.anomaly_count.saturating_add(1);
                // SECURITY (FIND-R174-006): Truncate user-supplied reason.
                let rsn = truncate_event_field(reason);
                if ctx.anomaly_count >= self.config.suspicious_threshold {
                    (
                        SessionState::Suspicious,
                        TransitionAction::Warn {
                            message: format!(
                                "Session transitioning to Suspicious after violation: {rsn}"
                            ),
                        },
                    )
                } else {
                    (
                        SessionState::Active,
                        TransitionAction::Warn {
                            message: format!("Policy violation: {rsn}"),
                        },
                    )
                }
            }
            (SessionState::Active, SessionEvent::RepeatedViolation { count }) => {
                // SECURITY (FIND-R174-003): count=0 should be a no-op, not escalate state.
                if *count == 0 {
                    return (SessionState::Active, TransitionAction::None);
                }
                ctx.violation_count = ctx.violation_count.saturating_add(*count);
                ctx.anomaly_count = ctx.anomaly_count.saturating_add(*count);
                (
                    SessionState::Suspicious,
                    TransitionAction::Warn {
                        message: format!(
                            "Repeated violations ({count}), transitioning to Suspicious"
                        ),
                    },
                )
            }
            (SessionState::Active, SessionEvent::SessionEnd) => (
                SessionState::Ended,
                TransitionAction::AuditEvent {
                    event_type: "session_ended".to_string(),
                },
            ),

            // === Suspicious state ===
            (SessionState::Suspicious, SessionEvent::NormalAction) => {
                (SessionState::Suspicious, TransitionAction::None)
            }
            (
                SessionState::Suspicious,
                SessionEvent::AnomalyDetected {
                    severity,
                    description,
                },
            ) => {
                ctx.anomaly_count = ctx.anomaly_count.saturating_add(1);
                let immediate =
                    matches!(severity, AnomalySeverity::Critical | AnomalySeverity::High);
                // SECURITY (FIND-R174-006): Truncate user-supplied description.
                let desc = truncate_event_field(description);
                if immediate || ctx.violation_count >= self.config.lock_threshold {
                    (
                        SessionState::Locked,
                        TransitionAction::DenyAll {
                            reason: format!(
                                "Session locked: {} (violations: {})",
                                desc, ctx.violation_count
                            ),
                        },
                    )
                } else {
                    (
                        SessionState::Suspicious,
                        TransitionAction::Warn {
                            message: format!("Anomaly in suspicious session: {desc}"),
                        },
                    )
                }
            }
            (SessionState::Suspicious, SessionEvent::PolicyViolation { reason }) => {
                ctx.violation_count = ctx.violation_count.saturating_add(1);
                // SECURITY (FIND-R174-006): Truncate user-supplied reason.
                let rsn = truncate_event_field(reason);
                if ctx.violation_count >= self.config.lock_threshold {
                    (
                        SessionState::Locked,
                        TransitionAction::DenyAll {
                            reason: format!(
                                "Session locked after {} violations: {}",
                                ctx.violation_count, rsn
                            ),
                        },
                    )
                } else {
                    (
                        SessionState::Suspicious,
                        TransitionAction::Warn {
                            message: format!("Policy violation in suspicious session: {rsn}"),
                        },
                    )
                }
            }
            (SessionState::Suspicious, SessionEvent::RepeatedViolation { count }) => {
                // SECURITY (FIND-R174-003): count=0 should be a no-op, not escalate state.
                if *count == 0 {
                    return (SessionState::Suspicious, TransitionAction::None);
                }
                ctx.violation_count = ctx.violation_count.saturating_add(*count);
                (
                    SessionState::Locked,
                    TransitionAction::DenyAll {
                        reason: format!(
                            "Session locked: repeated violations ({} total)",
                            ctx.violation_count
                        ),
                    },
                )
            }
            (SessionState::Suspicious, SessionEvent::SessionEnd) => (
                SessionState::Ended,
                TransitionAction::AuditEvent {
                    event_type: "session_ended".to_string(),
                },
            ),

            // === Locked state ===
            (SessionState::Locked, SessionEvent::CooldownElapsed) => {
                // Validate that the cooldown period has actually elapsed (FIND-P23-S09)
                let cooldown_ok = ctx
                    .locked_at
                    .is_some_and(|locked| now.saturating_sub(locked) >= self.config.cooldown_secs);
                if cooldown_ok {
                    (
                        SessionState::Suspicious,
                        TransitionAction::Warn {
                            message: "Cooldown elapsed, session returning to Suspicious"
                                .to_string(),
                        },
                    )
                } else {
                    (
                        SessionState::Locked,
                        TransitionAction::DenyAll {
                            reason: format!(
                                "Cooldown period ({} secs) has not elapsed",
                                self.config.cooldown_secs
                            ),
                        },
                    )
                }
            }
            // SECURITY (FIND-R46-007): AdminUnlock requires a valid admin token.
            // The token is verified with constant-time comparison to prevent
            // timing side-channels. If no admin_unlock_token is configured,
            // admin unlock is disabled entirely (fail-closed).
            // SECURITY (FIND-R188-005): Rate-limit failed attempts — end session
            // after MAX_FAILED_UNLOCK_ATTEMPTS to prevent brute-force.
            (SessionState::Locked, SessionEvent::AdminUnlock { ref admin_token }) => {
                // Check if too many failed attempts already
                if ctx.failed_unlock_attempts >= MAX_FAILED_UNLOCK_ATTEMPTS {
                    return (
                        SessionState::Ended,
                        TransitionAction::DenyAll {
                            reason: format!(
                                "Admin unlock permanently denied: {} failed attempts exceeded limit ({})",
                                ctx.failed_unlock_attempts, MAX_FAILED_UNLOCK_ATTEMPTS
                            ),
                        },
                    );
                }
                let authorized = match &self.config.admin_unlock_token {
                    Some(expected) => {
                        use subtle::ConstantTimeEq;
                        expected.as_bytes().ct_eq(admin_token.as_bytes()).into()
                    }
                    None => false, // Fail-closed: no configured token → never authorize
                };
                if authorized {
                    ctx.anomaly_count = 0;
                    ctx.violation_count = 0;
                    ctx.failed_unlock_attempts = 0;
                    (
                        SessionState::Active,
                        TransitionAction::AuditEvent {
                            event_type: "session_admin_unlocked".to_string(),
                        },
                    )
                } else {
                    ctx.failed_unlock_attempts = ctx.failed_unlock_attempts.saturating_add(1);
                    if ctx.failed_unlock_attempts >= MAX_FAILED_UNLOCK_ATTEMPTS {
                        (
                            SessionState::Ended,
                            TransitionAction::DenyAll {
                                reason: format!(
                                    "Admin unlock permanently denied: {} failed attempts exceeded limit ({})",
                                    ctx.failed_unlock_attempts, MAX_FAILED_UNLOCK_ATTEMPTS
                                ),
                            },
                        )
                    } else {
                        (
                            SessionState::Locked,
                            TransitionAction::DenyAll {
                                reason: "Admin unlock denied: invalid or missing admin token"
                                    .to_string(),
                            },
                        )
                    }
                }
            }
            (SessionState::Locked, SessionEvent::SessionEnd) => (
                SessionState::Ended,
                TransitionAction::AuditEvent {
                    event_type: "session_ended".to_string(),
                },
            ),
            // All other events in Locked are denied
            (SessionState::Locked, _) => (
                SessionState::Locked,
                TransitionAction::DenyAll {
                    reason: "Session is locked".to_string(),
                },
            ),

            // === Ended state ===
            (SessionState::Ended, _) => (
                SessionState::Ended,
                TransitionAction::DenyAll {
                    reason: "Session has ended".to_string(),
                },
            ),

            // Default: stay in current state
            (state, _) => (state, TransitionAction::None),
        }
    }

    /// Get the current state of a session.
    ///
    /// Fail-closed: if the lock is poisoned, returns `Locked` (deny-all)
    /// rather than `Init` (allow-all). Unknown sessions return `Init`.
    pub fn get_state(&self, session_id: &str) -> SessionState {
        match self.sessions.read() {
            Ok(sessions) => sessions
                .get(session_id)
                .map(|ctx| ctx.state)
                .unwrap_or(SessionState::Init),
            Err(_poisoned) => {
                // Fail-closed: lock poisoned → treat as locked
                SessionState::Locked
            }
        }
    }

    /// Check if a session should deny all actions.
    /// Returns Some(reason) if the session is in a deny-all state, None otherwise.
    ///
    /// SECURITY (FIND-R198-004): Also enforces `max_session_duration_secs` by
    /// checking elapsed time since session start. Previously this was only checked
    /// in `process_event_at`, so sessions that exceeded their duration but had no
    /// new events would not be denied.
    ///
    /// Fail-closed: if the lock is poisoned, returns a deny reason.
    pub fn should_deny(&self, session_id: &str) -> Option<String> {
        // SECURITY (FIND-R216-005): Validate session_id before embedding in
        // denial strings or tracing fields. Prevents log injection and
        // reflected control characters in HTTP responses.
        if session_id.is_empty()
            || session_id.len() > MAX_SESSION_ID_LEN
            || vellaveto_types::has_dangerous_chars(session_id)
        {
            return Some("Session ID invalid — fail-closed deny".to_string());
        }

        // Phase 1: read-only check for terminal states and expiry detection.
        let expired = match self.sessions.read() {
            Ok(sessions) => {
                match sessions.get(session_id) {
                    Some(ctx) => match ctx.state {
                        SessionState::Locked => {
                            return Some(format!("Session '{session_id}' is locked"));
                        }
                        SessionState::Ended => {
                            return Some(format!("Session '{session_id}' has ended"));
                        }
                        _ => {
                            // SECURITY (FIND-R198-004): Check max_session_duration_secs
                            // even between events, using current wall-clock time.
                            if self.config.max_session_duration_secs > 0 {
                                let now = Self::now();
                                if now.saturating_sub(ctx.started_at)
                                    >= self.config.max_session_duration_secs
                                {
                                    true // expired — need write lock to transition
                                } else {
                                    return None; // not expired
                                }
                            } else {
                                return None; // no duration limit
                            }
                        }
                    },
                    None => return None, // session not found
                }
            }
            Err(_poisoned) => {
                // Fail-closed: lock poisoned → deny
                return Some("Session guard lock poisoned — fail-closed deny".to_string());
            }
        };

        // Phase 2: SECURITY (FIND-R212-003): Transition expired sessions to Ended
        // state so subsequent checks short-circuit without re-computing expiry.
        if expired {
            match self.sessions.write() {
                Ok(mut sessions) => {
                    if let Some(ctx) = sessions.get_mut(session_id) {
                        // Double-check: another thread may have transitioned it already.
                        if ctx.state != SessionState::Ended && ctx.state != SessionState::Locked {
                            let old = ctx.state;
                            let now = Self::now();
                            ctx.state = SessionState::Ended;
                            ctx.last_action_at = now;
                            if ctx.transition_history.len() < MAX_TRANSITION_HISTORY {
                                ctx.transition_history.push((old, SessionState::Ended, now));
                            }
                            tracing::info!(
                                session_id = session_id,
                                "Session expired — transitioned {} → Ended",
                                old
                            );
                        }
                    }
                }
                Err(_poisoned) => {
                    // SECURITY (FIND-R218-004): Log write-lock poisoning so operators
                    // can detect the condition. The denial is still returned (fail-closed)
                    // but without persisting the Ended transition, every subsequent call
                    // will re-compute expiry instead of short-circuiting.
                    tracing::error!(
                        session_id = session_id,
                        "SessionGuard write lock poisoned — unable to persist expiry transition"
                    );
                }
            }
            // Fail-closed: even if write lock fails, still deny.
            Some(format!(
                "Session '{}' exceeded max duration ({} seconds)",
                session_id, self.config.max_session_duration_secs
            ))
        } else {
            None
        }
    }

    /// Get a summary of a session's state and history.
    pub fn session_summary(&self, session_id: &str) -> Option<SessionSummary> {
        self.sessions.read().ok().and_then(|sessions| {
            sessions.get(session_id).map(|ctx| SessionSummary {
                state: ctx.state,
                anomaly_count: ctx.anomaly_count,
                violation_count: ctx.violation_count,
                started_at: ctx.started_at,
                last_action_at: ctx.last_action_at,
                transitions: ctx.transition_history.clone(),
            })
        })
    }

    // ═══════════════════════════════════════════════════════════════
    // Integration with WorkflowTracker and GoalTracker
    // ═══════════════════════════════════════════════════════════════

    /// Integrate an alert from the WorkflowTracker.
    pub fn integrate_workflow_alert(
        &self,
        session_id: &str,
        alert: &WorkflowAlert,
    ) -> Result<TransitionResult, SessionGuardError> {
        let severity = workflow_alert_to_severity(alert.severity);
        self.process_event(
            session_id,
            SessionEvent::AnomalyDetected {
                severity,
                description: format!(
                    "Workflow alert ({:?}): {}",
                    alert.alert_type, alert.description
                ),
            },
        )
    }

    /// Integrate a goal drift alert from the GoalTracker.
    pub fn integrate_goal_drift(
        &self,
        session_id: &str,
        drift: &GoalDriftAlert,
    ) -> Result<TransitionResult, SessionGuardError> {
        // Map similarity score to anomaly severity:
        // 0.0 = completely different (Critical), 1.0 = identical (Low)
        // SECURITY (FIND-R174-001): NaN/Infinity/negative values fail-closed to Critical.
        // NaN causes all `<` comparisons to return false, falling through to Low.
        let severity = if !drift.similarity.is_finite() || drift.similarity < 0.2 {
            AnomalySeverity::Critical
        } else if drift.similarity < 0.4 {
            AnomalySeverity::High
        } else if drift.similarity < 0.6 {
            AnomalySeverity::Medium
        } else {
            AnomalySeverity::Low
        };

        self.process_event(
            session_id,
            SessionEvent::AnomalyDetected {
                severity,
                description: format!(
                    "Goal drift detected (similarity: {:.2}): {}",
                    drift.similarity, drift.description
                ),
            },
        )
    }
}

/// Map workflow alert severity (u8 1-5) to AnomalySeverity.
fn workflow_alert_to_severity(severity: u8) -> AnomalySeverity {
    match severity {
        0..=1 => AnomalySeverity::Low,
        2 => AnomalySeverity::Medium,
        3 => AnomalySeverity::High,
        _ => AnomalySeverity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow_tracker::WorkflowAlertType;

    fn default_guard() -> SessionGuard {
        SessionGuard::new(SessionGuardConfig::default())
    }

    fn guard_with_thresholds(suspicious: u32, lock: u32) -> SessionGuard {
        SessionGuard::new(SessionGuardConfig {
            suspicious_threshold: suspicious,
            lock_threshold: lock,
            ..Default::default()
        })
    }

    #[test]
    fn test_init_to_active_on_first_action() {
        let guard = default_guard();
        let result = guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        assert_eq!(result.previous, SessionState::Init);
        assert_eq!(result.current, SessionState::Active);
    }

    #[test]
    fn test_active_stays_active_on_normal_action() {
        let guard = default_guard();
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        let result = guard
            .process_event("s1", SessionEvent::NormalAction)
            .unwrap();
        assert_eq!(result.current, SessionState::Active);
    }

    #[test]
    fn test_active_to_suspicious_on_threshold() {
        let guard = guard_with_thresholds(2, 5);

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();

        // First anomaly — stays Active
        let r1 = guard
            .process_event(
                "s1",
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Low,
                    description: "anomaly 1".to_string(),
                },
            )
            .unwrap();
        assert_eq!(r1.current, SessionState::Active);

        // Second anomaly — triggers Suspicious (threshold=2)
        let r2 = guard
            .process_event(
                "s1",
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Low,
                    description: "anomaly 2".to_string(),
                },
            )
            .unwrap();
        assert_eq!(r2.current, SessionState::Suspicious);
    }

    #[test]
    fn test_critical_anomaly_immediate_suspicious() {
        let guard = guard_with_thresholds(10, 10);
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();

        let result = guard
            .process_event(
                "s1",
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Critical,
                    description: "critical issue".to_string(),
                },
            )
            .unwrap();
        assert_eq!(result.current, SessionState::Suspicious);
    }

    #[test]
    fn test_suspicious_to_locked_on_violations() {
        let guard = guard_with_thresholds(1, 2);

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();

        // Trigger Suspicious
        guard
            .process_event(
                "s1",
                SessionEvent::PolicyViolation {
                    reason: "v1".to_string(),
                },
            )
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Suspicious);

        // Second violation triggers Locked (lock_threshold=2)
        let result = guard
            .process_event(
                "s1",
                SessionEvent::PolicyViolation {
                    reason: "v2".to_string(),
                },
            )
            .unwrap();
        assert_eq!(result.current, SessionState::Locked);
    }

    #[test]
    fn test_locked_denies_normal_actions() {
        let guard = guard_with_thresholds(1, 1);

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        guard
            .process_event(
                "s1",
                SessionEvent::PolicyViolation {
                    reason: "v1".to_string(),
                },
            )
            .unwrap();
        // Now in Suspicious; one more violation → Locked
        guard
            .process_event(
                "s1",
                SessionEvent::PolicyViolation {
                    reason: "v2".to_string(),
                },
            )
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Locked);

        // Normal action should be denied
        let result = guard
            .process_event("s1", SessionEvent::NormalAction)
            .unwrap();
        assert_eq!(result.current, SessionState::Locked);
        assert!(matches!(result.action, TransitionAction::DenyAll { .. }));
    }

    #[test]
    fn test_locked_cooldown_to_suspicious() {
        let guard = SessionGuard::new(SessionGuardConfig {
            suspicious_threshold: 1,
            lock_threshold: 1,
            cooldown_secs: 60, // 60 second cooldown
            ..Default::default()
        });

        guard
            .process_event_at("s1", SessionEvent::FirstAction, 1000)
            .unwrap();
        guard
            .process_event_at("s1", SessionEvent::RepeatedViolation { count: 2 }, 1001)
            .unwrap();
        // Should be in Suspicious now; one more to lock it
        guard
            .process_event_at("s1", SessionEvent::RepeatedViolation { count: 1 }, 1002)
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Locked);

        // Premature cooldown — should be rejected
        let result = guard
            .process_event_at("s1", SessionEvent::CooldownElapsed, 1010)
            .unwrap();
        assert_eq!(result.current, SessionState::Locked);

        // Proper cooldown — after 60 seconds
        let result = guard
            .process_event_at("s1", SessionEvent::CooldownElapsed, 1062)
            .unwrap();
        assert_eq!(result.current, SessionState::Suspicious);
    }

    #[test]
    fn test_admin_unlock_to_active() {
        let guard = SessionGuard::new(SessionGuardConfig {
            suspicious_threshold: 1,
            lock_threshold: 1,
            admin_unlock_token: Some("correct-token".to_string()),
            ..Default::default()
        });

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 2 })
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 1 })
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Locked);

        let result = guard
            .process_event(
                "s1",
                SessionEvent::AdminUnlock {
                    admin_token: "correct-token".to_string(),
                },
            )
            .unwrap();
        assert_eq!(result.current, SessionState::Active);
    }

    // SECURITY (FIND-R46-007): Admin unlock must be rejected with wrong token
    #[test]
    fn test_admin_unlock_rejected_with_wrong_token() {
        let guard = SessionGuard::new(SessionGuardConfig {
            suspicious_threshold: 1,
            lock_threshold: 1,
            admin_unlock_token: Some("correct-token".to_string()),
            ..Default::default()
        });

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 2 })
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 1 })
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Locked);

        // Wrong token → stays Locked
        let result = guard
            .process_event(
                "s1",
                SessionEvent::AdminUnlock {
                    admin_token: "wrong-token".to_string(),
                },
            )
            .unwrap();
        assert_eq!(result.current, SessionState::Locked);
        assert!(matches!(result.action, TransitionAction::DenyAll { .. }));
    }

    // SECURITY (FIND-R46-007): Admin unlock disabled when no token configured
    #[test]
    fn test_admin_unlock_rejected_when_no_token_configured() {
        let guard = guard_with_thresholds(1, 1);
        // Default config has admin_unlock_token: None

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 2 })
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 1 })
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Locked);

        // Any token → stays Locked because no admin_unlock_token configured
        let result = guard
            .process_event(
                "s1",
                SessionEvent::AdminUnlock {
                    admin_token: "any-token".to_string(),
                },
            )
            .unwrap();
        assert_eq!(result.current, SessionState::Locked);
        assert!(matches!(result.action, TransitionAction::DenyAll { .. }));
    }

    #[test]
    fn test_should_deny_in_locked() {
        let guard = guard_with_thresholds(1, 1);

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        assert!(guard.should_deny("s1").is_none());

        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 2 })
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 1 })
            .unwrap();
        assert!(guard.should_deny("s1").is_some());
    }

    #[test]
    fn test_should_deny_none_in_active() {
        let guard = default_guard();
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        assert!(guard.should_deny("s1").is_none());
    }

    #[test]
    fn test_session_end_from_any_state() {
        let guard = default_guard();

        // End from Init
        let r = guard.process_event("s1", SessionEvent::SessionEnd).unwrap();
        assert_eq!(r.current, SessionState::Ended);

        // End from Active
        guard
            .process_event("s2", SessionEvent::FirstAction)
            .unwrap();
        let r = guard.process_event("s2", SessionEvent::SessionEnd).unwrap();
        assert_eq!(r.current, SessionState::Ended);
    }

    #[test]
    fn test_ended_state_is_terminal() {
        let guard = default_guard();
        guard.process_event("s1", SessionEvent::SessionEnd).unwrap();

        let r = guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        assert_eq!(r.current, SessionState::Ended);
        assert!(matches!(r.action, TransitionAction::DenyAll { .. }));
    }

    #[test]
    fn test_session_summary() {
        let guard = default_guard();
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        guard
            .process_event(
                "s1",
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Low,
                    description: "test".to_string(),
                },
            )
            .unwrap();

        let summary = guard.session_summary("s1").unwrap();
        assert_eq!(summary.state, SessionState::Active);
        assert_eq!(summary.anomaly_count, 1);
        assert!(!summary.transitions.is_empty());
    }

    #[test]
    fn test_concurrent_session_isolation() {
        let guard = guard_with_thresholds(1, 1);

        // s1 becomes Suspicious
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        guard
            .process_event(
                "s1",
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Medium,
                    description: "test".to_string(),
                },
            )
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Suspicious);

        // s2 should still be Active
        guard
            .process_event("s2", SessionEvent::FirstAction)
            .unwrap();
        assert_eq!(guard.get_state("s2"), SessionState::Active);
    }

    #[test]
    fn test_config_defaults() {
        let config = SessionGuardConfig::default();
        assert_eq!(config.suspicious_threshold, 3);
        assert_eq!(config.lock_threshold, 5);
        assert_eq!(config.cooldown_secs, 300);
        assert_eq!(config.max_session_duration_secs, 3600);
        assert_eq!(config.max_sessions, 10000);
    }

    #[test]
    fn test_workflow_alert_integration() {
        let guard = guard_with_thresholds(1, 5);
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();

        let alert = WorkflowAlert {
            session_id: "s1".to_string(),
            alert_type: WorkflowAlertType::ExfiltrationChain,
            description: "Data exfiltration detected".to_string(),
            involved_actions: vec!["read_file".to_string(), "send_email".to_string()],
            severity: 4,
        };

        let result = guard.integrate_workflow_alert("s1", &alert).unwrap();
        assert_eq!(result.current, SessionState::Suspicious);
    }

    #[test]
    fn test_goal_drift_integration() {
        let guard = guard_with_thresholds(1, 5);
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();

        let drift = GoalDriftAlert {
            session_id: "s1".to_string(),
            original_goal: "Summarize document".to_string(),
            current_goal: "Delete all files".to_string(),
            similarity: 0.1,
            description: "Goal completely changed".to_string(),
        };

        let result = guard.integrate_goal_drift("s1", &drift).unwrap();
        assert_eq!(result.current, SessionState::Suspicious);
    }

    #[test]
    fn test_max_sessions_eviction() {
        let guard = SessionGuard::new(SessionGuardConfig {
            max_sessions: 3,
            ..Default::default()
        });

        guard
            .process_event_at("s1", SessionEvent::FirstAction, 100)
            .unwrap();
        guard
            .process_event_at("s2", SessionEvent::FirstAction, 200)
            .unwrap();
        guard
            .process_event_at("s3", SessionEvent::FirstAction, 300)
            .unwrap();

        // Adding a 4th should evict s1 (oldest last_action_at among non-Locked/non-Ended)
        guard
            .process_event_at("s4", SessionEvent::FirstAction, 400)
            .unwrap();

        // s1 was evicted — returns Init (unknown session)
        assert_eq!(guard.get_state("s1"), SessionState::Init);
        assert_eq!(guard.get_state("s2"), SessionState::Active);
        assert_eq!(guard.get_state("s3"), SessionState::Active);
        assert_eq!(guard.get_state("s4"), SessionState::Active);
    }

    #[test]
    fn test_locked_sessions_not_evicted() {
        let guard = SessionGuard::new(SessionGuardConfig {
            max_sessions: 2,
            suspicious_threshold: 1,
            lock_threshold: 1,
            ..Default::default()
        });

        // Create and lock s1
        guard
            .process_event_at("s1", SessionEvent::FirstAction, 100)
            .unwrap();
        guard
            .process_event_at("s1", SessionEvent::RepeatedViolation { count: 2 }, 101)
            .unwrap();
        guard
            .process_event_at("s1", SessionEvent::RepeatedViolation { count: 1 }, 102)
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Locked);

        // Create s2
        guard
            .process_event_at("s2", SessionEvent::FirstAction, 200)
            .unwrap();

        // Creating s3 should evict s2 (Active), NOT s1 (Locked)
        guard
            .process_event_at("s3", SessionEvent::FirstAction, 300)
            .unwrap();

        // s1 should still be Locked (not evicted)
        assert_eq!(guard.get_state("s1"), SessionState::Locked);
        // s2 was evicted
        assert_eq!(guard.get_state("s2"), SessionState::Init);
        assert_eq!(guard.get_state("s3"), SessionState::Active);
    }

    /// SECURITY (FIND-R113-001): Suspicious sessions are not evicted.
    #[test]
    fn test_suspicious_sessions_not_evicted() {
        let guard = SessionGuard::new(SessionGuardConfig {
            max_sessions: 2,
            suspicious_threshold: 2,
            lock_threshold: 5,
            ..Default::default()
        });

        // Create s1 and push to Suspicious
        guard
            .process_event_at("s1", SessionEvent::FirstAction, 100)
            .unwrap();
        guard
            .process_event_at(
                "s1",
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Medium,
                    description: "test".to_string(),
                },
                101,
            )
            .unwrap();
        guard
            .process_event_at(
                "s1",
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Medium,
                    description: "test".to_string(),
                },
                102,
            )
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Suspicious);

        // Create s2
        guard
            .process_event_at("s2", SessionEvent::FirstAction, 200)
            .unwrap();

        // Creating s3 should fail (s1=Suspicious, s2=Active — only s2 is evictable,
        // but we need space for s3, so s2 gets evicted)
        guard
            .process_event_at("s3", SessionEvent::FirstAction, 300)
            .unwrap();

        // s1 should still be Suspicious (not evicted)
        assert_eq!(guard.get_state("s1"), SessionState::Suspicious);
        // s2 was evicted
        assert_eq!(guard.get_state("s2"), SessionState::Init);
        assert_eq!(guard.get_state("s3"), SessionState::Active);
    }

    #[test]
    fn test_unknown_session_returns_init() {
        let guard = default_guard();
        assert_eq!(guard.get_state("nonexistent"), SessionState::Init);
    }

    #[test]
    fn test_summary_serialization() {
        let summary = SessionSummary {
            state: SessionState::Active,
            anomaly_count: 2,
            violation_count: 1,
            started_at: 1700000000,
            last_action_at: 1700000100,
            transitions: vec![(SessionState::Init, SessionState::Active, 1700000000)],
        };

        let json = serde_json::to_string(&summary).expect("Should serialize");
        let deserialized: SessionSummary = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized.state, SessionState::Active);
        assert_eq!(deserialized.anomaly_count, 2);
    }

    #[test]
    fn test_summary_deny_unknown_fields() {
        let json = r#"{"state":"Active","anomaly_count":2,"violation_count":1,"started_at":1700000000,"last_action_at":1700000100,"transitions":[],"extra":"bad"}"#;
        let result: Result<SessionSummary, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "SessionSummary should reject unknown fields"
        );
    }

    #[test]
    fn test_transition_result_deny_unknown_fields() {
        let json = r#"{"previous":"Init","current":"Active","action":"None","extra":"bad"}"#;
        let result: Result<TransitionResult, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "TransitionResult should reject unknown fields"
        );
    }

    /// IMP-R122-005: Transitions beyond MAX_TRANSITION_HISTORY are silently
    /// dropped. This test verifies the bound is enforced and the state machine
    /// still works correctly even when the history is full.
    ///
    /// Only actual state changes are recorded in the transition history.
    /// We use SessionContext::record_transition directly to fill the history
    /// quickly, then verify that additional transitions are silently dropped.
    #[test]
    fn test_transition_history_bounded_at_max() {
        let guard = default_guard();
        let sid = "bounded-test";
        let base_ts = 1700000000u64;

        // First action transitions Init → Active (1 transition)
        guard
            .process_event_at(sid, SessionEvent::FirstAction, base_ts)
            .unwrap();

        let summary = guard.session_summary(sid).unwrap();
        assert_eq!(summary.transitions.len(), 1);

        // Manually fill the transition history via the guard's lock.
        // This is a unit test for the bounding behavior, not integration testing.
        {
            let mut sessions = guard.sessions.write().unwrap();
            let ctx = sessions.get_mut(sid).unwrap();
            // Fill from current len (1) up to MAX_TRANSITION_HISTORY
            for i in ctx.transition_history.len()..MAX_TRANSITION_HISTORY {
                ctx.transition_history.push((
                    SessionState::Active,
                    SessionState::Suspicious,
                    base_ts + i as u64,
                ));
            }
            assert_eq!(ctx.transition_history.len(), MAX_TRANSITION_HISTORY);
        }

        let summary = guard.session_summary(sid).unwrap();
        assert_eq!(summary.transitions.len(), MAX_TRANSITION_HISTORY);

        // Now trigger a real state change: anomaly should try to record
        // a transition but the history is full — it should be silently dropped.
        let result = guard
            .process_event_at(
                sid,
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Critical,
                    description: "test".to_string(),
                },
                base_ts + MAX_TRANSITION_HISTORY as u64 + 1,
            )
            .unwrap();

        // The state change DID happen
        assert_eq!(result.current, SessionState::Suspicious);

        let summary2 = guard.session_summary(sid).unwrap();
        // But the transition history was NOT extended
        assert_eq!(
            summary2.transitions.len(),
            MAX_TRANSITION_HISTORY,
            "History must not grow beyond MAX_TRANSITION_HISTORY"
        );
        // State machine still works
        assert_eq!(summary2.state, SessionState::Suspicious);
    }

    // ═══════════════════════════════════════════════════════════════
    // Round 174 validation tests (IMP-R174-001 through IMP-R174-004)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_process_event_rejects_empty_session_id() {
        let guard = default_guard();
        let result = guard.process_event("", SessionEvent::FirstAction);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("empty"),
            "Should mention empty"
        );
    }

    #[test]
    fn test_process_event_rejects_overlong_session_id() {
        let guard = default_guard();
        let long_id = "x".repeat(MAX_SESSION_ID_LEN + 1);
        let result = guard.process_event(&long_id, SessionEvent::FirstAction);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("exceeds maximum"),
            "Should mention exceeds maximum"
        );
    }

    #[test]
    fn test_process_event_rejects_control_char_session_id() {
        let guard = default_guard();
        let result = guard.process_event("session\x00id", SessionEvent::FirstAction);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("control or Unicode format"),
            "Should mention dangerous characters"
        );
    }

    #[test]
    fn test_process_event_rejects_unicode_format_session_id() {
        let guard = default_guard();
        // Zero-width space U+200B
        let result = guard.process_event("session\u{200B}id", SessionEvent::FirstAction);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("control or Unicode format"),
            "Should mention dangerous characters"
        );
    }

    #[test]
    fn test_active_repeated_violation_count_zero_is_noop() {
        let guard = default_guard();
        let sid = "zero-count";
        guard.process_event(sid, SessionEvent::FirstAction).unwrap();
        let result = guard
            .process_event(sid, SessionEvent::RepeatedViolation { count: 0 })
            .unwrap();
        assert_eq!(result.current, SessionState::Active);
        assert!(matches!(result.action, TransitionAction::None));
    }

    #[test]
    fn test_suspicious_repeated_violation_count_zero_is_noop() {
        let guard = SessionGuard::new(SessionGuardConfig {
            suspicious_threshold: 1,
            ..Default::default()
        });
        let sid = "zero-count-sus";
        guard.process_event(sid, SessionEvent::FirstAction).unwrap();
        // Push to Suspicious via anomaly
        guard
            .process_event(
                sid,
                SessionEvent::AnomalyDetected {
                    severity: AnomalySeverity::Critical,
                    description: "test".to_string(),
                },
            )
            .unwrap();
        assert_eq!(guard.get_state(sid), SessionState::Suspicious);
        // RepeatedViolation{count:0} should be noop
        let result = guard
            .process_event(sid, SessionEvent::RepeatedViolation { count: 0 })
            .unwrap();
        assert_eq!(result.current, SessionState::Suspicious);
        assert!(matches!(result.action, TransitionAction::None));
    }

    #[test]
    fn test_goal_drift_nan_similarity_maps_to_critical() {
        let guard = default_guard();
        let sid = "nan-drift";
        guard.process_event(sid, SessionEvent::FirstAction).unwrap();
        let drift = crate::goal_tracking::GoalDriftAlert {
            session_id: sid.to_string(),
            similarity: f32::NAN,
            description: "NaN test".to_string(),
            original_goal: "goal".to_string(),
            current_goal: "other".to_string(),
        };
        let result = guard.integrate_goal_drift(sid, &drift).unwrap();
        // NaN should map to Critical → Active → Suspicious immediately
        assert_eq!(result.current, SessionState::Suspicious);
    }

    #[test]
    fn test_goal_drift_negative_similarity_maps_to_critical() {
        let guard = default_guard();
        let sid = "neg-drift";
        guard.process_event(sid, SessionEvent::FirstAction).unwrap();
        let drift = crate::goal_tracking::GoalDriftAlert {
            session_id: sid.to_string(),
            similarity: -1.0,
            description: "negative test".to_string(),
            original_goal: "goal".to_string(),
            current_goal: "other".to_string(),
        };
        let result = guard.integrate_goal_drift(sid, &drift).unwrap();
        assert_eq!(result.current, SessionState::Suspicious);
    }

    #[test]
    fn test_truncate_event_field_under_limit() {
        let short = "hello world";
        assert_eq!(truncate_event_field(short), short);
    }

    #[test]
    fn test_truncate_event_field_over_limit() {
        let long = "x".repeat(MAX_EVENT_FIELD_LEN + 100);
        let result = truncate_event_field(&long);
        assert!(result.len() <= MAX_EVENT_FIELD_LEN);
        assert!(result.len() >= MAX_EVENT_FIELD_LEN - 4); // allow char boundary adjustment
    }

    #[test]
    fn test_truncate_event_field_multibyte_boundary() {
        // Create a string of 2-byte chars (e.g., ñ = 0xC3 0xB1)
        let multibyte = "ñ".repeat(MAX_EVENT_FIELD_LEN);
        let result = truncate_event_field(&multibyte);
        assert!(result.len() <= MAX_EVENT_FIELD_LEN);
        // Should end on a char boundary (even number of bytes for ñ)
        assert!(result.is_char_boundary(result.len()));
    }

    // SECURITY (FIND-R188-001): max_session_duration_secs enforcement
    #[test]
    fn test_session_duration_exceeded_ends_session() {
        let guard = SessionGuard::new(SessionGuardConfig {
            max_session_duration_secs: 60,
            ..Default::default()
        });
        guard
            .process_event_at("s1", SessionEvent::FirstAction, 1000)
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Active);

        // Action at 1061 (>60s) should end the session
        let result = guard
            .process_event_at("s1", SessionEvent::NormalAction, 1061)
            .unwrap();
        assert_eq!(result.current, SessionState::Ended);
        match result.action {
            TransitionAction::DenyAll { reason } => {
                assert!(reason.contains("duration exceeded"), "reason: {reason}");
            }
            _ => panic!("expected DenyAll"),
        }
    }

    #[test]
    fn test_session_duration_within_limit_ok() {
        let guard = SessionGuard::new(SessionGuardConfig {
            max_session_duration_secs: 60,
            ..Default::default()
        });
        guard
            .process_event_at("s1", SessionEvent::FirstAction, 1000)
            .unwrap();
        // Action at 1059 (<60s) is fine
        let result = guard
            .process_event_at("s1", SessionEvent::NormalAction, 1059)
            .unwrap();
        assert_eq!(result.current, SessionState::Active);
    }

    // SECURITY (FIND-R188-005): AdminUnlock brute-force rate limiting
    #[test]
    fn test_admin_unlock_brute_force_ends_session() {
        let guard = SessionGuard::new(SessionGuardConfig {
            suspicious_threshold: 1,
            lock_threshold: 1,
            admin_unlock_token: Some("correct-token".to_string()),
            ..Default::default()
        });

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 2 })
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 1 })
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Locked);

        // Send MAX_FAILED_UNLOCK_ATTEMPTS wrong tokens
        for i in 0..MAX_FAILED_UNLOCK_ATTEMPTS {
            let result = guard
                .process_event(
                    "s1",
                    SessionEvent::AdminUnlock {
                        admin_token: format!("wrong-{i}"),
                    },
                )
                .unwrap();
            if i < MAX_FAILED_UNLOCK_ATTEMPTS - 1 {
                assert_eq!(result.current, SessionState::Locked, "attempt {i}");
            } else {
                // Last failed attempt ends the session
                assert_eq!(result.current, SessionState::Ended, "attempt {i}");
                match result.action {
                    TransitionAction::DenyAll { reason } => {
                        assert!(reason.contains("failed attempts"), "reason: {reason}");
                    }
                    _ => panic!("expected DenyAll on final failed attempt"),
                }
            }
        }
    }

    #[test]
    fn test_admin_unlock_success_resets_attempts() {
        let guard = SessionGuard::new(SessionGuardConfig {
            suspicious_threshold: 1,
            lock_threshold: 1,
            admin_unlock_token: Some("correct-token".to_string()),
            ..Default::default()
        });

        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 2 })
            .unwrap();
        guard
            .process_event("s1", SessionEvent::RepeatedViolation { count: 1 })
            .unwrap();
        assert_eq!(guard.get_state("s1"), SessionState::Locked);

        // 3 wrong attempts (under limit)
        for _ in 0..3 {
            guard
                .process_event(
                    "s1",
                    SessionEvent::AdminUnlock {
                        admin_token: "wrong".to_string(),
                    },
                )
                .unwrap();
        }

        // Correct token succeeds
        let result = guard
            .process_event(
                "s1",
                SessionEvent::AdminUnlock {
                    admin_token: "correct-token".to_string(),
                },
            )
            .unwrap();
        assert_eq!(result.current, SessionState::Active);
    }

    // SECURITY (FIND-R198-004): should_deny() enforces max_session_duration_secs
    #[test]
    fn test_should_deny_enforces_duration_limit() {
        let guard = SessionGuard::new(SessionGuardConfig {
            max_session_duration_secs: 60,
            ..Default::default()
        });
        // Start session at t=1000
        guard
            .process_event_at("s1", SessionEvent::FirstAction, 1000)
            .unwrap();

        // Within duration: should_deny returns None
        // Note: should_deny uses Self::now() which uses real wall-clock time,
        // so the session started at t=1000 (epoch seconds) is always in the past.
        // A session with max_duration=60 started at t=1000 will have expired by
        // the current time (well past 1060). This validates the duration check.
        let result = guard.should_deny("s1");
        assert!(
            result.is_some(),
            "should_deny should reject expired session, got: None"
        );
        assert!(
            result.as_ref().unwrap().contains("exceeded max duration"),
            "got: {result:?}"
        );
    }

    // SECURITY (IMP-R218-003): should_deny() transitions expired sessions to Ended
    // so subsequent checks short-circuit without re-computing expiry every call.
    #[test]
    fn test_should_deny_transitions_expired_to_ended() {
        let guard = SessionGuard::new(SessionGuardConfig {
            max_session_duration_secs: 60,
            ..Default::default()
        });
        // Start session at t=1000 (far in the past — always expired)
        guard
            .process_event_at("s1", SessionEvent::FirstAction, 1000)
            .unwrap();

        // State should be Active before should_deny
        assert_eq!(guard.get_state("s1"), SessionState::Active);

        // First should_deny detects expiry and transitions to Ended
        let result = guard.should_deny("s1");
        assert!(result.is_some(), "should deny expired session");
        assert_eq!(
            guard.get_state("s1"),
            SessionState::Ended,
            "should_deny must transition expired Active → Ended"
        );

        // Second should_deny short-circuits on Ended state (different reason string)
        let result2 = guard.should_deny("s1");
        assert!(result2.is_some(), "should still deny ended session");
        assert!(
            result2.as_ref().unwrap().contains("has ended"),
            "subsequent deny should be 'has ended' (short-circuit), got: {result2:?}"
        );
    }

    #[test]
    fn test_should_deny_no_duration_limit_allows() {
        let guard = SessionGuard::new(SessionGuardConfig {
            max_session_duration_secs: 0, // unlimited
            ..Default::default()
        });
        guard
            .process_event("s1", SessionEvent::FirstAction)
            .unwrap();
        assert!(
            guard.should_deny("s1").is_none(),
            "unlimited duration should not deny"
        );
    }

    #[test]
    fn test_should_deny_unknown_session_returns_none() {
        let guard = default_guard();
        assert!(guard.should_deny("nonexistent").is_none());
    }

    // ── Session persistence backend tests ────────────────────────────────

    /// Test backend that records persisted sessions in a shared map.
    struct MockBackend {
        store: std::sync::Mutex<HashMap<String, SessionContext>>,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                store: std::sync::Mutex::new(HashMap::new()),
            }
        }
    }

    impl SessionBackend for MockBackend {
        fn store(&self, session_id: &str, ctx: &SessionContext) -> Result<(), String> {
            self.store
                .lock()
                .map_err(|_| "lock".to_string())?
                .insert(session_id.to_string(), ctx.clone());
            Ok(())
        }

        fn remove(&self, session_id: &str) -> Result<(), String> {
            self.store
                .lock()
                .map_err(|_| "lock".to_string())?
                .remove(session_id);
            Ok(())
        }

        fn load_all(&self) -> Result<Vec<(String, SessionContext)>, String> {
            Ok(self
                .store
                .lock()
                .map_err(|_| "lock".to_string())?
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        }
    }

    #[test]
    fn test_session_backend_write_through_on_transition() {
        let backend = std::sync::Arc::new(MockBackend::new());
        let guard = SessionGuard::new(SessionGuardConfig::default())
            .with_backend(Box::new(MockBackendRef(backend.clone())));
        guard
            .process_event("sess-1", SessionEvent::NormalAction)
            .unwrap();
        let store = backend.store.lock().unwrap();
        assert!(
            store.contains_key("sess-1"),
            "session should be persisted after transition"
        );
    }

    #[test]
    fn test_warm_restart_restores_locked_sessions() {
        let backend = std::sync::Arc::new(MockBackend::new());
        // Pre-populate the backend with a Locked session
        {
            let mut ctx = SessionContext::new(1000);
            ctx.state = SessionState::Locked;
            ctx.locked_at = Some(1000);
            backend
                .store
                .lock()
                .unwrap()
                .insert("locked-1".to_string(), ctx);
        }
        let guard = SessionGuard::new(SessionGuardConfig::default())
            .with_backend(Box::new(MockBackendRef(backend.clone())));
        let count = guard.warm_restart().unwrap();
        assert_eq!(count, 1, "should restore 1 Locked session");
        assert!(
            guard.should_deny("locked-1").is_some(),
            "restored Locked session should deny"
        );
    }

    #[test]
    fn test_warm_restart_skips_active_sessions() {
        let backend = std::sync::Arc::new(MockBackend::new());
        {
            let ctx = SessionContext::new(1000); // state = Init
            backend
                .store
                .lock()
                .unwrap()
                .insert("init-1".to_string(), ctx);
        }
        let guard = SessionGuard::new(SessionGuardConfig::default())
            .with_backend(Box::new(MockBackendRef(backend.clone())));
        let count = guard.warm_restart().unwrap();
        assert_eq!(count, 0, "should not restore Init sessions");
    }

    #[test]
    fn test_warm_restart_no_backend_returns_error() {
        let guard = SessionGuard::new(SessionGuardConfig::default());
        assert!(
            guard.warm_restart().is_err(),
            "no backend should return error"
        );
    }

    /// Wrapper to make Arc<MockBackend> implement SessionBackend.
    struct MockBackendRef(std::sync::Arc<MockBackend>);

    impl SessionBackend for MockBackendRef {
        fn store(&self, session_id: &str, ctx: &SessionContext) -> Result<(), String> {
            self.0.store(session_id, ctx)
        }
        fn remove(&self, session_id: &str) -> Result<(), String> {
            self.0.remove(session_id)
        }
        fn load_all(&self) -> Result<Vec<(String, SessionContext)>, String> {
            self.0.load_all()
        }
    }
}
