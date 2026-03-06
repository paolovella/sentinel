// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Confused deputy prevention (OWASP ASI02).
//!
//! Tracks principal delegation chains to prevent unauthorized tool access
//! through confused deputy attacks. A confused deputy attack occurs when
//! a privileged agent is tricked into acting on behalf of an unprivileged
//! attacker.
//!
//! # Example
//!
//! ```rust,ignore
//! use vellaveto_engine::deputy::DeputyValidator;
//!
//! let validator = DeputyValidator::new(3);
//!
//! // Register a delegation
//! validator.register_delegation(
//!     "session-1",
//!     "admin",
//!     "worker-agent",
//!     &["read_file", "write_file"],
//! ).unwrap();
//!
//! // Validate action
//! let result = validator.validate_action(
//!     "session-1",
//!     "read_file",
//!     "worker-agent",
//! );
//! assert!(result.is_ok());
//! ```

use crate::PatternMatcher;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use vellaveto_types::PrincipalContext;

/// Error types for deputy validation.
#[derive(Debug, Clone)]
pub enum DeputyError {
    /// Delegation from one principal to another is not authorized.
    UnauthorizedDelegation { from: String, to: String },
    /// Delegation chain is too deep.
    DelegationDepthExceeded { depth: u8, max: u8 },
    /// Tool is not in the delegation's allowed set.
    ToolNotInDelegation { tool: String },
    /// Delegation has expired.
    DelegationExpired,
    /// Principal in request doesn't match expected.
    PrincipalMismatch { expected: String, actual: String },
    /// Session not found.
    SessionNotFound { session_id: String },
    /// No principal identified.
    NoPrincipal,
    /// Internal error (e.g., RwLock poisoned). Fail-closed.
    InternalError { reason: String },
}

impl std::fmt::Display for DeputyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeputyError::UnauthorizedDelegation { from, to } => {
                write!(f, "Delegation from '{from}' to '{to}' is not authorized")
            }
            DeputyError::DelegationDepthExceeded { depth, max } => {
                write!(f, "Delegation depth {depth} exceeds maximum {max}")
            }
            DeputyError::ToolNotInDelegation { tool } => {
                write!(f, "Tool '{tool}' is not in the delegation's allowed set")
            }
            DeputyError::DelegationExpired => {
                write!(f, "Delegation has expired")
            }
            DeputyError::PrincipalMismatch { expected, actual } => {
                write!(
                    f,
                    "Principal mismatch: expected '{expected}', got '{actual}'"
                )
            }
            DeputyError::SessionNotFound { session_id } => {
                write!(f, "Session '{session_id}' not found")
            }
            DeputyError::NoPrincipal => {
                write!(f, "No principal identified")
            }
            DeputyError::InternalError { reason } => {
                write!(f, "Internal error (fail-closed): {reason}")
            }
        }
    }
}

impl std::error::Error for DeputyError {}

/// Rule for allowed delegations.
///
/// SECURITY (FIND-R67-PF-001): Fields are `pub(crate)` to prevent external
/// mutation that could bypass delegation validation invariants.
///
/// Note: Fields are stored for rule-based delegation validation (see `add_rule`).
/// The `register_delegation` method currently validates inline; the stored rules
/// will be consulted once policy-based delegation is wired end-to-end.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DelegationRule {
    /// Principal that can delegate.
    pub(crate) from_principal: String,
    /// Principal that can receive delegation.
    pub(crate) to_principal: String,
    /// Tools the delegate is allowed to access (glob patterns).
    pub(crate) allowed_tools: Vec<PatternMatcher>,
    /// Maximum delegation depth (0 = no further delegation).
    pub(crate) max_depth: u8,
    /// Expiry time in Unix seconds (None = no expiry).
    pub(crate) expires_secs: Option<u64>,
}

impl DelegationRule {
    /// Create a new delegation rule.
    pub fn new(
        from_principal: String,
        to_principal: String,
        allowed_tools: Vec<PatternMatcher>,
        max_depth: u8,
        expires_secs: Option<u64>,
    ) -> Self {
        Self {
            from_principal,
            to_principal,
            allowed_tools,
            max_depth,
            expires_secs,
        }
    }
}

/// Maximum number of delegation rules that can be registered.
/// Prevents unbounded memory growth (FIND-R71-001).
const MAX_DELEGATION_RULES: usize = 10_000;

/// Maximum number of active delegation contexts tracked concurrently.
/// Prevents unbounded memory growth (FIND-041-009).
const MAX_ACTIVE_CONTEXTS: usize = 10_000;

/// Validates principal binding to prevent confused deputy attacks.
#[derive(Debug)]
pub struct DeputyValidator {
    /// Static delegation rules (loaded from config).
    delegation_rules: RwLock<HashMap<String, DelegationRule>>,
    /// Active delegation contexts by session ID.
    active_contexts: RwLock<HashMap<String, PrincipalContext>>,
    /// Maximum allowed delegation depth.
    max_depth: u8,
}

impl DeputyValidator {
    /// Create a new deputy validator.
    ///
    /// # Arguments
    /// * `max_depth` - Maximum allowed delegation depth (0 = direct only)
    pub fn new(max_depth: u8) -> Self {
        Self {
            delegation_rules: RwLock::new(HashMap::new()),
            active_contexts: RwLock::new(HashMap::new()),
            max_depth,
        }
    }

    /// Create a shareable reference to this validator.
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Get the current timestamp as Unix seconds.
    ///
    /// Note: Returns 0 on system time error. This is acceptable for deputy
    /// expiry checks because 0 will cause all time-based expirations to trigger
    /// (fail-closed behavior).
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_else(|e| {
                tracing::error!("CRITICAL: System time error in deputy: {}", e);
                0
            })
    }

    /// Register a delegation rule.
    ///
    /// Note: If RwLock is poisoned, logs error and does nothing.
    /// SECURITY (FIND-R71-001): Checks capacity before inserting; logs and
    /// returns without inserting if at limit.
    pub fn add_rule(&self, rule_id: impl Into<String>, rule: DelegationRule) {
        let mut rules = match self.delegation_rules.write() {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("CRITICAL: Deputy RwLock poisoned in add_rule: {}", e);
                return;
            }
        };
        let id = rule_id.into();
        if !rules.contains_key(&id) && rules.len() >= MAX_DELEGATION_RULES {
            tracing::error!(
                target: "vellaveto::security",
                rule_id = %id,
                limit = MAX_DELEGATION_RULES,
                "Delegation rule limit reached — ignoring new rule"
            );
            return;
        }
        rules.insert(id, rule);
    }

    /// Register a delegation for a session.
    ///
    /// # Arguments
    /// * `session_id` - The session to register delegation for
    /// * `from` - The delegating principal
    /// * `to` - The receiving principal
    /// * `allowed_tools` - Tools the delegate can access
    ///
    /// # Returns
    /// `Ok(())` if delegation was registered, `Err(DeputyError)` if not authorized.
    ///
    /// SECURITY: Fails closed if RwLock is poisoned.
    pub fn register_delegation(
        &self,
        session_id: &str,
        from: &str,
        to: &str,
        allowed_tools: &[String],
    ) -> Result<(), DeputyError> {
        let mut contexts = self.active_contexts.write().map_err(|e| {
            tracing::error!(
                "CRITICAL: Deputy RwLock poisoned in register_delegation for session '{}': {}",
                session_id,
                e
            );
            DeputyError::InternalError {
                reason: "RwLock poisoned — failing closed".to_string(),
            }
        })?;

        // Get current context if exists
        let current_depth = contexts
            .get(session_id)
            .map_or(0, |ctx| ctx.delegation_depth);

        // Check depth limit
        // SECURITY (FIND-R67-SA-001): Use saturating_add to prevent overflow.
        let new_depth = current_depth.saturating_add(1);
        if new_depth > self.max_depth {
            return Err(DeputyError::DelegationDepthExceeded {
                depth: new_depth,
                max: self.max_depth,
            });
        }

        // SECURITY (FIND-082): Intersect requested tools with parent's granted scope.
        // Prevents re-delegation from granting tools beyond the parent's authorization.
        let effective_tools = if let Some(parent) = contexts.get(session_id) {
            if parent.allowed_tools.is_empty() {
                // Parent has unrestricted access — use child's requested tools
                allowed_tools.to_vec()
            } else {
                // Intersect: child can only get tools parent already has
                // SECURITY (FIND-R209-001): Normalize homoglyphs before comparison
                // to prevent Cyrillic/Greek/fullwidth characters from bypassing
                // delegation tool restrictions.
                allowed_tools
                    .iter()
                    .filter(|t| {
                        let norm_t = crate::normalize::normalize_full(&t.to_ascii_lowercase());
                        parent.allowed_tools.iter().any(|p| {
                            crate::normalize::normalize_full(&p.to_ascii_lowercase()) == norm_t
                        })
                    })
                    .cloned()
                    .collect()
            }
        } else {
            // No parent context — first delegation, use as-is
            allowed_tools.to_vec()
        };

        // Check capacity before inserting a new session (fail-closed)
        if !contexts.contains_key(session_id) && contexts.len() >= MAX_ACTIVE_CONTEXTS {
            tracing::error!(
                target: "vellaveto::security",
                session_id = %session_id,
                limit = MAX_ACTIVE_CONTEXTS,
                "Active delegation context limit reached — denying new delegation"
            );
            return Err(DeputyError::InternalError {
                reason: format!(
                    "Active delegation context limit ({MAX_ACTIVE_CONTEXTS}) reached — failing closed"
                ),
            });
        }

        // Create new context
        // SECURITY (FIND-R213-002): Normalize homoglyphs on `from` and `to` before
        // storing in PrincipalContext. This ensures identity consistency between the
        // deputy subsystem (which compares stored delegated_to against claimed_principal)
        // and AgentId context conditions (which already normalize). Without this,
        // Cyrillic/Greek/fullwidth variants of principal names would store differently
        // than they compare, creating an inconsistency that bypasses principal binding.
        let ctx = PrincipalContext {
            original_principal: crate::normalize::normalize_full(&from.to_ascii_lowercase()),
            delegated_to: Some(crate::normalize::normalize_full(&to.to_ascii_lowercase())),
            delegation_depth: new_depth,
            allowed_tools: effective_tools,
            delegation_expires: None, // Could be set from rule
        };

        contexts.insert(session_id.to_string(), ctx);

        tracing::debug!(
            session = %session_id,
            from = %from,
            to = %to,
            depth = %new_depth,
            "Delegation registered"
        );

        Ok(())
    }

    /// Validate that an action is authorized for the current principal chain.
    ///
    /// # Arguments
    /// * `session_id` - The session ID
    /// * `tool` - The tool being called
    /// * `claimed_principal` - The principal claiming to make the call
    ///
    /// # Returns
    /// `Ok(())` if authorized, `Err(DeputyError)` if not.
    ///
    /// SECURITY: Fails closed if RwLock is poisoned.
    #[must_use = "deputy validation results must not be discarded"]
    pub fn validate_action(
        &self,
        session_id: &str,
        tool: &str,
        claimed_principal: &str,
    ) -> Result<(), DeputyError> {
        let contexts = self.active_contexts.read().map_err(|e| {
            tracing::error!(
                "CRITICAL: Deputy RwLock poisoned in validate_action for session '{}': {}",
                session_id,
                e
            );
            DeputyError::InternalError {
                reason: "RwLock poisoned — failing closed".to_string(),
            }
        })?;

        let ctx = match contexts.get(session_id) {
            Some(c) => c,
            None => {
                // No delegation context = direct request
                // This is allowed if no explicit delegation is required
                return Ok(());
            }
        };

        // Check if delegation has expired
        let now = Self::now();
        if ctx.is_expired(now) {
            return Err(DeputyError::DelegationExpired);
        }

        // Verify the claimed principal matches the delegate
        // SECURITY (FIND-R213-002): Normalize homoglyphs on `claimed_principal` before
        // comparing with stored `delegated_to` (which is already normalized at registration
        // time). Without this, Cyrillic/Greek/fullwidth variants of a principal name would
        // bypass principal binding checks — e.g., "wоrker" (Cyrillic 'о') would not match
        // stored "worker" (Latin 'o'), allowing a different agent to impersonate the delegate.
        if let Some(ref delegate) = ctx.delegated_to {
            let claimed_norm =
                crate::normalize::normalize_full(&claimed_principal.to_ascii_lowercase());
            if *delegate != claimed_norm {
                return Err(DeputyError::PrincipalMismatch {
                    expected: delegate.clone(),
                    actual: claimed_principal.to_string(),
                });
            }
        }

        // Check if tool is in allowed set
        // SECURITY (FIND-R209-001): Normalize homoglyphs before comparison
        // to prevent Cyrillic/Greek/fullwidth characters from bypassing
        // delegation tool restrictions.
        if !ctx.allowed_tools.is_empty() {
            let tool_norm = crate::normalize::normalize_full(&tool.to_ascii_lowercase());
            let allowed = ctx
                .allowed_tools
                .iter()
                .any(|t| crate::normalize::normalize_full(&t.to_ascii_lowercase()) == tool_norm);

            if !allowed {
                return Err(DeputyError::ToolNotInDelegation {
                    tool: tool.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Check if a tool is allowed for the current delegation chain.
    ///
    /// Unlike `validate_action()`, this method only checks tool scope without
    /// verifying the claimed principal. This is appropriate for pre-flight
    /// tool availability checks where the caller's identity is not yet known
    /// or not relevant (e.g., building a tool menu for a session).
    ///
    /// SECURITY (FIND-R67-FC-001): Previously delegated via `validate_action()`
    /// with empty claimed_principal, which caused `PrincipalMismatch` for every
    /// session with a `delegated_to` set, making `is_tool_allowed()` always
    /// return `false` in delegation contexts.
    pub fn is_tool_allowed(&self, session_id: &str, tool: &str) -> bool {
        let contexts = match self.active_contexts.read() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "CRITICAL: Deputy RwLock poisoned in is_tool_allowed for session '{}': {}",
                    session_id,
                    e
                );
                // Fail-closed: poisoned lock → tool not allowed
                return false;
            }
        };

        let ctx = match contexts.get(session_id) {
            Some(c) => c,
            None => {
                // No delegation context = direct request, tool is allowed
                return true;
            }
        };

        // Check expiry (fail-closed)
        let now = Self::now();
        if ctx.is_expired(now) {
            return false;
        }

        // Check if tool is in allowed set (skip principal validation)
        if ctx.allowed_tools.is_empty() {
            // Empty allowed_tools = unrestricted
            return true;
        }

        // SECURITY (FIND-R209-001): Normalize homoglyphs before comparison
        // to prevent Cyrillic/Greek/fullwidth characters from bypassing
        // delegation tool restrictions.
        let tool_norm = crate::normalize::normalize_full(&tool.to_ascii_lowercase());
        ctx.allowed_tools
            .iter()
            .any(|t| crate::normalize::normalize_full(&t.to_ascii_lowercase()) == tool_norm)
    }

    /// Get the current principal context for a session.
    ///
    /// Note: If RwLock is poisoned, returns None and logs error.
    pub fn get_context(&self, session_id: &str) -> Option<PrincipalContext> {
        let contexts = match self.active_contexts.read() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "CRITICAL: Deputy RwLock poisoned in get_context for session '{}': {}",
                    session_id,
                    e
                );
                return None;
            }
        };
        contexts.get(session_id).cloned()
    }

    /// Remove a session's delegation context.
    ///
    /// Note: If RwLock is poisoned, logs error and does nothing.
    pub fn remove_context(&self, session_id: &str) {
        let mut contexts = match self.active_contexts.write() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "CRITICAL: Deputy RwLock poisoned in remove_context for session '{}': {}",
                    session_id,
                    e
                );
                return;
            }
        };
        contexts.remove(session_id);
    }

    /// Clean up expired delegation contexts.
    ///
    /// Returns the number of contexts removed.
    ///
    /// Note: If RwLock is poisoned, returns 0 and logs error.
    pub fn cleanup_expired(&self) -> usize {
        let now = Self::now();
        let mut contexts = match self.active_contexts.write() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("CRITICAL: Deputy RwLock poisoned in cleanup_expired: {}", e);
                return 0;
            }
        };

        let old_len = contexts.len();
        contexts.retain(|_, ctx| !ctx.is_expired(now));

        old_len - contexts.len()
    }

    /// Get the number of active delegation contexts.
    ///
    /// Note: If RwLock is poisoned, returns 0 and logs error.
    pub fn active_count(&self) -> usize {
        let contexts = match self.active_contexts.read() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("CRITICAL: Deputy RwLock poisoned in active_count: {}", e);
                return 0;
            }
        };
        contexts.len()
    }
}

impl Default for DeputyValidator {
    fn default() -> Self {
        Self::new(3) // Default max depth of 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_principal_allowed() {
        let validator = DeputyValidator::new(3);

        // No delegation context = direct request, always allowed
        let result = validator.validate_action("session-1", "read_file", "user-1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_single_delegation_allowed() {
        let validator = DeputyValidator::new(3);

        // Register delegation
        validator
            .register_delegation(
                "session-1",
                "admin",
                "worker",
                &["read_file".to_string(), "write_file".to_string()],
            )
            .unwrap();

        // Worker can call allowed tools
        let result = validator.validate_action("session-1", "read_file", "worker");
        assert!(result.is_ok());
    }

    #[test]
    fn test_delegation_depth_exceeded() {
        let validator = DeputyValidator::new(1); // Only allow depth 1

        // First delegation succeeds
        validator
            .register_delegation("session-1", "admin", "worker-1", &["*".to_string()])
            .unwrap();

        // Second delegation fails (depth exceeded)
        let result = validator.register_delegation("session-1", "worker-1", "worker-2", &[]);

        assert!(matches!(
            result,
            Err(DeputyError::DelegationDepthExceeded { .. })
        ));
    }

    #[test]
    fn test_tool_not_in_delegation() {
        let validator = DeputyValidator::new(3);

        // Register delegation with limited tools
        validator
            .register_delegation("session-1", "admin", "worker", &["read_file".to_string()])
            .unwrap();

        // Attempt to call non-allowed tool
        let result = validator.validate_action("session-1", "delete_file", "worker");

        assert!(matches!(
            result,
            Err(DeputyError::ToolNotInDelegation { .. })
        ));
    }

    #[test]
    fn test_principal_mismatch_denied() {
        let validator = DeputyValidator::new(3);

        // Register delegation to specific worker
        validator
            .register_delegation("session-1", "admin", "worker-1", &["*".to_string()])
            .unwrap();

        // Different worker tries to use it
        let result = validator.validate_action("session-1", "read_file", "worker-2");

        assert!(matches!(result, Err(DeputyError::PrincipalMismatch { .. })));
    }

    #[test]
    fn test_get_context() {
        let validator = DeputyValidator::new(3);

        validator
            .register_delegation("session-1", "admin", "worker", &["read_file".to_string()])
            .unwrap();

        let ctx = validator.get_context("session-1").unwrap();
        assert_eq!(ctx.original_principal, "admin");
        assert_eq!(ctx.delegated_to, Some("worker".to_string()));
        assert_eq!(ctx.delegation_depth, 1);
    }

    #[test]
    fn test_remove_context() {
        let validator = DeputyValidator::new(3);

        validator
            .register_delegation("session-1", "admin", "worker", &[])
            .unwrap();

        assert!(validator.get_context("session-1").is_some());

        validator.remove_context("session-1");

        assert!(validator.get_context("session-1").is_none());
    }

    #[test]
    fn test_active_count() {
        let validator = DeputyValidator::new(3);

        assert_eq!(validator.active_count(), 0);

        validator
            .register_delegation("session-1", "admin", "worker", &[])
            .unwrap();
        validator
            .register_delegation("session-2", "admin", "worker", &[])
            .unwrap();

        assert_eq!(validator.active_count(), 2);
    }

    /// FIND-R213-002: Registration normalizes homoglyphs in `from` and `to`.
    #[test]
    fn test_register_delegation_normalizes_homoglyphs() {
        let validator = DeputyValidator::new(3);

        // Register with Cyrillic 'а' (U+0430) in "admin" and 'о' (U+043E) in "worker"
        validator
            .register_delegation(
                "s1",
                "\u{0430}dmin",  // Cyrillic 'а' looks like Latin 'a'
                "w\u{043E}rker", // Cyrillic 'о' looks like Latin 'o'
                &["read_file".to_string()],
            )
            .unwrap();

        let ctx = validator.get_context("s1").unwrap();
        // Stored values should be normalized to Latin equivalents
        assert_eq!(ctx.original_principal, "admin");
        assert_eq!(ctx.delegated_to, Some("worker".to_string()));
    }

    /// FIND-R213-002: validate_action normalizes claimed_principal homoglyphs.
    #[test]
    fn test_validate_action_normalizes_claimed_principal_homoglyphs() {
        let validator = DeputyValidator::new(3);

        validator
            .register_delegation("s1", "admin", "worker", &["read_file".to_string()])
            .unwrap();

        // Claimed principal uses Cyrillic 'о' (U+043E) — should still match "worker"
        let result = validator.validate_action("s1", "read_file", "w\u{043E}rker");
        assert!(
            result.is_ok(),
            "Homoglyph-variant principal should match after normalization"
        );
    }

    /// FIND-R213-002: validate_action rejects genuinely different principals
    /// even after normalization.
    #[test]
    fn test_validate_action_rejects_different_principal_after_normalization() {
        let validator = DeputyValidator::new(3);

        validator
            .register_delegation("s1", "admin", "worker", &["read_file".to_string()])
            .unwrap();

        // "attacker" is genuinely different from "worker" — must be denied
        let result = validator.validate_action("s1", "read_file", "attacker");
        assert!(
            matches!(result, Err(DeputyError::PrincipalMismatch { .. })),
            "Different principal should still be denied: {:?}",
            result
        );
    }

    /// FIND-R213-002: Case normalization on registration and validation.
    #[test]
    fn test_validate_action_case_insensitive_principal() {
        let validator = DeputyValidator::new(3);

        validator
            .register_delegation("s1", "Admin", "Worker", &["read_file".to_string()])
            .unwrap();

        // Mixed case should match due to to_ascii_lowercase normalization
        let result = validator.validate_action("s1", "read_file", "WORKER");
        assert!(
            result.is_ok(),
            "Case-insensitive principal match should succeed"
        );
    }
}
