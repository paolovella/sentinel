// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Per-session PII sanitization and history tracking.

use crate::error::ShieldError;
use crate::sanitizer::QuerySanitizer;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use vellaveto_audit::PiiScanner;

/// Maximum number of concurrent sessions.
const MAX_SESSIONS: usize = 1_000;

/// Maximum history entries per session.
const MAX_HISTORY_PER_SESSION: usize = 10_000;

/// A single session's state.
struct SessionState {
    sanitizer: QuerySanitizer,
    history: VecDeque<String>,
}

/// Manages per-session PII sanitization with independent mapping tables.
pub struct SessionIsolator {
    sessions: Mutex<HashMap<String, SessionState>>,
    max_sessions: usize,
    max_history: usize,
}

impl SessionIsolator {
    /// Create a new session isolator with default bounds.
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_sessions: MAX_SESSIONS,
            max_history: MAX_HISTORY_PER_SESSION,
        }
    }

    /// Create a new session isolator with custom bounds.
    pub fn with_limits(max_sessions: usize, max_history: usize) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_sessions,
            max_history,
        }
    }

    /// Get or create a session, returning Ok if the session exists or was created.
    fn ensure_session(&self, session_id: &str) -> Result<(), ShieldError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("lock poisoned: {e}")))?;

        if sessions.contains_key(session_id) {
            return Ok(());
        }

        if sessions.len() >= self.max_sessions {
            return Err(ShieldError::SessionIsolation(
                "session capacity exhausted (fail-closed)".to_string(),
            ));
        }

        sessions.insert(
            session_id.to_string(),
            SessionState {
                sanitizer: QuerySanitizer::new(PiiScanner::default()),
                history: VecDeque::new(),
            },
        );
        Ok(())
    }

    /// Sanitize input within a specific session's context.
    pub fn sanitize_in_session(
        &self,
        session_id: &str,
        input: &str,
    ) -> Result<String, ShieldError> {
        self.ensure_session(session_id)?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("lock poisoned: {e}")))?;

        let state = sessions.get_mut(session_id).ok_or_else(|| {
            ShieldError::SessionIsolation("session not found after ensure".to_string())
        })?;

        let result = state.sanitizer.sanitize(input)?;

        // Record in history (bounded)
        if state.history.len() >= self.max_history {
            state.history.pop_front();
        }
        state.history.push_back(result.clone());

        Ok(result)
    }

    /// Desanitize input within a specific session's context.
    pub fn desanitize_in_session(
        &self,
        session_id: &str,
        input: &str,
    ) -> Result<String, ShieldError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("lock poisoned: {e}")))?;

        let state = sessions.get(session_id).ok_or_else(|| {
            ShieldError::SessionIsolation(format!("unknown session: {session_id}"))
        })?;

        state.sanitizer.desanitize(input)
    }

    /// End a session, wiping all state.
    pub fn end_session(&self, session_id: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(session_id);
        }
    }

    /// Get the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }
}

impl Default for SessionIsolator {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SessionIsolator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionIsolator")
            .field("session_count", &self.session_count())
            .finish()
    }
}
