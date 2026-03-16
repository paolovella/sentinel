// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Async task state management for MCP 2025-11-25 compliance.
//!
//! This module tracks the lifecycle of async MCP tasks to enforce:
//! - Maximum concurrent task limits per session
//! - Task duration limits with automatic expiry
//! - Cancellation authorization (self-cancel only vs. any agent)
//!
//! # Example
//!
//! ```rust,ignore
//! use vellaveto_mcp::task_state::TaskStateManager;
//! use vellaveto_types::{TrackedTask, TaskStatus};
//!
//! let manager = TaskStateManager::new(100, 3600);
//!
//! // Register a new task
//! let task = TrackedTask {
//!     task_id: "task-123".to_string(),
//!     tool: "background_job".to_string(),
//!     function: "execute".to_string(),
//!     status: TaskStatus::Pending,
//!     created_at: chrono::Utc::now().to_rfc3339(),
//!     expires_at: None,
//!     created_by: Some("agent-1".to_string()),
//!     session_id: Some("session-abc".to_string()),
//! };
//!
//! manager.register_task(task).await?;
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use vellaveto_types::{TaskCreateParams, TaskStatus, TrackedTask};

/// Absolute maximum number of tracked tasks to prevent unbounded memory growth.
///
/// SECURITY (FIND-R67-5-009): When `max_concurrent` is 0 (unlimited), the tasks
/// HashMap could grow without bound. This constant provides a hard cap.
const MAX_TRACKED_TASKS: usize = 100_000;

/// Manages async task state for MCP 2025-11-25 compliance.
///
/// Thread-safe via `RwLock` for concurrent access from multiple
/// proxy bridge instances.
#[derive(Debug)]
pub struct TaskStateManager {
    /// Active and recently completed tasks by task_id.
    tasks: RwLock<HashMap<String, TrackedTask>>,

    /// Maximum concurrent active tasks. 0 = unlimited.
    max_concurrent: usize,

    /// Maximum task duration in seconds. 0 = unlimited.
    max_duration_secs: u64,

    /// When true, only the creator can cancel a task.
    require_self_cancel: bool,

    /// Agent IDs allowed to cancel any task (when require_self_cancel is false).
    allow_cancellation: Vec<String>,

    /// Phase 1: When true, task get/send requires matching creator identity.
    require_task_creator_match: bool,
}

impl TaskStateManager {
    /// Create a new task state manager.
    ///
    /// # Arguments
    /// * `max_concurrent` - Maximum active tasks. 0 for unlimited.
    /// * `max_duration_secs` - Maximum task duration in seconds. 0 for unlimited.
    pub fn new(max_concurrent: usize, max_duration_secs: u64) -> Self {
        let initial_task_capacity = if max_concurrent > 0 {
            max_concurrent.min(1024)
        } else {
            256
        };
        Self {
            tasks: RwLock::new(HashMap::with_capacity(initial_task_capacity)),
            max_concurrent,
            max_duration_secs,
            require_self_cancel: true,
            allow_cancellation: Vec::new(),
            require_task_creator_match: true,
        }
    }

    /// Create a task state manager with full configuration.
    pub fn with_config(
        max_concurrent: usize,
        max_duration_secs: u64,
        require_self_cancel: bool,
        allow_cancellation: Vec<String>,
    ) -> Self {
        let initial_task_capacity = if max_concurrent > 0 {
            max_concurrent.min(1024)
        } else {
            256
        };
        Self {
            tasks: RwLock::new(HashMap::with_capacity(initial_task_capacity)),
            max_concurrent,
            max_duration_secs,
            require_self_cancel,
            allow_cancellation,
            require_task_creator_match: true,
        }
    }

    /// Set the require_task_creator_match flag.
    pub fn set_require_task_creator_match(&mut self, require: bool) {
        self.require_task_creator_match = require;
    }

    /// Check if task creator matching is required.
    pub fn requires_creator_match(&self) -> bool {
        self.require_task_creator_match
    }

    /// Create a shareable reference to this manager.
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Register a new task.
    ///
    /// Returns `Ok(())` if the task was registered successfully.
    /// Returns `Err(reason)` if:
    /// - A task with this ID already exists
    /// - Maximum concurrent task limit would be exceeded
    pub async fn register_task(&self, mut task: TrackedTask) -> Result<(), String> {
        let mut tasks = self.tasks.write().await;

        // Check if task ID already exists
        if tasks.contains_key(&task.task_id) {
            return Err(format!("Task '{}' already exists", task.task_id));
        }

        // SECURITY (FIND-R67-5-009): Absolute capacity bound. When max_concurrent is 0
        // (unlimited active tasks), we still enforce this hard limit on total tracked
        // entries to prevent unbounded HashMap growth. Try evicting terminal tasks first.
        if tasks.len() >= MAX_TRACKED_TASKS {
            // Evict terminal (completed/failed/cancelled/expired) tasks
            let terminal_keys: Vec<String> = tasks
                .iter()
                .filter(|(_, t)| t.is_terminal())
                .map(|(k, _)| k.clone())
                .collect();
            for key in &terminal_keys {
                tasks.remove(key);
            }
            // If still at capacity after eviction, reject
            if tasks.len() >= MAX_TRACKED_TASKS {
                return Err(format!(
                    "Maximum tracked tasks ({MAX_TRACKED_TASKS}) exceeded"
                ));
            }
        }

        // Check concurrent task limit
        if self.max_concurrent > 0 {
            let active_count = tasks.values().filter(|t| t.is_active()).count();
            if active_count >= self.max_concurrent {
                return Err(format!(
                    "Maximum concurrent tasks ({}) exceeded",
                    self.max_concurrent
                ));
            }
        }

        // Set expiry time if max_duration is configured
        if self.max_duration_secs > 0 && task.expires_at.is_none() {
            if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&task.created_at) {
                // SECURITY (FIND-R66-003): Reject created_at timestamps more than
                // 1 day in the future to prevent tasks that never expire.
                let now = chrono::Utc::now();
                let max_future = now + chrono::Duration::days(1);
                if created.with_timezone(&chrono::Utc) > max_future {
                    return Err("Task created_at is too far in the future".to_string());
                }
                // SECURITY (R240-MCP-2): Cap max_duration_secs before i64 cast to prevent
                // overflow. Values above i64::MAX would wrap to negative, setting expires_at
                // in the past. Cap at 1 year (31,536,000 seconds).
                const MAX_TASK_DURATION_SECS: u64 = 365 * 24 * 3600;
                let capped_secs = self.max_duration_secs.min(MAX_TASK_DURATION_SECS);
                let expires = created + chrono::Duration::seconds(capped_secs as i64);
                task.expires_at = Some(expires.to_rfc3339());
            }
        }

        tasks.insert(task.task_id.clone(), task);
        Ok(())
    }

    /// Register a new task from a `tasks/create` request.
    ///
    /// Validates the `TaskCreateParams`, generates a task ID if not provided,
    /// creates a `TrackedTask`, and delegates to `register_task()`.
    ///
    /// Returns the assigned `task_id` on success.
    /// Returns `Err(reason)` if validation or registration fails.
    pub async fn register_task_from_create(
        &self,
        params: &TaskCreateParams,
        created_by: Option<String>,
        session_id: Option<String>,
    ) -> Result<String, String> {
        // Validate input params at the trust boundary.
        params.validate()?;

        // Resolve task_id: use client-supplied or generate a UUID.
        let task_id = match &params.task_id {
            Some(tid) => tid.clone(),
            None => uuid::Uuid::new_v4().to_string(),
        };

        let task = TrackedTask {
            task_id: task_id.clone(),
            tool: params.tool.clone(),
            function: "execute".to_string(),
            status: TaskStatus::Pending,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
            created_by,
            session_id,
        };

        // Validate the constructed TrackedTask before registering.
        task.validate()
            .map_err(|e| format!("Task validation failed: {e}"))?;

        self.register_task(task).await?;
        Ok(task_id)
    }

    /// Update a task's status.
    ///
    /// Returns `Ok(())` if the status was updated.
    /// Returns `Err(reason)` if the task doesn't exist.
    pub async fn update_status(&self, task_id: &str, status: TaskStatus) -> Result<(), String> {
        let mut tasks = self.tasks.write().await;

        let task = tasks
            .get_mut(task_id)
            .ok_or_else(|| format!("Task '{task_id}' not found"))?;

        // SECURITY (FIND-R60-004): Enforce terminal state immutability.
        // Once a task reaches Completed, Failed, Cancelled, or Expired, its state
        // must not change. Without this check, a cancelled task could be un-cancelled
        // or a completed task moved to Running, violating the MCP task lifecycle and
        // undermining audit trail integrity.
        if task.is_terminal() {
            return Err(format!(
                "Task '{task_id}' is in terminal state and cannot be updated"
            ));
        }

        task.status = status;
        Ok(())
    }

    /// Check if an agent can cancel a task.
    ///
    /// Returns `Ok(true)` if cancellation is allowed.
    /// Returns `Ok(false)` if cancellation is not authorized.
    /// Returns `Err(reason)` if the task doesn't exist.
    pub async fn can_cancel(&self, task_id: &str, agent: Option<&str>) -> Result<bool, String> {
        let tasks = self.tasks.read().await;

        let task = tasks
            .get(task_id)
            .ok_or_else(|| format!("Task '{task_id}' not found"))?;

        // Task already in terminal state
        if task.is_terminal() {
            return Ok(false);
        }

        // If require_self_cancel is true, only the creator can cancel
        if self.require_self_cancel {
            match (&task.created_by, agent) {
                (Some(creator), Some(requester)) => Ok(creator == requester),
                (None, _) => Ok(true), // No creator recorded, allow anyone
                (Some(_), None) => Ok(false), // Creator recorded but no requester provided
            }
        } else {
            // Check if agent is in allow_cancellation list
            match agent {
                Some(a) => Ok(self.allow_cancellation.iter().any(|allowed| allowed == a)),
                None => Ok(false),
            }
        }
    }

    /// Phase 1: Verify that a requester has access to a task.
    ///
    /// When `require_creator_match` is true, denies access if:
    /// - The task has a `created_by` and it doesn't match the requester's agent_id
    /// - The task has a `session_id` and it doesn't match the requester's session
    ///
    /// Returns `Ok(())` if access is allowed, `Err(reason)` if denied.
    pub async fn verify_task_access(
        &self,
        task_id: &str,
        requester_agent_id: Option<&str>,
        requester_session_id: Option<&str>,
        require_creator_match: bool,
    ) -> Result<(), String> {
        if !require_creator_match {
            return Ok(());
        }
        let tasks = self.tasks.read().await;
        let task = match tasks.get(task_id) {
            Some(t) => t,
            None => return Ok(()), // Unknown task — let the server handle it
        };

        // Check agent identity match
        if let Some(creator) = &task.created_by {
            match requester_agent_id {
                Some(requester) if requester == creator => {}
                Some(_) => {
                    return Err(
                        "task access denied: requester does not match task creator".to_string(),
                    );
                }
                None => {
                    return Err(
                        "task access denied: no agent identity for creator-bound task".to_string(),
                    );
                }
            }
        }

        // Check session match
        if let Some(task_session) = &task.session_id {
            match requester_session_id {
                Some(requester_session) if requester_session == task_session => {}
                Some(_) => {
                    return Err(
                        "task access denied: requester session does not match task session"
                            .to_string(),
                    );
                }
                None => {} // No session provided — allow (session binding is optional)
            }
        }

        Ok(())
    }

    /// Get a task by ID.
    pub async fn get_task(&self, task_id: &str) -> Option<TrackedTask> {
        let tasks = self.tasks.read().await;
        tasks.get(task_id).cloned()
    }

    /// Get all tasks for a session.
    pub async fn get_session_tasks(&self, session_id: &str) -> Vec<TrackedTask> {
        let tasks = self.tasks.read().await;
        tasks
            .values()
            .filter(|t| t.session_id.as_deref() == Some(session_id))
            .cloned()
            .collect()
    }

    /// Count active (non-terminal) tasks.
    pub async fn active_count(&self) -> usize {
        let tasks = self.tasks.read().await;
        tasks.values().filter(|t| t.is_active()).count()
    }

    /// Count active tasks for a specific session.
    pub async fn session_active_count(&self, session_id: &str) -> usize {
        let tasks = self.tasks.read().await;
        tasks
            .values()
            .filter(|t| t.session_id.as_deref() == Some(session_id) && t.is_active())
            .count()
    }

    /// Evict expired tasks.
    ///
    /// Marks tasks as expired if they have passed their expiry time.
    /// Returns the number of tasks that were expired.
    pub async fn evict_expired(&self) -> usize {
        let now = chrono::Utc::now();
        let mut tasks = self.tasks.write().await;
        let mut expired_count = 0;

        for task in tasks.values_mut() {
            if task.is_active() {
                if let Some(ref expires_at) = task.expires_at {
                    if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires_at) {
                        if now > expiry {
                            task.status = TaskStatus::Expired;
                            expired_count += 1;
                        }
                    }
                }
            }
        }

        expired_count
    }

    /// Remove tasks that have been in terminal state for longer than `retention_secs`.
    ///
    /// Returns the number of tasks removed.
    pub async fn cleanup_old_tasks(&self, retention_secs: u64) -> usize {
        // SECURITY (R245-TASK-1): Clamp retention_secs to prevent u64→i64 overflow.
        // Values > i64::MAX wrap negative, producing a future cutoff that disables cleanup.
        // Matches the clamping in SecureTaskManager::cleanup_old_tasks.
        const MAX_RETENTION_SECS: u64 = 365 * 24 * 3600; // 1 year
        let clamped = retention_secs.min(MAX_RETENTION_SECS);
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(clamped as i64);
        let mut tasks = self.tasks.write().await;

        let old_len = tasks.len();
        tasks.retain(|_, task| {
            if !task.is_terminal() {
                return true; // Keep active tasks
            }
            // Keep if created_at is more recent than cutoff
            if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&task.created_at) {
                created > cutoff
            } else {
                // SECURITY (R245-TASK-2): Fail-closed — remove terminal tasks
                // with unparseable timestamps since they can never be cleaned up.
                false
            }
        });

        old_len - tasks.len()
    }

    /// Get statistics about task state.
    pub async fn stats(&self) -> TaskStats {
        let tasks = self.tasks.read().await;

        let mut pending = 0;
        let mut running = 0;
        let mut completed = 0;
        let mut failed = 0;
        let mut cancelled = 0;
        let mut expired = 0;

        for task in tasks.values() {
            match &task.status {
                TaskStatus::Pending => pending += 1,
                TaskStatus::Running => running += 1,
                TaskStatus::Completed => completed += 1,
                TaskStatus::Failed { .. } => failed += 1,
                TaskStatus::Cancelled => cancelled += 1,
                TaskStatus::Expired => expired += 1,
            }
        }

        TaskStats {
            total: tasks.len(),
            pending,
            running,
            completed,
            failed,
            cancelled,
            expired,
        }
    }
}

/// Statistics about task state.
#[derive(Debug, Clone, Default)]
pub struct TaskStats {
    pub total: usize,
    pub pending: usize,
    pub running: usize,
    pub completed: usize,
    pub failed: usize,
    pub cancelled: usize,
    pub expired: usize,
}

impl TaskStats {
    /// Number of active (non-terminal) tasks.
    pub fn active(&self) -> usize {
        self.pending + self.running
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_task(id: &str, agent: Option<&str>, session: Option<&str>) -> TrackedTask {
        TrackedTask {
            task_id: id.to_string(),
            tool: "test_tool".to_string(),
            function: "execute".to_string(),
            status: TaskStatus::Pending,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
            created_by: agent.map(|s| s.to_string()),
            session_id: session.map(|s| s.to_string()),
        }
    }

    #[tokio::test]
    async fn test_task_registration_under_limit_succeeds() {
        let manager = TaskStateManager::new(5, 0);

        for i in 0..5 {
            let task = make_task(&format!("task-{i}"), Some("agent-1"), None);
            assert!(manager.register_task(task).await.is_ok());
        }

        assert_eq!(manager.active_count().await, 5);
    }

    #[tokio::test]
    async fn test_task_registration_over_limit_denied() {
        let manager = TaskStateManager::new(2, 0);

        let task1 = make_task("task-1", Some("agent-1"), None);
        let task2 = make_task("task-2", Some("agent-1"), None);
        let task3 = make_task("task-3", Some("agent-1"), None);

        assert!(manager.register_task(task1).await.is_ok());
        assert!(manager.register_task(task2).await.is_ok());

        let result = manager.register_task(task3).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeded"));
    }

    #[tokio::test]
    async fn test_task_self_cancel_allowed() {
        let manager = TaskStateManager::new(10, 0);

        let task = make_task("task-1", Some("agent-1"), None);
        manager.register_task(task).await.unwrap();

        // Same agent can cancel
        assert!(manager.can_cancel("task-1", Some("agent-1")).await.unwrap());

        // Different agent cannot cancel
        assert!(!manager.can_cancel("task-1", Some("agent-2")).await.unwrap());
    }

    #[tokio::test]
    async fn test_task_cancel_by_other_denied() {
        let manager = TaskStateManager::with_config(10, 0, true, vec![]);

        let task = make_task("task-1", Some("agent-1"), None);
        manager.register_task(task).await.unwrap();

        // Other agent cannot cancel when require_self_cancel is true
        assert!(!manager.can_cancel("task-1", Some("agent-2")).await.unwrap());
    }

    #[tokio::test]
    async fn test_task_cancel_by_allowed_agent() {
        let manager = TaskStateManager::with_config(
            10,
            0,
            false,
            vec!["admin".to_string(), "operator".to_string()],
        );

        let task = make_task("task-1", Some("agent-1"), None);
        manager.register_task(task).await.unwrap();

        // Allowed agents can cancel
        assert!(manager.can_cancel("task-1", Some("admin")).await.unwrap());
        assert!(manager
            .can_cancel("task-1", Some("operator"))
            .await
            .unwrap());

        // Non-allowed agent cannot cancel
        assert!(!manager.can_cancel("task-1", Some("agent-1")).await.unwrap());
    }

    #[tokio::test]
    async fn test_task_expiry_eviction() {
        let manager = TaskStateManager::new(10, 1); // 1 second max duration

        let mut task = make_task("task-1", Some("agent-1"), None);
        // Set expiry to 1 second ago
        let past = chrono::Utc::now() - chrono::Duration::seconds(2);
        task.expires_at = Some(past.to_rfc3339());

        manager.register_task(task).await.unwrap();

        // Evict expired tasks
        let evicted = manager.evict_expired().await;
        assert_eq!(evicted, 1);

        // Task should be marked as expired
        let task = manager.get_task("task-1").await.unwrap();
        assert!(matches!(task.status, TaskStatus::Expired));
    }

    #[tokio::test]
    async fn test_update_status() {
        let manager = TaskStateManager::new(10, 0);

        let task = make_task("task-1", Some("agent-1"), None);
        manager.register_task(task).await.unwrap();

        // Update to running
        manager
            .update_status("task-1", TaskStatus::Running)
            .await
            .unwrap();
        let task = manager.get_task("task-1").await.unwrap();
        assert!(matches!(task.status, TaskStatus::Running));

        // Update to completed
        manager
            .update_status("task-1", TaskStatus::Completed)
            .await
            .unwrap();
        let task = manager.get_task("task-1").await.unwrap();
        assert!(matches!(task.status, TaskStatus::Completed));
    }

    #[tokio::test]
    async fn test_session_active_count() {
        let manager = TaskStateManager::new(10, 0);

        let task1 = make_task("task-1", Some("agent-1"), Some("session-a"));
        let task2 = make_task("task-2", Some("agent-1"), Some("session-a"));
        let task3 = make_task("task-3", Some("agent-1"), Some("session-b"));

        manager.register_task(task1).await.unwrap();
        manager.register_task(task2).await.unwrap();
        manager.register_task(task3).await.unwrap();

        assert_eq!(manager.session_active_count("session-a").await, 2);
        assert_eq!(manager.session_active_count("session-b").await, 1);
    }

    #[tokio::test]
    async fn test_stats() {
        let manager = TaskStateManager::new(10, 0);

        let task1 = make_task("task-1", None, None);
        let task2 = make_task("task-2", None, None);
        let task3 = make_task("task-3", None, None);

        manager.register_task(task1).await.unwrap();
        manager.register_task(task2).await.unwrap();
        manager.register_task(task3).await.unwrap();

        manager
            .update_status("task-2", TaskStatus::Running)
            .await
            .unwrap();
        manager
            .update_status("task-3", TaskStatus::Completed)
            .await
            .unwrap();

        let stats = manager.stats().await;
        assert_eq!(stats.total, 3);
        assert_eq!(stats.pending, 1);
        assert_eq!(stats.running, 1);
        assert_eq!(stats.completed, 1);
        assert_eq!(stats.active(), 2);
    }

    #[tokio::test]
    async fn test_duplicate_task_rejected() {
        let manager = TaskStateManager::new(10, 0);

        let task = make_task("task-1", Some("agent-1"), None);
        manager.register_task(task.clone()).await.unwrap();

        let result = manager.register_task(task).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[tokio::test]
    async fn test_cleanup_old_tasks_clamps_huge_retention() {
        let manager = TaskStateManager::new(10, 0);

        let mut task = make_task("task-1", Some("agent-1"), None);
        task.status = TaskStatus::Completed;
        task.created_at = (chrono::Utc::now() - chrono::Duration::days(800)).to_rfc3339();
        manager.register_task(task).await.unwrap();

        let removed = manager.cleanup_old_tasks(u64::MAX).await;
        assert_eq!(removed, 1);
        assert!(manager.get_task("task-1").await.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_old_tasks_removes_terminal_task_with_invalid_timestamp() {
        let manager = TaskStateManager::new(10, 0);

        let mut task = make_task("task-1", Some("agent-1"), None);
        task.status = TaskStatus::Completed;
        task.created_at = "not-a-timestamp".to_string();
        manager.register_task(task).await.unwrap();

        let removed = manager.cleanup_old_tasks(0).await;
        assert_eq!(removed, 1);
        assert!(manager.get_task("task-1").await.is_none());
    }

    // ═══════════════════════════════════════════════════
    // Phase 1: Task access verification tests
    // ═══════════════════════════════════════════════════

    #[tokio::test]
    async fn test_verify_task_access_creator_match_allowed() {
        let manager = TaskStateManager::new(10, 3600);
        let task = make_task("t1", Some("agent-A"), Some("session-1"));
        manager.register_task(task).await.unwrap();

        let result = manager
            .verify_task_access("t1", Some("agent-A"), Some("session-1"), true)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_task_access_different_agent_denied() {
        let manager = TaskStateManager::new(10, 3600);
        let task = make_task("t1", Some("agent-A"), Some("session-1"));
        manager.register_task(task).await.unwrap();

        let result = manager
            .verify_task_access("t1", Some("agent-B"), Some("session-1"), true)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not match"));
    }

    #[tokio::test]
    async fn test_verify_task_access_different_session_denied() {
        let manager = TaskStateManager::new(10, 3600);
        let task = make_task("t1", Some("agent-A"), Some("session-1"));
        manager.register_task(task).await.unwrap();

        let result = manager
            .verify_task_access("t1", Some("agent-A"), Some("session-2"), true)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("session"));
    }

    #[tokio::test]
    async fn test_verify_task_access_no_agent_denied_for_creator_bound() {
        let manager = TaskStateManager::new(10, 3600);
        let task = make_task("t1", Some("agent-A"), None);
        manager.register_task(task).await.unwrap();

        let result = manager.verify_task_access("t1", None, None, true).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no agent identity"));
    }

    #[tokio::test]
    async fn test_verify_task_access_disabled_allows_all() {
        let manager = TaskStateManager::new(10, 3600);
        let task = make_task("t1", Some("agent-A"), Some("session-1"));
        manager.register_task(task).await.unwrap();

        // require_creator_match = false → allow anyone
        let result = manager
            .verify_task_access("t1", Some("agent-B"), Some("session-2"), false)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_task_access_unknown_task_allowed() {
        let manager = TaskStateManager::new(10, 3600);

        // Unknown task — let the server handle 404
        let result = manager
            .verify_task_access("unknown", Some("agent-X"), None, true)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_task_access_no_creator_on_task_allows() {
        let manager = TaskStateManager::new(10, 3600);
        let task = make_task("t1", None, None);
        manager.register_task(task).await.unwrap();

        // Task has no creator — anyone can access
        let result = manager
            .verify_task_access("t1", Some("agent-X"), None, true)
            .await;
        assert!(result.is_ok());
    }
}
