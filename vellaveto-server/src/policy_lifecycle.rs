// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Policy lifecycle management: versioned policies with approval workflows,
//! staging shadow evaluation, and rollback.
//!
//! This module provides:
//! - `PolicyVersionStore` trait for pluggable version storage
//! - `InMemoryPolicyVersionStore` with bounded capacity and lifecycle transitions
//! - `LifecycleError` for fail-closed error handling

use std::collections::HashMap;
use tokio::sync::RwLock;
use vellaveto_config::PolicyLifecycleConfig;
use vellaveto_types::{
    has_dangerous_chars, Policy, PolicyApproval, PolicyLifecycleStatus, PolicyVersion,
    PolicyVersionDiff, PolicyVersionStatus, MAX_DIFF_CHANGES, MAX_TOTAL_VERSIONS,
};

/// Maximum number of distinct policy IDs tracked in the store.
///
/// SECURITY (FIND-R204-002): Without this bound, an attacker could create
/// versions for an unlimited number of unique policy IDs, exhausting memory
/// even within the MAX_TOTAL_VERSIONS limit (e.g. 10,000 policies × 1 version).
const MAX_TRACKED_POLICIES: usize = 1_000;

// ─── Error Type ──────────────────────────────────────────────────────────────

/// Errors from policy lifecycle operations.
///
/// All error variants produce fail-closed behavior: on any error, the
/// operation is rejected and no state mutation occurs.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LifecycleError {
    #[error("Policy not found: {0}")]
    PolicyNotFound(String),

    #[error("Version not found: policy={0} version={1}")]
    VersionNotFound(String, u64),

    #[error("Invalid status transition: {0}")]
    InvalidTransition(String),

    #[error("Approval required: {0}")]
    ApprovalRequired(String),

    #[error("Capacity exceeded: {0}")]
    CapacityExceeded(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Pluggable storage backend for policy version management.
///
/// All methods are async to support future database-backed implementations.
/// The in-memory implementation uses `tokio::sync::RwLock` for concurrency.
#[async_trait::async_trait]
pub trait PolicyVersionStore: Send + Sync {
    /// Create a new draft version for a policy.
    async fn create_version(
        &self,
        policy_id: &str,
        policy: Policy,
        created_by: &str,
        comment: Option<&str>,
    ) -> Result<PolicyVersion, LifecycleError>;

    /// Get a specific version of a policy.
    async fn get_version(
        &self,
        policy_id: &str,
        version: u64,
    ) -> Result<PolicyVersion, LifecycleError>;

    /// List all versions for a policy (newest first).
    async fn list_versions(&self, policy_id: &str) -> Result<Vec<PolicyVersion>, LifecycleError>;

    /// Get the currently active version for a policy, if any.
    async fn get_active_version(
        &self,
        policy_id: &str,
    ) -> Result<Option<PolicyVersion>, LifecycleError>;

    /// Record an approval for a version. Returns the updated version.
    async fn approve_version(
        &self,
        policy_id: &str,
        version: u64,
        approved_by: &str,
        comment: Option<&str>,
    ) -> Result<PolicyVersion, LifecycleError>;

    /// Promote a version: Draft→Staging or Staging→Active.
    /// When promoting to Active, archives the previous Active version.
    async fn promote_version(
        &self,
        policy_id: &str,
        version: u64,
    ) -> Result<PolicyVersion, LifecycleError>;

    /// Revert a promotion: set a version to Archived.
    /// Used to roll back after compile failure.
    async fn revert_promotion(
        &self,
        policy_id: &str,
        version: u64,
        original_status: PolicyVersionStatus,
    ) -> Result<(), LifecycleError>;

    /// Archive a version (Draft/Staging → Archived).
    async fn archive_version(
        &self,
        policy_id: &str,
        version: u64,
    ) -> Result<PolicyVersion, LifecycleError>;

    /// Create a new draft from an old version (rollback).
    async fn rollback(
        &self,
        policy_id: &str,
        to_version: u64,
        created_by: &str,
    ) -> Result<PolicyVersion, LifecycleError>;

    /// Compute structural diff between two versions.
    async fn diff_versions(
        &self,
        policy_id: &str,
        from_v: u64,
        to_v: u64,
    ) -> Result<PolicyVersionDiff, LifecycleError>;

    /// List policy IDs that have a version in Staging status.
    async fn list_staging_policies(&self) -> Result<Vec<String>, LifecycleError>;

    /// Return lifecycle subsystem status.
    async fn status(&self) -> PolicyLifecycleStatus;
}

// ─── In-Memory Implementation ────────────────────────────────────────────────

/// In-memory policy version store with bounded capacity.
///
/// Thread-safe via `tokio::sync::RwLock`. Suitable for single-instance
/// deployments. A future PostgreSQL-backed implementation would implement
/// the same `PolicyVersionStore` trait.
pub struct InMemoryPolicyVersionStore {
    /// Map of policy_id → list of versions (ordered by version number).
    versions: RwLock<HashMap<String, Vec<PolicyVersion>>>,
    /// Configuration controlling capacity and approval requirements.
    config: PolicyLifecycleConfig,
}

impl InMemoryPolicyVersionStore {
    /// Create a new in-memory store.
    pub fn new(config: PolicyLifecycleConfig) -> Self {
        // SECURITY (FIND-R204-006): Warn when auto_approve_roles is configured
        // but has no effect. This field is validated in config but the caller's
        // role is not passed to promote_to_active, so role-based auto-approval
        // cannot be enforced. Operators who set it would expect role-based
        // auto-approval to work, but it silently does nothing.
        if !config.auto_approve_roles.is_empty() {
            tracing::warn!(
                "policy_lifecycle: auto_approve_roles is configured ({} roles) but not \
                 enforced — role-based auto-approval is not yet implemented",
                config.auto_approve_roles.len()
            );
        }
        // SECURITY (FIND-R204-006): Warn when notification_webhook_url is set.
        // The webhook is now implemented in the route handler (notify_webhook),
        // but we log for operational visibility.
        if config.notification_webhook_url.is_some() {
            tracing::info!(
                "policy_lifecycle: notification_webhook_url configured — \
                 lifecycle events will be sent to webhook"
            );
        }

        Self {
            versions: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Count total versions across all policies.
    fn total_versions(map: &HashMap<String, Vec<PolicyVersion>>) -> usize {
        map.values().map(|v| v.len()).sum()
    }

    /// Prune oldest archived versions for a policy if over the per-policy limit.
    fn prune_archived(versions: &mut Vec<PolicyVersion>, max: usize) {
        while versions.len() > max {
            // Find the oldest Archived version and remove it
            if let Some(pos) = versions
                .iter()
                .position(|v| matches!(v.status, PolicyVersionStatus::Archived))
            {
                versions.remove(pos);
            } else {
                // No archived versions to prune — can't reduce further
                break;
            }
        }
    }

    /// Generate a version ID. Using a simple format for in-memory store.
    fn make_version_id(policy_id: &str, version: u64) -> String {
        format!("{policy_id}-v{version}")
    }

    /// Get current timestamp as ISO 8601 string.
    ///
    /// IMP-R204-007: Uses chrono (already a dependency) instead of
    /// hand-rolled date calculation that was fragile and approximate.
    fn now_iso8601() -> String {
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }
}

#[async_trait::async_trait]
impl PolicyVersionStore for InMemoryPolicyVersionStore {
    async fn create_version(
        &self,
        policy_id: &str,
        policy: Policy,
        created_by: &str,
        comment: Option<&str>,
    ) -> Result<PolicyVersion, LifecycleError> {
        // Validate inputs
        if policy_id.is_empty() || has_dangerous_chars(policy_id) {
            return Err(LifecycleError::Validation("Invalid policy_id".to_string()));
        }
        if created_by.is_empty() || has_dangerous_chars(created_by) {
            return Err(LifecycleError::Validation("Invalid created_by".to_string()));
        }
        if let Some(c) = comment {
            if c.len() > vellaveto_types::MAX_VERSION_COMMENT_LEN {
                return Err(LifecycleError::Validation("Comment too long".to_string()));
            }
            if has_dangerous_chars(c) {
                return Err(LifecycleError::Validation(
                    "Comment contains invalid characters".to_string(),
                ));
            }
        }
        // Validate the policy itself
        policy
            .validate()
            .map_err(|e| LifecycleError::Validation(format!("Policy validation: {e}")))?;

        let mut map = self.versions.write().await;

        // Check total capacity
        if Self::total_versions(&map) >= MAX_TOTAL_VERSIONS {
            return Err(LifecycleError::CapacityExceeded(format!(
                "Total version limit ({MAX_TOTAL_VERSIONS}) reached"
            )));
        }

        // SECURITY (FIND-R204-002): Bound distinct policy IDs to prevent
        // memory exhaustion via many unique policy IDs with few versions each.
        if !map.contains_key(policy_id) && map.len() >= MAX_TRACKED_POLICIES {
            return Err(LifecycleError::CapacityExceeded(format!(
                "Tracked policy limit ({MAX_TRACKED_POLICIES}) reached"
            )));
        }

        let versions = map.entry(policy_id.to_string()).or_default();

        // Next version number
        let max_ver = versions.iter().map(|v| v.version).max().unwrap_or(0);
        // SECURITY (FIND-R206-004): Guard against u64::MAX overflow. After
        // saturating_add, all subsequent versions would share the same number,
        // breaking uniqueness assumptions (get_version, diff, rollback).
        if max_ver == u64::MAX {
            return Err(LifecycleError::CapacityExceeded(
                "Maximum version number reached".to_string(),
            ));
        }
        let next_version = max_ver.saturating_add(1);

        let previous_version_id = versions.last().map(|v| v.version_id.clone());

        let pv = PolicyVersion {
            version_id: Self::make_version_id(policy_id, next_version),
            policy_id: policy_id.to_string(),
            version: next_version,
            policy,
            created_by: created_by.to_string(),
            created_at: Self::now_iso8601(),
            status: PolicyVersionStatus::Draft,
            comment: comment.map(|c| c.to_string()),
            approvals: Vec::new(),
            required_approvals: self.config.required_approvals,
            previous_version_id,
            staged_at: None,
        };

        versions.push(pv.clone());

        // Prune if over per-policy limit
        Self::prune_archived(versions, self.config.max_versions_per_policy);

        Ok(pv)
    }

    async fn get_version(
        &self,
        policy_id: &str,
        version: u64,
    ) -> Result<PolicyVersion, LifecycleError> {
        let map = self.versions.read().await;
        let versions = map
            .get(policy_id)
            .ok_or_else(|| LifecycleError::PolicyNotFound(policy_id.to_string()))?;
        versions
            .iter()
            .find(|v| v.version == version)
            .cloned()
            .ok_or_else(|| LifecycleError::VersionNotFound(policy_id.to_string(), version))
    }

    async fn list_versions(&self, policy_id: &str) -> Result<Vec<PolicyVersion>, LifecycleError> {
        let map = self.versions.read().await;
        let versions = map
            .get(policy_id)
            .ok_or_else(|| LifecycleError::PolicyNotFound(policy_id.to_string()))?;
        // Return newest first
        let mut result = versions.clone();
        result.reverse();
        Ok(result)
    }

    async fn get_active_version(
        &self,
        policy_id: &str,
    ) -> Result<Option<PolicyVersion>, LifecycleError> {
        let map = self.versions.read().await;
        match map.get(policy_id) {
            Some(versions) => Ok(versions
                .iter()
                .find(|v| matches!(v.status, PolicyVersionStatus::Active))
                .cloned()),
            None => Ok(None),
        }
    }

    async fn approve_version(
        &self,
        policy_id: &str,
        version: u64,
        approved_by: &str,
        comment: Option<&str>,
    ) -> Result<PolicyVersion, LifecycleError> {
        // Validate inputs
        if approved_by.is_empty() || has_dangerous_chars(approved_by) {
            return Err(LifecycleError::Validation(
                "Invalid approved_by".to_string(),
            ));
        }
        if let Some(c) = comment {
            if c.len() > vellaveto_types::MAX_VERSION_COMMENT_LEN || has_dangerous_chars(c) {
                return Err(LifecycleError::Validation("Invalid comment".to_string()));
            }
        }

        let mut map = self.versions.write().await;
        let versions = map
            .get_mut(policy_id)
            .ok_or_else(|| LifecycleError::PolicyNotFound(policy_id.to_string()))?;
        let pv = versions
            .iter_mut()
            .find(|v| v.version == version)
            .ok_or_else(|| LifecycleError::VersionNotFound(policy_id.to_string(), version))?;

        // Can only approve Draft or Staging versions
        if !matches!(
            pv.status,
            PolicyVersionStatus::Draft | PolicyVersionStatus::Staging
        ) {
            return Err(LifecycleError::InvalidTransition(format!(
                "Cannot approve version in {} status",
                pv.status
            )));
        }

        // SECURITY: Self-approval prevention.
        // Normalize with NFKC + Unicode case fold + homoglyph normalization
        // for robust comparison — parity with vellaveto-approval store
        // (FIND-R205-001).
        use unicode_normalization::UnicodeNormalization;
        use vellaveto_types::unicode::normalize_homoglyphs;
        let normalized_approver: String = normalize_homoglyphs(
            &approved_by
                .nfkc()
                .collect::<String>()
                .chars()
                .flat_map(char::to_lowercase)
                .collect::<String>(),
        );
        let normalized_creator: String = normalize_homoglyphs(
            &pv.created_by
                .as_str()
                .nfkc()
                .collect::<String>()
                .chars()
                .flat_map(char::to_lowercase)
                .collect::<String>(),
        );
        if normalized_approver == normalized_creator {
            return Err(LifecycleError::Validation(
                "Self-approval is not allowed".to_string(),
            ));
        }

        // Prevent duplicate approvals by the same approver
        // SECURITY (FIND-R205-001): Apply full normalization pipeline
        // (NFKC + Unicode case fold + homoglyph) for duplicate detection parity.
        if pv.approvals.iter().any(|a| {
            normalize_homoglyphs(
                &a.approved_by
                    .as_str()
                    .nfkc()
                    .collect::<String>()
                    .chars()
                    .flat_map(char::to_lowercase)
                    .collect::<String>(),
            ) == normalized_approver
        }) {
            return Err(LifecycleError::Validation(
                "Already approved by this approver".to_string(),
            ));
        }

        // Check bounds
        if pv.approvals.len() >= vellaveto_types::MAX_APPROVALS_PER_VERSION {
            return Err(LifecycleError::CapacityExceeded(
                "Maximum approvals reached".to_string(),
            ));
        }

        pv.approvals.push(PolicyApproval {
            approved_by: approved_by.to_string(),
            approved_at: Self::now_iso8601(),
            comment: comment.map(|c| c.to_string()),
        });

        Ok(pv.clone())
    }

    async fn promote_version(
        &self,
        policy_id: &str,
        version: u64,
    ) -> Result<PolicyVersion, LifecycleError> {
        let mut map = self.versions.write().await;
        let versions = map
            .get_mut(policy_id)
            .ok_or_else(|| LifecycleError::PolicyNotFound(policy_id.to_string()))?;

        // Find the target version
        let idx = versions
            .iter()
            .position(|v| v.version == version)
            .ok_or_else(|| LifecycleError::VersionNotFound(policy_id.to_string(), version))?;

        let pv = &versions[idx];

        // Check approval requirements.
        // NOTE: auto_approve_roles is parsed and validated in PolicyLifecycleConfig
        // but requires RBAC role context at the route layer to enforce. The promote
        // endpoint is admin-only (RBAC gate), which provides a baseline guarantee.
        // Full role-based auto-approval requires passing caller_role through promote_version.
        if self.config.required_approvals > 0
            && (pv.approvals.len() as u32) < self.config.required_approvals
        {
            return Err(LifecycleError::ApprovalRequired(format!(
                "Need {} approvals, have {}",
                self.config.required_approvals,
                pv.approvals.len()
            )));
        }

        match pv.status {
            PolicyVersionStatus::Draft => {
                if self.config.staging_period_secs == 0 {
                    // Skip staging: Draft → Active
                    // Archive current active version first
                    for v in versions.iter_mut() {
                        if matches!(v.status, PolicyVersionStatus::Active) {
                            v.status = PolicyVersionStatus::Archived;
                        }
                    }
                    versions[idx].status = PolicyVersionStatus::Active;
                } else {
                    // Draft → Staging
                    // Only one staging version per policy
                    if versions
                        .iter()
                        .any(|v| matches!(v.status, PolicyVersionStatus::Staging))
                    {
                        return Err(LifecycleError::InvalidTransition(
                            "Another version is already in staging".to_string(),
                        ));
                    }
                    versions[idx].status = PolicyVersionStatus::Staging;
                    // SECURITY (FIND-R204-002): Record when the version entered
                    // Staging so we can enforce staging_period_secs later.
                    versions[idx].staged_at = Some(Self::now_iso8601());
                }
            }
            PolicyVersionStatus::Staging => {
                // SECURITY (FIND-R204-002): Enforce staging_period_secs before
                // allowing Staging → Active promotion. Without this check, an
                // operator who configures a staging period would be surprised
                // when policies can be promoted immediately.
                if self.config.staging_period_secs > 0 {
                    if let Some(ref staged_at) = versions[idx].staged_at {
                        // Parse the staged_at timestamp using chrono for accurate
                        // epoch seconds. NOTE: We cannot use parse_iso8601_secs()
                        // here because it uses an approximate formula (365d/year,
                        // 30d/month) that's only suitable for relative comparisons
                        // between two timestamps parsed by the same function.
                        let staged_secs = chrono::NaiveDateTime::parse_from_str(
                            staged_at.trim_end_matches('Z'),
                            "%Y-%m-%dT%H:%M:%S",
                        )
                        // SECURITY (R240-P3-SRV-2): Use try_from to avoid wrap on pre-epoch timestamps.
                        .map(|ndt| u64::try_from(ndt.and_utc().timestamp()).unwrap_or(u64::MAX))
                        .unwrap_or(u64::MAX); // fail-closed: unparseable = never staged
                        let now_secs = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
                        let elapsed = now_secs.saturating_sub(staged_secs);
                        let required = self.config.staging_period_secs;
                        if elapsed < required {
                            let remaining = required.saturating_sub(elapsed);
                            return Err(LifecycleError::InvalidTransition(format!(
                                "Staging period not yet elapsed: {} seconds remaining (required: {}s)",
                                remaining, self.config.staging_period_secs
                            )));
                        }
                    } else {
                        // No staged_at timestamp — fail-closed: cannot determine
                        // when staging started, so reject promotion.
                        return Err(LifecycleError::InvalidTransition(
                            "Cannot promote: staged_at timestamp missing (staging period not tracked)".to_string(),
                        ));
                    }
                }
                // Staging → Active: archive current active
                for v in versions.iter_mut() {
                    if matches!(v.status, PolicyVersionStatus::Active) {
                        v.status = PolicyVersionStatus::Archived;
                    }
                }
                versions[idx].status = PolicyVersionStatus::Active;
            }
            PolicyVersionStatus::Active => {
                return Err(LifecycleError::InvalidTransition(
                    "Version is already active".to_string(),
                ));
            }
            PolicyVersionStatus::Archived => {
                return Err(LifecycleError::InvalidTransition(
                    "Cannot promote an archived version — use rollback instead".to_string(),
                ));
            }
            // Handle future variants
            _ => {
                return Err(LifecycleError::InvalidTransition(
                    "Unknown version status".to_string(),
                ));
            }
        }

        Ok(versions[idx].clone())
    }

    async fn revert_promotion(
        &self,
        policy_id: &str,
        version: u64,
        original_status: PolicyVersionStatus,
    ) -> Result<(), LifecycleError> {
        // SECURITY (FIND-R204-001): Only Draft and Staging are valid revert
        // targets. Allowing Active or Archived would let callers bypass the
        // approval workflow entirely by reverting directly to Active.
        match original_status {
            PolicyVersionStatus::Draft | PolicyVersionStatus::Staging => {}
            _ => {
                return Err(LifecycleError::InvalidTransition(format!(
                    "Cannot revert to {original_status} status — only Draft or Staging are valid revert targets"
                )));
            }
        }

        let mut map = self.versions.write().await;
        let versions = map
            .get_mut(policy_id)
            .ok_or_else(|| LifecycleError::PolicyNotFound(policy_id.to_string()))?;
        let pv = versions
            .iter_mut()
            .find(|v| v.version == version)
            .ok_or_else(|| LifecycleError::VersionNotFound(policy_id.to_string(), version))?;
        pv.status = original_status;
        Ok(())
    }

    async fn archive_version(
        &self,
        policy_id: &str,
        version: u64,
    ) -> Result<PolicyVersion, LifecycleError> {
        let mut map = self.versions.write().await;
        let versions = map
            .get_mut(policy_id)
            .ok_or_else(|| LifecycleError::PolicyNotFound(policy_id.to_string()))?;
        let pv = versions
            .iter_mut()
            .find(|v| v.version == version)
            .ok_or_else(|| LifecycleError::VersionNotFound(policy_id.to_string(), version))?;

        match pv.status {
            PolicyVersionStatus::Draft | PolicyVersionStatus::Staging => {
                pv.status = PolicyVersionStatus::Archived;
                Ok(pv.clone())
            }
            PolicyVersionStatus::Active => Err(LifecycleError::InvalidTransition(
                "Cannot directly archive an active version — promote a replacement first"
                    .to_string(),
            )),
            PolicyVersionStatus::Archived => Err(LifecycleError::InvalidTransition(
                "Version is already archived".to_string(),
            )),
            _ => Err(LifecycleError::InvalidTransition(
                "Unknown version status".to_string(),
            )),
        }
    }

    async fn rollback(
        &self,
        policy_id: &str,
        to_version: u64,
        created_by: &str,
    ) -> Result<PolicyVersion, LifecycleError> {
        if created_by.is_empty() || has_dangerous_chars(created_by) {
            return Err(LifecycleError::Validation("Invalid created_by".to_string()));
        }

        let mut map = self.versions.write().await;

        // Check total capacity
        if Self::total_versions(&map) >= MAX_TOTAL_VERSIONS {
            return Err(LifecycleError::CapacityExceeded(format!(
                "Total version limit ({MAX_TOTAL_VERSIONS}) reached"
            )));
        }

        let versions = map
            .get_mut(policy_id)
            .ok_or_else(|| LifecycleError::PolicyNotFound(policy_id.to_string()))?;

        // Find the source version to rollback to
        let source = versions
            .iter()
            .find(|v| v.version == to_version)
            .ok_or_else(|| LifecycleError::VersionNotFound(policy_id.to_string(), to_version))?;

        let policy_clone = source.policy.clone();
        let source_version_id = source.version_id.clone();

        let max_ver = versions.iter().map(|v| v.version).max().unwrap_or(0);
        // SECURITY (FIND-R206-004): Guard against u64::MAX overflow (parity
        // with create_version).
        if max_ver == u64::MAX {
            return Err(LifecycleError::CapacityExceeded(
                "Maximum version number reached".to_string(),
            ));
        }
        let next_version = max_ver.saturating_add(1);

        let pv = PolicyVersion {
            version_id: Self::make_version_id(policy_id, next_version),
            policy_id: policy_id.to_string(),
            version: next_version,
            policy: policy_clone,
            created_by: created_by.to_string(),
            created_at: Self::now_iso8601(),
            status: PolicyVersionStatus::Draft,
            comment: Some(format!("Rollback from version {to_version}")),
            approvals: Vec::new(),
            required_approvals: self.config.required_approvals,
            previous_version_id: Some(source_version_id),
            staged_at: None,
        };

        versions.push(pv.clone());
        Self::prune_archived(versions, self.config.max_versions_per_policy);

        Ok(pv)
    }

    async fn diff_versions(
        &self,
        policy_id: &str,
        from_v: u64,
        to_v: u64,
    ) -> Result<PolicyVersionDiff, LifecycleError> {
        let map = self.versions.read().await;
        let versions = map
            .get(policy_id)
            .ok_or_else(|| LifecycleError::PolicyNotFound(policy_id.to_string()))?;

        let from = versions
            .iter()
            .find(|v| v.version == from_v)
            .ok_or_else(|| LifecycleError::VersionNotFound(policy_id.to_string(), from_v))?;
        let to = versions
            .iter()
            .find(|v| v.version == to_v)
            .ok_or_else(|| LifecycleError::VersionNotFound(policy_id.to_string(), to_v))?;

        let mut changes = diff_policies(&from.policy, &to.policy);
        // Bound changes to MAX_DIFF_CHANGES
        changes.truncate(MAX_DIFF_CHANGES);

        Ok(PolicyVersionDiff {
            policy_id: policy_id.to_string(),
            from_version: from_v,
            to_version: to_v,
            changes,
        })
    }

    async fn list_staging_policies(&self) -> Result<Vec<String>, LifecycleError> {
        let map = self.versions.read().await;
        let mut result = Vec::new();
        for (policy_id, versions) in map.iter() {
            if versions
                .iter()
                .any(|v| matches!(v.status, PolicyVersionStatus::Staging))
            {
                result.push(policy_id.clone());
            }
        }
        result.sort();
        Ok(result)
    }

    async fn status(&self) -> PolicyLifecycleStatus {
        let map = self.versions.read().await;
        let total_versions: usize = map.values().map(|v| v.len()).sum();
        let staging_count = map
            .values()
            .filter(|versions| {
                versions
                    .iter()
                    .any(|v| matches!(v.status, PolicyVersionStatus::Staging))
            })
            .count();
        PolicyLifecycleStatus {
            enabled: true,
            tracked_policies: map.len(),
            total_versions,
            staging_count,
            approval_workflow_enabled: self.config.required_approvals > 0,
        }
    }
}

/// Compare two policies and return human-readable change descriptions.
/// Reuses the same structural diff logic as `simulator.rs:diff_policies()`.
fn diff_policies(before: &Policy, after: &Policy) -> Vec<String> {
    let mut changes = Vec::new();

    if before.id != after.id {
        changes.push(format!("id: '{}' -> '{}'", before.id, after.id));
    }
    if before.name != after.name {
        changes.push(format!("name: '{}' -> '{}'", before.name, after.name));
    }
    // SECURITY (IMP-R204-020): Use direct PartialEq comparison instead of
    // Debug-format string comparison. Debug formatting allocates two strings
    // per comparison and is fragile if the Debug representation changes.
    if before.policy_type != after.policy_type {
        changes.push(format!(
            "type: {:?} -> {:?}",
            before.policy_type, after.policy_type
        ));
    }
    if before.priority != after.priority {
        changes.push(format!(
            "priority: {} -> {}",
            before.priority, after.priority
        ));
    }
    if before.path_rules != after.path_rules {
        changes.push("path_rules changed".to_string());
    }
    if before.network_rules != after.network_rules {
        changes.push("network_rules changed".to_string());
    }

    changes
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_types::PolicyType;

    fn test_config() -> PolicyLifecycleConfig {
        PolicyLifecycleConfig {
            enabled: true,
            required_approvals: 1,
            auto_approve_roles: vec![],
            staging_period_secs: 3600,
            notification_webhook_url: None,
            max_versions_per_policy: 50,
        }
    }

    fn test_policy(id: &str) -> Policy {
        Policy {
            id: id.to_string(),
            name: format!("Test Policy {id}"),
            policy_type: PolicyType::Allow,
            priority: 0,
            path_rules: None,
            network_rules: None,
        }
    }

    #[tokio::test]
    async fn test_create_version() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        let pv = store
            .create_version("pol-1", test_policy("pol-1"), "alice", Some("first draft"))
            .await
            .unwrap();
        assert_eq!(pv.version, 1);
        assert_eq!(pv.policy_id, "pol-1");
        assert!(matches!(pv.status, PolicyVersionStatus::Draft));
        assert_eq!(pv.created_by, "alice");
        assert_eq!(pv.comment, Some("first draft".to_string()));
        assert_eq!(pv.required_approvals, 1);
    }

    #[tokio::test]
    async fn test_create_multiple_versions() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        let v2 = store
            .create_version("pol-1", test_policy("pol-1"), "bob", None)
            .await
            .unwrap();
        assert_eq!(v2.version, 2);
        assert!(v2.previous_version_id.is_some());
    }

    #[tokio::test]
    async fn test_get_version() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        let pv = store.get_version("pol-1", 1).await.unwrap();
        assert_eq!(pv.version, 1);
    }

    #[tokio::test]
    async fn test_get_version_not_found() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        let result = store.get_version("pol-1", 1).await;
        assert!(matches!(result, Err(LifecycleError::PolicyNotFound(_))));
    }

    #[tokio::test]
    async fn test_list_versions_newest_first() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .create_version("pol-1", test_policy("pol-1"), "bob", None)
            .await
            .unwrap();
        let versions = store.list_versions("pol-1").await.unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, 2); // newest first
        assert_eq!(versions[1].version, 1);
    }

    #[tokio::test]
    async fn test_approve_version() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        let pv = store
            .approve_version("pol-1", 1, "bob", Some("approved"))
            .await
            .unwrap();
        assert_eq!(pv.approvals.len(), 1);
        assert_eq!(pv.approvals[0].approved_by, "bob");
    }

    #[tokio::test]
    async fn test_self_approval_rejected() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        let result = store.approve_version("pol-1", 1, "alice", None).await;
        assert!(
            matches!(result, Err(LifecycleError::Validation(ref msg)) if msg.contains("Self-approval"))
        );
    }

    #[tokio::test]
    async fn test_self_approval_case_insensitive() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "Alice", None)
            .await
            .unwrap();
        let result = store.approve_version("pol-1", 1, "ALICE", None).await;
        assert!(
            matches!(result, Err(LifecycleError::Validation(ref msg)) if msg.contains("Self-approval"))
        );
    }

    #[tokio::test]
    async fn test_duplicate_approval_rejected() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        let result = store.approve_version("pol-1", 1, "bob", None).await;
        assert!(
            matches!(result, Err(LifecycleError::Validation(ref msg)) if msg.contains("Already approved"))
        );
    }

    #[tokio::test]
    async fn test_promote_draft_to_staging() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        let pv = store.promote_version("pol-1", 1).await.unwrap();
        assert!(matches!(pv.status, PolicyVersionStatus::Staging));
    }

    #[tokio::test]
    async fn test_promote_staging_to_active() {
        // Use staging_period_secs = 0 so Staging→Active is immediate
        let mut config = test_config();
        config.staging_period_secs = 0;
        let store = InMemoryPolicyVersionStore::new(config);
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        // With staging_period_secs = 0, Draft→Active directly
        let pv = store.promote_version("pol-1", 1).await.unwrap();
        assert!(matches!(pv.status, PolicyVersionStatus::Active));
    }

    #[tokio::test]
    async fn test_promote_to_active_archives_previous() {
        let mut config = test_config();
        config.staging_period_secs = 0; // skip staging
        let store = InMemoryPolicyVersionStore::new(config);

        // Create and promote v1 to Active
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        store.promote_version("pol-1", 1).await.unwrap();

        // Create and promote v2 to Active
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 2, "bob", None)
            .await
            .unwrap();
        store.promote_version("pol-1", 2).await.unwrap();

        // v1 should now be archived
        let v1 = store.get_version("pol-1", 1).await.unwrap();
        assert!(matches!(v1.status, PolicyVersionStatus::Archived));
    }

    #[tokio::test]
    async fn test_promote_without_approval_rejected() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        let result = store.promote_version("pol-1", 1).await;
        assert!(matches!(result, Err(LifecycleError::ApprovalRequired(_))));
    }

    #[tokio::test]
    async fn test_archive_draft() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        let pv = store.archive_version("pol-1", 1).await.unwrap();
        assert!(matches!(pv.status, PolicyVersionStatus::Archived));
    }

    #[tokio::test]
    async fn test_archive_active_rejected() {
        let mut config = test_config();
        config.staging_period_secs = 0;
        let store = InMemoryPolicyVersionStore::new(config);
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        store.promote_version("pol-1", 1).await.unwrap();
        let result = store.archive_version("pol-1", 1).await;
        assert!(matches!(result, Err(LifecycleError::InvalidTransition(_))));
    }

    #[tokio::test]
    async fn test_rollback_creates_new_draft() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .create_version("pol-1", test_policy("pol-1"), "bob", None)
            .await
            .unwrap();
        let rollback = store.rollback("pol-1", 1, "charlie").await.unwrap();
        assert_eq!(rollback.version, 3);
        assert!(matches!(rollback.status, PolicyVersionStatus::Draft));
        assert!(rollback
            .comment
            .as_ref()
            .unwrap()
            .contains("Rollback from version 1"));
    }

    #[tokio::test]
    async fn test_diff_versions() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        let mut p2 = test_policy("pol-1");
        p2.name = "Updated Policy".to_string();
        p2.priority = 10;
        store
            .create_version("pol-1", p2, "alice", None)
            .await
            .unwrap();
        let diff = store.diff_versions("pol-1", 1, 2).await.unwrap();
        assert_eq!(diff.from_version, 1);
        assert_eq!(diff.to_version, 2);
        assert!(diff.changes.iter().any(|c| c.contains("name")));
        assert!(diff.changes.iter().any(|c| c.contains("priority")));
    }

    #[tokio::test]
    async fn test_list_staging_policies() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        store.promote_version("pol-1", 1).await.unwrap(); // → staging
        let staging = store.list_staging_policies().await.unwrap();
        assert_eq!(staging, vec!["pol-1"]);
    }

    #[tokio::test]
    async fn test_status() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        let status = store.status().await;
        assert!(status.enabled);
        assert_eq!(status.tracked_policies, 1);
        assert_eq!(status.total_versions, 1);
        assert_eq!(status.staging_count, 0);
        assert!(status.approval_workflow_enabled);
    }

    #[tokio::test]
    async fn test_dangerous_chars_rejected() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        let result = store
            .create_version("pol\x00-1", test_policy("pol-1"), "alice", None)
            .await;
        assert!(matches!(result, Err(LifecycleError::Validation(_))));
    }

    #[tokio::test]
    async fn test_revert_promotion() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        store.promote_version("pol-1", 1).await.unwrap(); // → staging
        store
            .revert_promotion("pol-1", 1, PolicyVersionStatus::Draft)
            .await
            .unwrap();
        let pv = store.get_version("pol-1", 1).await.unwrap();
        assert!(matches!(pv.status, PolicyVersionStatus::Draft));
    }

    // ── Adversarial tests (FIND-R204-*) ───────────────────────────────────

    /// SECURITY (FIND-R204-001): Reverting to Active status would bypass the
    /// approval workflow entirely. Only Draft and Staging are valid targets.
    #[tokio::test]
    async fn test_revert_promotion_to_active_rejected() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        store.promote_version("pol-1", 1).await.unwrap(); // → staging

        // Attempt to revert to Active — must fail
        let result = store
            .revert_promotion("pol-1", 1, PolicyVersionStatus::Active)
            .await;
        assert!(
            matches!(result, Err(LifecycleError::InvalidTransition(ref msg)) if msg.contains("valid revert targets")),
            "expected InvalidTransition, got: {result:?}"
        );
    }

    /// SECURITY (FIND-R204-001): Reverting to Archived is also invalid.
    #[tokio::test]
    async fn test_revert_promotion_to_archived_rejected() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        store.promote_version("pol-1", 1).await.unwrap(); // → staging

        let result = store
            .revert_promotion("pol-1", 1, PolicyVersionStatus::Archived)
            .await;
        assert!(matches!(result, Err(LifecycleError::InvalidTransition(_))));
    }

    /// SECURITY (FIND-R204-002): Creating versions for too many distinct
    /// policy IDs must be rejected to prevent HashMap memory exhaustion.
    #[tokio::test]
    async fn test_tracked_policy_limit_enforced() {
        let mut config = test_config();
        config.max_versions_per_policy = 50;
        let store = InMemoryPolicyVersionStore::new(config);

        // Create versions for MAX_TRACKED_POLICIES distinct policies
        for i in 0..super::MAX_TRACKED_POLICIES {
            let pid = format!("pol-{i}");
            store
                .create_version(&pid, test_policy(&pid), "alice", None)
                .await
                .unwrap();
        }

        // One more should fail
        let result = store
            .create_version("pol-overflow", test_policy("pol-overflow"), "alice", None)
            .await;
        assert!(
            matches!(result, Err(LifecycleError::CapacityExceeded(ref msg)) if msg.contains("Tracked policy limit")),
            "expected CapacityExceeded, got: {result:?}"
        );
    }

    /// SECURITY: Verify that promoting from Archived is rejected (can't skip
    /// back to Draft→Staging→Active via promote).
    #[tokio::test]
    async fn test_promote_archived_rejected() {
        let mut config = test_config();
        config.required_approvals = 0; // skip approval requirement
        let store = InMemoryPolicyVersionStore::new(config);
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        // Archive the draft
        store.archive_version("pol-1", 1).await.unwrap();
        // Try to promote the archived version
        let result = store.promote_version("pol-1", 1).await;
        assert!(
            matches!(result, Err(LifecycleError::InvalidTransition(ref msg)) if msg.contains("rollback")),
            "expected InvalidTransition about rollback, got: {result:?}"
        );
    }

    /// SECURITY: Verify double-staging is rejected (only one staging version
    /// per policy at a time).
    #[tokio::test]
    async fn test_only_one_staging_per_policy() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        // Create and promote v1 to staging
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        store.promote_version("pol-1", 1).await.unwrap(); // → staging

        // Create v2 and try to also stage it
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 2, "bob", None)
            .await
            .unwrap();
        let result = store.promote_version("pol-1", 2).await;
        assert!(
            matches!(result, Err(LifecycleError::InvalidTransition(ref msg)) if msg.contains("already in staging")),
            "expected InvalidTransition about staging, got: {result:?}"
        );
    }

    /// SECURITY (FIND-R204-002): Staging period must be enforced.
    /// Immediate Staging → Active should be rejected when staging_period_secs > 0.
    #[tokio::test]
    async fn test_staging_period_enforced() {
        let store = InMemoryPolicyVersionStore::new(test_config()); // staging_period_secs = 3600
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        store.promote_version("pol-1", 1).await.unwrap(); // → Staging (sets staged_at)

        // Immediate Staging → Active should fail
        let result = store.promote_version("pol-1", 1).await;
        assert!(
            matches!(result, Err(LifecycleError::InvalidTransition(ref msg)) if msg.contains("Staging period not yet elapsed")),
            "expected staging period not elapsed, got: {result:?}"
        );
    }

    /// SECURITY (FIND-R204-002): When staging_period_secs = 0, Staging→Active should work
    /// (staging period enforcement is only active when configured > 0).
    #[tokio::test]
    async fn test_staging_period_zero_allows_immediate_promote() {
        let mut config = test_config();
        config.staging_period_secs = 0;
        // With staging_period_secs = 0, Draft→Active directly (no staging)
        let store = InMemoryPolicyVersionStore::new(config);
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        let pv = store.promote_version("pol-1", 1).await.unwrap();
        assert!(matches!(pv.status, PolicyVersionStatus::Active));
    }

    /// SECURITY (FIND-R204-002): staged_at field should be set when entering Staging.
    #[tokio::test]
    async fn test_staged_at_set_on_staging() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        store.promote_version("pol-1", 1).await.unwrap(); // → Staging

        let pv = store.get_version("pol-1", 1).await.unwrap();
        assert!(pv.staged_at.is_some(), "staged_at should be set on Staging");
        // Verify it's a valid ISO 8601 timestamp
        let ts = pv.staged_at.unwrap();
        assert!(ts.ends_with('Z'), "staged_at should end with Z: {ts}");
        assert!(
            ts.len() >= 20,
            "staged_at should be at least 20 chars: {ts}"
        );
    }

    // ── FIND-R205-001: Homoglyph self-approval bypass prevention ──

    /// SECURITY (FIND-R205-001): Self-approval via Cyrillic 'а' (U+0430) homoglyph
    /// must be detected. NFKC does NOT normalize cross-script confusables.
    #[tokio::test]
    async fn test_self_approval_cyrillic_homoglyph_rejected() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        // Cyrillic 'а' (U+0430) looks identical to Latin 'a'
        let result = store
            .approve_version("pol-1", 1, "\u{0430}lice", None)
            .await;
        assert!(
            matches!(result, Err(LifecycleError::Validation(ref msg)) if msg.contains("Self-approval")),
            "Cyrillic homoglyph self-approval must be rejected, got: {result:?}"
        );
    }

    /// SECURITY (FIND-R205-001): Greek alpha (U+03B1) homoglyph self-approval.
    #[tokio::test]
    async fn test_self_approval_greek_homoglyph_rejected() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        store
            .create_version("pol-1", test_policy("pol-1"), "alpha", None)
            .await
            .unwrap();
        // Greek α (U+03B1) looks identical to Latin 'a'
        let result = store
            .approve_version("pol-1", 1, "\u{03B1}lpha", None)
            .await;
        assert!(
            matches!(result, Err(LifecycleError::Validation(ref msg)) if msg.contains("Self-approval")),
            "Greek homoglyph self-approval must be rejected, got: {result:?}"
        );
    }

    /// SECURITY (FIND-R205-001): Duplicate approver detection with homoglyphs.
    /// Two approvers that differ only by Cyrillic confusables should be treated
    /// as the same person.
    #[tokio::test]
    async fn test_duplicate_approval_cyrillic_homoglyph_rejected() {
        let mut config = test_config();
        config.required_approvals = 2; // need 2 approvals
        let store = InMemoryPolicyVersionStore::new(config);
        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        // First approval by "bob" succeeds
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        // Second approval by "bоb" (Cyrillic 'о' U+043E) should be detected as duplicate
        let result = store.approve_version("pol-1", 1, "b\u{043E}b", None).await;
        assert!(
            matches!(result, Err(LifecycleError::Validation(ref msg)) if msg.contains("Already approved")),
            "Homoglyph duplicate approval must be rejected, got: {result:?}"
        );
    }

    /// SECURITY (FIND-R205-001): Verify Unicode case folding uses
    /// chars().flat_map(char::to_lowercase) for consistency with approval store.
    #[tokio::test]
    async fn test_self_approval_unicode_case_fold_parity() {
        let store = InMemoryPolicyVersionStore::new(test_config());
        // Turkish İ (U+0130) — .to_lowercase() on the full string may differ
        // from chars().flat_map(char::to_lowercase) for some locales.
        // Ensure the comparison is consistent.
        store
            .create_version("pol-1", test_policy("pol-1"), "\u{0130}d-1", None)
            .await
            .unwrap();
        // Lowercase 'i' should match after proper Unicode case folding
        let result = store
            .approve_version("pol-1", 1, "i\u{0307}d-1", None)
            .await;
        // This should be detected as self-approval since İ lowercases to i̇ (i + combining dot above)
        assert!(
            matches!(result, Err(LifecycleError::Validation(ref msg)) if msg.contains("Self-approval")),
            "Unicode case fold parity: {result:?}"
        );
    }

    // ─── auto_approve_roles tests ───────────────────────────────────────────

    #[tokio::test]
    async fn test_auto_approve_roles_does_not_bypass_approval() {
        // SECURITY: auto_approve_roles is configured but NOT enforced because
        // caller role is not available at the store layer. Approval should
        // still be required regardless of auto_approve_roles configuration.
        let mut config = test_config();
        config.required_approvals = 1;
        config.auto_approve_roles = vec!["senior-admin".to_string()];
        let store = InMemoryPolicyVersionStore::new(config);

        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();

        // Attempt to promote without any approvals — should be rejected
        // even though auto_approve_roles is configured, because we cannot
        // verify the caller has the required role.
        let result = store.promote_version("pol-1", 1).await;
        assert!(
            matches!(result, Err(LifecycleError::ApprovalRequired(_))),
            "auto_approve_roles should NOT bypass approval without role verification: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_promote_succeeds_with_approval_even_with_auto_approve_roles() {
        // When auto_approve_roles is configured AND approval is provided,
        // promotion should work normally.
        let mut config = test_config();
        config.required_approvals = 1;
        config.auto_approve_roles = vec!["senior-admin".to_string()];
        let store = InMemoryPolicyVersionStore::new(config);

        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        let pv = store.promote_version("pol-1", 1).await.unwrap();
        assert!(matches!(pv.status, PolicyVersionStatus::Staging));
    }

    #[tokio::test]
    async fn test_zero_required_approvals_allows_promote_without_approval() {
        // When required_approvals is 0, promotion should succeed without
        // any approvals regardless of auto_approve_roles.
        let mut config = test_config();
        config.required_approvals = 0;
        config.auto_approve_roles = vec![];
        let store = InMemoryPolicyVersionStore::new(config);

        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        let pv = store.promote_version("pol-1", 1).await.unwrap();
        assert!(matches!(pv.status, PolicyVersionStatus::Staging));
    }

    // ─── notification_webhook_url config tests ──────────────────────────────

    #[tokio::test]
    async fn test_webhook_config_does_not_affect_store_operations() {
        // Webhook notification is handled at the route layer, not the store
        // layer. Configuring a webhook URL should not change store behavior.
        let mut config = test_config();
        config.notification_webhook_url = Some("https://hooks.example.com/lifecycle".to_string());
        let store = InMemoryPolicyVersionStore::new(config);

        store
            .create_version("pol-1", test_policy("pol-1"), "alice", None)
            .await
            .unwrap();
        store
            .approve_version("pol-1", 1, "bob", None)
            .await
            .unwrap();
        let pv = store.promote_version("pol-1", 1).await.unwrap();
        assert!(matches!(pv.status, PolicyVersionStatus::Staging));
    }
}
