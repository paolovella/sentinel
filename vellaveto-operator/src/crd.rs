// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Custom Resource Definitions for the Vellaveto Kubernetes operator.
//!
//! Three CRDs are defined:
//! - `VellavetoCluster` — manages a Vellaveto server deployment
//! - `VellavetoPolicy` — declarative policy management
//! - `VellavetoTenant` — declarative tenant management

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════

/// Maximum cluster replicas.
const MAX_CLUSTER_REPLICAS: i32 = 10;

/// Maximum container image string length.
const MAX_IMAGE_LEN: usize = 512;

/// Maximum version tag length.
const MAX_VERSION_LEN: usize = 128;

/// Maximum cluster_ref name length.
const MAX_CLUSTER_REF_LEN: usize = 253;

/// Maximum tenant ID length (mirrors server validation).
const MAX_TENANT_ID_LEN: usize = 64;

/// Maximum tenant name length.
const MAX_TENANT_NAME_LEN: usize = 256;

/// Maximum metadata entries per tenant.
const MAX_TENANT_METADATA: usize = 100;

/// Maximum metadata key length.
const MAX_METADATA_KEY_LEN: usize = 128;

/// Maximum metadata value length.
const MAX_METADATA_VALUE_LEN: usize = 1024;

/// Maximum policy ID length (mirrors vellaveto-types).
const MAX_POLICY_ID_LEN: usize = 256;

/// Maximum policy name length (mirrors vellaveto-types).
const MAX_POLICY_NAME_LEN: usize = 512;

/// Maximum path rules entries.
const MAX_PATH_RULES: usize = 1_000;

/// Maximum domain rules entries.
const MAX_DOMAIN_RULES: usize = 1_000;

/// Maximum CIDR rules entries.
const MAX_CIDR_RULES: usize = 500;

/// Maximum conditions JSON size in bytes.
const MAX_CONDITIONS_SIZE: usize = 65_536;

/// Maximum staging period in seconds (30 days).
const MAX_STAGING_PERIOD_SECS: u64 = 2_592_000;

/// Maximum config override string length.
const MAX_CONFIG_OVERRIDE_LEN: usize = 4096;

/// Maximum resource value string length (e.g. "100m", "512Mi").
const MAX_RESOURCE_VALUE_LEN: usize = 64;

/// Maximum length of a single rule entry in PathRulesSpec/NetworkRulesSpec.
const MAX_RULE_ENTRY_LEN: usize = 1024;

/// Maximum Condition message length.
const MAX_CONDITION_MESSAGE_LEN: usize = 1024;

/// Maximum evaluations per minute upper bound.
const MAX_EVALUATIONS_PER_MINUTE_UPPER: u64 = 1_000_000;

/// Maximum policies upper bound.
const MAX_POLICIES_UPPER: u64 = 100_000;

/// Maximum pending approvals upper bound.
const MAX_PENDING_APPROVALS_UPPER: u64 = 10_000;

/// Maximum audit retention days upper bound (10 years).
const MAX_AUDIT_RETENTION_DAYS_UPPER: u64 = 3650;

// ═══════════════════════════════════════════════════
// VellavetoCluster CRD
// ═══════════════════════════════════════════════════

/// Manages a Vellaveto server deployment on Kubernetes.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "vellaveto.io",
    version = "v1alpha1",
    kind = "VellavetoCluster",
    namespaced
)]
#[kube(status = "VellavetoClusterStatus")]
#[kube(
    printcolumn = r#"{"name":"Replicas","type":"integer","jsonPath":".spec.replicas"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Ready","type":"integer","jsonPath":".status.readyReplicas"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct VellavetoClusterSpec {
    /// Number of Vellaveto server replicas (1-10).
    pub replicas: i32,
    /// Container image (e.g. "ghcr.io/paolovella/vellaveto:4.0.0").
    pub image: String,
    /// Application version tag override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Configuration overrides applied to the generated ConfigMap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<VellavetoConfigOverrides>,
    /// Kubernetes resource requirements for the Vellaveto pods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
}

/// Subset of Vellaveto configuration fields overridable via the CRD.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct VellavetoConfigOverrides {
    /// Security enforcement mode (e.g. "strict", "permissive", "audit").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_mode: Option<String>,
    /// Enable EU AI Act compliance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eu_ai_act_enabled: Option<bool>,
    /// Enable DORA compliance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dora_enabled: Option<bool>,
    /// Enable NIS2 compliance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nis2_enabled: Option<bool>,
    /// Enable audit logging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_enabled: Option<bool>,
    /// Global rate limit (evaluations per second).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_rps: Option<u32>,
}

/// Kubernetes resource requirements (simplified for CRD schema).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct ResourceRequirements {
    /// CPU request (e.g. "100m").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_request: Option<String>,
    /// Memory request (e.g. "128Mi").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_request: Option<String>,
    /// CPU limit (e.g. "500m").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_limit: Option<String>,
    /// Memory limit (e.g. "512Mi").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_limit: Option<String>,
}

/// Status subresource for VellavetoCluster.
///
/// SECURITY (FIND-R224-002): `deny_unknown_fields` is safe here because the status
/// subresource is entirely operator-controlled — Kubernetes stores exactly what the
/// operator writes and validates against the CRD schema.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct VellavetoClusterStatus {
    /// Current phase: Pending, Running, or Failed.
    #[serde(default)]
    pub phase: ClusterPhase,
    /// Desired replica count.
    #[serde(default)]
    pub replicas: i32,
    /// Number of ready replicas.
    #[serde(default, rename = "readyReplicas")]
    pub ready_replicas: i32,
    /// Standard Kubernetes conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    /// Last observed generation of the spec.
    #[serde(default, rename = "observedGeneration")]
    pub observed_generation: i64,
}

/// Phase of a VellavetoCluster.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
pub enum ClusterPhase {
    #[default]
    Pending,
    Running,
    Failed,
}

// ═══════════════════════════════════════════════════
// VellavetoPolicy CRD
// ═══════════════════════════════════════════════════

/// Declarative policy management — syncs policies to a Vellaveto cluster.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "vellaveto.io",
    version = "v1alpha1",
    kind = "VellavetoPolicy",
    namespaced
)]
#[kube(status = "VellavetoPolicyStatus")]
#[kube(
    printcolumn = r#"{"name":"Cluster","type":"string","jsonPath":".spec.clusterRef"}"#,
    printcolumn = r#"{"name":"PolicyID","type":"string","jsonPath":".spec.policy.id"}"#,
    printcolumn = r#"{"name":"Type","type":"string","jsonPath":".spec.policy.policyType"}"#,
    printcolumn = r#"{"name":"Synced","type":"boolean","jsonPath":".status.synced"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct VellavetoPolicySpec {
    /// Name of the target VellavetoCluster in the same namespace.
    #[serde(rename = "clusterRef")]
    pub cluster_ref: String,
    /// Policy specification (mirrors vellaveto-types Policy fields).
    pub policy: PolicySpec,
    /// Optional lifecycle management configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<PolicyLifecycleSpec>,
}

/// Policy specification mirroring vellaveto-types::Policy for JSON Schema generation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicySpec {
    /// Unique policy identifier.
    pub id: String,
    /// Human-readable policy name.
    pub name: String,
    /// Policy type: "Allow", "Deny", or "Conditional".
    #[serde(rename = "policyType")]
    pub policy_type: String,
    /// Evaluation priority (higher = evaluated first, >= 0).
    #[serde(default)]
    pub priority: i32,
    /// Conditional policy conditions (JSON object, only for policyType="Conditional").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Value>,
    /// Path-based access control rules.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pathRules")]
    pub path_rules: Option<PathRulesSpec>,
    /// Network-based access control rules.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "networkRules"
    )]
    pub network_rules: Option<NetworkRulesSpec>,
}

/// Path rules specification for CRD (mirrors vellaveto-types::PathRules).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct PathRulesSpec {
    /// Glob patterns for allowed paths.
    #[serde(default)]
    pub allowed: Vec<String>,
    /// Glob patterns for blocked paths.
    #[serde(default)]
    pub blocked: Vec<String>,
}

/// Network rules specification for CRD (mirrors vellaveto-types::NetworkRules).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkRulesSpec {
    /// Domain patterns for allowed destinations.
    #[serde(default, rename = "allowedDomains")]
    pub allowed_domains: Vec<String>,
    /// Domain patterns for blocked destinations.
    #[serde(default, rename = "blockedDomains")]
    pub blocked_domains: Vec<String>,
    /// IP-level access control rules.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipRules")]
    pub ip_rules: Option<IpRulesSpec>,
}

/// IP rules specification for CRD (mirrors vellaveto-types::IpRules).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct IpRulesSpec {
    /// Block connections to private/reserved IPs.
    #[serde(default, rename = "blockPrivate")]
    pub block_private: bool,
    /// CIDR ranges to block.
    #[serde(default, rename = "blockedCidrs")]
    pub blocked_cidrs: Vec<String>,
    /// CIDR ranges to allow (allowlist).
    #[serde(default, rename = "allowedCidrs")]
    pub allowed_cidrs: Vec<String>,
}

/// Policy lifecycle management configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleSpec {
    /// Automatically promote through Draft -> Staging -> Active.
    #[serde(default, rename = "autoPromote")]
    pub auto_promote: bool,
    /// Minimum staging period before promotion to Active (seconds).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "stagingPeriodSecs"
    )]
    pub staging_period_secs: Option<u64>,
}

/// Status subresource for VellavetoPolicy.
///
/// SECURITY (FIND-R224-002): `deny_unknown_fields` is safe — see `VellavetoClusterStatus`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct VellavetoPolicyStatus {
    /// Whether the policy is synchronized with the target cluster.
    #[serde(default)]
    pub synced: bool,
    /// Last successful sync time (RFC 3339).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "lastSyncTime"
    )]
    pub last_sync_time: Option<String>,
    /// Last error message, if any.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastError")]
    pub last_error: Option<String>,
    /// Standard Kubernetes conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    /// Last observed generation of the spec.
    #[serde(default, rename = "observedGeneration")]
    pub observed_generation: i64,
}

// ═══════════════════════════════════════════════════
// VellavetoTenant CRD
// ═══════════════════════════════════════════════════

/// Declarative tenant management — syncs tenants to a Vellaveto cluster.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "vellaveto.io",
    version = "v1alpha1",
    kind = "VellavetoTenant",
    namespaced
)]
#[kube(status = "VellavetoTenantStatus")]
#[kube(
    printcolumn = r#"{"name":"Cluster","type":"string","jsonPath":".spec.clusterRef"}"#,
    printcolumn = r#"{"name":"TenantID","type":"string","jsonPath":".spec.tenantId"}"#,
    printcolumn = r#"{"name":"Enabled","type":"boolean","jsonPath":".spec.enabled"}"#,
    printcolumn = r#"{"name":"Synced","type":"boolean","jsonPath":".status.synced"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct VellavetoTenantSpec {
    /// Name of the target VellavetoCluster in the same namespace.
    #[serde(rename = "clusterRef")]
    pub cluster_ref: String,
    /// Unique tenant identifier (1-64 chars, [a-zA-Z0-9_-]).
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Human-readable tenant name.
    pub name: String,
    /// Whether the tenant is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Tenant-specific quota overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quotas: Option<TenantQuotasSpec>,
    /// Tenant metadata (custom key-value pairs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
}

fn default_true() -> bool {
    true
}

/// Tenant quotas specification for CRD.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct TenantQuotasSpec {
    /// Maximum policy evaluations per minute.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "maxEvaluationsPerMinute"
    )]
    pub max_evaluations_per_minute: Option<u64>,
    /// Maximum number of policies this tenant can create.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "maxPolicies"
    )]
    pub max_policies: Option<u64>,
    /// Maximum pending approvals at any time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "maxPendingApprovals"
    )]
    pub max_pending_approvals: Option<u64>,
    /// Maximum audit log retention in days.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "maxAuditRetentionDays"
    )]
    pub max_audit_retention_days: Option<u64>,
}

/// Status subresource for VellavetoTenant.
///
/// SECURITY (FIND-R224-002): `deny_unknown_fields` is safe — see `VellavetoClusterStatus`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct VellavetoTenantStatus {
    /// Whether the tenant is synchronized with the target cluster.
    #[serde(default)]
    pub synced: bool,
    /// Last successful sync time (RFC 3339).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "lastSyncTime"
    )]
    pub last_sync_time: Option<String>,
    /// Last error message, if any.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastError")]
    pub last_error: Option<String>,
    /// Standard Kubernetes conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    /// Last observed generation of the spec.
    #[serde(default, rename = "observedGeneration")]
    pub observed_generation: i64,
}

// ═══════════════════════════════════════════════════
// Shared Types
// ═══════════════════════════════════════════════════

/// Standard Kubernetes-style condition.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    /// Type of condition (e.g. "Ready", "Synced", "Available").
    #[serde(rename = "type")]
    pub condition_type: String,
    /// Status: "True", "False", or "Unknown".
    pub status: String,
    /// Last time the condition transitioned.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "lastTransitionTime"
    )]
    pub last_transition_time: Option<String>,
    /// Human-readable reason for the condition's last transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Human-readable message with details about the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Condition {
    /// Create a new Condition with bounded message length.
    ///
    /// Truncates `message` to [`MAX_CONDITION_MESSAGE_LEN`] at a char boundary.
    /// SECURITY (FIND-R224-006): Strips dangerous chars (control + Unicode format)
    /// from `condition_type`, `status`, and `reason` to prevent log injection and
    /// bidi override attacks.
    pub fn new(
        condition_type: impl Into<String>,
        status: impl Into<String>,
        last_transition_time: Option<String>,
        reason: Option<String>,
        message: Option<String>,
    ) -> Self {
        let truncated_message = message.map(|m| {
            if m.len() > MAX_CONDITION_MESSAGE_LEN {
                let mut end = MAX_CONDITION_MESSAGE_LEN;
                while end > 0 && !m.is_char_boundary(end) {
                    end -= 1;
                }
                m[..end].to_string()
            } else {
                m
            }
        });
        Self {
            condition_type: strip_dangerous_chars(&condition_type.into()),
            status: strip_dangerous_chars(&status.into()),
            last_transition_time,
            reason: reason.map(|r| strip_dangerous_chars(&r)),
            message: truncated_message,
        }
    }
}

/// Strip control characters and Unicode format characters from a string.
///
/// Used in constructors where rejection is not appropriate — the sanitized
/// value is safe for logging and display.
fn strip_dangerous_chars(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !is_unicode_format_char(*c))
        .collect()
}

// ═══════════════════════════════════════════════════
// Validation
// ═══════════════════════════════════════════════════

/// Check for control characters or Unicode format characters in a string.
///
/// Mirrors `vellaveto_types::has_dangerous_chars()` without depending on
/// the types crate (operator is a standalone binary).
fn has_dangerous_chars(s: &str) -> bool {
    s.chars()
        .any(|c| c.is_control() || is_unicode_format_char(c))
}

/// Check for Unicode format characters (zero-width, bidi, BOM, etc.).
pub(crate) fn is_unicode_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2069}'
        | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{E0001}'..='\u{E007F}'
    )
}

/// Validate a tenant ID: 1-64 chars, [a-zA-Z0-9_-] only.
fn validate_tenant_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("tenant_id must not be empty".into());
    }
    if id.len() > MAX_TENANT_ID_LEN {
        return Err(format!(
            "tenant_id exceeds max length of {MAX_TENANT_ID_LEN}"
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("tenant_id must contain only [a-zA-Z0-9_-]".into());
    }
    Ok(())
}

/// Validate a Kubernetes resource name (DNS label: lowercase alphanumeric + hyphens,
/// no dots, no uppercase, must not start or end with hyphen, max 253).
fn validate_k8s_name(name: &str, field: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if name.len() > MAX_CLUSTER_REF_LEN {
        return Err(format!(
            "{field} exceeds max length of {MAX_CLUSTER_REF_LEN}"
        ));
    }
    if has_dangerous_chars(name) {
        return Err(format!("{field} contains dangerous characters"));
    }
    // DNS label: lowercase alphanumeric + hyphens only
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "{field} must contain only lowercase alphanumeric characters or hyphens"
        ));
    }
    // Must not start or end with hyphen
    if name.starts_with('-') || name.ends_with('-') {
        return Err(format!("{field} must not start or end with a hyphen"));
    }
    Ok(())
}

impl VellavetoClusterSpec {
    /// Validate the cluster spec.
    pub fn validate(&self) -> Result<(), String> {
        if self.replicas < 1 || self.replicas > MAX_CLUSTER_REPLICAS {
            return Err(format!(
                "replicas must be between 1 and {MAX_CLUSTER_REPLICAS}"
            ));
        }
        if self.image.is_empty() {
            return Err("image must not be empty".into());
        }
        if self.image.len() > MAX_IMAGE_LEN {
            return Err(format!("image exceeds max length of {MAX_IMAGE_LEN}"));
        }
        if has_dangerous_chars(&self.image) {
            return Err("image contains dangerous characters".into());
        }
        if self.image.contains(char::is_whitespace) {
            return Err("image must not contain whitespace".into());
        }
        if let Some(ref version) = self.version {
            if version.len() > MAX_VERSION_LEN {
                return Err(format!("version exceeds max length of {MAX_VERSION_LEN}"));
            }
            if has_dangerous_chars(version) {
                return Err("version contains dangerous characters".into());
            }
        }
        if let Some(ref config) = self.config {
            config.validate()?;
        }
        if let Some(ref resources) = self.resources {
            resources.validate()?;
        }
        Ok(())
    }
}

impl ResourceRequirements {
    /// Validate resource requirement fields for length and dangerous characters.
    pub fn validate(&self) -> Result<(), String> {
        for (field, value) in [
            ("cpu_request", &self.cpu_request),
            ("memory_request", &self.memory_request),
            ("cpu_limit", &self.cpu_limit),
            ("memory_limit", &self.memory_limit),
        ] {
            if let Some(ref v) = value {
                if v.len() > MAX_RESOURCE_VALUE_LEN {
                    return Err(format!(
                        "resources.{field} exceeds max length of {MAX_RESOURCE_VALUE_LEN}"
                    ));
                }
                if has_dangerous_chars(v) {
                    return Err(format!("resources.{field} contains dangerous characters"));
                }
                if v.trim().is_empty() {
                    return Err(format!("resources.{field} must not be blank"));
                }
            }
        }
        Ok(())
    }
}

impl VellavetoConfigOverrides {
    /// Validate config overrides.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref mode) = self.security_mode {
            if mode.len() > MAX_CONFIG_OVERRIDE_LEN {
                return Err("security_mode too long".into());
            }
            if has_dangerous_chars(mode) {
                return Err("security_mode contains dangerous characters".into());
            }
            let valid_modes = ["strict", "permissive", "audit"];
            if !valid_modes.contains(&mode.as_str()) {
                return Err(format!(
                    "security_mode must be one of: {}",
                    valid_modes.join(", ")
                ));
            }
        }
        if let Some(rps) = self.rate_limit_rps {
            if rps == 0 {
                return Err("rate_limit_rps must be > 0".into());
            }
            // SECURITY (FIND-R224-007): Upper bound prevents unreasonable rate
            // limits that could overwhelm the server or exhaust resources.
            const MAX_RATE_LIMIT_RPS: u32 = 100_000;
            if rps > MAX_RATE_LIMIT_RPS {
                return Err(format!(
                    "rate_limit_rps exceeds max of {MAX_RATE_LIMIT_RPS}"
                ));
            }
        }
        Ok(())
    }
}

impl VellavetoPolicySpec {
    /// Validate the policy spec.
    pub fn validate(&self) -> Result<(), String> {
        validate_k8s_name(&self.cluster_ref, "clusterRef")?;
        self.policy.validate()?;
        if let Some(ref lifecycle) = self.lifecycle {
            lifecycle.validate()?;
        }
        Ok(())
    }
}

impl PolicySpec {
    /// Validate the policy specification.
    pub fn validate(&self) -> Result<(), String> {
        // ID
        if self.id.is_empty() {
            return Err("policy.id must not be empty".into());
        }
        if self.id.len() > MAX_POLICY_ID_LEN {
            return Err(format!(
                "policy.id exceeds max length of {MAX_POLICY_ID_LEN}"
            ));
        }
        if has_dangerous_chars(&self.id) {
            return Err("policy.id contains dangerous characters".into());
        }
        // Name
        if self.name.is_empty() {
            return Err("policy.name must not be empty".into());
        }
        if self.name.len() > MAX_POLICY_NAME_LEN {
            return Err(format!(
                "policy.name exceeds max length of {MAX_POLICY_NAME_LEN}"
            ));
        }
        if has_dangerous_chars(&self.name) {
            return Err("policy.name contains dangerous characters".into());
        }
        // Policy type
        let valid_types = ["Allow", "Deny", "Conditional"];
        if !valid_types.contains(&self.policy_type.as_str()) {
            return Err(format!(
                "policy.policyType must be one of: {}",
                valid_types.join(", ")
            ));
        }
        // Conditions required for Conditional, forbidden otherwise
        if self.policy_type == "Conditional" {
            if self.conditions.is_none() {
                return Err("conditions required when policyType is Conditional".into());
            }
            if let Some(ref cond) = self.conditions {
                let serialized = serde_json::to_string(cond)
                    .map_err(|e| format!("conditions serialization failed (fail-closed): {e}"))?;
                if serialized.len() > MAX_CONDITIONS_SIZE {
                    return Err(format!(
                        "conditions exceed max size of {MAX_CONDITIONS_SIZE} bytes"
                    ));
                }
            }
        } else if self.conditions.is_some() {
            return Err("conditions must be absent for non-Conditional policy type".into());
        }
        // Priority
        if self.priority < 0 {
            return Err("policy.priority must be >= 0".into());
        }
        // Path rules
        if let Some(ref pr) = self.path_rules {
            if pr.allowed.len() > MAX_PATH_RULES {
                return Err(format!("pathRules.allowed exceeds max of {MAX_PATH_RULES}"));
            }
            if pr.blocked.len() > MAX_PATH_RULES {
                return Err(format!("pathRules.blocked exceeds max of {MAX_PATH_RULES}"));
            }
            for entry in pr.allowed.iter().chain(pr.blocked.iter()) {
                if entry.len() > MAX_RULE_ENTRY_LEN {
                    return Err(format!(
                        "pathRules entry exceeds max length of {MAX_RULE_ENTRY_LEN}"
                    ));
                }
                if has_dangerous_chars(entry) {
                    return Err("pathRules entry contains dangerous characters".into());
                }
            }
        }
        // Network rules
        if let Some(ref nr) = self.network_rules {
            if nr.allowed_domains.len() > MAX_DOMAIN_RULES {
                return Err(format!(
                    "networkRules.allowedDomains exceeds max of {MAX_DOMAIN_RULES}"
                ));
            }
            if nr.blocked_domains.len() > MAX_DOMAIN_RULES {
                return Err(format!(
                    "networkRules.blockedDomains exceeds max of {MAX_DOMAIN_RULES}"
                ));
            }
            for entry in nr.allowed_domains.iter().chain(nr.blocked_domains.iter()) {
                if entry.len() > MAX_RULE_ENTRY_LEN {
                    return Err(format!(
                        "networkRules domain entry exceeds max length of {MAX_RULE_ENTRY_LEN}"
                    ));
                }
                if has_dangerous_chars(entry) {
                    return Err("networkRules domain entry contains dangerous characters".into());
                }
            }
            if let Some(ref ip) = nr.ip_rules {
                if ip.blocked_cidrs.len() > MAX_CIDR_RULES {
                    return Err(format!(
                        "ipRules.blockedCidrs exceeds max of {MAX_CIDR_RULES}"
                    ));
                }
                if ip.allowed_cidrs.len() > MAX_CIDR_RULES {
                    return Err(format!(
                        "ipRules.allowedCidrs exceeds max of {MAX_CIDR_RULES}"
                    ));
                }
                for entry in ip.blocked_cidrs.iter().chain(ip.allowed_cidrs.iter()) {
                    if entry.len() > MAX_RULE_ENTRY_LEN {
                        return Err(format!(
                            "ipRules CIDR entry exceeds max length of {MAX_RULE_ENTRY_LEN}"
                        ));
                    }
                    if has_dangerous_chars(entry) {
                        return Err("ipRules CIDR entry contains dangerous characters".into());
                    }
                }
            }
        }
        Ok(())
    }
}

impl PolicyLifecycleSpec {
    /// Validate lifecycle settings.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(secs) = self.staging_period_secs {
            if secs > MAX_STAGING_PERIOD_SECS {
                return Err(format!(
                    "stagingPeriodSecs exceeds max of {MAX_STAGING_PERIOD_SECS}"
                ));
            }
        }
        Ok(())
    }
}

impl TenantQuotasSpec {
    /// Validate quota fields have sensible upper bounds.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(v) = self.max_evaluations_per_minute {
            if v > MAX_EVALUATIONS_PER_MINUTE_UPPER {
                return Err(format!(
                    "maxEvaluationsPerMinute exceeds upper bound of {MAX_EVALUATIONS_PER_MINUTE_UPPER}"
                ));
            }
        }
        if let Some(v) = self.max_policies {
            if v > MAX_POLICIES_UPPER {
                return Err(format!(
                    "maxPolicies exceeds upper bound of {MAX_POLICIES_UPPER}"
                ));
            }
        }
        if let Some(v) = self.max_pending_approvals {
            if v > MAX_PENDING_APPROVALS_UPPER {
                return Err(format!(
                    "maxPendingApprovals exceeds upper bound of {MAX_PENDING_APPROVALS_UPPER}"
                ));
            }
        }
        if let Some(v) = self.max_audit_retention_days {
            if v > MAX_AUDIT_RETENTION_DAYS_UPPER {
                return Err(format!(
                    "maxAuditRetentionDays exceeds upper bound of {MAX_AUDIT_RETENTION_DAYS_UPPER}"
                ));
            }
        }
        Ok(())
    }
}

impl VellavetoTenantSpec {
    /// Validate the tenant spec.
    pub fn validate(&self) -> Result<(), String> {
        validate_k8s_name(&self.cluster_ref, "clusterRef")?;
        validate_tenant_id(&self.tenant_id)?;
        // Name
        if self.name.is_empty() {
            return Err("name must not be empty".into());
        }
        if self.name.len() > MAX_TENANT_NAME_LEN {
            return Err(format!("name exceeds max length of {MAX_TENANT_NAME_LEN}"));
        }
        if has_dangerous_chars(&self.name) {
            return Err("name contains dangerous characters".into());
        }
        // Metadata
        if let Some(ref md) = self.metadata {
            if md.len() > MAX_TENANT_METADATA {
                return Err(format!(
                    "metadata exceeds max of {MAX_TENANT_METADATA} entries"
                ));
            }
            for (k, v) in md {
                if k.len() > MAX_METADATA_KEY_LEN {
                    return Err(format!(
                        "metadata key exceeds max length of {MAX_METADATA_KEY_LEN}"
                    ));
                }
                if v.len() > MAX_METADATA_VALUE_LEN {
                    return Err(format!(
                        "metadata value exceeds max length of {MAX_METADATA_VALUE_LEN}"
                    ));
                }
                if has_dangerous_chars(k) || has_dangerous_chars(v) {
                    return Err("metadata contains dangerous characters".into());
                }
            }
        }
        // Quotas
        if let Some(ref quotas) = self.quotas {
            quotas.validate()?;
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn test_cluster_crd_generation() {
        let crd = VellavetoCluster::crd();
        assert_eq!(
            crd.metadata.name.as_deref(),
            Some("vellavetoclusters.vellaveto.io")
        );
    }

    #[test]
    fn test_policy_crd_generation() {
        let crd = VellavetoPolicy::crd();
        assert_eq!(
            crd.metadata.name.as_deref(),
            Some("vellavetopolicies.vellaveto.io")
        );
    }

    #[test]
    fn test_tenant_crd_generation() {
        let crd = VellavetoTenant::crd();
        assert_eq!(
            crd.metadata.name.as_deref(),
            Some("vellavetotenants.vellaveto.io")
        );
    }

    #[test]
    fn test_cluster_spec_validate_valid() {
        let spec = VellavetoClusterSpec {
            replicas: 3,
            image: "ghcr.io/paolovella/vellaveto:4.0.0".into(),
            version: Some("4.0.0".into()),
            config: None,
            resources: None,
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn test_cluster_spec_validate_invalid_replicas() {
        let spec = VellavetoClusterSpec {
            replicas: 0,
            image: "test:latest".into(),
            version: None,
            config: None,
            resources: None,
        };
        assert!(spec.validate().unwrap_err().contains("replicas"));

        let spec2 = VellavetoClusterSpec {
            replicas: 11,
            image: "test:latest".into(),
            version: None,
            config: None,
            resources: None,
        };
        assert!(spec2.validate().unwrap_err().contains("replicas"));
    }

    #[test]
    fn test_cluster_spec_validate_empty_image() {
        let spec = VellavetoClusterSpec {
            replicas: 1,
            image: String::new(),
            version: None,
            config: None,
            resources: None,
        };
        assert!(spec.validate().unwrap_err().contains("image"));
    }

    #[test]
    fn test_cluster_spec_validate_dangerous_chars() {
        let spec = VellavetoClusterSpec {
            replicas: 1,
            image: "test\x00:latest".into(),
            version: None,
            config: None,
            resources: None,
        };
        assert!(spec.validate().unwrap_err().contains("dangerous"));
    }

    #[test]
    fn test_policy_spec_validate_valid_allow() {
        let spec = VellavetoPolicySpec {
            cluster_ref: "my-cluster".into(),
            policy: PolicySpec {
                id: "pol-1".into(),
                name: "Allow reads".into(),
                policy_type: "Allow".into(),
                priority: 10,
                conditions: None,
                path_rules: Some(PathRulesSpec {
                    allowed: vec!["/data/**".into()],
                    blocked: vec![],
                }),
                network_rules: None,
            },
            lifecycle: None,
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn test_policy_spec_validate_invalid_type() {
        let spec = VellavetoPolicySpec {
            cluster_ref: "my-cluster".into(),
            policy: PolicySpec {
                id: "pol-1".into(),
                name: "Bad type".into(),
                policy_type: "Invalid".into(),
                priority: 0,
                conditions: None,
                path_rules: None,
                network_rules: None,
            },
            lifecycle: None,
        };
        assert!(spec.validate().unwrap_err().contains("policyType"));
    }

    #[test]
    fn test_policy_spec_validate_conditional_needs_conditions() {
        let spec = VellavetoPolicySpec {
            cluster_ref: "my-cluster".into(),
            policy: PolicySpec {
                id: "pol-1".into(),
                name: "Conditional".into(),
                policy_type: "Conditional".into(),
                priority: 0,
                conditions: None,
                path_rules: None,
                network_rules: None,
            },
            lifecycle: None,
        };
        assert!(spec.validate().unwrap_err().contains("conditions required"));
    }

    #[test]
    fn test_policy_spec_validate_negative_priority() {
        let spec = VellavetoPolicySpec {
            cluster_ref: "my-cluster".into(),
            policy: PolicySpec {
                id: "pol-1".into(),
                name: "Neg priority".into(),
                policy_type: "Allow".into(),
                priority: -1,
                conditions: None,
                path_rules: None,
                network_rules: None,
            },
            lifecycle: None,
        };
        assert!(spec.validate().unwrap_err().contains("priority"));
    }

    #[test]
    fn test_tenant_spec_validate_valid() {
        let spec = VellavetoTenantSpec {
            cluster_ref: "my-cluster".into(),
            tenant_id: "acme-corp".into(),
            name: "ACME Corporation".into(),
            enabled: true,
            quotas: Some(TenantQuotasSpec {
                max_evaluations_per_minute: Some(5000),
                max_policies: Some(100),
                max_pending_approvals: None,
                max_audit_retention_days: None,
            }),
            metadata: None,
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn test_tenant_spec_validate_invalid_id() {
        let spec = VellavetoTenantSpec {
            cluster_ref: "my-cluster".into(),
            tenant_id: "invalid id!".into(),
            name: "Test".into(),
            enabled: true,
            quotas: None,
            metadata: None,
        };
        assert!(spec.validate().unwrap_err().contains("tenant_id"));
    }

    #[test]
    fn test_tenant_spec_validate_metadata_bounds() {
        let mut md = BTreeMap::new();
        for i in 0..=MAX_TENANT_METADATA {
            md.insert(format!("key-{i}"), "value".into());
        }
        let spec = VellavetoTenantSpec {
            cluster_ref: "my-cluster".into(),
            tenant_id: "test".into(),
            name: "Test".into(),
            enabled: true,
            quotas: None,
            metadata: Some(md),
        };
        assert!(spec.validate().unwrap_err().contains("metadata"));
    }

    #[test]
    fn test_config_overrides_validate_valid() {
        let config = VellavetoConfigOverrides {
            security_mode: Some("strict".into()),
            eu_ai_act_enabled: Some(true),
            dora_enabled: None,
            nis2_enabled: None,
            audit_enabled: Some(true),
            rate_limit_rps: Some(100),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_overrides_validate_invalid_mode() {
        let config = VellavetoConfigOverrides {
            security_mode: Some("unknown".into()),
            ..Default::default()
        };
        assert!(config.validate().unwrap_err().contains("security_mode"));
    }

    #[test]
    fn test_cluster_spec_serde_roundtrip() {
        let spec = VellavetoClusterSpec {
            replicas: 3,
            image: "test:latest".into(),
            version: Some("4.0.0".into()),
            config: None,
            resources: Some(ResourceRequirements {
                cpu_request: Some("100m".into()),
                memory_request: Some("128Mi".into()),
                cpu_limit: None,
                memory_limit: None,
            }),
        };
        let json = serde_json::to_string(&spec).expect("serialize");
        let parsed: VellavetoClusterSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.replicas, 3);
        assert_eq!(parsed.image, "test:latest");
    }

    #[test]
    fn test_policy_spec_serde_roundtrip() {
        let spec = PolicySpec {
            id: "p1".into(),
            name: "Test Policy".into(),
            policy_type: "Allow".into(),
            priority: 5,
            conditions: None,
            path_rules: Some(PathRulesSpec {
                allowed: vec!["/tmp/**".into()],
                blocked: vec![],
            }),
            network_rules: Some(NetworkRulesSpec {
                allowed_domains: vec!["example.com".into()],
                blocked_domains: vec![],
                ip_rules: None,
            }),
        };
        let json = serde_json::to_string(&spec).expect("serialize");
        let parsed: PolicySpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.id, "p1");
        assert_eq!(parsed.policy_type, "Allow");
    }

    // ═══════════════════════════════════════════════════
    // R216 finding tests
    // ═══════════════════════════════════════════════════

    // FIND-R216-002: validate_k8s_name DNS-safe enforcement
    #[test]
    fn test_validate_k8s_name_rejects_uppercase() {
        let err = validate_k8s_name("My-Cluster", "clusterRef").unwrap_err();
        assert!(err.contains("lowercase"));
    }

    #[test]
    fn test_validate_k8s_name_rejects_dots() {
        let err = validate_k8s_name("my.cluster", "clusterRef").unwrap_err();
        assert!(err.contains("lowercase"));
    }

    #[test]
    fn test_validate_k8s_name_rejects_leading_hyphen() {
        let err = validate_k8s_name("-my-cluster", "clusterRef").unwrap_err();
        assert!(err.contains("hyphen"));
    }

    #[test]
    fn test_validate_k8s_name_rejects_trailing_hyphen() {
        let err = validate_k8s_name("my-cluster-", "clusterRef").unwrap_err();
        assert!(err.contains("hyphen"));
    }

    #[test]
    fn test_validate_k8s_name_accepts_valid_dns() {
        assert!(validate_k8s_name("my-cluster-01", "clusterRef").is_ok());
    }

    // FIND-R216-004: deny_unknown_fields
    #[test]
    fn test_config_overrides_deny_unknown_fields() {
        let json = r#"{"security_mode": "strict", "unknown_field": true}"#;
        let result = serde_json::from_str::<VellavetoConfigOverrides>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_spec_deny_unknown_fields() {
        let json = r#"{"id":"p1","name":"t","policyType":"Allow","unknown":1}"#;
        let result = serde_json::from_str::<PolicySpec>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_path_rules_spec_deny_unknown_fields() {
        let json = r#"{"allowed":[],"blocked":[],"extra":"bad"}"#;
        let result = serde_json::from_str::<PathRulesSpec>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_network_rules_spec_deny_unknown_fields() {
        let json = r#"{"allowedDomains":[],"blockedDomains":[],"extra":"bad"}"#;
        let result = serde_json::from_str::<NetworkRulesSpec>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_ip_rules_spec_deny_unknown_fields() {
        let json = r#"{"blockPrivate":false,"blockedCidrs":[],"allowedCidrs":[],"extra":"bad"}"#;
        let result = serde_json::from_str::<IpRulesSpec>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_lifecycle_spec_deny_unknown_fields() {
        let json = r#"{"autoPromote":true,"extra":"bad"}"#;
        let result = serde_json::from_str::<PolicyLifecycleSpec>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_tenant_quotas_deny_unknown_fields() {
        let json = r#"{"maxEvaluationsPerMinute":100,"extra":"bad"}"#;
        let result = serde_json::from_str::<TenantQuotasSpec>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_resource_requirements_deny_unknown_fields() {
        let json = r#"{"cpu_request":"100m","extra":"bad"}"#;
        let result = serde_json::from_str::<ResourceRequirements>(json);
        assert!(result.is_err());
    }

    // FIND-R216-005: ResourceRequirements validation
    #[test]
    fn test_resource_requirements_validate_valid() {
        let res = ResourceRequirements {
            cpu_request: Some("100m".into()),
            memory_request: Some("128Mi".into()),
            cpu_limit: Some("1".into()),
            memory_limit: Some("512Mi".into()),
        };
        assert!(res.validate().is_ok());
    }

    #[test]
    fn test_resource_requirements_validate_too_long() {
        let res = ResourceRequirements {
            cpu_request: Some("x".repeat(MAX_RESOURCE_VALUE_LEN + 1)),
            ..Default::default()
        };
        assert!(res.validate().unwrap_err().contains("max length"));
    }

    #[test]
    fn test_resource_requirements_validate_dangerous_chars() {
        let res = ResourceRequirements {
            memory_limit: Some("512Mi\x00".into()),
            ..Default::default()
        };
        assert!(res.validate().unwrap_err().contains("dangerous"));
    }

    #[test]
    fn test_resource_requirements_validate_blank() {
        let res = ResourceRequirements {
            cpu_request: Some("   ".into()),
            ..Default::default()
        };
        assert!(res.validate().unwrap_err().contains("blank"));
    }

    #[test]
    fn test_resource_requirements_wired_to_cluster() {
        let spec = VellavetoClusterSpec {
            replicas: 1,
            image: "test:latest".into(),
            version: None,
            config: None,
            resources: Some(ResourceRequirements {
                cpu_request: Some("\x00bad".into()),
                ..Default::default()
            }),
        };
        assert!(spec.validate().unwrap_err().contains("dangerous"));
    }

    // FIND-R216-007: per-element rule validation
    #[test]
    fn test_path_rules_entry_too_long() {
        let spec = VellavetoPolicySpec {
            cluster_ref: "my-cluster".into(),
            policy: PolicySpec {
                id: "p1".into(),
                name: "test".into(),
                policy_type: "Allow".into(),
                priority: 0,
                conditions: None,
                path_rules: Some(PathRulesSpec {
                    allowed: vec!["x".repeat(MAX_RULE_ENTRY_LEN + 1)],
                    blocked: vec![],
                }),
                network_rules: None,
            },
            lifecycle: None,
        };
        assert!(spec
            .validate()
            .unwrap_err()
            .contains("pathRules entry exceeds"));
    }

    #[test]
    fn test_path_rules_entry_dangerous_chars() {
        let spec = VellavetoPolicySpec {
            cluster_ref: "my-cluster".into(),
            policy: PolicySpec {
                id: "p1".into(),
                name: "test".into(),
                policy_type: "Allow".into(),
                priority: 0,
                conditions: None,
                path_rules: Some(PathRulesSpec {
                    allowed: vec![],
                    blocked: vec!["/data/\u{200B}secret".into()],
                }),
                network_rules: None,
            },
            lifecycle: None,
        };
        assert!(spec
            .validate()
            .unwrap_err()
            .contains("pathRules entry contains dangerous"));
    }

    #[test]
    fn test_network_rules_domain_entry_too_long() {
        let spec = VellavetoPolicySpec {
            cluster_ref: "my-cluster".into(),
            policy: PolicySpec {
                id: "p1".into(),
                name: "test".into(),
                policy_type: "Deny".into(),
                priority: 0,
                conditions: None,
                path_rules: None,
                network_rules: Some(NetworkRulesSpec {
                    allowed_domains: vec!["x".repeat(MAX_RULE_ENTRY_LEN + 1)],
                    blocked_domains: vec![],
                    ip_rules: None,
                }),
            },
            lifecycle: None,
        };
        assert!(spec
            .validate()
            .unwrap_err()
            .contains("networkRules domain entry exceeds"));
    }

    #[test]
    fn test_network_rules_domain_entry_dangerous_chars() {
        let spec = VellavetoPolicySpec {
            cluster_ref: "my-cluster".into(),
            policy: PolicySpec {
                id: "p1".into(),
                name: "test".into(),
                policy_type: "Deny".into(),
                priority: 0,
                conditions: None,
                path_rules: None,
                network_rules: Some(NetworkRulesSpec {
                    allowed_domains: vec![],
                    blocked_domains: vec!["evil\x00.com".into()],
                    ip_rules: None,
                }),
            },
            lifecycle: None,
        };
        assert!(spec
            .validate()
            .unwrap_err()
            .contains("networkRules domain entry contains dangerous"));
    }

    #[test]
    fn test_ip_rules_cidr_entry_too_long() {
        let spec = VellavetoPolicySpec {
            cluster_ref: "my-cluster".into(),
            policy: PolicySpec {
                id: "p1".into(),
                name: "test".into(),
                policy_type: "Deny".into(),
                priority: 0,
                conditions: None,
                path_rules: None,
                network_rules: Some(NetworkRulesSpec {
                    allowed_domains: vec![],
                    blocked_domains: vec![],
                    ip_rules: Some(IpRulesSpec {
                        block_private: false,
                        blocked_cidrs: vec!["x".repeat(MAX_RULE_ENTRY_LEN + 1)],
                        allowed_cidrs: vec![],
                    }),
                }),
            },
            lifecycle: None,
        };
        assert!(spec
            .validate()
            .unwrap_err()
            .contains("ipRules CIDR entry exceeds"));
    }

    // FIND-R216-008: Condition message truncation
    #[test]
    fn test_condition_new_truncates_long_message() {
        let long_msg = "x".repeat(MAX_CONDITION_MESSAGE_LEN + 500);
        let cond = Condition::new("Ready", "True", None, None, Some(long_msg));
        assert!(cond.message.as_ref().unwrap().len() <= MAX_CONDITION_MESSAGE_LEN);
    }

    #[test]
    fn test_condition_new_preserves_short_message() {
        let msg = "all good".to_string();
        let cond = Condition::new("Ready", "True", None, None, Some(msg.clone()));
        assert_eq!(cond.message.as_deref(), Some("all good"));
    }

    #[test]
    fn test_condition_new_truncates_at_char_boundary() {
        // Multi-byte UTF-8 character to test char boundary handling
        let mut msg = "a".repeat(MAX_CONDITION_MESSAGE_LEN - 1);
        msg.push('\u{00E9}'); // e-acute is 2 bytes in UTF-8
        msg.push('z');
        let cond = Condition::new("Ready", "True", None, None, Some(msg));
        let truncated = cond.message.unwrap();
        assert!(truncated.len() <= MAX_CONDITION_MESSAGE_LEN);
        assert!(truncated.is_char_boundary(truncated.len()));
    }

    // FIND-R216-010: Image whitespace validation
    #[test]
    fn test_cluster_spec_validate_image_whitespace() {
        let spec = VellavetoClusterSpec {
            replicas: 1,
            image: "test :latest".into(),
            version: None,
            config: None,
            resources: None,
        };
        assert!(spec.validate().unwrap_err().contains("whitespace"));
    }

    // FIND-R216-012: TenantQuotasSpec upper bound validation
    #[test]
    fn test_tenant_quotas_validate_valid() {
        let q = TenantQuotasSpec {
            max_evaluations_per_minute: Some(5000),
            max_policies: Some(100),
            max_pending_approvals: Some(50),
            max_audit_retention_days: Some(365),
        };
        assert!(q.validate().is_ok());
    }

    #[test]
    fn test_tenant_quotas_validate_evaluations_too_high() {
        let q = TenantQuotasSpec {
            max_evaluations_per_minute: Some(MAX_EVALUATIONS_PER_MINUTE_UPPER + 1),
            ..Default::default()
        };
        assert!(q
            .validate()
            .unwrap_err()
            .contains("maxEvaluationsPerMinute"));
    }

    #[test]
    fn test_tenant_quotas_validate_policies_too_high() {
        let q = TenantQuotasSpec {
            max_policies: Some(MAX_POLICIES_UPPER + 1),
            ..Default::default()
        };
        assert!(q.validate().unwrap_err().contains("maxPolicies"));
    }

    #[test]
    fn test_tenant_quotas_validate_pending_approvals_too_high() {
        let q = TenantQuotasSpec {
            max_pending_approvals: Some(MAX_PENDING_APPROVALS_UPPER + 1),
            ..Default::default()
        };
        assert!(q.validate().unwrap_err().contains("maxPendingApprovals"));
    }

    #[test]
    fn test_tenant_quotas_validate_retention_days_too_high() {
        let q = TenantQuotasSpec {
            max_audit_retention_days: Some(MAX_AUDIT_RETENTION_DAYS_UPPER + 1),
            ..Default::default()
        };
        assert!(q.validate().unwrap_err().contains("maxAuditRetentionDays"));
    }

    #[test]
    fn test_tenant_quotas_wired_to_tenant_spec() {
        let spec = VellavetoTenantSpec {
            cluster_ref: "my-cluster".into(),
            tenant_id: "test".into(),
            name: "Test".into(),
            enabled: true,
            quotas: Some(TenantQuotasSpec {
                max_evaluations_per_minute: Some(MAX_EVALUATIONS_PER_MINUTE_UPPER + 1),
                ..Default::default()
            }),
            metadata: None,
        };
        assert!(spec
            .validate()
            .unwrap_err()
            .contains("maxEvaluationsPerMinute"));
    }

    // FIND-R216-011: conditions serialization failure returns error
    #[test]
    fn test_policy_spec_conditions_size_check() {
        // Verify that conditions serialization does not silently swallow errors
        // by checking a valid large condition is properly bounded
        let big_val = serde_json::json!({
            "data": "x".repeat(MAX_CONDITIONS_SIZE + 1)
        });
        let spec = PolicySpec {
            id: "p1".into(),
            name: "test".into(),
            policy_type: "Conditional".into(),
            priority: 0,
            conditions: Some(big_val),
            path_rules: None,
            network_rules: None,
        };
        assert!(spec
            .validate()
            .unwrap_err()
            .contains("conditions exceed max size"));
    }

    // ═══════════════════════════════════════════════════
    // FIND-R224 finding tests
    // ═══════════════════════════════════════════════════

    // FIND-R224-001: Condition deny_unknown_fields
    #[test]
    fn test_condition_deny_unknown_fields() {
        let json = r#"{"type":"Ready","status":"True","extra":"bad"}"#;
        let result = serde_json::from_str::<Condition>(json);
        assert!(result.is_err(), "Condition should reject unknown fields");
    }

    // FIND-R224-002: Status types deny_unknown_fields
    #[test]
    fn test_cluster_status_deny_unknown_fields() {
        let json = r#"{"phase":"Pending","replicas":0,"readyReplicas":0,"observedGeneration":0,"extra":"bad"}"#;
        let result = serde_json::from_str::<VellavetoClusterStatus>(json);
        assert!(
            result.is_err(),
            "VellavetoClusterStatus should reject unknown fields"
        );
    }

    #[test]
    fn test_policy_status_deny_unknown_fields() {
        let json = r#"{"synced":false,"observedGeneration":0,"extra":"bad"}"#;
        let result = serde_json::from_str::<VellavetoPolicyStatus>(json);
        assert!(
            result.is_err(),
            "VellavetoPolicyStatus should reject unknown fields"
        );
    }

    #[test]
    fn test_tenant_status_deny_unknown_fields() {
        let json = r#"{"synced":false,"observedGeneration":0,"extra":"bad"}"#;
        let result = serde_json::from_str::<VellavetoTenantStatus>(json);
        assert!(
            result.is_err(),
            "VellavetoTenantStatus should reject unknown fields"
        );
    }

    // Verify status types still deserialize correctly with only known fields
    #[test]
    fn test_cluster_status_valid_deserialize() {
        let json = r#"{"phase":"Running","replicas":3,"readyReplicas":3,"observedGeneration":1}"#;
        let status: VellavetoClusterStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.phase, ClusterPhase::Running);
        assert_eq!(status.replicas, 3);
    }

    #[test]
    fn test_policy_status_valid_deserialize() {
        let json = r#"{"synced":true,"observedGeneration":5}"#;
        let status: VellavetoPolicyStatus = serde_json::from_str(json).unwrap();
        assert!(status.synced);
        assert_eq!(status.observed_generation, 5);
    }

    #[test]
    fn test_tenant_status_valid_deserialize() {
        let json = r#"{"synced":true,"observedGeneration":2}"#;
        let status: VellavetoTenantStatus = serde_json::from_str(json).unwrap();
        assert!(status.synced);
    }

    // FIND-R224-006: Condition::new() strips dangerous chars
    #[test]
    fn test_condition_new_strips_control_chars_from_type() {
        let cond = Condition::new("Rea\x00dy", "True", None, None, None);
        assert_eq!(cond.condition_type, "Ready");
    }

    #[test]
    fn test_condition_new_strips_control_chars_from_status() {
        let cond = Condition::new("Ready", "Tr\x01ue", None, None, None);
        assert_eq!(cond.status, "True");
    }

    #[test]
    fn test_condition_new_strips_bidi_from_reason() {
        let cond = Condition::new(
            "Ready",
            "False",
            None,
            Some("failed\u{200B}check".to_string()),
            None,
        );
        assert_eq!(cond.reason.as_deref(), Some("failedcheck"));
    }

    #[test]
    fn test_condition_new_strips_unicode_format_from_type() {
        // BOM (U+FEFF)
        let cond = Condition::new("\u{FEFF}Synced", "True", None, None, None);
        assert_eq!(cond.condition_type, "Synced");
    }

    #[test]
    fn test_condition_new_clean_input_unchanged() {
        let cond = Condition::new(
            "Available",
            "True",
            None,
            Some("all pods ready".to_string()),
            None,
        );
        assert_eq!(cond.condition_type, "Available");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason.as_deref(), Some("all pods ready"));
    }

    // FIND-R224-007: rate_limit_rps upper bound
    #[test]
    fn test_config_overrides_validate_rate_limit_rps_upper_bound() {
        let config = VellavetoConfigOverrides {
            rate_limit_rps: Some(100_001),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("rate_limit_rps"), "err: {err}");
        assert!(err.contains("100000"), "err: {err}");
    }

    #[test]
    fn test_config_overrides_validate_rate_limit_rps_at_max() {
        let config = VellavetoConfigOverrides {
            rate_limit_rps: Some(100_000),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_overrides_validate_rate_limit_rps_zero() {
        let config = VellavetoConfigOverrides {
            rate_limit_rps: Some(0),
            ..Default::default()
        };
        assert!(config
            .validate()
            .unwrap_err()
            .contains("rate_limit_rps must be > 0"));
    }
}
