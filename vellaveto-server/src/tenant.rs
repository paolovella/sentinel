// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Multi-tenancy support for Vellaveto.
//!
//! Provides tenant isolation for SaaS deployments, including:
//! - Tenant data model with quotas
//! - Tenant extraction from JWT, headers, or subdomain
//! - Policy namespacing by tenant
//! - Tenant-scoped rate limiting
//!
//! ## Tenant Extraction Priority
//!
//! 1. JWT claim: `tenant_id` or `org_id`
//! 2. Header: `X-Tenant-ID`
//! 3. Subdomain: `{tenant}.vellaveto.example.com`
//! 4. Default tenant (for single-tenant mode)
//!
//! ## Policy Namespacing
//!
//! Policies are namespaced by tenant ID:
//! - Tenant-specific: `{tenant_id}:policy_name`
//! - Global (shared): `_global_:policy_name`

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

/// Global policy prefix for policies shared across all tenants.
pub const GLOBAL_TENANT_PREFIX: &str = "_global_";

/// Default tenant ID when multi-tenancy is disabled or no tenant is specified.
pub const DEFAULT_TENANT_ID: &str = "_default_";

/// Maximum number of metadata entries per tenant.
const MAX_TENANT_METADATA_ENTRIES: usize = 100;

/// Maximum number of tenants returned by `list_tenants()` at the store level.
///
/// SECURITY: Prevents unbounded memory allocation when iterating over the
/// tenant map. The route handler applies a tighter cap (1 K); this is a
/// defence-in-depth guard at the storage layer.
const MAX_TENANT_LIST: usize = 10_000;

/// Maximum length for a metadata key.
const MAX_TENANT_METADATA_KEY_LEN: usize = 128;

/// Maximum length for a metadata value.
const MAX_TENANT_METADATA_VALUE_LEN: usize = 1024;

/// Maximum length for tenant name.
const MAX_TENANT_NAME_LEN: usize = 256;

// SECURITY (IMP-R106-001): Use canonical is_unsafe_char from routes/mod.rs
// instead of maintaining a duplicate copy.
use crate::routes::is_unsafe_char;

/// Tenant data model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tenant {
    /// Unique tenant identifier (e.g., UUID or slug).
    pub id: String,

    /// Human-readable tenant name.
    pub name: String,

    /// Whether the tenant is active (disabled tenants are rejected).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Tenant-specific quota overrides.
    #[serde(default)]
    pub quotas: TenantQuotas,

    /// Tenant metadata (custom key-value pairs).
    #[serde(default)]
    pub metadata: HashMap<String, String>,

    /// Creation timestamp (ISO 8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,

    /// Last update timestamp (ISO 8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Tenant {
    /// Create a new tenant with default quotas.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            enabled: true,
            quotas: TenantQuotas::default(),
            metadata: HashMap::new(),
            created_at: Some(chrono::Utc::now().to_rfc3339()),
            updated_at: None,
        }
    }

    /// Create the default tenant (for single-tenant mode).
    pub fn default_tenant() -> Self {
        Self {
            id: DEFAULT_TENANT_ID.to_string(),
            name: "Default Tenant".to_string(),
            enabled: true,
            quotas: TenantQuotas::unlimited(),
            metadata: HashMap::new(),
            created_at: None,
            updated_at: None,
        }
    }

    /// Validate tenant fields: ID format, name bounds, and metadata safety.
    ///
    /// SECURITY: Enforces bounds on metadata (max entries, max key/value length)
    /// and rejects control/Unicode format characters in name, metadata keys and
    /// values to prevent log injection and display manipulation.
    pub fn validate(&self) -> Result<(), TenantError> {
        validate_tenant_id(&self.id)?;

        // Validate name
        if self.name.is_empty() {
            return Err(TenantError::InvalidTenantId(
                "tenant name cannot be empty".to_string(),
            ));
        }
        if self.name.len() > MAX_TENANT_NAME_LEN {
            return Err(TenantError::InvalidTenantId(format!(
                "tenant name too long ({} > {} chars)",
                self.name.len(),
                MAX_TENANT_NAME_LEN
            )));
        }
        if self.name.chars().any(is_unsafe_char) {
            return Err(TenantError::InvalidTenantId(
                "tenant name contains control or format characters".to_string(),
            ));
        }

        // SECURITY (FIND-R58-SRV-010): Validate timestamp format (Trap 17).
        if let Some(ref ts) = self.created_at {
            if chrono::DateTime::parse_from_rfc3339(ts).is_err() {
                return Err(TenantError::InvalidTenantId(
                    "invalid created_at timestamp (must be RFC 3339)".to_string(),
                ));
            }
        }
        if let Some(ref ts) = self.updated_at {
            if chrono::DateTime::parse_from_rfc3339(ts).is_err() {
                return Err(TenantError::InvalidTenantId(
                    "invalid updated_at timestamp (must be RFC 3339)".to_string(),
                ));
            }
        }

        // Validate metadata bounds
        if self.metadata.len() > MAX_TENANT_METADATA_ENTRIES {
            return Err(TenantError::InvalidTenantId(format!(
                "too many metadata entries ({} > {})",
                self.metadata.len(),
                MAX_TENANT_METADATA_ENTRIES
            )));
        }

        for (key, value) in &self.metadata {
            if key.len() > MAX_TENANT_METADATA_KEY_LEN {
                return Err(TenantError::InvalidTenantId(format!(
                    "metadata key too long ({} > {} bytes)",
                    key.len(),
                    MAX_TENANT_METADATA_KEY_LEN
                )));
            }
            if value.len() > MAX_TENANT_METADATA_VALUE_LEN {
                return Err(TenantError::InvalidTenantId(format!(
                    "metadata value too long ({} > {} bytes)",
                    value.len(),
                    MAX_TENANT_METADATA_VALUE_LEN
                )));
            }
            if key.chars().any(is_unsafe_char) {
                return Err(TenantError::InvalidTenantId(
                    "metadata key contains control or format characters".to_string(),
                ));
            }
            if value.chars().any(is_unsafe_char) {
                return Err(TenantError::InvalidTenantId(
                    "metadata value contains control or format characters".to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Tenant quota limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantQuotas {
    /// Maximum number of policies this tenant can create.
    #[serde(default = "default_max_policies")]
    pub max_policies: u64,

    /// Maximum policy evaluations per minute.
    #[serde(default = "default_max_evaluations_per_minute")]
    pub max_evaluations_per_minute: u64,

    /// Maximum pending approvals at any time.
    #[serde(default = "default_max_pending_approvals")]
    pub max_pending_approvals: u64,

    /// Maximum audit log retention in days.
    #[serde(default = "default_max_audit_retention_days")]
    pub max_audit_retention_days: u64,

    /// Maximum request body size in bytes.
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: u64,
}

fn default_max_policies() -> u64 {
    1000
}

fn default_max_evaluations_per_minute() -> u64 {
    10000
}

fn default_max_pending_approvals() -> u64 {
    100
}

fn default_max_audit_retention_days() -> u64 {
    90
}

fn default_max_request_body_bytes() -> u64 {
    1024 * 1024 // 1 MB
}

impl Default for TenantQuotas {
    fn default() -> Self {
        Self {
            max_policies: default_max_policies(),
            max_evaluations_per_minute: default_max_evaluations_per_minute(),
            max_pending_approvals: default_max_pending_approvals(),
            max_audit_retention_days: default_max_audit_retention_days(),
            max_request_body_bytes: default_max_request_body_bytes(),
        }
    }
}

impl TenantQuotas {
    /// Create unlimited quotas (for default tenant or super-admin).
    pub fn unlimited() -> Self {
        Self {
            max_policies: u64::MAX,
            max_evaluations_per_minute: u64::MAX,
            max_pending_approvals: u64::MAX,
            max_audit_retention_days: u64::MAX,
            max_request_body_bytes: u64::MAX,
        }
    }
}

/// Multi-tenancy configuration.
#[derive(Debug, Clone)]
pub struct TenantConfig {
    /// Whether multi-tenancy is enabled.
    pub enabled: bool,

    /// Whether to allow tenant extraction from headers (X-Tenant-ID).
    /// Should be disabled in production unless behind a trusted proxy.
    pub allow_header_tenant: bool,

    /// Whether to extract tenant from subdomain.
    pub allow_subdomain_tenant: bool,

    /// Base domain for subdomain extraction (e.g., "vellaveto.example.com").
    pub base_domain: Option<String>,

    /// Default tenant ID when no tenant is specified.
    pub default_tenant_id: String,

    /// Whether to require a valid tenant (reject requests without tenant).
    pub require_tenant: bool,
}

impl Default for TenantConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_header_tenant: false,
            allow_subdomain_tenant: false,
            base_domain: None,
            default_tenant_id: DEFAULT_TENANT_ID.to_string(),
            require_tenant: false,
        }
    }
}

/// Extracted tenant context stored in request extensions.
#[derive(Debug, Clone)]
pub struct TenantContext {
    /// Tenant identifier.
    pub tenant_id: String,

    /// How the tenant was extracted.
    pub source: TenantSource,

    /// Tenant quotas (if available).
    pub quotas: Option<TenantQuotas>,
}

impl TenantContext {
    /// Create a context for the default tenant.
    pub fn default_tenant() -> Self {
        Self {
            tenant_id: DEFAULT_TENANT_ID.to_string(),
            source: TenantSource::Default,
            quotas: Some(TenantQuotas::unlimited()),
        }
    }

    /// Check if this is the default tenant.
    pub fn is_default(&self) -> bool {
        self.tenant_id == DEFAULT_TENANT_ID
    }

    /// Check if this is a global policy prefix.
    pub fn is_global(policy_id: &str) -> bool {
        policy_id.starts_with(GLOBAL_TENANT_PREFIX)
    }

    /// Namespace a policy ID for this tenant.
    pub fn namespace_policy(&self, policy_id: &str) -> String {
        if Self::is_global(policy_id) {
            policy_id.to_string()
        } else {
            format!("{}:{}", self.tenant_id, policy_id)
        }
    }

    /// Extract the tenant ID from a namespaced policy ID.
    pub fn extract_tenant_from_policy(policy_id: &str) -> Option<&str> {
        policy_id.split_once(':').map(|(tenant, _)| tenant)
    }

    /// Check if a policy belongs to this tenant (or is global/legacy).
    ///
    /// Policy matching rules:
    /// - `_global_:{policy}` - matches all tenants (global shared policy)
    /// - `{tenant_id}:{tool}:{rest}` - matches only that tenant (has 2+ colons)
    /// - `{tool}:{function}` - legacy format, matches all tenants (has 1 colon)
    /// - `{policy_name}` - legacy format, matches all tenants (no colon)
    ///
    /// The distinguishing factor is the number of colons: namespaced policies
    /// have at least 2 colons (tenant:tool:function), while legacy policies
    /// have at most 1 colon (tool:function or just policy_name).
    pub fn policy_matches(&self, policy_id: &str) -> bool {
        // Global policies match all tenants
        if Self::is_global(policy_id) {
            return true;
        }

        // Count colons to distinguish namespaced from legacy
        let colon_count = policy_id.chars().filter(|&c| c == ':').count();

        if colon_count >= 2 {
            // Namespaced format: {tenant_id}:{tool}:{rest}
            if let Some((tenant_prefix, _rest)) = policy_id.split_once(':') {
                // Must be this tenant's policy
                return tenant_prefix == self.tenant_id;
            }
        }

        // Legacy policy (0-1 colons) - matches all tenants for backwards compatibility
        true
    }
}

/// How the tenant was extracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantSource {
    /// From JWT claims (tenant_id or org_id).
    Jwt,
    /// From X-Tenant-ID header.
    Header,
    /// From subdomain.
    Subdomain,
    /// Default tenant (no explicit tenant specified).
    Default,
}

/// JWT claims for tenant extraction.
#[derive(Debug, Clone, Deserialize)]
pub struct TenantClaims {
    /// Tenant ID claim (primary).
    #[serde(default)]
    pub tenant_id: Option<String>,

    /// Organization ID claim (alternative).
    #[serde(default)]
    pub org_id: Option<String>,

    /// Organization claim (another alternative).
    #[serde(default)]
    pub organization: Option<String>,
}

impl TenantClaims {
    /// Extract the effective tenant ID from claims.
    pub fn effective_tenant_id(&self) -> Option<&str> {
        self.tenant_id
            .as_deref()
            .or(self.org_id.as_deref())
            .or(self.organization.as_deref())
    }
}

/// Tenant extraction errors.
#[derive(Debug, thiserror::Error)]
pub enum TenantError {
    #[error("tenant required but not specified")]
    TenantRequired,

    #[error("tenant not found: {0}")]
    TenantNotFound(String),

    #[error("tenant disabled: {0}")]
    TenantDisabled(String),

    #[error("invalid tenant ID: {0}")]
    InvalidTenantId(String),

    /// SECURITY (FIND-025): Internal error for lock poisoning.
    /// Fail-closed: lock poisoning prevents tenant operations rather than panicking.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Extract tenant ID from request headers.
///
/// SECURITY (FIND-R202-007): Rejects reserved tenant IDs (starting with `_`)
/// from header extraction to prevent privilege escalation via `X-Tenant-ID: _default_`.
pub fn extract_tenant_from_header(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        // SECURITY (FIND-R202-007): Reject reserved tenant IDs from headers.
        // The _default_ tenant has admin privileges; allowing it from headers
        // would let any caller bypass tenant isolation.
        .filter(|s| !s.starts_with('_'))
        .map(|s| s.to_string())
}

/// Extract tenant ID from subdomain.
///
/// SECURITY (FIND-R202-005): Requires a dot separator between subdomain and base
/// domain to prevent suffix-matching attacks (e.g., `evil-vellaveto.example.com`
/// should not match base domain `vellaveto.example.com`).
pub fn extract_tenant_from_subdomain(host: &str, base_domain: &str) -> Option<String> {
    // Remove port if present
    let host = host.split(':').next().unwrap_or(host);
    let base = base_domain.trim_start_matches('.');

    // SECURITY (FIND-R202-005): Require dot separator before base domain.
    // `host.ends_with(base)` alone would match "evil-base.example.com" against
    // "base.example.com". We must check for a preceding dot.
    let with_dot = format!(".{base}");
    if host == base {
        // Exact match = no subdomain
        return None;
    }
    if !host.ends_with(&with_dot) {
        return None;
    }

    // Extract subdomain (everything before ".{base}")
    let prefix = host.strip_suffix(&with_dot)?;
    if prefix.is_empty() {
        return None;
    }

    // Only use first subdomain segment (rightmost before base)
    let tenant = prefix.rsplit('.').next()?;
    if tenant.is_empty() {
        return None;
    }

    // SECURITY (FIND-R203-003): Reject reserved prefixes from subdomain extraction,
    // matching the guard already applied in `extract_tenant_from_header`.
    // Without this check, a host like `_default_.vellaveto.example.com` would
    // extract "_default_" and grant admin-level access to any caller who can
    // craft the Host header — a privilege-escalation vector identical to
    // FIND-R202-007 but via the subdomain path.
    if tenant.starts_with('_') {
        return None;
    }

    Some(tenant.to_string())
}

/// Validate a tenant ID format.
pub fn validate_tenant_id(id: &str) -> Result<(), TenantError> {
    if id.is_empty() {
        return Err(TenantError::InvalidTenantId(
            "tenant ID cannot be empty".to_string(),
        ));
    }

    if id.len() > 64 {
        return Err(TenantError::InvalidTenantId(
            "tenant ID too long (max 64 chars)".to_string(),
        ));
    }

    // Allow alphanumeric, hyphens, underscores
    if !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(TenantError::InvalidTenantId(
            "tenant ID contains invalid characters".to_string(),
        ));
    }

    // Reserved prefixes
    if id.starts_with('_') && id != DEFAULT_TENANT_ID {
        return Err(TenantError::InvalidTenantId(
            "tenant ID cannot start with underscore (reserved)".to_string(),
        ));
    }

    Ok(())
}

/// Middleware state for tenant extraction.
#[derive(Clone)]
pub struct TenantState {
    pub config: TenantConfig,
    /// Tenant store for looking up tenant details and quotas.
    pub store: Option<Arc<dyn TenantStore>>,
}

/// Trait for tenant storage backends.
pub trait TenantStore: Send + Sync {
    /// Look up a tenant by ID.
    fn get_tenant(&self, id: &str) -> Option<Tenant>;

    /// List all tenants.
    fn list_tenants(&self) -> Vec<Tenant>;

    /// Create a new tenant.
    fn create_tenant(&self, tenant: Tenant) -> Result<(), TenantError>;

    /// Update an existing tenant.
    fn update_tenant(&self, tenant: Tenant) -> Result<(), TenantError>;

    /// Delete a tenant.
    fn delete_tenant(&self, id: &str) -> Result<(), TenantError>;
}

/// In-memory tenant store for testing and single-instance deployments.
#[derive(Debug, Default)]
pub struct InMemoryTenantStore {
    tenants: std::sync::RwLock<HashMap<String, Tenant>>,
}

impl InMemoryTenantStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_default_tenant() -> Self {
        let store = Self::new();
        // SECURITY (FIND-025): Use ok() to avoid panic on lock poisoning.
        // If poisoned at construction time, the store is empty but usable.
        if let Ok(mut tenants) = store.tenants.write() {
            tenants.insert(DEFAULT_TENANT_ID.to_string(), Tenant::default_tenant());
        }
        store
    }
}

impl TenantStore for InMemoryTenantStore {
    fn get_tenant(&self, id: &str) -> Option<Tenant> {
        // SECURITY (FIND-025): Fail-closed on lock poisoning — return None (tenant not found).
        // This denies access rather than panicking.
        self.tenants
            .read()
            .ok()
            .and_then(|guard| guard.get(id).cloned())
    }

    fn list_tenants(&self) -> Vec<Tenant> {
        // SECURITY (FIND-025): Fail-closed on lock poisoning — return empty list.
        // SECURITY: Cap at MAX_TENANT_LIST to prevent unbounded allocation.
        self.tenants
            .read()
            .ok()
            .map(|guard| guard.values().take(MAX_TENANT_LIST).cloned().collect())
            .unwrap_or_default()
    }

    fn create_tenant(&self, tenant: Tenant) -> Result<(), TenantError> {
        // SECURITY: Validate tenant before storing.
        tenant.validate()?;
        // SECURITY (FIND-025): Return error on lock poisoning instead of panicking.
        let mut tenants = self
            .tenants
            .write()
            .map_err(|_| TenantError::Internal("lock poisoned".into()))?;
        if tenants.contains_key(&tenant.id) {
            return Err(TenantError::InvalidTenantId(format!(
                "tenant already exists: {}",
                tenant.id
            )));
        }
        tenants.insert(tenant.id.clone(), tenant);
        Ok(())
    }

    fn update_tenant(&self, tenant: Tenant) -> Result<(), TenantError> {
        // SECURITY: Validate tenant before storing.
        tenant.validate()?;
        // SECURITY (FIND-025): Return error on lock poisoning instead of panicking.
        let mut tenants = self
            .tenants
            .write()
            .map_err(|_| TenantError::Internal("lock poisoned".into()))?;
        if !tenants.contains_key(&tenant.id) {
            return Err(TenantError::TenantNotFound(tenant.id.clone()));
        }
        tenants.insert(tenant.id.clone(), tenant);
        Ok(())
    }

    fn delete_tenant(&self, id: &str) -> Result<(), TenantError> {
        // SECURITY (FIND-025): Return error on lock poisoning instead of panicking.
        let mut tenants = self
            .tenants
            .write()
            .map_err(|_| TenantError::Internal("lock poisoned".into()))?;
        if tenants.remove(id).is_none() {
            return Err(TenantError::TenantNotFound(id.to_string()));
        }
        Ok(())
    }
}

/// Extract tenant context from a request.
pub fn extract_tenant_from_request(
    headers: &axum::http::HeaderMap,
    host: Option<&str>,
    config: &TenantConfig,
    store: Option<&dyn TenantStore>,
) -> Result<TenantContext, TenantError> {
    // Skip extraction if multi-tenancy is disabled
    if !config.enabled {
        return Ok(TenantContext::default_tenant());
    }

    // Try extraction in priority order
    let (tenant_id, source) = {
        // 1. Header (if allowed)
        if config.allow_header_tenant {
            if let Some(id) = extract_tenant_from_header(headers) {
                (Some(id), TenantSource::Header)
            } else {
                (None, TenantSource::Default)
            }
        }
        // 2. Subdomain (if allowed)
        else if config.allow_subdomain_tenant {
            if let (Some(host), Some(base)) = (host, &config.base_domain) {
                if let Some(id) = extract_tenant_from_subdomain(host, base) {
                    (Some(id), TenantSource::Subdomain)
                } else {
                    (None, TenantSource::Default)
                }
            } else {
                (None, TenantSource::Default)
            }
        } else {
            (None, TenantSource::Default)
        }
    };

    // Use default tenant if none extracted
    let (tenant_id, source) = match tenant_id {
        Some(id) => (id, source),
        None => {
            if config.require_tenant {
                return Err(TenantError::TenantRequired);
            }
            (config.default_tenant_id.clone(), TenantSource::Default)
        }
    };

    // Validate tenant ID format
    validate_tenant_id(&tenant_id)?;

    // Look up tenant in store (if available) to get quotas and check enabled status
    let quotas = if let Some(store) = store {
        match store.get_tenant(&tenant_id) {
            Some(tenant) => {
                if !tenant.enabled {
                    return Err(TenantError::TenantDisabled(tenant_id));
                }
                Some(tenant.quotas)
            }
            None => {
                // Tenant not found in store - use default quotas
                // (or reject if require_tenant is true)
                if config.require_tenant && source != TenantSource::Default {
                    return Err(TenantError::TenantNotFound(tenant_id));
                }
                None
            }
        }
    } else {
        None
    };

    Ok(TenantContext {
        tenant_id,
        source,
        quotas,
    })
}

/// Tenant extraction middleware.
///
/// Extracts tenant from JWT, header, or subdomain and stores in request extensions.
pub async fn tenant_middleware(
    State(tenant_state): State<TenantState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Skip if multi-tenancy is disabled
    if !tenant_state.config.enabled {
        request
            .extensions_mut()
            .insert(TenantContext::default_tenant());
        return next.run(request).await;
    }

    // Extract host from headers
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract tenant
    let store = tenant_state.store.as_deref();
    match extract_tenant_from_request(
        request.headers(),
        host.as_deref(),
        &tenant_state.config,
        store,
    ) {
        Ok(context) => {
            request.extensions_mut().insert(context);
            next.run(request).await
        }
        Err(e) => {
            // SECURITY (FIND-047): Generic messages to prevent tenant enumeration.
            // Log the full error server-side; return opaque message to client.
            tracing::warn!("Tenant error: {}", e);
            let (status, msg) = match &e {
                TenantError::TenantRequired => (StatusCode::BAD_REQUEST, "Tenant header required"),
                TenantError::TenantNotFound(_) | TenantError::TenantDisabled(_) => {
                    (StatusCode::FORBIDDEN, "Access denied")
                }
                TenantError::InvalidTenantId(_) => {
                    (StatusCode::BAD_REQUEST, "Invalid tenant identifier")
                }
                TenantError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
            };
            (status, Json(json!({ "error": msg }))).into_response()
        }
    }
}

/// Verify a Bearer token against the tenant's stored API key hash.
///
/// Returns `Ok(())` if verification passes, `Err(status)` if it fails.
/// Gracefully passes (returns `Ok(())`) when:
/// - No tenant store is configured (single-tenant mode)
/// - The tenant has no `api_key_hash` in metadata (legacy tenant)
/// - The request has no Authorization header (unauthenticated — other middleware handles this)
/// - The tenant context is the default tenant (admin)
///
/// SECURITY: Uses constant-time comparison via `subtle::ConstantTimeEq` to prevent
/// timing attacks on key hash verification.
pub fn verify_tenant_api_key(
    tenant_ctx: &TenantContext,
    auth_header: Option<&str>,
    tenant_store: Option<&dyn TenantStore>,
) -> Result<(), StatusCode> {
    // Skip for default tenant (admin)
    if tenant_ctx.is_default() {
        return Ok(());
    }

    // Look up tenant to check if it has an api_key_hash
    let store = match tenant_store {
        Some(s) => s,
        None => return Ok(()), // No store — single-tenant mode
    };
    let tenant = match store.get_tenant(&tenant_ctx.tenant_id) {
        Some(t) => t,
        None => return Ok(()), // Tenant not found in store — let tenant middleware handle
    };

    let stored_hash = match tenant.metadata.get("api_key_hash") {
        Some(h) => h,
        None => return Ok(()), // No hash stored — legacy tenant, skip verification
    };

    // SECURITY (R263-TEN-1): If the tenant HAS a stored api_key_hash, a valid
    // Bearer token is REQUIRED. Previously returned Ok(()) when no auth header
    // was present, allowing complete bypass of per-tenant key verification.
    let auth = match auth_header {
        Some(h) if h.len() > 7 && h[..7].eq_ignore_ascii_case("bearer ") => h[7..].trim(),
        _ => {
            tracing::warn!(
                tenant_id = %tenant_ctx.tenant_id,
                "Per-tenant API key required but no Bearer token provided"
            );
            return Err(StatusCode::UNAUTHORIZED);
        }
    };
    if auth.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Compute SHA-256 of the presented token and constant-time compare.
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    let token_hash = hex::encode(Sha256::digest(auth.as_bytes()));

    if token_hash.as_bytes().ct_eq(stored_hash.as_bytes()).into() {
        Ok(())
    } else {
        tracing::warn!(
            tenant_id = %tenant_ctx.tenant_id,
            "Per-tenant API key verification failed"
        );
        Err(StatusCode::UNAUTHORIZED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_new() {
        let tenant = Tenant::new("test-tenant", "Test Tenant");
        assert_eq!(tenant.id, "test-tenant");
        assert_eq!(tenant.name, "Test Tenant");
        assert!(tenant.enabled);
        assert!(tenant.created_at.is_some());
    }

    #[test]
    fn test_tenant_quotas_default() {
        let quotas = TenantQuotas::default();
        assert_eq!(quotas.max_policies, 1000);
        assert_eq!(quotas.max_evaluations_per_minute, 10000);
        assert_eq!(quotas.max_pending_approvals, 100);
        assert_eq!(quotas.max_audit_retention_days, 90);
    }

    #[test]
    fn test_tenant_quotas_unlimited() {
        let quotas = TenantQuotas::unlimited();
        assert_eq!(quotas.max_policies, u64::MAX);
        assert_eq!(quotas.max_evaluations_per_minute, u64::MAX);
    }

    #[test]
    fn test_tenant_context_namespace_policy() {
        let context = TenantContext {
            tenant_id: "acme".to_string(),
            source: TenantSource::Header,
            quotas: None,
        };

        // Regular policy gets namespaced (adds tenant: prefix)
        assert_eq!(context.namespace_policy("file:read"), "acme:file:read");
        assert_eq!(
            context.namespace_policy("file_system:read_file"),
            "acme:file_system:read_file"
        );

        // Policy without colons gets namespaced
        assert_eq!(
            context.namespace_policy("dangerous_block"),
            "acme:dangerous_block"
        );

        // Global policy stays as-is
        assert_eq!(
            context.namespace_policy("_global_:dangerous_block"),
            "_global_:dangerous_block"
        );
    }

    #[test]
    fn test_tenant_context_policy_matches() {
        let context = TenantContext {
            tenant_id: "acme".to_string(),
            source: TenantSource::Header,
            quotas: None,
        };

        // Matches own policies (namespaced: tenant:tool:function with 2+ colons)
        assert!(context.policy_matches("acme:file:read"));
        assert!(context.policy_matches("acme:file_system:read_file"));

        // Matches global policies
        assert!(context.policy_matches("_global_:block_dangerous"));

        // Doesn't match other tenant's policies
        assert!(!context.policy_matches("other:file:read"));
        assert!(!context.policy_matches("competitor:file_system:write"));

        // Matches legacy policies (0-1 colons for backwards compatibility)
        assert!(context.policy_matches("file:read")); // 1 colon - legacy
        assert!(context.policy_matches("dangerous_block")); // 0 colons - legacy
    }

    #[test]
    fn test_extract_tenant_from_subdomain() {
        // Basic extraction
        assert_eq!(
            extract_tenant_from_subdomain("acme.vellaveto.example.com", "vellaveto.example.com"),
            Some("acme".to_string())
        );

        // With port
        assert_eq!(
            extract_tenant_from_subdomain(
                "acme.vellaveto.example.com:8080",
                "vellaveto.example.com"
            ),
            Some("acme".to_string())
        );

        // Multi-level subdomain (only first level)
        assert_eq!(
            extract_tenant_from_subdomain(
                "dev.acme.vellaveto.example.com",
                "vellaveto.example.com"
            ),
            Some("acme".to_string())
        );

        // No subdomain
        assert_eq!(
            extract_tenant_from_subdomain("vellaveto.example.com", "vellaveto.example.com"),
            None
        );

        // Different domain
        assert_eq!(
            extract_tenant_from_subdomain("acme.other.com", "vellaveto.example.com"),
            None
        );
    }

    #[test]
    fn test_validate_tenant_id() {
        // Valid
        assert!(validate_tenant_id("acme").is_ok());
        assert!(validate_tenant_id("acme-corp").is_ok());
        assert!(validate_tenant_id("tenant_123").is_ok());
        assert!(validate_tenant_id("ACME").is_ok());

        // Invalid: empty
        assert!(validate_tenant_id("").is_err());

        // Invalid: too long
        let long_id = "a".repeat(65);
        assert!(validate_tenant_id(&long_id).is_err());

        // Invalid: special characters
        assert!(validate_tenant_id("acme.corp").is_err());
        assert!(validate_tenant_id("acme/corp").is_err());
        assert!(validate_tenant_id("acme:corp").is_err());

        // Invalid: underscore prefix (reserved)
        assert!(validate_tenant_id("_custom").is_err());

        // Valid: _default_ is allowed
        assert!(validate_tenant_id("_default_").is_ok());
    }

    #[test]
    fn test_in_memory_tenant_store() {
        let store = InMemoryTenantStore::new();

        // Create
        let tenant = Tenant::new("acme", "Acme Corp");
        store.create_tenant(tenant.clone()).unwrap();

        // Get
        let fetched = store.get_tenant("acme").unwrap();
        assert_eq!(fetched.name, "Acme Corp");

        // List
        let tenants = store.list_tenants();
        assert_eq!(tenants.len(), 1);

        // Update
        let mut updated = tenant.clone();
        updated.name = "Acme Corporation".to_string();
        store.update_tenant(updated).unwrap();
        let fetched = store.get_tenant("acme").unwrap();
        assert_eq!(fetched.name, "Acme Corporation");

        // Delete
        store.delete_tenant("acme").unwrap();
        assert!(store.get_tenant("acme").is_none());

        // Delete non-existent
        assert!(store.delete_tenant("nonexistent").is_err());
    }

    #[test]
    fn test_extract_tenant_from_request_disabled() {
        let config = TenantConfig {
            enabled: false,
            ..Default::default()
        };

        let headers = axum::http::HeaderMap::new();
        let result = extract_tenant_from_request(&headers, None, &config, None);
        assert!(result.is_ok());

        let context = result.unwrap();
        assert_eq!(context.tenant_id, DEFAULT_TENANT_ID);
        assert!(context.is_default());
    }

    #[test]
    fn test_extract_tenant_from_request_header() {
        let config = TenantConfig {
            enabled: true,
            allow_header_tenant: true,
            ..Default::default()
        };

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_static("x-tenant-id"),
            axum::http::HeaderValue::from_static("acme"),
        );

        let result = extract_tenant_from_request(&headers, None, &config, None);
        assert!(result.is_ok());

        let context = result.unwrap();
        assert_eq!(context.tenant_id, "acme");
        assert_eq!(context.source, TenantSource::Header);
    }

    #[test]
    fn test_extract_tenant_required() {
        let config = TenantConfig {
            enabled: true,
            allow_header_tenant: true,
            require_tenant: true,
            ..Default::default()
        };

        let headers = axum::http::HeaderMap::new();
        let result = extract_tenant_from_request(&headers, None, &config, None);
        assert!(matches!(result, Err(TenantError::TenantRequired)));
    }

    #[test]
    fn test_tenant_context_is_global() {
        assert!(TenantContext::is_global("_global_:dangerous_block"));
        assert!(!TenantContext::is_global("acme:file:read"));
        assert!(!TenantContext::is_global("file:read"));
    }

    #[test]
    fn test_tenant_validate_valid() {
        let tenant = Tenant::new("acme", "Acme Corp");
        assert!(tenant.validate().is_ok());
    }

    #[test]
    fn test_tenant_validate_empty_name() {
        let mut tenant = Tenant::new("acme", "Acme Corp");
        tenant.name = String::new();
        assert!(tenant.validate().is_err());
    }

    #[test]
    fn test_tenant_validate_name_too_long() {
        let mut tenant = Tenant::new("acme", "Acme Corp");
        tenant.name = "x".repeat(257);
        assert!(tenant.validate().is_err());
    }

    #[test]
    fn test_tenant_validate_name_control_chars() {
        let mut tenant = Tenant::new("acme", "Acme Corp");
        tenant.name = "Acme\x00Corp".to_string();
        assert!(tenant.validate().is_err());
    }

    #[test]
    fn test_tenant_validate_name_unicode_format_chars() {
        let mut tenant = Tenant::new("acme", "Acme Corp");
        tenant.name = "Acme\u{200B}Corp".to_string();
        assert!(tenant.validate().is_err());
    }

    #[test]
    fn test_tenant_validate_metadata_too_many_entries() {
        let mut tenant = Tenant::new("acme", "Acme Corp");
        for i in 0..=MAX_TENANT_METADATA_ENTRIES {
            tenant.metadata.insert(format!("key{i}"), format!("val{i}"));
        }
        assert!(tenant.validate().is_err());
    }

    #[test]
    fn test_tenant_validate_metadata_key_control_chars() {
        let mut tenant = Tenant::new("acme", "Acme Corp");
        tenant
            .metadata
            .insert("key\x07bell".to_string(), "val".to_string());
        assert!(tenant.validate().is_err());
    }

    #[test]
    fn test_tenant_validate_metadata_value_control_chars() {
        let mut tenant = Tenant::new("acme", "Acme Corp");
        tenant
            .metadata
            .insert("key".to_string(), "val\nnewline".to_string());
        assert!(tenant.validate().is_err());
    }

    #[test]
    fn test_tenant_validate_metadata_value_bidi_override() {
        let mut tenant = Tenant::new("acme", "Acme Corp");
        tenant
            .metadata
            .insert("key".to_string(), "val\u{202E}rtl".to_string());
        assert!(tenant.validate().is_err());
    }

    #[test]
    fn test_tenant_deny_unknown_fields() {
        let json = r#"{"id":"test","name":"Test","unknown_field":"bad"}"#;
        let result: Result<Tenant, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown keys"
        );
    }

    #[test]
    fn test_tenant_validate_valid_metadata() {
        let mut tenant = Tenant::new("acme", "Acme Corp");
        tenant
            .metadata
            .insert("env".to_string(), "production".to_string());
        assert!(tenant.validate().is_ok());
    }

    // ── Additional TenantClaims tests ─────────────────────────────────

    #[test]
    fn test_tenant_claims_effective_tenant_id_priority() {
        // tenant_id takes precedence over org_id and organization
        let claims = TenantClaims {
            tenant_id: Some("primary".into()),
            org_id: Some("secondary".into()),
            organization: Some("tertiary".into()),
        };
        assert_eq!(claims.effective_tenant_id(), Some("primary"));
    }

    #[test]
    fn test_tenant_claims_fallback_to_org_id() {
        let claims = TenantClaims {
            tenant_id: None,
            org_id: Some("org-123".into()),
            organization: Some("fallback".into()),
        };
        assert_eq!(claims.effective_tenant_id(), Some("org-123"));
    }

    #[test]
    fn test_tenant_claims_fallback_to_organization() {
        let claims = TenantClaims {
            tenant_id: None,
            org_id: None,
            organization: Some("acme-org".into()),
        };
        assert_eq!(claims.effective_tenant_id(), Some("acme-org"));
    }

    #[test]
    fn test_tenant_claims_none_when_all_empty() {
        let claims = TenantClaims {
            tenant_id: None,
            org_id: None,
            organization: None,
        };
        assert_eq!(claims.effective_tenant_id(), None);
    }

    // ── Subdomain extraction security tests ───────────────────────────

    #[test]
    fn test_extract_tenant_from_subdomain_suffix_attack_rejected() {
        // SECURITY (FIND-R202-005): suffix-matching attack prevention
        assert_eq!(
            extract_tenant_from_subdomain("evil-vellaveto.example.com", "vellaveto.example.com"),
            None
        );
    }

    #[test]
    fn test_extract_tenant_from_subdomain_reserved_prefix_rejected() {
        // SECURITY (FIND-R203-003): reserved prefix rejection
        assert_eq!(
            extract_tenant_from_subdomain(
                "_default_.vellaveto.example.com",
                "vellaveto.example.com"
            ),
            None
        );
        assert_eq!(
            extract_tenant_from_subdomain("_admin_.vellaveto.example.com", "vellaveto.example.com"),
            None
        );
    }

    #[test]
    fn test_extract_tenant_from_subdomain_empty_subdomain() {
        assert_eq!(
            extract_tenant_from_subdomain(".vellaveto.example.com", "vellaveto.example.com"),
            None
        );
    }

    #[test]
    fn test_extract_tenant_from_subdomain_base_domain_with_leading_dot() {
        assert_eq!(
            extract_tenant_from_subdomain("acme.vellaveto.example.com", ".vellaveto.example.com"),
            Some("acme".to_string())
        );
    }

    // ── Header extraction security tests ──────────────────────────────

    #[test]
    fn test_extract_tenant_from_header_reserved_prefix_rejected() {
        // SECURITY (FIND-R202-007): reserved _default_ from headers
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_static("x-tenant-id"),
            axum::http::HeaderValue::from_static("_default_"),
        );
        assert_eq!(extract_tenant_from_header(&headers), None);
    }

    #[test]
    fn test_extract_tenant_from_header_empty_rejected() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_static("x-tenant-id"),
            axum::http::HeaderValue::from_static(""),
        );
        assert_eq!(extract_tenant_from_header(&headers), None);
    }

    #[test]
    fn test_extract_tenant_from_header_valid() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_static("x-tenant-id"),
            axum::http::HeaderValue::from_static("valid-tenant"),
        );
        assert_eq!(
            extract_tenant_from_header(&headers),
            Some("valid-tenant".to_string())
        );
    }

    #[test]
    fn test_extract_tenant_from_header_missing() {
        let headers = axum::http::HeaderMap::new();
        assert_eq!(extract_tenant_from_header(&headers), None);
    }

    // ── validate_tenant_id additional tests ───────────────────────────

    #[test]
    fn test_validate_tenant_id_exact_max_length() {
        let id = "a".repeat(64);
        assert!(validate_tenant_id(&id).is_ok());
    }

    #[test]
    fn test_validate_tenant_id_spaces_rejected() {
        assert!(validate_tenant_id("tenant with spaces").is_err());
    }

    #[test]
    fn test_validate_tenant_id_unicode_alphanumeric_accepted() {
        // Rust's is_alphanumeric() considers Unicode letters valid
        assert!(validate_tenant_id("tenant-über").is_ok());
    }

    #[test]
    fn test_validate_tenant_id_emoji_rejected() {
        // Emoji are not alphanumeric, not hyphens, not underscores
        assert!(validate_tenant_id("tenant-🔒").is_err());
    }

    // ── TenantContext policy matching edge cases ──────────────────────

    #[test]
    fn test_tenant_context_extract_tenant_from_policy() {
        assert_eq!(
            TenantContext::extract_tenant_from_policy("acme:file:read"),
            Some("acme")
        );
        assert_eq!(
            TenantContext::extract_tenant_from_policy("_global_:block"),
            Some("_global_")
        );
        assert_eq!(
            TenantContext::extract_tenant_from_policy("no_colon_policy"),
            None
        );
    }

    #[test]
    fn test_tenant_context_policy_matches_empty_tenant() {
        let context = TenantContext {
            tenant_id: "".to_string(),
            source: TenantSource::Default,
            quotas: None,
        };
        // Legacy policies (0-1 colons) match all tenants
        assert!(context.policy_matches("file:read"));
        assert!(context.policy_matches("simple_policy"));
    }

    // ── Tenant validate timestamp tests ───────────────────────────────

    #[test]
    fn test_tenant_validate_invalid_created_at_timestamp() {
        let mut tenant = Tenant::new("acme", "Acme Corp");
        tenant.created_at = Some("not-a-timestamp".to_string());
        assert!(tenant.validate().is_err());
    }

    #[test]
    fn test_tenant_validate_invalid_updated_at_timestamp() {
        let mut tenant = Tenant::new("acme", "Acme Corp");
        tenant.updated_at = Some("2026-13-01T00:00:00Z".to_string());
        assert!(tenant.validate().is_err());
    }

    #[test]
    fn test_tenant_validate_valid_rfc3339_timestamps() {
        let mut tenant = Tenant::new("acme", "Acme Corp");
        tenant.created_at = Some("2026-01-15T10:30:00Z".to_string());
        tenant.updated_at = Some("2026-02-20T14:00:00+00:00".to_string());
        assert!(tenant.validate().is_ok());
    }

    // ── Tenant metadata key/value length tests ────────────────────────

    #[test]
    fn test_tenant_validate_metadata_key_too_long() {
        let mut tenant = Tenant::new("acme", "Acme Corp");
        let long_key = "k".repeat(MAX_TENANT_METADATA_KEY_LEN + 1);
        tenant.metadata.insert(long_key, "value".to_string());
        let err = tenant.validate();
        assert!(err.is_err());
    }

    #[test]
    fn test_tenant_validate_metadata_value_too_long() {
        let mut tenant = Tenant::new("acme", "Acme Corp");
        let long_value = "v".repeat(MAX_TENANT_METADATA_VALUE_LEN + 1);
        tenant.metadata.insert("key".to_string(), long_value);
        let err = tenant.validate();
        assert!(err.is_err());
    }

    // ── InMemoryTenantStore edge cases ────────────────────────────────

    #[test]
    fn test_in_memory_tenant_store_with_default_tenant() {
        let store = InMemoryTenantStore::with_default_tenant();
        let default = store.get_tenant(DEFAULT_TENANT_ID);
        assert!(default.is_some());
        assert_eq!(default.unwrap().quotas.max_policies, u64::MAX);
    }

    #[test]
    fn test_in_memory_tenant_store_duplicate_create_rejected() {
        let store = InMemoryTenantStore::new();
        let tenant = Tenant::new("dup", "Duplicate");
        store.create_tenant(tenant).unwrap();

        let tenant2 = Tenant::new("dup", "Duplicate 2");
        let err = store.create_tenant(tenant2);
        assert!(err.is_err());
    }

    #[test]
    fn test_in_memory_tenant_store_update_nonexistent_rejected() {
        let store = InMemoryTenantStore::new();
        let tenant = Tenant::new("ghost", "Ghost Tenant");
        let err = store.update_tenant(tenant);
        assert!(matches!(err, Err(TenantError::TenantNotFound(_))));
    }

    #[test]
    fn test_tenant_config_default() {
        let config = TenantConfig::default();
        assert!(!config.enabled);
        assert!(!config.allow_header_tenant);
        assert!(!config.allow_subdomain_tenant);
        assert!(config.base_domain.is_none());
        assert_eq!(config.default_tenant_id, DEFAULT_TENANT_ID);
        assert!(!config.require_tenant);
    }

    // ── Per-tenant API key verification tests ────────────────────────────

    fn make_tenant_with_key_hash(id: &str, api_key: &str) -> Tenant {
        use sha2::{Digest, Sha256};
        let hash = hex::encode(Sha256::digest(api_key.as_bytes()));
        let mut t = Tenant::new(id, id);
        t.metadata.insert("api_key_hash".to_string(), hash);
        t
    }

    #[test]
    fn test_verify_tenant_key_valid_passes() {
        let store = InMemoryTenantStore::new();
        store
            .create_tenant(make_tenant_with_key_hash("t1", "vvt_correct_key"))
            .unwrap();
        let ctx = TenantContext {
            tenant_id: "t1".to_string(),
            source: TenantSource::Header,
            quotas: None,
        };
        let result = verify_tenant_api_key(&ctx, Some("Bearer vvt_correct_key"), Some(&store));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_tenant_key_invalid_rejected() {
        let store = InMemoryTenantStore::new();
        store
            .create_tenant(make_tenant_with_key_hash("t1", "vvt_correct_key"))
            .unwrap();
        let ctx = TenantContext {
            tenant_id: "t1".to_string(),
            source: TenantSource::Header,
            quotas: None,
        };
        let result = verify_tenant_api_key(&ctx, Some("Bearer vvt_wrong_key"), Some(&store));
        assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn test_verify_tenant_key_default_tenant_passes() {
        let ctx = TenantContext::default_tenant();
        let result = verify_tenant_api_key(&ctx, Some("Bearer anything"), None);
        assert!(result.is_ok(), "default tenant should bypass verification");
    }

    #[test]
    fn test_verify_tenant_key_no_store_passes() {
        let ctx = TenantContext {
            tenant_id: "t1".to_string(),
            source: TenantSource::Header,
            quotas: None,
        };
        let result = verify_tenant_api_key(&ctx, Some("Bearer key"), None);
        assert!(result.is_ok(), "no tenant store should pass gracefully");
    }

    #[test]
    fn test_verify_tenant_key_no_hash_in_metadata_passes() {
        let store = InMemoryTenantStore::new();
        store.create_tenant(Tenant::new("t1", "T1")).unwrap(); // No api_key_hash
        let ctx = TenantContext {
            tenant_id: "t1".to_string(),
            source: TenantSource::Header,
            quotas: None,
        };
        let result = verify_tenant_api_key(&ctx, Some("Bearer key"), Some(&store));
        assert!(result.is_ok(), "tenant without hash should pass (legacy)");
    }

    #[test]
    fn test_verify_tenant_key_no_auth_header_no_store_passes() {
        let ctx = TenantContext {
            tenant_id: "t1".to_string(),
            source: TenantSource::Header,
            quotas: None,
        };
        // No store → no hash to check → pass (single-tenant mode)
        let result = verify_tenant_api_key(&ctx, None, None);
        assert!(result.is_ok(), "no store means no hash to verify");
    }

    // R263-TEN-1: Tenant with stored hash MUST reject missing auth header
    #[test]
    fn test_verify_tenant_key_with_hash_no_auth_rejected() {
        let store = InMemoryTenantStore::new();
        store
            .create_tenant(make_tenant_with_key_hash("t1", "vvt_the_key"))
            .unwrap();
        let ctx = TenantContext {
            tenant_id: "t1".to_string(),
            source: TenantSource::Header,
            quotas: None,
        };
        // Tenant has api_key_hash but request has no Authorization header
        let result = verify_tenant_api_key(&ctx, None, Some(&store));
        assert_eq!(
            result,
            Err(StatusCode::UNAUTHORIZED),
            "tenant with stored hash must reject missing auth"
        );
    }
}
