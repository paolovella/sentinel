// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Role-Based Access Control (RBAC) for the Vellaveto HTTP API server.
//!
//! Defines permissions, roles, and middleware for enforcing access control
//! on API endpoints. Roles are extracted from JWT claims or a dedicated header.
//!
//! ## Permission Model
//!
//! Permissions are fine-grained capabilities representing specific actions:
//! - Policy management: read, write, reload
//! - Approvals: read pending, resolve (approve/deny)
//! - Audit: read entries, export, create checkpoints
//! - Admin: metrics, dashboard, config reload
//!
//! ## Built-in Roles
//!
//! | Role     | Description                                    |
//! |----------|------------------------------------------------|
//! | Admin    | Full access to all endpoints                   |
//! | Operator | Policy read, approval resolution, audit read   |
//! | Auditor  | Audit read and export only                     |
//! | Viewer   | Read-only access to policies and audit         |
//!
//! ## Role Extraction
//!
//! Roles are determined in order of precedence:
//! 1. JWT claim: `role` or `vellaveto_role`
//! 2. Header: `X-Vellaveto-Role` (for development/testing)
//! 3. Default: `Viewer` (least privilege)

use crate::iam::extract_session_cookie;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::sync::Arc;

/// Fine-grained permissions for API operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    // Policy management
    /// Read policy configurations
    PolicyRead,
    /// Create or modify policies
    PolicyWrite,
    /// Hot-reload policies from config file
    PolicyReload,

    // Approvals
    /// View pending approvals
    ApprovalRead,
    /// Approve or deny pending approvals
    ApprovalResolve,

    // Audit
    /// Read audit log entries
    AuditRead,
    /// Export audit logs (CEF, JSON Lines, etc.)
    AuditExport,
    /// Create signed audit checkpoints
    AuditCheckpoint,

    // Admin
    /// Read Prometheus and JSON metrics
    MetricsRead,
    /// Access the admin dashboard
    DashboardAccess,
    /// Reload configuration (restart-level changes)
    ConfigReload,

    // Evaluation
    /// Submit actions for policy evaluation
    Evaluate,

    // Tool registry
    /// Read tool registry entries
    ToolRegistryRead,
    /// Approve or revoke tools in the registry
    ToolRegistryWrite,
}

impl Permission {
    /// Return all defined permissions.
    pub fn all() -> &'static [Permission] {
        &[
            Permission::PolicyRead,
            Permission::PolicyWrite,
            Permission::PolicyReload,
            Permission::ApprovalRead,
            Permission::ApprovalResolve,
            Permission::AuditRead,
            Permission::AuditExport,
            Permission::AuditCheckpoint,
            Permission::MetricsRead,
            Permission::DashboardAccess,
            Permission::ConfigReload,
            Permission::Evaluate,
            Permission::ToolRegistryRead,
            Permission::ToolRegistryWrite,
        ]
    }
}

/// Built-in roles with predefined permission sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Full access to all permissions.
    Admin,

    /// Operational access: policy read, approval resolution, audit read, metrics.
    Operator,

    /// Audit-focused: read and export audit logs only.
    Auditor,

    /// Read-only access to policies and audit logs.
    #[default]
    Viewer,
}

impl Role {
    /// Parse a role from a string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Role> {
        match s.to_lowercase().as_str() {
            "admin" => Some(Role::Admin),
            "operator" => Some(Role::Operator),
            "auditor" => Some(Role::Auditor),
            "viewer" => Some(Role::Viewer),
            _ => None,
        }
    }

    /// Get the set of permissions granted to this role.
    pub fn permissions(&self) -> HashSet<Permission> {
        match self {
            Role::Admin => Permission::all().iter().copied().collect(),
            Role::Operator => [
                Permission::PolicyRead,
                Permission::PolicyReload,
                Permission::ApprovalRead,
                Permission::ApprovalResolve,
                Permission::AuditRead,
                Permission::MetricsRead,
                Permission::DashboardAccess,
                Permission::Evaluate,
                Permission::ToolRegistryRead,
            ]
            .into_iter()
            .collect(),
            Role::Auditor => [
                Permission::AuditRead,
                Permission::AuditExport,
                Permission::DashboardAccess,
            ]
            .into_iter()
            .collect(),
            Role::Viewer => [
                Permission::PolicyRead,
                Permission::AuditRead,
                Permission::DashboardAccess,
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Check if this role has a specific permission.
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions().contains(&permission)
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::Operator => write!(f, "operator"),
            Role::Auditor => write!(f, "auditor"),
            Role::Viewer => write!(f, "viewer"),
        }
    }
}

impl std::str::FromStr for Role {
    type Err = RbacError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Role::from_str_loose(s).ok_or_else(|| RbacError::UnknownRole(s.to_string()))
    }
}

/// RBAC-related errors.
#[derive(Debug, thiserror::Error)]
pub enum RbacError {
    #[error("unknown role: {0}")]
    UnknownRole(String),

    #[error("permission denied: {0} required")]
    PermissionDenied(String),

    #[error("authentication required")]
    AuthenticationRequired,
}

/// Extracted principal information from the request.
///
/// Stored in request extensions for downstream handlers.
#[derive(Debug, Clone)]
pub struct Principal {
    /// Subject identifier (user ID, client ID, etc.)
    pub subject: Option<String>,
    /// Assigned role
    pub role: Role,
    /// Source of role assignment (jwt, header, default)
    pub role_source: RoleSource,
}

/// How the role was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleSource {
    /// Extracted from JWT claims
    Jwt,
    /// From X-Vellaveto-Role header (development/testing)
    Header,
    /// From IAM session cookie (Phase 46)
    Session,
    /// Default role (no explicit assignment)
    Default,
}

impl Principal {
    /// Create a principal with the default (Viewer) role.
    pub fn default_viewer() -> Self {
        Self {
            subject: None,
            role: Role::Viewer,
            role_source: RoleSource::Default,
        }
    }

    /// Check if this principal has a specific permission.
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.role.has_permission(permission)
    }

    /// Require a permission, returning an error response if denied.
    pub fn require_permission(&self, permission: Permission) -> Result<(), Box<Response>> {
        if self.has_permission(permission) {
            Ok(())
        } else {
            // SECURITY (FIND-048): Don't leak permission names or caller role.
            tracing::warn!(
                role = %self.role,
                permission = ?permission,
                "RBAC permission denied"
            );
            Err(Box::new(
                (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "Permission denied",
                    })),
                )
                    .into_response(),
            ))
        }
    }
}

/// JWT claims structure for role extraction.
///
/// Supports both `role` and `vellaveto_role` claim names for flexibility
/// with different identity providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleClaims {
    /// Standard subject claim
    #[serde(default)]
    pub sub: Option<String>,

    /// Role claim (primary)
    #[serde(default)]
    pub role: Option<String>,

    /// Alternative role claim for namespaced tokens
    #[serde(default)]
    pub vellaveto_role: Option<String>,

    /// Roles claim (array form, some IdPs use this)
    #[serde(default)]
    pub roles: Option<Vec<String>>,

    /// Audience claim supporting both string and string-array forms.
    #[serde(default)]
    pub aud: Option<AudienceClaim>,

    /// Nonce used in OIDC authentication flows.
    #[serde(default)]
    pub nonce: Option<String>,
}

/// JWT `aud` claim representation (string or array of strings).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AudienceClaim {
    Single(String),
    Multiple(Vec<String>),
}

impl AudienceClaim {
    fn contains(&self, expected: &str) -> bool {
        match self {
            AudienceClaim::Single(value) => value == expected,
            AudienceClaim::Multiple(values) => values.iter().any(|value| value == expected),
        }
    }
}

impl RoleClaims {
    /// Extract the effective role from claims.
    ///
    /// Priority:
    /// 1. `role` claim (direct)
    /// 2. `vellaveto_role` claim (namespaced)
    /// 3. First element of `roles` array
    pub fn effective_role(&self) -> Option<Role> {
        // Try role claim first
        if let Some(ref role_str) = self.role {
            if let Some(role) = Role::from_str_loose(role_str) {
                return Some(role);
            }
        }

        // Try vellaveto_role claim
        if let Some(ref role_str) = self.vellaveto_role {
            if let Some(role) = Role::from_str_loose(role_str) {
                return Some(role);
            }
        }

        // Try roles array
        if let Some(ref roles) = self.roles {
            for role_str in roles {
                if let Some(role) = Role::from_str_loose(role_str) {
                    return Some(role);
                }
            }
        }

        None
    }

    fn matches_audience(&self, expected: &str) -> bool {
        self.aud
            .as_ref()
            .is_some_and(|aud_claim| aud_claim.contains(expected))
    }
}

/// Configuration for RBAC middleware.
#[derive(Debug, Clone)]
pub struct RbacConfig {
    /// Whether to allow role assignment via X-Vellaveto-Role header.
    /// Should be disabled in production (security risk).
    pub allow_header_role: bool,

    /// Default role when no role is specified.
    pub default_role: Role,

    /// Whether RBAC is enabled. When disabled, all requests get Admin role.
    pub enabled: bool,

    /// JWT validation configuration. When set, Bearer tokens are validated.
    pub jwt_config: Option<JwtConfig>,
}

impl Default for RbacConfig {
    fn default() -> Self {
        Self {
            allow_header_role: false,
            default_role: Role::Viewer,
            // Disabled by default for backwards compatibility. Enable explicitly
            // via configuration when RBAC is desired.
            enabled: false,
            jwt_config: None,
        }
    }
}

/// JWT validation configuration for role extraction.
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// The secret or public key for validating JWT signatures.
    /// For HMAC (HS256/HS384/HS512): the shared secret.
    /// For RSA/ECDSA: the PEM-encoded public key.
    pub key: JwtKey,

    /// Expected issuer (`iss` claim). If set, tokens without a matching
    /// issuer are rejected.
    pub issuer: Option<String>,

    /// Expected audience (`aud` claim). If set, tokens without a matching
    /// audience are rejected.
    pub audience: Option<String>,

    /// Allowed signing algorithms. Defaults to RS256 only.
    /// SECURITY: Never include HS* algorithms when using RSA/ECDSA keys
    /// to prevent algorithm confusion attacks.
    pub algorithms: Vec<jsonwebtoken::Algorithm>,

    /// Clock skew leeway for exp/nbf validation (seconds).
    pub leeway_seconds: u64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            key: JwtKey::Secret(String::new()),
            issuer: None,
            audience: None,
            algorithms: vec![jsonwebtoken::Algorithm::RS256],
            leeway_seconds: 60,
        }
    }
}

/// JWT key material for signature validation.
#[derive(Debug, Clone)]
pub enum JwtKey {
    /// HMAC shared secret (for HS256/HS384/HS512).
    /// SECURITY: Only use for trusted internal tokens.
    Secret(String),

    /// RSA public key in PEM format (for RS256/RS384/RS512/PS256/PS384/PS512).
    RsaPublicKeyPem(String),

    /// ECDSA public key in PEM format (for ES256/ES384).
    EcPublicKeyPem(String),

    /// Ed25519 public key in PEM format (for EdDSA).
    EdDsaPublicKeyPem(String),
}

impl JwtKey {
    fn key_kind(&self) -> &'static str {
        match self {
            JwtKey::Secret(_) => "hmac",
            JwtKey::RsaPublicKeyPem(_) => "rsa",
            JwtKey::EcPublicKeyPem(_) => "ecdsa",
            JwtKey::EdDsaPublicKeyPem(_) => "eddsa",
        }
    }

    fn supports_algorithm(&self, algorithm: jsonwebtoken::Algorithm) -> bool {
        use jsonwebtoken::Algorithm;

        match self {
            JwtKey::Secret(_) => matches!(
                algorithm,
                Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
            ),
            JwtKey::RsaPublicKeyPem(_) => matches!(
                algorithm,
                Algorithm::RS256
                    | Algorithm::RS384
                    | Algorithm::RS512
                    | Algorithm::PS256
                    | Algorithm::PS384
                    | Algorithm::PS512
            ),
            JwtKey::EcPublicKeyPem(_) => {
                matches!(algorithm, Algorithm::ES256 | Algorithm::ES384)
            }
            JwtKey::EdDsaPublicKeyPem(_) => matches!(algorithm, Algorithm::EdDSA),
        }
    }
}

/// JWT validation errors.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("missing Authorization header")]
    MissingToken,

    #[error("invalid Authorization header format (expected: Bearer <token>)")]
    InvalidFormat,

    #[error("JWT validation failed: {0}")]
    ValidationFailed(String),

    #[error("invalid key configuration: {0}")]
    InvalidKey(String),

    #[error("unsupported algorithm: {0:?}")]
    UnsupportedAlgorithm(jsonwebtoken::Algorithm),

    #[error("algorithm/key mismatch: {algorithm:?} is incompatible with {key_type} key")]
    AlgorithmKeyMismatch {
        algorithm: jsonwebtoken::Algorithm,
        key_type: &'static str,
    },
}

/// Extract and validate a JWT token from the Authorization header.
///
/// Returns the extracted claims on success.
pub fn extract_jwt_claims(auth_header: &str, config: &JwtConfig) -> Result<RoleClaims, JwtError> {
    use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};

    // Extract Bearer token
    let token = if auth_header.len() > 7 && auth_header[..7].eq_ignore_ascii_case("bearer ") {
        &auth_header[7..]
    } else {
        return Err(JwtError::InvalidFormat);
    };

    if token.is_empty() {
        return Err(JwtError::InvalidFormat);
    }

    // Decode header to verify algorithm
    let header = decode_header(token).map_err(|e| JwtError::ValidationFailed(e.to_string()))?;

    // Verify algorithm is allowed
    if !config.algorithms.contains(&header.alg) {
        return Err(JwtError::UnsupportedAlgorithm(header.alg));
    }

    if !config.key.supports_algorithm(header.alg) {
        return Err(JwtError::AlgorithmKeyMismatch {
            algorithm: header.alg,
            key_type: config.key.key_kind(),
        });
    }

    // Build decoding key based on key type
    let decoding_key = match &config.key {
        JwtKey::Secret(secret) => DecodingKey::from_secret(secret.as_bytes()),
        JwtKey::RsaPublicKeyPem(pem) => DecodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|e| JwtError::InvalidKey(format!("RSA PEM: {}", e)))?,
        JwtKey::EcPublicKeyPem(pem) => DecodingKey::from_ec_pem(pem.as_bytes())
            .map_err(|e| JwtError::InvalidKey(format!("EC PEM: {}", e)))?,
        JwtKey::EdDsaPublicKeyPem(pem) => DecodingKey::from_ed_pem(pem.as_bytes())
            .map_err(|e| JwtError::InvalidKey(format!("EdDSA PEM: {}", e)))?,
    };

    // Build validation parameters
    let mut validation = Validation::new(header.alg);
    validation.leeway = config.leeway_seconds;

    // Set issuer validation if configured
    if let Some(ref iss) = config.issuer {
        validation.set_issuer(&[iss]);
    }

    // Set audience validation if configured
    if let Some(ref aud) = config.audience {
        validation.set_audience(&[aud]);
    }

    // When issuer/audience aren't set, jsonwebtoken skips validation for those claims

    // Decode and validate
    let token_data = decode::<RoleClaims>(token, &decoding_key, &validation)
        .map_err(|e| JwtError::ValidationFailed(e.to_string()))?;
    let claims = token_data.claims;

    // Defense in depth: independently inspect aud claim so audience
    // enforcement remains strict for both string and array forms.
    if let Some(ref aud) = config.audience {
        if !claims.matches_audience(aud) {
            return Err(JwtError::ValidationFailed(format!(
                "token audience mismatch: expected '{}'",
                aud
            )));
        }
    }

    Ok(claims)
}

/// Extract principal from a request using JWT validation.
///
/// Priority:
/// 1. JWT token in Authorization header (if jwt_config is set)
/// 2. X-Vellaveto-Role header (if allow_header_role is true)
/// 3. Default role
pub fn extract_principal_from_request(
    headers: &axum::http::HeaderMap,
    config: &RbacConfig,
) -> Result<Principal, JwtError> {
    // Try JWT first if configured
    if let Some(ref jwt_config) = config.jwt_config {
        if let Some(auth_header) = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            let claims = extract_jwt_claims(auth_header, jwt_config)?;
            let role = claims.effective_role().unwrap_or(config.default_role);
            return Ok(Principal {
                subject: claims.sub,
                role,
                role_source: RoleSource::Jwt,
            });
        }
    }

    // Try header role if allowed
    if config.allow_header_role {
        if let Some(role) = extract_role_from_header(headers) {
            return Ok(Principal {
                subject: None,
                role,
                role_source: RoleSource::Header,
            });
        }
    }

    // Default role
    Ok(Principal {
        subject: None,
        role: config.default_role,
        role_source: RoleSource::Default,
    })
}

/// Extract role from request headers (development/testing only).
///
/// SECURITY: This should be disabled in production. The `allow_header_role`
/// config option controls whether this is checked.
pub fn extract_role_from_header(headers: &axum::http::HeaderMap) -> Option<Role> {
    headers
        .get("x-vellaveto-role")
        .and_then(|v| v.to_str().ok())
        .and_then(Role::from_str_loose)
}

/// Required permission for each endpoint path and method.
///
/// Returns the permission required to access the given endpoint.
pub fn endpoint_permission(method: &axum::http::Method, path: &str) -> Option<Permission> {
    use axum::http::Method;

    // Health endpoint is always public
    if path == "/health" {
        return None;
    }

    // Match endpoint patterns
    match (method, path) {
        // Evaluation
        (_, "/api/evaluate") => Some(Permission::Evaluate),

        // Policies
        (&Method::GET, "/api/policies") => Some(Permission::PolicyRead),
        (&Method::POST, "/api/policies") => Some(Permission::PolicyWrite),
        (&Method::POST, "/api/policies/reload") => Some(Permission::PolicyReload),
        (_, p) if p.starts_with("/api/policies/") && method == Method::DELETE => {
            Some(Permission::PolicyWrite)
        }

        // Audit
        (&Method::GET, "/api/audit/entries") => Some(Permission::AuditRead),
        (&Method::GET, "/api/audit/export") => Some(Permission::AuditExport),
        (&Method::GET, "/api/audit/report") => Some(Permission::AuditRead),
        (&Method::GET, "/api/audit/verify") => Some(Permission::AuditRead),
        (&Method::GET, "/api/audit/checkpoints") => Some(Permission::AuditRead),
        (&Method::GET, "/api/audit/checkpoints/verify") => Some(Permission::AuditRead),
        (&Method::POST, "/api/audit/checkpoint") => Some(Permission::AuditCheckpoint),

        // Approvals
        (&Method::GET, "/api/approvals/pending") => Some(Permission::ApprovalRead),
        (_, p) if p.starts_with("/api/approvals/") => {
            if p.ends_with("/approve") || p.ends_with("/deny") {
                Some(Permission::ApprovalResolve)
            } else {
                Some(Permission::ApprovalRead)
            }
        }

        // Metrics
        (&Method::GET, "/api/metrics") => Some(Permission::MetricsRead),
        (&Method::GET, "/metrics") => Some(Permission::MetricsRead),
        (&Method::GET, "/iam/scim/status") => Some(Permission::MetricsRead),
        (&Method::POST, "/api/auth/client-metadata") => Some(Permission::ConfigReload),

        // Billing and metering
        (&Method::GET, "/api/billing/license") => Some(Permission::MetricsRead),
        (&Method::GET, p) if p.starts_with("/api/billing/usage/") && p.ends_with("/history") => {
            Some(Permission::MetricsRead)
        }
        (&Method::GET, p) if p.starts_with("/api/billing/usage/") => Some(Permission::MetricsRead),
        (&Method::GET, p) if p.starts_with("/api/billing/quotas/") => Some(Permission::MetricsRead),
        (&Method::POST, p) if p.starts_with("/api/billing/usage/") && p.ends_with("/reset") => {
            Some(Permission::ConfigReload)
        }

        // Tool registry
        (&Method::GET, "/api/registry/tools") => Some(Permission::ToolRegistryRead),
        (_, p) if p.starts_with("/api/registry/tools/") => Some(Permission::ToolRegistryWrite),

        // Dashboard
        (_, p) if p.starts_with("/dashboard") => Some(Permission::DashboardAccess),

        // SECURITY (R230-SRV-1): Explicit topology endpoint permissions.
        (&Method::GET, "/api/topology") => Some(Permission::MetricsRead),
        (&Method::GET, "/api/topology/status") => Some(Permission::MetricsRead),
        (&Method::POST, "/api/topology/recrawl") => Some(Permission::ConfigReload),
        (_, p) if p.starts_with("/api/topology/servers/") && method == Method::DELETE => {
            Some(Permission::ConfigReload)
        }

        // Discovery endpoints
        (&Method::GET, p) if p.starts_with("/api/discovery/") => Some(Permission::ToolRegistryRead),
        (&Method::POST, p) if p.starts_with("/api/discovery/") => {
            Some(Permission::ToolRegistryWrite)
        }

        // Default: require admin for unknown endpoints (fail-closed)
        _ => Some(Permission::ConfigReload),
    }
}

/// Middleware state for RBAC.
#[derive(Clone)]
pub struct RbacState {
    pub config: RbacConfig,
    pub iam_state: Option<Arc<crate::iam::IamState>>,
}

/// RBAC enforcement middleware.
///
/// Extracts the principal from the request, checks permissions against
/// the endpoint's requirements, and stores the principal in extensions.
///
/// Role extraction priority:
/// 1. JWT token in Authorization header (if jwt_config is set)
/// 2. X-Vellaveto-Role header (if allow_header_role is true)
/// 3. Default role (Viewer)
pub async fn rbac_middleware(
    State(rbac_state): State<RbacState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Skip RBAC if disabled (all requests get Admin)
    if !rbac_state.config.enabled {
        request.extensions_mut().insert(Principal {
            subject: None,
            role: Role::Admin,
            role_source: RoleSource::Default,
        });
        return next.run(request).await;
    }

    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let required_permission = match endpoint_permission(&method, &path) {
        Some(permission) => permission,
        None => {
            // Public endpoints skip authentication checks.
            request.extensions_mut().insert(Principal {
                subject: None,
                role: rbac_state.config.default_role,
                role_source: RoleSource::Default,
            });
            return next.run(request).await;
        }
    };

    if let Some(iam_state) = &rbac_state.iam_state {
        if let Some(session_id) =
            extract_session_cookie(request.headers(), iam_state.session_cookie_name())
        {
            if let Some(session) = iam_state.find_session(&session_id) {
                let principal = Principal {
                    subject: session.subject.clone(),
                    role: session.role,
                    role_source: RoleSource::Session,
                };
                if !principal.has_permission(required_permission) {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": "Permission denied",
                        })),
                    )
                        .into_response();
                }
                request.extensions_mut().insert(principal);
                return next.run(request).await;
            }
        }
    }

    // SECURITY: In JWT mode, protected endpoints must not silently fall back
    // to the default role. Require either:
    // 1) Authorization header (validated JWT), or
    // 2) X-Vellaveto-Role header when explicit header-role mode is enabled.
    let has_authz = request
        .headers()
        .contains_key(axum::http::header::AUTHORIZATION);
    let has_valid_role_header = rbac_state.config.allow_header_role
        && extract_role_from_header(request.headers()).is_some();
    if rbac_state.config.jwt_config.is_some() && !has_authz && !has_valid_role_header {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Authentication required",
            })),
        )
            .into_response();
    }

    // Extract principal from JWT, header, or use default.
    // SECURITY: If an Authorization header is present but JWT validation fails,
    // fail closed with 401 instead of silently falling back to header/default roles.
    let principal = match extract_principal_from_request(request.headers(), &rbac_state.config) {
        Ok(principal) => principal,
        Err(err) => {
            tracing::warn!("RBAC JWT authentication failed: {}", err);
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Invalid authentication token",
                })),
            )
                .into_response();
        }
    };

    if !principal.has_permission(required_permission) {
        // SECURITY (FIND-R51-002): Only return a generic error message.
        // Do not leak required_permission, role, or path to the client.
        tracing::warn!(
            role = %principal.role,
            permission = ?required_permission,
            path = %path,
            "RBAC middleware permission denied"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Permission denied",
            })),
        )
            .into_response();
    }

    // Store principal in extensions for handlers
    request.extensions_mut().insert(principal);

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_from_str_loose() {
        assert_eq!(Role::from_str_loose("admin"), Some(Role::Admin));
        assert_eq!(Role::from_str_loose("ADMIN"), Some(Role::Admin));
        assert_eq!(Role::from_str_loose("Admin"), Some(Role::Admin));
        assert_eq!(Role::from_str_loose("operator"), Some(Role::Operator));
        assert_eq!(Role::from_str_loose("auditor"), Some(Role::Auditor));
        assert_eq!(Role::from_str_loose("viewer"), Some(Role::Viewer));
        assert_eq!(Role::from_str_loose("unknown"), None);
    }

    #[test]
    fn test_admin_has_all_permissions() {
        let admin_perms = Role::Admin.permissions();
        for perm in Permission::all() {
            assert!(admin_perms.contains(perm), "Admin should have {:?}", perm);
        }
    }

    #[test]
    fn test_viewer_permissions() {
        let viewer = Role::Viewer;
        assert!(viewer.has_permission(Permission::PolicyRead));
        assert!(viewer.has_permission(Permission::AuditRead));
        assert!(viewer.has_permission(Permission::DashboardAccess));
        assert!(!viewer.has_permission(Permission::PolicyWrite));
        assert!(!viewer.has_permission(Permission::ApprovalResolve));
        assert!(!viewer.has_permission(Permission::Evaluate));
    }

    #[test]
    fn test_operator_permissions() {
        let operator = Role::Operator;
        assert!(operator.has_permission(Permission::PolicyRead));
        assert!(operator.has_permission(Permission::PolicyReload));
        assert!(operator.has_permission(Permission::ApprovalRead));
        assert!(operator.has_permission(Permission::ApprovalResolve));
        assert!(operator.has_permission(Permission::AuditRead));
        assert!(operator.has_permission(Permission::MetricsRead));
        assert!(operator.has_permission(Permission::Evaluate));
        assert!(!operator.has_permission(Permission::PolicyWrite));
        assert!(!operator.has_permission(Permission::AuditExport));
        assert!(!operator.has_permission(Permission::AuditCheckpoint));
    }

    #[test]
    fn test_auditor_permissions() {
        let auditor = Role::Auditor;
        assert!(auditor.has_permission(Permission::AuditRead));
        assert!(auditor.has_permission(Permission::AuditExport));
        assert!(auditor.has_permission(Permission::DashboardAccess));
        assert!(!auditor.has_permission(Permission::PolicyRead));
        assert!(!auditor.has_permission(Permission::Evaluate));
        assert!(!auditor.has_permission(Permission::ApprovalResolve));
    }

    #[test]
    fn test_role_display() {
        assert_eq!(Role::Admin.to_string(), "admin");
        assert_eq!(Role::Operator.to_string(), "operator");
        assert_eq!(Role::Auditor.to_string(), "auditor");
        assert_eq!(Role::Viewer.to_string(), "viewer");
    }

    #[test]
    fn test_role_from_str() {
        assert_eq!("admin".parse::<Role>().unwrap(), Role::Admin);
        assert_eq!("OPERATOR".parse::<Role>().unwrap(), Role::Operator);
        assert!("unknown".parse::<Role>().is_err());
    }

    #[test]
    fn test_role_claims_effective_role() {
        // role claim
        let claims = RoleClaims {
            sub: Some("user-1".into()),
            role: Some("admin".into()),
            vellaveto_role: None,
            roles: None,
            aud: None,
            nonce: None,
        };
        assert_eq!(claims.effective_role(), Some(Role::Admin));

        // vellaveto_role claim
        let claims = RoleClaims {
            sub: None,
            role: None,
            vellaveto_role: Some("operator".into()),
            roles: None,
            aud: None,
            nonce: None,
        };
        assert_eq!(claims.effective_role(), Some(Role::Operator));

        // roles array
        let claims = RoleClaims {
            sub: None,
            role: None,
            vellaveto_role: None,
            roles: Some(vec!["auditor".into()]),
            aud: None,
            nonce: None,
        };
        assert_eq!(claims.effective_role(), Some(Role::Auditor));

        // role takes precedence over vellaveto_role
        let claims = RoleClaims {
            sub: None,
            role: Some("admin".into()),
            vellaveto_role: Some("viewer".into()),
            roles: None,
            aud: None,
            nonce: None,
        };
        assert_eq!(claims.effective_role(), Some(Role::Admin));

        // no role
        let claims = RoleClaims {
            sub: None,
            role: None,
            vellaveto_role: None,
            roles: None,
            aud: None,
            nonce: None,
        };
        assert_eq!(claims.effective_role(), None);
    }

    #[test]
    fn test_endpoint_permission_health_public() {
        use axum::http::Method;
        assert_eq!(endpoint_permission(&Method::GET, "/health"), None);
    }

    #[test]
    fn test_endpoint_permission_evaluate() {
        use axum::http::Method;
        assert_eq!(
            endpoint_permission(&Method::POST, "/api/evaluate"),
            Some(Permission::Evaluate)
        );
    }

    #[test]
    fn test_endpoint_permission_policies() {
        use axum::http::Method;
        assert_eq!(
            endpoint_permission(&Method::GET, "/api/policies"),
            Some(Permission::PolicyRead)
        );
        assert_eq!(
            endpoint_permission(&Method::POST, "/api/policies"),
            Some(Permission::PolicyWrite)
        );
        assert_eq!(
            endpoint_permission(&Method::POST, "/api/policies/reload"),
            Some(Permission::PolicyReload)
        );
        assert_eq!(
            endpoint_permission(&Method::DELETE, "/api/policies/abc-123"),
            Some(Permission::PolicyWrite)
        );
    }

    #[test]
    fn test_endpoint_permission_audit() {
        use axum::http::Method;
        assert_eq!(
            endpoint_permission(&Method::GET, "/api/audit/entries"),
            Some(Permission::AuditRead)
        );
        assert_eq!(
            endpoint_permission(&Method::GET, "/api/audit/export"),
            Some(Permission::AuditExport)
        );
        assert_eq!(
            endpoint_permission(&Method::POST, "/api/audit/checkpoint"),
            Some(Permission::AuditCheckpoint)
        );
    }

    #[test]
    fn test_endpoint_permission_approvals() {
        use axum::http::Method;
        assert_eq!(
            endpoint_permission(&Method::GET, "/api/approvals/pending"),
            Some(Permission::ApprovalRead)
        );
        assert_eq!(
            endpoint_permission(&Method::GET, "/api/approvals/abc-123"),
            Some(Permission::ApprovalRead)
        );
        assert_eq!(
            endpoint_permission(&Method::POST, "/api/approvals/abc-123/approve"),
            Some(Permission::ApprovalResolve)
        );
        assert_eq!(
            endpoint_permission(&Method::POST, "/api/approvals/abc-123/deny"),
            Some(Permission::ApprovalResolve)
        );
    }

    #[test]
    fn test_endpoint_permission_metrics() {
        use axum::http::Method;
        assert_eq!(
            endpoint_permission(&Method::GET, "/api/metrics"),
            Some(Permission::MetricsRead)
        );
        assert_eq!(
            endpoint_permission(&Method::GET, "/metrics"),
            Some(Permission::MetricsRead)
        );
        assert_eq!(
            endpoint_permission(&Method::GET, "/iam/scim/status"),
            Some(Permission::MetricsRead)
        );
    }

    #[test]
    fn test_endpoint_permission_cimd_fetch() {
        use axum::http::Method;
        assert_eq!(
            endpoint_permission(&Method::POST, "/api/auth/client-metadata"),
            Some(Permission::ConfigReload)
        );
    }

    #[test]
    fn test_endpoint_permission_billing_and_metering() {
        use axum::http::Method;
        assert_eq!(
            endpoint_permission(&Method::GET, "/api/billing/license"),
            Some(Permission::MetricsRead)
        );
        assert_eq!(
            endpoint_permission(&Method::GET, "/api/billing/usage/acme"),
            Some(Permission::MetricsRead)
        );
        assert_eq!(
            endpoint_permission(&Method::GET, "/api/billing/usage/acme/history"),
            Some(Permission::MetricsRead)
        );
        assert_eq!(
            endpoint_permission(&Method::GET, "/api/billing/quotas/acme"),
            Some(Permission::MetricsRead)
        );
        assert_eq!(
            endpoint_permission(&Method::POST, "/api/billing/usage/acme/reset"),
            Some(Permission::ConfigReload)
        );
    }

    #[test]
    fn test_endpoint_permission_dashboard() {
        use axum::http::Method;
        assert_eq!(
            endpoint_permission(&Method::GET, "/dashboard"),
            Some(Permission::DashboardAccess)
        );
        assert_eq!(
            endpoint_permission(&Method::POST, "/dashboard/approvals/123/approve"),
            Some(Permission::DashboardAccess)
        );
    }

    #[test]
    fn test_endpoint_permission_unknown_fails_closed() {
        use axum::http::Method;
        // Unknown endpoints require ConfigReload (admin only)
        assert_eq!(
            endpoint_permission(&Method::GET, "/api/unknown"),
            Some(Permission::ConfigReload)
        );
    }

    #[test]
    fn test_principal_require_permission() {
        let admin = Principal {
            subject: Some("admin-user".into()),
            role: Role::Admin,
            role_source: RoleSource::Jwt,
        };
        assert!(admin.require_permission(Permission::PolicyWrite).is_ok());

        let viewer = Principal {
            subject: None,
            role: Role::Viewer,
            role_source: RoleSource::Default,
        };
        assert!(viewer.require_permission(Permission::PolicyWrite).is_err());
        assert!(viewer.require_permission(Permission::PolicyRead).is_ok());
    }

    #[test]
    fn test_rbac_config_default() {
        let config = RbacConfig::default();
        assert!(!config.allow_header_role);
        assert_eq!(config.default_role, Role::Viewer);
        // Disabled by default for backwards compatibility
        assert!(!config.enabled);
    }

    #[test]
    fn test_permission_all_returns_all_variants() {
        let all = Permission::all();
        assert!(all.len() >= 14); // At least 14 permissions defined
        assert!(all.contains(&Permission::PolicyRead));
        assert!(all.contains(&Permission::Evaluate));
        assert!(all.contains(&Permission::ToolRegistryWrite));
    }

    // ────────────────────────────────
    // JWT extraction tests
    // ────────────────────────────────

    #[test]
    fn test_jwt_error_display() {
        let err = JwtError::MissingToken;
        assert_eq!(err.to_string(), "missing Authorization header");

        let err = JwtError::InvalidFormat;
        assert!(err.to_string().contains("Bearer"));

        let err = JwtError::UnsupportedAlgorithm(jsonwebtoken::Algorithm::HS256);
        assert!(err.to_string().contains("HS256"));

        let err = JwtError::AlgorithmKeyMismatch {
            algorithm: jsonwebtoken::Algorithm::RS256,
            key_type: "hmac",
        };
        assert!(err.to_string().contains("incompatible"));
    }

    #[test]
    fn test_jwt_config_default() {
        let config = JwtConfig::default();
        assert!(config.issuer.is_none());
        assert!(config.audience.is_none());
        assert_eq!(config.leeway_seconds, 60);
        assert!(config.algorithms.contains(&jsonwebtoken::Algorithm::RS256));
    }

    #[test]
    fn test_jwt_key_algorithm_compatibility_matrix() {
        use jsonwebtoken::Algorithm;

        let hmac = JwtKey::Secret("secret".into());
        assert!(hmac.supports_algorithm(Algorithm::HS256));
        assert!(!hmac.supports_algorithm(Algorithm::RS256));

        let rsa = JwtKey::RsaPublicKeyPem("pem".into());
        assert!(rsa.supports_algorithm(Algorithm::RS256));
        assert!(rsa.supports_algorithm(Algorithm::PS512));
        assert!(!rsa.supports_algorithm(Algorithm::HS256));

        let ec = JwtKey::EcPublicKeyPem("pem".into());
        assert!(ec.supports_algorithm(Algorithm::ES256));
        assert!(!ec.supports_algorithm(Algorithm::RS256));

        let ed = JwtKey::EdDsaPublicKeyPem("pem".into());
        assert!(ed.supports_algorithm(Algorithm::EdDSA));
        assert!(!ed.supports_algorithm(Algorithm::ES384));
    }

    #[test]
    fn test_extract_jwt_claims_invalid_format() {
        let config = JwtConfig {
            key: JwtKey::Secret("test-secret".into()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            ..Default::default()
        };

        // Missing Bearer prefix
        let result = extract_jwt_claims("token", &config);
        assert!(matches!(result, Err(JwtError::InvalidFormat)));

        // Empty token
        let result = extract_jwt_claims("Bearer ", &config);
        assert!(matches!(result, Err(JwtError::InvalidFormat)));
    }

    /// JWT claims with exp for testing (since jsonwebtoken validates exp by default)
    #[derive(Debug, Serialize)]
    struct TestClaims {
        sub: Option<String>,
        role: Option<String>,
        exp: u64,
    }

    #[test]
    fn test_extract_jwt_claims_with_hmac_secret() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = "test-secret-key-for-hmac-256";
        let config = JwtConfig {
            key: JwtKey::Secret(secret.into()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: None,
            leeway_seconds: 60,
        };

        // Create a valid JWT with role claim and exp in the future
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600; // 1 hour from now

        let claims = TestClaims {
            sub: Some("test-user".into()),
            role: Some("admin".into()),
            exp,
        };

        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let auth_header = format!("Bearer {}", token);
        let result = extract_jwt_claims(&auth_header, &config);
        assert!(result.is_ok(), "JWT validation failed: {:?}", result);

        let extracted = result.unwrap();
        assert_eq!(extracted.sub, Some("test-user".into()));
        assert_eq!(extracted.role, Some("admin".into()));
        assert_eq!(extracted.effective_role(), Some(Role::Admin));
    }

    #[test]
    fn test_extract_jwt_claims_algorithm_mismatch() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = "test-secret";
        let config = JwtConfig {
            key: JwtKey::Secret(secret.into()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256], // Only allow HS256
            ..Default::default()
        };

        // Create token with HS384 (not allowed)
        let claims = RoleClaims {
            sub: Some("user".into()),
            role: Some("admin".into()),
            vellaveto_role: None,
            roles: None,
            aud: None,
            nonce: None,
        };

        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS384),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let result = extract_jwt_claims(&format!("Bearer {}", token), &config);
        assert!(matches!(result, Err(JwtError::UnsupportedAlgorithm(_))));
    }

    #[test]
    fn test_extract_jwt_claims_key_algorithm_mismatch_fails_closed() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = "test-secret-key-for-hmac";
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let claims = TestClaims {
            sub: Some("user-1".into()),
            role: Some("viewer".into()),
            exp,
        };

        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let config = JwtConfig {
            // No PEM parsing should be reached because mismatch is rejected first.
            key: JwtKey::RsaPublicKeyPem("not-a-real-pem".into()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            ..Default::default()
        };

        let result = extract_jwt_claims(&format!("Bearer {}", token), &config);
        assert!(matches!(
            result,
            Err(JwtError::AlgorithmKeyMismatch {
                algorithm: jsonwebtoken::Algorithm::HS256,
                ..
            })
        ));
    }

    #[test]
    fn test_extract_jwt_claims_audience_mismatch_fails() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        #[derive(Debug, Serialize)]
        struct AudienceStringClaims {
            sub: Option<String>,
            role: Option<String>,
            exp: u64,
            aud: String,
        }

        let secret = "test-secret";
        let config = JwtConfig {
            key: JwtKey::Secret(secret.into()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: Some("vellaveto-api".into()),
            leeway_seconds: 60,
        };

        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let claims = AudienceStringClaims {
            sub: Some("user-1".into()),
            role: Some("viewer".into()),
            exp,
            aud: "other-audience".into(),
        };

        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let result = extract_jwt_claims(&format!("Bearer {}", token), &config);
        assert!(matches!(result, Err(JwtError::ValidationFailed(_))));
    }

    #[test]
    fn test_extract_jwt_claims_missing_audience_fails_when_required() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = "test-secret";
        let config = JwtConfig {
            key: JwtKey::Secret(secret.into()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: Some("vellaveto-api".into()),
            leeway_seconds: 60,
        };

        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let claims = TestClaims {
            sub: Some("user-1".into()),
            role: Some("viewer".into()),
            exp,
        };

        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let result = extract_jwt_claims(&format!("Bearer {}", token), &config);
        assert!(matches!(result, Err(JwtError::ValidationFailed(_))));
    }

    #[test]
    fn test_extract_jwt_claims_audience_array_with_expected_succeeds() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        #[derive(Debug, Serialize)]
        struct AudienceArrayClaims {
            sub: Option<String>,
            role: Option<String>,
            exp: u64,
            aud: Vec<String>,
        }

        let secret = "test-secret";
        let config = JwtConfig {
            key: JwtKey::Secret(secret.into()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: Some("vellaveto-api".into()),
            leeway_seconds: 60,
        };

        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let claims = AudienceArrayClaims {
            sub: Some("user-1".into()),
            role: Some("operator".into()),
            exp,
            aud: vec!["other".into(), "vellaveto-api".into()],
        };

        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let result = extract_jwt_claims(&format!("Bearer {}", token), &config);
        assert!(
            result.is_ok(),
            "JWT audience array should validate: {:?}",
            result
        );
    }

    #[test]
    fn test_extract_principal_from_request_jwt() {
        use axum::http::{header, HeaderMap, HeaderValue};
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = "test-secret";
        let config = RbacConfig {
            enabled: true,
            allow_header_role: false,
            default_role: Role::Viewer,
            jwt_config: Some(JwtConfig {
                key: JwtKey::Secret(secret.into()),
                algorithms: vec![jsonwebtoken::Algorithm::HS256],
                ..Default::default()
            }),
        };

        // Create valid JWT with operator role (include exp for validation)
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let claims = TestClaims {
            sub: Some("operator-user".into()),
            role: Some("operator".into()),
            exp,
        };

        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        );

        let principal = extract_principal_from_request(&headers, &config)
            .expect("valid JWT should extract principal");
        assert_eq!(principal.role, Role::Operator);
        assert_eq!(principal.role_source, RoleSource::Jwt);
        assert_eq!(principal.subject, Some("operator-user".into()));
    }

    #[test]
    fn test_extract_principal_fallback_to_header() {
        use axum::http::{HeaderMap, HeaderName, HeaderValue};

        let config = RbacConfig {
            enabled: true,
            allow_header_role: true,
            default_role: Role::Viewer,
            jwt_config: None, // No JWT config
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-vellaveto-role"),
            HeaderValue::from_static("auditor"),
        );

        let principal = extract_principal_from_request(&headers, &config)
            .expect("header role should extract principal");
        assert_eq!(principal.role, Role::Auditor);
        assert_eq!(principal.role_source, RoleSource::Header);
    }

    #[test]
    fn test_extract_principal_fallback_to_default() {
        use axum::http::HeaderMap;

        let config = RbacConfig {
            enabled: true,
            allow_header_role: false,
            default_role: Role::Viewer,
            jwt_config: None,
        };

        let headers = HeaderMap::new();
        let principal = extract_principal_from_request(&headers, &config)
            .expect("missing auth should fall back to default role");
        assert_eq!(principal.role, Role::Viewer);
        assert_eq!(principal.role_source, RoleSource::Default);
    }

    #[test]
    fn test_extract_principal_rejects_invalid_jwt_when_auth_header_present() {
        use axum::http::{header, HeaderMap, HeaderValue};

        let config = RbacConfig {
            enabled: true,
            allow_header_role: true,
            default_role: Role::Viewer,
            jwt_config: Some(JwtConfig {
                key: JwtKey::Secret("test-secret".into()),
                algorithms: vec![jsonwebtoken::Algorithm::HS256],
                ..Default::default()
            }),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer not-a-jwt"),
        );
        headers.insert(
            axum::http::HeaderName::from_static("x-vellaveto-role"),
            HeaderValue::from_static("admin"),
        );

        let err = extract_principal_from_request(&headers, &config)
            .expect_err("invalid JWT must not fall back to header role");
        assert!(matches!(err, JwtError::ValidationFailed(_)));
    }

    #[test]
    fn test_rbac_config_with_jwt() {
        let config = RbacConfig {
            enabled: true,
            allow_header_role: false,
            default_role: Role::Viewer,
            jwt_config: Some(JwtConfig::default()),
        };
        assert!(config.jwt_config.is_some());
    }
}
