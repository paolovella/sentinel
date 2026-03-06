// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

use crate::default_true;
use serde::{Deserialize, Serialize};
use vellaveto_types::has_dangerous_chars;

const MAX_OIDC_URL_LEN: usize = 512;
const MAX_OIDC_CLIENT_ID_LEN: usize = 128;
const MAX_OIDC_SECRET_LEN: usize = 512;
const MAX_OIDC_SCOPE_LEN: usize = 64;
const MAX_OIDC_SCOPES: usize = 16;

const MAX_SAML_URL_LEN: usize = 512;
const MAX_SAML_FIELD_LEN: usize = 256;

const MAX_COOKIE_NAME_LEN: usize = 64;
const MIN_SESSION_TIMEOUT_SECS: u64 = 60;
const MAX_SESSION_TIMEOUT_SECS: u64 = 86_400;
const MAX_SESSIONS_PER_PRINCIPAL: u32 = 100;

const MIN_SCIM_SYNC_SECS: u64 = 60;
const MAX_SCIM_SYNC_SECS: u64 = 86_400;

/// Maximum number of M2M clients that can be configured.
const MAX_M2M_CLIENTS: usize = 100;
/// Maximum length for an M2M client_id.
const MAX_M2M_CLIENT_ID_LEN: usize = 128;
/// Maximum length for an M2M client_secret_hash (Argon2 hashes are ~97 chars).
const MAX_M2M_SECRET_HASH_LEN: usize = 256;
/// Maximum length for an M2M role string.
const MAX_M2M_ROLE_LEN: usize = 64;
/// Maximum number of allowed scopes per M2M client.
const MAX_M2M_SCOPES_PER_CLIENT: usize = 32;
/// Minimum M2M token TTL in seconds (30 seconds).
const MIN_M2M_TOKEN_TTL_SECS: u64 = 30;
/// Maximum M2M token TTL in seconds (1 hour).
const MAX_M2M_TOKEN_TTL_SECS: u64 = 3_600;
/// Default M2M token TTL in seconds (5 minutes).
const DEFAULT_M2M_TOKEN_TTL_SECS: u64 = 300;
/// Maximum length for the M2M issuer string.
const MAX_M2M_ISSUER_LEN: usize = 256;

fn default_oidc_role_claim() -> String {
    "vellaveto_role".to_string()
}

fn default_oidc_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ]
}

fn default_jwks_cache_secs() -> u64 {
    300
}

fn default_session_cookie_name() -> String {
    "vellaveto_session".to_string()
}

fn default_session_idle_timeout() -> u64 {
    3_600
}

fn default_session_max_age() -> u64 {
    3_600
}

fn default_max_sessions_per_principal() -> u32 {
    10
}

fn default_scim_sync_interval() -> u64 {
    3_600
}

fn default_m2m_token_ttl_secs() -> u64 {
    DEFAULT_M2M_TOKEN_TTL_SECS
}

fn ensure_safe_str(field: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{} must not be empty", field));
    }
    if value.len() > max_len {
        return Err(format!(
            "{} length {} exceeds max {}",
            field,
            value.len(),
            max_len
        ));
    }
    if has_dangerous_chars(value) {
        return Err(format!(
            "{} contains control or Unicode format characters",
            field
        ));
    }
    Ok(())
}

fn ensure_env_var(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{} must not be empty", field));
    }
    if has_dangerous_chars(value) {
        return Err(format!(
            "{} contains control or Unicode format characters",
            field
        ));
    }
    Ok(())
}

/// Enterprise IAM configuration covering OIDC, SAML, session, SCIM, and M2M plumbing.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IamConfig {
    /// Globally enable IAM integration.
    #[serde(default)]
    pub enabled: bool,

    /// OpenID Connect provider configuration.
    #[serde(default)]
    pub oidc: OidcConfig,

    /// SAML 2.0 service provider configuration.
    #[serde(default)]
    pub saml: SamlConfig,

    /// Session management controls (secure cookies, timeouts, session caps).
    #[serde(default)]
    pub session: SessionConfig,

    /// SCIM provisioning integration configuration.
    #[serde(default)]
    pub scim: ScimConfig,

    /// Machine-to-machine (OAuth client credentials) configuration.
    #[serde(default)]
    pub m2m: M2mConfig,
}

impl IamConfig {
    /// Validate IAM configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        self.oidc.validate()?;
        self.saml.validate()?;
        self.session.validate()?;
        self.scim.validate()?;
        self.m2m.validate()?;

        if self.enabled && !self.oidc.enabled && !self.saml.enabled && !self.m2m.enabled {
            return Err(
                "iam.enabled is true but none of oidc.enabled, saml.enabled, or m2m.enabled is configured"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// OpenID Connect provider configuration.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_url: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,

    #[serde(default = "default_oidc_role_claim")]
    pub role_claim: String,

    #[serde(default)]
    pub allow_insecure_issuer: bool,

    #[serde(default)]
    pub pkce: bool,

    #[serde(default = "default_jwks_cache_secs")]
    pub jwks_cache_secs: u64,
}

/// SECURITY (FIND-038): Custom Debug redacts client_secret to prevent
/// leaking OIDC credential material in log output.
impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("enabled", &self.enabled)
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .field("role_claim", &self.role_claim)
            .field("allow_insecure_issuer", &self.allow_insecure_issuer)
            .field("pkce", &self.pkce)
            .field("jwks_cache_secs", &self.jwks_cache_secs)
            .finish()
    }
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer_url: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scopes: default_oidc_scopes(),
            role_claim: default_oidc_role_claim(),
            allow_insecure_issuer: false,
            pkce: true,
            jwks_cache_secs: default_jwks_cache_secs(),
        }
    }
}

impl OidcConfig {
    fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let issuer = self.issuer_url.as_ref().ok_or_else(|| {
            "iam.oidc.issuer_url is required when oidc.enabled is true".to_string()
        })?;
        ensure_safe_str("iam.oidc.issuer_url", issuer, MAX_OIDC_URL_LEN)?;
        // R231-CFG-3: Enforce https:// scheme at config validation (defense-in-depth).
        // Runtime also checks in OidcDiscovery::fetch(), but fail-closed demands
        // rejection at load time so admins discover misconfig before first request.
        if !self.allow_insecure_issuer && !issuer.starts_with("https://") {
            return Err(
                "iam.oidc.issuer_url must use https:// scheme (set allow_insecure_issuer=true for testing)".to_string()
            );
        }

        let client_id = self.client_id.as_ref().ok_or_else(|| {
            "iam.oidc.client_id is required when oidc.enabled is true".to_string()
        })?;
        ensure_safe_str("iam.oidc.client_id", client_id, MAX_OIDC_CLIENT_ID_LEN)?;

        if let Some(client_secret) = &self.client_secret {
            ensure_safe_str("iam.oidc.client_secret", client_secret, MAX_OIDC_SECRET_LEN)?;
        } else if !self.pkce {
            return Err("iam.oidc.client_secret is required when PKCE is disabled".to_string());
        }

        let redirect = self.redirect_uri.as_ref().ok_or_else(|| {
            "iam.oidc.redirect_uri is required when oidc.enabled is true".to_string()
        })?;
        ensure_safe_str("iam.oidc.redirect_uri", redirect, MAX_OIDC_URL_LEN)?;

        if self.scopes.is_empty() {
            return Err("iam.oidc.scopes must contain at least one scope".to_string());
        }
        if self.scopes.len() > MAX_OIDC_SCOPES {
            return Err(format!(
                "iam.oidc.scopes length {} exceeds max {}",
                self.scopes.len(),
                MAX_OIDC_SCOPES
            ));
        }
        for (i, scope) in self.scopes.iter().enumerate() {
            if scope.len() > MAX_OIDC_SCOPE_LEN {
                return Err(format!(
                    "iam.oidc.scopes[{}] length {} exceeds max {}",
                    i,
                    scope.len(),
                    MAX_OIDC_SCOPE_LEN
                ));
            }
            ensure_safe_str(
                &format!("iam.oidc.scopes[{}]", i),
                scope,
                MAX_OIDC_SCOPE_LEN,
            )?;
        }

        ensure_safe_str("iam.oidc.role_claim", &self.role_claim, MAX_SAML_FIELD_LEN)?;

        if self.jwks_cache_secs == 0 {
            return Err("iam.oidc.jwks_cache_secs must be greater than 0".to_string());
        }

        Ok(())
    }
}

/// SAML 2.0 service provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SamlConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acs_url: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idp_metadata_url: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_attribute: Option<String>,
}

impl Default for SamlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            entity_id: None,
            acs_url: None,
            idp_metadata_url: None,
            role_attribute: Some("Role".to_string()),
        }
    }
}

impl SamlConfig {
    fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let entity_id = self.entity_id.as_ref().ok_or_else(|| {
            "iam.saml.entity_id is required when saml.enabled is true".to_string()
        })?;
        ensure_safe_str("iam.saml.entity_id", entity_id, MAX_SAML_FIELD_LEN)?;

        let acs = self
            .acs_url
            .as_ref()
            .ok_or_else(|| "iam.saml.acs_url is required when saml.enabled is true".to_string())?;
        ensure_safe_str("iam.saml.acs_url", acs, MAX_SAML_URL_LEN)?;

        let metadata = self.idp_metadata_url.as_ref().ok_or_else(|| {
            "iam.saml.idp_metadata_url is required when saml.enabled is true".to_string()
        })?;
        ensure_safe_str("iam.saml.idp_metadata_url", metadata, MAX_SAML_URL_LEN)?;

        if let Some(role_attr) = &self.role_attribute {
            ensure_safe_str("iam.saml.role_attribute", role_attr, MAX_SAML_FIELD_LEN)?;
        }

        Ok(())
    }
}

/// Session configuration for IAM sessions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    #[serde(default = "default_session_cookie_name")]
    pub cookie_name: String,

    #[serde(default = "default_true")]
    pub secure_cookie: bool,

    #[serde(default = "default_true")]
    pub http_only: bool,

    #[serde(default = "default_session_idle_timeout")]
    pub idle_timeout_secs: u64,

    #[serde(default = "default_session_max_age")]
    pub max_age_secs: u64,

    #[serde(default = "default_max_sessions_per_principal")]
    pub max_sessions_per_principal: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: default_session_cookie_name(),
            secure_cookie: true,
            http_only: true,
            idle_timeout_secs: default_session_idle_timeout(),
            max_age_secs: default_session_max_age(),
            max_sessions_per_principal: default_max_sessions_per_principal(),
        }
    }
}

impl SessionConfig {
    fn validate(&self) -> Result<(), String> {
        ensure_safe_str(
            "iam.session.cookie_name",
            &self.cookie_name,
            MAX_COOKIE_NAME_LEN,
        )?;

        if self.idle_timeout_secs < MIN_SESSION_TIMEOUT_SECS
            || self.idle_timeout_secs > MAX_SESSION_TIMEOUT_SECS
        {
            return Err(format!(
                "iam.session.idle_timeout_secs must be between {} and {}",
                MIN_SESSION_TIMEOUT_SECS, MAX_SESSION_TIMEOUT_SECS
            ));
        }
        if self.max_age_secs < MIN_SESSION_TIMEOUT_SECS
            || self.max_age_secs > MAX_SESSION_TIMEOUT_SECS
        {
            return Err(format!(
                "iam.session.max_age_secs must be between {} and {}",
                MIN_SESSION_TIMEOUT_SECS, MAX_SESSION_TIMEOUT_SECS
            ));
        }
        if self.max_sessions_per_principal == 0
            || self.max_sessions_per_principal > MAX_SESSIONS_PER_PRINCIPAL
        {
            return Err(format!(
                "iam.session.max_sessions_per_principal must be between 1 and {}",
                MAX_SESSIONS_PER_PRINCIPAL
            ));
        }
        Ok(())
    }
}

/// SCIM provisioning configuration.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScimConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token_env: Option<String>,

    #[serde(default = "default_scim_sync_interval")]
    pub sync_interval_secs: u64,
}

/// SECURITY (FIND-039): Custom Debug redacts bearer_token to prevent
/// leaking SCIM credential material in log output.
impl std::fmt::Debug for ScimConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScimConfig")
            .field("enabled", &self.enabled)
            .field("endpoint", &self.endpoint)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("bearer_token_env", &self.bearer_token_env)
            .field("sync_interval_secs", &self.sync_interval_secs)
            .finish()
    }
}

impl Default for ScimConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            bearer_token: None,
            bearer_token_env: None,
            sync_interval_secs: default_scim_sync_interval(),
        }
    }
}

impl ScimConfig {
    fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| "iam.scim.endpoint is required when scim.enabled is true".to_string())?;
        ensure_safe_str("iam.scim.endpoint", endpoint, MAX_OIDC_URL_LEN)?;

        if self.bearer_token.is_none() && self.bearer_token_env.is_none() {
            return Err(
                "iam.scim.bearer_token or iam.scim.bearer_token_env is required when scim.enabled is true".to_string(),
            );
        }
        if let Some(token) = &self.bearer_token {
            ensure_safe_str("iam.scim.bearer_token", token, MAX_OIDC_SECRET_LEN)?;
        }
        if let Some(env) = &self.bearer_token_env {
            ensure_env_var("iam.scim.bearer_token_env", env)?;
        }

        if self.sync_interval_secs < MIN_SCIM_SYNC_SECS
            || self.sync_interval_secs > MAX_SCIM_SYNC_SECS
        {
            return Err(format!(
                "iam.scim.sync_interval_secs must be between {} and {}",
                MIN_SCIM_SYNC_SECS, MAX_SCIM_SYNC_SECS
            ));
        }

        Ok(())
    }
}

/// Machine-to-machine (M2M) OAuth client credentials configuration.
///
/// When enabled, service accounts can authenticate using the client credentials
/// grant flow (RFC 6749 Section 4.4) without interactive login. The server
/// generates short-lived JWTs with scopes mapped to RBAC roles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct M2mConfig {
    /// Enable M2M client credentials authentication.
    #[serde(default)]
    pub enabled: bool,

    /// Registered M2M clients.
    #[serde(default)]
    pub clients: Vec<M2mClient>,

    /// Token time-to-live in seconds. Default 300 (5 minutes).
    #[serde(default = "default_m2m_token_ttl_secs")]
    pub token_ttl_secs: u64,

    /// Issuer value for M2M-issued JWTs. Defaults to "vellaveto".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

impl Default for M2mConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            clients: Vec::new(),
            token_ttl_secs: default_m2m_token_ttl_secs(),
            issuer: None,
        }
    }
}

impl M2mConfig {
    /// Validate M2M configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        if self.clients.is_empty() {
            return Err(
                "iam.m2m.clients must contain at least one client when m2m.enabled is true"
                    .to_string(),
            );
        }
        if self.clients.len() > MAX_M2M_CLIENTS {
            return Err(format!(
                "iam.m2m.clients count {} exceeds max {}",
                self.clients.len(),
                MAX_M2M_CLIENTS
            ));
        }

        if self.token_ttl_secs < MIN_M2M_TOKEN_TTL_SECS
            || self.token_ttl_secs > MAX_M2M_TOKEN_TTL_SECS
        {
            return Err(format!(
                "iam.m2m.token_ttl_secs must be between {} and {}",
                MIN_M2M_TOKEN_TTL_SECS, MAX_M2M_TOKEN_TTL_SECS
            ));
        }

        if let Some(ref issuer) = self.issuer {
            ensure_safe_str("iam.m2m.issuer", issuer, MAX_M2M_ISSUER_LEN)?;
        }

        let mut seen_ids = std::collections::HashSet::new();
        for (i, client) in self.clients.iter().enumerate() {
            client.validate(i)?;
            if !seen_ids.insert(&client.client_id) {
                return Err(format!(
                    "iam.m2m.clients[{}].client_id '{}' is duplicated",
                    i, client.client_id
                ));
            }
        }

        Ok(())
    }
}

/// A single M2M client registration.
///
/// SECURITY: The `client_secret_hash` stores an Argon2id hash of the client
/// secret. The plaintext secret is never stored in configuration. The custom
/// `Debug` implementation redacts the hash to prevent leaking it in logs.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct M2mClient {
    /// Unique client identifier (e.g., "ci-pipeline", "monitoring-agent").
    pub client_id: String,

    /// Argon2id hash of the client secret. Never store plaintext.
    pub client_secret_hash: String,

    /// RBAC role assigned to this client (e.g., "operator", "viewer").
    pub role: String,

    /// Scopes this client is permitted to request.
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
}

/// SECURITY: Custom Debug redacts the secret hash to prevent leaking
/// credential material in log output.
impl std::fmt::Debug for M2mClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("M2mClient")
            .field("client_id", &self.client_id)
            .field("client_secret_hash", &"[REDACTED]")
            .field("role", &self.role)
            .field("allowed_scopes", &self.allowed_scopes)
            .finish()
    }
}

impl M2mClient {
    fn validate(&self, index: usize) -> Result<(), String> {
        let prefix = format!("iam.m2m.clients[{}]", index);

        ensure_safe_str(
            &format!("{}.client_id", prefix),
            &self.client_id,
            MAX_M2M_CLIENT_ID_LEN,
        )?;

        if self.client_secret_hash.is_empty() {
            return Err(format!("{}.client_secret_hash must not be empty", prefix));
        }
        if self.client_secret_hash.len() > MAX_M2M_SECRET_HASH_LEN {
            return Err(format!(
                "{}.client_secret_hash length {} exceeds max {}",
                prefix,
                self.client_secret_hash.len(),
                MAX_M2M_SECRET_HASH_LEN
            ));
        }

        ensure_safe_str(&format!("{}.role", prefix), &self.role, MAX_M2M_ROLE_LEN)?;

        if self.allowed_scopes.len() > MAX_M2M_SCOPES_PER_CLIENT {
            return Err(format!(
                "{}.allowed_scopes count {} exceeds max {}",
                prefix,
                self.allowed_scopes.len(),
                MAX_M2M_SCOPES_PER_CLIENT
            ));
        }
        for (j, scope) in self.allowed_scopes.iter().enumerate() {
            ensure_safe_str(
                &format!("{}.allowed_scopes[{}]", prefix, j),
                scope,
                MAX_OIDC_SCOPE_LEN,
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_config_debug_redacts_client_secret() {
        let config = OidcConfig {
            client_secret: Some("super-secret-value-12345".to_string()),
            ..Default::default()
        };
        let debug_output = format!("{:?}", config);
        assert!(
            !debug_output.contains("super-secret-value-12345"),
            "client_secret leaked in Debug output: {}",
            debug_output
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output missing [REDACTED]: {}",
            debug_output
        );
    }

    #[test]
    fn test_oidc_config_debug_none_secret() {
        let config = OidcConfig::default();
        let debug_output = format!("{:?}", config);
        assert!(
            debug_output.contains("None"),
            "Debug output should show None for absent client_secret: {}",
            debug_output
        );
    }

    #[test]
    fn test_scim_config_debug_redacts_bearer_token() {
        let config = ScimConfig {
            bearer_token: Some("Bearer my-secret-token-xyz".to_string()),
            ..Default::default()
        };
        let debug_output = format!("{:?}", config);
        assert!(
            !debug_output.contains("my-secret-token-xyz"),
            "bearer_token leaked in Debug output: {}",
            debug_output
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output missing [REDACTED]: {}",
            debug_output
        );
    }

    #[test]
    fn test_scim_config_debug_none_token() {
        let config = ScimConfig::default();
        let debug_output = format!("{:?}", config);
        assert!(
            debug_output.contains("None"),
            "Debug output should show None for absent bearer_token: {}",
            debug_output
        );
    }

    // R231-CFG-3: OIDC issuer_url scheme enforcement
    #[test]
    fn test_oidc_http_issuer_rejected_by_default() {
        let config = OidcConfig {
            enabled: true,
            issuer_url: Some("http://example.com".to_string()),
            client_id: Some("client-id".to_string()),
            client_secret: Some("secret".to_string()),
            redirect_uri: Some("https://app.example.com/callback".to_string()),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err(), "http:// issuer should be rejected");
        assert!(
            result.unwrap_err().contains("https://"),
            "Error should mention https:// requirement"
        );
    }

    #[test]
    fn test_oidc_https_issuer_accepted() {
        let config = OidcConfig {
            enabled: true,
            issuer_url: Some("https://example.com".to_string()),
            client_id: Some("client-id".to_string()),
            client_secret: Some("secret".to_string()),
            redirect_uri: Some("https://app.example.com/callback".to_string()),
            ..Default::default()
        };
        let result = config.validate();
        assert!(
            result.is_ok(),
            "https:// issuer should be accepted: {:?}",
            result
        );
    }

    #[test]
    fn test_oidc_http_issuer_allowed_when_insecure_flag() {
        let config = OidcConfig {
            enabled: true,
            issuer_url: Some("http://localhost:8080".to_string()),
            client_id: Some("client-id".to_string()),
            client_secret: Some("secret".to_string()),
            redirect_uri: Some("https://app.example.com/callback".to_string()),
            allow_insecure_issuer: true,
            ..Default::default()
        };
        let result = config.validate();
        assert!(
            result.is_ok(),
            "http:// issuer should be allowed with allow_insecure_issuer=true: {:?}",
            result
        );
    }
}
