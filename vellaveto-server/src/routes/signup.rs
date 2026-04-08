// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

// ═══════════════════════════════════════════════════════════════════════════════
// SELF-SERVICE SIGNUP — Marketplace Onboarding (Phase 53)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Provides self-service tenant provisioning for marketplace customers.
// Creates a tenant, generates an API key, and returns onboarding details.
//
// SECURITY:
// - Rate-limited to prevent abuse (shared with unauthenticated rate limiter)
// - Input validated: org name, email, plan tier
// - API key generated with cryptographic randomness (OsRng)
// - No secrets logged
// - Email validated with basic RFC 5321 checks (no MX lookup)
// - Org name max 200 chars, reject control/format characters

use axum::{extract::State, http::StatusCode, Json};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::routes::ErrorResponse;
use crate::AppState;

/// Maximum organization name length.
const MAX_ORG_NAME_LEN: usize = 200;

/// Maximum email length (RFC 5321: 254 octets).
const MAX_EMAIL_LEN: usize = 254;

/// Maximum plan tier length.
const MAX_PLAN_TIER_LEN: usize = 64;

/// Maximum number of tenants before rejecting new signups.
const MAX_TOTAL_TENANTS: usize = 10_000;

/// API key prefix for marketplace-issued keys.
const API_KEY_PREFIX: &str = "vvt_";

/// Length of the random portion of the API key (32 bytes = 64 hex chars).
const API_KEY_RANDOM_LEN: usize = 32;

/// Allowed plan tiers for self-service signup.
const ALLOWED_TIERS: &[&str] = &["free", "starter", "team", "enterprise-trial"];

/// Self-service signup request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignupRequest {
    /// Organization name (required, max 200 chars).
    pub org_name: String,
    /// Contact email (required, max 254 chars).
    pub email: String,
    /// Plan tier: free, starter, team, enterprise-trial.
    #[serde(default = "default_tier")]
    pub plan: String,
}

fn default_tier() -> String {
    "free".to_string()
}

/// Self-service signup response.
#[derive(Serialize)]
pub struct SignupResponse {
    /// Created tenant ID.
    pub tenant_id: String,
    /// Generated API key (shown once — not retrievable later).
    pub api_key: String,
    /// Plan tier.
    pub plan: String,
    /// Server URL for SDK configuration.
    pub server_url: String,
    /// Onboarding instructions.
    pub next_steps: Vec<String>,
}

// SECURITY (FIND-GAP-001): Custom Debug redacts api_key to prevent log leakage.
impl std::fmt::Debug for SignupResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupResponse")
            .field("tenant_id", &self.tenant_id)
            .field("api_key", &"[REDACTED]")
            .field("plan", &self.plan)
            .field("server_url", &self.server_url)
            .field("next_steps", &self.next_steps)
            .finish()
    }
}

/// `POST /api/signup`
///
/// Self-service tenant provisioning. Creates a tenant with the specified plan
/// tier and returns a fresh API key. The API key is shown once and cannot be
/// retrieved later.
///
/// This endpoint is rate-limited and does not require authentication
/// (it creates the credentials).
pub async fn signup(
    State(state): State<AppState>,
    Json(req): Json<SignupRequest>,
) -> Result<(StatusCode, Json<SignupResponse>), (StatusCode, Json<ErrorResponse>)> {
    // ─── Validate org_name ──────────────────────────────────────────────
    let org_name = req.org_name.trim();
    if org_name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "org_name is required".to_string(),
            }),
        ));
    }
    if org_name.len() > MAX_ORG_NAME_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("org_name exceeds {MAX_ORG_NAME_LEN} character limit"),
            }),
        ));
    }
    if org_name.chars().any(crate::routes::is_unsafe_char) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "org_name contains invalid characters".to_string(),
            }),
        ));
    }

    // ─── Validate email ─────────────────────────────────────────────────
    let email = req.email.trim();
    if email.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "email is required".to_string(),
            }),
        ));
    }
    if email.len() > MAX_EMAIL_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "email exceeds maximum length".to_string(),
            }),
        ));
    }
    // SECURITY (R231-SRV-8): Use is_unsafe_char (control + Unicode format chars)
    // consistent with org_name validation. Prevents invisible Unicode characters
    // in email addresses that create confusable identities.
    if email.chars().any(crate::routes::is_unsafe_char) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "email contains invalid characters".to_string(),
            }),
        ));
    }
    if !is_valid_email_format(email) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid email format".to_string(),
            }),
        ));
    }

    // ─── Validate plan tier ─────────────────────────────────────────────
    let plan = req.plan.trim().to_lowercase();
    if plan.len() > MAX_PLAN_TIER_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "plan tier exceeds maximum length".to_string(),
            }),
        ));
    }
    if !ALLOWED_TIERS.contains(&plan.as_str()) {
        // SECURITY (R243-SRV-3): Do not enumerate valid tiers to clients.
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid plan tier".to_string(),
            }),
        ));
    }

    // ─── Check capacity (atomic with creation) ───────────────────────────
    // SECURITY: Acquire signup mutex so capacity check + tenant creation is
    // atomic. Without this, N concurrent requests could all pass the check
    // and exceed MAX_TOTAL_TENANTS (TOCTOU race).
    let _signup_guard = state.signup_lock.lock().await;

    let tenant_count = state
        .tenant_store
        .as_ref()
        .map(|s| s.list_tenants().len())
        .unwrap_or(0);
    if tenant_count >= MAX_TOTAL_TENANTS {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "maximum tenant capacity reached".to_string(),
            }),
        ));
    }

    // ─── Generate tenant ID ─────────────────────────────────────────────
    let tenant_id = generate_tenant_id(org_name);

    // ─── Generate API key ───────────────────────────────────────────────
    let api_key = generate_api_key();

    // ─── Create tenant via store ────────────────────────────────────────
    let store = state.tenant_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(ErrorResponse {
                error: "Tenant store not configured — enable multi-tenancy to use signup"
                    .to_string(),
            }),
        )
    })?;

    // SECURITY (R230-SRV-1): Store API key hash in tenant metadata so the key
    // can be verified for per-tenant authentication. Without this, the returned
    // key is unverifiable and effectively useless.
    let api_key_hash = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(api_key.as_bytes());
        hex::encode(hash)
    };

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("email".to_string(), email.to_string());
    metadata.insert("plan".to_string(), plan.clone());
    metadata.insert("source".to_string(), "self-service-signup".to_string());
    metadata.insert("api_key_hash".to_string(), api_key_hash);

    let now = chrono::Utc::now().to_rfc3339();

    let tenant = crate::tenant::Tenant {
        id: tenant_id.clone(),
        name: org_name.to_string(),
        enabled: true,
        quotas: tier_to_quotas(&plan),
        metadata,
        created_at: Some(now.clone()),
        updated_at: None,
    };

    store.create_tenant(tenant).map_err(|e| {
        tracing::warn!(error = %e, "Signup tenant creation failed");
        // create_tenant returns InvalidTenantId for duplicates.
        let msg = e.to_string();
        if msg.contains("already exists") {
            (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "Organization already registered".to_string(),
                }),
            )
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to create tenant".to_string(),
                }),
            )
        }
    })?;

    // Log signup event (no secrets).
    tracing::info!(
        tenant_id = %tenant_id,
        plan = %plan,
        "Self-service signup completed"
    );

    // Use VELLAVETO_PUBLIC_URL env var if set, otherwise default.
    let server_url = std::env::var("VELLAVETO_PUBLIC_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());

    let next_steps = vec![
        "1. Install an SDK: pip install vellaveto / npm install @vellaveto/sdk / go get github.com/paolovella/sdk".to_string(),
        format!(
            "2. Configure: VELLAVETO_URL={} VELLAVETO_API_KEY=<your-key> VELLAVETO_TENANT_ID={}",
            server_url, tenant_id
        ),
        "3. Create a policy config — see examples/presets/ for templates".to_string(),
        "4. Start the proxy: vellaveto serve --config your-policy.toml".to_string(),
        "5. Open the Admin Console at /dashboard to manage policies".to_string(),
    ];

    Ok((
        StatusCode::CREATED,
        Json(SignupResponse {
            tenant_id,
            api_key,
            plan,
            server_url,
            next_steps,
        }),
    ))
}

/// Generate a tenant ID from the org name.
///
/// Slugifies the org name (lowercase, alphanumeric + hyphens, max 40 chars)
/// and appends a random suffix to avoid collisions.
fn generate_tenant_id(org_name: &str) -> String {
    let slug: String = org_name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string();

    // Truncate slug to leave room for suffix.
    let max_slug = 32;
    let truncated = if slug.len() > max_slug {
        &slug[..max_slug]
    } else {
        &slug
    };
    let truncated = truncated.trim_end_matches('-');

    // SECURITY (R230-SRV-2): 16-char random hex suffix (64-bit entropy).
    // Previously 6-char (24-bit) which gave ~50% collision at ~4096 signups
    // with the same slug. 64-bit gives collision resistance past 2^32 signups.
    let mut suffix = [0u8; 8];
    rand::rng().fill_bytes(&mut suffix);
    let hex_suffix = hex::encode(suffix);

    format!("{truncated}-{hex_suffix}")
}

/// Generate a cryptographically random API key.
fn generate_api_key() -> String {
    let mut bytes = [0u8; API_KEY_RANDOM_LEN];
    rand::rng().fill_bytes(&mut bytes);
    format!("{}{}", API_KEY_PREFIX, hex::encode(bytes))
}

/// Basic email format validation (RFC 5321 simplified).
///
/// Checks: exactly one `@`, non-empty local part, domain has at least one `.`,
/// no spaces, no consecutive dots.
fn is_valid_email_format(email: &str) -> bool {
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 {
        return false;
    }
    let local = parts[0];
    let domain = parts[1];

    if local.is_empty() || domain.is_empty() {
        return false;
    }
    if local.len() > 64 || domain.len() > 253 {
        return false;
    }
    if email.contains(' ') || email.contains("..") {
        return false;
    }
    // Domain must have at least one dot (e.g., example.com).
    if !domain.contains('.') {
        return false;
    }
    // Domain must not start or end with a dot.
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }

    // R262-SRV-1: Reject control characters, angle brackets, and other characters
    // that could enable log injection or header injection in confirmation emails.
    if email
        .chars()
        .any(|c| c.is_control() || matches!(c, '<' | '>' | '"' | '\'' | '\\' | '`'))
    {
        return false;
    }

    true
}

/// Map plan tier to tenant quotas.
fn tier_to_quotas(plan: &str) -> crate::tenant::TenantQuotas {
    match plan {
        "free" => crate::tenant::TenantQuotas {
            max_policies: 10,
            max_evaluations_per_minute: 20, // ~1,200/hour
            max_pending_approvals: 5,
            max_audit_retention_days: 7,
            max_request_body_bytes: 512 * 1024, // 512 KB
        },
        "starter" => crate::tenant::TenantQuotas {
            max_policies: 50,
            max_evaluations_per_minute: 1000, // ~60K/hour
            max_pending_approvals: 50,
            max_audit_retention_days: 30,
            max_request_body_bytes: 1024 * 1024, // 1 MB
        },
        "team" => crate::tenant::TenantQuotas {
            max_policies: 200,
            max_evaluations_per_minute: 5000, // ~300K/hour
            max_pending_approvals: 100,
            max_audit_retention_days: 90,
            max_request_body_bytes: 1024 * 1024, // 1 MB
        },
        "enterprise-trial" => crate::tenant::TenantQuotas {
            max_policies: 500,
            max_evaluations_per_minute: 10000, // ~600K/hour
            max_pending_approvals: 100,
            max_audit_retention_days: 365,
            max_request_body_bytes: 1024 * 1024, // 1 MB
        },
        _ => crate::tenant::TenantQuotas::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_valid() {
        assert!(is_valid_email_format("user@example.com"));
        assert!(is_valid_email_format("a@b.co"));
        assert!(is_valid_email_format("user+tag@example.org"));
        assert!(is_valid_email_format("user.name@sub.domain.com"));
    }

    #[test]
    fn test_email_invalid() {
        assert!(!is_valid_email_format(""));
        assert!(!is_valid_email_format("user"));
        assert!(!is_valid_email_format("@example.com"));
        assert!(!is_valid_email_format("user@"));
        assert!(!is_valid_email_format("user@localhost"));
        assert!(!is_valid_email_format("user @example.com"));
        assert!(!is_valid_email_format("user@.com"));
        assert!(!is_valid_email_format("user@example."));
        assert!(!is_valid_email_format("user@exam..ple.com"));
    }

    // R262-SRV-1: Reject injection characters in email
    #[test]
    fn test_email_rejects_injection_chars() {
        assert!(!is_valid_email_format("test<script>@example.com"));
        assert!(!is_valid_email_format("test>@example.com"));
        assert!(!is_valid_email_format("test\"@example.com"));
        assert!(!is_valid_email_format("test\\@example.com"));
        assert!(!is_valid_email_format("test\x00@example.com"));
        assert!(!is_valid_email_format("test\n@example.com"));
    }

    #[test]
    fn test_email_length_limits() {
        let long_local = "a".repeat(65);
        assert!(!is_valid_email_format(&format!("{long_local}@example.com")));

        let long_domain = format!("{}.com", "a".repeat(251));
        assert!(!is_valid_email_format(&format!("user@{long_domain}")));
    }

    #[test]
    fn test_tenant_id_generation() {
        let id = generate_tenant_id("My Cool Company");
        assert!(id.starts_with("my-cool-company-"));
        assert!(id.len() <= 40);
    }

    #[test]
    fn test_tenant_id_special_chars() {
        let id = generate_tenant_id("Acme Inc. (Italy)");
        assert!(!id.contains('.'));
        assert!(!id.contains('('));
        assert!(!id.contains(')'));
    }

    #[test]
    fn test_tenant_id_long_name() {
        let long_name = "a".repeat(100);
        let id = generate_tenant_id(&long_name);
        // 32 char slug + 1 hyphen + 16 hex = 49 chars max (R230-SRV-2: 64-bit suffix)
        assert!(id.len() <= 50);
    }

    #[test]
    fn test_api_key_format() {
        let key = generate_api_key();
        assert!(key.starts_with("vvt_"));
        // vvt_ (4) + 64 hex chars = 68
        assert_eq!(key.len(), 4 + API_KEY_RANDOM_LEN * 2);
    }

    #[test]
    fn test_api_key_uniqueness() {
        let k1 = generate_api_key();
        let k2 = generate_api_key();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_tier_to_quotas_free() {
        let q = tier_to_quotas("free");
        assert_eq!(q.max_policies, 10);
        assert_eq!(q.max_evaluations_per_minute, 20);
    }

    #[test]
    fn test_tier_to_quotas_starter() {
        let q = tier_to_quotas("starter");
        assert_eq!(q.max_policies, 50);
        assert_eq!(q.max_evaluations_per_minute, 1000);
    }

    #[test]
    fn test_tier_to_quotas_team() {
        let q = tier_to_quotas("team");
        assert_eq!(q.max_policies, 200);
        assert_eq!(q.max_evaluations_per_minute, 5000);
    }

    #[test]
    fn test_tier_to_quotas_enterprise_trial() {
        let q = tier_to_quotas("enterprise-trial");
        assert_eq!(q.max_policies, 500);
    }

    #[test]
    fn test_tier_to_quotas_unknown_returns_default() {
        let q = tier_to_quotas("premium");
        let d = crate::tenant::TenantQuotas::default();
        assert_eq!(q.max_policies, d.max_policies);
    }

    #[test]
    fn test_allowed_tiers_have_distinct_quotas() {
        let free = tier_to_quotas("free");
        let starter = tier_to_quotas("starter");
        let team = tier_to_quotas("team");
        let enterprise = tier_to_quotas("enterprise-trial");
        assert!(free.max_policies < starter.max_policies);
        assert!(starter.max_policies < team.max_policies);
        assert!(team.max_policies < enterprise.max_policies);
    }

    /// R230-SRV-2: Tenant ID suffix is 16 hex chars (64-bit entropy).
    #[test]
    fn test_r230_tenant_id_suffix_is_64_bit() {
        let id = generate_tenant_id("test-company");
        // Format: slug-<16 hex chars>
        let parts: Vec<&str> = id.rsplitn(2, '-').collect();
        assert_eq!(parts.len(), 2, "ID should contain a hyphen");
        let suffix = parts[0];
        assert_eq!(suffix.len(), 16, "Suffix should be 16 hex chars (64-bit)");
        assert!(
            suffix.chars().all(|c| c.is_ascii_hexdigit()),
            "Suffix should be hex: {suffix}"
        );
    }
}
