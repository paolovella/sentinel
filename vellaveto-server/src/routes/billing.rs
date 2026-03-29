// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

// ═══════════════════════════════════════════════════════════════════════════════
// BILLING WEBHOOK ROUTES — Paddle + Stripe
// ═══════════════════════════════════════════════════════════════════════════════
//
// These endpoints receive webhook events from payment providers and update
// the license tier accordingly. Each provider uses its own signature scheme.
//
// SECURITY:
// - Webhooks bypass API key auth (they use provider-specific signatures)
// - Secrets read from env vars only (never config files)
// - Signature failures return 200 OK with received:false (prevents retries)
// - No secrets logged — only event type and subscription ID
// - Request body size bounded by server's DefaultBodyLimit (1MB)

use axum::{
    body::Bytes,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use vellaveto_mcp::mediation::build_secondary_acis_envelope;
use vellaveto_types::acis::DecisionOrigin;
use vellaveto_types::{Action, Verdict};

use crate::routes::ErrorResponse;
use crate::tenant::TenantContext;
use crate::AppState;

/// Maximum webhook payload size (256 KB — well under the server's 1MB limit).
const MAX_WEBHOOK_PAYLOAD: usize = 262_144;

/// Maximum age for webhook timestamps (5 minutes).
///
/// SECURITY (P1-4): Prevents replay attacks by rejecting webhook events
/// with timestamps older than this tolerance. Both Paddle and Stripe include
/// timestamps in their signature headers.
const MAX_WEBHOOK_TIMESTAMP_AGE_SECS: u64 = 300;

/// SECURITY (FIND-R63-001): Maximum length for webhook signature headers.
/// Paddle: `ts=<20>;h1=<64>` ≈ 90 chars. Stripe: `t=<20>,v1=<64>` ≈ 90 chars.
/// 512 is generous but prevents parsing DoS from multi-megabyte headers.
const MAX_SIGNATURE_HEADER_LENGTH: usize = 512;

/// Expected hex length of HMAC-SHA256 output (32 bytes = 64 hex chars).
const HMAC_SHA256_HEX_LENGTH: usize = 64;

/// Maximum event ID length for webhook dedup.
const MAX_WEBHOOK_EVENT_ID_LEN: usize = 512;
/// Maximum number of tracked webhook event IDs.
const MAX_WEBHOOK_DEDUP_ENTRIES: usize = 100_000;

/// Idempotency tracker for webhook events.
///
/// Stores recently seen event IDs with timestamps. Duplicate events within
/// the TTL window are acknowledged without reprocessing.
pub struct WebhookDedup {
    seen: dashmap::DashMap<String, std::time::Instant>,
    ttl: std::time::Duration,
}

impl WebhookDedup {
    /// Create a new dedup tracker with the given TTL.
    pub fn new(ttl: std::time::Duration) -> Self {
        Self {
            seen: dashmap::DashMap::new(),
            ttl,
        }
    }

    /// Returns `true` if this event ID has NOT been seen before (first occurrence).
    /// Returns `false` if the event is a duplicate (already seen within TTL).
    pub fn check_or_insert(&self, event_id: &str) -> bool {
        // Validate the event ID
        if event_id.is_empty()
            || event_id.len() > MAX_WEBHOOK_EVENT_ID_LEN
            || vellaveto_types::has_dangerous_chars(event_id)
        {
            // Reject malformed IDs — treat as duplicate to prevent processing.
            return false;
        }

        let now = std::time::Instant::now();

        // R263-DEDUP-1: Evict expired entries when AT capacity (was > instead of >=,
        // allowing the map to exceed MAX by 1 before triggering eviction).
        if self.seen.len() >= MAX_WEBHOOK_DEDUP_ENTRIES {
            self.seen.retain(|_, ts| now.duration_since(*ts) < self.ttl);
        }

        // Check if already seen
        if let Some(existing) = self.seen.get(event_id) {
            if now.duration_since(*existing) < self.ttl {
                return false; // duplicate
            }
        }

        // Insert as first occurrence
        self.seen.insert(event_id.to_string(), now);
        true
    }
}

/// Response returned to webhook callers.
#[derive(Debug, Serialize)]
pub struct WebhookResponse {
    received: bool,
}

// ═══════════════════════════════════════════════════════════════════════════════
// PADDLE WEBHOOK
// ═══════════════════════════════════════════════════════════════════════════════

/// Paddle webhook event payload (simplified — only fields we need).
// SECURITY (R239-SRV-14): Reject unknown fields — webhook format is well-defined.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PaddleWebhookPayload {
    /// Event type (e.g., "subscription.created", "subscription.updated").
    #[serde(default)]
    event_type: String,
    /// Unique event identifier for idempotency tracking.
    #[serde(default)]
    event_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebhookDisposition {
    /// Event can be safely acknowledged without changing runtime billing state.
    Acknowledge,
    /// Event would change license/subscription state and must not be acknowledged
    /// until billing state synchronization is implemented.
    RequiresStateSync,
}

fn classify_paddle_event(event_type: &str) -> WebhookDisposition {
    match event_type {
        // Provider connectivity checks (no billing state mutation).
        "webhook.ping" | "webhook.health_check" | "event.test" => WebhookDisposition::Acknowledge,
        // Fail closed for all business events (known and unknown) until sync is wired.
        _ => WebhookDisposition::RequiresStateSync,
    }
}

/// `POST /api/billing/paddle/webhook`
///
/// Receives Paddle webhook events. Validates the signature using
/// `VELLAVETO_PADDLE_WEBHOOK_SECRET` env var.
///
/// Returns 200 OK for all payloads (valid or not) to prevent retry storms.
/// Invalid signatures are logged but not rejected at HTTP level.
pub async fn paddle_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<WebhookResponse>) {
    // SECURITY (P2-4): Return 413 for oversized payloads — this is not a
    // legitimate provider event and should not be acknowledged as received.
    if body.len() > MAX_WEBHOOK_PAYLOAD {
        tracing::warn!(
            size = body.len(),
            "Paddle webhook payload exceeds size limit"
        );
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(WebhookResponse { received: false }),
        );
    }

    // Read webhook secret from billing config env var
    let secret_env = &state.billing_config.paddle.webhook_secret_env;

    let secret = match std::env::var(secret_env) {
        Ok(s) if !s.is_empty() => s,
        _ => {
            tracing::warn!("Paddle webhook secret not configured, ignoring event");
            return (StatusCode::OK, Json(WebhookResponse { received: false }));
        }
    };

    // Validate Paddle signature (ts + h1 scheme)
    let signature = headers
        .get("paddle-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // SECURITY (P2-5): Return received:false on signature failure so the
    // provider's dashboard reflects that the event was not processed.
    if !verify_paddle_signature(signature, &body, &secret) {
        tracing::warn!("Paddle webhook signature verification failed");
        return (StatusCode::OK, Json(WebhookResponse { received: false }));
    }

    // Parse payload
    let payload: PaddleWebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse Paddle webhook payload");
            return (StatusCode::OK, Json(WebhookResponse { received: false }));
        }
    };

    // SECURITY: Idempotency check — reject duplicate webhook events.
    if let Some(ref event_id) = payload.event_id {
        if !state.webhook_dedup.check_or_insert(event_id) {
            tracing::debug!(
                event_id = %event_id,
                "Paddle webhook duplicate — acknowledging without reprocessing"
            );
            return (StatusCode::OK, Json(WebhookResponse { received: true }));
        }
    }

    // Log the event (no secrets)
    tracing::info!(
        event_type = %payload.event_type,
        "Paddle webhook received"
    );

    if classify_paddle_event(&payload.event_type) == WebhookDisposition::RequiresStateSync {
        tracing::warn!(
            event_type = %payload.event_type,
            "Paddle webhook validated but not applied: billing state sync not configured"
        );
        return (StatusCode::OK, Json(WebhookResponse { received: false }));
    }

    (StatusCode::OK, Json(WebhookResponse { received: true }))
}

/// Verify Paddle webhook signature.
///
/// Paddle uses `ts=<timestamp>;h1=<hmac_hex>` format in the `Paddle-Signature` header.
/// HMAC-SHA256 is computed over `<timestamp>:<body>` using the webhook secret.
fn verify_paddle_signature(signature_header: &str, body: &[u8], secret: &str) -> bool {
    // SECURITY (FIND-R63-001): Bound header length before parsing.
    if signature_header.len() > MAX_SIGNATURE_HEADER_LENGTH {
        tracing::warn!(
            len = signature_header.len(),
            "Paddle signature header exceeds max length"
        );
        return false;
    }

    // Parse "ts=<ts>;h1=<hmac>"
    let mut ts_value: Option<&str> = None;
    let mut h1_value: Option<&str> = None;

    for part in signature_header.split(';') {
        let part = part.trim();
        if let Some(ts) = part.strip_prefix("ts=") {
            if ts_value.replace(ts).is_some() {
                tracing::warn!("Paddle signature contains duplicate timestamp field");
                return false;
            }
        } else if let Some(h1) = part.strip_prefix("h1=") {
            if h1_value.replace(h1).is_some() {
                tracing::warn!("Paddle signature contains duplicate h1 field");
                return false;
            }
        }
    }

    let (ts_value, h1_value) = match (ts_value, h1_value) {
        (Some(ts), Some(h1)) if !ts.is_empty() && !h1.is_empty() => (ts, h1),
        _ => return false,
    };

    // SECURITY (FIND-R63-001): Validate HMAC hex length — SHA-256 produces exactly 64 hex chars.
    // Reject early to prevent large allocations from oversized h1 values.
    if !is_valid_sha256_hex(h1_value) {
        return false;
    }

    // SECURITY (P1-4): Reject stale timestamps to prevent replay attacks.
    if !ts_value.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let ts = match ts_value.parse::<u64>() {
        Ok(ts) => ts,
        Err(_) => return false,
    };
    let now = match current_unix_timestamp_secs() {
        Some(now) => now,
        None => return false,
    };
    if now.abs_diff(ts) > MAX_WEBHOOK_TIMESTAMP_AGE_SECS {
        tracing::warn!(
            ts,
            now,
            "Paddle webhook timestamp too old or too far in the future"
        );
        return false;
    }

    // Compute HMAC-SHA256 over "ts:body"
    // SECURITY (FIND-R63-001): Use saturating_add to prevent overflow in capacity calculation.
    let capacity = ts_value.len().saturating_add(1).saturating_add(body.len());
    let mut signed_payload = Vec::with_capacity(capacity);
    signed_payload.extend_from_slice(ts_value.as_bytes());
    signed_payload.push(b':');
    signed_payload.extend_from_slice(body);

    let expected = compute_hmac_sha256(secret.as_bytes(), &signed_payload);

    // Constant-time comparison
    constant_time_eq(
        expected.as_bytes(),
        h1_value.to_ascii_lowercase().as_bytes(),
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRIPE WEBHOOK
// ═══════════════════════════════════════════════════════════════════════════════

/// Stripe webhook event payload (simplified — only fields we need).
// SECURITY (R239-SRV-14): Reject unknown fields — webhook format is well-defined.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StripeWebhookPayload {
    /// Event type (e.g., "invoice.paid", "customer.subscription.updated").
    #[serde(default, rename = "type")]
    event_type: String,
}

fn classify_stripe_event(event_type: &str) -> WebhookDisposition {
    match event_type {
        // Provider connectivity checks (no billing state mutation).
        "webhook_endpoint.ping" => WebhookDisposition::Acknowledge,
        // Fail closed for all business events (known and unknown) until sync is wired.
        _ => WebhookDisposition::RequiresStateSync,
    }
}

/// `POST /api/billing/stripe/webhook`
///
/// Receives Stripe webhook events. Validates the signature using
/// `VELLAVETO_STRIPE_WEBHOOK_SECRET` env var (Stripe-Signature header).
///
/// Returns 200 OK for all payloads to prevent retry storms.
pub async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<WebhookResponse>) {
    // SECURITY (P2-4): Return 413 for oversized payloads.
    if body.len() > MAX_WEBHOOK_PAYLOAD {
        tracing::warn!(
            size = body.len(),
            "Stripe webhook payload exceeds size limit"
        );
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(WebhookResponse { received: false }),
        );
    }

    // Read webhook secret from billing config env var
    let secret_env = &state.billing_config.stripe.webhook_secret_env;

    let secret = match std::env::var(secret_env) {
        Ok(s) if !s.is_empty() => s,
        _ => {
            tracing::warn!("Stripe webhook secret not configured, ignoring event");
            return (StatusCode::OK, Json(WebhookResponse { received: false }));
        }
    };

    // Validate Stripe signature
    let signature = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // SECURITY (P2-5): Return received:false on signature failure.
    if !verify_stripe_signature(signature, &body, &secret) {
        tracing::warn!("Stripe webhook signature verification failed");
        return (StatusCode::OK, Json(WebhookResponse { received: false }));
    }

    // Parse payload
    let payload: StripeWebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse Stripe webhook payload");
            return (StatusCode::OK, Json(WebhookResponse { received: false }));
        }
    };

    // Log the event (no secrets)
    tracing::info!(
        event_type = %payload.event_type,
        "Stripe webhook received"
    );

    if classify_stripe_event(&payload.event_type) == WebhookDisposition::RequiresStateSync {
        tracing::warn!(
            event_type = %payload.event_type,
            "Stripe webhook validated but not applied: billing state sync not configured"
        );
        return (StatusCode::OK, Json(WebhookResponse { received: false }));
    }

    (StatusCode::OK, Json(WebhookResponse { received: true }))
}

/// Verify Stripe webhook signature (v1 scheme).
///
/// Stripe uses `t=<timestamp>,v1=<hmac_hex>` format in `Stripe-Signature` header.
/// HMAC-SHA256 is computed over `<timestamp>.<body>` using the `whsec_` signing secret.
fn verify_stripe_signature(signature_header: &str, body: &[u8], secret: &str) -> bool {
    // SECURITY (FIND-R63-001): Bound header length before parsing.
    if signature_header.len() > MAX_SIGNATURE_HEADER_LENGTH {
        tracing::warn!(
            len = signature_header.len(),
            "Stripe signature header exceeds max length"
        );
        return false;
    }

    let mut t_value: Option<&str> = None;
    let mut v1_value: Option<&str> = None;

    for part in signature_header.split(',') {
        let part = part.trim();
        if let Some(t) = part.strip_prefix("t=") {
            if t_value.replace(t).is_some() {
                tracing::warn!("Stripe signature contains duplicate timestamp field");
                return false;
            }
        } else if let Some(v1) = part.strip_prefix("v1=") {
            if v1_value.replace(v1).is_some() {
                tracing::warn!("Stripe signature contains duplicate v1 field");
                return false;
            }
        }
    }

    let (t_value, v1_value) = match (t_value, v1_value) {
        (Some(t), Some(v1)) if !t.is_empty() && !v1.is_empty() => (t, v1),
        _ => return false,
    };

    // SECURITY (FIND-R63-001): Validate HMAC hex length — SHA-256 produces exactly 64 hex chars.
    if !is_valid_sha256_hex(v1_value) {
        return false;
    }

    // SECURITY (P1-4): Reject stale timestamps to prevent replay attacks.
    if !t_value.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let ts = match t_value.parse::<u64>() {
        Ok(ts) => ts,
        Err(_) => return false,
    };
    let now = match current_unix_timestamp_secs() {
        Some(now) => now,
        None => return false,
    };
    if now.abs_diff(ts) > MAX_WEBHOOK_TIMESTAMP_AGE_SECS {
        tracing::warn!(
            ts,
            now,
            "Stripe webhook timestamp too old or too far in the future"
        );
        return false;
    }

    // Compute HMAC-SHA256 over "timestamp.body"
    // SECURITY (FIND-R63-001): Use saturating_add to prevent overflow in capacity calculation.
    let capacity = t_value.len().saturating_add(1).saturating_add(body.len());
    let mut signed_payload = Vec::with_capacity(capacity);
    signed_payload.extend_from_slice(t_value.as_bytes());
    signed_payload.push(b'.');
    signed_payload.extend_from_slice(body);

    let expected = compute_hmac_sha256(secret.as_bytes(), &signed_payload);

    constant_time_eq(
        expected.as_bytes(),
        v1_value.to_ascii_lowercase().as_bytes(),
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// HMAC-SHA256 (shared with licensing module — inline here to avoid cross-crate dep)
// ═══════════════════════════════════════════════════════════════════════════════

/// Compute HMAC-SHA256 using the SHA-256 primitive directly.
fn compute_hmac_sha256(key: &[u8], message: &[u8]) -> String {
    use sha2::Digest;

    const BLOCK_SIZE: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    let mut k_prime = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = Sha256::digest(key);
        k_prime[..32].copy_from_slice(&hash);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    let mut inner_hasher = Sha256::new();
    let mut inner_key_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_key_pad[i] = k_prime[i] ^ IPAD;
    }
    inner_hasher.update(inner_key_pad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    let mut outer_key_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer_key_pad[i] = k_prime[i] ^ OPAD;
    }
    outer_hasher.update(outer_key_pad);
    outer_hasher.update(inner_hash);
    let outer_hash = outer_hasher.finalize();

    hex::encode(outer_hash)
}

/// Constant-time byte comparison.
///
/// SECURITY (FIND-R72-SRV-003): Uses `subtle::ConstantTimeEq` which provides
/// a compiler-resistant constant-time comparison, replacing the previous
/// `std::hint::black_box` approach which is not a guaranteed defense against
/// compiler optimizations.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == HMAC_SHA256_HEX_LENGTH && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn current_unix_timestamp_secs() -> Option<u64> {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => Some(d.as_secs()),
        Err(e) => {
            tracing::warn!(error = %e, "System clock before UNIX epoch during webhook validation");
            None
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// LICENSE INFO ENDPOINT
// ═══════════════════════════════════════════════════════════════════════════════

/// Response for the license info endpoint.
#[derive(Debug, Serialize)]
pub struct LicenseInfoResponse {
    pub tier: String,
    pub limits: vellaveto_config::TierLimits,
    pub customer_id: Option<String>,
    pub max_nodes: Option<u32>,
    pub max_endpoints: Option<u32>,
    pub reason: String,
}

/// `GET /api/billing/license`
///
/// Returns the current license tier and feature limits.
/// Requires API key authentication (handled by the auth middleware).
pub async fn license_info(State(state): State<AppState>) -> Json<LicenseInfoResponse> {
    let validation = state.billing_config.licensing_validation.clone();
    Json(LicenseInfoResponse {
        tier: validation.tier.to_string(),
        limits: validation.limits,
        customer_id: validation.customer_id,
        max_nodes: validation.max_nodes,
        max_endpoints: validation.max_endpoints,
        reason: validation.reason,
    })
}

// =============================================================================
// PHASE 50: USAGE METERING API ENDPOINTS
// =============================================================================

/// Maximum tenant ID length for path parameters.
const MAX_USAGE_TENANT_ID_LEN: usize = 64;

/// Validate a tenant_id path parameter for usage endpoints.
fn validate_usage_tenant_id(tenant_id: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if tenant_id.is_empty() || tenant_id.len() > MAX_USAGE_TENANT_ID_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid tenant_id: must be 1-64 characters".to_string(),
            }),
        ));
    }
    if !tenant_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid tenant_id: only alphanumeric, hyphens, and underscores allowed"
                    .to_string(),
            }),
        ));
    }
    Ok(())
}

/// SECURITY (FIND-R203-008): Enforce tenant isolation on metering routes.
///
/// Non-default tenants may only read/mutate usage for their own tenant ID.
/// Return 404 (not 403) for cross-tenant access to avoid tenant enumeration.
fn enforce_usage_tenant_scope(
    tenant_ctx: &TenantContext,
    tenant_id: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if !tenant_ctx.is_default() && tenant_ctx.tenant_id != tenant_id {
        tracing::warn!(
            requester_tenant = %tenant_ctx.tenant_id,
            requested_tenant = %tenant_id,
            "Cross-tenant billing usage access denied"
        );
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Usage data not found".to_string(),
            }),
        ));
    }
    Ok(())
}

/// `GET /api/billing/usage/{tenant_id}`
///
/// Returns current-period usage metrics for a tenant.
/// Requires API key authentication. Returns 404 when metering is disabled.
pub async fn get_usage(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    Path(tenant_id): Path<String>,
) -> Result<Json<vellaveto_types::metering::UsageMetrics>, (StatusCode, Json<ErrorResponse>)> {
    validate_usage_tenant_id(&tenant_id)?;
    enforce_usage_tenant_scope(&tenant_ctx, &tenant_id)?;

    let tracker = state.usage_tracker.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Usage metering is not enabled".to_string(),
            }),
        )
    })?;

    match tracker.get_usage(&tenant_id) {
        Some(usage) => Ok(Json(usage)),
        None => {
            // Return zeroed metrics for unknown tenants (not an error)
            let period = tracker.current_billing_period();
            Ok(Json(vellaveto_types::metering::UsageMetrics {
                tenant_id,
                period_start: period.start,
                period_end: period.end,
                evaluations: 0,
                evaluations_allowed: 0,
                evaluations_denied: 0,
                policies_created: 0,
                approvals_processed: 0,
                audit_entries: 0,
            }))
        }
    }
}

/// `GET /api/billing/quotas/{tenant_id}`
///
/// Returns quota status (usage vs limits) for a tenant.
/// Requires API key authentication. Returns 404 when metering is disabled.
pub async fn get_quota_status(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    Path(tenant_id): Path<String>,
) -> Result<Json<vellaveto_types::metering::QuotaStatus>, (StatusCode, Json<ErrorResponse>)> {
    validate_usage_tenant_id(&tenant_id)?;
    enforce_usage_tenant_scope(&tenant_ctx, &tenant_id)?;

    let tracker = state.usage_tracker.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Usage metering is not enabled".to_string(),
            }),
        )
    })?;

    let tier = &state.billing_config.licensing_validation.tier;
    let tier_limit = tracker.limit_for_tier(tier);

    // Use the tenant's max_policies quota if available, else default
    let policies_limit = state
        .tenant_store
        .as_ref()
        .and_then(|store| store.get_tenant(&tenant_id))
        .map(|t| t.quotas.max_policies)
        .unwrap_or(1000);

    let status = tracker.get_quota_status(&tenant_id, tier_limit, policies_limit);
    Ok(Json(status))
}

/// Query parameters for usage history endpoint.
// SECURITY (R239-SRV-6): Reject unknown fields to prevent parameter smuggling.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageHistoryQuery {
    /// Number of periods to return (max 120, default 12).
    #[serde(default = "default_history_periods")]
    pub periods: u32,
}

fn default_history_periods() -> u32 {
    12
}

/// `GET /api/billing/usage/{tenant_id}/history`
///
/// Returns a usage summary for the tenant. Currently returns only the
/// current period (historical storage deferred to Phase 50b with persistence).
/// Requires API key authentication.
pub async fn get_usage_history(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    Path(tenant_id): Path<String>,
    Query(query): Query<UsageHistoryQuery>,
) -> Result<Json<vellaveto_types::metering::UsageSummary>, (StatusCode, Json<ErrorResponse>)> {
    validate_usage_tenant_id(&tenant_id)?;
    enforce_usage_tenant_scope(&tenant_ctx, &tenant_id)?;

    let tracker = state.usage_tracker.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Usage metering is not enabled".to_string(),
            }),
        )
    })?;

    // Cap periods at MAX_USAGE_PERIODS
    let _max_periods = query
        .periods
        .min(vellaveto_types::metering::MAX_USAGE_PERIODS as u32);

    // Currently only the current period is available (in-memory).
    // Historical periods will be available when persistence is added (Phase 50b).
    let periods = match tracker.get_usage(&tenant_id) {
        Some(usage) => vec![usage],
        None => vec![],
    };
    let total_evaluations = periods.iter().map(|p| p.evaluations).sum();

    Ok(Json(vellaveto_types::metering::UsageSummary {
        tenant_id,
        periods,
        total_evaluations,
    }))
}

/// `POST /api/billing/usage/{tenant_id}/reset`
///
/// Force-reset usage counters for a tenant (admin operation).
/// Requires API key authentication.
pub async fn reset_usage(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    Path(tenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_usage_tenant_id(&tenant_id)?;
    enforce_usage_tenant_scope(&tenant_ctx, &tenant_id)?;

    let tracker = state.usage_tracker.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Usage metering is not enabled".to_string(),
            }),
        )
    })?;

    tracker.reset_period(&tenant_id);

    // SECURITY: Audit administrative usage reset operations.
    let audit_action = Action::new(
        "vellaveto",
        "billing_usage_reset",
        serde_json::json!({ "tenant_id": &tenant_id }),
    );
    let acis_envelope = build_secondary_acis_envelope(
        &audit_action,
        &Verdict::Allow,
        DecisionOrigin::PolicyEngine,
        "http",
        Some(&tenant_id),
    );
    if let Err(e) = state
        .audit
        .log_entry_with_acis(
            &audit_action,
            &Verdict::Allow,
            serde_json::json!({
                "event": "billing.usage_reset",
                "tenant_id": &tenant_id,
                "source": "api",
            }),
            acis_envelope,
        )
        .await
    {
        tracing::warn!(
            tenant_id = %tenant_id,
            error = %e,
            "Failed to audit usage reset operation"
        );
    } else {
        crate::metrics::increment_audit_entries();
    }

    tracing::info!(tenant_id = %tenant_id, "Usage counters reset (admin)");

    Ok(Json(serde_json::json!({
        "reset": true,
        "tenant_id": tenant_id
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_ts() -> String {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .to_string()
    }

    #[test]
    fn test_verify_paddle_signature_valid() {
        let secret = "pdl_test_secret";
        let body = b"{\"event_type\":\"subscription.created\"}";
        let ts = current_ts();

        // Compute expected HMAC
        let mut signed = Vec::new();
        signed.extend_from_slice(ts.as_bytes());
        signed.push(b':');
        signed.extend_from_slice(body);
        let hmac = compute_hmac_sha256(secret.as_bytes(), &signed);

        let header = format!("ts={ts};h1={hmac}");
        assert!(verify_paddle_signature(&header, body, secret));
    }

    #[test]
    fn test_verify_paddle_signature_invalid() {
        let secret = "pdl_test_secret";
        let body = b"{\"event_type\":\"subscription.created\"}";
        let ts = current_ts();
        let header = format!("ts={ts};h1=deadbeef");
        assert!(!verify_paddle_signature(&header, body, secret));
    }

    #[test]
    fn test_verify_paddle_signature_missing_parts() {
        assert!(!verify_paddle_signature("", b"body", "secret"));
        let ts = current_ts();
        assert!(!verify_paddle_signature(
            &format!("ts={ts}"),
            b"body",
            "secret"
        ));
        assert!(!verify_paddle_signature("h1=abc", b"body", "secret"));
    }

    #[test]
    fn test_verify_paddle_signature_stale_timestamp() {
        let secret = "pdl_test_secret";
        let body = b"{\"event_type\":\"subscription.created\"}";
        let stale_ts = "1234567890"; // 2009 — way too old

        let mut signed = Vec::new();
        signed.extend_from_slice(stale_ts.as_bytes());
        signed.push(b':');
        signed.extend_from_slice(body);
        let hmac = compute_hmac_sha256(secret.as_bytes(), &signed);

        let header = format!("ts={stale_ts};h1={hmac}");
        assert!(!verify_paddle_signature(&header, body, secret));
    }

    #[test]
    fn test_verify_stripe_signature_valid() {
        let secret = "whsec_test_secret";
        let body = b"{\"type\":\"invoice.paid\"}";
        let ts = current_ts();

        let mut signed = Vec::new();
        signed.extend_from_slice(ts.as_bytes());
        signed.push(b'.');
        signed.extend_from_slice(body);
        let hmac = compute_hmac_sha256(secret.as_bytes(), &signed);

        let header = format!("t={ts},v1={hmac}");
        assert!(verify_stripe_signature(&header, body, secret));
    }

    #[test]
    fn test_verify_stripe_signature_invalid() {
        let secret = "whsec_test_secret";
        let body = b"{\"type\":\"invoice.paid\"}";
        let ts = current_ts();
        let header = format!("t={ts},v1=deadbeef");
        assert!(!verify_stripe_signature(&header, body, secret));
    }

    #[test]
    fn test_verify_stripe_signature_missing_parts() {
        assert!(!verify_stripe_signature("", b"body", "secret"));
        let ts = current_ts();
        assert!(!verify_stripe_signature(
            &format!("t={ts}"),
            b"body",
            "secret"
        ));
        assert!(!verify_stripe_signature("v1=abc", b"body", "secret"));
    }

    #[test]
    fn test_verify_stripe_signature_stale_timestamp() {
        let body = b"{\"type\":\"invoice.paid\"}";
        let stale_ts = "1234567890"; // 2009 — way too old

        let mut signed = Vec::new();
        signed.extend_from_slice(stale_ts.as_bytes());
        signed.push(b'.');
        signed.extend_from_slice(body);
        let hmac = compute_hmac_sha256(b"whsec_test_secret", &signed);

        let header = format!("t={stale_ts},v1={hmac}");
        assert!(!verify_stripe_signature(&header, body, "whsec_test_secret"));
    }

    #[test]
    fn test_verify_stripe_signature_wrong_secret() {
        let body = b"{\"type\":\"invoice.paid\"}";
        let ts = current_ts();

        let mut signed = Vec::new();
        signed.extend_from_slice(ts.as_bytes());
        signed.push(b'.');
        signed.extend_from_slice(body);
        let hmac = compute_hmac_sha256(b"correct_secret", &signed);

        let header = format!("t={ts},v1={hmac}");
        assert!(!verify_stripe_signature(&header, body, "wrong_secret"));
    }

    #[test]
    fn test_classify_paddle_probe_event_acknowledged() {
        assert_eq!(
            classify_paddle_event("webhook.ping"),
            WebhookDisposition::Acknowledge
        );
    }

    #[test]
    fn test_classify_paddle_subscription_event_requires_state_sync() {
        assert_eq!(
            classify_paddle_event("subscription.updated"),
            WebhookDisposition::RequiresStateSync
        );
    }

    #[test]
    fn test_classify_stripe_probe_event_acknowledged() {
        assert_eq!(
            classify_stripe_event("webhook_endpoint.ping"),
            WebhookDisposition::Acknowledge
        );
    }

    #[test]
    fn test_classify_stripe_invoice_event_requires_state_sync() {
        assert_eq!(
            classify_stripe_event("invoice.paid"),
            WebhookDisposition::RequiresStateSync
        );
    }

    #[test]
    fn test_webhook_response_serialization() {
        let resp = WebhookResponse { received: true };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains("\"received\":true"));
    }

    // SECURITY (FIND-R63-001): Signature header length bounds
    #[test]
    fn test_paddle_signature_oversized_header_rejected() {
        let huge_header = "a".repeat(MAX_SIGNATURE_HEADER_LENGTH + 1);
        assert!(!verify_paddle_signature(&huge_header, b"body", "secret"));
    }

    #[test]
    fn test_stripe_signature_oversized_header_rejected() {
        let huge_header = "a".repeat(MAX_SIGNATURE_HEADER_LENGTH + 1);
        assert!(!verify_stripe_signature(&huge_header, b"body", "secret"));
    }

    // SECURITY (FIND-R63-001): HMAC hex length validation
    #[test]
    fn test_paddle_signature_wrong_hmac_length_rejected() {
        let ts = current_ts();
        // 63 chars — one short of the expected 64
        let header = format!("ts={};h1={}", ts, "a".repeat(63));
        assert!(!verify_paddle_signature(&header, b"body", "secret"));
        // 65 chars — one over
        let header = format!("ts={};h1={}", ts, "a".repeat(65));
        assert!(!verify_paddle_signature(&header, b"body", "secret"));
    }

    #[test]
    fn test_stripe_signature_wrong_hmac_length_rejected() {
        let ts = current_ts();
        let header = format!("t={},v1={}", ts, "a".repeat(63));
        assert!(!verify_stripe_signature(&header, b"body", "secret"));
        let header = format!("t={},v1={}", ts, "a".repeat(65));
        assert!(!verify_stripe_signature(&header, b"body", "secret"));
    }

    #[test]
    fn test_paddle_signature_non_hex_digest_rejected() {
        let ts = current_ts();
        let header = format!("ts={};h1={}", ts, "z".repeat(HMAC_SHA256_HEX_LENGTH));
        assert!(!verify_paddle_signature(&header, b"body", "secret"));
    }

    #[test]
    fn test_stripe_signature_non_hex_digest_rejected() {
        let ts = current_ts();
        let header = format!("t={},v1={}", ts, "z".repeat(HMAC_SHA256_HEX_LENGTH));
        assert!(!verify_stripe_signature(&header, b"body", "secret"));
    }

    #[test]
    fn test_paddle_signature_duplicate_fields_rejected() {
        let ts = current_ts();
        let header = format!(
            "ts={0};h1={1};ts={0}",
            ts,
            "a".repeat(HMAC_SHA256_HEX_LENGTH)
        );
        assert!(!verify_paddle_signature(&header, b"body", "secret"));
    }

    #[test]
    fn test_stripe_signature_duplicate_fields_rejected() {
        let ts = current_ts();
        let header = format!(
            "t={0},v1={1},v1={1}",
            ts,
            "a".repeat(HMAC_SHA256_HEX_LENGTH)
        );
        assert!(!verify_stripe_signature(&header, b"body", "secret"));
    }

    #[test]
    fn test_hmac_sha256_hex_length_constant() {
        assert_eq!(HMAC_SHA256_HEX_LENGTH, 64);
    }

    // ── Webhook dedup tests ──────────────────────────────────────────────

    #[test]
    fn test_webhook_dedup_first_event_accepted() {
        let dedup = WebhookDedup::new(std::time::Duration::from_secs(60));
        assert!(
            dedup.check_or_insert("evt_001"),
            "first occurrence should be accepted"
        );
    }

    #[test]
    fn test_webhook_dedup_duplicate_rejected() {
        let dedup = WebhookDedup::new(std::time::Duration::from_secs(60));
        assert!(dedup.check_or_insert("evt_002"));
        assert!(
            !dedup.check_or_insert("evt_002"),
            "duplicate should be rejected"
        );
    }

    #[test]
    fn test_webhook_dedup_different_ids_accepted() {
        let dedup = WebhookDedup::new(std::time::Duration::from_secs(60));
        assert!(dedup.check_or_insert("evt_a"));
        assert!(dedup.check_or_insert("evt_b"));
    }

    #[test]
    fn test_webhook_dedup_empty_id_rejected() {
        let dedup = WebhookDedup::new(std::time::Duration::from_secs(60));
        assert!(
            !dedup.check_or_insert(""),
            "empty event ID should be rejected"
        );
    }

    #[test]
    fn test_webhook_dedup_dangerous_chars_rejected() {
        let dedup = WebhookDedup::new(std::time::Duration::from_secs(60));
        assert!(
            !dedup.check_or_insert("evt\x00bad"),
            "event ID with control chars should be rejected"
        );
    }
}
