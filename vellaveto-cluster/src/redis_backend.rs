// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Redis cluster backend for distributed Vellaveto state.
//!
//! Stores approvals and rate limit state in Redis, enabling multiple Vellaveto
//! instances to share state behind a load balancer.
//!
//! **Data model:**
//! - Approval objects: `{prefix}approval:{id}` → JSON string (Redis string)
//! - Dedup index: `{prefix}dedup:{hash}` → approval ID (Redis string with TTL)
//! - Pending set: `{prefix}pending` → sorted set scored by expiry timestamp
//! - Rate limits: `{prefix}rl:{category}:{key}` → sliding window counter (Lua script)
//!
//! **Fail-closed:** All operations return `ClusterError::Connection` on Redis
//! failures. The caller converts errors to `Deny` verdicts.

use async_trait::async_trait;
use deadpool_redis::redis;
use deadpool_redis::redis::AsyncCommands;
use deadpool_redis::{Config as PoolConfig, Pool, Runtime};
use vellaveto_approval::{ApprovalContainmentContext, ApprovalStatus, PendingApproval};
use vellaveto_types::Action;

use crate::{ClusterBackend, ClusterError};

/// Redis-backed cluster state.
pub struct RedisBackend {
    pool: Pool,
    key_prefix: String,
    default_ttl_secs: u64,
    max_pending: usize,
}

/// Default maximum pending approvals in Redis.
const DEFAULT_MAX_PENDING: usize = 10_000;

/// Default approval TTL in seconds (15 minutes).
const DEFAULT_TTL_SECS: u64 = 900;

/// Maximum number of entries to process from a single ZRANGEBYSCORE fetch.
///
/// Without this bound, an attacker who fills the pending sorted set can cause
/// OOM when `approval_list_pending()` or `approval_expire_stale()` fetches all
/// entries into memory. (FIND-R84-002)
const MAX_APPROVAL_FETCH: usize = 10_000;

/// Maximum length of an approval ID passed to Redis operations.
///
/// SECURITY (FIND-R112-009): Prevents oversized IDs from causing OOM and
/// blocks Redis cluster slot manipulation via hash tag characters.
const MAX_APPROVAL_ID_LEN: usize = 512;

/// Maximum length of a rate limit key parameter (category or key).
///
/// SECURITY (FIND-R113-003): Prevents oversized parameters from inflating
/// Redis key size and blocks cluster slot manipulation via hash tags.
const MAX_RATE_LIMIT_PARAM_LEN: usize = 512;

/// Validate an approval ID before using it to construct Redis keys.
///
/// SECURITY (FIND-R112-009): Rejects:
/// - Empty IDs
/// - IDs exceeding MAX_APPROVAL_ID_LEN (512)
/// - Control characters (0x00-0x1F, 0x7F, 0x80-0x9F) that can cause log injection
/// - Redis hash tag characters `{` and `}` that can manipulate cluster slot routing
fn validate_approval_id_for_redis(id: &str) -> Result<(), ClusterError> {
    if id.is_empty() {
        return Err(ClusterError::Validation(
            "approval ID must not be empty".to_string(),
        ));
    }
    if id.len() > MAX_APPROVAL_ID_LEN {
        return Err(ClusterError::Validation(format!(
            "approval ID exceeds maximum length of {MAX_APPROVAL_ID_LEN} bytes"
        )));
    }
    for c in id.chars() {
        // Reject C0 control chars, DEL, and C1 control chars
        if c.is_control() {
            return Err(ClusterError::Validation(
                "approval ID contains control characters".to_string(),
            ));
        }
        // SECURITY (FIND-R126-003): Reject Unicode format characters to prevent
        // invisible-character-based ID confusion and dedup bypass.
        if vellaveto_types::is_unicode_format_char(c) {
            return Err(ClusterError::Validation(
                "approval ID contains Unicode format characters".to_string(),
            ));
        }
        // SECURITY: Reject Redis hash tag characters to prevent cluster slot manipulation.
        // An attacker could craft an ID like "{slot1}attack" to force all related keys
        // onto the same Redis shard, bypassing intended data distribution.
        if c == '{' || c == '}' {
            return Err(ClusterError::Validation(
                "approval ID contains invalid characters ('{' or '}')".to_string(),
            ));
        }
    }
    Ok(())
}

/// Validate a resolver identity (`by` parameter) for approval approve/deny.
///
/// SECURITY (IMP-R170-007): Extracted from duplicated blocks in approval_approve
/// and approval_deny. Rejects empty, overlong, control char, and format char values.
fn validate_resolver_identity(by: &str) -> Result<(), ClusterError> {
    if by.is_empty() {
        return Err(ClusterError::Validation(
            "resolved_by must not be empty".to_string(),
        ));
    }
    if by.len() > vellaveto_approval::MAX_IDENTITY_LEN {
        return Err(ClusterError::Validation(format!(
            "resolved_by exceeds maximum length of {} bytes",
            vellaveto_approval::MAX_IDENTITY_LEN
        )));
    }
    if by.chars().any(|c| c.is_control()) {
        return Err(ClusterError::Validation(
            "resolved_by contains control characters".to_string(),
        ));
    }
    if by.chars().any(vellaveto_types::is_unicode_format_char) {
        return Err(ClusterError::Validation(
            "resolved_by contains Unicode format characters".to_string(),
        ));
    }
    Ok(())
}

/// Validate a rate limit key parameter (category or key) before using it
/// to construct Redis keys.
///
/// SECURITY (FIND-R113-003): Rejects:
/// - Empty parameters
/// - Parameters exceeding MAX_RATE_LIMIT_PARAM_LEN (512 bytes)
/// - Control characters (0x00-0x1F, 0x7F, 0x80-0x9F) that can cause log injection
/// - Redis hash tag characters `{` and `}` that can manipulate cluster slot routing
fn validate_rate_limit_param(name: &str, value: &str) -> Result<(), ClusterError> {
    if value.is_empty() {
        return Err(ClusterError::Validation(format!(
            "rate limit {name} must not be empty"
        )));
    }
    if value.len() > MAX_RATE_LIMIT_PARAM_LEN {
        return Err(ClusterError::Validation(format!(
            "rate limit {name} exceeds maximum length of {MAX_RATE_LIMIT_PARAM_LEN} bytes"
        )));
    }
    for c in value.chars() {
        // Reject C0 control chars, DEL, and C1 control chars
        if c.is_control() {
            return Err(ClusterError::Validation(format!(
                "rate limit {name} contains control characters"
            )));
        }
        // SECURITY (FIND-R126-003): Reject Unicode format characters.
        if vellaveto_types::is_unicode_format_char(c) {
            return Err(ClusterError::Validation(format!(
                "rate limit {name} contains Unicode format characters"
            )));
        }
        // SECURITY: Reject Redis hash tag characters to prevent cluster slot manipulation.
        if c == '{' || c == '}' {
            return Err(ClusterError::Validation(format!(
                "rate limit {name} contains invalid characters ('{{' or '}}')"
            )));
        }
    }
    Ok(())
}

impl RedisBackend {
    /// Create a new Redis backend.
    ///
    /// # Errors
    ///
    /// Returns `ClusterError::Connection` if the pool cannot be created.
    pub fn new(redis_url: &str, pool_size: usize, key_prefix: &str) -> Result<Self, ClusterError> {
        // SECURITY (R228-A2A-3): Validate key_prefix to prevent control char injection
        // into Redis keys and unbounded key lengths.
        const MAX_KEY_PREFIX_LEN: usize = 128;
        if key_prefix.is_empty() {
            return Err(ClusterError::Validation(
                "Redis key_prefix must not be empty".to_string(),
            ));
        }
        if key_prefix.len() > MAX_KEY_PREFIX_LEN {
            return Err(ClusterError::Validation(format!(
                "Redis key_prefix length {} exceeds maximum {}",
                key_prefix.len(),
                MAX_KEY_PREFIX_LEN
            )));
        }
        if key_prefix.chars().any(|c| c.is_control()) {
            return Err(ClusterError::Validation(
                "Redis key_prefix must not contain control characters".to_string(),
            ));
        }
        // SECURITY (R229-CLUS-1): Reject Redis hash tag characters {} which allow
        // cluster slot manipulation via hash tags like {slot}.
        if key_prefix.contains('{') || key_prefix.contains('}') {
            return Err(ClusterError::Validation(
                "Redis key_prefix must not contain hash tag characters '{' or '}'".to_string(),
            ));
        }
        // SECURITY (R229-CLUS-1): Reject Unicode format characters (invisible chars
        // that can be used for key injection/confusion in multi-tenant environments).
        if key_prefix
            .chars()
            .any(vellaveto_types::is_unicode_format_char)
        {
            return Err(ClusterError::Validation(
                "Redis key_prefix must not contain Unicode format characters".to_string(),
            ));
        }
        // R244-CLUSTER-1: Enforce TLS for non-localhost Redis connections.
        // Approval state, rate limits, and dedup hashes are security-sensitive;
        // transmitting them over plaintext enables MITM approval hijacking.
        let is_localhost = redis_url.contains("://127.0.0.1")
            || redis_url.contains("://localhost")
            || redis_url.contains("://[::1]");
        if !is_localhost && !redis_url.starts_with("rediss://") {
            return Err(ClusterError::Validation(
                "Redis URL must use rediss:// (TLS) for non-localhost connections".to_string(),
            ));
        }

        let cfg = PoolConfig::from_url(redis_url);
        let pool = cfg
            .builder()
            .map_err(|e| ClusterError::Connection(format!("Failed to create pool builder: {}", e)))?
            .max_size(pool_size)
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|e| ClusterError::Connection(format!("Failed to build pool: {}", e)))?;

        Ok(Self {
            pool,
            key_prefix: key_prefix.to_string(),
            default_ttl_secs: DEFAULT_TTL_SECS,
            max_pending: DEFAULT_MAX_PENDING,
        })
    }

    /// Set the default TTL for approvals (useful for testing).
    ///
    /// # Errors
    ///
    /// Returns an error if TTL is 0 or exceeds 30 days (2,592,000 seconds).
    pub fn with_ttl_secs(mut self, ttl: u64) -> Result<Self, ClusterError> {
        // SECURITY (FIND-R184-006): Validate TTL to prevent immediate-expiry (0)
        // or i64 overflow (u64::MAX wraps to negative Duration::seconds).
        const MAX_APPROVAL_TTL_SECS: u64 = 86400 * 30; // 30 days
        if ttl == 0 {
            return Err(ClusterError::Validation(
                "approval TTL must be >= 1 second".to_string(),
            ));
        }
        if ttl > MAX_APPROVAL_TTL_SECS {
            return Err(ClusterError::Validation(format!(
                "approval TTL {} exceeds maximum {} seconds",
                ttl, MAX_APPROVAL_TTL_SECS
            )));
        }
        self.default_ttl_secs = ttl;
        Ok(self)
    }

    /// Set the maximum number of pending approvals.
    ///
    /// # Errors
    ///
    /// Returns an error if max is 0.
    pub fn with_max_pending(mut self, max: usize) -> Result<Self, ClusterError> {
        // SECURITY (FIND-R184-006): Zero means all creation blocked — likely misconfiguration.
        if max == 0 {
            return Err(ClusterError::Validation(
                "max_pending must be >= 1".to_string(),
            ));
        }
        self.max_pending = max;
        Ok(self)
    }

    fn key(&self, suffix: &str) -> String {
        format!("{}{}", self.key_prefix, suffix)
    }

    fn approval_key(&self, id: &str) -> String {
        self.key(&format!("approval:{}", id))
    }

    fn dedup_key(&self, hash: &str) -> String {
        self.key(&format!("dedup:{}", hash))
    }

    fn pending_set_key(&self) -> String {
        self.key("pending")
    }

    fn rate_limit_key(&self, category: &str, key: &str) -> String {
        self.key(&format!("rl:{}:{}", category, key))
    }

    async fn get_conn(&self) -> Result<deadpool_redis::Connection, ClusterError> {
        self.pool
            .get()
            .await
            .map_err(|e| ClusterError::Connection(format!("Failed to get Redis connection: {}", e)))
    }

    /// Compute a dedup key from action + reason + requested_by + session_id.
    /// Mirrors the logic in vellaveto-approval to ensure compatibility.
    fn compute_dedup_hash_with_context(
        action: &Action,
        reason: &str,
        requested_by: Option<&str>,
        session_id: Option<&str>,
        containment_context: Option<&ApprovalContainmentContext>,
    ) -> Result<String, ClusterError> {
        use sha2::{Digest, Sha256};
        use unicode_normalization::UnicodeNormalization;
        use vellaveto_types::unicode::normalize_homoglyphs;

        let mut sorted_ips = action.resolved_ips.clone();
        sorted_ips.sort();
        let mut sorted_paths = action.target_paths.clone();
        sorted_paths.sort();
        let mut sorted_domains = action.target_domains.clone();
        sorted_domains.sort();

        // R231-CLUS-1: Normalize tool and function names with NFKC + homoglyph
        // mapping to prevent dedup bypass via Unicode confusables.
        let tool_normalized: String =
            normalize_homoglyphs(&action.tool.nfkc().collect::<String>().to_lowercase());
        let function_normalized: String =
            normalize_homoglyphs(&action.function.nfkc().collect::<String>().to_lowercase());

        let canonical = serde_json::json!({
            "tool": tool_normalized,
            "function": function_normalized,
            "parameters": action.parameters,
            "target_paths": sorted_paths,
            "target_domains": sorted_domains,
            "resolved_ips": sorted_ips,
        });

        let canonical_str = serde_json::to_string(&canonical)
            .map_err(|e| ClusterError::Serialization(e.to_string()))?;
        // SECURITY (FIND-R122-003): Use a distinct sentinel for None to avoid
        // collision with Some(""). Mirrors vellaveto-approval parity.
        let rb_component = requested_by.unwrap_or("\x00NONE\x00");
        // SECURITY (E3-1): Session binding must participate in dedup so an
        // approval created in session A cannot be reused through a collision
        // with the same action in session B.
        let sess_component = session_id.unwrap_or("\x00NOSESS\x00");
        let containment_component = match containment_context {
            Some(context) if context.is_meaningful() => {
                serde_json::to_string(&context.normalized())
                    .map_err(|e| ClusterError::Serialization(e.to_string()))?
            }
            _ => "\x00NOCTX\x00".to_string(),
        };
        let input = format!(
            "{}||{}||{}||{}||{}",
            canonical_str, reason, rb_component, sess_component, containment_component
        );
        let hash = Sha256::digest(input.as_bytes());
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        Ok(hex)
    }
}

/// Lua script for atomic sliding window rate limiting.
///
/// Uses a sorted set where members are unique request IDs (timestamps + random)
/// and scores are timestamps. On each check:
/// 1. Remove entries older than the window
/// 2. Count remaining entries
/// 3. If under limit, add the new entry
/// 4. Set TTL on the key to auto-cleanup
///
/// Returns 1 if allowed, 0 if rate-limited.
const RATE_LIMIT_SCRIPT: &str = r#"
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local request_id = ARGV[4]

-- Remove entries outside the window
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

-- Count current entries
local count = redis.call('ZCARD', key)

if count < limit then
    -- Add the new request
    redis.call('ZADD', key, now, request_id)
    -- Set TTL to auto-cleanup abandoned keys
    redis.call('EXPIRE', key, window + 1)
    return 1
else
    return 0
end
"#;

/// Lua script for atomic single-use approval consumption.
///
/// Returns:
/// - 1 when the approval was consumed
/// - 0 when the approval exists but is not usable for this request
/// - Redis nil when the approval key does not exist
const CONSUME_APPROVED_SCRIPT: &str = r#"
local approval_key = KEYS[1]
local json = redis.call('GET', approval_key)
if not json then
    return nil
end

local approval = cjson.decode(json)
if approval['status'] ~= 'Approved' then
    return 0
end

local bound_fingerprint = approval['action_fingerprint']
if not bound_fingerprint or bound_fingerprint == cjson.null then
    return 0
end

local requested_fingerprint = ARGV[1]
if requested_fingerprint == '' or requested_fingerprint ~= bound_fingerprint then
    return 0
end

local bound_session = approval['session_id']
local requested_session = ARGV[2]
if bound_session and bound_session ~= cjson.null then
    if requested_session == '' or requested_session ~= bound_session then
        return 0
    end
end

approval['status'] = 'Consumed'
approval['consumed_at'] = ARGV[3]
redis.call('SET', approval_key, cjson.encode(approval))
redis.call('EXPIRE', approval_key, tonumber(ARGV[4]))
return 1
"#;

#[async_trait]
impl ClusterBackend for RedisBackend {
    async fn approval_create_with_context(
        &self,
        action: Action,
        reason: String,
        requested_by: Option<String>,
        session_id: Option<String>,
        action_fingerprint: Option<String>,
        containment_context: Option<ApprovalContainmentContext>,
    ) -> Result<String, ClusterError> {
        // SECURITY (FIND-R111-001): Validate reason length — mirrors vellaveto-approval
        // store-level check. Without this, an attacker can store arbitrarily large strings
        // in Redis, causing OOM across all cluster nodes.
        // SECURITY (R246-APPR-1): Don't expose actual length in error message.
        if reason.len() > vellaveto_approval::MAX_REASON_LEN {
            return Err(ClusterError::Validation(format!(
                "reason exceeds maximum length of {} bytes",
                vellaveto_approval::MAX_REASON_LEN
            )));
        }
        // Validate identity length (mirrors vellaveto-approval store-level check)
        if let Some(ref rb) = requested_by {
            // SECURITY (FIND-R170-003): Reject empty requested_by — parity with
            // local ApprovalStore (FIND-R143-004). Empty requested_by causes the
            // self-approval check to be skipped entirely.
            if rb.is_empty() {
                return Err(ClusterError::Validation(
                    "requested_by must not be empty".to_string(),
                ));
            }
            if rb.len() > vellaveto_approval::MAX_IDENTITY_LEN {
                return Err(ClusterError::Validation(format!(
                    "requested_by exceeds maximum length of {} bytes",
                    vellaveto_approval::MAX_IDENTITY_LEN
                )));
            }
            // SECURITY (FIND-R122-001): Reject control/format chars in identity
            // fields — parity with local ApprovalStore.
            if rb.chars().any(|c| c.is_control()) {
                return Err(ClusterError::Validation(
                    "requested_by contains control characters".to_string(),
                ));
            }
            if rb.chars().any(vellaveto_types::is_unicode_format_char) {
                return Err(ClusterError::Validation(
                    "requested_by contains Unicode format characters".to_string(),
                ));
            }
        }
        // SECURITY (E3-1): Validate session_id with the same fail-closed
        // constraints as the local approval store.
        if let Some(ref sid) = session_id {
            if sid.is_empty() {
                return Err(ClusterError::Validation(
                    "session_id must not be empty".to_string(),
                ));
            }
            if sid.len() > vellaveto_approval::MAX_SESSION_ID_LEN {
                return Err(ClusterError::Validation(format!(
                    "session_id exceeds maximum length of {} bytes",
                    vellaveto_approval::MAX_SESSION_ID_LEN
                )));
            }
            if sid.chars().any(|c| c.is_control()) {
                return Err(ClusterError::Validation(
                    "session_id contains control characters".to_string(),
                ));
            }
        }
        // SECURITY (E3-1): Validate fingerprint shape with the same constraints
        // as the local approval store.
        if let Some(ref fp) = action_fingerprint {
            if fp.is_empty() {
                return Err(ClusterError::Validation(
                    "action_fingerprint must not be empty".to_string(),
                ));
            }
            if fp.len() > vellaveto_approval::MAX_FINGERPRINT_LEN {
                return Err(ClusterError::Validation(format!(
                    "action_fingerprint exceeds maximum length of {} bytes",
                    vellaveto_approval::MAX_FINGERPRINT_LEN
                )));
            }
            if !fp.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ClusterError::Validation(
                    "action_fingerprint must be hex-encoded".to_string(),
                ));
            }
        }
        // SECURITY (FIND-R122-006, FIND-R126-002): Reject control/format chars in reason field.
        if reason.chars().any(|c| c.is_control()) {
            return Err(ClusterError::Validation(
                "reason contains control characters".to_string(),
            ));
        }
        if reason.chars().any(vellaveto_types::is_unicode_format_char) {
            return Err(ClusterError::Validation(
                "reason contains Unicode format characters".to_string(),
            ));
        }

        let containment_context = containment_context
            .map(|context| context.normalized())
            .filter(|context| context.is_meaningful());

        let dedup_hash = Self::compute_dedup_hash_with_context(
            &action,
            &reason,
            requested_by.as_deref(),
            session_id.as_deref(),
            containment_context.as_ref(),
        )?;
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        // SECURITY (R246-CLUST-1): Use try_from for defense-in-depth. The
        // with_ttl_secs() validation caps at 30 days, but the cast should be
        // safe independently in case validation is ever relaxed.
        let ttl_secs = i64::try_from(self.default_ttl_secs)
            .map_err(|_| ClusterError::Validation("approval TTL overflows i64".to_string()))?;
        let ttl = chrono::Duration::seconds(ttl_secs);
        let expires_at = now + ttl;

        let approval = PendingApproval {
            id: id.clone(),
            action,
            reason,
            created_at: now,
            expires_at,
            status: ApprovalStatus::Pending,
            resolved_by: None,
            resolved_at: None,
            consumed_at: None,
            requested_by,
            session_id,
            action_fingerprint,
            containment_context,
        };

        let approval_json = serde_json::to_string(&approval)
            .map_err(|e| ClusterError::Serialization(e.to_string()))?;

        let mut conn = self.get_conn().await?;

        // R230-CLUS-1: Atomic dedup via SET NX EX (eliminates TOCTOU race).
        // Previously used GET-then-SET which allowed concurrent callers to both
        // see the dedup key as absent and create duplicate approvals.
        // Now uses SET NX EX to atomically claim the dedup slot.
        let dedup_redis_key = self.dedup_key(&dedup_hash);

        // Attempt atomic claim: SET key value NX EX ttl
        // Returns true if key was set (slot claimed), false if key already exists.
        let claimed: bool = redis::cmd("SET")
            .arg(&dedup_redis_key)
            .arg(&id)
            .arg("NX")
            .arg("EX")
            .arg(self.default_ttl_secs)
            .query_async::<Option<String>>(&mut conn)
            .await
            .map(|r: Option<String>| r.is_some()) // SET NX returns "OK" on success, nil on key-exists
            .map_err(|e| ClusterError::Connection(format!("Redis SET NX dedup failed: {}", e)))?;

        if !claimed {
            // Dedup key exists — check if the referenced approval is still pending
            let existing_id: Option<String> = conn
                .get(&dedup_redis_key)
                .await
                .map_err(|e| ClusterError::Connection(format!("Redis GET dedup failed: {}", e)))?;
            if let Some(ref eid) = existing_id {
                let existing_json: Option<String> =
                    conn.get(self.approval_key(eid)).await.map_err(|e| {
                        ClusterError::Connection(format!("Redis GET approval failed: {}", e))
                    })?;
                if let Some(ref json_str) = existing_json {
                    if let Ok(existing) = serde_json::from_str::<PendingApproval>(json_str) {
                        if existing.status == ApprovalStatus::Pending {
                            return Ok(eid.clone());
                        }
                    }
                }
                // Stale dedup — remove and retry creation via recursion-free path:
                // Delete the stale key, then atomically claim again.
                let _: () = conn.del(&dedup_redis_key).await.map_err(|e| {
                    ClusterError::Connection(format!("Redis DEL dedup failed: {}", e))
                })?;
                // Re-attempt atomic claim after stale removal
                let reclaimed: bool = redis::cmd("SET")
                    .arg(&dedup_redis_key)
                    .arg(&id)
                    .arg("NX")
                    .arg("EX")
                    .arg(self.default_ttl_secs)
                    .query_async::<Option<String>>(&mut conn)
                    .await
                    .map(|r: Option<String>| r.is_some())
                    .map_err(|e| {
                        ClusterError::Connection(format!("Redis SET NX dedup retry failed: {}", e))
                    })?;
                if !reclaimed {
                    // Another caller won the race after stale removal — re-check
                    let new_eid: Option<String> =
                        conn.get(&dedup_redis_key).await.map_err(|e| {
                            ClusterError::Connection(format!("Redis GET dedup failed: {}", e))
                        })?;
                    if let Some(eid) = new_eid {
                        return Ok(eid);
                    }
                    // Key vanished between SET NX and GET — create new below
                }
            }
        }

        // Check capacity
        let pending_count: usize = conn
            .zcard(self.pending_set_key())
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis ZCARD failed: {}", e)))?;
        if pending_count >= self.max_pending {
            // Clean up the dedup key we claimed since we can't create the approval
            let _: () = conn.del(&dedup_redis_key).await.unwrap_or(()); // Best-effort cleanup
            return Err(ClusterError::CapacityExceeded(self.max_pending));
        }

        // Store the approval
        let approval_redis_key = self.approval_key(&id);
        let _: () = conn
            .set(&approval_redis_key, &approval_json)
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis SET approval failed: {}", e)))?;

        // Add to pending sorted set (scored by expiry timestamp)
        let expiry_ts = expires_at.timestamp() as f64;
        let _: () = conn
            .zadd(self.pending_set_key(), &id, expiry_ts)
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis ZADD pending failed: {}", e)))?;

        Ok(id)
    }

    async fn approval_get(&self, id: &str) -> Result<PendingApproval, ClusterError> {
        // SECURITY (FIND-R112-009): Validate ID before constructing Redis key.
        validate_approval_id_for_redis(id)?;
        let mut conn = self.get_conn().await?;
        let json: Option<String> = conn
            .get(self.approval_key(id))
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis GET failed: {}", e)))?;

        match json {
            Some(j) => {
                serde_json::from_str(&j).map_err(|e| ClusterError::Serialization(e.to_string()))
            }
            None => Err(ClusterError::NotFound(id.to_string())),
        }
    }

    async fn approval_approve(&self, id: &str, by: &str) -> Result<PendingApproval, ClusterError> {
        // SECURITY (FIND-R112-009): Validate ID before constructing Redis key.
        validate_approval_id_for_redis(id)?;
        // SECURITY (FIND-R170-002, FIND-R122-001, IMP-R170-007): Validate resolver identity.
        validate_resolver_identity(by)?;

        let mut conn = self.get_conn().await?;
        let json: Option<String> = conn
            .get(self.approval_key(id))
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis GET failed: {}", e)))?;

        let mut approval: PendingApproval = match json {
            Some(j) => {
                serde_json::from_str(&j).map_err(|e| ClusterError::Serialization(e.to_string()))?
            }
            None => return Err(ClusterError::NotFound(id.to_string())),
        };

        if approval.status != ApprovalStatus::Pending {
            return Err(ClusterError::AlreadyResolved(id.to_string()));
        }

        // Check expiry
        let now = chrono::Utc::now();
        if now > approval.expires_at {
            approval.status = ApprovalStatus::Expired;
            self.persist_and_cleanup(&mut conn, &approval).await?;
            return Err(ClusterError::Expired(id.to_string()));
        }

        // Self-approval check: delegate to the same logic that vellaveto-approval uses.
        // We replicate the key checks here to avoid depending on internal approval methods.
        if let Some(ref requester) = approval.requested_by {
            let requester_base = requester.split(" (note:").next().unwrap_or(requester);
            let approver_base = by.split(" (note:").next().unwrap_or(by);

            if requester_base.contains('(') || approver_base.contains('(') {
                return Err(ClusterError::Validation(
                    "Self-approval denied: principal contains invalid characters".to_string(),
                ));
            }

            use unicode_normalization::UnicodeNormalization;
            use vellaveto_types::unicode::normalize_homoglyphs;
            let requester_normalized: String = requester_base.nfkc().collect();
            let approver_normalized: String = approver_base.nfkc().collect();
            let req_lower: String = requester_normalized
                .chars()
                .flat_map(char::to_lowercase)
                .collect();
            let app_lower: String = approver_normalized
                .chars()
                .flat_map(char::to_lowercase)
                .collect();
            // SECURITY (FIND-R58-CFG-001): Apply homoglyph normalization
            // to match vellaveto-approval parity. Without this, Cyrillic
            // homoglyphs (e.g., U+0430 for 'a') bypass self-approval check.
            let req_final = normalize_homoglyphs(&req_lower);
            let app_final = normalize_homoglyphs(&app_lower);
            if !req_final.is_empty() && req_final != "anonymous" && req_final == app_final {
                // SECURITY (R245-APPR-2): Genericize self-approval error to prevent
                // requester identity enumeration. Previously leaked the requester identity.
                return Err(ClusterError::Validation(
                    "Self-approval denied: resolver cannot approve their own request".to_string(),
                ));
            }
        }

        approval.status = ApprovalStatus::Approved;
        approval.resolved_by = Some(by.to_string());
        approval.resolved_at = Some(now);
        approval.consumed_at = None;

        self.persist_and_cleanup(&mut conn, &approval).await?;
        Ok(approval)
    }

    async fn approval_consume_approved(
        &self,
        id: &str,
        session_id: Option<&str>,
        action_fingerprint: Option<&str>,
    ) -> Result<bool, ClusterError> {
        validate_approval_id_for_redis(id)?;

        let mut conn = self.get_conn().await?;
        let consumed_at = chrono::Utc::now().to_rfc3339();
        let result: Option<i32> = deadpool_redis::redis::Script::new(CONSUME_APPROVED_SCRIPT)
            .key(self.approval_key(id))
            .arg(action_fingerprint.unwrap_or_default())
            .arg(session_id.unwrap_or_default())
            .arg(consumed_at)
            .arg(3600)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| {
                ClusterError::Connection(format!("Redis approval consume failed: {}", e))
            })?;

        match result {
            Some(1) => {
                // R254-CLUS-1: Best-effort dedup key cleanup on consumption.
                // The Lua script atomically set status=Consumed (no double-consume).
                // We now remove the dedup key and pending-set entry to match local
                // ApprovalStore behavior (lib.rs:1079). Failure here is non-critical
                // — the dedup key has a TTL and will expire regardless.
                if let Ok(Some(json)) = conn.get::<_, Option<String>>(self.approval_key(id)).await {
                    if let Ok(approval) = serde_json::from_str::<PendingApproval>(&json) {
                        let _: Result<(), _> =
                            conn.zrem(self.pending_set_key(), &approval.id).await;
                        if let Ok(dedup_hash) = Self::compute_dedup_hash_with_context(
                            &approval.action,
                            &approval.reason,
                            approval.requested_by.as_deref(),
                            approval.session_id.as_deref(),
                            approval.containment_context.as_ref(),
                        ) {
                            let _: Result<(), _> = conn.del(self.dedup_key(&dedup_hash)).await;
                        }
                    }
                }
                Ok(true)
            }
            Some(0) => Ok(false),
            Some(other) => Err(ClusterError::Backend(format!(
                "Unexpected Redis approval consume result: {}",
                other
            ))),
            None => Err(ClusterError::NotFound(id.to_string())),
        }
    }

    async fn approval_deny(&self, id: &str, by: &str) -> Result<PendingApproval, ClusterError> {
        // SECURITY (FIND-R112-009): Validate ID before constructing Redis key.
        validate_approval_id_for_redis(id)?;
        // SECURITY (FIND-R170-002, FIND-R122-001, IMP-R170-007): Validate resolver identity.
        validate_resolver_identity(by)?;

        let mut conn = self.get_conn().await?;
        let json: Option<String> = conn
            .get(self.approval_key(id))
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis GET failed: {}", e)))?;

        let mut approval: PendingApproval = match json {
            Some(j) => {
                serde_json::from_str(&j).map_err(|e| ClusterError::Serialization(e.to_string()))?
            }
            None => return Err(ClusterError::NotFound(id.to_string())),
        };

        if approval.status != ApprovalStatus::Pending {
            return Err(ClusterError::AlreadyResolved(id.to_string()));
        }

        let now = chrono::Utc::now();
        if now > approval.expires_at {
            approval.status = ApprovalStatus::Expired;
            self.persist_and_cleanup(&mut conn, &approval).await?;
            return Err(ClusterError::Expired(id.to_string()));
        }

        // SECURITY (FIND-R58-CFG-002): Self-denial prevention — mirrors
        // vellaveto-approval::ApprovalStore::deny() parity. A requester
        // must not be able to deny their own request, as this breaks
        // separation-of-privilege.
        if let Some(ref requester) = approval.requested_by {
            let requester_base = requester.split(" (note:").next().unwrap_or(requester);
            let denier_base = by.split(" (note:").next().unwrap_or(by);

            if requester_base.contains('(') || denier_base.contains('(') {
                return Err(ClusterError::Validation(
                    "Self-denial denied: principal contains invalid characters".to_string(),
                ));
            }

            use unicode_normalization::UnicodeNormalization;
            use vellaveto_types::unicode::normalize_homoglyphs;
            let requester_normalized: String = requester_base.nfkc().collect();
            let denier_normalized: String = denier_base.nfkc().collect();
            let req_lower: String = requester_normalized
                .chars()
                .flat_map(char::to_lowercase)
                .collect();
            let den_lower: String = denier_normalized
                .chars()
                .flat_map(char::to_lowercase)
                .collect();
            let req_final = normalize_homoglyphs(&req_lower);
            let den_final = normalize_homoglyphs(&den_lower);
            if !req_final.is_empty() && req_final != "anonymous" && req_final == den_final {
                // SECURITY (R245-APPR-2): Genericize self-denial error to prevent
                // requester identity enumeration. Previously leaked the requester identity.
                return Err(ClusterError::Validation(
                    "Self-denial denied: resolver cannot deny their own request".to_string(),
                ));
            }
        }

        approval.status = ApprovalStatus::Denied;
        approval.resolved_by = Some(by.to_string());
        approval.resolved_at = Some(now);
        approval.consumed_at = None;

        self.persist_and_cleanup(&mut conn, &approval).await?;
        Ok(approval)
    }

    async fn approval_list_pending(&self) -> Result<Vec<PendingApproval>, ClusterError> {
        let mut conn = self.get_conn().await?;

        // Get all members of the pending set
        let mut ids: Vec<String> = conn
            .zrangebyscore(self.pending_set_key(), "-inf", "+inf")
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis ZRANGEBYSCORE failed: {}", e)))?;

        // SECURITY (FIND-R84-002): Bound fetched entries to prevent OOM
        if ids.len() > MAX_APPROVAL_FETCH {
            tracing::warn!(
                fetched = ids.len(),
                max = MAX_APPROVAL_FETCH,
                "approval_list_pending: truncating results to MAX_APPROVAL_FETCH"
            );
            ids.truncate(MAX_APPROVAL_FETCH);
        }

        let mut approvals = Vec::with_capacity(ids.len());
        for id in &ids {
            let json: Option<String> = conn
                .get(self.approval_key(id))
                .await
                .map_err(|e| ClusterError::Connection(format!("Redis GET failed: {}", e)))?;
            if let Some(j) = json {
                if let Ok(approval) = serde_json::from_str::<PendingApproval>(&j) {
                    if approval.status == ApprovalStatus::Pending {
                        approvals.push(approval);
                    }
                }
            }
        }

        Ok(approvals)
    }

    async fn approval_pending_count(&self) -> Result<usize, ClusterError> {
        let mut conn = self.get_conn().await?;
        let count: usize = conn
            .zcard(self.pending_set_key())
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis ZCARD failed: {}", e)))?;
        Ok(count)
    }

    async fn approval_expire_stale(&self) -> Result<usize, ClusterError> {
        let mut conn = self.get_conn().await?;
        let now = chrono::Utc::now();
        let now_ts = now.timestamp() as f64;

        // Get expired members (score <= now timestamp)
        let mut expired_ids: Vec<String> = conn
            .zrangebyscore(self.pending_set_key(), "-inf", now_ts)
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis ZRANGEBYSCORE failed: {}", e)))?;

        // SECURITY (FIND-R84-002): Bound fetched entries to prevent OOM
        if expired_ids.len() > MAX_APPROVAL_FETCH {
            tracing::warn!(
                fetched = expired_ids.len(),
                max = MAX_APPROVAL_FETCH,
                "approval_expire_stale: truncating results to MAX_APPROVAL_FETCH"
            );
            expired_ids.truncate(MAX_APPROVAL_FETCH);
        }

        let mut expired_count = 0;
        for id in &expired_ids {
            let json: Option<String> = conn
                .get(self.approval_key(id))
                .await
                .map_err(|e| ClusterError::Connection(format!("Redis GET failed: {}", e)))?;
            if let Some(j) = json {
                if let Ok(mut approval) = serde_json::from_str::<PendingApproval>(&j) {
                    if approval.status == ApprovalStatus::Pending {
                        approval.status = ApprovalStatus::Expired;
                        self.persist_and_cleanup(&mut conn, &approval).await?;
                        expired_count += 1;
                    } else {
                        // Already resolved — just remove from pending set
                        let _: () = conn.zrem(self.pending_set_key(), id).await.map_err(|e| {
                            ClusterError::Connection(format!("Redis ZREM failed: {}", e))
                        })?;
                    }
                }
            } else {
                // Orphan entry in pending set — remove it
                let _: () = conn
                    .zrem(self.pending_set_key(), id)
                    .await
                    .map_err(|e| ClusterError::Connection(format!("Redis ZREM failed: {}", e)))?;
            }
        }

        Ok(expired_count)
    }

    async fn rate_limit_check(
        &self,
        category: &str,
        key: &str,
        rps: u32,
        burst: u32,
    ) -> Result<bool, ClusterError> {
        // SECURITY (FIND-R113-003): Validate rate limit parameters before
        // constructing Redis keys. Prevents empty/oversized/control-char/hash-tag abuse.
        validate_rate_limit_param("category", category)?;
        validate_rate_limit_param("key", key)?;

        let mut conn = self.get_conn().await?;
        let redis_key = self.rate_limit_key(category, key);

        // Sliding window: window = 1 second, limit = burst (or rps if burst is 0)
        let limit = if burst > 0 { burst } else { rps };
        let window_ms: u64 = 1000; // 1 second window
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| ClusterError::Backend(format!("System time error: {}", e)))?
            .as_millis();
        // SECURITY (R246-ENG-1): Safe cast — as_millis() returns u128.
        let now_ms = u64::try_from(now_ms).map_err(|_| {
            ClusterError::Backend("System time milliseconds overflow u64".to_string())
        })?;

        let request_id = format!("{}:{}", now_ms, uuid::Uuid::new_v4());

        let result: i32 = deadpool_redis::redis::Script::new(RATE_LIMIT_SCRIPT)
            .key(&redis_key)
            .arg(now_ms)
            .arg(window_ms)
            .arg(limit)
            .arg(&request_id)
            .invoke_async(&mut *conn)
            .await
            .map_err(|e| {
                ClusterError::Connection(format!("Redis rate limit script failed: {}", e))
            })?;

        Ok(result == 1)
    }

    async fn health_check(&self) -> Result<(), ClusterError> {
        let mut conn = self.get_conn().await?;
        let pong: String = deadpool_redis::redis::cmd("PING")
            .query_async(&mut *conn)
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis PING failed: {}", e)))?;
        if pong != "PONG" {
            return Err(ClusterError::Connection(format!(
                "Unexpected PING response: {}",
                pong
            )));
        }
        Ok(())
    }
}

impl RedisBackend {
    /// Expose key construction for testing.
    #[cfg(test)]
    pub(crate) fn test_key(&self, suffix: &str) -> String {
        self.key(suffix)
    }

    /// Expose approval_key for testing.
    #[cfg(test)]
    pub(crate) fn test_approval_key(&self, id: &str) -> String {
        self.approval_key(id)
    }

    /// Expose dedup_key for testing.
    #[cfg(test)]
    pub(crate) fn test_dedup_key(&self, hash: &str) -> String {
        self.dedup_key(hash)
    }

    /// Expose pending_set_key for testing.
    #[cfg(test)]
    pub(crate) fn test_pending_set_key(&self) -> String {
        self.pending_set_key()
    }

    /// Expose rate_limit_key for testing.
    #[cfg(test)]
    pub(crate) fn test_rate_limit_key(&self, category: &str, key: &str) -> String {
        self.rate_limit_key(category, key)
    }

    /// Expose compute_dedup_hash for testing.
    #[cfg(test)]
    pub(crate) fn test_compute_dedup_hash(
        action: &Action,
        reason: &str,
        requested_by: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<String, ClusterError> {
        Self::compute_dedup_hash_with_context(action, reason, requested_by, session_id, None)
    }

    /// Expose compute_dedup_hash_with_context for testing.
    #[cfg(test)]
    pub(crate) fn test_compute_dedup_hash_with_context(
        action: &Action,
        reason: &str,
        requested_by: Option<&str>,
        session_id: Option<&str>,
        containment_context: Option<&ApprovalContainmentContext>,
    ) -> Result<String, ClusterError> {
        Self::compute_dedup_hash_with_context(
            action,
            reason,
            requested_by,
            session_id,
            containment_context,
        )
    }

    /// Persist an updated approval and cleanup associated indices.
    async fn persist_and_cleanup(
        &self,
        conn: &mut deadpool_redis::Connection,
        approval: &PendingApproval,
    ) -> Result<(), ClusterError> {
        let json = serde_json::to_string(approval)
            .map_err(|e| ClusterError::Serialization(e.to_string()))?;

        // Update the approval object
        let _: () = conn
            .set(self.approval_key(&approval.id), &json)
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis SET failed: {}", e)))?;

        // If no longer pending, remove from pending set and dedup index
        if approval.status != ApprovalStatus::Pending {
            let _: () = conn
                .zrem(self.pending_set_key(), &approval.id)
                .await
                .map_err(|e| ClusterError::Connection(format!("Redis ZREM failed: {}", e)))?;

            // Remove dedup key
            if let Ok(dedup_hash) = Self::compute_dedup_hash_with_context(
                &approval.action,
                &approval.reason,
                approval.requested_by.as_deref(),
                approval.session_id.as_deref(),
                approval.containment_context.as_ref(),
            ) {
                let _: () = conn.del(self.dedup_key(&dedup_hash)).await.map_err(|e| {
                    ClusterError::Connection(format!("Redis DEL dedup failed: {}", e))
                })?;
            }

            // Set a TTL on the approval itself for eventual cleanup (1 hour)
            let _: () = conn
                .expire(self.approval_key(&approval.id), 3600)
                .await
                .map_err(|e| ClusterError::Connection(format!("Redis EXPIRE failed: {}", e)))?;
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "redis-backend"))]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_action(tool: &str, function: &str) -> Action {
        Action {
            tool: tool.to_string(),
            function: function.to_string(),
            parameters: json!({}),
            target_paths: vec![],
            target_domains: vec![],
            resolved_ips: vec![],
        }
    }

    fn make_containment_context(risk: u8) -> ApprovalContainmentContext {
        ApprovalContainmentContext {
            semantic_taint: vec![
                vellaveto_types::SemanticTaint::Quarantined,
                vellaveto_types::SemanticTaint::IntegrityFailed,
            ],
            lineage_channels: vec![
                vellaveto_types::ContextChannel::CommandLike,
                vellaveto_types::ContextChannel::ToolOutput,
            ],
            effective_trust_tier: Some(vellaveto_types::TrustTier::Low),
            sink_class: Some(vellaveto_types::SinkClass::CodeExecution),
            containment_mode: Some(vellaveto_types::ContainmentMode::RequireApproval),
            semantic_risk_score: Some(vellaveto_types::SemanticRiskScore { value: risk }),
            counterfactual_review_required: risk >= 90,
            ..ApprovalContainmentContext::default()
        }
    }

    fn make_backend(prefix: &str) -> RedisBackend {
        RedisBackend::new("redis://127.0.0.1:6379", 1, prefix).unwrap()
    }

    fn err_str(result: Result<RedisBackend, ClusterError>) -> String {
        match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("Expected Err, got Ok"),
        }
    }

    // Key construction

    #[test]
    fn test_key_construction_basic() {
        let b = make_backend("vellaveto:");
        assert_eq!(b.test_key("suffix"), "vellaveto:suffix");
    }

    #[test]
    fn test_approval_key_format() {
        let b = make_backend("vellaveto:");
        assert_eq!(b.test_approval_key("abc-123"), "vellaveto:approval:abc-123");
    }

    #[test]
    fn test_dedup_key_format() {
        let b = make_backend("vellaveto:");
        assert_eq!(b.test_dedup_key("deadbeef"), "vellaveto:dedup:deadbeef");
    }

    #[test]
    fn test_pending_set_key_format() {
        let b = make_backend("vellaveto:");
        assert_eq!(b.test_pending_set_key(), "vellaveto:pending");
    }

    #[test]
    fn test_rate_limit_key_format() {
        let b = make_backend("vellaveto:");
        assert_eq!(
            b.test_rate_limit_key("per_ip", "10.0.0.1"),
            "vellaveto:rl:per_ip:10.0.0.1"
        );
    }

    #[test]
    fn test_key_construction_custom_prefix() {
        let b = make_backend("prod-us-east:");
        assert_eq!(b.test_approval_key("id1"), "prod-us-east:approval:id1");
        assert_eq!(
            b.test_rate_limit_key("burst", "user"),
            "prod-us-east:rl:burst:user"
        );
    }

    // Key prefix validation

    #[test]
    fn test_new_empty_prefix_rejected() {
        let msg = err_str(RedisBackend::new("redis://127.0.0.1:6379", 1, ""));
        assert!(msg.contains("must not be empty"));
    }

    #[test]
    fn test_new_overlong_prefix_rejected() {
        let msg = err_str(RedisBackend::new(
            "redis://127.0.0.1:6379",
            1,
            &"x".repeat(129),
        ));
        assert!(msg.contains("exceeds maximum"));
    }

    #[test]
    fn test_new_prefix_at_max_length_accepted() {
        assert!(RedisBackend::new("redis://127.0.0.1:6379", 1, &"x".repeat(128)).is_ok());
    }

    #[test]
    fn test_new_prefix_with_control_char_rejected() {
        let msg = err_str(RedisBackend::new(
            "redis://127.0.0.1:6379",
            1,
            "prefix\x00bad:",
        ));
        assert!(msg.contains("control characters"));
    }

    #[test]
    fn test_new_prefix_with_hash_tag_brace_rejected() {
        let msg = err_str(RedisBackend::new(
            "redis://127.0.0.1:6379",
            1,
            "prefix{slot}:",
        ));
        assert!(msg.contains("hash tag characters"));
    }

    #[test]
    fn test_new_prefix_with_unicode_format_char_rejected() {
        let msg = err_str(RedisBackend::new(
            "redis://127.0.0.1:6379",
            1,
            "vellaveto\u{200B}:",
        ));
        assert!(msg.contains("Unicode format characters"));
    }

    // TTL validation

    #[test]
    fn test_with_ttl_zero_rejected() {
        let msg = err_str(make_backend("v:").with_ttl_secs(0));
        assert!(msg.contains(">= 1 second"));
    }

    #[test]
    fn test_with_ttl_exceeds_30_days_rejected() {
        let msg = err_str(make_backend("v:").with_ttl_secs(86400 * 30 + 1));
        assert!(msg.contains("exceeds maximum"));
    }

    #[test]
    fn test_with_ttl_exactly_30_days_accepted() {
        assert!(make_backend("v:").with_ttl_secs(86400 * 30).is_ok());
    }

    #[test]
    fn test_with_ttl_one_second_accepted() {
        assert!(make_backend("v:").with_ttl_secs(1).is_ok());
    }

    // Max pending validation

    #[test]
    fn test_with_max_pending_zero_rejected() {
        let msg = err_str(make_backend("v:").with_max_pending(0));
        assert!(msg.contains(">= 1"));
    }

    #[test]
    fn test_with_max_pending_one_accepted() {
        assert!(make_backend("v:").with_max_pending(1).is_ok());
    }

    // Approval ID validation

    #[test]
    fn test_validate_approval_id_empty_rejected() {
        assert!(validate_approval_id_for_redis("").is_err());
    }

    #[test]
    fn test_validate_approval_id_valid() {
        assert!(validate_approval_id_for_redis("abc-123-def").is_ok());
    }

    #[test]
    fn test_validate_approval_id_overlong_rejected() {
        let r = validate_approval_id_for_redis(&"x".repeat(MAX_APPROVAL_ID_LEN + 1));
        assert!(r.unwrap_err().to_string().contains("maximum length"));
    }

    #[test]
    fn test_validate_approval_id_at_max_length_accepted() {
        assert!(validate_approval_id_for_redis(&"x".repeat(MAX_APPROVAL_ID_LEN)).is_ok());
    }

    #[test]
    fn test_validate_approval_id_control_char_rejected() {
        assert!(validate_approval_id_for_redis("id\x00bad").is_err());
        assert!(validate_approval_id_for_redis("id\nwith\nnewlines").is_err());
        assert!(validate_approval_id_for_redis("id\x7F_del").is_err());
    }

    #[test]
    fn test_validate_approval_id_hash_tag_brace_rejected() {
        let r = validate_approval_id_for_redis("id{slot}");
        assert!(r.unwrap_err().to_string().contains("'{' or '}'"));
    }

    #[test]
    fn test_validate_approval_id_unicode_format_char_rejected() {
        let r = validate_approval_id_for_redis(&format!("id\u{FEFF}bad"));
        assert!(r
            .unwrap_err()
            .to_string()
            .contains("Unicode format characters"));
    }

    // Resolver identity validation

    #[test]
    fn test_validate_resolver_identity_empty_rejected() {
        assert!(validate_resolver_identity("").is_err());
    }

    #[test]
    fn test_validate_resolver_identity_valid() {
        assert!(validate_resolver_identity("admin@corp.com").is_ok());
    }

    #[test]
    fn test_validate_resolver_identity_overlong_rejected() {
        let r = validate_resolver_identity(&"a".repeat(vellaveto_approval::MAX_IDENTITY_LEN + 1));
        assert!(r.unwrap_err().to_string().contains("maximum length"));
    }

    #[test]
    fn test_validate_resolver_identity_control_chars_rejected() {
        assert!(validate_resolver_identity("user\x00name").is_err());
    }

    #[test]
    fn test_validate_resolver_identity_unicode_format_rejected() {
        assert!(validate_resolver_identity("user\u{200D}name").is_err());
    }

    // Rate limit parameter validation

    #[test]
    fn test_validate_rate_limit_param_empty_rejected() {
        let r = validate_rate_limit_param("category", "");
        assert!(r.unwrap_err().to_string().contains("must not be empty"));
    }

    #[test]
    fn test_validate_rate_limit_param_valid() {
        assert!(validate_rate_limit_param("category", "per_ip").is_ok());
        assert!(validate_rate_limit_param("key", "10.0.0.1").is_ok());
    }

    #[test]
    fn test_validate_rate_limit_param_overlong_rejected() {
        let r = validate_rate_limit_param("key", &"x".repeat(MAX_RATE_LIMIT_PARAM_LEN + 1));
        assert!(r.unwrap_err().to_string().contains("maximum length"));
    }

    #[test]
    fn test_validate_rate_limit_param_control_char_rejected() {
        let r = validate_rate_limit_param("key", "val\x0Aue");
        assert!(r.unwrap_err().to_string().contains("control characters"));
    }

    #[test]
    fn test_validate_rate_limit_param_hash_tag_rejected() {
        let r = validate_rate_limit_param("key", "val{ue}");
        assert!(r.unwrap_err().to_string().contains("invalid characters"));
    }

    #[test]
    fn test_validate_rate_limit_param_unicode_format_rejected() {
        let r = validate_rate_limit_param("key", "val\u{200B}ue");
        assert!(r
            .unwrap_err()
            .to_string()
            .contains("Unicode format characters"));
    }

    #[test]
    fn test_validate_rate_limit_param_name_appears_in_error() {
        let r = validate_rate_limit_param("category", "");
        assert!(r.unwrap_err().to_string().contains("category"));
        let r = validate_rate_limit_param("key", "");
        assert!(r.unwrap_err().to_string().contains("key"));
    }

    // Dedup hash tests

    #[test]
    fn test_compute_dedup_hash_deterministic() {
        let a = make_action("read_file", "read");
        let h1 = RedisBackend::test_compute_dedup_hash(&a, "reason", None, None).unwrap();
        let h2 = RedisBackend::test_compute_dedup_hash(&a, "reason", None, None).unwrap();
        assert_eq!(h1, h2, "Dedup hash must be deterministic");
    }

    #[test]
    fn test_compute_dedup_hash_different_tool_different_hash() {
        let a1 = make_action("read_file", "read");
        let a2 = make_action("write_file", "read");
        let h1 = RedisBackend::test_compute_dedup_hash(&a1, "reason", None, None).unwrap();
        let h2 = RedisBackend::test_compute_dedup_hash(&a2, "reason", None, None).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_dedup_hash_different_function_different_hash() {
        let a1 = make_action("tool", "read");
        let a2 = make_action("tool", "write");
        let h1 = RedisBackend::test_compute_dedup_hash(&a1, "reason", None, None).unwrap();
        let h2 = RedisBackend::test_compute_dedup_hash(&a2, "reason", None, None).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_dedup_hash_different_reason_different_hash() {
        let a = make_action("tool", "func");
        let h1 = RedisBackend::test_compute_dedup_hash(&a, "reason1", None, None).unwrap();
        let h2 = RedisBackend::test_compute_dedup_hash(&a, "reason2", None, None).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_dedup_hash_none_vs_some_empty_different() {
        let a = make_action("tool", "func");
        let h1 = RedisBackend::test_compute_dedup_hash(&a, "reason", None, None).unwrap();
        let h2 = RedisBackend::test_compute_dedup_hash(&a, "reason", Some(""), None).unwrap();
        assert_ne!(h1, h2, "None vs Some(\"\") must produce different hashes");
    }

    #[test]
    fn test_compute_dedup_hash_different_requested_by_different_hash() {
        let a = make_action("tool", "func");
        let h1 = RedisBackend::test_compute_dedup_hash(&a, "reason", Some("alice"), None).unwrap();
        let h2 = RedisBackend::test_compute_dedup_hash(&a, "reason", Some("bob"), None).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_dedup_hash_different_session_ids_different_hash() {
        let a = make_action("tool", "func");
        let h1 =
            RedisBackend::test_compute_dedup_hash(&a, "reason", Some("alice"), Some("s1")).unwrap();
        let h2 =
            RedisBackend::test_compute_dedup_hash(&a, "reason", Some("alice"), Some("s2")).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_dedup_hash_none_vs_some_session_id_different() {
        let a = make_action("tool", "func");
        let h1 = RedisBackend::test_compute_dedup_hash(&a, "reason", Some("alice"), None).unwrap();
        let h2 =
            RedisBackend::test_compute_dedup_hash(&a, "reason", Some("alice"), Some("s1")).unwrap();
        assert_ne!(
            h1, h2,
            "None vs Some(session_id) must produce different hashes"
        );
    }

    #[test]
    fn test_compute_dedup_hash_normalizes_equivalent_containment_context() {
        let action = make_action("tool", "func");
        let first = make_containment_context(90);
        let second = ApprovalContainmentContext {
            semantic_taint: vec![
                vellaveto_types::SemanticTaint::IntegrityFailed,
                vellaveto_types::SemanticTaint::Quarantined,
            ],
            lineage_channels: vec![
                vellaveto_types::ContextChannel::ToolOutput,
                vellaveto_types::ContextChannel::CommandLike,
            ],
            ..make_containment_context(90)
        };

        let h1 = RedisBackend::test_compute_dedup_hash_with_context(
            &action,
            "reason",
            Some("alice"),
            Some("session-1"),
            Some(&first),
        )
        .unwrap();
        let h2 = RedisBackend::test_compute_dedup_hash_with_context(
            &action,
            "reason",
            Some("alice"),
            Some("session-1"),
            Some(&second),
        )
        .unwrap();

        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_dedup_hash_distinguishes_containment_context() {
        let action = make_action("tool", "func");
        let low_risk = make_containment_context(40);
        let high_risk = make_containment_context(95);

        let h1 = RedisBackend::test_compute_dedup_hash_with_context(
            &action,
            "reason",
            Some("alice"),
            Some("session-1"),
            Some(&low_risk),
        )
        .unwrap();
        let h2 = RedisBackend::test_compute_dedup_hash_with_context(
            &action,
            "reason",
            Some("alice"),
            Some("session-1"),
            Some(&high_risk),
        )
        .unwrap();

        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_dedup_hash_sorted_domains() {
        let mut a1 = make_action("tool", "func");
        a1.target_domains = vec!["b.com".into(), "a.com".into()];
        let mut a2 = make_action("tool", "func");
        a2.target_domains = vec!["a.com".into(), "b.com".into()];
        let h1 = RedisBackend::test_compute_dedup_hash(&a1, "reason", None, None).unwrap();
        let h2 = RedisBackend::test_compute_dedup_hash(&a2, "reason", None, None).unwrap();
        assert_eq!(h1, h2, "Different domain order must produce same hash");
    }

    #[test]
    fn test_compute_dedup_hash_sorted_paths() {
        let mut a1 = make_action("tool", "func");
        a1.target_paths = vec!["/z/file".into(), "/a/file".into()];
        let mut a2 = make_action("tool", "func");
        a2.target_paths = vec!["/a/file".into(), "/z/file".into()];
        let h1 = RedisBackend::test_compute_dedup_hash(&a1, "reason", None, None).unwrap();
        let h2 = RedisBackend::test_compute_dedup_hash(&a2, "reason", None, None).unwrap();
        assert_eq!(h1, h2, "Different path order must produce same hash");
    }

    #[test]
    fn test_compute_dedup_hash_sorted_ips() {
        let mut a1 = make_action("tool", "func");
        a1.resolved_ips = vec!["10.0.0.2".into(), "10.0.0.1".into()];
        let mut a2 = make_action("tool", "func");
        a2.resolved_ips = vec!["10.0.0.1".into(), "10.0.0.2".into()];
        let h1 = RedisBackend::test_compute_dedup_hash(&a1, "reason", None, None).unwrap();
        let h2 = RedisBackend::test_compute_dedup_hash(&a2, "reason", None, None).unwrap();
        assert_eq!(h1, h2, "Different IP order must produce same hash");
    }

    #[test]
    fn test_compute_dedup_hash_nfkc_normalization() {
        let a1 = make_action("abc", "func");
        let a2 = make_action("\u{FF41}bc", "func"); // fullwidth 'a'
        let h1 = RedisBackend::test_compute_dedup_hash(&a1, "reason", None, None).unwrap();
        let h2 = RedisBackend::test_compute_dedup_hash(&a2, "reason", None, None).unwrap();
        assert_eq!(h1, h2, "NFKC-equivalent tool names must produce same hash");
    }

    #[test]
    fn test_compute_dedup_hash_case_insensitive() {
        let a1 = make_action("tool", "func");
        let a2 = make_action("TOOL", "FUNC");
        let h1 = RedisBackend::test_compute_dedup_hash(&a1, "reason", None, None).unwrap();
        let h2 = RedisBackend::test_compute_dedup_hash(&a2, "reason", None, None).unwrap();
        assert_eq!(h1, h2, "Case-different names must produce same hash");
    }

    #[test]
    fn test_compute_dedup_hash_is_hex_string() {
        let a = make_action("tool", "func");
        let h = RedisBackend::test_compute_dedup_hash(&a, "reason", None, None).unwrap();
        assert_eq!(h.len(), 64, "SHA-256 hex digest must be 64 chars");
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit()),
            "Hash must be valid hex"
        );
    }

    #[tokio::test]
    async fn test_approval_create_rejects_empty_session_id_before_redis() {
        let backend = make_backend("vellaveto:");
        let result = backend
            .approval_create(
                make_action("tool", "func"),
                "needs review".to_string(),
                Some("requester".to_string()),
                Some(String::new()),
                None,
            )
            .await;
        assert!(matches!(result, Err(ClusterError::Validation(_))));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("session_id must not be empty"));
    }

    #[tokio::test]
    async fn test_approval_create_rejects_control_chars_in_session_id_before_redis() {
        let backend = make_backend("vellaveto:");
        let result = backend
            .approval_create(
                make_action("tool", "func"),
                "needs review".to_string(),
                Some("requester".to_string()),
                Some("session\tbad".to_string()),
                None,
            )
            .await;
        assert!(matches!(result, Err(ClusterError::Validation(_))));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("session_id contains control characters"));
    }

    #[tokio::test]
    async fn test_approval_create_rejects_non_hex_fingerprint_before_redis() {
        let backend = make_backend("vellaveto:");
        let result = backend
            .approval_create(
                make_action("tool", "func"),
                "needs review".to_string(),
                Some("requester".to_string()),
                Some("session-a".to_string()),
                Some("not-hex".to_string()),
            )
            .await;
        assert!(matches!(result, Err(ClusterError::Validation(_))));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("action_fingerprint must be hex-encoded"));
    }

    // Constants sanity checks

    #[test]
    fn test_default_ttl_is_15_minutes() {
        assert_eq!(DEFAULT_TTL_SECS, 900);
    }

    #[test]
    fn test_default_max_pending_is_10k() {
        assert_eq!(DEFAULT_MAX_PENDING, 10_000);
    }

    #[test]
    fn test_max_approval_fetch_is_10k() {
        assert_eq!(MAX_APPROVAL_FETCH, 10_000);
    }

    #[test]
    fn test_max_approval_id_len_is_512() {
        assert_eq!(MAX_APPROVAL_ID_LEN, 512);
    }

    #[test]
    fn test_max_rate_limit_param_len_is_512() {
        assert_eq!(MAX_RATE_LIMIT_PARAM_LEN, 512);
    }

    // ── R244-CLUSTER-1: TLS enforcement tests ───────────────────────────

    #[test]
    fn test_r244_remote_redis_without_tls_rejected() {
        let result = RedisBackend::new("redis://remote-host:6379", 4, "vv:");
        let err = match result {
            Err(e) => format!("{e}"),
            Ok(_) => panic!("expected TLS validation error for plaintext remote Redis"),
        };
        assert!(
            err.contains("rediss://"),
            "Expected TLS enforcement error, got: {err}"
        );
    }

    #[test]
    fn test_r244_remote_redis_with_tls_accepted() {
        // rediss:// URL will fail at pool creation (no actual Redis), but
        // should NOT fail the TLS validation check.
        let result = RedisBackend::new("rediss://secure-host:6380", 4, "vv:");
        // The error should be about connection, not validation.
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(
                !msg.contains("rediss://"),
                "TLS validation should pass for rediss:// URL"
            );
        }
    }

    #[test]
    fn test_r244_localhost_redis_without_tls_accepted() {
        // localhost connections are exempt from TLS requirement.
        // Will fail at pool creation but should NOT fail TLS validation.
        let result = RedisBackend::new("redis://127.0.0.1:6379", 4, "vv:");
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(
                !msg.contains("rediss://"),
                "Localhost should be exempt from TLS requirement"
            );
        }
    }

    #[test]
    fn test_r244_localhost_name_redis_without_tls_accepted() {
        let result = RedisBackend::new("redis://localhost:6379", 4, "vv:");
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(
                !msg.contains("rediss://"),
                "localhost should be exempt from TLS requirement"
            );
        }
    }
}
