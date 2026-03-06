// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Decision cache for policy evaluation results.
//!
//! Provides an LRU-based cache that stores [`Verdict`] results keyed by
//! [`Action`] identity (tool, function, paths, domains) and optional
//! agent identity. Cached verdicts are invalidated when the policy
//! generation counter is bumped (e.g., on policy reload).
//!
//! # Security
//!
//! - **Context-dependent results are NOT cached.** When the
//!   [`EvaluationContext`] carries session-dependent state (call counts,
//!   previous actions, time windows, call chains, capability tokens, session
//!   state), the result depends on mutable session state and must be
//!   evaluated fresh every time.
//! - **Fail-closed on lock poisoning.** If the internal `RwLock` is
//!   poisoned, `get` returns `None` (cache miss) and `insert` is a no-op.
//!   This ensures a poisoned cache never serves stale Allow verdicts.
//! - **Bounded memory.** The cache enforces [`MAX_CACHE_ENTRIES`] and
//!   evicts the least-recently-used entry when at capacity.
//! - **Counters use `saturating_add`.** Hit/miss/eviction counters cannot
//!   wrap to zero.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use vellaveto_types::{Action, EvaluationContext, Verdict};

/// Absolute upper bound on cache entries to prevent memory exhaustion.
pub const MAX_CACHE_ENTRIES: usize = 100_000;

/// Minimum allowed TTL in seconds.
pub const MIN_TTL_SECS: u64 = 1;

/// Maximum allowed TTL in seconds (1 hour).
pub const MAX_TTL_SECS: u64 = 3600;

/// Hash-based key for cached policy decisions.
///
/// Each field is a pre-computed `u64` hash of the corresponding [`Action`]
/// component. This avoids storing the full action data in the cache and
/// provides O(1) key comparison.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct CacheKey {
    tool_hash: u64,
    function_hash: u64,
    paths_hash: u64,
    domains_hash: u64,
    /// SECURITY (R228-ENG-1): Include resolved IPs in cache key to prevent
    /// DNS rebinding attacks from hitting a stale Allow verdict cached for
    /// a different IP resolution of the same domain.
    resolved_ips_hash: u64,
    identity_hash: u64,
}

/// A single cached verdict with insertion metadata.
struct CacheEntry {
    verdict: Verdict,
    inserted_at: Instant,
    generation: u64,
    /// Monotonic counter tracking last access time for LRU eviction.
    last_accessed: u64,
}

/// Aggregate cache performance statistics.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub insertions: u64,
    pub invalidations: u64,
}

/// LRU decision cache for policy evaluation results.
///
/// Thread-safe via `RwLock`. Lock poisoning is handled fail-closed
/// (cache miss on read, no-op on write).
pub struct DecisionCache {
    cache: RwLock<HashMap<CacheKey, CacheEntry>>,
    max_entries: usize,
    ttl: Duration,
    policy_generation: AtomicU64,
    // Stats counters — all use saturating_add to prevent wrap-around.
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    insertions: AtomicU64,
    invalidations: AtomicU64,
    /// Monotonic counter for LRU ordering.
    access_counter: AtomicU64,
}

impl std::fmt::Debug for DecisionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionCache")
            .field("max_entries", &self.max_entries)
            .field("ttl", &self.ttl)
            .field(
                "policy_generation",
                &self.policy_generation.load(Ordering::SeqCst),
            )
            .field(
                "current_size",
                &self.cache.read().map(|c| c.len()).unwrap_or_default(),
            )
            .finish()
    }
}

impl DecisionCache {
    /// Create a new decision cache.
    ///
    /// # Arguments
    ///
    /// * `max_entries` — Maximum number of cached verdicts. Clamped to
    ///   `[1, MAX_CACHE_ENTRIES]`.
    /// * `ttl` — Time-to-live for each entry. Clamped to
    ///   `[MIN_TTL_SECS, MAX_TTL_SECS]` seconds.
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        let clamped_max = max_entries.clamp(1, MAX_CACHE_ENTRIES);
        let clamped_ttl_secs = ttl.as_secs().clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        let clamped_ttl = Duration::from_secs(clamped_ttl_secs);

        Self {
            cache: RwLock::new(HashMap::with_capacity(clamped_max.min(1024))),
            max_entries: clamped_max,
            ttl: clamped_ttl,
            policy_generation: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            insertions: AtomicU64::new(0),
            invalidations: AtomicU64::new(0),
            access_counter: AtomicU64::new(0),
        }
    }

    /// Look up a cached verdict for the given action and optional context.
    ///
    /// Returns `None` (cache miss) if:
    /// - The context is session-dependent (non-cacheable)
    /// - No entry exists for this action
    /// - The entry's TTL has expired
    /// - The entry's policy generation is stale
    /// - The internal lock is poisoned (fail-closed)
    pub fn get(&self, action: &Action, context: Option<&EvaluationContext>) -> Option<Verdict> {
        if !Self::is_cacheable_context(context) {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let key = Self::build_key(action, context);
        let current_gen = self.policy_generation.load(Ordering::SeqCst);

        // Fail-closed: poisoned lock → cache miss
        let cache = match self.cache.read() {
            Ok(guard) => guard,
            Err(_) => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };

        match cache.get(&key) {
            Some(entry)
                if entry.generation == current_gen && entry.inserted_at.elapsed() < self.ttl =>
            {
                self.hits.fetch_add(1, Ordering::Relaxed);
                // Note: We do not update last_accessed here under a read lock
                // to avoid upgrading to a write lock on every hit. The LRU
                // eviction is approximate — this is acceptable for a cache
                // that also has TTL-based expiry.
                Some(entry.verdict.clone())
            }
            _ => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Insert a verdict into the cache for the given action.
    ///
    /// If the context is session-dependent, this is a no-op (the result
    /// should not be cached). If the cache is at capacity, the
    /// least-recently-used entry is evicted.
    ///
    /// No-op if the internal lock is poisoned (fail-closed: we do not
    /// serve stale data from a potentially corrupted map).
    pub fn insert(&self, action: &Action, context: Option<&EvaluationContext>, verdict: &Verdict) {
        if !Self::is_cacheable_context(context) {
            return;
        }

        let key = Self::build_key(action, context);
        let current_gen = self.policy_generation.load(Ordering::SeqCst);
        // SECURITY (R229-ENG-7): SeqCst for LRU ordering counter — Relaxed could
        // allow reordering that causes incorrect eviction of recently-used entries.
        let access_order = self.access_counter.fetch_add(1, Ordering::SeqCst);

        // Fail-closed: poisoned lock → no-op
        let mut cache = match self.cache.write() {
            Ok(guard) => guard,
            Err(_) => return,
        };

        // Evict LRU if at capacity and this is a new key
        if cache.len() >= self.max_entries && !cache.contains_key(&key) {
            self.evict_lru(&mut cache);
        }

        cache.insert(
            key,
            CacheEntry {
                verdict: verdict.clone(),
                inserted_at: Instant::now(),
                generation: current_gen,
                last_accessed: access_order,
            },
        );
        self.insertions.fetch_add(1, Ordering::Relaxed);
    }

    /// Invalidate all cached entries by bumping the policy generation counter.
    ///
    /// Existing entries remain in memory but will be treated as stale on
    /// the next `get` call. This is O(1) — no iteration required.
    pub fn invalidate(&self) {
        self.policy_generation.fetch_add(1, Ordering::SeqCst);
        self.invalidations.fetch_add(1, Ordering::Relaxed);
    }

    /// Return aggregate cache performance statistics.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            insertions: self.insertions.load(Ordering::Relaxed),
            invalidations: self.invalidations.load(Ordering::Relaxed),
        }
    }

    /// Return the number of entries currently in the cache.
    ///
    /// Returns 0 if the lock is poisoned (fail-closed).
    pub fn len(&self) -> usize {
        self.cache.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Returns `true` if the cache contains no entries.
    ///
    /// Returns `true` if the lock is poisoned (fail-closed).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Determine whether the evaluation context allows caching.
    ///
    /// Context-dependent results (those relying on mutable session state)
    /// must NOT be cached because the verdict may change between calls
    /// even for the same action.
    fn is_cacheable_context(context: Option<&EvaluationContext>) -> bool {
        match context {
            None => true,
            Some(ctx) => {
                // Session-dependent fields that make caching unsafe:
                // - call_counts: changes every call
                // - previous_actions: changes every call
                // - call_chain: may vary per request path
                // - timestamp: time-window policies depend on wall clock
                // - capability_token: token-specific, may expire
                // - session_state: changes with session lifecycle
                // - verification_tier: may change mid-session
                //
                // Cacheable fields (stable within a session):
                // - agent_id: identity doesn't change
                // - agent_identity: attested identity doesn't change
                // - tenant_id: tenant doesn't change
                ctx.timestamp.is_none()
                    && ctx.call_counts.is_empty()
                    && ctx.previous_actions.is_empty()
                    && ctx.call_chain.is_empty()
                    && ctx.capability_token.is_none()
                    && ctx.session_state.is_none()
                    && ctx.verification_tier.is_none()
            }
        }
    }

    /// Build a cache key from an action and optional context.
    ///
    /// SECURITY (R227-ENG-1, R228-ENG-4): Tool and function names are normalized
    /// through normalize_full() (NFKC + lowercase + homoglyph mapping) before
    /// hashing to ensure cache key consistency with engine evaluation. Without this,
    /// "FileRead", "fileread", and "ﬁleread" (fullwidth) produce different cache keys,
    /// causing cache pollution and inconsistent verdicts for the same logical tool.
    fn build_key(action: &Action, context: Option<&EvaluationContext>) -> CacheKey {
        CacheKey {
            tool_hash: Self::hash_str(&crate::normalize::normalize_full(&action.tool)),
            function_hash: Self::hash_str(&crate::normalize::normalize_full(&action.function)),
            // SECURITY (R229-ENG-1): Normalize paths and domains before hashing so that
            // case/Unicode variants of the same logical target share a cache entry.
            paths_hash: Self::hash_sorted_normalized_strs(&action.target_paths),
            domains_hash: Self::hash_sorted_normalized_strs(&action.target_domains),
            resolved_ips_hash: Self::hash_sorted_strs(&action.resolved_ips),
            identity_hash: Self::hash_identity(context),
        }
    }

    /// Hash a single string using `DefaultHasher`.
    fn hash_str(s: &str) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish()
    }

    /// Hash a sorted slice of strings for order-independent comparison.
    ///
    /// Sorts a clone of the slice so that `["a", "b"]` and `["b", "a"]`
    /// produce the same hash. Used for resolved_ips which are already canonical.
    fn hash_sorted_strs(strs: &[String]) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        let mut sorted: Vec<&str> = strs.iter().map(|s| s.as_str()).collect();
        sorted.sort_unstable();
        sorted.len().hash(&mut hasher);
        for s in &sorted {
            s.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Hash a sorted slice of strings after normalizing each entry.
    ///
    /// SECURITY (R229-ENG-1): target_paths and target_domains must be normalized
    /// before hashing to prevent cache pollution — e.g., "/TMP/FOO" and "/tmp/foo"
    /// must produce the same cache key since the engine evaluates them identically.
    fn hash_sorted_normalized_strs(strs: &[String]) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        let mut normalized: Vec<String> = strs
            .iter()
            .map(|s| crate::normalize::normalize_full(s))
            .collect();
        normalized.sort_unstable();
        normalized.len().hash(&mut hasher);
        for s in &normalized {
            s.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Hash the identity components of an evaluation context.
    ///
    /// Hashes all identity-affecting fields: `agent_id`, `tenant_id`,
    /// and the full `agent_identity` (issuer, subject, audience, claims).
    fn hash_identity(context: Option<&EvaluationContext>) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        match context {
            None => {
                0u8.hash(&mut hasher); // sentinel for no context
            }
            Some(ctx) => {
                1u8.hash(&mut hasher); // sentinel for present context
                                       // SECURITY (R226-ENG-1): Hash Option<String> directly, not unwrap_or("").
                                       // Previously, None and Some("") hashed to the same value, causing
                                       // cross-tenant cache collisions when one tenant has agent_id=None
                                       // and another has agent_id=Some("").
                ctx.agent_id.hash(&mut hasher);
                ctx.tenant_id.hash(&mut hasher);
                if let Some(ref identity) = ctx.agent_identity {
                    2u8.hash(&mut hasher); // sentinel for identity present
                    identity.issuer.hash(&mut hasher);
                    identity.subject.hash(&mut hasher);
                    // R230-ENG-2: Include audience and claims in cache key.
                    // AgentIdentityMatch constraints check required_claims and
                    // audience — different claims/audience must produce different
                    // cache entries to prevent cross-identity cache collisions.
                    identity.audience.len().hash(&mut hasher);
                    for aud in &identity.audience {
                        aud.hash(&mut hasher);
                    }
                    // Hash claims deterministically: sort by key
                    let mut claim_keys: Vec<&String> = identity.claims.keys().collect();
                    claim_keys.sort_unstable();
                    claim_keys.len().hash(&mut hasher);
                    for key in &claim_keys {
                        key.hash(&mut hasher);
                        // Hash the JSON string representation for Value
                        if let Ok(val_str) = serde_json::to_string(&identity.claims[*key]) {
                            val_str.hash(&mut hasher);
                        }
                    }
                } else {
                    3u8.hash(&mut hasher); // sentinel for identity absent
                }
            }
        }
        hasher.finish()
    }

    /// Evict the least-recently-used entry from the cache.
    ///
    /// Scans all entries to find the one with the lowest `last_accessed`
    /// counter. This is O(n) but only called when the cache is full,
    /// which is bounded by `max_entries`.
    fn evict_lru(&self, cache: &mut HashMap<CacheKey, CacheEntry>) {
        let lru_key = cache
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(key, _)| key.clone());

        if let Some(key) = lru_key {
            cache.remove(&key);
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use std::thread;
    use vellaveto_types::EvaluationContext;

    /// Helper: create a simple action.
    fn make_action(tool: &str, function: &str) -> Action {
        Action::new(tool.to_string(), function.to_string(), json!({}))
    }

    /// Helper: create an action with target paths and domains.
    fn make_action_with_targets(
        tool: &str,
        function: &str,
        paths: Vec<&str>,
        domains: Vec<&str>,
    ) -> Action {
        Action {
            tool: tool.to_string(),
            function: function.to_string(),
            parameters: json!({}),
            target_paths: paths.into_iter().map(|s| s.to_string()).collect(),
            target_domains: domains.into_iter().map(|s| s.to_string()).collect(),
            resolved_ips: vec![],
        }
    }

    /// Helper: create a cacheable context (only stable identity fields).
    fn make_cacheable_context(agent_id: &str) -> EvaluationContext {
        EvaluationContext {
            agent_id: Some(agent_id.to_string()),
            tenant_id: None,
            timestamp: None,
            agent_identity: None,
            call_counts: HashMap::new(),
            previous_actions: vec![],
            call_chain: vec![],
            verification_tier: None,
            capability_token: None,
            session_state: None,
        }
    }

    /// Helper: create a non-cacheable context (has session-dependent fields).
    fn make_noncacheable_context() -> EvaluationContext {
        let mut counts = HashMap::new();
        counts.insert("bash".to_string(), 5);
        EvaluationContext {
            agent_id: Some("agent-1".to_string()),
            tenant_id: None,
            timestamp: None,
            agent_identity: None,
            call_counts: counts,
            previous_actions: vec!["read_file".to_string()],
            call_chain: vec![],
            verification_tier: None,
            capability_token: None,
            session_state: None,
        }
    }

    #[test]
    fn test_cache_hit_and_miss() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));
        let action = make_action("read_file", "read");
        let verdict = Verdict::Allow;

        // Miss before insert
        assert!(cache.get(&action, None).is_none());
        assert_eq!(cache.stats().misses, 1);

        // Insert and hit
        cache.insert(&action, None, &verdict);
        let result = cache.get(&action, None);
        assert!(result.is_some());
        assert_eq!(result, Some(Verdict::Allow));
        assert_eq!(cache.stats().hits, 1);
        assert_eq!(cache.stats().insertions, 1);

        // Different action is a miss
        let other_action = make_action("write_file", "write");
        assert!(cache.get(&other_action, None).is_none());
        assert_eq!(cache.stats().misses, 2);
    }

    #[test]
    fn test_ttl_expiry() {
        // Use a very short TTL (minimum 1 second)
        let cache = DecisionCache::new(100, Duration::from_secs(1));
        let action = make_action("read_file", "read");
        let verdict = Verdict::Allow;

        cache.insert(&action, None, &verdict);
        assert!(cache.get(&action, None).is_some());

        // Wait for TTL to expire
        thread::sleep(Duration::from_millis(1100));

        // Should be a miss after TTL
        assert!(cache.get(&action, None).is_none());
    }

    #[test]
    fn test_invalidation_on_policy_change() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));
        let action = make_action("read_file", "read");
        let verdict = Verdict::Allow;

        cache.insert(&action, None, &verdict);
        assert!(cache.get(&action, None).is_some());

        // Invalidate (simulates policy reload)
        cache.invalidate();
        assert_eq!(cache.stats().invalidations, 1);

        // Previous entry is now stale
        assert!(cache.get(&action, None).is_none());

        // New insert under new generation works
        let deny = Verdict::Deny {
            reason: "blocked".to_string(),
        };
        cache.insert(&action, None, &deny);
        let result = cache.get(&action, None);
        assert!(matches!(result, Some(Verdict::Deny { .. })));
    }

    #[test]
    fn test_lru_eviction() {
        let cache = DecisionCache::new(3, Duration::from_secs(60));

        // Fill cache to capacity
        for i in 0..3 {
            let action = make_action(&format!("tool_{i}"), "func");
            cache.insert(&action, None, &Verdict::Allow);
        }
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.stats().evictions, 0);

        // Insert a 4th entry — should evict LRU (tool_0)
        let action_new = make_action("tool_new", "func");
        cache.insert(&action_new, None, &Verdict::Allow);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.stats().evictions, 1);

        // The new entry should be present
        assert!(cache.get(&action_new, None).is_some());

        // The evicted entry (tool_0) should be gone
        let action_0 = make_action("tool_0", "func");
        assert!(cache.get(&action_0, None).is_none());
    }

    #[test]
    fn test_stats_tracking() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));
        let action = make_action("read_file", "read");

        // Initial stats are zero
        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.evictions, 0);
        assert_eq!(stats.insertions, 0);
        assert_eq!(stats.invalidations, 0);

        // Miss
        cache.get(&action, None);
        assert_eq!(cache.stats().misses, 1);

        // Insert
        cache.insert(&action, None, &Verdict::Allow);
        assert_eq!(cache.stats().insertions, 1);

        // Hit
        cache.get(&action, None);
        assert_eq!(cache.stats().hits, 1);

        // Invalidate
        cache.invalidate();
        assert_eq!(cache.stats().invalidations, 1);
    }

    #[test]
    fn test_context_dependent_not_cached() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));
        let action = make_action("bash", "execute");
        let verdict = Verdict::Allow;
        let ctx = make_noncacheable_context();

        // Insert with non-cacheable context is a no-op
        cache.insert(&action, Some(&ctx), &verdict);
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.stats().insertions, 0);

        // Get with non-cacheable context is always a miss
        assert!(cache.get(&action, Some(&ctx)).is_none());
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn test_context_dependent_timestamp_not_cached() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));
        let action = make_action("bash", "execute");
        let verdict = Verdict::Allow;

        let ctx = EvaluationContext {
            timestamp: Some("2026-01-01T12:00:00Z".to_string()),
            agent_id: None,
            tenant_id: None,
            agent_identity: None,
            call_counts: HashMap::new(),
            previous_actions: vec![],
            call_chain: vec![],
            verification_tier: None,
            capability_token: None,
            session_state: None,
        };

        cache.insert(&action, Some(&ctx), &verdict);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_context_dependent_session_state_not_cached() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));
        let action = make_action("bash", "execute");
        let verdict = Verdict::Allow;

        let ctx = EvaluationContext {
            session_state: Some("active".to_string()),
            agent_id: None,
            tenant_id: None,
            timestamp: None,
            agent_identity: None,
            call_counts: HashMap::new(),
            previous_actions: vec![],
            call_chain: vec![],
            verification_tier: None,
            capability_token: None,
        };

        cache.insert(&action, Some(&ctx), &verdict);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cacheable_context_with_identity() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));
        let action = make_action("read_file", "read");
        let verdict = Verdict::Allow;
        let ctx = make_cacheable_context("agent-42");

        // Cacheable context with only agent_id should work
        cache.insert(&action, Some(&ctx), &verdict);
        assert_eq!(cache.len(), 1);

        let result = cache.get(&action, Some(&ctx));
        assert_eq!(result, Some(Verdict::Allow));
    }

    #[test]
    fn test_cache_key_collision_resistance() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));

        // These actions differ only in tool name
        let action_a = make_action("read_file", "execute");
        let action_b = make_action("write_file", "execute");

        cache.insert(&action_a, None, &Verdict::Allow);
        cache.insert(
            &action_b,
            None,
            &Verdict::Deny {
                reason: "blocked".to_string(),
            },
        );

        assert_eq!(cache.get(&action_a, None), Some(Verdict::Allow));
        assert!(matches!(
            cache.get(&action_b, None),
            Some(Verdict::Deny { .. })
        ));

        // Actions with different target paths
        let action_c = make_action_with_targets("read", "exec", vec!["/tmp/a"], vec![]);
        let action_d = make_action_with_targets("read", "exec", vec!["/tmp/b"], vec![]);

        cache.insert(&action_c, None, &Verdict::Allow);
        cache.insert(
            &action_d,
            None,
            &Verdict::Deny {
                reason: "path denied".to_string(),
            },
        );

        assert_eq!(cache.get(&action_c, None), Some(Verdict::Allow));
        assert!(matches!(
            cache.get(&action_d, None),
            Some(Verdict::Deny { .. })
        ));

        // Actions with different domains
        let action_e = make_action_with_targets("http", "get", vec![], vec!["example.com"]);
        let action_f = make_action_with_targets("http", "get", vec![], vec!["evil.com"]);

        cache.insert(&action_e, None, &Verdict::Allow);
        cache.insert(
            &action_f,
            None,
            &Verdict::Deny {
                reason: "domain denied".to_string(),
            },
        );

        assert_eq!(cache.get(&action_e, None), Some(Verdict::Allow));
        assert!(matches!(
            cache.get(&action_f, None),
            Some(Verdict::Deny { .. })
        ));

        // Different identity contexts produce different keys
        let ctx_agent_1 = make_cacheable_context("agent-1");
        let ctx_agent_2 = make_cacheable_context("agent-2");
        let action_g = make_action("tool", "func");

        cache.insert(&action_g, Some(&ctx_agent_1), &Verdict::Allow);
        cache.insert(
            &action_g,
            Some(&ctx_agent_2),
            &Verdict::Deny {
                reason: "wrong agent".to_string(),
            },
        );

        assert_eq!(
            cache.get(&action_g, Some(&ctx_agent_1)),
            Some(Verdict::Allow)
        );
        assert!(matches!(
            cache.get(&action_g, Some(&ctx_agent_2)),
            Some(Verdict::Deny { .. })
        ));
    }

    #[test]
    fn test_max_entries_bound() {
        // Request more than MAX_CACHE_ENTRIES — should be clamped
        let cache = DecisionCache::new(MAX_CACHE_ENTRIES + 1000, Duration::from_secs(60));
        assert_eq!(cache.max_entries, MAX_CACHE_ENTRIES);

        // Request 0 — should be clamped to 1
        let cache_min = DecisionCache::new(0, Duration::from_secs(60));
        assert_eq!(cache_min.max_entries, 1);
    }

    #[test]
    fn test_ttl_bounds_clamped() {
        // TTL below minimum is clamped
        let cache = DecisionCache::new(100, Duration::from_secs(0));
        assert_eq!(cache.ttl, Duration::from_secs(MIN_TTL_SECS));

        // TTL above maximum is clamped
        let cache_max = DecisionCache::new(100, Duration::from_secs(MAX_TTL_SECS + 1000));
        assert_eq!(cache_max.ttl, Duration::from_secs(MAX_TTL_SECS));
    }

    #[test]
    fn test_is_empty() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));
        assert!(cache.is_empty());

        let action = make_action("tool", "func");
        cache.insert(&action, None, &Verdict::Allow);
        assert!(!cache.is_empty());
    }

    #[test]
    fn test_deny_verdict_cached() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));
        let action = make_action("bash", "execute");
        let verdict = Verdict::Deny {
            reason: "dangerous tool".to_string(),
        };

        cache.insert(&action, None, &verdict);
        let result = cache.get(&action, None);
        assert!(matches!(result, Some(Verdict::Deny { ref reason }) if reason == "dangerous tool"));
    }

    #[test]
    fn test_require_approval_verdict_cached() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));
        let action = make_action("deploy", "production");
        let verdict = Verdict::RequireApproval {
            reason: "needs human review".to_string(),
        };

        cache.insert(&action, None, &verdict);
        let result = cache.get(&action, None);
        assert!(
            matches!(result, Some(Verdict::RequireApproval { ref reason }) if reason == "needs human review")
        );
    }

    #[test]
    fn test_overwrite_existing_entry() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));
        let action = make_action("tool", "func");

        cache.insert(&action, None, &Verdict::Allow);
        assert_eq!(cache.get(&action, None), Some(Verdict::Allow));

        // Overwrite with Deny
        let deny = Verdict::Deny {
            reason: "now denied".to_string(),
        };
        cache.insert(&action, None, &deny);
        assert!(matches!(
            cache.get(&action, None),
            Some(Verdict::Deny { .. })
        ));

        // Length should still be 1 (overwrite, not add)
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_path_order_independence() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));

        // Same paths in different order should produce the same cache key
        let action_a = make_action_with_targets("read", "exec", vec!["/a", "/b"], vec![]);
        let action_b = make_action_with_targets("read", "exec", vec!["/b", "/a"], vec![]);

        cache.insert(&action_a, None, &Verdict::Allow);
        // Should be a hit because paths are sorted before hashing
        assert_eq!(cache.get(&action_b, None), Some(Verdict::Allow));
    }

    #[test]
    fn test_domain_order_independence() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));

        let action_a = make_action_with_targets("http", "get", vec![], vec!["a.com", "b.com"]);
        let action_b = make_action_with_targets("http", "get", vec![], vec!["b.com", "a.com"]);

        cache.insert(&action_a, None, &Verdict::Allow);
        assert_eq!(cache.get(&action_b, None), Some(Verdict::Allow));
    }

    #[test]
    fn test_multiple_invalidations() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));
        let action = make_action("tool", "func");

        cache.insert(&action, None, &Verdict::Allow);
        cache.invalidate();
        cache.invalidate();
        cache.invalidate();

        assert_eq!(cache.stats().invalidations, 3);
        assert!(cache.get(&action, None).is_none());

        // Insert after multiple invalidations still works
        cache.insert(&action, None, &Verdict::Allow);
        assert!(cache.get(&action, None).is_some());
    }

    #[test]
    fn test_debug_does_not_leak_entries() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));
        let action = make_action("secret_tool", "func");
        cache.insert(&action, None, &Verdict::Allow);

        let debug_output = format!("{:?}", cache);
        // Debug output should show metadata, not entry contents
        assert!(debug_output.contains("max_entries"));
        assert!(debug_output.contains("current_size"));
        assert!(!debug_output.contains("secret_tool"));
    }

    /// R227-ENG-1: Cache keys are case-insensitive for tool/function names.
    #[test]
    fn test_r227_cache_key_case_insensitive() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));
        let action_lower = make_action("file_read", "get_content");
        let action_upper = make_action("File_Read", "Get_Content");
        let action_mixed = make_action("FILE_READ", "GET_CONTENT");

        cache.insert(&action_lower, None, &Verdict::Allow);

        // All case variants should hit the same cache entry
        assert!(
            cache.get(&action_upper, None).is_some(),
            "Mixed-case tool name should match lowercased cache key"
        );
        assert!(
            cache.get(&action_mixed, None).is_some(),
            "All-caps tool name should match lowercased cache key"
        );
    }

    /// R228-ENG-1: Different resolved IPs must produce different cache keys.
    /// This prevents DNS rebinding attacks from hitting a stale Allow verdict
    /// cached for a different IP resolution of the same domain.
    #[test]
    fn test_r228_resolved_ips_in_cache_key() {
        let cache = DecisionCache::new(100, Duration::from_secs(60));

        let mut action_public = Action::new("tool", "fn", serde_json::json!({}));
        action_public.target_domains.push("attacker.com".into());
        action_public.resolved_ips.push("1.2.3.4".into());

        let mut action_metadata = Action::new("tool", "fn", serde_json::json!({}));
        action_metadata.target_domains.push("attacker.com".into());
        action_metadata.resolved_ips.push("169.254.169.254".into());

        // Cache Allow for public IP
        cache.insert(&action_public, None, &Verdict::Allow);

        // Same domain but different resolved IP must be a cache miss
        let result = cache.get(&action_metadata, None);
        assert!(
            result.is_none(),
            "Different resolved IP must produce a cache miss (DNS rebinding defense)"
        );
    }
}
