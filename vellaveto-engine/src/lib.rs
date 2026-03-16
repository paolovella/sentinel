// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Policy evaluation engine for the Vellaveto MCP tool firewall.
//!
//! Evaluates [`Action`](vellaveto_types::core::Action) requests against
//! configured [`Policy`](vellaveto_types::core::Policy) rules and returns a
//! [`Verdict`](vellaveto_types::core::Verdict) (Allow, Deny, or RequireApproval).
//! Supports glob/regex path matching, domain/IP rules, ABAC attribute constraints,
//! call-chain validation, decision caching (LRU+TTL), and Wasm policy plugins.
//!
//! The engine is synchronous by design — all evaluation completes in <5ms P99.

pub mod abac;
pub mod acis;
pub mod adaptive_rate;
pub mod behavioral;
pub mod cache;
pub mod cascading;
pub mod circuit_breaker;
pub mod collusion;
mod compiled;
pub mod contagion;
mod constraint_eval;
mod context_check;
pub mod coverage;
pub mod delegation;
pub mod deputy;
mod domain;
mod entropy_gate;
mod error;
pub mod impact;
mod ip;
pub mod least_agency;
mod legacy;
pub mod lint;
mod matcher;
mod normalize;
mod path;
mod policy_compile;
mod rule_check;
mod traced;
mod verified_capability_context;
mod verified_capability_delegation_context;
pub mod verified_constraint_eval;
mod verified_context_delegation;
pub mod verified_core;
mod verified_deputy;
mod verified_entropy_gate;
pub mod wasm_plugin;

#[cfg(kani)]
mod kani_proofs;

pub use compiled::{
    CompiledConstraint, CompiledContextCondition, CompiledIpRules, CompiledNetworkRules,
    CompiledPathRules, CompiledPolicy,
};
pub use error::{EngineError, PolicyValidationError};
pub use matcher::{CompiledToolMatcher, PatternMatcher};
pub use path::DEFAULT_MAX_PATH_DECODE_ITERATIONS;

use vellaveto_types::{
    Action, ActionSummary, EvaluationContext, EvaluationTrace, Policy, PolicyType, Verdict,
};

use globset::{Glob, GlobMatcher};
use regex::Regex;
use std::collections::HashMap;
use std::sync::RwLock;

/// Maximum number of compiled glob matchers kept in the legacy runtime cache.
const MAX_GLOB_MATCHER_CACHE_ENTRIES: usize = 2048;
/// Maximum number of domain normalization results kept in the runtime cache.
///
/// Currently the cache starts empty and is not actively populated by
/// evaluation paths (domain normalization is done inline).  The constant is
/// retained as the documented eviction cap for the `domain_norm_cache`
/// field so that any future population path has a bound ready.
#[allow(dead_code)]
const MAX_DOMAIN_NORM_CACHE_ENTRIES: usize = 4096;

/// The core policy evaluation engine.
///
/// Evaluates [`Action`]s against a set of [`Policy`] rules to produce a [`Verdict`].
///
/// # Security Model
///
/// - **Fail-closed**: An empty policy set produces `Verdict::Deny`.
/// - **Priority ordering**: Higher-priority policies are evaluated first.
/// - **Pattern matching**: Policy IDs use `"tool:function"` convention with wildcard support.
pub struct PolicyEngine {
    strict_mode: bool,
    compiled_policies: Vec<CompiledPolicy>,
    /// Maps exact tool names to sorted indices in `compiled_policies`.
    /// Only policies with an exact tool name pattern are indexed here.
    tool_index: HashMap<String, Vec<usize>>,
    /// Indices of policies that cannot be indexed by tool name
    /// (Universal, prefix, suffix, or Any tool patterns).
    /// Already sorted by position in `compiled_policies` (= priority order).
    always_check: Vec<usize>,
    /// When false (default), time-window context conditions always use wall-clock
    /// time. When true, the engine honors `EvaluationContext.timestamp` from the
    /// caller. **Only enable for deterministic testing** — in production, a client
    /// could supply a fake timestamp to bypass time-window policies.
    trust_context_timestamps: bool,
    /// Maximum percent-decoding iterations in `normalize_path` before
    /// fail-closing to `"/"`. Defaults to [`DEFAULT_MAX_PATH_DECODE_ITERATIONS`] (20).
    max_path_decode_iterations: u32,
    /// Legacy runtime cache for glob matcher compilation.
    ///
    /// This cache is used by `glob_is_match` on the non-precompiled path.
    glob_matcher_cache: RwLock<HashMap<String, GlobMatcher>>,
    /// Runtime cache for domain normalization results.
    ///
    /// Caches both successful normalization (Some) and invalid domains (None)
    /// to avoid repeated IDNA parsing on hot network/domain constraint paths.
    ///
    /// SECURITY (FIND-R46-003): Bounded to [`MAX_DOMAIN_NORM_CACHE_ENTRIES`].
    /// When capacity is exceeded, the cache is cleared to prevent unbounded
    /// memory growth from attacker-controlled domain strings. Currently this
    /// cache is not actively populated — domain normalization is done inline
    /// via [`domain::normalize_domain_for_match`]. The eviction guard exists
    /// as a defense-in-depth measure for future caching additions.
    domain_norm_cache: RwLock<HashMap<String, Option<String>>>,
    /// Optional topology guard for pre-policy tool call filtering.
    /// When set, tool calls are checked against the live topology graph
    /// before policy evaluation. Unknown tools may be denied or trigger
    /// a re-crawl depending on configuration.
    ///
    /// Only available when the `discovery` feature is enabled.
    #[cfg(feature = "discovery")]
    topology_guard: Option<std::sync::Arc<vellaveto_discovery::guard::TopologyGuard>>,
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("PolicyEngine");
        s.field("strict_mode", &self.strict_mode)
            .field("compiled_policies_count", &self.compiled_policies.len())
            .field("indexed_tools", &self.tool_index.len())
            .field("always_check_count", &self.always_check.len())
            .field(
                "max_path_decode_iterations",
                &self.max_path_decode_iterations,
            )
            .field(
                "glob_matcher_cache_size",
                &self
                    .glob_matcher_cache
                    .read()
                    .map(|c| c.len())
                    .unwrap_or_default(),
            )
            .field(
                "domain_norm_cache_size",
                &self
                    .domain_norm_cache
                    .read()
                    .map(|c| c.len())
                    .unwrap_or_default(),
            );
        #[cfg(feature = "discovery")]
        {
            s.field("topology_guard", &self.topology_guard.is_some());
        }
        s.finish()
    }
}

impl PolicyEngine {
    /// Create a new policy engine.
    ///
    /// When `strict_mode` is true, the engine applies stricter validation
    /// on conditions and parameters.
    pub fn new(strict_mode: bool) -> Self {
        Self {
            strict_mode,
            compiled_policies: Vec::new(),
            tool_index: HashMap::new(),
            always_check: Vec::new(),
            trust_context_timestamps: false,
            max_path_decode_iterations: DEFAULT_MAX_PATH_DECODE_ITERATIONS,
            glob_matcher_cache: RwLock::new(HashMap::with_capacity(256)),
            // IMP-R208-001: Zero initial capacity — cache not actively populated.
            domain_norm_cache: RwLock::new(HashMap::new()),
            #[cfg(feature = "discovery")]
            topology_guard: None,
        }
    }

    /// Returns the engine's strict_mode setting.
    pub fn strict_mode(&self) -> bool {
        self.strict_mode
    }

    /// Validate a domain pattern used in network_rules.
    ///
    /// Rules per RFC 1035:
    /// - Labels (parts between dots) must be 1-63 characters each
    /// - Each label must be alphanumeric + hyphen only (no leading/trailing hyphen)
    /// - Total domain length max 253 characters
    /// - Wildcard `*.` prefix is allowed (only at the beginning)
    /// - Empty string is rejected
    ///
    /// See the internal `domain::validate_domain_pattern` function for details.
    pub fn validate_domain_pattern(pattern: &str) -> Result<(), String> {
        domain::validate_domain_pattern(pattern)
    }

    /// Create a new policy engine with pre-compiled policies.
    ///
    /// All regex and glob patterns are compiled at construction time.
    /// Invalid patterns cause immediate rejection with descriptive errors.
    /// The compiled policies are sorted by priority (highest first, deny-overrides).
    pub fn with_policies(
        strict_mode: bool,
        policies: &[Policy],
    ) -> Result<Self, Vec<PolicyValidationError>> {
        let compiled = Self::compile_policies(policies, strict_mode)?;
        let (tool_index, always_check) = Self::build_tool_index(&compiled);
        Ok(Self {
            strict_mode,
            compiled_policies: compiled,
            tool_index,
            always_check,
            trust_context_timestamps: false,
            max_path_decode_iterations: DEFAULT_MAX_PATH_DECODE_ITERATIONS,
            glob_matcher_cache: RwLock::new(HashMap::with_capacity(256)),
            // IMP-R208-001: Zero initial capacity — cache not actively populated.
            domain_norm_cache: RwLock::new(HashMap::new()),
            #[cfg(feature = "discovery")]
            topology_guard: None,
        })
    }

    /// Enable trusting `EvaluationContext.timestamp` for time-window checks.
    ///
    /// **WARNING:** Only use for deterministic testing. In production, a client
    /// can supply a fake timestamp to bypass time-window policies.
    #[cfg(test)]
    pub fn set_trust_context_timestamps(&mut self, trust: bool) {
        self.trust_context_timestamps = trust;
    }

    /// Set the topology guard for pre-policy tool call filtering.
    ///
    /// When set, `evaluate_action` checks the tool against the topology graph
    /// before policy evaluation. Unknown tools produce `Verdict::Deny` with a
    /// topology-specific reason, unless the guard returns `Bypassed`.
    #[cfg(feature = "discovery")]
    pub fn set_topology_guard(
        &mut self,
        guard: std::sync::Arc<vellaveto_discovery::guard::TopologyGuard>,
    ) {
        self.topology_guard = Some(guard);
    }

    /// Check the topology guard (if set) before policy evaluation.
    ///
    /// Returns `Some(Verdict::Deny)` if the tool is unknown or ambiguous
    /// and the guard is configured to block. Returns `None` to proceed
    /// with normal policy evaluation.
    #[cfg(feature = "discovery")]
    fn check_topology(&self, action: &Action) -> Option<Verdict> {
        let guard = self.topology_guard.as_ref()?;
        let tool_name = &action.tool;
        match guard.check(tool_name) {
            vellaveto_discovery::guard::TopologyVerdict::Known { .. } => None,
            vellaveto_discovery::guard::TopologyVerdict::Bypassed => None,
            vellaveto_discovery::guard::TopologyVerdict::Unknown { suggestion, .. } => {
                let reason = if let Some(closest) = suggestion {
                    format!(
                        "Tool '{tool_name}' not found in topology graph (did you mean '{closest}'?)"
                    )
                } else {
                    format!("Tool '{tool_name}' not found in topology graph")
                };
                Some(Verdict::Deny { reason })
            }
            vellaveto_discovery::guard::TopologyVerdict::Ambiguous { matches, .. } => {
                Some(Verdict::Deny {
                    reason: format!(
                        "Tool '{}' is ambiguous — matches servers: {}. Use qualified name (server::tool).",
                        tool_name,
                        matches.join(", ")
                    ),
                })
            }
        }
    }

    /// Set the maximum percent-decoding iterations for path normalization.
    ///
    /// Paths requiring more iterations fail-closed to `"/"`. The default is
    /// [`DEFAULT_MAX_PATH_DECODE_ITERATIONS`] (20). A value of 0 disables
    /// iterative decoding entirely (single pass only).
    pub fn set_max_path_decode_iterations(&mut self, max: u32) {
        self.max_path_decode_iterations = max;
    }

    /// Build a tool-name index for O(matching) evaluation.
    fn build_tool_index(compiled: &[CompiledPolicy]) -> (HashMap<String, Vec<usize>>, Vec<usize>) {
        let mut index: HashMap<String, Vec<usize>> = HashMap::with_capacity(compiled.len());
        let mut always_check = Vec::with_capacity(compiled.len());
        for (i, cp) in compiled.iter().enumerate() {
            match &cp.tool_matcher {
                CompiledToolMatcher::Universal => always_check.push(i),
                CompiledToolMatcher::ToolOnly(PatternMatcher::Exact(name)) => {
                    index.entry(name.clone()).or_default().push(i);
                }
                CompiledToolMatcher::ToolAndFunction(PatternMatcher::Exact(name), _) => {
                    index.entry(name.clone()).or_default().push(i);
                }
                _ => always_check.push(i),
            }
        }
        // SECURITY (FIND-R49-003): Assert sorted invariant in debug builds.
        // The always_check list must be sorted by index for deterministic evaluation order.
        // Tool index values must also be sorted per-key for the same reason.
        debug_assert!(
            always_check.windows(2).all(|w| w[0] < w[1]),
            "always_check must be sorted"
        );
        debug_assert!(
            index.values().all(|v| v.windows(2).all(|w| w[0] < w[1])),
            "tool_index values must be sorted"
        );
        (index, always_check)
    }

    /// Sort policies by priority (highest first), with deny-overrides at equal priority,
    /// and a stable tertiary tiebreaker by policy ID for deterministic ordering.
    ///
    /// Call this once when loading or modifying policies, then pass the sorted
    /// slice to [`Self::evaluate_action`] to avoid re-sorting on every evaluation.
    pub fn sort_policies(policies: &mut [Policy]) {
        policies.sort_by(|a, b| {
            let pri = b.priority.cmp(&a.priority);
            if pri != std::cmp::Ordering::Equal {
                return pri;
            }
            let a_deny = matches!(a.policy_type, PolicyType::Deny);
            let b_deny = matches!(b.policy_type, PolicyType::Deny);
            let deny_ord = b_deny.cmp(&a_deny);
            if deny_ord != std::cmp::Ordering::Equal {
                return deny_ord;
            }
            // Tertiary tiebreaker: lexicographic by ID for deterministic ordering
            a.id.cmp(&b.id)
        });
    }

    // VERIFIED [S1]: Deny-by-default — empty policy set produces Deny (MCPPolicyEngine.tla S1)
    // VERIFIED [S2]: Priority ordering — higher priority wins (MCPPolicyEngine.tla S2)
    // VERIFIED [S3]: Deny-overrides — Deny beats Allow at same priority (MCPPolicyEngine.tla S3)
    // VERIFIED [S5]: Errors produce Deny — every Allow verdict has a matching Allow policy (MCPPolicyEngine.tla S5)
    // VERIFIED [L1]: Progress — every action gets a verdict (MCPPolicyEngine.tla L1)
    /// Evaluate an action against a set of policies.
    ///
    /// For best performance, pass policies that have been pre-sorted with
    /// [`Self::sort_policies`]. If not pre-sorted, this method will sort a temporary
    /// copy (which adds O(n log n) overhead per call).
    ///
    /// The first matching policy determines the verdict.
    /// If no policy matches, the default is Deny (fail-closed).
    #[must_use = "security verdicts must not be discarded"]
    pub fn evaluate_action(
        &self,
        action: &Action,
        policies: &[Policy],
    ) -> Result<Verdict, EngineError> {
        // Topology pre-filter: check if the tool exists in the topology graph.
        // Unknown/ambiguous tools are denied before policy evaluation.
        #[cfg(feature = "discovery")]
        if let Some(deny) = self.check_topology(action) {
            return Ok(deny);
        }

        // Fast path: use pre-compiled policies (zero Mutex, zero runtime compilation)
        if !self.compiled_policies.is_empty() {
            return self.evaluate_with_compiled(action);
        }

        // Legacy path: evaluate ad-hoc policies (compiles patterns on the fly)
        if policies.is_empty() {
            return Ok(Verdict::Deny {
                reason: "No policies defined".to_string(),
            });
        }

        // Check if already sorted (by priority desc, deny-first at equal priority,
        // then by ID ascending as a tiebreaker — FIND-R44-057)
        let is_sorted = policies.windows(2).all(|w| {
            let pri = w[0].priority.cmp(&w[1].priority);
            if pri == std::cmp::Ordering::Equal {
                let a_deny = matches!(w[0].policy_type, PolicyType::Deny);
                let b_deny = matches!(w[1].policy_type, PolicyType::Deny);
                if a_deny == b_deny {
                    // FIND-R44-057: Tertiary tiebreaker by ID for deterministic ordering
                    w[0].id.cmp(&w[1].id) != std::cmp::Ordering::Greater
                } else {
                    b_deny <= a_deny
                }
            } else {
                pri != std::cmp::Ordering::Less
            }
        });

        if is_sorted {
            for policy in policies {
                if self.matches_action(action, policy) {
                    if let Some(verdict) = self.apply_policy(action, policy)? {
                        return Ok(verdict);
                    }
                    // None: on_no_match="continue", try next policy
                }
            }
        } else {
            let mut sorted: Vec<&Policy> = policies.iter().collect();
            sorted.sort_by(|a, b| {
                let pri = b.priority.cmp(&a.priority);
                if pri != std::cmp::Ordering::Equal {
                    return pri;
                }
                let a_deny = matches!(a.policy_type, PolicyType::Deny);
                let b_deny = matches!(b.policy_type, PolicyType::Deny);
                let deny_cmp = b_deny.cmp(&a_deny);
                if deny_cmp != std::cmp::Ordering::Equal {
                    return deny_cmp;
                }
                // FIND-R44-057: Tertiary tiebreaker by ID for deterministic ordering
                a.id.cmp(&b.id)
            });
            for policy in &sorted {
                if self.matches_action(action, policy) {
                    if let Some(verdict) = self.apply_policy(action, policy)? {
                        return Ok(verdict);
                    }
                    // None: on_no_match="continue", try next policy
                }
            }
        }

        Ok(Verdict::Deny {
            reason: "No matching policy".to_string(),
        })
    }

    /// Evaluate an action with optional session context.
    ///
    /// This is the context-aware counterpart to [`Self::evaluate_action`].
    /// When `context` is `Some`, context conditions (time windows, call limits,
    /// agent identity, action history) are evaluated. When `None`, behaves
    /// identically to `evaluate_action`.
    ///
    /// # WARNING: `policies` parameter ignored when compiled policies exist
    ///
    /// When the engine was constructed with [`Self::with_policies`] (or any
    /// builder that populates `compiled_policies`), the `policies` parameter
    /// is **completely ignored**. The engine uses its pre-compiled policy set
    /// instead.
    #[deprecated(
        since = "4.0.1",
        note = "policies parameter is silently ignored when compiled policies exist. \
                Use evaluate_action() for compiled engines or build a new engine \
                with with_policies() for dynamic policy sets."
    )]
    #[must_use = "security verdicts must not be discarded"]
    pub fn evaluate_action_with_context(
        &self,
        action: &Action,
        policies: &[Policy],
        context: Option<&EvaluationContext>,
    ) -> Result<Verdict, EngineError> {
        #[cfg(feature = "discovery")]
        if let Some(deny) = self.check_topology(action) {
            return Ok(deny);
        }
        if let Some(ctx) = context {
            if let Err(reason) = ctx.validate() {
                return Ok(Verdict::Deny { reason });
            }
        }
        if context.is_none() {
            return self.evaluate_action(action, policies);
        }
        if !self.compiled_policies.is_empty() {
            return self.evaluate_with_compiled_ctx(action, context);
        }
        if let Some(ctx) = context {
            if ctx.has_any_meaningful_fields() {
                return Ok(Verdict::Deny {
                    reason: "Policy engine has no compiled policies; \
                             context conditions cannot be evaluated (fail-closed)"
                        .to_string(),
                });
            }
        }
        self.evaluate_action(action, policies)
    }

    /// Evaluate an action with optional session context, returning only the verdict.
    ///
    /// This is the context-aware counterpart to [`Self::evaluate_action`].
    /// When `context` is `Some`, context conditions (time windows, call limits,
    /// agent identity, action history) are evaluated. When `None`, behaves
    /// identically to `evaluate_action`.
    ///
    /// For the full decision trace, use [`Self::evaluate_action_traced_with_context`].
    #[must_use = "security verdicts must not be discarded"]
    pub fn evaluate_with_context(
        &self,
        action: &Action,
        context: Option<&EvaluationContext>,
    ) -> Result<Verdict, EngineError> {
        self.evaluate_action_traced_with_context(action, context)
            .map(|(verdict, _trace)| verdict)
    }

    /// Evaluate an action with full decision trace and optional session context.
    #[must_use = "security verdicts must not be discarded"]
    pub fn evaluate_action_traced_with_context(
        &self,
        action: &Action,
        context: Option<&EvaluationContext>,
    ) -> Result<(Verdict, EvaluationTrace), EngineError> {
        // Topology pre-filter: check if the tool exists in the topology graph.
        #[cfg(feature = "discovery")]
        if let Some(deny) = self.check_topology(action) {
            let param_keys: Vec<String> = action
                .parameters
                .as_object()
                .map(|o| o.keys().cloned().collect::<Vec<String>>())
                .unwrap_or_default();
            let trace = EvaluationTrace {
                action_summary: ActionSummary {
                    tool: action.tool.clone(),
                    function: action.function.clone(),
                    param_count: param_keys.len(),
                    param_keys,
                },
                policies_checked: 0,
                policies_matched: 0,
                matches: vec![],
                verdict: deny.clone(),
                duration_us: 0,
            };
            return Ok((deny, trace));
        }

        // SECURITY (FIND-R50-063): Validate context bounds before evaluation.
        if let Some(ctx) = context {
            if let Err(reason) = ctx.validate() {
                let deny = Verdict::Deny {
                    reason: reason.clone(),
                };
                let param_keys: Vec<String> = action
                    .parameters
                    .as_object()
                    .map(|o| o.keys().cloned().collect::<Vec<String>>())
                    .unwrap_or_default();
                let trace = EvaluationTrace {
                    action_summary: ActionSummary {
                        tool: action.tool.clone(),
                        function: action.function.clone(),
                        param_count: param_keys.len(),
                        param_keys,
                    },
                    policies_checked: 0,
                    policies_matched: 0,
                    matches: vec![],
                    verdict: deny.clone(),
                    duration_us: 0,
                };
                return Ok((deny, trace));
            }
        }
        if context.is_none() {
            return self.evaluate_action_traced(action);
        }
        // Traced context-aware path
        self.evaluate_action_traced_ctx(action, context)
    }

    // ═══════════════════════════════════════════════════
    // COMPILED EVALUATION PATH (zero Mutex, zero runtime compilation)
    // ═══════════════════════════════════════════════════

    /// Evaluate an action using pre-compiled policies. Zero Mutex acquisitions.
    /// Compiled policies are already sorted at compile time.
    ///
    /// Uses the tool-name index when available: only checks policies whose tool
    /// pattern could match `action.tool`, plus `always_check` (wildcard/prefix/suffix).
    /// Falls back to linear scan when no index has been built.
    fn evaluate_with_compiled(&self, action: &Action) -> Result<Verdict, EngineError> {
        // SECURITY (FIND-SEM-003, R227-TYP-1): Normalize tool/function names through
        // the full pipeline (NFKC + lowercase + homoglyph) before policy matching.
        // This prevents fullwidth Unicode, circled letters (Ⓐ), and mathematical
        // variants from bypassing exact-match Deny policies. Patterns are also
        // normalized via normalize_full at compile time for consistency.
        let norm_tool = crate::normalize::normalize_full(&action.tool);
        let norm_func = crate::normalize::normalize_full(&action.function);

        // If index was built, use it for O(matching) instead of O(all)
        if !self.tool_index.is_empty() || !self.always_check.is_empty() {
            let tool_specific = self.tool_index.get(&norm_tool);
            let tool_slice = tool_specific.map_or(&[][..], |v| v.as_slice());
            let always_slice = &self.always_check;

            // Merge two sorted index slices, iterating in priority order.
            // SECURITY (R26-ENG-1): When both slices reference the same policy index,
            // increment BOTH pointers to avoid evaluating the policy twice.
            let mut ti = 0;
            let mut ai = 0;
            loop {
                let next_idx = match (tool_slice.get(ti), always_slice.get(ai)) {
                    (Some(&t), Some(&a)) => {
                        if t < a {
                            ti += 1;
                            t
                        } else if t > a {
                            ai += 1;
                            a
                        } else {
                            // t == a: same policy in both slices, skip duplicate
                            ti += 1;
                            ai += 1;
                            t
                        }
                    }
                    (Some(&t), None) => {
                        ti += 1;
                        t
                    }
                    (None, Some(&a)) => {
                        ai += 1;
                        a
                    }
                    (None, None) => break,
                };

                let cp = &self.compiled_policies[next_idx];
                if cp.tool_matcher.matches_normalized(&norm_tool, &norm_func) {
                    if let Some(verdict) = self.apply_compiled_policy(action, cp)? {
                        return Ok(verdict);
                    }
                    // None: on_no_match="continue", try next policy
                }
            }
        } else {
            // No index: linear scan (legacy compiled path)
            for cp in &self.compiled_policies {
                if cp.tool_matcher.matches_normalized(&norm_tool, &norm_func) {
                    if let Some(verdict) = self.apply_compiled_policy(action, cp)? {
                        return Ok(verdict);
                    }
                    // None: on_no_match="continue", try next policy
                }
            }
        }

        Ok(Verdict::Deny {
            reason: "No matching policy".to_string(),
        })
    }

    /// Evaluate with compiled policies and session context.
    fn evaluate_with_compiled_ctx(
        &self,
        action: &Action,
        context: Option<&EvaluationContext>,
    ) -> Result<Verdict, EngineError> {
        // SECURITY (FIND-SEM-003, R227-TYP-1): Normalize tool/function names through
        // the full pipeline (same as evaluate_with_compiled).
        let norm_tool = crate::normalize::normalize_full(&action.tool);
        let norm_func = crate::normalize::normalize_full(&action.function);

        if !self.tool_index.is_empty() || !self.always_check.is_empty() {
            let tool_specific = self.tool_index.get(&norm_tool);
            let tool_slice = tool_specific.map_or(&[][..], |v| v.as_slice());
            let always_slice = &self.always_check;

            // SECURITY (R26-ENG-1): Deduplicate merge — see evaluate_compiled().
            let mut ti = 0;
            let mut ai = 0;
            loop {
                let next_idx = match (tool_slice.get(ti), always_slice.get(ai)) {
                    (Some(&t), Some(&a)) => {
                        if t < a {
                            ti += 1;
                            t
                        } else if t > a {
                            ai += 1;
                            a
                        } else {
                            ti += 1;
                            ai += 1;
                            t
                        }
                    }
                    (Some(&t), None) => {
                        ti += 1;
                        t
                    }
                    (None, Some(&a)) => {
                        ai += 1;
                        a
                    }
                    (None, None) => break,
                };

                let cp = &self.compiled_policies[next_idx];
                if cp.tool_matcher.matches_normalized(&norm_tool, &norm_func) {
                    if let Some(verdict) = self.apply_compiled_policy_ctx(action, cp, context)? {
                        return Ok(verdict);
                    }
                }
            }
        } else {
            for cp in &self.compiled_policies {
                if cp.tool_matcher.matches_normalized(&norm_tool, &norm_func) {
                    if let Some(verdict) = self.apply_compiled_policy_ctx(action, cp, context)? {
                        return Ok(verdict);
                    }
                }
            }
        }

        Ok(Verdict::Deny {
            reason: "No matching policy".to_string(),
        })
    }

    /// Apply a matched compiled policy to produce a verdict (no context).
    /// Returns `None` when a Conditional policy with `on_no_match: "continue"` has no
    /// constraints fire, signaling the evaluation loop to try the next policy.
    fn apply_compiled_policy(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
    ) -> Result<Option<Verdict>, EngineError> {
        self.apply_compiled_policy_ctx(action, cp, None)
    }

    /// Apply a matched compiled policy with optional context.
    fn apply_compiled_policy_ctx(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
        context: Option<&EvaluationContext>,
    ) -> Result<Option<Verdict>, EngineError> {
        // Check path rules before policy type dispatch.
        // Blocked paths → deny immediately regardless of policy type.
        if let Some(denial) = self.check_path_rules(action, cp) {
            Self::debug_assert_verified_deny(cp, true, false);
            return Ok(Some(denial));
        }
        // Check network rules before policy type dispatch.
        if let Some(denial) = self.check_network_rules(action, cp) {
            Self::debug_assert_verified_deny(cp, true, false);
            return Ok(Some(denial));
        }
        // Check IP rules (DNS rebinding protection) after network rules.
        if let Some(denial) = self.check_ip_rules(action, cp) {
            Self::debug_assert_verified_deny(cp, true, false);
            return Ok(Some(denial));
        }
        // Check context conditions (session-level) before policy type dispatch.
        // SECURITY: If a policy declares context conditions but no context is
        // provided, deny the action (fail-closed). Skipping would let callers
        // bypass time-window / max-calls / agent-id restrictions by omitting context.
        if !cp.context_conditions.is_empty() {
            match context {
                Some(ctx) => {
                    // SECURITY (R231-ENG-3): Normalize tool name before passing to
                    // context conditions, consistent with policy matching which uses
                    // normalize_full(). Prevents future context conditions from
                    // receiving raw attacker-controlled tool names.
                    let norm_tool = crate::normalize::normalize_full(&action.tool);
                    if let Some(denial) = self.check_context_conditions(ctx, cp, &norm_tool) {
                        Self::debug_assert_verified_deny(cp, false, true);
                        return Ok(Some(denial));
                    }
                }
                None => {
                    Self::debug_assert_verified_deny(cp, false, true);
                    return Ok(Some(Verdict::Deny {
                        reason: format!(
                            "Policy '{}' requires evaluation context (has {} context condition(s)) but none was provided",
                            cp.policy.name,
                            cp.context_conditions.len()
                        ),
                    }));
                }
            }
        }

        match &cp.policy.policy_type {
            PolicyType::Allow => {
                Self::debug_assert_verified_allow(cp);
                Ok(Some(Verdict::Allow))
            }
            PolicyType::Deny => {
                Self::debug_assert_verified_policy_deny(cp);
                Ok(Some(Verdict::Deny {
                    reason: cp.deny_reason.clone(),
                }))
            }
            PolicyType::Conditional { .. } => self.evaluate_compiled_conditions(action, cp),
            // Handle future variants - fail closed (deny)
            _ => {
                // SECURITY (R239-XCUT-5): Genericize — policy name in debug only.
                tracing::debug!(policy = %cp.policy.name, "Request denied (unknown policy type)");
                Ok(Some(Verdict::Deny {
                    reason: "Request denied (unknown policy type)".to_string(),
                }))
            }
        }
    }

    /// Debug-assert: verified core confirms rule/context override produces Deny.
    #[inline]
    fn debug_assert_verified_deny(cp: &CompiledPolicy, rule_override: bool, ctx_deny: bool) {
        debug_assert!({
            let rm = verified_core::ResolvedMatch {
                matched: true,
                is_deny: matches!(cp.policy.policy_type, PolicyType::Deny),
                is_conditional: matches!(cp.policy.policy_type, PolicyType::Conditional { .. }),
                priority: u32::try_from(cp.policy.priority.max(0)).unwrap_or(0),
                rule_override_deny: rule_override,
                context_deny: ctx_deny,
                require_approval: false,
                condition_fired: false,
                condition_verdict: verified_core::VerdictKind::Deny,
                on_no_match_continue: false,
                all_constraints_skipped: false,
            };
            verified_core::compute_single_verdict(&rm)
                == verified_core::VerdictOutcome::Decided(verified_core::VerdictKind::Deny)
        });
    }

    /// Debug-assert: verified core confirms Allow policy produces Allow.
    #[inline]
    fn debug_assert_verified_allow(cp: &CompiledPolicy) {
        debug_assert!({
            let rm = verified_core::ResolvedMatch {
                matched: true,
                is_deny: false,
                is_conditional: false,
                priority: u32::try_from(cp.policy.priority.max(0)).unwrap_or(0),
                rule_override_deny: false,
                context_deny: false,
                require_approval: false,
                condition_fired: false,
                condition_verdict: verified_core::VerdictKind::Allow,
                on_no_match_continue: false,
                all_constraints_skipped: false,
            };
            verified_core::compute_single_verdict(&rm)
                == verified_core::VerdictOutcome::Decided(verified_core::VerdictKind::Allow)
        });
    }

    /// Debug-assert: verified core confirms Deny policy produces Deny.
    #[inline]
    fn debug_assert_verified_policy_deny(cp: &CompiledPolicy) {
        debug_assert!({
            let rm = verified_core::ResolvedMatch {
                matched: true,
                is_deny: true,
                is_conditional: false,
                priority: u32::try_from(cp.policy.priority.max(0)).unwrap_or(0),
                rule_override_deny: false,
                context_deny: false,
                require_approval: false,
                condition_fired: false,
                condition_verdict: verified_core::VerdictKind::Deny,
                on_no_match_continue: false,
                all_constraints_skipped: false,
            };
            verified_core::compute_single_verdict(&rm)
                == verified_core::VerdictOutcome::Decided(verified_core::VerdictKind::Deny)
        });
    }

    /// Normalize a file path: resolve `..`, `.`, reject null bytes, ensure deterministic form.
    ///
    /// Handles percent-encoding, null bytes, and path traversal attempts.
    pub fn normalize_path(raw: &str) -> Result<String, EngineError> {
        path::normalize_path(raw)
    }

    /// Normalize a file path with a configurable percent-decoding iteration limit.
    ///
    /// Use this variant when you need to control the maximum decode iterations
    /// to prevent DoS from deeply nested percent-encoding.
    pub fn normalize_path_bounded(raw: &str, max_iterations: u32) -> Result<String, EngineError> {
        path::normalize_path_bounded(raw, max_iterations)
    }

    /// Extract the domain from a URL string.
    ///
    /// Returns the host portion of the URL, or the original string if parsing fails.
    pub fn extract_domain(url: &str) -> String {
        domain::extract_domain(url)
    }

    /// Match a domain against a pattern like `*.example.com` or `example.com`.
    ///
    /// Supports wildcard patterns with `*.` prefix for subdomain matching.
    pub fn match_domain_pattern(domain_str: &str, pattern: &str) -> bool {
        domain::match_domain_pattern(domain_str, pattern)
    }

    /// Normalize a domain for matching: lowercase, strip trailing dots, apply IDNA.
    ///
    /// See [`domain::normalize_domain_for_match`] for details.
    fn normalize_domain_for_match(s: &str) -> Option<std::borrow::Cow<'_, str>> {
        domain::normalize_domain_for_match(s)
    }

    /// Maximum regex pattern length to prevent ReDoS via overlength patterns.
    const MAX_REGEX_LEN: usize = 1024;

    /// Validate a regex pattern for ReDoS safety.
    ///
    /// Rejects patterns that are too long (>1024 chars) or contain constructs
    /// known to cause exponential backtracking:
    ///
    /// 1. **Nested quantifiers** like `(a+)+`, `(a*)*`, `(a+)*`, `(a*)+`
    /// 2. **Overlapping alternation with quantifiers** like `(a|a)+` or `(a|ab)+`
    ///
    /// **Known limitations (FIND-R46-007):** This is a heuristic check, not a
    /// full NFA analysis. It does NOT detect all possible ReDoS patterns:
    /// - Alternation with overlapping character classes (e.g., `([a-z]|[a-m])+`)
    /// - Backreferences with quantifiers
    /// - Lookahead/lookbehind with quantifiers
    /// - Possessive quantifiers (these are actually safe but not recognized)
    ///
    /// The `regex` crate uses a DFA/NFA hybrid that is immune to most ReDoS,
    /// but pattern compilation itself can be expensive for very complex patterns,
    /// hence the length limit.
    fn validate_regex_safety(pattern: &str) -> Result<(), String> {
        if pattern.len() > Self::MAX_REGEX_LEN {
            return Err(format!(
                "Regex pattern exceeds maximum length of {} chars ({} chars)",
                Self::MAX_REGEX_LEN,
                pattern.len()
            ));
        }

        // Detect nested quantifiers: a quantifier applied to a group that
        // itself contains a quantifier. Simplified check for common patterns.
        let quantifiers = ['+', '*'];
        let mut paren_depth = 0i32;
        let mut has_inner_quantifier = false;
        let chars: Vec<char> = pattern.chars().collect();
        // SECURITY (R8-5): Use a skip_next flag to correctly handle escape
        // sequences. The previous approach checked chars[i-1] == '\\' but
        // failed for double-escapes like `\\\\(` (literal backslash + open paren).
        let mut skip_next = false;

        // Track alternation branches within groups to detect overlapping alternation.
        // SECURITY (FIND-R46-007): Detect `(branch1|branch2)+` where branches share
        // a common prefix, which can cause backtracking even without nested quantifiers.
        let mut group_has_alternation = false;

        for i in 0..chars.len() {
            if skip_next {
                skip_next = false;
                continue;
            }
            match chars[i] {
                '\\' => {
                    // Skip the NEXT character (the escaped one)
                    skip_next = true;
                    continue;
                }
                '(' => {
                    paren_depth += 1;
                    has_inner_quantifier = false;
                    group_has_alternation = false;
                }
                ')' => {
                    paren_depth -= 1;
                    // SECURITY (FIND-R58-ENG-002): Reject unbalanced closing parens.
                    // Negative paren_depth disables alternation/inner-quantifier
                    // tracking, allowing ReDoS patterns to bypass the safety check.
                    if paren_depth < 0 {
                        return Err(format!(
                            "Invalid regex pattern — unbalanced parentheses: '{}'",
                            &pattern[..pattern.len().min(100)]
                        ));
                    }
                    // Check if the next char is a quantifier
                    if i + 1 < chars.len() && quantifiers.contains(&chars[i + 1]) {
                        if has_inner_quantifier {
                            return Err(format!(
                                "Regex pattern contains nested quantifiers (potential ReDoS): '{}'",
                                &pattern[..pattern.len().min(100)]
                            ));
                        }
                        // FIND-R46-007: Alternation with a quantifier on the group
                        // can cause backtracking if branches overlap.
                        if group_has_alternation {
                            return Err(format!(
                                "Regex pattern contains alternation with outer quantifier (potential ReDoS): '{}'",
                                &pattern[..pattern.len().min(100)]
                            ));
                        }
                    }
                }
                '|' if paren_depth > 0 => {
                    group_has_alternation = true;
                }
                c if quantifiers.contains(&c) && paren_depth > 0 => {
                    has_inner_quantifier = true;
                }
                _ => {}
            }
        }

        // SECURITY (FIND-R58-ENG-004): Reject patterns with unclosed parentheses.
        if paren_depth != 0 {
            return Err(format!(
                "Invalid regex pattern — unbalanced parentheses ({} unclosed): '{}'",
                paren_depth,
                &pattern[..pattern.len().min(100)]
            ));
        }

        Ok(())
    }

    /// Compile a regex pattern and test whether it matches the input.
    ///
    /// Legacy path: compiles the pattern on each call (no caching).
    /// For zero-overhead evaluation, use `with_policies()` to pre-compile.
    ///
    /// Validates the pattern for ReDoS safety before compilation (H2).
    fn regex_is_match(
        &self,
        pattern: &str,
        input: &str,
        policy_id: &str,
    ) -> Result<bool, EngineError> {
        Self::validate_regex_safety(pattern).map_err(|reason| EngineError::InvalidCondition {
            policy_id: policy_id.to_string(),
            reason,
        })?;
        let re = Regex::new(pattern).map_err(|e| EngineError::InvalidCondition {
            policy_id: policy_id.to_string(),
            reason: format!("Invalid regex pattern '{pattern}': {e}"),
        })?;
        Ok(re.is_match(input))
    }

    /// Compile a glob pattern and test whether it matches the input.
    ///
    /// Legacy path: compiles the pattern on each call (no caching).
    /// For zero-overhead evaluation, use `with_policies()` to pre-compile.
    fn glob_is_match(
        &self,
        pattern: &str,
        input: &str,
        policy_id: &str,
    ) -> Result<bool, EngineError> {
        // SECURITY: On poisoned read lock, treat as cache miss rather than
        // accessing potentially corrupted data. The pattern will be compiled fresh.
        {
            let cache_result = self.glob_matcher_cache.read();
            match cache_result {
                Ok(cache) => {
                    if let Some(matcher) = cache.get(pattern) {
                        return Ok(matcher.is_match(input));
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "glob_matcher_cache read lock poisoned, treating as cache miss: {}",
                        e
                    );
                    // Fall through to compile the pattern fresh
                }
            }
        }

        let matcher = Glob::new(pattern)
            .map_err(|e| EngineError::InvalidCondition {
                policy_id: policy_id.to_string(),
                reason: format!("Invalid glob pattern '{pattern}': {e}"),
            })?
            .compile_matcher();
        let is_match = matcher.is_match(input);

        // SECURITY: On poisoned write lock, skip cache insertion rather than
        // writing into potentially corrupted state. The result is still correct,
        // just not cached.
        let cache_write = self.glob_matcher_cache.write();
        let mut cache = match cache_write {
            Ok(guard) => guard,
            Err(e) => {
                tracing::warn!(
                    "glob_matcher_cache write lock poisoned, skipping cache insert: {}",
                    e
                );
                return Ok(is_match);
            }
        };
        // FIND-R58-ENG-011: Full cache.clear() can cause a thundering herd of
        // recompilation on the legacy (non-precompiled) path. For production,
        // use with_policies() to pre-compile patterns and avoid this cache entirely.
        if cache.len() >= MAX_GLOB_MATCHER_CACHE_ENTRIES {
            // SECURITY (P3-ENG-004): Warn on cache eviction so cache thrashing is
            // observable in logs. This indicates a policy set with more unique glob
            // patterns than MAX_GLOB_MATCHER_CACHE_ENTRIES, which causes repeated
            // recompilation and may indicate a misconfiguration or DoS attempt.
            tracing::warn!(
                capacity = MAX_GLOB_MATCHER_CACHE_ENTRIES,
                "glob_matcher_cache capacity exceeded — clearing cache (cache thrashing possible; prefer with_policies() to pre-compile patterns)"
            );
            cache.clear();
        }
        cache.insert(pattern.to_string(), matcher);

        Ok(is_match)
    }

    /// Retrieve a parameter value by dot-separated path.
    ///
    /// Supports both simple keys (`"path"`) and nested paths (`"config.output.path"`).
    ///
    /// **Resolution order** (Exploit #5 fix): When the path contains dots, the function
    /// checks both an exact key match (e.g., `params["config.path"]`) and dot-split
    /// traversal (e.g., `params["config"]["path"]`).
    ///
    /// **Ambiguity handling (fail-closed):** If both interpretations resolve to different
    /// values, the function returns `None`. This prevents an attacker from shadowing a
    /// nested value with a literal dotted key (or vice versa). The `None` triggers
    /// deny behavior through the constraint's `on_missing` handling.
    ///
    /// When only one interpretation resolves, that value is returned.
    /// When both resolve to the same value, that value is returned.
    ///
    /// IMPROVEMENT_PLAN 4.1: Also supports bracket notation for array access:
    /// - `items[0]` — access first element of array "items"
    /// - `config.items[0].path` — traverse nested path with array access
    /// - `matrix[0][1]` — multi-dimensional array access
    pub fn get_param_by_path<'a>(
        params: &'a serde_json::Value,
        path: &str,
    ) -> Option<&'a serde_json::Value> {
        let exact_match = params.get(path);

        // For non-dotted paths without brackets, exact match is the only interpretation
        if !path.contains('.') && !path.contains('[') {
            return exact_match;
        }

        // Try dot-split traversal for nested objects with bracket notation support
        let traversal_match = Self::traverse_path(params, path);

        match (exact_match, traversal_match) {
            // Both exist but differ: ambiguous — fail-closed (return None)
            (Some(exact), Some(traversal)) if exact != traversal => None,
            // Both exist and are equal: no ambiguity
            (Some(exact), Some(_)) => Some(exact),
            // Only one interpretation resolves
            (Some(exact), None) => Some(exact),
            (None, Some(traversal)) => Some(traversal),
            (None, None) => None,
        }
    }

    /// Traverse a JSON value using a path with dot notation and bracket notation.
    ///
    /// Supports:
    /// - `foo.bar` — nested object access
    /// - `items[0]` — array index access
    /// - `foo.items[0].bar` — mixed traversal
    /// - `matrix[0][1]` — consecutive array access
    fn traverse_path<'a>(
        params: &'a serde_json::Value,
        path: &str,
    ) -> Option<&'a serde_json::Value> {
        let mut current = params;

        // Split by dots first, then handle bracket notation within each segment
        for segment in path.split('.') {
            if segment.is_empty() {
                continue;
            }

            // Check for bracket notation: field[index] or just [index]
            if let Some(bracket_pos) = segment.find('[') {
                // Get the field name before the bracket (may be empty for [0][1] style)
                let field_name = &segment[..bracket_pos];

                // If there's a field name, traverse into it first
                if !field_name.is_empty() {
                    current = current.get(field_name)?;
                }

                // Parse all bracket indices in this segment: [0][1][2]...
                let mut rest = &segment[bracket_pos..];
                while rest.starts_with('[') {
                    let close_pos = rest.find(']')?;
                    let index_str = &rest[1..close_pos];
                    let index: usize = index_str.parse().ok()?;

                    // Access array element
                    current = current.get(index)?;

                    // Move past this bracket pair
                    rest = &rest[close_pos + 1..];
                }

                // If there's remaining content after brackets, it's malformed
                if !rest.is_empty() {
                    return None;
                }
            } else {
                // Simple field access
                current = current.get(segment)?;
            }
        }

        Some(current)
    }

    /// Maximum number of string values to collect during recursive parameter scanning.
    /// Prevents DoS from parameters with thousands of nested string values.
    const MAX_SCAN_VALUES: usize = 500;

    /// Maximum nesting depth for recursive parameter scanning.
    ///
    /// 32 levels is sufficient for any reasonable MCP tool parameter structure
    /// (typical JSON has 3-5 levels; 32 provides ample headroom). Objects or
    /// arrays nested beyond this depth are silently skipped — their string
    /// values will not be collected for constraint evaluation or DLP scanning.
    /// This prevents stack/memory exhaustion from attacker-crafted deeply nested JSON.
    const MAX_JSON_DEPTH: usize = 32;

    /// Maximum work stack size for iterative JSON traversal.
    ///
    /// SECURITY (FIND-R168-003): Caps the iterative traversal stack to prevent
    /// transient memory spikes from flat JSON objects/arrays with many children.
    /// Without this, a 1MB JSON with 100K keys at depth 0 would push all 100K
    /// items before the depth/results checks trigger.
    const MAX_STACK_SIZE: usize = 10_000;

    /// Recursively collect all string values from a JSON structure.
    ///
    /// Returns a list of `(path, value)` pairs where `path` is a dot-separated
    /// description of where the value was found (e.g., `"options.target"`), and
    /// a boolean indicating whether results were truncated at [`MAX_SCAN_VALUES`].
    /// Uses an iterative approach to avoid stack overflow on deep JSON.
    ///
    /// Bounded by [`MAX_SCAN_VALUES`] total values and [`MAX_JSON_DEPTH`] nesting depth.
    ///
    /// SECURITY (R234-ENG-4): Returns truncation flag so callers can fail-closed
    /// when the parameter space exceeds scan capacity.
    fn collect_all_string_values(params: &serde_json::Value) -> (Vec<(String, &str)>, bool) {
        // Pre-allocate for typical parameter sizes; bounded by MAX_SCAN_VALUES
        let mut results = Vec::with_capacity(16);
        let mut truncated = false;
        // Stack: (value, current_path, depth)
        let mut stack: Vec<(&serde_json::Value, String, usize)> = vec![(params, String::new(), 0)];

        while let Some((val, path, depth)) = stack.pop() {
            if results.len() >= Self::MAX_SCAN_VALUES {
                truncated = true;
                break;
            }
            match val {
                serde_json::Value::String(s) => {
                    if !path.is_empty() {
                        results.push((path, s.as_str()));
                    }
                }
                serde_json::Value::Object(obj) => {
                    if depth >= Self::MAX_JSON_DEPTH {
                        continue;
                    }
                    for (key, child) in obj {
                        // SECURITY (FIND-R168-003): Bound stack inside push loop.
                        if stack.len() >= Self::MAX_STACK_SIZE {
                            break;
                        }
                        let child_path = if path.is_empty() {
                            key.clone()
                        } else {
                            let mut p = String::with_capacity(path.len() + 1 + key.len());
                            p.push_str(&path);
                            p.push('.');
                            p.push_str(key);
                            p
                        };
                        stack.push((child, child_path, depth + 1));
                    }
                }
                serde_json::Value::Array(arr) => {
                    if depth >= Self::MAX_JSON_DEPTH {
                        continue;
                    }
                    for (i, child) in arr.iter().enumerate() {
                        if stack.len() >= Self::MAX_STACK_SIZE {
                            break;
                        }
                        let child_path = if path.is_empty() {
                            format!("[{i}]")
                        } else {
                            format!("{path}[{i}]")
                        };
                        stack.push((child, child_path, depth + 1));
                    }
                }
                _ => {}
            }
        }

        (results, truncated)
    }

    /// Convert an `on_match` action string into a Verdict.
    fn make_constraint_verdict(on_match: &str, reason: &str) -> Result<Verdict, EngineError> {
        match on_match {
            "deny" => Ok(Verdict::Deny {
                reason: reason.to_string(),
            }),
            "require_approval" => Ok(Verdict::RequireApproval {
                reason: reason.to_string(),
            }),
            "allow" => Ok(Verdict::Allow),
            other => Err(EngineError::EvaluationError(format!(
                "Unknown on_match action: '{other}'"
            ))),
        }
    }
    /// Returns true if any compiled policy has IP rules configured.
    ///
    /// Used by proxy layers to skip DNS resolution when no policies require it.
    pub fn has_ip_rules(&self) -> bool {
        self.compiled_policies
            .iter()
            .any(|cp| cp.compiled_ip_rules.is_some())
    }
}

#[cfg(test)]
#[allow(deprecated)] // evaluate_action_with_context: migration tracked in FIND-CREATIVE-005
#[path = "engine_tests.rs"]
mod tests;
