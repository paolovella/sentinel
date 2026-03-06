// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! ABAC (Attribute-Based Access Control) engine — Cedar-style policy evaluation.
//!
//! Compiles ABAC policies at load time into a fast in-memory representation
//! and evaluates them with forbid-overrides semantics.

use crate::matcher::PatternMatcher;
use std::collections::{HashMap, HashSet};
use vellaveto_types::{
    is_unicode_format_char, AbacEffect, AbacEntity, AbacOp, AbacPolicy, Action, EvaluationContext,
    RiskScore,
};

/// A compiled path matcher that uses `globset::Glob` for patterns containing
/// wildcards (`*`, `**`, `?`, `[`) and falls back to `PatternMatcher` for simple
/// exact/prefix/suffix patterns.
///
/// SECURITY (FIND-P1-5): ABAC resource path matching must have parity with
/// the main engine's path rules, which use `globset::Glob`. Without this,
/// patterns like `/home/**/*.txt` would not match correctly.
#[derive(Debug, Clone)]
enum CompiledPathMatcher {
    /// Simple pattern (no glob metacharacters) — use PatternMatcher.
    Simple(PatternMatcher),
    /// Glob pattern — pre-compiled for fast matching.
    Glob(globset::GlobMatcher),
}

impl CompiledPathMatcher {
    /// Compile a path pattern. If the pattern contains glob metacharacters
    /// (`*`, `**`, `?`, `[`), compile as a glob. Otherwise, use PatternMatcher.
    ///
    /// Uses `literal_separator(true)` so that `*` does not match path
    /// separators (`/`), matching standard filesystem glob behavior. Only
    /// `**` crosses directory boundaries.
    ///
    /// SECURITY: If a glob pattern fails to compile, returns `None` (fail-closed).
    /// The caller must treat `None` as a deny.
    fn compile(pattern: &str) -> Option<Self> {
        let has_glob_meta = pattern.contains('*') || pattern.contains('?') || pattern.contains('[');

        if !has_glob_meta {
            // No glob metacharacters — simple exact match
            return Some(CompiledPathMatcher::Simple(PatternMatcher::compile(
                pattern,
            )));
        }

        // Try to compile as a glob with literal_separator so that `*` does
        // not cross `/` boundaries (only `**` does).
        match globset::GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
        {
            Ok(glob) => Some(CompiledPathMatcher::Glob(glob.compile_matcher())),
            Err(e) => {
                tracing::error!(
                    pattern = pattern,
                    error = %e,
                    "ABAC path pattern failed to compile as glob — fail-closed (deny)"
                );
                None // Fail-closed: caller treats as always-deny
            }
        }
    }

    /// Check if a path matches this compiled pattern.
    fn matches(&self, path: &str) -> bool {
        match self {
            CompiledPathMatcher::Simple(m) => m.matches(path),
            CompiledPathMatcher::Glob(g) => g.is_match(path),
        }
    }
}

/// Maximum transitive group membership depth to prevent cycles.
const MAX_MEMBERSHIP_DEPTH: usize = 16;

// ═══════════════════════════════════════════════════════════════════════════════
// ABAC EVALUATION RESULT
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of ABAC policy evaluation.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[must_use = "ABAC decisions must not be discarded"]
pub enum AbacDecision {
    /// An ABAC permit policy matched — allow the action.
    Allow { policy_id: String },
    /// An ABAC forbid policy matched — deny the action.
    Deny { policy_id: String, reason: String },
    /// No ABAC policy matched — fall through to existing verdict.
    NoMatch,
}

/// Conflict between permit and forbid policies on overlapping patterns.
#[derive(Debug, Clone)]
pub struct AbacConflict {
    pub permit_id: String,
    pub forbid_id: String,
    pub overlap_description: String,
}

// ═══════════════════════════════════════════════════════════════════════════════
// EVAL CONTEXT
// ═══════════════════════════════════════════════════════════════════════════════

/// Context for ABAC evaluation — combines EvaluationContext with resolved principal.
pub struct AbacEvalContext<'a> {
    pub eval_ctx: &'a EvaluationContext,
    pub principal_type: &'a str,
    pub principal_id: &'a str,
    pub risk_score: Option<&'a RiskScore>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPILED TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Compiled principal constraint with pre-built matchers.
struct CompiledPrincipal {
    principal_type: Option<String>,
    id_matchers: Vec<PatternMatcher>,
    claims: Vec<(String, PatternMatcher)>,
}

/// Compiled action constraint with pre-built tool:function matchers.
struct CompiledAction {
    /// Each pattern is "tool:function" split and compiled separately.
    matchers: Vec<(PatternMatcher, PatternMatcher)>,
}

/// Compiled resource constraint with pre-built path/domain matchers.
///
/// SECURITY (FIND-P1-5): Path matchers use `CompiledPathMatcher` which
/// delegates to `globset::Glob` for patterns containing wildcards. If any
/// path pattern fails to compile, the entire resource becomes a "fail-closed
/// deny" (no action can match it) via the `path_compile_failed` flag.
struct CompiledResource {
    path_matchers: Vec<CompiledPathMatcher>,
    domain_matchers: Vec<PatternMatcher>,
    tags: Vec<String>,
    /// Set to true if any path pattern failed to compile as a glob.
    /// When true, `matches_resource` returns false (fail-closed).
    path_compile_failed: bool,
}

/// Compiled ABAC condition — ready for evaluation.
struct CompiledCondition {
    field: String,
    op: AbacOp,
    value: serde_json::Value,
}

/// A fully compiled ABAC policy ready for evaluation.
struct CompiledAbacPolicy {
    id: String,
    effect: AbacEffect,
    priority: i32,
    principal: CompiledPrincipal,
    action: CompiledAction,
    resource: CompiledResource,
    conditions: Vec<CompiledCondition>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENTITY STORE
// ═══════════════════════════════════════════════════════════════════════════════

/// In-memory entity store for ABAC principal/resource attributes.
///
/// # Security
///
/// This store is the authority for group membership lookups used by ABAC
/// principal matching. Membership queries (`is_member_of`) are bounded
/// by [`MAX_MEMBERSHIP_DEPTH`] and use a visited set to prevent cycles
/// and exponential blowup in diamond-shaped group hierarchies.
pub struct EntityStore {
    /// Entities keyed by "Type::id".
    entities: HashMap<String, AbacEntity>,
    /// Group membership: entity_key → parent entity_keys.
    memberships: HashMap<String, Vec<String>>,
}

impl EntityStore {
    /// Build an entity store from config entities.
    pub fn from_config(entities: &[AbacEntity]) -> Self {
        let mut map = HashMap::new();
        let mut memberships = HashMap::new();
        for entity in entities {
            let key = format!("{}::{}", entity.entity_type, entity.id);
            memberships.insert(key.clone(), entity.parents.clone());
            map.insert(key, entity.clone());
        }
        Self {
            entities: map,
            memberships,
        }
    }

    /// Look up an entity by type and ID.
    pub fn lookup(&self, entity_type: &str, id: &str) -> Option<&AbacEntity> {
        let key = format!("{entity_type}::{id}");
        self.entities.get(&key)
    }

    /// Check if an entity is a (transitive) member of a group.
    /// Bounded to MAX_MEMBERSHIP_DEPTH to prevent infinite loops.
    /// Uses a visited set to prevent exponential blowup through diamond-shaped
    /// membership graphs (FIND-R44-001).
    pub fn is_member_of(&self, entity_key: &str, group_key: &str) -> bool {
        let mut visited = HashSet::new();
        self.is_member_of_bounded(entity_key, group_key, 0, &mut visited)
    }

    fn is_member_of_bounded(
        &self,
        entity_key: &str,
        group_key: &str,
        depth: usize,
        visited: &mut HashSet<String>,
    ) -> bool {
        if depth >= MAX_MEMBERSHIP_DEPTH {
            return false;
        }
        // FIND-R44-001: Skip entities already visited through a different path
        // to prevent exponential blowup in diamond-shaped graphs.
        if !visited.insert(entity_key.to_string()) {
            return false;
        }
        if let Some(parents) = self.memberships.get(entity_key) {
            for parent in parents {
                if parent == group_key {
                    return true;
                }
                if self.is_member_of_bounded(parent, group_key, depth + 1, visited) {
                    return true;
                }
            }
        }
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ABAC ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

/// The ABAC policy evaluation engine.
///
/// Compiles policies at construction time and evaluates them with
/// forbid-overrides semantics (any matching forbid wins over all permits).
pub struct AbacEngine {
    compiled: Vec<CompiledAbacPolicy>,
    entity_store: EntityStore,
}

/// Maximum number of ABAC entities to prevent memory exhaustion during engine construction.
///
/// SECURITY (FIND-R111-003): Unbounded entity lists from operator-supplied configuration
/// could cause OOM when building the EntityStore.
const MAX_ABAC_ENTITIES: usize = 10_000;

impl AbacEngine {
    /// Create an ABAC engine from policies and entities.
    ///
    /// Compiles all policies and builds the entity store. Returns an error
    /// if any policy pattern is invalid or entity bounds are exceeded.
    pub fn new(policies: &[AbacPolicy], entities: &[AbacEntity]) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(policies.len());
        for policy in policies {
            // SECURITY: Validate policy bounds before compiling to reject
            // oversized conditions, patterns, or other bounded fields early.
            policy
                .validate()
                .map_err(|e| format!("ABAC policy '{}' validation failed: {e}", policy.id))?;
            compiled.push(compile_policy(policy)?);
        }
        // Sort by priority descending (higher priority first)
        compiled.sort_by(|a, b| b.priority.cmp(&a.priority));

        // SECURITY (FIND-R111-003): Validate entity count and each entity's bounds
        // before building the EntityStore. Without this, attacker-controlled entity
        // lists bypass AbacEntity::validate() bounds and can cause OOM.
        if entities.len() > MAX_ABAC_ENTITIES {
            return Err(format!(
                "ABAC entity count {} exceeds maximum {}",
                entities.len(),
                MAX_ABAC_ENTITIES
            ));
        }
        for entity in entities {
            entity.validate().map_err(|e| {
                format!(
                    "ABAC entity '{}::{}' validation failed: {e}",
                    entity.entity_type, entity.id
                )
            })?;
        }

        let entity_store = EntityStore::from_config(entities);
        Ok(Self {
            compiled,
            entity_store,
        })
    }

    // VERIFIED [S7]: Forbid-overrides — a single Forbid beats any number of Permits (AbacForbidOverrides.tla S7)
    /// Evaluate an action against all ABAC policies.
    ///
    /// Uses forbid-overrides semantics:
    /// 1. Collect matching policies (principal + action + resource + conditions)
    /// 2. If any matching policy is Forbid → Deny
    /// 3. If any matching policy is Permit (and no Forbid) → Allow
    /// 4. If nothing matches → NoMatch (caller decides)
    #[must_use = "ABAC decisions must not be discarded"]
    pub fn evaluate(&self, action: &Action, ctx: &AbacEvalContext<'_>) -> AbacDecision {
        let mut best_permit: Option<&str> = None;

        for policy in &self.compiled {
            if !matches_principal(&policy.principal, ctx, &self.entity_store) {
                continue;
            }
            if !matches_action(&policy.action, action) {
                continue;
            }
            if !matches_resource(&policy.resource, action) {
                continue;
            }
            if !evaluate_conditions(&policy.conditions, ctx) {
                continue;
            }

            match policy.effect {
                AbacEffect::Forbid => {
                    // SECURITY (FIND-R58-ENG-008): Early exit on first Forbid match.
                    // With forbid-overrides semantics, no subsequent match can change
                    // the outcome. Continuing wastes CPU on the critical evaluation path.
                    return AbacDecision::Deny {
                        policy_id: policy.id.clone(),
                        reason: format!("ABAC forbid policy '{}' matched", policy.id),
                    };
                }
                AbacEffect::Permit => {
                    if best_permit.is_none() {
                        best_permit = Some(&policy.id);
                    }
                }
            }
        }

        if let Some(id) = best_permit {
            return AbacDecision::Allow {
                policy_id: id.to_string(),
            };
        }

        AbacDecision::NoMatch
    }

    /// Get a reference to the entity store.
    pub fn entity_store(&self) -> &EntityStore {
        &self.entity_store
    }

    /// Detect conflicts where permit and forbid policies overlap.
    pub fn find_conflicts(&self) -> Vec<AbacConflict> {
        let mut conflicts = Vec::new();
        let permits: Vec<_> = self
            .compiled
            .iter()
            .filter(|p| p.effect == AbacEffect::Permit)
            .collect();
        let forbids: Vec<_> = self
            .compiled
            .iter()
            .filter(|p| p.effect == AbacEffect::Forbid)
            .collect();

        for permit in &permits {
            for forbid in &forbids {
                if action_patterns_overlap(&permit.action, &forbid.action) {
                    conflicts.push(AbacConflict {
                        permit_id: permit.id.clone(),
                        forbid_id: forbid.id.clone(),
                        overlap_description: format!(
                            "Permit '{}' and Forbid '{}' have overlapping action patterns",
                            permit.id, forbid.id
                        ),
                    });
                }
            }
        }
        conflicts
    }

    /// Return the number of compiled policies.
    pub fn policy_count(&self) -> usize {
        self.compiled.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPILATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Known condition fields that can be resolved at evaluation time.
const KNOWN_CONDITION_FIELDS: &[&str] = &[
    "principal.type",
    "principal.id",
    "risk.score",
    "context.agent_id",
    "context.tenant_id",
    "context.call_chain_depth",
];

fn compile_policy(policy: &AbacPolicy) -> Result<CompiledAbacPolicy, String> {
    let principal = compile_principal(&policy.principal);
    let action = compile_action(&policy.action);
    let resource = compile_resource(&policy.resource)?;

    // SECURITY (FIND-R46-008): Validate condition fields at compile time.
    // Reject conditions with empty field names, and warn about unknown fields
    // (fields not in the known set and not starting with "claims." prefix).
    let mut conditions = Vec::with_capacity(policy.conditions.len());
    for c in &policy.conditions {
        if c.field.is_empty() {
            return Err(format!(
                "ABAC policy '{}' has a condition with an empty field name",
                policy.id
            ));
        }
        // SECURITY (P3-ENG-001): Reject control characters and Unicode format characters
        // in condition field names. A field like "context.agent_id\x00suffix" would not
        // match any known key (silently resolving to Null), which can bypass Forbid
        // conditions that compare against expected values.
        if c.field
            .chars()
            .any(|ch| ch.is_control() || is_unicode_format_char(ch))
        {
            return Err(format!(
                "ABAC policy '{}' has a condition with control or format characters in field name: {:?}",
                policy.id,
                c.field.escape_debug().to_string()
            ));
        }
        if !KNOWN_CONDITION_FIELDS.contains(&c.field.as_str()) && !c.field.starts_with("claims.") {
            tracing::warn!(
                policy_id = %policy.id,
                field = %c.field,
                "ABAC condition references unknown field — will resolve to null at evaluation time"
            );
        }
        // SECURITY: For numeric comparison operators, validate that the condition
        // value is a finite number. NaN/Infinity in the condition value causes all
        // comparisons to return false, silently bypassing Forbid policies.
        if matches!(c.op, AbacOp::Gt | AbacOp::Lt | AbacOp::Gte | AbacOp::Lte) {
            match c.value.as_f64() {
                Some(v) if !v.is_finite() => {
                    return Err(format!(
                        "ABAC policy '{}' condition on field '{}' has non-finite numeric value",
                        policy.id, c.field
                    ));
                }
                None => {
                    return Err(format!(
                        "ABAC policy '{}' condition on field '{}' uses numeric operator {:?} but value is not a number",
                        policy.id, c.field, c.op
                    ));
                }
                _ => {} // finite number, OK
            }
        }
        conditions.push(CompiledCondition {
            field: c.field.clone(),
            op: c.op,
            value: c.value.clone(),
        });
    }

    Ok(CompiledAbacPolicy {
        id: policy.id.clone(),
        effect: policy.effect,
        priority: policy.priority,
        principal,
        action,
        resource,
        conditions,
    })
}

fn compile_principal(pc: &vellaveto_types::PrincipalConstraint) -> CompiledPrincipal {
    CompiledPrincipal {
        principal_type: pc.principal_type.clone(),
        id_matchers: pc
            .id_patterns
            .iter()
            .map(|p| PatternMatcher::compile(p))
            .collect(),
        claims: pc
            .claims
            .iter()
            .map(|(k, v)| (k.clone(), PatternMatcher::compile(v)))
            .collect(),
    }
}

fn compile_action(ac: &vellaveto_types::ActionConstraint) -> CompiledAction {
    let matchers = ac
        .patterns
        .iter()
        .map(|p| {
            if let Some((tool, func)) = p.split_once(':') {
                (PatternMatcher::compile(tool), PatternMatcher::compile(func))
            } else {
                // No colon — treat as tool-only match (any function)
                (PatternMatcher::compile(p), PatternMatcher::compile("*"))
            }
        })
        .collect();
    CompiledAction { matchers }
}

fn compile_resource(rc: &vellaveto_types::ResourceConstraint) -> Result<CompiledResource, String> {
    let mut path_matchers = Vec::with_capacity(rc.path_patterns.len());
    let mut path_compile_failed = false;

    for pattern in &rc.path_patterns {
        match CompiledPathMatcher::compile(pattern) {
            Some(m) => path_matchers.push(m),
            None => {
                // SECURITY (FIND-P1-5): Glob compilation failed — fail-closed.
                // We still collect remaining matchers for diagnostics, but mark
                // the resource as failed so matches_resource always returns false.
                path_compile_failed = true;
            }
        }
    }

    Ok(CompiledResource {
        path_matchers,
        domain_matchers: rc
            .domain_patterns
            .iter()
            .map(|p| PatternMatcher::compile(p))
            .collect(),
        tags: rc.tags.clone(),
        path_compile_failed,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// MATCHING
// ═══════════════════════════════════════════════════════════════════════════════

fn matches_principal(
    principal: &CompiledPrincipal,
    ctx: &AbacEvalContext<'_>,
    entity_store: &EntityStore,
) -> bool {
    // SECURITY (FIND-R215-007, R228-ENG-2): Normalize both required_type and ctx.principal_type
    // through normalize_full() (NFKC + lowercase + homoglyphs) to prevent circled/fullwidth
    // characters from bypassing principal type matching in ABAC policies.
    // Type check
    if let Some(ref required_type) = principal.principal_type {
        let norm_required = crate::normalize::normalize_full(required_type);
        let norm_ctx_type = crate::normalize::normalize_full(ctx.principal_type);
        if norm_required != norm_ctx_type {
            // Check group membership: maybe this principal is a member of the required type
            let entity_key = format!("{}::{}", ctx.principal_type, ctx.principal_id);
            let group_key = format!("{}::{}", required_type, ctx.principal_id);
            if entity_key != group_key && !entity_store.is_member_of(&entity_key, &group_key) {
                return false;
            }
        }
    }

    // SECURITY (FIND-R215-004, R228-ENG-2): Normalize principal_id through normalize_full()
    // before matching against compiled id_matchers. Patterns are normalized at compile
    // time; runtime input must also be normalized to prevent Cyrillic/fullwidth
    // characters from bypassing Forbid policies.
    // ID pattern check
    if !principal.id_matchers.is_empty() {
        let norm_id = crate::normalize::normalize_full(ctx.principal_id);
        if !principal.id_matchers.iter().any(|m| m.matches(&norm_id)) {
            return false;
        }
    }

    // Claims check
    for (claim_key, pattern) in &principal.claims {
        // SECURITY (FIND-R49-010): Absent claim must not match — returning false
        // when the key is missing prevents treating missing claims as empty strings,
        // which would incorrectly match patterns like "" or wildcard.
        let claim_value = match ctx
            .eval_ctx
            .agent_identity
            .as_ref()
            .and_then(|id| id.claims.get(claim_key))
        {
            Some(v) => v.as_str().unwrap_or(""),
            None => return false,
        };
        // SECURITY (FIND-R215-005, R228-ENG-2): Normalize claim values through normalize_full()
        // before matching against compiled patterns. Without this, Cyrillic/fullwidth
        // characters in JWT claim values bypass ABAC principal claim checks.
        let norm_claim = crate::normalize::normalize_full(claim_value);
        if !pattern.matches(&norm_claim) {
            return false;
        }
    }

    true
}

fn matches_action(action_constraint: &CompiledAction, action: &Action) -> bool {
    // Empty patterns = match any action
    if action_constraint.matchers.is_empty() {
        return true;
    }
    // SECURITY (FIND-R206-002, R228-ENG-2): Normalize tool/function names through
    // normalize_full() (NFKC + lowercase + homoglyphs) before ABAC matching. Patterns
    // are normalized at compile time; input must also be normalized to prevent
    // circled/Cyrillic/Greek/fullwidth characters from bypassing Forbid policies.
    let norm_tool = crate::normalize::normalize_full(&action.tool);
    let norm_func = crate::normalize::normalize_full(&action.function);
    action_constraint.matchers.iter().any(|(tool_m, func_m)| {
        tool_m.matches_normalized(&norm_tool) && func_m.matches_normalized(&norm_func)
    })
}

fn matches_resource(resource: &CompiledResource, action: &Action) -> bool {
    // SECURITY (FIND-P1-5): If any path pattern failed to compile as a glob,
    // fail-closed — no action can match this resource constraint.
    if resource.path_compile_failed {
        return false;
    }

    // Path check: if patterns specified, at least one path must match
    // SECURITY (FIND-R46-001): Apply path normalization before matching to prevent
    // traversal bypasses (e.g., "/home/../etc/passwd" matching "/home/*").
    if !resource.path_matchers.is_empty() {
        if action.target_paths.is_empty() {
            return false;
        }
        let any_path_matches = action.target_paths.iter().any(|path| {
            // SECURITY (FIND-R49-001): Use bounded path normalization.
            // SECURITY (FIND-R149-006): On normalization failure, skip the path
            // (return false for this path). This is fail-closed because:
            // - Permit policies won't match → no false Allow
            // - Forbid policies won't match → but unmatched actions still need a
            //   Permit to be allowed, so the result is NoMatch → Deny at caller
            // Previous behavior was `unwrap_or_else(|_| "/".to_string())` which
            // was unpredictable: "/" could match broad Permit patterns like "/**"
            // (false Allow) or miss specific Forbid patterns (false pass).
            let normalized = match crate::path::normalize_path_bounded(
                path,
                crate::path::DEFAULT_MAX_PATH_DECODE_ITERATIONS,
            ) {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(
                        path = %path,
                        error = %e,
                        "ABAC resource match: path normalization failed — skipping path (fail-closed)"
                    );
                    return false;
                }
            };
            resource
                .path_matchers
                .iter()
                .any(|m| m.matches(&normalized))
        });
        if !any_path_matches {
            return false;
        }
    }

    // Domain check: if patterns specified, at least one domain must match
    // SECURITY (FIND-R46-002): Apply domain normalization (lowercase, trim trailing dots)
    // before matching to prevent bypass via case or trailing dot variations.
    // SECURITY (FIND-P2-001): Apply full IDNA normalization via normalize_domain_for_match()
    // to prevent bypass via internationalized domain name variations (e.g., punycode vs
    // Unicode, homoglyphs). Domains that fail IDNA normalization are rejected (fail-closed).
    if !resource.domain_matchers.is_empty() {
        if action.target_domains.is_empty() {
            return false;
        }
        let any_domain_matches = action.target_domains.iter().any(|domain| {
            let normalized = match crate::domain::normalize_domain_for_match(domain) {
                Some(cow) => cow.into_owned(),
                None => {
                    // SECURITY (FIND-P2-001): Fail-closed — domain cannot be IDNA-normalized.
                    tracing::warn!(
                        domain = %domain,
                        "ABAC resource domain match: domain failed IDNA normalization — fail-closed"
                    );
                    return false;
                }
            };
            resource
                .domain_matchers
                .iter()
                .any(|m| m.matches(&normalized))
        });
        if !any_domain_matches {
            return false;
        }
    }

    // Tags check: all tags must be present (checked against action parameters)
    // Tags are metadata labels — for now we check if they appear as parameter keys
    if !resource.tags.is_empty() {
        if let Some(params) = action.parameters.as_object() {
            for tag in &resource.tags {
                if !params.contains_key(tag) {
                    return false;
                }
            }
        } else {
            return false;
        }
    }

    true
}

fn evaluate_conditions(conditions: &[CompiledCondition], ctx: &AbacEvalContext<'_>) -> bool {
    // SECURITY (FIND-R46-008): Log a warning when conditions array is empty.
    // Empty conditions = no restrictions is correct for ABAC (vacuous truth),
    // but it may indicate a misconfiguration. Compile-time validation in
    // compile_policy() ensures condition fields are well-formed.
    if conditions.is_empty() {
        tracing::trace!("ABAC policy has empty conditions array — matches unconditionally");
    }
    conditions.iter().all(|c| evaluate_single_condition(c, ctx))
}

fn evaluate_single_condition(condition: &CompiledCondition, ctx: &AbacEvalContext<'_>) -> bool {
    let field_value = resolve_field(&condition.field, ctx);
    match condition.op {
        AbacOp::Eq => field_value == condition.value,
        AbacOp::Ne => field_value != condition.value,
        AbacOp::In => {
            if let Some(arr) = condition.value.as_array() {
                arr.contains(&field_value)
            } else {
                false
            }
        }
        AbacOp::NotIn => {
            if let Some(arr) = condition.value.as_array() {
                !arr.contains(&field_value)
            } else {
                // SECURITY (FIND-R46-009): Fail-closed when NotIn policy value is
                // not an array. A non-array value indicates a misconfigured policy.
                // Previously returned `true` (pass), allowing the action through.
                // Now returns `false` (condition fails → policy doesn't match),
                // which is fail-closed because unmatched policies don't permit.
                false
            }
        }
        AbacOp::Contains => {
            if let (Some(haystack), Some(needle)) = (field_value.as_str(), condition.value.as_str())
            {
                haystack.contains(needle)
            } else {
                false
            }
        }
        AbacOp::StartsWith => {
            if let (Some(s), Some(prefix)) = (field_value.as_str(), condition.value.as_str()) {
                s.starts_with(prefix)
            } else {
                false
            }
        }
        AbacOp::Gt => compare_numbers(&field_value, &condition.value, |a, b| a > b),
        AbacOp::Lt => compare_numbers(&field_value, &condition.value, |a, b| a < b),
        AbacOp::Gte => compare_numbers(&field_value, &condition.value, |a, b| a >= b),
        AbacOp::Lte => compare_numbers(&field_value, &condition.value, |a, b| a <= b),
    }
}

fn compare_numbers(
    a: &serde_json::Value,
    b: &serde_json::Value,
    cmp: fn(f64, f64) -> bool,
) -> bool {
    match (a.as_f64(), b.as_f64()) {
        // SECURITY (FIND-R215-006): Guard against NaN/Infinity values that could
        // cause unpredictable comparison results (NaN < x is always false, etc.).
        // Non-finite values in either operand cause the comparison to fail-closed.
        (Some(av), Some(bv)) if av.is_finite() && bv.is_finite() => cmp(av, bv),
        _ => false,
    }
}

fn resolve_field(field: &str, ctx: &AbacEvalContext<'_>) -> serde_json::Value {
    match field {
        "principal.type" => serde_json::Value::String(ctx.principal_type.to_string()),
        "principal.id" => serde_json::Value::String(ctx.principal_id.to_string()),
        // SECURITY (FIND-R48-002): Non-finite risk.score (NaN/Inf) must fail-closed.
        // json!(NaN) produces Null, which would cause Forbid conditions to not match.
        // Treat non-finite scores as maximum risk (1.0) to ensure Forbid policies fire.
        "risk.score" => ctx
            .risk_score
            .map(|r| {
                if r.score.is_finite() {
                    serde_json::json!(r.score)
                } else {
                    tracing::warn!(
                        "ABAC resolve_field: risk.score is non-finite ({}) — treating as max risk",
                        r.score
                    );
                    serde_json::json!(1.0)
                }
            })
            .unwrap_or(serde_json::Value::Null),
        "context.agent_id" => ctx
            .eval_ctx
            .agent_id
            .as_ref()
            .map(|s| serde_json::Value::String(s.clone()))
            .unwrap_or(serde_json::Value::Null),
        "context.tenant_id" => ctx
            .eval_ctx
            .tenant_id
            .as_ref()
            .map(|s| serde_json::Value::String(s.clone()))
            .unwrap_or(serde_json::Value::Null),
        "context.call_chain_depth" => {
            serde_json::json!(ctx.eval_ctx.call_chain_depth())
        }
        _ => {
            // Try to resolve from agent identity claims: "claims.<key>"
            if let Some(claim_key) = field.strip_prefix("claims.") {
                ctx.eval_ctx
                    .agent_identity
                    .as_ref()
                    .and_then(|id| id.claims.get(claim_key).cloned())
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        }
    }
}

/// Check if two action constraints could match the same action.
fn action_patterns_overlap(a: &CompiledAction, b: &CompiledAction) -> bool {
    // Empty patterns match everything, so they always overlap
    if a.matchers.is_empty() || b.matchers.is_empty() {
        return true;
    }
    // Check pairwise — conservative: if any pair could overlap, report it
    for (at, af) in &a.matchers {
        for (bt, bf) in &b.matchers {
            if patterns_could_overlap(at, bt) && patterns_could_overlap(af, bf) {
                return true;
            }
        }
    }
    false
}

/// Conservative check: could two pattern matchers match the same string?
fn patterns_could_overlap(a: &PatternMatcher, b: &PatternMatcher) -> bool {
    match (a, b) {
        (PatternMatcher::Any, _) | (_, PatternMatcher::Any) => true,
        (PatternMatcher::Exact(x), PatternMatcher::Exact(y)) => x == y,
        (PatternMatcher::Exact(e), PatternMatcher::Prefix(p))
        | (PatternMatcher::Prefix(p), PatternMatcher::Exact(e)) => e.starts_with(p.as_str()),
        (PatternMatcher::Exact(e), PatternMatcher::Suffix(s))
        | (PatternMatcher::Suffix(s), PatternMatcher::Exact(e)) => e.ends_with(s.as_str()),
        // For prefix/suffix/prefix-prefix/suffix-suffix, conservatively assume overlap
        _ => true,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_types::*;

    fn make_action(tool: &str, function: &str) -> Action {
        Action {
            tool: tool.to_string(),
            function: function.to_string(),
            parameters: serde_json::json!({}),
            target_paths: Vec::new(),
            target_domains: Vec::new(),
            resolved_ips: Vec::new(),
        }
    }

    fn make_action_with_paths(tool: &str, function: &str, paths: Vec<&str>) -> Action {
        Action {
            tool: tool.to_string(),
            function: function.to_string(),
            parameters: serde_json::json!({}),
            target_paths: paths.into_iter().map(String::from).collect(),
            target_domains: Vec::new(),
            resolved_ips: Vec::new(),
        }
    }

    fn make_action_with_domains(tool: &str, function: &str, domains: Vec<&str>) -> Action {
        Action {
            tool: tool.to_string(),
            function: function.to_string(),
            parameters: serde_json::json!({}),
            target_paths: Vec::new(),
            target_domains: domains.into_iter().map(String::from).collect(),
            resolved_ips: Vec::new(),
        }
    }

    fn make_permit_policy(id: &str, tool_pattern: &str) -> AbacPolicy {
        AbacPolicy {
            id: id.to_string(),
            description: format!("Permit {}", id),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: ActionConstraint {
                patterns: vec![tool_pattern.to_string()],
            },
            resource: Default::default(),
            conditions: vec![],
        }
    }

    fn make_forbid_policy(id: &str, tool_pattern: &str) -> AbacPolicy {
        AbacPolicy {
            id: id.to_string(),
            description: format!("Forbid {}", id),
            effect: AbacEffect::Forbid,
            priority: 0,
            principal: Default::default(),
            action: ActionConstraint {
                patterns: vec![tool_pattern.to_string()],
            },
            resource: Default::default(),
            conditions: vec![],
        }
    }

    fn make_ctx<'a>(
        eval_ctx: &'a EvaluationContext,
        principal_type: &'a str,
        principal_id: &'a str,
    ) -> AbacEvalContext<'a> {
        AbacEvalContext {
            eval_ctx,
            principal_type,
            principal_id,
            risk_score: None,
        }
    }

    fn make_engine(policies: Vec<AbacPolicy>) -> AbacEngine {
        AbacEngine::new(&policies, &[]).unwrap()
    }

    #[test]
    fn test_compile_valid_policies() {
        let engine = make_engine(vec![make_permit_policy("p1", "filesystem:read*")]);
        assert_eq!(engine.policy_count(), 1);
    }

    #[test]
    fn test_compile_empty_policies() {
        let engine = make_engine(vec![]);
        assert_eq!(engine.policy_count(), 0);
    }

    #[test]
    fn test_evaluate_permit_matches() {
        let engine = make_engine(vec![make_permit_policy("p1", "filesystem:read*")]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test-agent");
        let action = make_action("filesystem", "read_file");

        match engine.evaluate(&action, &ctx) {
            AbacDecision::Allow { policy_id } => assert_eq!(policy_id, "p1"),
            other => panic!("Expected Allow, got {:?}", other),
        }
    }

    #[test]
    fn test_evaluate_forbid_overrides_permit() {
        let engine = make_engine(vec![
            make_permit_policy("permit-all", "*:*"),
            make_forbid_policy("forbid-bash", "bash:*"),
        ]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        let action = make_action("bash", "execute");

        match engine.evaluate(&action, &ctx) {
            AbacDecision::Deny { policy_id, .. } => assert_eq!(policy_id, "forbid-bash"),
            other => panic!("Expected Deny, got {:?}", other),
        }
    }

    #[test]
    fn test_evaluate_no_match_returns_nomatch() {
        let engine = make_engine(vec![make_permit_policy("p1", "filesystem:read*")]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        let action = make_action("network", "fetch");

        assert_eq!(engine.evaluate(&action, &ctx), AbacDecision::NoMatch);
    }

    #[test]
    fn test_evaluate_principal_type_match() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "Only for Agents".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: PrincipalConstraint {
                principal_type: Some("Agent".to_string()),
                id_patterns: vec![],
                claims: HashMap::new(),
            },
            action: ActionConstraint {
                patterns: vec!["*:*".to_string()],
            },
            resource: Default::default(),
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();

        // Agent matches
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));

        // Service doesn't match
        let ctx = make_ctx(&eval_ctx, "Service", "test");
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_evaluate_principal_id_glob() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "code-* agents".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: PrincipalConstraint {
                principal_type: None,
                id_patterns: vec!["code-*".to_string()],
                claims: HashMap::new(),
            },
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();

        let ctx = make_ctx(&eval_ctx, "Agent", "code-assistant");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));

        let ctx = make_ctx(&eval_ctx, "Agent", "data-pipeline");
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_evaluate_principal_claims_match() {
        let mut claims = HashMap::new();
        claims.insert("team".to_string(), "security*".to_string());

        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "security team".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: PrincipalConstraint {
                principal_type: None,
                id_patterns: vec![],
                claims,
            },
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);

        // Matching claim
        let mut identity_claims = HashMap::new();
        identity_claims.insert("team".to_string(), serde_json::json!("security-ops"));
        let eval_ctx = EvaluationContext {
            agent_identity: Some(AgentIdentity {
                claims: identity_claims,
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));

        // Non-matching claim
        let mut identity_claims = HashMap::new();
        identity_claims.insert("team".to_string(), serde_json::json!("engineering"));
        let eval_ctx = EvaluationContext {
            agent_identity: Some(AgentIdentity {
                claims: identity_claims,
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_evaluate_action_tool_function_match() {
        let engine = make_engine(vec![make_permit_policy("p1", "filesystem:write_file")]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        // Exact match
        assert!(matches!(
            engine.evaluate(&make_action("filesystem", "write_file"), &ctx),
            AbacDecision::Allow { .. }
        ));
        // Different function
        assert_eq!(
            engine.evaluate(&make_action("filesystem", "read_file"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_evaluate_action_wildcard() {
        let engine = make_engine(vec![make_permit_policy("p1", "*:*")]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        assert!(matches!(
            engine.evaluate(&make_action("anything", "anything"), &ctx),
            AbacDecision::Allow { .. }
        ));
    }

    #[test]
    fn test_evaluate_resource_path_match() {
        // FIND-P1-5: Updated from `/home/*` to `/home/**` because with
        // proper globset matching, `*` no longer crosses path separators.
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "home dir only".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: ResourceConstraint {
                path_patterns: vec!["/home/**".to_string()],
                domain_patterns: vec![],
                tags: vec![],
            },
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        // Matching path
        let action = make_action_with_paths("fs", "read", vec!["/home/user/file.txt"]);
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));

        // Non-matching path
        let action = make_action_with_paths("fs", "read", vec!["/etc/passwd"]);
        assert_eq!(engine.evaluate(&action, &ctx), AbacDecision::NoMatch);

        // No paths at all → fails resource match
        let action = make_action("fs", "read");
        assert_eq!(engine.evaluate(&action, &ctx), AbacDecision::NoMatch);
    }

    #[test]
    fn test_evaluate_resource_domain_match() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "example.com only".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: ResourceConstraint {
                path_patterns: vec![],
                domain_patterns: vec!["*example.com".to_string()],
                tags: vec![],
            },
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        let action = make_action_with_domains("net", "fetch", vec!["api.example.com"]);
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));
    }

    #[test]
    fn test_evaluate_resource_tags_match() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "tagged resources".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: ResourceConstraint {
                path_patterns: vec![],
                domain_patterns: vec![],
                tags: vec!["sensitive".to_string()],
            },
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        let mut action = make_action("fs", "read");
        action.parameters = serde_json::json!({"sensitive": true, "path": "/tmp"});
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));

        // Missing tag
        let mut action = make_action("fs", "read");
        action.parameters = serde_json::json!({"path": "/tmp"});
        assert_eq!(engine.evaluate(&action, &ctx), AbacDecision::NoMatch);
    }

    #[test]
    fn test_evaluate_condition_eq() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "tenant check".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![AbacCondition {
                field: "context.tenant_id".to_string(),
                op: AbacOp::Eq,
                value: serde_json::json!("acme"),
            }],
        };
        let engine = make_engine(vec![policy]);

        let eval_ctx = EvaluationContext {
            tenant_id: Some("acme".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));

        let eval_ctx = EvaluationContext {
            tenant_id: Some("other".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_evaluate_condition_in() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "tenant in list".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![AbacCondition {
                field: "context.tenant_id".to_string(),
                op: AbacOp::In,
                value: serde_json::json!(["acme", "globex"]),
            }],
        };
        let engine = make_engine(vec![policy]);

        let eval_ctx = EvaluationContext {
            tenant_id: Some("acme".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));
    }

    #[test]
    fn test_evaluate_condition_starts_with() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "agent prefix".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![AbacCondition {
                field: "context.agent_id".to_string(),
                op: AbacOp::StartsWith,
                value: serde_json::json!("prod-"),
            }],
        };
        let engine = make_engine(vec![policy]);

        let eval_ctx = EvaluationContext {
            agent_id: Some("prod-agent-1".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));
    }

    #[test]
    fn test_evaluate_condition_gt_lt() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "low risk only".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![AbacCondition {
                field: "risk.score".to_string(),
                op: AbacOp::Lt,
                value: serde_json::json!(0.5),
            }],
        };
        let engine = make_engine(vec![policy]);

        let risk = RiskScore {
            score: 0.3,
            factors: vec![],
            updated_at: "2026-02-14T00:00:00Z".to_string(),
        };
        let eval_ctx = EvaluationContext::default();
        let ctx = AbacEvalContext {
            eval_ctx: &eval_ctx,
            principal_type: "Agent",
            principal_id: "test",
            risk_score: Some(&risk),
        };
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));

        let risk = RiskScore {
            score: 0.8,
            factors: vec![],
            updated_at: "2026-02-14T00:00:00Z".to_string(),
        };
        let ctx = AbacEvalContext {
            eval_ctx: &eval_ctx,
            principal_type: "Agent",
            principal_id: "test",
            risk_score: Some(&risk),
        };
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_evaluate_multiple_conditions_all_must_pass() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "both conditions".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![
                AbacCondition {
                    field: "context.tenant_id".to_string(),
                    op: AbacOp::Eq,
                    value: serde_json::json!("acme"),
                },
                AbacCondition {
                    field: "context.agent_id".to_string(),
                    op: AbacOp::Eq,
                    value: serde_json::json!("agent-1"),
                },
            ],
        };
        let engine = make_engine(vec![policy]);

        // Both match
        let eval_ctx = EvaluationContext {
            tenant_id: Some("acme".to_string()),
            agent_id: Some("agent-1".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));

        // Only one matches
        let eval_ctx = EvaluationContext {
            tenant_id: Some("acme".to_string()),
            agent_id: Some("agent-2".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_evaluate_priority_ordering() {
        // Higher priority permit should be reported even if lower priority forbid exists
        // But forbid-overrides means forbid always wins regardless of priority
        let engine = make_engine(vec![
            AbacPolicy {
                id: "high-permit".to_string(),
                description: "high priority permit".to_string(),
                effect: AbacEffect::Permit,
                priority: 100,
                principal: Default::default(),
                action: ActionConstraint {
                    patterns: vec!["*:*".to_string()],
                },
                resource: Default::default(),
                conditions: vec![],
            },
            AbacPolicy {
                id: "low-forbid".to_string(),
                description: "low priority forbid".to_string(),
                effect: AbacEffect::Forbid,
                priority: 1,
                principal: Default::default(),
                action: ActionConstraint {
                    patterns: vec!["*:*".to_string()],
                },
                resource: Default::default(),
                conditions: vec![],
            },
        ]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        // Forbid wins even with lower priority
        match engine.evaluate(&make_action("any", "any"), &ctx) {
            AbacDecision::Deny { policy_id, .. } => assert_eq!(policy_id, "low-forbid"),
            other => panic!("Expected Deny, got {:?}", other),
        }
    }

    #[test]
    fn test_evaluate_fail_closed_missing_principal() {
        // Policy requires specific principal type, context has different type
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "admins only".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: PrincipalConstraint {
                principal_type: Some("Admin".to_string()),
                id_patterns: vec![],
                claims: HashMap::new(),
            },
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "anonymous");

        // No match → fail-closed at the caller
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    #[test]
    fn test_entity_store_lookup() {
        let entities = vec![AbacEntity {
            entity_type: "Agent".to_string(),
            id: "agent-1".to_string(),
            attributes: HashMap::new(),
            parents: vec![],
        }];
        let store = EntityStore::from_config(&entities);
        assert!(store.lookup("Agent", "agent-1").is_some());
        assert!(store.lookup("Agent", "nonexistent").is_none());
    }

    #[test]
    fn test_entity_store_group_membership() {
        let entities = vec![
            AbacEntity {
                entity_type: "Group".to_string(),
                id: "admins".to_string(),
                attributes: HashMap::new(),
                parents: vec![],
            },
            AbacEntity {
                entity_type: "Agent".to_string(),
                id: "agent-1".to_string(),
                attributes: HashMap::new(),
                parents: vec!["Group::admins".to_string()],
            },
        ];
        let store = EntityStore::from_config(&entities);
        assert!(store.is_member_of("Agent::agent-1", "Group::admins"));
        assert!(!store.is_member_of("Agent::agent-1", "Group::operators"));
    }

    #[test]
    fn test_entity_store_transitive_membership_bounded() {
        // Chain: a → b → c → d (transitive)
        let entities = vec![
            AbacEntity {
                entity_type: "G".to_string(),
                id: "d".to_string(),
                attributes: HashMap::new(),
                parents: vec![],
            },
            AbacEntity {
                entity_type: "G".to_string(),
                id: "c".to_string(),
                attributes: HashMap::new(),
                parents: vec!["G::d".to_string()],
            },
            AbacEntity {
                entity_type: "G".to_string(),
                id: "b".to_string(),
                attributes: HashMap::new(),
                parents: vec!["G::c".to_string()],
            },
            AbacEntity {
                entity_type: "A".to_string(),
                id: "a".to_string(),
                attributes: HashMap::new(),
                parents: vec!["G::b".to_string()],
            },
        ];
        let store = EntityStore::from_config(&entities);
        assert!(store.is_member_of("A::a", "G::d"));
        assert!(store.is_member_of("A::a", "G::b"));
    }

    #[test]
    fn test_find_conflicts_none() {
        let engine = make_engine(vec![
            make_permit_policy("p1", "filesystem:*"),
            make_forbid_policy("f1", "bash:*"),
        ]);
        assert!(engine.find_conflicts().is_empty());
    }

    #[test]
    fn test_find_conflicts_detected() {
        let engine = make_engine(vec![
            make_permit_policy("p1", "*:*"),
            make_forbid_policy("f1", "bash:*"),
        ]);
        let conflicts = engine.find_conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].permit_id, "p1");
        assert_eq!(conflicts[0].forbid_id, "f1");
    }

    #[test]
    fn test_evaluate_with_risk_score_threshold() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "low risk".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![AbacCondition {
                field: "risk.score".to_string(),
                op: AbacOp::Lte,
                value: serde_json::json!(0.5),
            }],
        };
        let engine = make_engine(vec![policy]);

        let risk = RiskScore {
            score: 0.5,
            factors: vec![],
            updated_at: "2026-02-14T00:00:00Z".to_string(),
        };
        let eval_ctx = EvaluationContext::default();
        let ctx = AbacEvalContext {
            eval_ctx: &eval_ctx,
            principal_type: "Agent",
            principal_id: "test",
            risk_score: Some(&risk),
        };
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));
    }

    #[test]
    fn test_evaluate_condition_ne_not_in() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "not in blocklist".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![
                AbacCondition {
                    field: "context.tenant_id".to_string(),
                    op: AbacOp::Ne,
                    value: serde_json::json!("blocked"),
                },
                AbacCondition {
                    field: "context.agent_id".to_string(),
                    op: AbacOp::NotIn,
                    value: serde_json::json!(["evil-agent", "bad-agent"]),
                },
            ],
        };
        let engine = make_engine(vec![policy]);

        let eval_ctx = EvaluationContext {
            tenant_id: Some("acme".to_string()),
            agent_id: Some("good-agent".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(matches!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::Allow { .. }
        ));

        let eval_ctx = EvaluationContext {
            tenant_id: Some("blocked".to_string()),
            agent_id: Some("good-agent".to_string()),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch
        );
    }

    // ════════════════════════════════════════════════════════
    // FIND-R44-001: Diamond-shaped membership graph
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_diamond_membership_no_exponential_blowup() {
        // Diamond graph: entity → A, entity → B, A → top, B → top
        // Without visited-set, checking membership in "top" would visit
        // the "top" node twice. With wider diamonds this becomes exponential.
        let entities = vec![
            AbacEntity {
                entity_type: "G".to_string(),
                id: "top".to_string(),
                attributes: HashMap::new(),
                parents: vec![],
            },
            AbacEntity {
                entity_type: "G".to_string(),
                id: "a".to_string(),
                attributes: HashMap::new(),
                parents: vec!["G::top".to_string()],
            },
            AbacEntity {
                entity_type: "G".to_string(),
                id: "b".to_string(),
                attributes: HashMap::new(),
                parents: vec!["G::top".to_string()],
            },
            AbacEntity {
                entity_type: "E".to_string(),
                id: "entity".to_string(),
                attributes: HashMap::new(),
                parents: vec!["G::a".to_string(), "G::b".to_string()],
            },
        ];
        let store = EntityStore::from_config(&entities);
        assert!(store.is_member_of("E::entity", "G::top"));
        assert!(store.is_member_of("E::entity", "G::a"));
        assert!(store.is_member_of("E::entity", "G::b"));
        assert!(!store.is_member_of("E::entity", "G::nonexistent"));
    }

    #[test]
    fn test_wide_diamond_membership_completes_quickly() {
        // Create a wide diamond: entity → [g0..g15] → top
        // Without visited-set this could be slow; with it, each node visited once.
        let mut entities = vec![AbacEntity {
            entity_type: "G".to_string(),
            id: "top".to_string(),
            attributes: HashMap::new(),
            parents: vec![],
        }];
        let mut mid_parents = Vec::new();
        for i in 0..16 {
            let id = format!("mid{}", i);
            entities.push(AbacEntity {
                entity_type: "G".to_string(),
                id: id.clone(),
                attributes: HashMap::new(),
                parents: vec!["G::top".to_string()],
            });
            mid_parents.push(format!("G::{}", id));
        }
        entities.push(AbacEntity {
            entity_type: "E".to_string(),
            id: "leaf".to_string(),
            attributes: HashMap::new(),
            parents: mid_parents,
        });
        let store = EntityStore::from_config(&entities);
        assert!(store.is_member_of("E::leaf", "G::top"));
    }

    // ════════════════════════════════════════════════════════
    // FIND-R46-001: Path normalization in ABAC resource matching
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_r46_001_path_traversal_normalized_in_resource_match() {
        // A path like "/home/../etc/passwd" should be normalized to "/etc/passwd"
        // and should NOT match a policy for "/home/**".
        // FIND-P1-5: Updated from `/home/*` to `/home/**` because with
        // proper globset matching, `*` no longer crosses path separators.
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "home dir only".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: ResourceConstraint {
                path_patterns: vec!["/home/**".to_string()],
                domain_patterns: vec![],
                tags: vec![],
            },
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        // Traversal path should normalize to /etc/passwd, not match /home/**
        let action = make_action_with_paths("fs", "read", vec!["/home/../etc/passwd"]);
        assert_eq!(
            engine.evaluate(&action, &ctx),
            AbacDecision::NoMatch,
            "Path traversal should be normalized before ABAC resource matching"
        );

        // Normal home path should still match
        let action = make_action_with_paths("fs", "read", vec!["/home/user/file.txt"]);
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));
    }

    // ════════════════════════════════════════════════════════
    // FIND-R46-002: Domain normalization in ABAC resource matching
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_r46_002_domain_case_normalized_in_resource_match() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "example.com only".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: ResourceConstraint {
                path_patterns: vec![],
                domain_patterns: vec!["*example.com".to_string()],
                tags: vec![],
            },
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        // Mixed case should be normalized to lowercase
        let action = make_action_with_domains("net", "fetch", vec!["API.EXAMPLE.COM"]);
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));

        // Trailing dot should be trimmed
        let action = make_action_with_domains("net", "fetch", vec!["api.example.com."]);
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));
    }

    // ════════════════════════════════════════════════════════
    // FIND-R46-008: Empty conditions compile-time validation
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_r46_008_empty_field_condition_rejected_at_compile() {
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "bad condition".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![AbacCondition {
                field: "".to_string(),
                op: AbacOp::Eq,
                value: serde_json::json!("test"),
            }],
        };
        let result = AbacEngine::new(&[policy], &[]);
        assert!(
            result.is_err(),
            "Empty condition field should be rejected at compile time"
        );
    }

    #[test]
    fn test_cycle_in_membership_terminates() {
        // Cycle: a → b → c → a (should terminate via depth or visited-set)
        let entities = vec![
            AbacEntity {
                entity_type: "G".to_string(),
                id: "a".to_string(),
                attributes: HashMap::new(),
                parents: vec!["G::b".to_string()],
            },
            AbacEntity {
                entity_type: "G".to_string(),
                id: "b".to_string(),
                attributes: HashMap::new(),
                parents: vec!["G::c".to_string()],
            },
            AbacEntity {
                entity_type: "G".to_string(),
                id: "c".to_string(),
                attributes: HashMap::new(),
                parents: vec!["G::a".to_string()],
            },
        ];
        let store = EntityStore::from_config(&entities);
        // Should terminate without stack overflow
        assert!(!store.is_member_of("G::a", "G::nonexistent"));
        // Self-cycle should still find transitive membership
        assert!(store.is_member_of("G::a", "G::b"));
    }

    // ════════════════════════════════════════════════════════
    // FIND-P1-5: ABAC resource path matching uses globset
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_p1_5_glob_double_star_path_matching() {
        // `**/*.txt` should match nested paths — PatternMatcher cannot do this
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "txt files under /data".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: ResourceConstraint {
                path_patterns: vec!["/data/**/*.txt".to_string()],
                domain_patterns: vec![],
                tags: vec![],
            },
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        // Nested txt file should match
        let action = make_action_with_paths("fs", "read", vec!["/data/subdir/file.txt"]);
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));

        // Deeply nested txt file should match
        let action = make_action_with_paths("fs", "read", vec!["/data/a/b/c/file.txt"]);
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));

        // Non-txt file should not match
        let action = make_action_with_paths("fs", "read", vec!["/data/subdir/file.json"]);
        assert_eq!(engine.evaluate(&action, &ctx), AbacDecision::NoMatch);

        // Path outside /data should not match
        let action = make_action_with_paths("fs", "read", vec!["/etc/file.txt"]);
        assert_eq!(engine.evaluate(&action, &ctx), AbacDecision::NoMatch);
    }

    #[test]
    fn test_p1_5_glob_single_star_path_matching() {
        // `/home/*/config` should match single-level wildcard
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "user config".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: ResourceConstraint {
                path_patterns: vec!["/home/*/config".to_string()],
                domain_patterns: vec![],
                tags: vec![],
            },
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        let action = make_action_with_paths("fs", "read", vec!["/home/alice/config"]);
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));

        // Nested path should NOT match single-star (unlike **)
        let action = make_action_with_paths("fs", "read", vec!["/home/alice/sub/config"]);
        assert_eq!(engine.evaluate(&action, &ctx), AbacDecision::NoMatch);
    }

    #[test]
    fn test_p1_5_glob_question_mark_path_matching() {
        // `/tmp/file?.log` should match single character wildcard
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "single char wildcard".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: ResourceConstraint {
                path_patterns: vec!["/tmp/file?.log".to_string()],
                domain_patterns: vec![],
                tags: vec![],
            },
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        let action = make_action_with_paths("fs", "read", vec!["/tmp/file1.log"]);
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));

        // Two characters should not match single ?
        let action = make_action_with_paths("fs", "read", vec!["/tmp/file12.log"]);
        assert_eq!(engine.evaluate(&action, &ctx), AbacDecision::NoMatch);
    }

    #[test]
    fn test_p1_5_exact_path_still_works_without_glob() {
        // Exact paths (no wildcards) should still work via PatternMatcher
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "exact path".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: ResourceConstraint {
                path_patterns: vec!["/etc/config.yaml".to_string()],
                domain_patterns: vec![],
                tags: vec![],
            },
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        let action = make_action_with_paths("fs", "read", vec!["/etc/config.yaml"]);
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));

        let action = make_action_with_paths("fs", "read", vec!["/etc/other.yaml"]);
        assert_eq!(engine.evaluate(&action, &ctx), AbacDecision::NoMatch);
    }

    #[test]
    fn test_p1_5_glob_bracket_pattern() {
        // `[` triggers glob compilation — test bracket character class
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "bracket pattern".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: ResourceConstraint {
                path_patterns: vec!["/data/file[0-9].csv".to_string()],
                domain_patterns: vec![],
                tags: vec![],
            },
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();
        let ctx = make_ctx(&eval_ctx, "Agent", "test");

        let action = make_action_with_paths("fs", "read", vec!["/data/file5.csv"]);
        assert!(matches!(
            engine.evaluate(&action, &ctx),
            AbacDecision::Allow { .. }
        ));

        let action = make_action_with_paths("fs", "read", vec!["/data/fileA.csv"]);
        assert_eq!(engine.evaluate(&action, &ctx), AbacDecision::NoMatch);
    }

    // ════════════════════════════════════════════════════════
    // FIND-R215-004: ABAC principal ID homoglyph normalization
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_r215_004_principal_id_homoglyph_normalization() {
        // Principal ID pattern "admin*" should match a Cyrillic-homoglyph variant
        // because normalize_homoglyphs maps Cyrillic 'а' (U+0430) to Latin 'a'.
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "admin agents".to_string(),
            effect: AbacEffect::Forbid,
            priority: 0,
            principal: PrincipalConstraint {
                principal_type: None,
                id_patterns: vec!["admin*".to_string()],
                claims: HashMap::new(),
            },
            action: ActionConstraint {
                patterns: vec!["*:*".to_string()],
            },
            resource: Default::default(),
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();

        // Cyrillic 'а' (U+0430) visually identical to Latin 'a'
        let ctx = make_ctx(&eval_ctx, "Agent", "\u{0430}dmin-user");
        match engine.evaluate(&make_action("any", "any"), &ctx) {
            AbacDecision::Deny { policy_id, .. } => assert_eq!(policy_id, "p1"),
            other => panic!("Expected Deny from homoglyph principal ID, got {:?}", other),
        }
    }

    // ════════════════════════════════════════════════════════
    // FIND-R215-005: ABAC principal claims homoglyph normalization
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_r215_005_principal_claims_homoglyph_normalization() {
        // Claim pattern "security*" should match Cyrillic-homoglyph variant
        let mut claims = HashMap::new();
        claims.insert("team".to_string(), "security*".to_string());

        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "security team".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: PrincipalConstraint {
                principal_type: None,
                id_patterns: vec![],
                claims,
            },
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);

        // Cyrillic 'ѕ' (U+0455) looks like Latin 's', 'е' (U+0435) looks like 'e'
        let mut identity_claims = HashMap::new();
        identity_claims.insert(
            "team".to_string(),
            serde_json::json!("\u{0455}\u{0435}curity-ops"),
        );
        let eval_ctx = EvaluationContext {
            agent_identity: Some(AgentIdentity {
                claims: identity_claims,
                ..Default::default()
            }),
            ..Default::default()
        };
        let ctx = make_ctx(&eval_ctx, "Agent", "test");
        assert!(
            matches!(
                engine.evaluate(&make_action("any", "any"), &ctx),
                AbacDecision::Allow { .. }
            ),
            "Homoglyph claim value should match after normalization"
        );
    }

    // ════════════════════════════════════════════════════════
    // FIND-R215-006: compare_numbers NaN guard
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_r215_006_compare_numbers_nan_guard() {
        // NaN in risk.score should cause Permit condition to not match (fail-closed)
        let policy = AbacPolicy {
            id: "permit-low-risk".to_string(),
            description: "low risk only".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![AbacCondition {
                field: "risk.score".to_string(),
                op: AbacOp::Lt,
                value: serde_json::json!(0.5),
            }],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();

        // NaN risk score — resolve_field treats non-finite as 1.0 (max risk),
        // and compare_numbers guards against non-finite operands. Either way,
        // the permit condition should NOT match.
        let risk = RiskScore {
            score: f64::NAN,
            factors: vec![],
            updated_at: "2026-02-14T00:00:00Z".to_string(),
        };
        let ctx = AbacEvalContext {
            eval_ctx: &eval_ctx,
            principal_type: "Agent",
            principal_id: "test",
            risk_score: Some(&risk),
        };
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch,
            "NaN risk score should not match Lt condition"
        );
    }

    #[test]
    fn test_r215_006_compare_numbers_infinity_guard() {
        // Infinity should also fail-closed
        let policy = AbacPolicy {
            id: "permit-low-risk".to_string(),
            description: "low risk only".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![AbacCondition {
                field: "risk.score".to_string(),
                op: AbacOp::Lte,
                value: serde_json::json!(0.5),
            }],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();

        let risk = RiskScore {
            score: f64::INFINITY,
            factors: vec![],
            updated_at: "2026-02-14T00:00:00Z".to_string(),
        };
        let ctx = AbacEvalContext {
            eval_ctx: &eval_ctx,
            principal_type: "Agent",
            principal_id: "test",
            risk_score: Some(&risk),
        };
        assert_eq!(
            engine.evaluate(&make_action("any", "any"), &ctx),
            AbacDecision::NoMatch,
            "Infinity risk score should not match Lte condition"
        );
    }

    // ════════════════════════════════════════════════════════
    // FIND-R215-007: ABAC principal_type homoglyph normalization
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_r215_007_principal_type_homoglyph_normalization() {
        // Required type "Agent" should match Cyrillic-homoglyph "Аgent"
        // (Cyrillic 'А' U+0410 looks like Latin 'A')
        let policy = AbacPolicy {
            id: "p1".to_string(),
            description: "Agents only".to_string(),
            effect: AbacEffect::Permit,
            priority: 0,
            principal: PrincipalConstraint {
                principal_type: Some("Agent".to_string()),
                id_patterns: vec![],
                claims: HashMap::new(),
            },
            action: ActionConstraint {
                patterns: vec!["*:*".to_string()],
            },
            resource: Default::default(),
            conditions: vec![],
        };
        let engine = make_engine(vec![policy]);
        let eval_ctx = EvaluationContext::default();

        // Cyrillic 'А' (U+0410) visually identical to Latin 'A'
        let ctx = make_ctx(&eval_ctx, "\u{0410}gent", "test-agent");
        assert!(
            matches!(
                engine.evaluate(&make_action("any", "any"), &ctx),
                AbacDecision::Allow { .. }
            ),
            "Homoglyph principal_type should match after normalization"
        );
    }
}
