// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! ABAC (Attribute-Based Access Control) types — Cedar-style policies,
//! entity store, risk scores, federation, and least-agency tracking.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════════════
// ABAC POLICY TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// ABAC policy effect — Cedar-style permit/forbid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AbacEffect {
    Permit,
    Forbid,
}

/// Principal constraint — who is performing the action.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrincipalConstraint {
    /// Principal type (e.g., "Agent", "Service", "User"). None = any.
    #[serde(default)]
    pub principal_type: Option<String>,
    /// Glob patterns for principal ID (e.g., "code-agent", "team-*").
    #[serde(default)]
    pub id_patterns: Vec<String>,
    /// Required JWT claims (key → glob value pattern).
    #[serde(default)]
    pub claims: HashMap<String, String>,
}

/// Action constraint — what operation is being performed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActionConstraint {
    /// Tool:function patterns the action must match (e.g., ["filesystem:read_*"]).
    #[serde(default)]
    pub patterns: Vec<String>,
}

/// Resource constraint — what is being acted upon.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceConstraint {
    /// Path glob patterns the resource must match.
    #[serde(default)]
    pub path_patterns: Vec<String>,
    /// Domain patterns the resource must match.
    #[serde(default)]
    pub domain_patterns: Vec<String>,
    /// Required resource tags (all must be present).
    #[serde(default)]
    pub tags: Vec<String>,
}

/// ABAC condition — additional constraints on the evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AbacCondition {
    /// Field path to evaluate (e.g., "context.verified", "principal.team").
    pub field: String,
    /// Comparison operator.
    pub op: AbacOp,
    /// Value to compare against.
    pub value: serde_json::Value,
}

impl AbacCondition {
    /// Maximum serialized size of `value` in bytes.
    pub const MAX_VALUE_SIZE: usize = 8192;
    /// Maximum length for the `field` path string.
    const MAX_FIELD_LEN: usize = 256;

    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (FIND-R215-010): Validate field path is non-empty, bounded,
        // and free of control/format characters to prevent log injection and
        // oversized condition fields in deserialized policies.
        if self.field.is_empty() {
            return Err("AbacCondition field must not be empty".to_string());
        }
        if self.field.len() > Self::MAX_FIELD_LEN {
            return Err(format!(
                "AbacCondition field length {} exceeds max {}",
                self.field.len(),
                Self::MAX_FIELD_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.field) {
            return Err(format!(
                "AbacCondition field '{}' contains control or format characters",
                self.field.escape_debug()
            ));
        }
        let size = serde_json::to_string(&self.value)
            .map_err(|e| format!("AbacCondition value serialization failed: {e}"))?
            .len();
        if size > Self::MAX_VALUE_SIZE {
            return Err(format!(
                "AbacCondition field '{}' value serialized size {} exceeds max {}",
                self.field,
                size,
                Self::MAX_VALUE_SIZE
            ));
        }
        Ok(())
    }
}

/// ABAC comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbacOp {
    Eq,
    Ne,
    In,
    NotIn,
    Contains,
    StartsWith,
    Gt,
    Lt,
    Gte,
    Lte,
}

/// A Cedar-style ABAC policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AbacPolicy {
    pub id: String,
    pub description: String,
    pub effect: AbacEffect,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub principal: PrincipalConstraint,
    #[serde(default)]
    pub action: ActionConstraint,
    #[serde(default)]
    pub resource: ResourceConstraint,
    #[serde(default)]
    pub conditions: Vec<AbacCondition>,
}

impl AbacPolicy {
    /// Maximum number of conditions per policy.
    pub const MAX_CONDITIONS: usize = 256;

    /// SECURITY (FIND-R49-005): Validate AbacPolicy bounds.
    /// SECURITY (FIND-R115-006): Validate control/format chars on id and description.
    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (FIND-R115-006): Reject control/format chars in identity fields.
        if crate::core::has_dangerous_chars(&self.id) {
            return Err(format!(
                "AbacPolicy '{}' id contains control or format characters",
                self.id
            ));
        }
        if crate::core::has_dangerous_chars(&self.description) {
            return Err(format!(
                "AbacPolicy '{}' description contains control or format characters",
                self.id
            ));
        }
        if self.conditions.len() > Self::MAX_CONDITIONS {
            return Err(format!(
                "AbacPolicy conditions count {} exceeds max {}",
                self.conditions.len(),
                Self::MAX_CONDITIONS
            ));
        }
        for (i, cond) in self.conditions.iter().enumerate() {
            cond.validate()
                .map_err(|e| format!("conditions[{}]: {}", i, e))?;
        }
        self.principal.validate()?;
        self.action.validate()?;
        self.resource.validate()?;
        Ok(())
    }
}

impl PrincipalConstraint {
    /// Maximum number of ID patterns per principal constraint.
    pub const MAX_ID_PATTERNS: usize = 64;
    /// Maximum number of required claims per principal constraint.
    pub const MAX_CLAIMS: usize = 64;
    /// Maximum length for a single ID pattern entry.
    const MAX_PATTERN_LEN: usize = 1024;
    /// Maximum length for a claim key.
    const MAX_CLAIM_KEY_LEN: usize = 256;
    /// Maximum length for a claim value.
    const MAX_CLAIM_VALUE_LEN: usize = 1024;

    /// SECURITY (FIND-R49-005): Validate PrincipalConstraint bounds.
    /// SECURITY (FIND-R216-002): Per-entry validation on id_patterns and claims.
    pub fn validate(&self) -> Result<(), String> {
        // Validate principal_type if present.
        if let Some(ref pt) = self.principal_type {
            if crate::core::has_dangerous_chars(pt) {
                return Err(
                    "PrincipalConstraint principal_type contains control or format characters"
                        .to_string(),
                );
            }
        }
        if self.id_patterns.len() > Self::MAX_ID_PATTERNS {
            return Err(format!(
                "PrincipalConstraint id_patterns count {} exceeds max {}",
                self.id_patterns.len(),
                Self::MAX_ID_PATTERNS
            ));
        }
        // SECURITY (FIND-R216-002): Per-entry length and dangerous char checks.
        for (i, pat) in self.id_patterns.iter().enumerate() {
            if pat.len() > Self::MAX_PATTERN_LEN {
                return Err(format!(
                    "PrincipalConstraint id_patterns[{}] length {} exceeds max {}",
                    i,
                    pat.len(),
                    Self::MAX_PATTERN_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(pat) {
                return Err(format!(
                    "PrincipalConstraint id_patterns[{}] contains control or format characters",
                    i,
                ));
            }
        }
        if self.claims.len() > Self::MAX_CLAIMS {
            return Err(format!(
                "PrincipalConstraint claims count {} exceeds max {}",
                self.claims.len(),
                Self::MAX_CLAIMS
            ));
        }
        // SECURITY (FIND-R216-002): Per-key/value length and dangerous char checks.
        for (key, value) in &self.claims {
            if key.len() > Self::MAX_CLAIM_KEY_LEN {
                return Err(format!(
                    "PrincipalConstraint claims key length {} exceeds max {}",
                    key.len(),
                    Self::MAX_CLAIM_KEY_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(key) {
                return Err(
                    "PrincipalConstraint claims key contains control or format characters"
                        .to_string(),
                );
            }
            if value.len() > Self::MAX_CLAIM_VALUE_LEN {
                return Err(format!(
                    "PrincipalConstraint claims value length {} exceeds max {}",
                    value.len(),
                    Self::MAX_CLAIM_VALUE_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(value) {
                return Err(
                    "PrincipalConstraint claims value contains control or format characters"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

impl ActionConstraint {
    /// Maximum number of patterns per action constraint.
    pub const MAX_PATTERNS: usize = 256;
    /// Maximum length for a single pattern entry.
    const MAX_PATTERN_LEN: usize = 1024;

    /// SECURITY (FIND-R49-005): Validate ActionConstraint bounds.
    /// SECURITY (FIND-R216-003): Per-entry validation on patterns.
    pub fn validate(&self) -> Result<(), String> {
        if self.patterns.len() > Self::MAX_PATTERNS {
            return Err(format!(
                "ActionConstraint patterns count {} exceeds max {}",
                self.patterns.len(),
                Self::MAX_PATTERNS
            ));
        }
        // SECURITY (FIND-R216-003): Per-entry length and dangerous char checks.
        for (i, pat) in self.patterns.iter().enumerate() {
            if pat.len() > Self::MAX_PATTERN_LEN {
                return Err(format!(
                    "ActionConstraint patterns[{}] length {} exceeds max {}",
                    i,
                    pat.len(),
                    Self::MAX_PATTERN_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(pat) {
                return Err(format!(
                    "ActionConstraint patterns[{}] contains control or format characters",
                    i,
                ));
            }
        }
        Ok(())
    }
}

impl ResourceConstraint {
    /// Maximum number of path patterns per resource constraint.
    pub const MAX_PATH_PATTERNS: usize = 256;
    /// Maximum number of domain patterns per resource constraint.
    pub const MAX_DOMAIN_PATTERNS: usize = 256;
    /// Maximum number of tags per resource constraint.
    pub const MAX_TAGS: usize = 64;
    /// Maximum length for a single path pattern entry.
    const MAX_PATH_PATTERN_LEN: usize = 2048;
    /// Maximum length for a single domain pattern entry.
    const MAX_DOMAIN_PATTERN_LEN: usize = 1024;
    /// Maximum length for a single tag entry.
    const MAX_TAG_LEN: usize = 256;

    /// SECURITY (FIND-R49-005): Validate ResourceConstraint bounds.
    /// SECURITY (FIND-R216-004): Per-entry validation on path_patterns, domain_patterns, tags.
    pub fn validate(&self) -> Result<(), String> {
        if self.path_patterns.len() > Self::MAX_PATH_PATTERNS {
            return Err(format!(
                "ResourceConstraint path_patterns count {} exceeds max {}",
                self.path_patterns.len(),
                Self::MAX_PATH_PATTERNS
            ));
        }
        // SECURITY (FIND-R216-004): Per-entry length and dangerous char checks.
        for (i, pat) in self.path_patterns.iter().enumerate() {
            if pat.len() > Self::MAX_PATH_PATTERN_LEN {
                return Err(format!(
                    "ResourceConstraint path_patterns[{}] length {} exceeds max {}",
                    i,
                    pat.len(),
                    Self::MAX_PATH_PATTERN_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(pat) {
                return Err(format!(
                    "ResourceConstraint path_patterns[{}] contains control or format characters",
                    i,
                ));
            }
        }
        if self.domain_patterns.len() > Self::MAX_DOMAIN_PATTERNS {
            return Err(format!(
                "ResourceConstraint domain_patterns count {} exceeds max {}",
                self.domain_patterns.len(),
                Self::MAX_DOMAIN_PATTERNS
            ));
        }
        for (i, pat) in self.domain_patterns.iter().enumerate() {
            if pat.len() > Self::MAX_DOMAIN_PATTERN_LEN {
                return Err(format!(
                    "ResourceConstraint domain_patterns[{}] length {} exceeds max {}",
                    i,
                    pat.len(),
                    Self::MAX_DOMAIN_PATTERN_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(pat) {
                return Err(format!(
                    "ResourceConstraint domain_patterns[{}] contains control or format characters",
                    i,
                ));
            }
        }
        if self.tags.len() > Self::MAX_TAGS {
            return Err(format!(
                "ResourceConstraint tags count {} exceeds max {}",
                self.tags.len(),
                Self::MAX_TAGS
            ));
        }
        for (i, tag) in self.tags.iter().enumerate() {
            if tag.len() > Self::MAX_TAG_LEN {
                return Err(format!(
                    "ResourceConstraint tags[{}] length {} exceeds max {}",
                    i,
                    tag.len(),
                    Self::MAX_TAG_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(tag) {
                return Err(format!(
                    "ResourceConstraint tags[{}] contains control or format characters",
                    i,
                ));
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENTITY STORE TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Entity in the ABAC entity store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AbacEntity {
    /// Entity type (e.g., "Agent", "Service", "Resource", "Group").
    pub entity_type: String,
    /// Unique entity identifier.
    pub id: String,
    /// Arbitrary attributes for condition evaluation.
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,
    /// Parent entity IDs (for group membership: Agent in Group).
    #[serde(default)]
    pub parents: Vec<String>,
}

impl AbacEntity {
    /// Maximum parents per entity.
    pub const MAX_PARENTS: usize = 256;
    /// Maximum attributes per entity.
    pub const MAX_ATTRIBUTES: usize = 256;
    /// Maximum length for a single parent ID entry.
    const MAX_PARENT_ID_LEN: usize = 256;
    /// R228-TYP-2: Maximum length for entity_type field.
    const MAX_ENTITY_TYPE_LEN: usize = 256;
    /// R228-TYP-2: Maximum length for entity id field.
    const MAX_ENTITY_ID_LEN: usize = 512;
    /// R228-TYP-2: Maximum length for a single attribute key.
    const MAX_ATTR_KEY_LEN: usize = 256;
    /// R228-TYP-2: Maximum serialized size for a single attribute value.
    const MAX_ATTR_VALUE_SIZE: usize = 65_536;

    /// Validate bounds on deserialized data.
    ///
    /// SECURITY (FIND-R48-004): Unbounded parents and attributes from deserialization.
    /// SECURITY (FIND-R115-006): Validate control/format chars on entity_type and id.
    /// SECURITY (FIND-R216-005): Per-entry validation on parents.
    /// SECURITY (R228-TYP-2): Length bounds on entity_type, id, and attribute keys/values.
    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (R228-TYP-2): Length bounds on entity_type and id.
        if self.entity_type.len() > Self::MAX_ENTITY_TYPE_LEN {
            return Err(format!(
                "AbacEntity entity_type length {} exceeds max {}",
                self.entity_type.len(),
                Self::MAX_ENTITY_TYPE_LEN
            ));
        }
        if self.id.len() > Self::MAX_ENTITY_ID_LEN {
            return Err(format!(
                "AbacEntity id length {} exceeds max {}",
                self.id.len(),
                Self::MAX_ENTITY_ID_LEN
            ));
        }
        // SECURITY (FIND-R115-006): Reject control/format chars in identity fields.
        if crate::core::has_dangerous_chars(&self.entity_type) {
            return Err(format!(
                "AbacEntity '{}::{}' entity_type contains control or format characters",
                self.entity_type, self.id
            ));
        }
        if crate::core::has_dangerous_chars(&self.id) {
            return Err(format!(
                "AbacEntity '{}::{}' id contains control or format characters",
                self.entity_type, self.id
            ));
        }
        if self.parents.len() > Self::MAX_PARENTS {
            return Err(format!(
                "AbacEntity '{}::{}' has {} parents (max {})",
                self.entity_type,
                self.id,
                self.parents.len(),
                Self::MAX_PARENTS
            ));
        }
        // SECURITY (FIND-R216-005): Per-entry length and dangerous char checks.
        for (i, parent) in self.parents.iter().enumerate() {
            if parent.len() > Self::MAX_PARENT_ID_LEN {
                return Err(format!(
                    "AbacEntity '{}::{}' parents[{}] length {} exceeds max {}",
                    self.entity_type,
                    self.id,
                    i,
                    parent.len(),
                    Self::MAX_PARENT_ID_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(parent) {
                return Err(format!(
                    "AbacEntity '{}::{}' parents[{}] contains control or format characters",
                    self.entity_type, self.id, i,
                ));
            }
        }
        if self.attributes.len() > Self::MAX_ATTRIBUTES {
            return Err(format!(
                "AbacEntity '{}::{}' has {} attributes (max {})",
                self.entity_type,
                self.id,
                self.attributes.len(),
                Self::MAX_ATTRIBUTES
            ));
        }
        // SECURITY (R228-TYP-2): Per-key length, dangerous char, and per-value size checks.
        for (key, value) in &self.attributes {
            if key.len() > Self::MAX_ATTR_KEY_LEN {
                return Err(format!(
                    "AbacEntity '{}::{}' attribute key length {} exceeds max {}",
                    self.entity_type,
                    self.id,
                    key.len(),
                    Self::MAX_ATTR_KEY_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(key) {
                return Err(format!(
                    "AbacEntity '{}::{}' attribute key contains control or format characters",
                    self.entity_type, self.id,
                ));
            }
            // Bound serialized value size to prevent memory amplification.
            // SECURITY (R229-TYP-2): Fail-closed — serialization failure rejects the entity
            // instead of defaulting to 0 which silently bypasses the size check.
            let val_size = serde_json::to_string(value).map(|s| s.len()).map_err(|e| {
                format!(
                    "AbacEntity '{}::{}' attribute '{}' value failed to serialize: {}",
                    self.entity_type, self.id, key, e,
                )
            })?;
            if val_size > Self::MAX_ATTR_VALUE_SIZE {
                return Err(format!(
                    "AbacEntity '{}::{}' attribute '{}' value size {} exceeds max {}",
                    self.entity_type,
                    self.id,
                    key,
                    val_size,
                    Self::MAX_ATTR_VALUE_SIZE,
                ));
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTINUOUS AUTHORIZATION (21.4)
// ═══════════════════════════════════════════════════════════════════════════════

/// Risk score for continuous authorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RiskScore {
    /// Risk score from 0.0 (safe) to 1.0 (critical).
    pub score: f64,
    /// Contributing risk factors.
    #[serde(default)]
    pub factors: Vec<RiskFactor>,
    /// ISO 8601 timestamp of last update.
    pub updated_at: String,
}

/// A single contributing factor to the overall risk score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RiskFactor {
    /// Factor name (e.g., "anomaly_score", "threat_intel", "failed_auth").
    pub name: String,
    /// Weight of this factor in the composite score.
    pub weight: f64,
    /// Current value of this factor.
    pub value: f64,
}

impl RiskScore {
    /// Maximum length for `updated_at` ISO 8601 timestamp (bytes).
    const MAX_TIMESTAMP_LEN: usize = 64;

    /// Validate that all f64 fields are finite (not NaN or Infinity).
    pub fn validate_finite(&self) -> Result<(), String> {
        if !self.score.is_finite() {
            return Err(format!("RiskScore::score is not finite: {}", self.score));
        }
        // SECURITY (FIND-R51-001): Validate score is in documented [0.0, 1.0] range.
        if self.score < 0.0 || self.score > 1.0 {
            return Err(format!(
                "RiskScore::score must be in [0.0, 1.0], got {}",
                self.score
            ));
        }
        // SECURITY (FIND-R52-001): Bound factors collection size.
        const MAX_FACTORS: usize = 256;
        if self.factors.len() > MAX_FACTORS {
            return Err(format!(
                "RiskScore factors count {} exceeds max {}",
                self.factors.len(),
                MAX_FACTORS,
            ));
        }
        for factor in &self.factors {
            factor.validate_finite()?;
        }
        // SECURITY (FIND-R157-002): Validate updated_at timestamp length and
        // reject control/format characters to prevent log injection.
        if self.updated_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "RiskScore updated_at length {} exceeds max {}",
                self.updated_at.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.updated_at) {
            return Err("RiskScore updated_at contains control or format characters".to_string());
        }
        Ok(())
    }
}

impl RiskFactor {
    /// Maximum length for `name` field (bytes).
    const MAX_NAME_LEN: usize = 256;

    /// Validate that all f64 fields are finite and in [0.0, 1.0].
    pub fn validate_finite(&self) -> Result<(), String> {
        // SECURITY (FIND-R157-003): Validate name length and reject
        // control/format characters to prevent log injection and OOM.
        if self.name.len() > Self::MAX_NAME_LEN {
            return Err(format!(
                "RiskFactor name length {} exceeds max {}",
                self.name.len(),
                Self::MAX_NAME_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.name) {
            return Err(format!(
                "RiskFactor '{}' name contains control or format characters",
                self.name,
            ));
        }
        // SECURITY (FIND-R52-003): Range-validate weight and value to prevent
        // adversarial composite score manipulation via negative factors.
        if !self.weight.is_finite() || self.weight < 0.0 || self.weight > 1.0 {
            return Err(format!(
                "RiskFactor '{}' weight must be in [0.0, 1.0], got {}",
                self.name, self.weight
            ));
        }
        if !self.value.is_finite() || self.value < 0.0 || self.value > 1.0 {
            return Err(format!(
                "RiskFactor '{}' value must be in [0.0, 1.0], got {}",
                self.name, self.value
            ));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// IDENTITY FEDERATION (21.3)
// ═══════════════════════════════════════════════════════════════════════════════

/// Federation trust anchor for cross-org identity mapping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FederationTrustAnchor {
    /// Organization identifier.
    pub org_id: String,
    /// Human-readable name for the trust anchor.
    pub display_name: String,
    /// Optional JWKS URI for verifying federated tokens.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Glob pattern for trusted JWT issuers.
    pub issuer_pattern: String,
    /// Identity claim-to-principal mappings.
    #[serde(default)]
    pub identity_mappings: Vec<IdentityMapping>,
    /// Trust level for this federated organization.
    /// Injected as `federation.trust_level` claim in mapped identity.
    /// ABAC policies can condition on this value.
    /// Valid values: "full", "limited", "read_only".
    #[serde(default = "default_trust_level")]
    pub trust_level: String,
}

fn default_trust_level() -> String {
    "limited".to_string()
}

/// Allowed trust level values for federation trust anchors.
const VALID_TRUST_LEVELS: &[&str] = &["full", "limited", "read_only"];

impl FederationTrustAnchor {
    /// Maximum number of identity mappings per trust anchor.
    pub const MAX_IDENTITY_MAPPINGS: usize = 64;

    /// Maximum length for issuer_pattern.
    pub const MAX_ISSUER_PATTERN_LEN: usize = 2048;

    /// Validate the trust anchor configuration.
    ///
    /// Checks: org_id non-empty, issuer_pattern non-empty and bounded,
    /// issuer_pattern not bare wildcard, jwks_uri scheme and SSRF safety,
    /// trust_level enum, identity_mappings bounds and individual validation.
    pub fn validate(&self) -> Result<(), String> {
        if self.org_id.is_empty() {
            return Err("FederationTrustAnchor org_id must not be empty".to_string());
        }
        // SECURITY (FIND-R104-003): Also reject Unicode format characters
        // (zero-width, bidi overrides, BOM) which bypass visual inspection.
        if crate::core::has_dangerous_chars(&self.org_id) {
            return Err(format!(
                "FederationTrustAnchor '{}' org_id contains control or format characters",
                self.org_id
            ));
        }
        // SECURITY (FIND-R157-P3): Reject control/format chars in display_name
        // to prevent log injection and misleading visual display.
        if crate::core::has_dangerous_chars(&self.display_name) {
            return Err(format!(
                "FederationTrustAnchor '{}' display_name contains control or format characters",
                self.org_id
            ));
        }
        if self.issuer_pattern.is_empty() {
            return Err(format!(
                "FederationTrustAnchor '{}' issuer_pattern must not be empty",
                self.org_id
            ));
        }
        // SECURITY (FIND-R50-009): Bound issuer_pattern length.
        if self.issuer_pattern.len() > Self::MAX_ISSUER_PATTERN_LEN {
            return Err(format!(
                "FederationTrustAnchor '{}' issuer_pattern length {} exceeds max {}",
                self.org_id,
                self.issuer_pattern.len(),
                Self::MAX_ISSUER_PATTERN_LEN
            ));
        }
        // SECURITY (FIND-R50-009): Reject bare `*` wildcard — it would match
        // any issuer, which is almost certainly a misconfiguration.
        if self.issuer_pattern.trim() == "*" {
            return Err(format!(
                "FederationTrustAnchor '{}' issuer_pattern must not be a bare '*' wildcard",
                self.org_id
            ));
        }
        if let Some(ref uri) = self.jwks_uri {
            // SECURITY (FIND-R50-010): Require https:// scheme for JWKS URIs
            // in production. http:// is only allowed for testing.
            if !uri.starts_with("https://") && !uri.starts_with("http://") {
                return Err(format!(
                    "FederationTrustAnchor '{}' jwks_uri must use http(s) scheme, got: {}",
                    self.org_id, uri
                ));
            }
            // SECURITY (FIND-R50-010): Validate jwks_uri against SSRF —
            // reject localhost, loopback, link-local, and private IP ranges.
            Self::validate_jwks_uri_ssrf(uri)
                .map_err(|e| format!("FederationTrustAnchor '{}' jwks_uri {}", self.org_id, e))?;
        }
        if !VALID_TRUST_LEVELS.contains(&self.trust_level.as_str()) {
            return Err(format!(
                "FederationTrustAnchor '{}' trust_level must be one of {:?}, got: {}",
                self.org_id, VALID_TRUST_LEVELS, self.trust_level
            ));
        }
        if self.identity_mappings.len() > Self::MAX_IDENTITY_MAPPINGS {
            return Err(format!(
                "FederationTrustAnchor '{}' identity_mappings count {} exceeds max {}",
                self.org_id,
                self.identity_mappings.len(),
                Self::MAX_IDENTITY_MAPPINGS
            ));
        }
        for (i, mapping) in self.identity_mappings.iter().enumerate() {
            mapping.validate().map_err(|e| {
                format!(
                    "FederationTrustAnchor '{}' identity_mappings[{}]: {}",
                    self.org_id, i, e
                )
            })?;
        }
        Ok(())
    }

    /// SECURITY (FIND-R50-010): Validate a JWKS URI against SSRF vectors.
    ///
    /// Delegates to [`crate::core::validate_url_no_ssrf`] (IMP-R120-009).
    fn validate_jwks_uri_ssrf(uri: &str) -> Result<(), String> {
        crate::core::validate_url_no_ssrf(uri)
    }
}

/// Maps external identity claims to an internal Vellaveto principal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IdentityMapping {
    /// JWT claim to read (e.g., "sub", "email").
    pub external_claim: String,
    /// Internal principal type to map to.
    pub internal_principal_type: String,
    /// Template for the internal principal ID: "{org_id}:{claim_value}".
    pub id_template: String,
}

impl IdentityMapping {
    /// Validate the identity mapping configuration.
    ///
    /// Checks: external_claim non-empty, id_template contains `{claim_value}`,
    /// no control characters in any field.
    pub fn validate(&self) -> Result<(), String> {
        if self.external_claim.is_empty() {
            return Err("external_claim must not be empty".to_string());
        }
        // SECURITY (FIND-R104-002): Also reject Unicode format characters
        // (zero-width, bidi overrides, BOM) which bypass visual inspection.
        if crate::core::has_dangerous_chars(&self.external_claim) {
            return Err(format!(
                "external_claim '{}' contains control or format characters",
                self.external_claim
            ));
        }
        if !self.id_template.contains("{claim_value}") {
            return Err(format!(
                "id_template '{}' must contain '{{claim_value}}' placeholder",
                self.id_template
            ));
        }
        // SECURITY (FIND-R104-002): Also reject Unicode format characters
        // (zero-width, bidi overrides, BOM) which bypass visual inspection.
        if crate::core::has_dangerous_chars(&self.id_template) {
            return Err(format!(
                "id_template '{}' contains control or format characters",
                self.id_template
            ));
        }
        if self.internal_principal_type.is_empty() {
            return Err("internal_principal_type must not be empty".to_string());
        }
        // SECURITY (FIND-R157-P3): Reject control/format chars in internal_principal_type
        // to prevent log injection and identity spoofing.
        if crate::core::has_dangerous_chars(&self.internal_principal_type) {
            return Err(format!(
                "internal_principal_type '{}' contains control or format characters",
                self.internal_principal_type
            ));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEDERATION STATUS TYPES (Phase 39)
// ═══════════════════════════════════════════════════════════════════════════════

/// Federation status returned by GET /api/federation/status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FederationStatus {
    /// Whether federation is enabled.
    pub enabled: bool,
    /// Number of configured trust anchors.
    pub trust_anchor_count: usize,
    /// Per-anchor status.
    pub anchors: Vec<FederationAnchorStatus>,
}

/// Per-anchor status with JWKS cache info.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FederationAnchorStatus {
    /// Organization identifier.
    pub org_id: String,
    /// Human-readable name.
    pub display_name: String,
    /// Issuer glob pattern.
    pub issuer_pattern: String,
    /// Trust level.
    pub trust_level: String,
    /// Whether a JWKS URI is configured.
    /// SECURITY (FIND-R50-030): Changed from `Option<String>` to `bool` to avoid
    /// exposing the full JWKS endpoint URL in API responses.
    pub has_jwks_uri: bool,
    /// Whether JWKS keys are currently cached.
    pub jwks_cached: bool,
    /// ISO 8601 timestamp of last JWKS fetch.
    pub jwks_last_fetched: Option<String>,
    /// Number of identity mappings.
    pub identity_mapping_count: usize,
    /// Successful validation count.
    pub successful_validations: u64,
    /// Failed validation count.
    pub failed_validations: u64,
}

/// Abbreviated anchor info for API listing (excludes JWKS keys).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FederationAnchorInfo {
    /// Organization identifier.
    pub org_id: String,
    /// Human-readable name.
    pub display_name: String,
    /// Issuer glob pattern.
    pub issuer_pattern: String,
    /// Trust level.
    pub trust_level: String,
    /// Whether a JWKS URI is configured.
    pub has_jwks_uri: bool,
    /// Number of identity mappings.
    pub identity_mapping_count: usize,
}

// ═══════════════════════════════════════════════════════════════════════════════
// LEAST-AGENCY TRACKING (21.2)
// ═══════════════════════════════════════════════════════════════════════════════

/// Permission usage record for least-agency tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PermissionUsage {
    /// Tool pattern from the granting policy.
    pub tool_pattern: String,
    /// Function pattern from the granting policy.
    pub function_pattern: String,
    /// Number of times this permission has been exercised.
    pub used_count: u64,
    /// ISO 8601 timestamp of last usage.
    #[serde(default)]
    pub last_used: Option<String>,
}

impl PermissionUsage {
    /// Maximum length for pattern fields.
    const MAX_PATTERN_LEN: usize = 1024;
    /// Maximum length for ISO 8601 timestamp.
    const MAX_TIMESTAMP_LEN: usize = 64;

    /// Validate structural bounds on deserialized data.
    ///
    /// SECURITY (FIND-R216-008): Prevents oversized or injection-prone pattern
    /// and timestamp strings from untrusted deserialized payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.tool_pattern.len() > Self::MAX_PATTERN_LEN {
            return Err(format!(
                "PermissionUsage tool_pattern length {} exceeds max {}",
                self.tool_pattern.len(),
                Self::MAX_PATTERN_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.tool_pattern) {
            return Err(
                "PermissionUsage tool_pattern contains control or format characters".to_string(),
            );
        }
        if self.function_pattern.len() > Self::MAX_PATTERN_LEN {
            return Err(format!(
                "PermissionUsage function_pattern length {} exceeds max {}",
                self.function_pattern.len(),
                Self::MAX_PATTERN_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.function_pattern) {
            return Err(
                "PermissionUsage function_pattern contains control or format characters"
                    .to_string(),
            );
        }
        if let Some(ref lu) = self.last_used {
            if lu.len() > Self::MAX_TIMESTAMP_LEN {
                return Err(format!(
                    "PermissionUsage last_used length {} exceeds max {}",
                    lu.len(),
                    Self::MAX_TIMESTAMP_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(lu) {
                return Err(
                    "PermissionUsage last_used contains control or format characters".to_string(),
                );
            }
        }
        Ok(())
    }
}

/// Least-agency compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeastAgencyReport {
    /// Agent identifier.
    pub agent_id: String,
    /// Session identifier.
    pub session_id: String,
    /// Total number of permissions granted.
    pub granted_permissions: usize,
    /// Number of permissions actually exercised.
    pub used_permissions: usize,
    /// Policy IDs that were never exercised.
    pub unused_permissions: Vec<String>,
    /// Ratio of used to granted permissions (0.0–1.0).
    ///
    /// When `granted_permissions == 0`, this is `1.0` (not `0.0`) to avoid
    /// division by zero and to indicate that no permissions were wasted — an
    /// agent with zero grants has no unused permissions, so it is trivially
    /// "optimal" from a least-agency perspective.
    pub usage_ratio: f64,
    /// Recommended action based on usage ratio.
    pub recommendation: AgencyRecommendation,
}

impl LeastAgencyReport {
    /// Maximum number of unused permission entries.
    pub const MAX_UNUSED_PERMISSIONS: usize = 10_000;

    /// Validate structural invariants: finite scores, range checks, collection bounds.
    ///
    /// SECURITY (FIND-P2-007): Non-finite floats can propagate through
    /// calculations and comparisons unpredictably, potentially bypassing
    /// threshold checks (e.g., NaN < 0.5 is false, NaN > 0.5 is also false).
    /// SECURITY (FIND-R53-004): usage_ratio must be in [0.0, 1.0] to prevent
    /// negative or >1.0 values from bypassing threshold checks.
    /// SECURITY (FIND-R53-005): Unbounded unused_permissions can cause OOM.
    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (FIND-R115-006): Reject control/format chars in identity fields.
        if crate::core::has_dangerous_chars(&self.agent_id) {
            return Err(format!(
                "LeastAgencyReport agent_id '{}' contains control or format characters",
                self.agent_id
            ));
        }
        if crate::core::has_dangerous_chars(&self.session_id) {
            return Err(format!(
                "LeastAgencyReport session_id '{}' contains control or format characters",
                self.session_id
            ));
        }
        if !self.usage_ratio.is_finite() {
            return Err(format!(
                "LeastAgencyReport for agent '{}' session '{}' has non-finite usage_ratio: {}",
                self.agent_id, self.session_id, self.usage_ratio
            ));
        }
        if self.usage_ratio < 0.0 || self.usage_ratio > 1.0 {
            return Err(format!(
                "LeastAgencyReport for agent '{}' session '{}' usage_ratio must be in [0.0, 1.0], got {}",
                self.agent_id, self.session_id, self.usage_ratio
            ));
        }
        if self.unused_permissions.len() > Self::MAX_UNUSED_PERMISSIONS {
            return Err(format!(
                "LeastAgencyReport for agent '{}' session '{}' has {} unused_permissions (max {})",
                self.agent_id,
                self.session_id,
                self.unused_permissions.len(),
                Self::MAX_UNUSED_PERMISSIONS,
            ));
        }
        Ok(())
    }

    /// Deprecated alias for [`LeastAgencyReport::validate()`].
    #[deprecated(since = "4.0.1", note = "renamed to validate()")]
    pub fn validate_finite(&self) -> Result<(), String> {
        self.validate()
    }
}

/// Recommendation for adjusting an agent's permission scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgencyRecommendation {
    /// >80% usage — permissions are well-calibrated.
    Optimal,
    /// 50–80% usage — consider reviewing grants.
    ReviewGrants,
    /// 20–50% usage — scope should be narrowed.
    NarrowScope,
    /// <20% usage — severely over-permissioned.
    Critical,
}
