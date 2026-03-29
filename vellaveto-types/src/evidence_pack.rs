// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Compliance Evidence Pack types for DORA, NIS2, ISO 42001, and EU AI Act.
//!
//! Defines a unified evidence bundle format for auditor-ready compliance
//! evidence packs. Each pack contains sections of evidence items mapping
//! regulatory requirements to Vellaveto capabilities.

use serde::{Deserialize, Serialize};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of sections in an evidence pack.
pub const MAX_EVIDENCE_SECTIONS: usize = 100;

/// Maximum number of evidence items per section.
pub const MAX_EVIDENCE_ITEMS_PER_SECTION: usize = 200;

/// Maximum number of critical gaps in an evidence pack.
pub const MAX_EVIDENCE_PACK_GAPS: usize = 500;

/// Maximum number of recommendations in an evidence pack.
pub const MAX_EVIDENCE_RECOMMENDATIONS: usize = 100;

/// Maximum length for evidence string fields.
pub const MAX_EVIDENCE_STRING_LEN: usize = 4_096;

// ── Evidence Framework ───────────────────────────────────────────────────────

/// Compliance framework for which an evidence pack can be generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum EvidenceFramework {
    /// EU Digital Operational Resilience Act.
    Dora,
    /// EU Network and Information Security Directive 2.
    Nis2,
    /// ISO/IEC 42001 AI Management System.
    Iso42001,
    /// EU Artificial Intelligence Act.
    EuAiAct,
}

impl std::fmt::Display for EvidenceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dora => write!(f, "DORA"),
            Self::Nis2 => write!(f, "NIS2"),
            Self::Iso42001 => write!(f, "ISO 42001"),
            Self::EuAiAct => write!(f, "EU AI Act"),
        }
    }
}

// ── Evidence Confidence ──────────────────────────────────────────────────────

/// Confidence level of evidence mapping a requirement to a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceConfidence {
    /// No evidence available.
    None,
    /// Minimal evidence — indirect or tangential coverage.
    Low,
    /// Partial evidence — some capability mapped but gaps remain.
    Medium,
    /// Strong evidence — capability directly addresses the requirement.
    High,
    /// Complete evidence — full coverage with verification.
    Full,
}

impl std::fmt::Display for EvidenceConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Full => write!(f, "Full"),
        }
    }
}

// ── Evidence Item ────────────────────────────────────────────────────────────

/// A single evidence item mapping a regulatory requirement to a Vellaveto capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceItem {
    /// Requirement identifier (e.g., "Art 5", "21.2.a").
    pub requirement_id: String,
    /// Short title of the requirement.
    pub requirement_title: String,
    /// Article or clause reference in the regulation.
    pub article_ref: String,
    /// Vellaveto capability providing the evidence.
    pub vellaveto_capability: String,
    /// Description of how the capability addresses the requirement.
    pub evidence_description: String,
    /// Confidence level of this evidence mapping.
    pub confidence: EvidenceConfidence,
    /// Identified gaps for this requirement.
    #[serde(default)]
    pub gaps: Vec<String>,
}

impl EvidenceItem {
    /// Validate evidence item bounds.
    pub fn validate(&self) -> Result<(), String> {
        Self::check_field("requirement_id", &self.requirement_id)?;
        Self::check_field("requirement_title", &self.requirement_title)?;
        Self::check_field("article_ref", &self.article_ref)?;
        Self::check_field("vellaveto_capability", &self.vellaveto_capability)?;
        Self::check_field("evidence_description", &self.evidence_description)?;
        if self.gaps.len() > MAX_EVIDENCE_PACK_GAPS {
            return Err(format!(
                "EvidenceItem.gaps has {} entries, max is {}",
                self.gaps.len(),
                MAX_EVIDENCE_PACK_GAPS,
            ));
        }
        for (i, gap) in self.gaps.iter().enumerate() {
            if gap.len() > MAX_EVIDENCE_STRING_LEN {
                return Err(format!(
                    "EvidenceItem.gaps[{}] length {} exceeds max {}",
                    i,
                    gap.len(),
                    MAX_EVIDENCE_STRING_LEN,
                ));
            }
            if crate::has_dangerous_chars(gap) {
                return Err(format!(
                    "EvidenceItem.gaps[{i}] contains control or format characters",
                ));
            }
        }
        Ok(())
    }

    fn check_field(name: &str, value: &str) -> Result<(), String> {
        if value.len() > MAX_EVIDENCE_STRING_LEN {
            return Err(format!(
                "EvidenceItem.{} length {} exceeds max {}",
                name,
                value.len(),
                MAX_EVIDENCE_STRING_LEN,
            ));
        }
        if crate::has_dangerous_chars(value) {
            return Err(format!(
                "EvidenceItem.{name} contains control or format characters",
            ));
        }
        Ok(())
    }
}

// ── Evidence Section ─────────────────────────────────────────────────────────

/// A group of related evidence items within an evidence pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSection {
    /// Section identifier (e.g., "ict-risk", "art-21-2").
    pub section_id: String,
    /// Human-readable section title.
    pub title: String,
    /// Section description.
    pub description: String,
    /// Evidence items in this section.
    pub items: Vec<EvidenceItem>,
    /// Coverage percentage for this section (0.0–100.0).
    pub section_coverage_percent: f32,
}

impl EvidenceSection {
    /// Validate evidence section bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.section_id.len() > MAX_EVIDENCE_STRING_LEN {
            return Err(format!(
                "EvidenceSection.section_id length {} exceeds max {}",
                self.section_id.len(),
                MAX_EVIDENCE_STRING_LEN,
            ));
        }
        if crate::has_dangerous_chars(&self.section_id) {
            return Err(
                "EvidenceSection.section_id contains control or format characters".to_string(),
            );
        }
        if self.title.len() > MAX_EVIDENCE_STRING_LEN {
            return Err(format!(
                "EvidenceSection.title length {} exceeds max {}",
                self.title.len(),
                MAX_EVIDENCE_STRING_LEN,
            ));
        }
        if crate::has_dangerous_chars(&self.title) {
            return Err("EvidenceSection.title contains control or format characters".to_string());
        }
        if self.description.len() > MAX_EVIDENCE_STRING_LEN {
            return Err(format!(
                "EvidenceSection.description length {} exceeds max {MAX_EVIDENCE_STRING_LEN}",
                self.description.len(),
            ));
        }
        if crate::has_dangerous_chars(&self.description) {
            return Err(
                "EvidenceSection.description contains control or format characters".to_string(),
            );
        }
        if self.items.len() > MAX_EVIDENCE_ITEMS_PER_SECTION {
            return Err(format!(
                "EvidenceSection.items has {} entries, max is {}",
                self.items.len(),
                MAX_EVIDENCE_ITEMS_PER_SECTION,
            ));
        }
        if !self.section_coverage_percent.is_finite()
            || self.section_coverage_percent < 0.0
            || self.section_coverage_percent > 100.0
        {
            return Err(format!(
                "EvidenceSection.section_coverage_percent {} out of range [0.0, 100.0]",
                self.section_coverage_percent,
            ));
        }
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
    }
}

// ── Evidence Pack ────────────────────────────────────────────────────────────

/// A complete compliance evidence pack for a single framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePack {
    /// The compliance framework this pack covers.
    pub framework: EvidenceFramework,
    /// Human-readable framework name.
    pub framework_name: String,
    /// ISO 8601 timestamp of generation.
    pub generated_at: String,
    /// Organization name.
    pub organization_name: String,
    /// System identifier.
    pub system_id: String,
    /// Optional period start (ISO 8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period_start: Option<String>,
    /// Optional period end (ISO 8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period_end: Option<String>,
    /// Evidence sections grouped by regulatory topic.
    pub sections: Vec<EvidenceSection>,
    /// Overall coverage percentage (0.0–100.0).
    pub overall_coverage_percent: f32,
    /// Total number of requirements in the framework.
    pub total_requirements: usize,
    /// Number of fully covered requirements.
    pub covered_requirements: usize,
    /// Number of partially covered requirements.
    pub partial_requirements: usize,
    /// Number of uncovered requirements.
    pub uncovered_requirements: usize,
    /// Critical gaps requiring attention.
    pub critical_gaps: Vec<String>,
    /// Actionable recommendations.
    pub recommendations: Vec<String>,

    /// Ed25519 signature over the canonical evidence pack content (hex-encoded).
    /// When present, provides non-repudiation: the pack was generated by a holder
    /// of the corresponding signing key and has not been tampered with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Ed25519 verifying key (public key) for signature verification (hex-encoded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifying_key: Option<String>,
}

/// Maximum length for Ed25519 signature hex (64 bytes = 128 hex chars).
const MAX_EVIDENCE_SIGNATURE_HEX_LEN: usize = 128;
/// Maximum length for Ed25519 verifying key hex (32 bytes = 64 hex chars).
const MAX_EVIDENCE_VERIFYING_KEY_HEX_LEN: usize = 64;

impl EvidencePack {
    /// Compute the canonical content that is signed.
    ///
    /// Uses SHA-256 over length-prefixed fields (same pattern as
    /// `Checkpoint::signing_content()`) to produce a deterministic
    /// byte sequence independent of serialization format.
    pub fn signing_content(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let hash_field = |h: &mut Sha256, data: &[u8]| {
            h.update((data.len() as u64).to_le_bytes());
            h.update(data);
        };
        hash_field(&mut hasher, self.framework_name.as_bytes());
        hash_field(&mut hasher, self.generated_at.as_bytes());
        hash_field(&mut hasher, self.organization_name.as_bytes());
        hash_field(&mut hasher, self.system_id.as_bytes());
        hash_field(
            &mut hasher,
            &self.overall_coverage_percent.to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            &(self.total_requirements as u64).to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            &(self.covered_requirements as u64).to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            &(self.partial_requirements as u64).to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            &(self.uncovered_requirements as u64).to_le_bytes(),
        );
        // Include critical gaps content so tampering is detected.
        hash_field(
            &mut hasher,
            &(self.critical_gaps.len() as u64).to_le_bytes(),
        );
        for gap in &self.critical_gaps {
            hash_field(&mut hasher, gap.as_bytes());
        }
        hasher.finalize().to_vec()
    }

    /// Validate evidence pack bounds.
    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (IMP-R222-EP-001): Validate generated_at and period timestamps.
        // These ISO 8601 strings were missing length + dangerous char checks.
        for (name, val) in [
            ("generated_at", Some(&self.generated_at)),
            ("period_start", self.period_start.as_ref()),
            ("period_end", self.period_end.as_ref()),
        ] {
            if let Some(v) = val {
                if v.len() > MAX_EVIDENCE_STRING_LEN {
                    return Err(format!(
                        "EvidencePack.{name} length {} exceeds max {MAX_EVIDENCE_STRING_LEN}",
                        v.len(),
                    ));
                }
                if crate::has_dangerous_chars(v) {
                    return Err(format!(
                        "EvidencePack.{name} contains control or format characters",
                    ));
                }
            }
        }
        if self.framework_name.len() > MAX_EVIDENCE_STRING_LEN {
            return Err(format!(
                "EvidencePack.framework_name length {} exceeds max {}",
                self.framework_name.len(),
                MAX_EVIDENCE_STRING_LEN,
            ));
        }
        if crate::has_dangerous_chars(&self.framework_name) {
            return Err(
                "EvidencePack.framework_name contains control or format characters".to_string(),
            );
        }
        if self.organization_name.len() > MAX_EVIDENCE_STRING_LEN {
            return Err(format!(
                "EvidencePack.organization_name length {} exceeds max {}",
                self.organization_name.len(),
                MAX_EVIDENCE_STRING_LEN,
            ));
        }
        if crate::has_dangerous_chars(&self.organization_name) {
            return Err(
                "EvidencePack.organization_name contains control or format characters".to_string(),
            );
        }
        if self.system_id.len() > MAX_EVIDENCE_STRING_LEN {
            return Err(format!(
                "EvidencePack.system_id length {} exceeds max {}",
                self.system_id.len(),
                MAX_EVIDENCE_STRING_LEN,
            ));
        }
        if crate::has_dangerous_chars(&self.system_id) {
            return Err("EvidencePack.system_id contains control or format characters".to_string());
        }
        if self.sections.len() > MAX_EVIDENCE_SECTIONS {
            return Err(format!(
                "EvidencePack.sections has {} entries, max is {}",
                self.sections.len(),
                MAX_EVIDENCE_SECTIONS,
            ));
        }
        if !self.overall_coverage_percent.is_finite()
            || self.overall_coverage_percent < 0.0
            || self.overall_coverage_percent > 100.0
        {
            return Err(format!(
                "EvidencePack.overall_coverage_percent {} out of range [0.0, 100.0]",
                self.overall_coverage_percent,
            ));
        }
        if self.critical_gaps.len() > MAX_EVIDENCE_PACK_GAPS {
            return Err(format!(
                "EvidencePack.critical_gaps has {} entries, max is {}",
                self.critical_gaps.len(),
                MAX_EVIDENCE_PACK_GAPS,
            ));
        }
        for (i, gap) in self.critical_gaps.iter().enumerate() {
            if gap.len() > MAX_EVIDENCE_STRING_LEN {
                return Err(format!(
                    "EvidencePack.critical_gaps[{i}] length {} exceeds max {MAX_EVIDENCE_STRING_LEN}",
                    gap.len(),
                ));
            }
            if crate::has_dangerous_chars(gap) {
                return Err(format!(
                    "EvidencePack.critical_gaps[{i}] contains control or format characters",
                ));
            }
        }
        if self.recommendations.len() > MAX_EVIDENCE_RECOMMENDATIONS {
            return Err(format!(
                "EvidencePack.recommendations has {} entries, max is {}",
                self.recommendations.len(),
                MAX_EVIDENCE_RECOMMENDATIONS,
            ));
        }
        for (i, rec) in self.recommendations.iter().enumerate() {
            if rec.len() > MAX_EVIDENCE_STRING_LEN {
                return Err(format!(
                    "EvidencePack.recommendations[{i}] length {} exceeds max {MAX_EVIDENCE_STRING_LEN}",
                    rec.len(),
                ));
            }
            if crate::has_dangerous_chars(rec) {
                return Err(format!(
                    "EvidencePack.recommendations[{i}] contains control or format characters",
                ));
            }
        }
        // SECURITY (IMP-R222-009): Requirement count consistency check.
        let sum = self
            .covered_requirements
            .saturating_add(self.partial_requirements)
            .saturating_add(self.uncovered_requirements);
        if sum > self.total_requirements {
            return Err(format!(
                "EvidencePack: covered({}) + partial({}) + uncovered({}) = {} exceeds total_requirements({})",
                self.covered_requirements,
                self.partial_requirements,
                self.uncovered_requirements,
                sum,
                self.total_requirements,
            ));
        }
        for section in &self.sections {
            section.validate()?;
        }
        // SECURITY: Validate signature fields if present.
        if let Some(ref sig) = self.signature {
            if sig.len() != MAX_EVIDENCE_SIGNATURE_HEX_LEN {
                return Err(format!(
                    "EvidencePack.signature must be exactly {} hex chars, got {}",
                    MAX_EVIDENCE_SIGNATURE_HEX_LEN,
                    sig.len(),
                ));
            }
            if crate::has_dangerous_chars(sig) {
                return Err(
                    "EvidencePack.signature contains dangerous characters".to_string(),
                );
            }
        }
        if let Some(ref vk) = self.verifying_key {
            if vk.len() != MAX_EVIDENCE_VERIFYING_KEY_HEX_LEN {
                return Err(format!(
                    "EvidencePack.verifying_key must be exactly {} hex chars, got {}",
                    MAX_EVIDENCE_VERIFYING_KEY_HEX_LEN,
                    vk.len(),
                ));
            }
            if crate::has_dangerous_chars(vk) {
                return Err(
                    "EvidencePack.verifying_key contains dangerous characters".to_string(),
                );
            }
        }
        Ok(())
    }
}

// ── Evidence Pack Status ─────────────────────────────────────────────────────

/// Status response for the evidence pack endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePackStatus {
    /// Frameworks available for evidence pack generation.
    pub available_frameworks: Vec<EvidenceFramework>,
    /// Whether DORA evidence generation is enabled.
    pub dora_enabled: bool,
    /// Whether NIS2 evidence generation is enabled.
    pub nis2_enabled: bool,
}

impl EvidencePackStatus {
    /// Maximum number of available frameworks.
    const MAX_FRAMEWORKS: usize = 50;

    /// Validate structural bounds on deserialized data.
    ///
    /// SECURITY (FIND-R216-016): Prevents unbounded framework lists from
    /// untrusted deserialized payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.available_frameworks.len() > Self::MAX_FRAMEWORKS {
            return Err(format!(
                "EvidencePackStatus available_frameworks count {} exceeds max {}",
                self.available_frameworks.len(),
                Self::MAX_FRAMEWORKS,
            ));
        }
        Ok(())
    }
}
