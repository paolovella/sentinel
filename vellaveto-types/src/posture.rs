// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use serde::{Deserialize, Serialize};

/// Scope attached to posture responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureScope {
    /// Scope kind (`global` or `tenant`).
    pub kind: String,
    /// Tenant identifier when the response is tenant-scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

impl PostureScope {
    /// Build a global posture scope.
    pub fn global() -> Self {
        Self {
            kind: "global".to_string(),
            tenant: None,
        }
    }

    /// Build a tenant-scoped posture scope.
    pub fn tenant(tenant: impl Into<String>) -> Self {
        Self {
            kind: "tenant".to_string(),
            tenant: Some(tenant.into()),
        }
    }

    /// Return true when this scope is global.
    pub fn is_global(&self) -> bool {
        self.tenant.is_none()
    }
}

/// Per-category score within the aggregate security posture response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureCategoryScore {
    /// Category identifier (for example: governance, runtime, supply_chain).
    pub name: String,
    /// Aggregate score for the category, in percent.
    pub score_percent: f32,
    /// Number of framework inputs used to compute the category.
    pub inputs: usize,
}

impl PostureCategoryScore {
    /// SECURITY (R260-TYP-1): Validate category score for NaN/Infinity, bounds, and
    /// dangerous characters. Previously only validated transitively via SecurityPostureScore.
    pub fn validate(&self) -> Result<(), String> {
        if !self.score_percent.is_finite() || !(0.0..=100.0).contains(&self.score_percent) {
            return Err(format!(
                "category score_percent {} is not in [0.0, 100.0]",
                self.score_percent
            ));
        }
        if self.name.len() > MAX_POSTURE_STRING_LEN {
            return Err(format!(
                "category name too long ({} > {})",
                self.name.len(),
                MAX_POSTURE_STRING_LEN
            ));
        }
        if crate::has_dangerous_chars(&self.name) {
            return Err("category name contains dangerous characters".to_string());
        }
        Ok(())
    }
}

/// Coverage or readiness score for a single framework in the posture view.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureFrameworkScore {
    /// Framework display name.
    pub name: String,
    /// Coverage or readiness score for the framework, in percent.
    pub score_percent: f32,
    /// Whether the framework-specific reporting is enabled in the current config.
    pub enabled: bool,
}

impl PostureFrameworkScore {
    /// SECURITY (R260-TYP-1): Validate framework score for NaN/Infinity, bounds, and
    /// dangerous characters. Previously only validated transitively via SecurityPostureScore.
    pub fn validate(&self) -> Result<(), String> {
        if !self.score_percent.is_finite() || !(0.0..=100.0).contains(&self.score_percent) {
            return Err(format!(
                "framework score_percent {} is not in [0.0, 100.0]",
                self.score_percent
            ));
        }
        if self.name.len() > MAX_POSTURE_STRING_LEN {
            return Err(format!(
                "framework name too long ({} > {})",
                self.name.len(),
                MAX_POSTURE_STRING_LEN
            ));
        }
        if crate::has_dangerous_chars(&self.name) {
            return Err("framework name contains dangerous characters".to_string());
        }
        Ok(())
    }
}

/// High-level security posture score for the active Vellaveto deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityPostureScore {
    /// Report generation timestamp (RFC 3339).
    pub generated_at: String,
    /// Scope used to generate the posture score.
    pub scope: PostureScope,
    /// Aggregate score across the category breakdown.
    pub overall_score_percent: f32,
    /// Qualitative tier derived from the overall score.
    pub tier: String,
    /// Category breakdown used to compute the overall score.
    pub categories: Vec<PostureCategoryScore>,
    /// Framework-level inputs that feed the posture score.
    pub frameworks: Vec<PostureFrameworkScore>,
}

/// Maximum number of items in posture collections.
const MAX_POSTURE_ITEMS: usize = 500;

/// Maximum length for string fields in posture types.
const MAX_POSTURE_STRING_LEN: usize = 1024;

impl SecurityPostureScore {
    /// SECURITY (R239-TYP-1): Validate posture score for NaN/Infinity and bounds.
    pub fn validate(&self) -> Result<(), String> {
        fn check_percent(name: &str, v: f32) -> Result<(), String> {
            if !v.is_finite() || !(0.0..=100.0).contains(&v) {
                return Err(format!("{name} {v} is not in [0.0, 100.0]"));
            }
            Ok(())
        }
        check_percent("overall_score_percent", self.overall_score_percent)?;
        if self.categories.len() > MAX_POSTURE_ITEMS {
            return Err(format!(
                "categories count {} exceeds max {MAX_POSTURE_ITEMS}",
                self.categories.len()
            ));
        }
        for c in &self.categories {
            check_percent("category score_percent", c.score_percent)?;
        }
        if self.frameworks.len() > MAX_POSTURE_ITEMS {
            return Err(format!(
                "frameworks count {} exceeds max {MAX_POSTURE_ITEMS}",
                self.frameworks.len()
            ));
        }
        for f in &self.frameworks {
            check_percent("framework score_percent", f.score_percent)?;
        }
        if self.generated_at.len() > MAX_POSTURE_STRING_LEN {
            return Err("generated_at too long".to_string());
        }
        // SECURITY (R243-TYP-3): Validate string content — these flow into
        // API responses, dashboards, and audit trails.
        if crate::core::has_dangerous_chars(&self.generated_at) {
            return Err("generated_at contains control or format characters".to_string());
        }
        if self.tier.len() > MAX_POSTURE_STRING_LEN {
            return Err("tier too long".to_string());
        }
        if crate::core::has_dangerous_chars(&self.tier) {
            return Err("tier contains control or format characters".to_string());
        }
        if self.scope.kind.len() > MAX_POSTURE_STRING_LEN
            || crate::core::has_dangerous_chars(&self.scope.kind)
        {
            return Err("scope.kind invalid".to_string());
        }
        if let Some(ref tenant) = self.scope.tenant {
            if tenant.len() > MAX_POSTURE_STRING_LEN || crate::core::has_dangerous_chars(tenant) {
                return Err("scope.tenant invalid".to_string());
            }
        }
        for c in &self.categories {
            if c.name.len() > MAX_POSTURE_STRING_LEN || crate::core::has_dangerous_chars(&c.name) {
                return Err("category name invalid".to_string());
            }
        }
        for f in &self.frameworks {
            if f.name.len() > MAX_POSTURE_STRING_LEN || crate::core::has_dangerous_chars(&f.name) {
                return Err("framework name invalid".to_string());
            }
        }
        Ok(())
    }
}

impl PostureGapReport {
    /// SECURITY (R239-TYP-1): Validate gap report for NaN/Infinity and bounds.
    pub fn validate(&self) -> Result<(), String> {
        if !self.overall_coverage_percent.is_finite()
            || self.overall_coverage_percent < 0.0
            || self.overall_coverage_percent > 100.0
        {
            return Err(format!(
                "overall_coverage_percent {} is not in [0.0, 100.0]",
                self.overall_coverage_percent
            ));
        }
        if self.critical_gaps.len() > MAX_POSTURE_ITEMS {
            return Err(format!(
                "critical_gaps count {} exceeds max {MAX_POSTURE_ITEMS}",
                self.critical_gaps.len()
            ));
        }
        if self.recommendations.len() > MAX_POSTURE_ITEMS {
            return Err(format!(
                "recommendations count {} exceeds max {MAX_POSTURE_ITEMS}",
                self.recommendations.len()
            ));
        }
        if self.high_priority_focus_areas.len() > MAX_POSTURE_ITEMS {
            return Err(format!(
                "high_priority_focus_areas count {} exceeds max {MAX_POSTURE_ITEMS}",
                self.high_priority_focus_areas.len()
            ));
        }
        // SECURITY (R243-TYP-3): Validate string content.
        if self.generated_at.len() > MAX_POSTURE_STRING_LEN
            || crate::core::has_dangerous_chars(&self.generated_at)
        {
            return Err("generated_at invalid".to_string());
        }
        if let Some(ref tenant) = self.scope.tenant {
            if tenant.len() > MAX_POSTURE_STRING_LEN || crate::core::has_dangerous_chars(tenant) {
                return Err("scope.tenant invalid".to_string());
            }
        }
        for gap in &self.critical_gaps {
            for (name, val) in [
                ("framework", &gap.framework),
                ("item_id", &gap.item_id),
                ("severity", &gap.severity),
                ("description", &gap.description),
            ] {
                if val.len() > MAX_POSTURE_STRING_LEN || crate::core::has_dangerous_chars(val) {
                    return Err(format!("critical_gap {name} invalid"));
                }
            }
        }
        for (i, rec) in self.recommendations.iter().enumerate() {
            if rec.len() > MAX_POSTURE_STRING_LEN || crate::core::has_dangerous_chars(rec) {
                return Err(format!("recommendations[{i}] invalid"));
            }
        }
        for (i, area) in self.high_priority_focus_areas.iter().enumerate() {
            if area.len() > MAX_POSTURE_STRING_LEN || crate::core::has_dangerous_chars(area) {
                return Err(format!("high_priority_focus_areas[{i}] invalid"));
            }
        }
        Ok(())
    }
}

/// A normalized coverage summary for a framework in the control matrix view.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlCoverageSummary {
    /// Framework display name.
    pub framework: String,
    /// Total controls/techniques/items for the framework.
    pub total_items: usize,
    /// Covered controls/techniques/items for the framework.
    pub covered_items: usize,
    /// Percent of covered items in the framework.
    pub coverage_percent: f32,
}

/// Consolidated control coverage matrix used by posture dashboards.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlCoverageMatrix {
    /// Report generation timestamp (RFC 3339).
    pub generated_at: String,
    /// Scope used to generate the control coverage matrix.
    pub scope: PostureScope,
    /// Weighted aggregate coverage across the listed frameworks.
    pub overall_coverage_percent: f32,
    /// Per-framework control coverage summaries.
    pub frameworks: Vec<ControlCoverageSummary>,
    /// Short operator-facing notes that explain how to interpret the matrix.
    pub highlights: Vec<String>,
}

impl ControlCoverageMatrix {
    /// SECURITY (R243-TYP-3): Validate coverage matrix for NaN/Infinity, bounds, and string content.
    pub fn validate(&self) -> Result<(), String> {
        if !self.overall_coverage_percent.is_finite()
            || !(0.0..=100.0).contains(&self.overall_coverage_percent)
        {
            return Err(format!(
                "overall_coverage_percent {} is not in [0.0, 100.0]",
                self.overall_coverage_percent
            ));
        }
        if self.frameworks.len() > MAX_POSTURE_ITEMS {
            return Err(format!(
                "frameworks count {} exceeds max {MAX_POSTURE_ITEMS}",
                self.frameworks.len()
            ));
        }
        if self.highlights.len() > MAX_POSTURE_ITEMS {
            return Err(format!(
                "highlights count {} exceeds max {MAX_POSTURE_ITEMS}",
                self.highlights.len()
            ));
        }
        if self.generated_at.len() > MAX_POSTURE_STRING_LEN
            || crate::core::has_dangerous_chars(&self.generated_at)
        {
            return Err("generated_at invalid".to_string());
        }
        if let Some(ref tenant) = self.scope.tenant {
            if tenant.len() > MAX_POSTURE_STRING_LEN || crate::core::has_dangerous_chars(tenant) {
                return Err("scope.tenant invalid".to_string());
            }
        }
        for f in &self.frameworks {
            if !f.coverage_percent.is_finite() || !(0.0..=100.0).contains(&f.coverage_percent) {
                return Err(format!(
                    "framework coverage_percent {} is not in [0.0, 100.0]",
                    f.coverage_percent
                ));
            }
            if f.framework.len() > MAX_POSTURE_STRING_LEN
                || crate::core::has_dangerous_chars(&f.framework)
            {
                return Err("framework name invalid".to_string());
            }
        }
        for (i, h) in self.highlights.iter().enumerate() {
            if h.len() > MAX_POSTURE_STRING_LEN || crate::core::has_dangerous_chars(h) {
                return Err(format!("highlights[{i}] invalid"));
            }
        }
        Ok(())
    }
}

/// A normalized remediation gap in the posture API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureGap {
    /// Framework where the gap appears.
    pub framework: String,
    /// Gap identifier within the framework.
    pub item_id: String,
    /// Severity label (for example: High, Medium).
    pub severity: String,
    /// Human-readable description of the gap.
    pub description: String,
}

/// Prioritized remediation gaps derived from the broader control matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureGapReport {
    /// Report generation timestamp (RFC 3339).
    pub generated_at: String,
    /// Scope used to generate the remediation queue.
    pub scope: PostureScope,
    /// Weighted aggregate coverage across the sources used in this report.
    pub overall_coverage_percent: f32,
    /// Highest-priority gaps to address.
    pub critical_gaps: Vec<PostureGap>,
    /// Actionable remediation guidance.
    pub recommendations: Vec<String>,
    /// A compact list of themes that need immediate attention.
    pub high_priority_focus_areas: Vec<String>,
}

/// Posture-focused export that combines a compliance evidence pack with the
/// current posture score and remediation focus areas.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureEvidencePackExport {
    /// Report generation timestamp (RFC 3339).
    pub generated_at: String,
    /// Evidence pack framework identifier.
    pub framework: String,
    /// Scope used for the posture context.
    pub scope: PostureScope,
    /// Aggregate posture at export time.
    pub posture: SecurityPostureScore,
    /// Highest-priority remediation themes.
    pub high_priority_focus_areas: Vec<String>,
    /// Framework-specific evidence pack payload.
    pub evidence_pack: serde_json::Value,
}

impl PostureEvidencePackExport {
    /// SECURITY (R243-TYP-3): Validate evidence pack export.
    pub fn validate(&self) -> Result<(), String> {
        if self.generated_at.len() > MAX_POSTURE_STRING_LEN
            || crate::core::has_dangerous_chars(&self.generated_at)
        {
            return Err("generated_at invalid".to_string());
        }
        if self.framework.len() > MAX_POSTURE_STRING_LEN
            || crate::core::has_dangerous_chars(&self.framework)
        {
            return Err("framework invalid".to_string());
        }
        if let Some(ref tenant) = self.scope.tenant {
            if tenant.len() > MAX_POSTURE_STRING_LEN || crate::core::has_dangerous_chars(tenant) {
                return Err("scope.tenant invalid".to_string());
            }
        }
        self.posture.validate()?;
        if self.high_priority_focus_areas.len() > MAX_POSTURE_ITEMS {
            return Err(format!(
                "high_priority_focus_areas count {} exceeds max {MAX_POSTURE_ITEMS}",
                self.high_priority_focus_areas.len()
            ));
        }
        for (i, area) in self.high_priority_focus_areas.iter().enumerate() {
            if area.len() > MAX_POSTURE_STRING_LEN || crate::core::has_dangerous_chars(area) {
                return Err(format!("high_priority_focus_areas[{i}] invalid"));
            }
        }
        Ok(())
    }
}
