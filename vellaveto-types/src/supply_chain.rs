// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Phase 5: Supply-chain trust types.
//!
//! Types for SBOM ingestion, attestation verification, and supply-chain
//! trust scoring. Used by discovery and registry to build trust decisions
//! from provenance inputs.

use serde::{Deserialize, Serialize};

/// Supply-chain attestation for an MCP server or tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SupplyChainAttestation {
    /// Attestation type.
    pub attestation_type: AttestationType,
    /// Issuer (e.g., Sigstore, publisher, registry).
    pub issuer: String,
    /// Subject (server ID, tool name, or package name).
    pub subject: String,
    /// Whether the attestation has been verified.
    pub verified: bool,
    /// ISO 8601 timestamp of the attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    /// ISO 8601 expiry timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Digest of the attested artifact (e.g., "sha256:abc123").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<String>,
}

/// Types of supply-chain attestations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttestationType {
    /// SLSA provenance attestation.
    SlsaProvenance,
    /// Sigstore signature.
    SigstoreSignature,
    /// SBOM (CycloneDX or SPDX).
    Sbom,
    /// Publisher-signed tool description (ETDI).
    EtdiSignature,
    /// Registry-verified namespace.
    RegistryVerified,
    /// Custom attestation.
    Custom(String),
}

/// SBOM entry for a dependency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomEntry {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// License (SPDX identifier).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Known vulnerabilities (CVE IDs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<String>,
    /// Package source (crates.io, npm, PyPI, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Supply-chain trust decision for a server or tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SupplyChainTrustDecision {
    /// Subject being evaluated.
    pub subject: String,
    /// Trust decision.
    pub decision: TrustDecision,
    /// Factors that contributed to the decision.
    pub factors: Vec<TrustFactor>,
    /// Computed trust score (0-100).
    pub score: u32,
}

/// Trust decision outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustDecision {
    /// Trusted — all attestations verified, no known issues.
    Trusted,
    /// Conditional — some attestations present but not all verified.
    Conditional,
    /// Untrusted — missing attestations or known issues.
    Untrusted,
    /// Blocked — known malicious or compromised.
    Blocked,
}

/// A factor in a trust decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustFactor {
    /// Factor name.
    pub name: String,
    /// Whether this factor is positive or negative.
    pub positive: bool,
    /// Weight (1-100).
    pub weight: u32,
    /// Description.
    pub description: String,
}

/// Compute a supply-chain trust decision from attestations and SBOM.
pub fn compute_trust_decision(
    subject: &str,
    attestations: &[SupplyChainAttestation],
    sbom_vulnerabilities: usize,
    behavioral_reputation_score: Option<u32>,
) -> SupplyChainTrustDecision {
    let mut factors = Vec::new();
    let mut score: i32 = 50; // Start at neutral

    // Attestation factors
    let verified_count = attestations.iter().filter(|a| a.verified).count();
    let total_count = attestations.len();

    if total_count > 0 {
        if verified_count == total_count {
            factors.push(TrustFactor {
                name: "attestations_verified".to_string(),
                positive: true,
                weight: 30,
                description: format!("All {verified_count} attestations verified"),
            });
            score += 30;
        } else {
            factors.push(TrustFactor {
                name: "attestations_partial".to_string(),
                positive: false,
                weight: 15,
                description: format!("{verified_count}/{total_count} attestations verified"),
            });
            score -= 15;
        }
    } else {
        factors.push(TrustFactor {
            name: "no_attestations".to_string(),
            positive: false,
            weight: 20,
            description: "No supply-chain attestations provided".to_string(),
        });
        score -= 20;
    }

    // Vulnerability factors
    if sbom_vulnerabilities > 0 {
        let weight = (sbom_vulnerabilities as i32 * 10).min(40);
        factors.push(TrustFactor {
            name: "known_vulnerabilities".to_string(),
            positive: false,
            weight: weight as u32,
            description: format!("{sbom_vulnerabilities} known vulnerabilities in SBOM"),
        });
        score -= weight;
    }

    // Behavioral reputation
    if let Some(rep_score) = behavioral_reputation_score {
        if rep_score >= 80 {
            factors.push(TrustFactor {
                name: "behavioral_reputation".to_string(),
                positive: true,
                weight: 20,
                description: format!("Reputation score: {rep_score}/100"),
            });
            score += 20;
        } else if rep_score < 40 {
            factors.push(TrustFactor {
                name: "behavioral_reputation_low".to_string(),
                positive: false,
                weight: 25,
                description: format!("Low reputation score: {rep_score}/100"),
            });
            score -= 25;
        }
    }

    let clamped_score = score.clamp(0, 100) as u32;

    let decision = if clamped_score >= 80 {
        TrustDecision::Trusted
    } else if clamped_score >= 50 {
        TrustDecision::Conditional
    } else if clamped_score >= 20 {
        TrustDecision::Untrusted
    } else {
        TrustDecision::Blocked
    };

    SupplyChainTrustDecision {
        subject: subject.to_string(),
        decision,
        factors,
        score: clamped_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified_attestation(atype: AttestationType) -> SupplyChainAttestation {
        SupplyChainAttestation {
            attestation_type: atype,
            issuer: "sigstore".to_string(),
            subject: "test-server".to_string(),
            verified: true,
            issued_at: None,
            expires_at: None,
            artifact_digest: Some("sha256:abc".to_string()),
        }
    }

    #[test]
    fn test_fully_attested_trusted() {
        let decision = compute_trust_decision(
            "good-server",
            &[
                verified_attestation(AttestationType::SlsaProvenance),
                verified_attestation(AttestationType::SigstoreSignature),
            ],
            0,
            Some(95),
        );
        assert_eq!(decision.decision, TrustDecision::Trusted);
        assert!(decision.score >= 80);
    }

    #[test]
    fn test_no_attestations_untrusted() {
        let decision = compute_trust_decision("unknown-server", &[], 0, None);
        assert!(decision.score < 50);
        assert!(matches!(
            decision.decision,
            TrustDecision::Untrusted | TrustDecision::Conditional
        ));
    }

    #[test]
    fn test_vulnerabilities_lower_score() {
        let decision = compute_trust_decision(
            "vuln-server",
            &[verified_attestation(AttestationType::SlsaProvenance)],
            5,
            None,
        );
        assert!(decision.score < 80);
        assert!(decision.factors.iter().any(|f| f.name == "known_vulnerabilities"));
    }

    #[test]
    fn test_low_reputation_lowers_score() {
        let decision = compute_trust_decision(
            "bad-rep-server",
            &[verified_attestation(AttestationType::SlsaProvenance)],
            0,
            Some(20),
        );
        assert!(decision.score < 80);
    }

    #[test]
    fn test_partial_attestations_conditional() {
        let mut att = verified_attestation(AttestationType::SlsaProvenance);
        let att2 = SupplyChainAttestation {
            verified: false,
            ..att.clone()
        };
        att.subject = "s".to_string();
        let decision = compute_trust_decision("partial-server", &[att, att2], 0, None);
        assert!(decision
            .factors
            .iter()
            .any(|f| f.name == "attestations_partial"));
    }

    #[test]
    fn test_score_clamped_to_bounds() {
        // Many negatives shouldn't go below 0
        let decision = compute_trust_decision("terrible", &[], 10, Some(10));
        assert!(decision.score <= 100);
        // Score should be 0 (clamped from negative)
        assert_eq!(decision.decision, TrustDecision::Blocked);
    }
}
