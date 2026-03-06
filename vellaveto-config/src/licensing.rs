// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

// =============================================================================
// LICENSING — Tier configuration, limits, and Ed25519 license key validation
// =============================================================================
//
// License key format (v2, Ed25519):
//   VLV-{TIER}-{EXPIRY}-{CUSTOMER_ID}-{MAX_NODES}-{MAX_ENDPOINTS}.{SIG_HEX}
//
// The payload (everything before the '.') is signed with the licensor's Ed25519
// private key. The binary embeds only the public key for verification.
// No shared secret is distributed to customers.
//
// Migration from v1 (HMAC-SHA256):
//   Old format: VLV-{TIER}-{EXPIRY}-{HMAC_HEX}
//   Old keys will fail validation (no '.' separator) and fall back to Community.
//   Customers must obtain new Ed25519-signed keys from the licensor.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Maximum total length of a license key string.
/// Payload (~120 chars max) + '.' + 128 hex chars signature = ~250 max.
const MAX_LICENSE_KEY_LEN: usize = 512;

/// Ed25519 public key is 32 bytes = 64 hex characters.
const EXPECTED_PUBLIC_KEY_HEX_LEN: usize = 64;

/// Ed25519 signature is 64 bytes = 128 hex characters.
const EXPECTED_SIGNATURE_HEX_LEN: usize = 128;

/// Maximum length for the customer ID field in a license key.
const MAX_CUSTOMER_ID_LEN: usize = 64;

/// License tier determining feature limits.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    #[default]
    Community,
    Pro,
    Business,
    Enterprise,
}

impl LicenseTier {
    fn from_key_segment(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "community" | "com" => Some(LicenseTier::Community),
            "pro" => Some(LicenseTier::Pro),
            "business" | "biz" => Some(LicenseTier::Business),
            "enterprise" | "ent" => Some(LicenseTier::Enterprise),
            _ => None,
        }
    }

    /// Returns the feature limits for this tier.
    pub fn limits(&self) -> TierLimits {
        match self {
            LicenseTier::Community => TierLimits {
                max_mcp_servers: Some(5),
                max_users: Some(3),
                siem_export: false,
                sso_oidc: false,
                sso_saml: false,
                rbac: false,
                multi_tenancy: false,
                ha_clustering: false,
                compliance_reports: false,
                nis2_evidence: false,
                incident_workflow: false,
            },
            LicenseTier::Pro => TierLimits {
                max_mcp_servers: Some(25),
                max_users: Some(20),
                siem_export: true,
                sso_oidc: true,
                sso_saml: false,
                rbac: false,
                multi_tenancy: false,
                ha_clustering: false,
                compliance_reports: false,
                nis2_evidence: false,
                incident_workflow: false,
            },
            LicenseTier::Business => TierLimits {
                max_mcp_servers: Some(100),
                max_users: None,
                siem_export: true,
                sso_oidc: true,
                sso_saml: true,
                rbac: true,
                multi_tenancy: true,
                ha_clustering: false,
                compliance_reports: true,
                nis2_evidence: false,
                incident_workflow: false,
            },
            LicenseTier::Enterprise => TierLimits {
                max_mcp_servers: None,
                max_users: None,
                siem_export: true,
                sso_oidc: true,
                sso_saml: true,
                rbac: true,
                multi_tenancy: true,
                ha_clustering: true,
                compliance_reports: true,
                nis2_evidence: true,
                incident_workflow: true,
            },
        }
    }

    /// Returns the tier name as used in license key segments.
    pub fn as_key_segment(&self) -> &'static str {
        match self {
            LicenseTier::Community => "COM",
            LicenseTier::Pro => "PRO",
            LicenseTier::Business => "BIZ",
            LicenseTier::Enterprise => "ENT",
        }
    }
}

impl std::fmt::Display for LicenseTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseTier::Community => write!(f, "Community"),
            LicenseTier::Pro => write!(f, "Pro"),
            LicenseTier::Business => write!(f, "Business"),
            LicenseTier::Enterprise => write!(f, "Enterprise"),
        }
    }
}

/// Feature limits for a given license tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierLimits {
    pub max_mcp_servers: Option<u32>,
    pub max_users: Option<u32>,
    pub siem_export: bool,
    pub sso_oidc: bool,
    pub sso_saml: bool,
    pub rbac: bool,
    pub multi_tenancy: bool,
    pub ha_clustering: bool,
    pub compliance_reports: bool,
    pub nis2_evidence: bool,
    pub incident_workflow: bool,
}

/// Licensing configuration section of PolicyConfig.
///
/// SECURITY: Custom Debug impl redacts license_key to prevent secret leakage.
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicensingConfig {
    #[serde(default)]
    pub license_key: Option<String>,
    #[serde(default)]
    pub tier_override: Option<LicenseTier>,
}

impl std::fmt::Debug for LicensingConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LicensingConfig")
            .field(
                "license_key",
                &self.license_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("tier_override", &self.tier_override)
            .finish()
    }
}

/// Result of license key validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseValidation {
    pub tier: LicenseTier,
    pub limits: TierLimits,
    /// Customer identifier from the license key (None for Community/override).
    pub customer_id: Option<String>,
    /// Maximum cluster nodes permitted by this license.
    pub max_nodes: Option<u32>,
    /// Maximum managed MCP endpoints permitted by this license.
    pub max_endpoints: Option<u32>,
    pub reason: String,
}

fn community(reason: &str) -> LicenseValidation {
    LicenseValidation {
        tier: LicenseTier::Community,
        limits: LicenseTier::Community.limits(),
        customer_id: None,
        max_nodes: None,
        max_endpoints: None,
        reason: reason.to_string(),
    }
}

impl LicensingConfig {
    /// Validate licensing configuration bounds.
    ///
    /// SECURITY: Rejects oversized or control-char-injected license keys
    /// at config load time (fail-closed).
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref key) = self.license_key {
            if key.len() > MAX_LICENSE_KEY_LEN {
                return Err(format!(
                    "licensing.license_key length {} exceeds max {}",
                    key.len(),
                    MAX_LICENSE_KEY_LEN,
                ));
            }
            if key
                .bytes()
                .any(|b| b < 0x20 || b == 0x7F || (0x80..=0x9F).contains(&b))
            {
                return Err("licensing.license_key contains control characters".to_string());
            }
        }
        Ok(())
    }

    /// Resolve the effective license tier. Fail-closed to Community.
    ///
    /// Verification uses Ed25519 asymmetric signatures. The public key is
    /// loaded from `VELLAVETO_LICENSE_PUBLIC_KEY` (hex-encoded, 64 chars).
    /// No shared secret is required on the customer's side.
    pub fn resolve(&self) -> LicenseValidation {
        if let Some(tier) = self.tier_override {
            tracing::warn!(tier = %tier, "License tier override active — bypasses key validation");
            return LicenseValidation {
                tier,
                limits: tier.limits(),
                customer_id: None,
                max_nodes: None,
                max_endpoints: None,
                reason: "tier_override in config".to_string(),
            };
        }

        let key = std::env::var("VELLAVETO_LICENSE_KEY")
            .ok()
            .or_else(|| self.license_key.clone());

        let key = match key {
            Some(k) if !k.is_empty() => k,
            _ => {
                tracing::info!("No license key provided, defaulting to Community tier");
                return community("no license key");
            }
        };

        if key.len() > MAX_LICENSE_KEY_LEN {
            tracing::warn!("License key exceeds maximum length, defaulting to Community tier");
            return community("key too long");
        }

        // SECURITY: Validate env-var key against control characters,
        // matching the same check performed on config-file keys in validate().
        if key
            .bytes()
            .any(|b| b < 0x20 || b == 0x7F || (0x80..=0x9F).contains(&b))
        {
            tracing::warn!("License key contains control characters, defaulting to Community tier");
            return community("key contains control characters");
        }

        let verifying_key = match load_verifying_key() {
            Some(vk) => vk,
            None => {
                tracing::warn!(
                    "VELLAVETO_LICENSE_PUBLIC_KEY not set or invalid, defaulting to Community tier"
                );
                return community("no license public key");
            }
        };

        validate_license_key(&key, &verifying_key)
    }
}

/// Load the Ed25519 verifying key from `VELLAVETO_LICENSE_PUBLIC_KEY` env var.
///
/// The env var must contain exactly 64 hex characters (32 bytes).
/// Returns None on any error (fail-closed).
fn load_verifying_key() -> Option<VerifyingKey> {
    let hex_key = std::env::var("VELLAVETO_LICENSE_PUBLIC_KEY").ok()?;

    if hex_key.len() != EXPECTED_PUBLIC_KEY_HEX_LEN {
        tracing::warn!(
            len = hex_key.len(),
            expected = EXPECTED_PUBLIC_KEY_HEX_LEN,
            "VELLAVETO_LICENSE_PUBLIC_KEY has wrong length"
        );
        return None;
    }

    // Reject non-hex characters early.
    if !hex_key.bytes().all(|b| b.is_ascii_hexdigit()) {
        tracing::warn!("VELLAVETO_LICENSE_PUBLIC_KEY contains non-hex characters");
        return None;
    }

    let bytes = hex::decode(&hex_key).ok()?;
    let key_bytes: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&key_bytes).ok()
}

/// Validate an Ed25519-signed license key.
///
/// Key format: `VLV-{TIER}-{EXPIRY}-{CUSTOMER_ID}-{MAX_NODES}-{MAX_ENDPOINTS}.{SIG_HEX}`
///
/// SECURITY: Fail-closed — any parse or verification error returns Community tier.
/// Ed25519 verify is internally constant-time.
fn validate_license_key(key: &str, verifying_key: &VerifyingKey) -> LicenseValidation {
    // Split payload from signature at the last '.'
    let (payload, sig_hex) = match key.rsplit_once('.') {
        Some(parts) => parts,
        None => return community("invalid license key"),
    };

    // Ed25519 signature is 64 bytes = 128 hex characters.
    if sig_hex.len() != EXPECTED_SIGNATURE_HEX_LEN {
        return community("invalid license key");
    }

    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return community("invalid license key"),
    };

    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return community("invalid license key"),
    };

    // Parse payload: VLV-{TIER}-{EXPIRY}-{CUSTOMER_ID}-{MAX_NODES}-{MAX_ENDPOINTS}
    let parts: Vec<&str> = payload.split('-').collect();
    if parts.len() != 6 || parts[0] != "VLV" {
        return community("invalid license key");
    }

    let tier = match LicenseTier::from_key_segment(parts[1]) {
        Some(t) => t,
        None => return community("invalid license key"),
    };

    let expiry: u64 = match parts[2].parse() {
        Ok(e) => e,
        Err(_) => return community("invalid license key"),
    };

    let customer_id = parts[3];
    if customer_id.is_empty() || customer_id.len() > MAX_CUSTOMER_ID_LEN {
        return community("invalid license key");
    }
    // SECURITY: Only allow alphanumeric + underscore in customer ID to prevent
    // injection via crafted identifiers in logs, configs, or API responses.
    if !customer_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return community("invalid license key");
    }

    let max_nodes: u32 = match parts[4].parse() {
        Ok(n) => n,
        Err(_) => return community("invalid license key"),
    };

    let max_endpoints: u32 = match parts[5].parse() {
        Ok(e) => e,
        Err(_) => return community("invalid license key"),
    };

    // SECURITY: Verify Ed25519 signature over the payload.
    // ed25519-dalek::verify is internally constant-time.
    if verifying_key
        .verify(payload.as_bytes(), &signature)
        .is_err()
    {
        return community("invalid license key");
    }

    // Check expiry after signature verification to avoid timing oracle on
    // unsigned payloads.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_else(|_| {
            tracing::warn!("SystemTime before UNIX_EPOCH; treating license as expired");
            u64::MAX
        });

    if now >= expiry {
        return community("license key expired");
    }

    tracing::info!(
        tier = %tier,
        customer_id,
        expiry,
        max_nodes,
        max_endpoints,
        "License key validated successfully"
    );
    LicenseValidation {
        tier,
        limits: tier.limits(),
        customer_id: Some(customer_id.to_string()),
        max_nodes: Some(max_nodes),
        max_endpoints: Some(max_endpoints),
        reason: "valid license key".to_string(),
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
use ed25519_dalek::SigningKey;

/// Generate an Ed25519-signed license key (test/tooling utility).
#[cfg(test)]
fn generate_license_key(
    tier: LicenseTier,
    expiry_epoch: u64,
    customer_id: &str,
    max_nodes: u32,
    max_endpoints: u32,
    signing_key: &SigningKey,
) -> String {
    use ed25519_dalek::Signer;

    let payload = format!(
        "VLV-{}-{}-{}-{}-{}",
        tier.as_key_segment(),
        expiry_epoch,
        customer_id,
        max_nodes,
        max_endpoints,
    );
    let signature = signing_key.sign(payload.as_bytes());
    format!("{}.{}", payload, hex::encode(signature.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        // Deterministic test keypair from fixed seed.
        let seed: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn future_expiry() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + 86400 * 365)
            .unwrap_or(0)
    }

    #[test]
    fn test_generate_and_validate_pro_key() {
        let (sk, vk) = test_keypair();
        let expiry = future_expiry();
        let key = generate_license_key(LicenseTier::Pro, expiry, "CUST_001", 3, 25, &sk);
        let result = validate_license_key(&key, &vk);
        assert_eq!(result.tier, LicenseTier::Pro);
        assert_eq!(result.customer_id.as_deref(), Some("CUST_001"));
        assert_eq!(result.max_nodes, Some(3));
        assert_eq!(result.max_endpoints, Some(25));
    }

    #[test]
    fn test_generate_and_validate_all_tiers() {
        let (sk, vk) = test_keypair();
        let expiry = future_expiry();
        for tier in [
            LicenseTier::Community,
            LicenseTier::Pro,
            LicenseTier::Business,
            LicenseTier::Enterprise,
        ] {
            let key = generate_license_key(tier, expiry, "TEST", 10, 100, &sk);
            let result = validate_license_key(&key, &vk);
            assert_eq!(result.tier, tier);
        }
    }

    #[test]
    fn test_expired_key_returns_community() {
        let (sk, vk) = test_keypair();
        let key = generate_license_key(LicenseTier::Enterprise, 1_000_000, "CUST", 10, 100, &sk);
        let result = validate_license_key(&key, &vk);
        assert_eq!(result.tier, LicenseTier::Community);
        assert_eq!(result.reason, "license key expired");
    }

    #[test]
    fn test_wrong_key_returns_community() {
        let (sk, _vk) = test_keypair();
        let expiry = future_expiry();
        let key = generate_license_key(LicenseTier::Enterprise, expiry, "CUST", 10, 100, &sk);

        // Verify against a different public key
        let other_seed: [u8; 32] = [0xFFu8; 32];
        let other_vk = SigningKey::from_bytes(&other_seed).verifying_key();
        let result = validate_license_key(&key, &other_vk);
        assert_eq!(result.tier, LicenseTier::Community);
        assert_eq!(result.reason, "invalid license key");
    }

    #[test]
    fn test_tampered_tier_returns_community() {
        let (sk, vk) = test_keypair();
        let expiry = future_expiry();
        let key = generate_license_key(LicenseTier::Community, expiry, "CUST", 3, 25, &sk);
        // Tamper the tier segment — signature will not match.
        let tampered = key.replace("VLV-COM-", "VLV-ENT-");
        let result = validate_license_key(&tampered, &vk);
        assert_eq!(result.tier, LicenseTier::Community);
        assert_eq!(result.reason, "invalid license key");
    }

    #[test]
    fn test_tampered_nodes_returns_community() {
        let (sk, vk) = test_keypair();
        let expiry = future_expiry();
        let key = generate_license_key(LicenseTier::Enterprise, expiry, "CUST", 3, 25, &sk);
        // Tamper max_nodes from 3 to 999 — signature will not match.
        let tampered = key.replace("-3-25.", "-999-25.");
        let result = validate_license_key(&tampered, &vk);
        assert_eq!(result.tier, LicenseTier::Community);
    }

    #[test]
    fn test_tampered_customer_id_returns_community() {
        let (sk, vk) = test_keypair();
        let expiry = future_expiry();
        let key = generate_license_key(LicenseTier::Enterprise, expiry, "LEGIT", 3, 25, &sk);
        let tampered = key.replace("-LEGIT-", "-PIRATE-");
        let result = validate_license_key(&tampered, &vk);
        assert_eq!(result.tier, LicenseTier::Community);
    }

    #[test]
    fn test_malformed_key_returns_community() {
        let (_sk, vk) = test_keypair();
        for key in [
            "",
            "not-a-key",
            "VLV",
            "VLV-PRO",
            "VLV-PRO-123",
            "VLV-UNKNOWN-123-abc.deadbeef",
            "XXX-PRO-123-CID-3-25.deadbeef",
            // Old v1 format (no '.' separator)
            "VLV-PRO-123-abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        ] {
            let result = validate_license_key(key, &vk);
            assert_eq!(result.tier, LicenseTier::Community, "key={key:?}");
        }
    }

    #[test]
    fn test_customer_id_validation() {
        let (sk, vk) = test_keypair();
        let expiry = future_expiry();

        // Empty customer ID — manually craft since generate_license_key won't
        let payload = format!("VLV-ENT-{expiry}--3-25");
        let sig = {
            use ed25519_dalek::Signer;
            sk.sign(payload.as_bytes())
        };
        let key = format!("{}.{}", payload, hex::encode(sig.to_bytes()));
        let result = validate_license_key(&key, &vk);
        assert_eq!(result.tier, LicenseTier::Community);

        // Customer ID with special chars
        let payload = format!("VLV-ENT-{expiry}-CUST@EVIL-3-25");
        let sig = {
            use ed25519_dalek::Signer;
            sk.sign(payload.as_bytes())
        };
        let key = format!("{}.{}", payload, hex::encode(sig.to_bytes()));
        let result = validate_license_key(&key, &vk);
        assert_eq!(result.tier, LicenseTier::Community);
    }

    #[test]
    fn test_tier_limits() {
        assert_eq!(LicenseTier::Community.limits().max_mcp_servers, Some(5));
        assert_eq!(LicenseTier::Pro.limits().max_mcp_servers, Some(25));
        assert_eq!(LicenseTier::Business.limits().max_mcp_servers, Some(100));
        assert_eq!(LicenseTier::Enterprise.limits().max_mcp_servers, None);
    }

    #[test]
    fn test_tier_serde_roundtrip() {
        for tier in [
            LicenseTier::Community,
            LicenseTier::Pro,
            LicenseTier::Business,
            LicenseTier::Enterprise,
        ] {
            let json = serde_json::to_string(&tier).expect("serialize");
            let parsed: LicenseTier = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed, tier);
        }
    }

    #[test]
    fn test_tier_override_takes_precedence() {
        let config = LicensingConfig {
            license_key: Some("invalid".to_string()),
            tier_override: Some(LicenseTier::Enterprise),
        };
        let result = config.resolve();
        assert_eq!(result.tier, LicenseTier::Enterprise);
    }

    #[test]
    fn test_no_key_returns_community() {
        let config = LicensingConfig::default();
        let result = config.resolve();
        assert_eq!(result.tier, LicenseTier::Community);
    }

    #[test]
    fn test_ed25519_signature_is_deterministic() {
        let (sk, _vk) = test_keypair();
        let key1 = generate_license_key(LicenseTier::Pro, 9999999999, "C1", 3, 25, &sk);
        let key2 = generate_license_key(LicenseTier::Pro, 9999999999, "C1", 3, 25, &sk);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_deployment_limits_in_validation() {
        let (sk, vk) = test_keypair();
        let expiry = future_expiry();
        let key = generate_license_key(LicenseTier::Business, expiry, "ACME_CORP", 5, 50, &sk);
        let result = validate_license_key(&key, &vk);
        assert_eq!(result.tier, LicenseTier::Business);
        assert_eq!(result.max_nodes, Some(5));
        assert_eq!(result.max_endpoints, Some(50));
        assert_eq!(result.customer_id.as_deref(), Some("ACME_CORP"));
    }

    #[test]
    fn test_v1_hmac_key_fails_gracefully() {
        let (_sk, vk) = test_keypair();
        // Old v1 format: VLV-{TIER}-{EXPIRY}-{HMAC_HEX} (no '.' separator)
        let old_key =
            "VLV-ENT-1740000000-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let result = validate_license_key(old_key, &vk);
        assert_eq!(result.tier, LicenseTier::Community);
        assert_eq!(result.reason, "invalid license key");
    }

    // =============================================================================
    // LicensingConfig::validate() tests
    // =============================================================================

    #[test]
    fn test_licensing_config_validate_ok() {
        let config = LicensingConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_licensing_config_validate_ok_with_key() {
        let config = LicensingConfig {
            license_key: Some("VLV-PRO-12345-CID-3-25.abcdef".to_string()),
            tier_override: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_licensing_config_validate_oversized_key() {
        let config = LicensingConfig {
            license_key: Some("K".repeat(MAX_LICENSE_KEY_LEN + 1)),
            tier_override: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("exceeds max"));
    }

    #[test]
    fn test_licensing_config_validate_null_byte_in_key() {
        let config = LicensingConfig {
            license_key: Some("VLV-PRO-123\x00-abc".to_string()),
            tier_override: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("control characters"));
    }

    #[test]
    fn test_licensing_config_validate_newline_in_key() {
        let config = LicensingConfig {
            license_key: Some("VLV-PRO-123\n-abc".to_string()),
            tier_override: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("control characters"));
    }

    #[test]
    fn test_licensing_config_validate_tab_in_key() {
        let config = LicensingConfig {
            license_key: Some("VLV\t-PRO-123-abc".to_string()),
            tier_override: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("control characters"));
    }

    #[test]
    fn test_licensing_config_validate_c1_control_in_key() {
        let config = LicensingConfig {
            license_key: Some("VLV-PRO-\u{0085}-abc".to_string()),
            tier_override: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("control characters"));
    }

    #[test]
    fn test_licensing_config_deny_unknown_fields() {
        let json = r#"{"license_key": "test", "unknown_field": true}"#;
        let result: Result<LicensingConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_oversized_key_returns_community() {
        let (_sk, vk) = test_keypair();
        let key = "K".repeat(MAX_LICENSE_KEY_LEN + 1);
        let result = validate_license_key(&key, &vk);
        assert_eq!(result.tier, LicenseTier::Community);
    }

    #[test]
    fn test_load_verifying_key_wrong_length() {
        // Temporarily set env var with wrong length
        std::env::set_var("VELLAVETO_LICENSE_PUBLIC_KEY", "aabbcc");
        let result = load_verifying_key();
        assert!(result.is_none());
        std::env::remove_var("VELLAVETO_LICENSE_PUBLIC_KEY");
    }

    #[test]
    fn test_load_verifying_key_non_hex() {
        std::env::set_var(
            "VELLAVETO_LICENSE_PUBLIC_KEY",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        );
        let result = load_verifying_key();
        assert!(result.is_none());
        std::env::remove_var("VELLAVETO_LICENSE_PUBLIC_KEY");
    }

    #[test]
    fn test_load_verifying_key_valid() {
        let (_sk, vk) = test_keypair();
        let hex_key = hex::encode(vk.as_bytes());
        std::env::set_var("VELLAVETO_LICENSE_PUBLIC_KEY", &hex_key);
        let result = load_verifying_key();
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_bytes(), vk.as_bytes());
        std::env::remove_var("VELLAVETO_LICENSE_PUBLIC_KEY");
    }

    #[test]
    fn test_signature_truncation_rejected() {
        let (sk, vk) = test_keypair();
        let expiry = future_expiry();
        let key = generate_license_key(LicenseTier::Pro, expiry, "CUST", 3, 25, &sk);
        // Truncate the signature
        let truncated = &key[..key.len() - 10];
        let result = validate_license_key(truncated, &vk);
        assert_eq!(result.tier, LicenseTier::Community);
    }

    #[test]
    fn test_zero_nodes_and_endpoints_valid() {
        let (sk, vk) = test_keypair();
        let expiry = future_expiry();
        let key = generate_license_key(LicenseTier::Community, expiry, "FREE_USER", 0, 0, &sk);
        let result = validate_license_key(&key, &vk);
        assert_eq!(result.tier, LicenseTier::Community);
        assert_eq!(result.max_nodes, Some(0));
        assert_eq!(result.max_endpoints, Some(0));
    }

    #[test]
    fn test_customer_id_max_length() {
        let (sk, vk) = test_keypair();
        let expiry = future_expiry();
        let cid = "A".repeat(MAX_CUSTOMER_ID_LEN);
        let key = generate_license_key(LicenseTier::Pro, expiry, &cid, 3, 25, &sk);
        let result = validate_license_key(&key, &vk);
        assert_eq!(result.tier, LicenseTier::Pro);

        // One char over max
        let cid_over = "A".repeat(MAX_CUSTOMER_ID_LEN + 1);
        let key = generate_license_key(LicenseTier::Pro, expiry, &cid_over, 3, 25, &sk);
        let result = validate_license_key(&key, &vk);
        assert_eq!(result.tier, LicenseTier::Community);
    }
}
