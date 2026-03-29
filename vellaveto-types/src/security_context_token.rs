// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! SecurityContextToken — HMAC-SHA256 signed attestation binding security
//! scan results to response content.
//!
//! The proxy computes SHA-256 of the response body, records scan results
//! (injection score, DLP findings, trust tier), and signs everything with
//! HMAC-SHA256. Downstream consumers verify the signature to confirm the
//! proxy genuinely assessed this exact content.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Maximum length for the token signature field.
const MAX_SIGNATURE_LEN: usize = 128;
/// Maximum length for the content hash field.
const MAX_CONTENT_HASH_LEN: usize = 128;

/// Signed attestation that the proxy scanned a specific response.
///
/// Attached to `result._meta.vellaveto_attestation` on every proxied response.
/// Consumers verify with their SDK's `verify_attestation()` method using the
/// shared HMAC secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityContextToken {
    /// Token format version (currently "1").
    pub version: u8,
    /// Unix timestamp (seconds) when the attestation was created.
    pub timestamp: u64,
    /// SHA-256 hex digest of the canonicalized response content.
    /// Covers `result` (or `error`) — the entire response payload.
    pub content_hash: String,
    /// Whether injection scanning passed (no findings).
    pub injection_clean: bool,
    /// Whether DLP scanning passed (no secret findings).
    pub dlp_clean: bool,
    /// Whether output schema validation passed.
    pub schema_valid: bool,
    /// Trust tier assigned by the proxy ("Verified", "Trusted", "Untrusted", etc.)
    pub trust_tier: String,
    /// Number of security scan passes applied to this content.
    pub scan_passes: u8,
    /// HMAC-SHA256 hex signature over the canonicalized token fields.
    /// Computed as: HMAC-SHA256(key, "v{version}:{timestamp}:{content_hash}:{injection_clean}:{dlp_clean}:{schema_valid}:{trust_tier}:{scan_passes}")
    pub signature: String,
}

impl SecurityContextToken {
    /// The canonical string representation used for HMAC signing.
    pub fn signing_content(&self) -> String {
        format!(
            "v{}:{}:{}:{}:{}:{}:{}:{}",
            self.version,
            self.timestamp,
            self.content_hash,
            self.injection_clean,
            self.dlp_clean,
            self.schema_valid,
            self.trust_tier,
            self.scan_passes,
        )
    }

    /// Validate field bounds and format.
    pub fn validate(&self) -> Result<(), String> {
        if self.version == 0 {
            return Err("version must be >= 1".to_string());
        }
        if self.content_hash.len() > MAX_CONTENT_HASH_LEN {
            return Err(format!(
                "content_hash too long ({} > {})",
                self.content_hash.len(),
                MAX_CONTENT_HASH_LEN
            ));
        }
        if self.signature.len() > MAX_SIGNATURE_LEN {
            return Err(format!(
                "signature too long ({} > {})",
                self.signature.len(),
                MAX_SIGNATURE_LEN
            ));
        }
        if crate::has_dangerous_chars(&self.content_hash) {
            return Err("content_hash contains dangerous characters".to_string());
        }
        if crate::has_dangerous_chars(&self.trust_tier) {
            return Err("trust_tier contains dangerous characters".to_string());
        }
        if crate::has_dangerous_chars(&self.signature) {
            return Err("signature contains dangerous characters".to_string());
        }
        Ok(())
    }
}

/// Create a SecurityContextToken by signing the given scan results
/// and content hash with the provided HMAC key.
pub fn mint_attestation(
    content_hash: &str,
    injection_clean: bool,
    dlp_clean: bool,
    schema_valid: bool,
    trust_tier: &str,
    scan_passes: u8,
    hmac_key: &[u8],
) -> Result<SecurityContextToken, String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut token = SecurityContextToken {
        version: 1,
        timestamp,
        content_hash: content_hash.to_string(),
        injection_clean,
        dlp_clean,
        schema_valid,
        trust_tier: trust_tier.to_string(),
        scan_passes,
        signature: String::new(),
    };

    let signing_content = token.signing_content();
    let mut mac =
        HmacSha256::new_from_slice(hmac_key).map_err(|e| format!("HMAC key error: {}", e))?;
    mac.update(signing_content.as_bytes());
    let result = mac.finalize();
    token.signature = hex::encode(result.into_bytes());

    Ok(token)
}

/// Verify a SecurityContextToken's HMAC signature.
///
/// Returns Ok(()) if the signature is valid, Err with reason otherwise.
pub fn verify_attestation(token: &SecurityContextToken, hmac_key: &[u8]) -> Result<(), String> {
    let signing_content = token.signing_content();
    let mut mac =
        HmacSha256::new_from_slice(hmac_key).map_err(|e| format!("HMAC key error: {}", e))?;
    mac.update(signing_content.as_bytes());

    let expected_sig =
        hex::decode(&token.signature).map_err(|_| "Invalid signature hex encoding".to_string())?;

    mac.verify_slice(&expected_sig)
        .map_err(|_| "HMAC signature verification failed".to_string())
}

/// Compute SHA-256 hex digest of a JSON value's canonical representation.
pub fn hash_content(content: &serde_json::Value) -> String {
    use sha2::Digest;
    let canonical = match serde_json::to_string(content) {
        Ok(s) => s,
        Err(_) => return "SERIALIZATION_FAILED".to_string(),
    };
    let hash = Sha256::digest(canonical.as_bytes());
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mint_and_verify_roundtrip() {
        let key = b"test-secret-key-for-attestation";
        let content_hash = hash_content(&serde_json::json!({"data": "hello"}));
        let token = mint_attestation(&content_hash, true, true, true, "Verified", 5, key).unwrap();
        assert_eq!(token.version, 1);
        assert!(token.timestamp > 0);
        assert!(verify_attestation(&token, key).is_ok());
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let key = b"correct-key";
        let wrong_key = b"wrong-key-here";
        let token = mint_attestation("abc123", true, true, true, "Verified", 5, key).unwrap();
        assert!(verify_attestation(&token, wrong_key).is_err());
    }

    #[test]
    fn test_verify_rejects_tampered_content_hash() {
        let key = b"test-key";
        let mut token = mint_attestation("abc123", true, true, true, "Verified", 5, key).unwrap();
        token.content_hash = "tampered".to_string();
        assert!(verify_attestation(&token, key).is_err());
    }

    #[test]
    fn test_verify_rejects_tampered_injection_clean() {
        let key = b"test-key";
        let mut token = mint_attestation("abc123", false, true, true, "Untrusted", 5, key).unwrap();
        token.injection_clean = true; // Attacker flips to true
        assert!(verify_attestation(&token, key).is_err());
    }

    #[test]
    fn test_hash_content_deterministic() {
        let val = serde_json::json!({"key": "value", "num": 42});
        assert_eq!(hash_content(&val), hash_content(&val));
    }

    #[test]
    fn test_validate_rejects_dangerous_chars() {
        let mut token = SecurityContextToken {
            version: 1,
            timestamp: 1000,
            content_hash: "abc\x00def".to_string(),
            injection_clean: true,
            dlp_clean: true,
            schema_valid: true,
            trust_tier: "Verified".to_string(),
            scan_passes: 1,
            signature: "aabbcc".to_string(),
        };
        assert!(token.validate().is_err());
        token.content_hash = "clean".to_string();
        token.trust_tier = "Verified\u{200B}".to_string();
        assert!(token.validate().is_err());
    }

    #[test]
    fn test_signing_content_format() {
        let token = SecurityContextToken {
            version: 1,
            timestamp: 12345,
            content_hash: "deadbeef".to_string(),
            injection_clean: true,
            dlp_clean: false,
            schema_valid: true,
            trust_tier: "Trusted".to_string(),
            scan_passes: 3,
            signature: String::new(),
        };
        assert_eq!(
            token.signing_content(),
            "v1:12345:deadbeef:true:false:true:Trusted:3"
        );
    }
}
