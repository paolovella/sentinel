// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! FIPS 140-3 Compliance Mode (Phase 23.3).
//!
//! When the `fips` feature is enabled, this module provides:
//! - ECDSA P-256 signing/verification as an alternative to Ed25519
//! - Algorithm validation that rejects non-FIPS algorithms
//! - FIPS mode flag for runtime enforcement
//!
//! # Feature Flag
//!
//! Requires the `fips` feature:
//! ```toml
//! vellaveto-mcp = { version = "2.2", features = ["fips"] }
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// FIPS 140-3 approved algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FipsAlgorithm {
    /// ECDSA with NIST P-256 curve.
    EcdsaP256,
    /// SHA-256 hash.
    Sha256,
    /// SHA-384 hash.
    Sha384,
    /// AES-256-GCM authenticated encryption.
    Aes256Gcm,
    /// HMAC-SHA-256 message authentication.
    HmacSha256,
}

impl FipsAlgorithm {
    /// Returns the algorithm name string.
    pub fn name(&self) -> &'static str {
        match self {
            FipsAlgorithm::EcdsaP256 => "ecdsa-p256",
            FipsAlgorithm::Sha256 => "sha256",
            FipsAlgorithm::Sha384 => "sha384",
            FipsAlgorithm::Aes256Gcm => "aes-256-gcm",
            FipsAlgorithm::HmacSha256 => "hmac-sha256",
        }
    }
}

/// Non-FIPS algorithms that must be rejected in FIPS mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonFipsAlgorithm {
    /// Ed25519 signatures (not NIST-approved).
    Ed25519,
    /// ChaCha20-Poly1305 (not NIST-approved).
    ChaCha20Poly1305,
    /// BLAKE2 hash (not NIST-approved).
    Blake2,
}

/// Errors from FIPS mode operations.
#[derive(Error, Debug)]
pub enum FipsError {
    #[error("Algorithm '{0}' is not FIPS 140-3 approved")]
    NonFipsAlgorithm(String),
    #[error("FIPS mode is not enabled")]
    NotEnabled,
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
}

/// FIPS 140-3 compliance mode controller.
pub struct FipsMode {
    enabled: bool,
}

/// Known algorithm names for validation.
const FIPS_APPROVED_ALGORITHMS: &[&str] = &[
    "ecdsa-p256",
    "ecdsa_p256",
    "sha256",
    "sha-256",
    "sha384",
    "sha-384",
    "sha512",
    "sha-512",
    "aes-256-gcm",
    "aes256gcm",
    "hmac-sha256",
    "hmac-sha-256",
    "rsa-pss",
];

const NON_FIPS_ALGORITHMS: &[&str] = &[
    "ed25519",
    "chacha20poly1305",
    "chacha20-poly1305",
    "blake2",
    "blake2b",
    "blake2s",
    "curve25519",
    "x25519",
];

impl FipsMode {
    /// Create a new FIPS mode controller.
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Check if FIPS mode is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Validate that an algorithm is FIPS 140-3 approved.
    ///
    /// When FIPS mode is enabled, rejects non-FIPS algorithms.
    /// When disabled, all algorithms are accepted.
    pub fn validate_algorithm(&self, algorithm: &str) -> Result<(), FipsError> {
        if !self.enabled {
            return Ok(());
        }

        // SECURITY (FIND-R188-003): Validate input before processing to prevent
        // oversized allocation in to_lowercase() and control char injection.
        const MAX_ALGORITHM_NAME_LEN: usize = 64;
        if algorithm.len() > MAX_ALGORITHM_NAME_LEN {
            return Err(FipsError::NonFipsAlgorithm(format!(
                "<algorithm name too long: {} bytes>",
                algorithm.len()
            )));
        }
        if vellaveto_types::has_dangerous_chars(algorithm) {
            return Err(FipsError::NonFipsAlgorithm(
                "<algorithm name contains control characters>".to_string(),
            ));
        }

        let alg_lower = algorithm.to_lowercase();

        // Check explicit non-FIPS list first
        if NON_FIPS_ALGORITHMS.contains(&alg_lower.as_str()) {
            return Err(FipsError::NonFipsAlgorithm(algorithm.to_string()));
        }

        // Check if it's in the approved list
        if FIPS_APPROVED_ALGORITHMS.contains(&alg_lower.as_str()) {
            return Ok(());
        }

        // Unknown algorithm — fail-closed in FIPS mode
        Err(FipsError::NonFipsAlgorithm(algorithm.to_string()))
    }

    /// Returns the list of allowed signature algorithms.
    pub fn allowed_signature_algorithms(&self) -> Vec<&'static str> {
        if self.enabled {
            vec!["ecdsa-p256", "rsa-pss"]
        } else {
            vec!["ed25519", "ecdsa-p256", "rsa-pss"]
        }
    }

    /// Returns the list of allowed hash algorithms.
    pub fn allowed_hash_algorithms(&self) -> Vec<&'static str> {
        if self.enabled {
            vec!["sha256", "sha384", "sha512"]
        } else {
            vec!["sha256", "sha384", "sha512", "blake2"]
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// ECDSA P-256 Operations (feature-gated)
// ═══════════════════════════════════════════════════════════════════

/// Sign data using ECDSA P-256.
///
/// Requires the `fips` feature.
#[cfg(feature = "fips")]
pub fn sign_ecdsa_p256(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, FipsError> {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    // p256 0.14 removed the `&[u8]` conversion into the field-element array,
    // so the length is now checked explicitly instead of failing inside
    // `from_bytes`. A P-256 scalar is always 32 bytes.
    let key_bytes: &[u8; 32] = private_key.try_into().map_err(|_| {
        FipsError::InvalidKey(format!(
            "Invalid P-256 private key: expected 32 bytes, got {}",
            private_key.len()
        ))
    })?;

    let signing_key = SigningKey::from_bytes(key_bytes.into())
        .map_err(|e| FipsError::InvalidKey(format!("Invalid P-256 private key: {}", e)))?;

    let signature: Signature = signing_key.sign(data);
    Ok(signature.to_der().as_bytes().to_vec())
}

/// Verify an ECDSA P-256 signature.
///
/// Requires the `fips` feature.
#[cfg(feature = "fips")]
pub fn verify_ecdsa_p256(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, FipsError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    // p256 0.14 removed `p256::EncodedPoint` from the crate root and dropped
    // `VerifyingKey::from_encoded_point`. `from_sec1_bytes` parses the same
    // SEC1 encoding directly, so accepted public-key inputs are unchanged:
    // both compressed (33-byte) and uncompressed (65-byte) forms still work.
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| FipsError::InvalidKey(format!("Invalid P-256 public key: {}", e)))?;

    let sig = Signature::from_der(signature)
        .map_err(|e| FipsError::VerificationFailed(format!("Invalid DER signature: {}", e)))?;

    match verifying_key.verify(data, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Stub for when `fips` feature is not enabled.
#[cfg(not(feature = "fips"))]
pub fn sign_ecdsa_p256(_data: &[u8], _private_key: &[u8]) -> Result<Vec<u8>, FipsError> {
    Err(FipsError::NotEnabled)
}

/// Stub for when `fips` feature is not enabled.
#[cfg(not(feature = "fips"))]
pub fn verify_ecdsa_p256(
    _data: &[u8],
    _signature: &[u8],
    _public_key: &[u8],
) -> Result<bool, FipsError> {
    Err(FipsError::NotEnabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_mode_rejects_ed25519() {
        let fips = FipsMode::new(true);
        let result = fips.validate_algorithm("ed25519");
        assert!(matches!(result, Err(FipsError::NonFipsAlgorithm(_))));
    }

    #[test]
    fn test_fips_mode_accepts_ecdsa_p256() {
        let fips = FipsMode::new(true);
        assert!(fips.validate_algorithm("ecdsa-p256").is_ok());
        assert!(fips.validate_algorithm("ecdsa_p256").is_ok());
    }

    #[test]
    fn test_fips_mode_accepts_sha256() {
        let fips = FipsMode::new(true);
        assert!(fips.validate_algorithm("sha256").is_ok());
        assert!(fips.validate_algorithm("sha-256").is_ok());
    }

    #[test]
    fn test_fips_mode_rejects_chacha20() {
        let fips = FipsMode::new(true);
        let result = fips.validate_algorithm("chacha20poly1305");
        assert!(matches!(result, Err(FipsError::NonFipsAlgorithm(_))));
    }

    #[test]
    fn test_fips_mode_rejects_blake2() {
        let fips = FipsMode::new(true);
        let result = fips.validate_algorithm("blake2");
        assert!(matches!(result, Err(FipsError::NonFipsAlgorithm(_))));
    }

    #[test]
    fn test_disabled_fips_allows_everything() {
        let fips = FipsMode::new(false);
        assert!(fips.validate_algorithm("ed25519").is_ok());
        assert!(fips.validate_algorithm("chacha20poly1305").is_ok());
        assert!(fips.validate_algorithm("blake2").is_ok());
        assert!(fips.validate_algorithm("anything").is_ok());
    }

    #[test]
    fn test_fips_mode_rejects_unknown_algorithm() {
        let fips = FipsMode::new(true);
        let result = fips.validate_algorithm("totally_made_up");
        assert!(matches!(result, Err(FipsError::NonFipsAlgorithm(_))));
    }

    #[test]
    fn test_allowed_signature_algorithms_fips() {
        let fips = FipsMode::new(true);
        let algs = fips.allowed_signature_algorithms();
        assert!(algs.contains(&"ecdsa-p256"));
        assert!(!algs.contains(&"ed25519"));
    }

    #[test]
    fn test_allowed_signature_algorithms_non_fips() {
        let fips = FipsMode::new(false);
        let algs = fips.allowed_signature_algorithms();
        assert!(algs.contains(&"ed25519"));
        assert!(algs.contains(&"ecdsa-p256"));
    }

    #[test]
    fn test_allowed_hash_algorithms() {
        let fips = FipsMode::new(true);
        let algs = fips.allowed_hash_algorithms();
        assert!(algs.contains(&"sha256"));
        assert!(!algs.contains(&"blake2"));
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_ecdsa_p256_not_enabled() {
        let result = sign_ecdsa_p256(b"test", &[0; 32]);
        assert!(matches!(result, Err(FipsError::NotEnabled)));

        let result = verify_ecdsa_p256(b"test", &[0; 64], &[0; 33]);
        assert!(matches!(result, Err(FipsError::NotEnabled)));
    }

    /// Round-trip exercise of real P-256 signing and verification.
    ///
    /// Only the `NotEnabled` stub path was covered before, so the actual
    /// cryptography shipped under the `fips` feature had no test at all.
    #[cfg(feature = "fips")]
    #[test]
    fn test_ecdsa_p256_sign_verify_roundtrip() {
        use p256::ecdsa::SigningKey;

        let private_key = [0x11u8; 32];
        let data = b"vellaveto fips p256 attestation v1";

        let signature = sign_ecdsa_p256(data, &private_key).expect("signing must succeed");

        let key = SigningKey::from_bytes((&private_key).into()).expect("valid key");
        let public_point = key.verifying_key().to_sec1_point(false);

        assert!(
            verify_ecdsa_p256(data, &signature, public_point.as_bytes()).expect("verify must run"),
            "a signature must verify against its own public key"
        );

        assert!(
            !verify_ecdsa_p256(b"tampered", &signature, public_point.as_bytes())
                .expect("verify must run"),
            "a signature must not verify against different data"
        );
    }

    /// Known-answer test pinning the DER-encoded ECDSA P-256 signature.
    ///
    /// ECDSA signatures here are deterministic (RFC 6979), so a fixed key and
    /// message must always produce identical DER bytes. Signatures are a wire
    /// format consumed by verifiers outside this process, so a change in the
    /// encoding would break interoperability without failing a round-trip
    /// test — which signs and verifies with the same implementation and would
    /// pass regardless.
    ///
    /// This vector was generated under p256 0.13 and must continue to hold
    /// across dependency upgrades.
    #[cfg(feature = "fips")]
    #[test]
    fn test_ecdsa_p256_known_answer_vector() {
        let private_key = [0x11u8; 32];
        let data = b"vellaveto fips p256 attestation v1";

        // Generated with p256 0.13, RFC 6979 deterministic nonce.
        let expected_hex = "30460221008b4d9c4ffb80a3b85156e756ac5fdd53b33c4c519b57966d\
                            99a822ec186a15be022100f7f0cbfd98924f9a1c1f3da56f3f81b0681d\
                            79284f5ab71f63d1dbba7b5f2b6f";

        let signature = sign_ecdsa_p256(data, &private_key).expect("signing must succeed");
        let actual_hex: String = signature.iter().map(|b| format!("{b:02x}")).collect();

        assert_eq!(
            actual_hex, expected_hex,
            "ECDSA P-256 DER signature changed — external verifiers would reject \
             signatures produced by this build"
        );
        assert_eq!(signature.len(), 72, "unexpected DER signature length");
    }

    #[test]
    fn test_fips_algorithm_names() {
        assert_eq!(FipsAlgorithm::EcdsaP256.name(), "ecdsa-p256");
        assert_eq!(FipsAlgorithm::Sha256.name(), "sha256");
        assert_eq!(FipsAlgorithm::Sha384.name(), "sha384");
        assert_eq!(FipsAlgorithm::Aes256Gcm.name(), "aes-256-gcm");
        assert_eq!(FipsAlgorithm::HmacSha256.name(), "hmac-sha256");
    }

    // SECURITY (FIND-R188-003): Reject oversized and control-char algorithm names
    #[test]
    fn test_fips_rejects_oversized_algorithm_name() {
        let fips = FipsMode::new(true);
        let long_name = "a".repeat(100);
        let err = fips.validate_algorithm(&long_name).unwrap_err();
        assert!(err.to_string().contains("too long"), "error: {err}");
    }

    #[test]
    fn test_fips_rejects_control_chars_in_algorithm_name() {
        let fips = FipsMode::new(true);
        let err = fips.validate_algorithm("sha256\x00injected").unwrap_err();
        assert!(
            err.to_string().contains("control characters"),
            "error: {err}"
        );
    }
}
