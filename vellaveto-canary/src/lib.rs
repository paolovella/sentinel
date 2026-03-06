// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! Warrant canary creation and cryptographic verification.
//!
//! A warrant canary is a cryptographically signed statement that asserts
//! no government surveillance orders have been received. When the canary
//! expires or is not renewed, users can infer that a gag order may have
//! been issued.

use chrono::{NaiveDate, Utc};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum statement length to prevent abuse.
const MAX_STATEMENT_LENGTH: usize = 4096;

/// Maximum signing key hex length (Ed25519 = 64 hex chars).
const MAX_KEY_HEX_LENGTH: usize = 128;

/// Canary version — increment on format changes.
const CANARY_VERSION: u8 = 1;

/// A cryptographically signed warrant canary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WarrantCanary {
    /// Format version for forward compatibility.
    pub version: u8,
    /// Date the canary was signed (YYYY-MM-DD).
    pub signed_date: String,
    /// Date the canary expires (YYYY-MM-DD).
    pub expires_date: String,
    /// The canary statement text.
    pub statement: String,
    /// Ed25519 signature over the canonical payload (hex-encoded).
    pub signature: String,
    /// Ed25519 verifying key (hex-encoded).
    pub verifying_key: String,
}

/// Result of canary verification.
#[derive(Debug, Clone, PartialEq)]
pub struct CanaryVerification {
    /// Whether the signature is cryptographically valid.
    pub signature_valid: bool,
    /// Whether the canary has expired.
    pub expired: bool,
    /// Days until expiration (negative if expired).
    pub days_remaining: i64,
}

/// Check a string for dangerous characters (control chars, Unicode format chars).
fn has_dangerous_chars(s: &str) -> bool {
    s.chars().any(|c| {
        c.is_control()
            || matches!(c,
                '\u{200B}'..='\u{200F}' // zero-width, bidi
                | '\u{202A}'..='\u{202E}' // bidi overrides
                | '\u{2060}'..='\u{2064}' // invisible operators
                | '\u{FEFF}' // BOM
                | '\u{FE00}'..='\u{FE0F}' // variation selectors
            )
    })
}

/// Build the canonical payload for signing/verification.
fn canonical_payload(
    version: u8,
    signed_date: &str,
    expires_date: &str,
    statement: &str,
) -> Vec<u8> {
    let obj = serde_json::json!({
        "version": version,
        "signed_date": signed_date,
        "expires_date": expires_date,
        "statement": statement,
    });
    let canonical = serde_json_canonicalizer::to_string(&obj)
        .unwrap_or_else(|_| serde_json::to_string(&obj).unwrap_or_default());
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher.finalize().to_vec()
}

/// Create a new warrant canary.
///
/// # Arguments
/// - `statement`: The canary statement text (max 4096 chars).
/// - `valid_days`: Number of days the canary is valid from today.
/// - `signing_key_hex`: Ed25519 signing key as hex string.
///
/// # Errors
/// Returns an error string if the statement is too long, contains dangerous
/// characters, or the signing key is invalid.
pub fn create_canary(
    statement: &str,
    valid_days: u64,
    signing_key_hex: &str,
) -> Result<WarrantCanary, String> {
    // Validate statement
    if statement.is_empty() {
        return Err("statement must not be empty".to_string());
    }
    if statement.len() > MAX_STATEMENT_LENGTH {
        return Err(format!(
            "statement exceeds max length ({} > {})",
            statement.len(),
            MAX_STATEMENT_LENGTH
        ));
    }
    if has_dangerous_chars(statement) {
        return Err("statement contains dangerous characters".to_string());
    }

    // Validate signing key
    if signing_key_hex.len() > MAX_KEY_HEX_LENGTH {
        return Err("signing key hex too long".to_string());
    }
    let key_bytes =
        hex::decode(signing_key_hex).map_err(|e| format!("invalid signing key hex: {e}"))?;
    if key_bytes.len() != 32 {
        return Err(format!(
            "signing key must be 32 bytes, got {}",
            key_bytes.len()
        ));
    }
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "signing key must be exactly 32 bytes".to_string())?;
    let signing_key = SigningKey::from_bytes(&key_array);
    let verifying_key = signing_key.verifying_key();

    // Compute dates
    let now = Utc::now().date_naive();
    let signed_date = now.format("%Y-%m-%d").to_string();
    let expires_date = now
        .checked_add_days(chrono::Days::new(valid_days))
        .ok_or_else(|| "valid_days overflow".to_string())?
        .format("%Y-%m-%d")
        .to_string();

    // Sign canonical payload
    let payload = canonical_payload(CANARY_VERSION, &signed_date, &expires_date, statement);
    let signature = signing_key.sign(&payload);

    Ok(WarrantCanary {
        version: CANARY_VERSION,
        signed_date,
        expires_date,
        statement: statement.to_string(),
        signature: hex::encode(signature.to_bytes()),
        verifying_key: hex::encode(verifying_key.to_bytes()),
    })
}

/// Verify a warrant canary's signature and expiration status.
///
/// # Errors
/// Returns an error string if the canary data is malformed (invalid hex,
/// wrong key size, unparseable dates).
pub fn verify_canary(canary: &WarrantCanary) -> Result<CanaryVerification, String> {
    // Validate statement bounds
    if canary.statement.len() > MAX_STATEMENT_LENGTH {
        return Err(format!(
            "statement exceeds max length ({} > {})",
            canary.statement.len(),
            MAX_STATEMENT_LENGTH
        ));
    }
    if has_dangerous_chars(&canary.statement) {
        return Err("statement contains dangerous characters".to_string());
    }

    // Parse verifying key
    let vk_bytes = hex::decode(&canary.verifying_key)
        .map_err(|e| format!("invalid verifying key hex: {e}"))?;
    if vk_bytes.len() != 32 {
        return Err(format!(
            "verifying key must be 32 bytes, got {}",
            vk_bytes.len()
        ));
    }
    let vk_array: [u8; 32] = vk_bytes
        .try_into()
        .map_err(|_| "verifying key conversion failed".to_string())?;
    let verifying_key =
        VerifyingKey::from_bytes(&vk_array).map_err(|e| format!("invalid verifying key: {e}"))?;

    // Parse signature
    let sig_bytes =
        hex::decode(&canary.signature).map_err(|e| format!("invalid signature hex: {e}"))?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        ));
    }
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature conversion failed".to_string())?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    // Verify signature
    let payload = canonical_payload(
        canary.version,
        &canary.signed_date,
        &canary.expires_date,
        &canary.statement,
    );
    let signature_valid = verifying_key.verify(&payload, &signature).is_ok();

    // Check expiration
    let expires = NaiveDate::parse_from_str(&canary.expires_date, "%Y-%m-%d")
        .map_err(|e| format!("invalid expires_date: {e}"))?;
    let today = Utc::now().date_naive();
    let days_remaining = (expires - today).num_days();
    let expired = days_remaining < 0;

    Ok(CanaryVerification {
        signature_valid,
        expired,
        days_remaining,
    })
}

#[cfg(test)]
mod tests;
