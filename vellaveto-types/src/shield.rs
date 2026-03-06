// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Consumer Shield types — blind credentials, session unlinkability,
//! and credential vault management.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum length of a blind credential blob (4 KB).
pub const MAX_CREDENTIAL_LEN: usize = 4096;

/// Maximum length of a blind signature blob (4 KB).
pub const MAX_SIGNATURE_LEN: usize = 4096;

/// Maximum length of a provider key ID (256 bytes).
pub const MAX_PROVIDER_KEY_ID_LEN: usize = 256;

/// Maximum credential pool size.
pub const MAX_CREDENTIAL_POOL_SIZE: usize = 10_000;

/// Maximum credential epoch value (prevent overflow in rotation arithmetic).
pub const MAX_CREDENTIAL_EPOCH: u64 = u64::MAX / 2;

/// Type of credential, determining access tier without revealing identity.
///
/// Each tier grants different rate limits / capabilities, but the provider
/// cannot determine *which* subscriber holds the credential.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    /// Basic subscriber access.
    #[default]
    Subscriber,
    /// Premium subscriber with higher rate limits (no identity leak).
    PremiumSubscriber,
    /// Programmatic / API access credential.
    ApiAccess,
}

impl fmt::Debug for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialType::Subscriber => write!(f, "subscriber"),
            CredentialType::PremiumSubscriber => write!(f, "premium_subscriber"),
            CredentialType::ApiAccess => write!(f, "api_access"),
        }
    }
}

impl fmt::Display for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// A blind credential issued via RSA blind signatures (RFC 9474).
///
/// The credential proves the holder is a valid subscriber WITHOUT revealing
/// which subscriber they are. The provider signs a blinded nonce; the user
/// unblinds it. The resulting credential is unlinkable to the blinding step.
///
/// # Security Properties
/// - Provider learns: "this is a valid subscriber"
/// - Provider does NOT learn: "this is subscriber #12345"
/// - Two presentations of different credentials are unlinkable
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BlindCredential {
    /// The unblinded signed nonce (credential material).
    pub credential: Vec<u8>,
    /// The provider's blind signature over the credential.
    pub signature: Vec<u8>,
    /// Which provider key signed this credential (for key rotation).
    pub provider_key_id: String,
    /// Rotation epoch (NOT a timestamp — avoids timing correlation).
    /// Credentials from the same epoch are interchangeable.
    pub issued_epoch: u64,
    /// The access tier this credential grants.
    pub credential_type: CredentialType,
}

impl BlindCredential {
    /// Validate the credential fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.credential.is_empty() {
            return Err("credential must not be empty".to_string());
        }
        if self.credential.len() > MAX_CREDENTIAL_LEN {
            return Err(format!(
                "credential length {} exceeds maximum {}",
                self.credential.len(),
                MAX_CREDENTIAL_LEN
            ));
        }
        if self.signature.is_empty() {
            return Err("signature must not be empty".to_string());
        }
        if self.signature.len() > MAX_SIGNATURE_LEN {
            return Err(format!(
                "signature length {} exceeds maximum {}",
                self.signature.len(),
                MAX_SIGNATURE_LEN
            ));
        }
        if self.provider_key_id.is_empty() {
            return Err("provider_key_id must not be empty".to_string());
        }
        if self.provider_key_id.len() > MAX_PROVIDER_KEY_ID_LEN {
            return Err(format!(
                "provider_key_id length {} exceeds maximum {}",
                self.provider_key_id.len(),
                MAX_PROVIDER_KEY_ID_LEN
            ));
        }
        if crate::core::has_dangerous_chars(&self.provider_key_id) {
            return Err("provider_key_id contains dangerous characters".to_string());
        }
        if self.issued_epoch > MAX_CREDENTIAL_EPOCH {
            return Err(format!(
                "issued_epoch {} exceeds maximum {}",
                self.issued_epoch, MAX_CREDENTIAL_EPOCH
            ));
        }
        Ok(())
    }
}

/// Custom Debug that redacts credential and signature bytes.
impl fmt::Debug for BlindCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindCredential")
            .field(
                "credential",
                &format!("[{} bytes REDACTED]", self.credential.len()),
            )
            .field(
                "signature",
                &format!("[{} bytes REDACTED]", self.signature.len()),
            )
            .field("provider_key_id", &self.provider_key_id)
            .field("issued_epoch", &self.issued_epoch)
            .field("credential_type", &self.credential_type)
            .finish()
    }
}

/// Status of a credential in the local vault.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    /// Available for use (not yet consumed).
    Available,
    /// Currently bound to an active session.
    Active,
    /// Consumed and no longer usable.
    Consumed,
    /// Expired (epoch rotated past this credential's epoch).
    Expired,
}

/// Summary of the credential vault state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialVaultStatus {
    /// Total credentials in vault.
    pub total: usize,
    /// Credentials available for new sessions.
    pub available: usize,
    /// Credentials currently bound to active sessions.
    pub active: usize,
    /// Credentials consumed (spent).
    pub consumed: usize,
    /// Whether replenishment is needed (available < threshold).
    pub needs_replenishment: bool,
    /// Current epoch for credential issuance.
    pub current_epoch: u64,
}

/// A session-to-credential binding.
///
/// Tracks which credential is used for a specific session.
/// The session ID is local-only and never sent to the provider.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionCredentialBinding {
    /// Local session identifier (never leaves the device).
    pub session_id: String,
    /// Index of the credential in the vault (not the credential itself).
    pub credential_index: usize,
    /// When this binding was created (local monotonic counter, not wall clock).
    pub binding_sequence: u64,
}

impl fmt::Debug for SessionCredentialBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionCredentialBinding")
            .field("session_id", &self.session_id)
            .field("credential_index", &"[REDACTED]")
            .field("binding_sequence", &self.binding_sequence)
            .finish()
    }
}
