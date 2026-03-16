// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Phase 3: Cryptographic inter-agent delegation tokens.
//!
//! When agent A delegates a capability to agent B, A issues a signed
//! delegation token that bounds: the delegated tool, the trust tier,
//! the maximum chain depth, and the expiry. B can re-delegate to C
//! by chaining tokens, but the chain is monotonically bounded — each
//! hop can only reduce trust and depth, never escalate.

use serde::{Deserialize, Serialize};

use crate::TrustTier;

/// A signed delegation token for inter-agent capability transfer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationToken {
    /// Unique token ID.
    pub token_id: String,
    /// Issuer agent ID.
    pub issuer: String,
    /// Subject (delegatee) agent ID.
    pub subject: String,
    /// Delegated tool pattern (glob).
    pub tool_pattern: String,
    /// Maximum trust tier the subject can claim.
    pub max_trust_tier: TrustTier,
    /// Remaining delegation depth (0 = cannot re-delegate).
    pub remaining_depth: u8,
    /// Expiry as Unix epoch seconds.
    pub expires_at_epoch_secs: u64,
    /// Parent token ID (for chained delegations). None for root tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_token_id: Option<String>,
    /// HMAC-SHA256 signature over the token fields.
    pub signature: String,
}

/// Maximum delegation chain depth.
pub const MAX_DELEGATION_DEPTH: u8 = 10;

/// Maximum token field lengths.
const MAX_TOKEN_FIELD_LEN: usize = 256;

impl DelegationToken {
    /// Validate token field bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.token_id.is_empty() || self.token_id.len() > MAX_TOKEN_FIELD_LEN {
            return Err("delegation_token.token_id must be 1-256 chars".to_string());
        }
        if crate::has_dangerous_chars(&self.token_id) {
            return Err("delegation_token.token_id contains dangerous characters".to_string());
        }
        if self.issuer.is_empty() || self.issuer.len() > MAX_TOKEN_FIELD_LEN {
            return Err("delegation_token.issuer must be 1-256 chars".to_string());
        }
        if crate::has_dangerous_chars(&self.issuer) {
            return Err("delegation_token.issuer contains dangerous characters".to_string());
        }
        if self.subject.is_empty() || self.subject.len() > MAX_TOKEN_FIELD_LEN {
            return Err("delegation_token.subject must be 1-256 chars".to_string());
        }
        if crate::has_dangerous_chars(&self.subject) {
            return Err("delegation_token.subject contains dangerous characters".to_string());
        }
        if self.tool_pattern.is_empty() || self.tool_pattern.len() > MAX_TOKEN_FIELD_LEN {
            return Err("delegation_token.tool_pattern must be 1-256 chars".to_string());
        }
        if self.remaining_depth > MAX_DELEGATION_DEPTH {
            return Err(format!(
                "delegation_token.remaining_depth {} exceeds max {MAX_DELEGATION_DEPTH}",
                self.remaining_depth
            ));
        }
        if self.signature.is_empty() || self.signature.len() > 512 {
            return Err("delegation_token.signature must be 1-512 chars".to_string());
        }
        Ok(())
    }

    /// Check if this token can be used to re-delegate.
    pub fn can_redelegate(&self) -> bool {
        self.remaining_depth > 0
    }

    /// Create a child token for re-delegation.
    ///
    /// The child inherits the parent's constraints with monotonic reduction:
    /// - Trust tier can only decrease or stay the same
    /// - Remaining depth decreases by 1
    /// - Expiry can only be earlier or the same
    ///
    /// Returns None if re-delegation is not possible.
    pub fn derive_child(
        &self,
        child_token_id: &str,
        child_subject: &str,
        child_trust: TrustTier,
        child_expires: u64,
        child_signature: &str,
    ) -> Option<DelegationToken> {
        if !self.can_redelegate() {
            return None;
        }
        // Monotonic trust: child cannot exceed parent
        let effective_trust = if child_trust.rank() > self.max_trust_tier.rank() {
            self.max_trust_tier
        } else {
            child_trust
        };
        // Monotonic expiry: child cannot outlive parent
        let effective_expires = child_expires.min(self.expires_at_epoch_secs);

        Some(DelegationToken {
            token_id: child_token_id.to_string(),
            issuer: self.subject.clone(), // current subject becomes issuer
            subject: child_subject.to_string(),
            tool_pattern: self.tool_pattern.clone(),
            max_trust_tier: effective_trust,
            remaining_depth: self.remaining_depth.saturating_sub(1),
            expires_at_epoch_secs: effective_expires,
            parent_token_id: Some(self.token_id.clone()),
            signature: child_signature.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_token() -> DelegationToken {
        DelegationToken {
            token_id: "tok-1".to_string(),
            issuer: "agent-A".to_string(),
            subject: "agent-B".to_string(),
            tool_pattern: "read_*".to_string(),
            max_trust_tier: TrustTier::High,
            remaining_depth: 3,
            expires_at_epoch_secs: 1710600000,
            parent_token_id: None,
            signature: "sig-root".to_string(),
        }
    }

    #[test]
    fn test_validate_ok() {
        assert!(root_token().validate().is_ok());
    }

    #[test]
    fn test_validate_empty_token_id() {
        let mut t = root_token();
        t.token_id = String::new();
        assert!(t.validate().is_err());
    }

    #[test]
    fn test_can_redelegate() {
        assert!(root_token().can_redelegate());
        let mut t = root_token();
        t.remaining_depth = 0;
        assert!(!t.can_redelegate());
    }

    #[test]
    fn test_derive_child_monotonic_trust() {
        let parent = root_token(); // High trust, depth 3
        let child = parent
            .derive_child(
                "tok-2",
                "agent-C",
                TrustTier::Verified,
                1710600000,
                "sig-child",
            )
            .unwrap();
        // Verified > High → clamped to High
        assert_eq!(child.max_trust_tier, TrustTier::High);
        assert_eq!(child.remaining_depth, 2);
        assert_eq!(child.issuer, "agent-B"); // B delegates to C
        assert_eq!(child.parent_token_id, Some("tok-1".to_string()));
    }

    #[test]
    fn test_derive_child_monotonic_expiry() {
        let parent = root_token(); // expires at 1710600000
        let child = parent
            .derive_child("tok-2", "agent-C", TrustTier::Medium, 1710700000, "sig")
            .unwrap();
        // Child tried to set later expiry → clamped to parent's
        assert_eq!(child.expires_at_epoch_secs, 1710600000);
    }

    #[test]
    fn test_derive_child_at_depth_zero_fails() {
        let mut parent = root_token();
        parent.remaining_depth = 0;
        assert!(parent
            .derive_child("tok-2", "C", TrustTier::Low, 0, "sig")
            .is_none());
    }

    #[test]
    fn test_chain_delegation_three_hops() {
        let root = root_token(); // A→B, depth 3, High
        let hop1 = root
            .derive_child("t2", "C", TrustTier::Medium, 1710600000, "s2")
            .unwrap();
        assert_eq!(hop1.remaining_depth, 2);
        assert_eq!(hop1.max_trust_tier, TrustTier::Medium);

        let hop2 = hop1
            .derive_child("t3", "D", TrustTier::Low, 1710500000, "s3")
            .unwrap();
        assert_eq!(hop2.remaining_depth, 1);
        assert_eq!(hop2.max_trust_tier, TrustTier::Low);
        assert_eq!(hop2.expires_at_epoch_secs, 1710500000); // earlier expiry

        let hop3 = hop2
            .derive_child("t4", "E", TrustTier::Low, 1710500000, "s4")
            .unwrap();
        assert_eq!(hop3.remaining_depth, 0);
        assert!(hop3
            .derive_child("t5", "F", TrustTier::Low, 0, "s5")
            .is_none());
    }
}
