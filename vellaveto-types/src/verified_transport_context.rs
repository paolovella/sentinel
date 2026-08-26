// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified transport-trust projection for sensitive evaluation-context fields.
//!
//! `agent_identity` and `capability_token` are only safe to preserve when they
//! originate from a transport that has already validated them. Untrusted
//! transports must strip both fields fail-closed.

use crate::{AgentIdentity, CapabilityToken};

/// Return true when a transport may preserve an `agent_identity` field.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn trusted_transport_preserves_agent_identity(
    transport_trusted: bool,
    identity_present: bool,
) -> bool {
    transport_trusted && identity_present
}

/// Return true when a transport may preserve a `capability_token` field.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn trusted_transport_preserves_capability_token(
    transport_trusted: bool,
    capability_token_present: bool,
) -> bool {
    transport_trusted && capability_token_present
}

/// Project an `agent_identity` field through the transport trust boundary.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub fn project_agent_identity_from_transport(
    transport_trusted: bool,
    agent_identity: Option<AgentIdentity>,
) -> Option<AgentIdentity> {
    if trusted_transport_preserves_agent_identity(transport_trusted, agent_identity.is_some()) {
        agent_identity
    } else {
        None
    }
}

/// Project a `capability_token` field through the transport trust boundary.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub fn project_capability_token_from_transport(
    transport_trusted: bool,
    capability_token: Option<CapabilityToken>,
) -> Option<CapabilityToken> {
    if trusted_transport_preserves_capability_token(transport_trusted, capability_token.is_some()) {
        capability_token
    } else {
        None
    }
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_transport_context.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function. Symbol parity cannot see this:
    //! `check-verus-parity.sh` greps for names.
    //!
    //! TOTAL discharge: both predicates range over booleans only.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_trusted_transport_preserves_agent_identity(
        transport_trusted: bool,
        identity_present: bool,
    ) -> bool {
        transport_trusted && identity_present
    }

    fn spec_trusted_transport_preserves_capability_token(
        transport_trusted: bool,
        capability_token_present: bool,
    ) -> bool {
        transport_trusted && capability_token_present
    }

    #[test]
    fn test_production_matches_verus_spec_total_domain() {
        for a in [false, true] {
            for b in [false, true] {
                assert_eq!(
                    trusted_transport_preserves_agent_identity(a, b),
                    spec_trusted_transport_preserves_agent_identity(a, b),
                    "PARITY-HAND-1: trusted_transport_preserves_agent_identity disagrees at \
                     ({a}, {b})"
                );
                assert_eq!(
                    trusted_transport_preserves_capability_token(a, b),
                    spec_trusted_transport_preserves_capability_token(a, b),
                    "PARITY-HAND-1: trusted_transport_preserves_capability_token disagrees at \
                     ({a}, {b})"
                );
            }
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // An untrusted transport carries neither identity nor capability
        // across the boundary, whatever it presents.
        assert!(!spec_trusted_transport_preserves_agent_identity(
            false, true
        ));
        assert!(!spec_trusted_transport_preserves_capability_token(
            false, true
        ));
        assert!(spec_trusted_transport_preserves_agent_identity(true, true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapabilityGrant;
    use std::collections::HashMap;

    fn sample_identity() -> AgentIdentity {
        AgentIdentity {
            claims: HashMap::new(),
            issuer: Some("issuer.example".to_string()),
            subject: Some("agent-123".to_string()),
            audience: vec!["vellaveto".to_string()],
        }
    }

    fn sample_capability_token() -> CapabilityToken {
        CapabilityToken {
            token_id: "token-123".to_string(),
            parent_token_id: None,
            issuer: "issuer-1".to_string(),
            holder: "holder-1".to_string(),
            grants: vec![CapabilityGrant {
                tool_pattern: "file_system".to_string(),
                function_pattern: "read_file".to_string(),
                allowed_paths: vec!["/tmp/*".to_string()],
                allowed_domains: Vec::new(),
                max_invocations: 1,
            }],
            remaining_depth: 1,
            issued_at: "2026-03-08T00:00:00Z".to_string(),
            expires_at: "2026-03-09T00:00:00Z".to_string(),
            signature: "deadbeef".to_string(),
            issuer_public_key: "feedface".to_string(),
        }
    }

    #[test]
    fn test_trusted_transport_preserves_agent_identity_only_when_present() {
        assert!(trusted_transport_preserves_agent_identity(true, true));
        assert!(!trusted_transport_preserves_agent_identity(true, false));
        assert!(!trusted_transport_preserves_agent_identity(false, true));
        assert!(!trusted_transport_preserves_agent_identity(false, false));
    }

    #[test]
    fn test_trusted_transport_preserves_capability_token_only_when_present() {
        assert!(trusted_transport_preserves_capability_token(true, true));
        assert!(!trusted_transport_preserves_capability_token(true, false));
        assert!(!trusted_transport_preserves_capability_token(false, true));
        assert!(!trusted_transport_preserves_capability_token(false, false));
    }

    #[test]
    fn test_project_agent_identity_from_trusted_transport_preserves_identity() {
        let identity = sample_identity();

        assert_eq!(
            project_agent_identity_from_transport(true, Some(identity.clone())),
            Some(identity)
        );
    }

    #[test]
    fn test_project_agent_identity_from_untrusted_transport_strips_identity() {
        assert_eq!(
            project_agent_identity_from_transport(false, Some(sample_identity())),
            None
        );
        assert_eq!(project_agent_identity_from_transport(false, None), None);
    }

    #[test]
    fn test_project_capability_token_from_trusted_transport_preserves_token() {
        let token = sample_capability_token();

        assert_eq!(
            project_capability_token_from_transport(true, Some(token.clone())),
            Some(token)
        );
    }

    #[test]
    fn test_project_capability_token_from_untrusted_transport_strips_token() {
        assert_eq!(
            project_capability_token_from_transport(false, Some(sample_capability_token())),
            None
        );
        assert_eq!(project_capability_token_from_transport(false, None), None);
    }
}
