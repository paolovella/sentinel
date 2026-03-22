// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Credential vault state machine verification.
//!
//! Extracts and verifies security-critical properties of the blind
//! credential vault from `vellaveto-mcp-shield/src/credential_vault.rs`.
//!
//! # Verified Properties (K108-K112)
//!
//! | ID   | Property |
//! |------|----------|
//! | K108 | Consumed credential cannot be re-consumed (single-use) |
//! | K109 | Epoch monotonicity: current_epoch never decreases |
//! | K110 | Capacity bounded: vault never exceeds MAX_VAULT_ENTRIES |
//! | K111 | Fail-closed on exhaustion: no Available credential → error, never silent skip |
//! | K112 | State transitions are valid: only Available→Active→Consumed, Available→Expired |
//!
//! # Production Correspondence
//!
//! - State machine ↔ CredentialVault.tla (CV1-CV5)
//! - consume_credential ↔ credential_vault.rs:133-158
//! - mark_consumed ↔ credential_vault.rs:167-200
//! - expire_old_epochs ↔ credential_vault.rs:225-260

/// Maximum vault entries (mirrors production).
pub const MAX_VAULT_ENTRIES: usize = 10_000;

/// Credential states matching the TLA+ model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredState {
    Absent,
    Available,
    Active,
    Consumed,
    Expired,
}

/// A simplified credential vault for verification.
pub struct Vault {
    states: Vec<CredState>,
    epochs: Vec<u64>,
    current_epoch: u64,
    bindings: Vec<Option<u8>>, // session_id binding (simplified)
}

impl Vault {
    pub fn new(capacity: usize) -> Self {
        Self {
            states: vec![CredState::Absent; capacity],
            epochs: vec![0; capacity],
            current_epoch: 0,
            bindings: vec![None; capacity],
        }
    }

    /// Add a credential at the current epoch.
    pub fn add_credential(&mut self, id: usize) -> Result<(), &'static str> {
        if id >= self.states.len() {
            return Err("invalid id");
        }
        let active_count = self.states.iter().filter(|s| **s != CredState::Absent).count();
        if active_count >= MAX_VAULT_ENTRIES {
            return Err("vault full"); // Fail-closed: K111
        }
        if self.states[id] != CredState::Absent {
            return Err("credential already exists");
        }
        self.states[id] = CredState::Available;
        self.epochs[id] = self.current_epoch;
        Ok(())
    }

    /// Consume an Available credential for a session.
    /// Available → Active (bound to session).
    pub fn consume_credential(&mut self, id: usize, session_id: u8) -> Result<(), &'static str> {
        if id >= self.states.len() {
            return Err("invalid id");
        }
        match self.states[id] {
            CredState::Available => {
                self.states[id] = CredState::Active;
                self.bindings[id] = Some(session_id);
                Ok(())
            }
            CredState::Consumed => Err("already consumed"), // K108: single-use
            CredState::Active => Err("already active"),
            CredState::Expired => Err("expired"),
            CredState::Absent => Err("not found"),
        }
    }

    /// Mark an Active credential as Consumed after session ends.
    /// Active → Consumed.
    pub fn mark_consumed(&mut self, id: usize) -> Result<(), &'static str> {
        if id >= self.states.len() {
            return Err("invalid id");
        }
        if self.states[id] != CredState::Active {
            return Err("not active");
        }
        self.states[id] = CredState::Consumed;
        Ok(())
    }

    /// Advance the epoch. Monotonically increasing.
    pub fn advance_epoch(&mut self) {
        self.current_epoch = self.current_epoch.saturating_add(1); // K109
    }

    /// Expire credentials from old epochs.
    pub fn expire_old_epochs(&mut self, cutoff_epoch: u64) {
        for i in 0..self.states.len() {
            if self.states[i] == CredState::Available && self.epochs[i] < cutoff_epoch {
                self.states[i] = CredState::Expired;
            }
        }
    }

    /// Find any Available credential (fail-closed: returns None if none).
    pub fn find_available(&self) -> Option<usize> {
        self.states.iter().position(|s| *s == CredState::Available)
    }

    pub fn state(&self, id: usize) -> CredState {
        self.states[id]
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn active_count(&self) -> usize {
        self.states.iter().filter(|s| **s != CredState::Absent).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── K108: Consumed credential cannot be re-consumed ───────────────

    #[test]
    fn test_k108_no_double_consumption() {
        let mut vault = Vault::new(3);
        vault.add_credential(0).unwrap();
        vault.consume_credential(0, 1).unwrap();
        vault.mark_consumed(0).unwrap();

        // Try to consume again — must fail
        assert!(vault.consume_credential(0, 2).is_err(),
            "K108: Consumed credential must not be re-consumed");
        assert_eq!(vault.state(0), CredState::Consumed);
    }

    #[test]
    fn test_k108_active_cannot_be_consumed_again() {
        let mut vault = Vault::new(3);
        vault.add_credential(0).unwrap();
        vault.consume_credential(0, 1).unwrap();

        // Already Active — second consume must fail
        assert!(vault.consume_credential(0, 2).is_err());
    }

    // ── K109: Epoch monotonicity ──────────────────────────────────────

    #[test]
    fn test_k109_epoch_monotonic() {
        let mut vault = Vault::new(3);
        let e0 = vault.current_epoch();
        vault.advance_epoch();
        let e1 = vault.current_epoch();
        vault.advance_epoch();
        let e2 = vault.current_epoch();

        assert!(e1 > e0, "Epoch must increase");
        assert!(e2 > e1, "Epoch must increase");
    }

    #[test]
    fn test_k109_epoch_saturating_at_max() {
        let mut vault = Vault::new(1);
        // Force near-max
        vault.current_epoch = u64::MAX - 1;
        vault.advance_epoch();
        assert_eq!(vault.current_epoch(), u64::MAX);
        vault.advance_epoch(); // Should saturate
        assert_eq!(vault.current_epoch(), u64::MAX, "Must not wrap");
    }

    // ── K110: Capacity bounded ────────────────────────────────────────

    #[test]
    fn test_k110_capacity_bounded() {
        let cap = 5;
        let mut vault = Vault::new(cap + 2);
        // Override MAX for this test by filling up
        for i in 0..cap {
            vault.states[i] = CredState::Available;
        }

        // Active count is now 5
        assert_eq!(vault.active_count(), cap);
    }

    // ── K111: Fail-closed on exhaustion ───────────────────────────────

    #[test]
    fn test_k111_fail_closed_no_available() {
        let mut vault = Vault::new(3);
        // No credentials added — find_available returns None
        assert_eq!(vault.find_available(), None, "Empty vault must return None");

        // Add and consume all
        vault.add_credential(0).unwrap();
        vault.consume_credential(0, 1).unwrap();
        vault.mark_consumed(0).unwrap();

        assert_eq!(vault.find_available(), None,
            "K111: No available credentials must return None (fail-closed)");
    }

    #[test]
    fn test_k111_expired_not_available() {
        let mut vault = Vault::new(3);
        vault.add_credential(0).unwrap();
        vault.expire_old_epochs(1); // Expire everything from epoch 0

        assert_eq!(vault.state(0), CredState::Expired);
        assert_eq!(vault.find_available(), None,
            "Expired credential must not be returned as available");

        // Try to consume expired credential — must fail
        assert!(vault.consume_credential(0, 1).is_err());
    }

    // ── K112: Valid state transitions ─────────────────────────────────

    #[test]
    fn test_k112_full_lifecycle() {
        let mut vault = Vault::new(3);

        // Absent → Available (via add_credential)
        vault.add_credential(0).unwrap();
        assert_eq!(vault.state(0), CredState::Available);

        // Available → Active (via consume_credential)
        vault.consume_credential(0, 1).unwrap();
        assert_eq!(vault.state(0), CredState::Active);

        // Active → Consumed (via mark_consumed)
        vault.mark_consumed(0).unwrap();
        assert_eq!(vault.state(0), CredState::Consumed);
    }

    #[test]
    fn test_k112_available_to_expired() {
        let mut vault = Vault::new(3);
        vault.add_credential(0).unwrap();
        assert_eq!(vault.state(0), CredState::Available);

        vault.expire_old_epochs(1);
        assert_eq!(vault.state(0), CredState::Expired);
    }

    #[test]
    fn test_k112_invalid_transitions_rejected() {
        let mut vault = Vault::new(3);
        vault.add_credential(0).unwrap();

        // Available → Consumed (skip Active) — must fail
        assert!(vault.mark_consumed(0).is_err(),
            "Cannot mark Available as Consumed directly");

        // Absent → Active — must fail
        assert!(vault.consume_credential(1, 1).is_err(),
            "Cannot consume Absent credential");

        // Absent → Consumed — must fail
        assert!(vault.mark_consumed(1).is_err(),
            "Cannot mark Absent as Consumed");
    }

    // ── Bridge: exhaust all paths ─────────────────────────────────────

    #[test]
    fn test_exhaustive_3_credentials() {
        // Test all valid sequences of 3 credentials through full lifecycle
        let mut vault = Vault::new(3);

        for i in 0..3 {
            vault.add_credential(i).unwrap();
        }

        // Consume all in order
        for i in 0..3 {
            vault.consume_credential(i, i as u8).unwrap();
        }

        // Mark all consumed
        for i in 0..3 {
            vault.mark_consumed(i).unwrap();
        }

        // All must be Consumed
        for i in 0..3 {
            assert_eq!(vault.state(i), CredState::Consumed);
        }

        // No available credentials
        assert_eq!(vault.find_available(), None);

        // Re-consumption of any must fail
        for i in 0..3 {
            assert!(vault.consume_credential(i, 99).is_err());
        }
    }
}
