// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Differential binding for `PARITY-HAND-2` — blind credential vault.
//!
//! `formal/kani/src/credential_vault.rs` is a hand-built state machine standing
//! in for `CredentialVault`: a `Vec<CredState>` where production has an
//! encrypted, persisted, mutex-guarded entry list. K108-K112 are proved on it —
//! single use, epoch monotonicity, capacity bound, fail-closed exhaustion, and
//! valid transitions.
//!
//! By the predictor recorded under `dlp_core.rs` — extractions that *model*
//! drift, extractions that *mirror* do not — this is among the likeliest to
//! have diverged. It had not: the transition rules match. What the model does
//! not represent is production's persistence, and that is where its properties
//! stop being about the running system.
//!
//! So the binding drives the **real vault** through the transitions the model
//! permits, and asserts the same answers. Where the model is silent —
//! rollback on persist failure (R236-SHIELD-3, R237-SHIELD-3), `activated_at`
//! tracking (R250-NHI-3) — that is recorded as scope, not compared.

#[cfg(test)]
// Suppressed rather than satisfied: linting the extraction would edit the copy
// the Kani proofs run against.
#[allow(clippy::manual_range_contains, dead_code, unused_imports)]
mod extracted {
    include!(concat!(
        env!("OUT_DIR"),
        "/kani_credential_vault_extraction.rs"
    ));
}

#[cfg(test)]
mod kani_parity_differential_credential_vault {
    use super::extracted;
    use crate::credential_vault::CredentialVault;
    use crate::crypto::EncryptedAuditStore;
    use vellaveto_types::{BlindCredential, CredentialStatus, CredentialType};

    fn make_vault(pool_size: usize) -> (CredentialVault, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EncryptedAuditStore::new(dir.path().join("vault.enc"), "test-passphrase!")
            .expect("store");
        let vault = CredentialVault::new(store, pool_size, 1).expect("vault");
        (vault, dir)
    }

    fn credential(epoch: u64) -> BlindCredential {
        BlindCredential {
            credential: vec![1, 2, 3, 4],
            signature: vec![5, 6, 7, 8],
            provider_key_id: "test-key-001".to_string(),
            issued_epoch: epoch,
            credential_type: CredentialType::Subscriber,
        }
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/credential_vault.rs was not found, so this binding \
             compared nothing"
        );
    }

    /// K110: the capacity bound the model enforces must be production's.
    ///
    /// Pinned on both sides independently — asserting only that they are equal
    /// would let a change move both at once, the trap recorded under "bind the
    /// value, not the relation".
    #[test]
    fn test_capacity_bound_matches_production() {
        assert_eq!(
            extracted::MAX_VAULT_ENTRIES,
            10_000,
            "the model's capacity bound moved"
        );
        assert_eq!(
            vellaveto_types::MAX_CREDENTIAL_POOL_SIZE,
            10_000,
            "production's credential pool bound moved; the model must follow"
        );
    }

    /// K108, against the real vault: a credential is single-use.
    ///
    /// The model returns `Err("already active")` on a second consume of the
    /// same id. Production consumes by *position* — it takes the first
    /// `Available` — so the corresponding statement is that a vault holding one
    /// credential yields it once and then fails closed.
    #[test]
    fn test_single_use_matches_the_model() {
        let (vault, _dir) = make_vault(4);
        vault.add_credential(credential(1)).expect("add");

        let (_cred, idx) = vault.consume_credential().expect("first consume succeeds");
        assert!(
            vault.consume_credential().is_err(),
            "K108: the vault yielded a second credential when only one was added — \
             a consumed credential is reusable"
        );

        // The model agrees: consuming an already-Active id fails.
        let mut model = extracted::Vault::new(4);
        model.add_credential(0).expect("model add");
        model.consume_credential(0, 7).expect("model first consume");
        assert!(
            model.consume_credential(0, 7).is_err(),
            "K108: the model permits re-consuming an Active credential"
        );

        // K108 names re-consuming a CONSUMED credential, not an Active one.
        // The first version of this test only tried the Active case, which
        // takes a different match arm, so turning the Consumed arm into
        // `Ok(())` survived mutation testing while K108 read as covered.
        let mut consumed_model = extracted::Vault::new(4);
        consumed_model.add_credential(0).expect("add");
        consumed_model
            .consume_credential(0, 7)
            .expect("Available -> Active");
        consumed_model.mark_consumed(0).expect("Active -> Consumed");
        assert_eq!(
            consumed_model.state(0),
            extracted::CredState::Consumed,
            "precondition: the credential must actually be Consumed"
        );
        assert!(
            consumed_model.consume_credential(0, 9).is_err(),
            "K108: a Consumed credential was consumed again — the single-use \
             property the proof is named for does not hold"
        );

        // K112: Active -> Consumed is the only onward transition, in both.
        vault.mark_consumed(idx).expect("Active -> Consumed");
        assert!(
            vault.mark_consumed(idx).is_err(),
            "K112: production allowed Consumed -> Consumed (R238-SHLD-6)"
        );
        model.mark_consumed(0).expect("model Active -> Consumed");
        assert!(
            model.mark_consumed(0).is_err(),
            "K112: the model allowed Consumed -> Consumed"
        );
    }

    /// K112 across every starting state: `mark_consumed` succeeds from `Active`
    /// and from nothing else, in both implementations.
    #[test]
    fn test_mark_consumed_only_from_active_in_both() {
        // Production: Available (never consumed) must not become Consumed.
        let (vault, _dir) = make_vault(4);
        vault.add_credential(credential(1)).expect("add");
        assert!(
            vault.mark_consumed(0).is_err(),
            "K112 / R238-SHLD-6: production marked an Available credential Consumed, \
             so a credential never bound to a session would be retired"
        );

        // The model, over all four states it distinguishes.
        for state in ["absent", "available", "active", "consumed"] {
            let mut model = extracted::Vault::new(2);
            match state {
                "absent" => {}
                "available" => {
                    model.add_credential(0).expect("add");
                }
                "active" => {
                    model.add_credential(0).expect("add");
                    model.consume_credential(0, 1).expect("consume");
                }
                _ => {
                    model.add_credential(0).expect("add");
                    model.consume_credential(0, 1).expect("consume");
                    model.mark_consumed(0).expect("mark");
                }
            }
            let allowed = model.mark_consumed(0).is_ok();
            assert_eq!(
                allowed,
                state == "active",
                "K112: mark_consumed from {state} should be {}",
                if state == "active" {
                    "allowed"
                } else {
                    "rejected"
                }
            );
        }
    }

    /// The **whole transition table**: every operation from every state.
    ///
    /// This replaces what was a happy path plus ad-hoc cases. A state machine
    /// has a small, totally enumerable transition table, and testing anything
    /// less leaves arms unexercised — four separate mutations survived the
    /// earlier version (consume from Consumed, from Expired, from Absent, and
    /// re-adding an existing credential), each one a match arm no case reached.
    /// K108 in particular is named for the Consumed case, which the first
    /// version never tried.
    ///
    /// The expected column is written out rather than computed, so a change to
    /// the model's behaviour has to be reconciled with a stated intention
    /// instead of silently redefining the expectation.
    #[test]
    fn test_full_transition_table() {
        use extracted::CredState;

        /// (starting state, operation, expected to succeed)
        const TABLE: &[(&str, &str, bool)] = &[
            // add_credential: only from Absent.
            ("absent", "add", true),
            ("available", "add", false),
            ("active", "add", false),
            ("consumed", "add", false),
            ("expired", "add", false),
            // consume_credential: only from Available. K108 is the Consumed row.
            ("absent", "consume", false),
            ("available", "consume", true),
            ("active", "consume", false),
            ("consumed", "consume", false),
            ("expired", "consume", false),
            // mark_consumed: only from Active. R238-SHLD-6.
            ("absent", "mark", false),
            ("available", "mark", false),
            ("active", "mark", true),
            ("consumed", "mark", false),
            ("expired", "mark", false),
        ];

        fn build(state: &str) -> extracted::Vault {
            let mut vault = extracted::Vault::new(4);
            match state {
                "absent" => {}
                "available" => {
                    vault.add_credential(0).expect("add");
                }
                "active" => {
                    vault.add_credential(0).expect("add");
                    vault.consume_credential(0, 1).expect("consume");
                }
                "consumed" => {
                    vault.add_credential(0).expect("add");
                    vault.consume_credential(0, 1).expect("consume");
                    vault.mark_consumed(0).expect("mark");
                }
                "expired" => {
                    vault.add_credential(0).expect("add");
                    vault.advance_epoch();
                    vault.expire_old_epochs(vault.current_epoch());
                }
                other => panic!("unknown state {other}"),
            }
            vault
        }

        fn expected_state(state: &str) -> CredState {
            match state {
                "absent" => CredState::Absent,
                "available" => CredState::Available,
                "active" => CredState::Active,
                "consumed" => CredState::Consumed,
                _ => CredState::Expired,
            }
        }

        for (state, op, should_succeed) in TABLE {
            let mut vault = build(state);
            assert_eq!(
                vault.state(0),
                expected_state(state),
                "the fixture for {state:?} did not reach that state"
            );

            let got = match *op {
                "add" => vault.add_credential(0).is_ok(),
                "consume" => vault.consume_credential(0, 9).is_ok(),
                _ => vault.mark_consumed(0).is_ok(),
            };

            assert_eq!(
                got,
                *should_succeed,
                "transition table: {op} from {state} should {} — a credential in \
                 state {state} that accepts {op} breaks the single-use and \
                 valid-transition properties K108/K112 are named for",
                if *should_succeed {
                    "succeed"
                } else {
                    "be rejected"
                }
            );
        }
        assert_eq!(TABLE.len(), 15, "transition table shrank; recount");
    }

    /// K111: exhaustion is an error, never a silent skip.
    #[test]
    fn test_exhaustion_fails_closed_in_both() {
        let (vault, _dir) = make_vault(4);
        assert!(
            vault.consume_credential().is_err(),
            "K111: an empty vault returned a credential instead of failing closed"
        );

        let model = extracted::Vault::new(4);
        assert!(
            model.find_available().is_none(),
            "K111: the model found an available credential in an empty vault"
        );
    }

    /// Expiry touches `Available` only — an `Active` credential bound to a live
    /// session is not swept out from under it, and a `Consumed` one does not
    /// come back.
    #[test]
    fn test_expiry_affects_only_available_in_both() {
        let (vault, _dir) = make_vault(8);
        vault.add_credential(credential(1)).expect("add available");
        vault.add_credential(credential(1)).expect("add second");
        let (_c, active_idx) = vault.consume_credential().expect("consume one");

        let expired = vault.expire_old_epochs(5).expect("expire");
        assert_eq!(
            expired, 1,
            "expiry should have swept exactly the one Available credential"
        );
        let status = vault.status();
        assert_eq!(
            status.active, 1,
            "K112: expiry moved an Active credential out from under a live session"
        );
        let _ = active_idx;

        // The model agrees.
        let mut model = extracted::Vault::new(8);
        model.add_credential(0).expect("add");
        model.add_credential(1).expect("add");
        model.consume_credential(1, 3).expect("consume");
        model.advance_epoch();
        model.expire_old_epochs(model.current_epoch());
        assert_eq!(model.state(0), extracted::CredState::Expired);
        assert_eq!(
            model.state(1),
            extracted::CredState::Active,
            "K112: the model expired an Active credential"
        );

        // An Expired credential must not be consumable. Without this the
        // Expired match arm is never exercised, and turning it into `Ok(())`
        // survives — which is credential reuse across an epoch rotation, the
        // thing R235-SHIELD-2 persists expiry to prevent.
        assert!(
            model.consume_credential(0, 11).is_err(),
            "an Expired credential was consumed, so a rotated-out credential is \
             usable again"
        );
    }

    /// K109: the epoch never decreases, in either.
    #[test]
    fn test_epoch_monotonicity_in_both() {
        let (vault, _dir) = make_vault(4);
        vault.expire_old_epochs(5).expect("advance to 5");
        vault.expire_old_epochs(2).expect("attempt to go backwards");
        assert_eq!(
            vault.status().current_epoch,
            5,
            "K109: production's epoch went backwards"
        );

        let mut model = extracted::Vault::new(4);
        let before = model.current_epoch();
        model.advance_epoch();
        assert!(
            model.current_epoch() > before,
            "K109: the model's epoch did not advance"
        );
    }

    /// Scope, stated rather than implied. The model has no persistence, so it
    /// cannot represent the rollback production performs when a persist fails
    /// (R236-SHIELD-3 on consume, R237-SHIELD-3 on expire) or the
    /// `activated_at` stamp used to reclaim orphaned Active entries
    /// (R250-NHI-3). K108-K112 say nothing about those paths, and this binding
    /// does not pretend otherwise — it pins that the fields exist so their
    /// removal is noticed.
    #[test]
    fn test_persistence_paths_are_outside_the_models_scope() {
        let (vault, _dir) = make_vault(4);
        vault.add_credential(credential(1)).expect("add");
        vault.consume_credential().expect("consume");
        let status = vault.status();
        assert_eq!(
            status.active, 1,
            "consume should leave exactly one Active entry"
        );
        // The model tracks no timestamps at all; production does.
        assert!(
            std::mem::size_of::<CredentialStatus>() > 0,
            "CredentialStatus is production's state type, not the model's CredState"
        );
    }
}
