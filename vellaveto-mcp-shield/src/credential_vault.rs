// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Encrypted local vault for blind credentials.
//!
//! Stores pre-generated blind credentials in an encrypted file,
//! tracks consumption, and signals when replenishment is needed.
//! Uses XChaCha20-Poly1305 + Argon2id (same crypto stack as audit store).

use crate::crypto::EncryptedAuditStore;
use crate::error::ShieldError;
use std::sync::Mutex;
use vellaveto_types::shield::{
    BlindCredential, CredentialStatus, CredentialVaultStatus, MAX_CREDENTIAL_POOL_SIZE,
};

/// Maximum vault entries to prevent unbounded growth.
const MAX_VAULT_ENTRIES: usize = MAX_CREDENTIAL_POOL_SIZE;

/// Maximum age (in seconds) for an Active credential before it is considered orphaned.
///
/// SECURITY (R250-NHI-3): If a session crashes after `consume_credential()` without
/// calling `mark_consumed()`, the credential stays Active forever, permanently draining
/// the pool. After this TTL, `reclaim_orphaned_active()` transitions it to Expired.
const MAX_ACTIVE_AGE_SECS: u64 = 3600; // 1 hour

/// A single vault entry: credential + status.
#[derive(Clone)]
struct VaultEntry {
    credential: BlindCredential,
    status: CredentialStatus,
    /// Timestamp (Unix seconds) when the credential was marked Active.
    /// None for non-Active credentials.
    activated_at: Option<u64>,
}

/// Encrypted local vault for blind credentials.
///
/// Thread-safe via internal Mutex. Credentials are stored in memory
/// after decryption and persisted to the encrypted store on mutation.
pub struct CredentialVault {
    entries: Mutex<Vec<VaultEntry>>,
    store: Mutex<EncryptedAuditStore>,
    pool_size: usize,
    replenish_threshold: usize,
    current_epoch: Mutex<u64>,
}

impl CredentialVault {
    /// Create a new credential vault backed by an encrypted store.
    ///
    /// Loads existing credentials from the store file if present.
    pub fn new(
        store: EncryptedAuditStore,
        pool_size: usize,
        replenish_threshold: usize,
    ) -> Result<Self, ShieldError> {
        let pool_size = pool_size.min(MAX_VAULT_ENTRIES);

        // Load existing entries from encrypted store
        let raw_entries = store.read_all_entries()?;
        let mut entries = Vec::with_capacity(raw_entries.len().min(MAX_VAULT_ENTRIES));
        let mut max_epoch: u64 = 0;

        for raw in raw_entries.iter().take(MAX_VAULT_ENTRIES) {
            let entry: StoredVaultEntry = serde_json::from_slice(raw)
                .map_err(|e| ShieldError::Decryption(format!("vault entry deserialize: {e}")))?;
            max_epoch = max_epoch.max(entry.credential.issued_epoch);
            entries.push(VaultEntry {
                credential: entry.credential,
                status: entry.status,
                activated_at: entry.activated_at,
            });
        }

        Ok(Self {
            entries: Mutex::new(entries),
            store: Mutex::new(store),
            pool_size,
            replenish_threshold,
            current_epoch: Mutex::new(max_epoch),
        })
    }

    /// Add a credential to the vault and persist it.
    pub fn add_credential(&self, credential: BlindCredential) -> Result<(), ShieldError> {
        credential.validate().map_err(ShieldError::Config)?;

        let mut entries = self
            .entries
            .lock()
            .map_err(|e| ShieldError::Encryption(format!("vault lock poisoned: {e}")))?;

        if entries.len() >= MAX_VAULT_ENTRIES {
            return Err(ShieldError::Config(format!(
                "vault capacity exhausted (max {MAX_VAULT_ENTRIES})"
            )));
        }

        // SECURITY (R233-SHIELD-5): Fail-closed on epoch lock poisoning.
        // Silently skipping epoch update would allow stale epoch tracking.
        let mut epoch = self
            .current_epoch
            .lock()
            .map_err(|e| ShieldError::Encryption(format!("epoch lock poisoned: {e}")))?;
        if credential.issued_epoch > *epoch {
            *epoch = credential.issued_epoch;
        }
        drop(epoch);

        let stored = StoredVaultEntry {
            credential: credential.clone(),
            status: CredentialStatus::Available,
            activated_at: None,
        };

        // Persist to encrypted store
        let serialized = serde_json::to_vec(&stored)
            .map_err(|e| ShieldError::Encryption(format!("vault entry serialize: {e}")))?;

        let store = self
            .store
            .lock()
            .map_err(|e| ShieldError::Encryption(format!("store lock poisoned: {e}")))?;
        store.write_encrypted_entry(&serialized)?;

        entries.push(VaultEntry {
            credential,
            status: CredentialStatus::Available,
            activated_at: None,
        });

        Ok(())
    }

    /// Consume the next available credential for a new session.
    ///
    /// Returns the credential and its vault index. The credential is
    /// marked as Active and the status change is persisted to disk.
    /// Returns an error if no credentials are available
    /// (fail-closed: no credential = no session).
    pub fn consume_credential(&self) -> Result<(BlindCredential, usize), ShieldError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|e| ShieldError::Encryption(format!("vault lock poisoned: {e}")))?;

        let idx = entries
            .iter()
            .position(|e| e.status == CredentialStatus::Available)
            .ok_or_else(|| {
                ShieldError::Config("no available credentials in vault (fail-closed)".to_string())
            })?;

        entries[idx].status = CredentialStatus::Active;
        // SECURITY (R250-NHI-3): Track when the credential became Active so
        // reclaim_orphaned_active() can detect stale Active entries.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        entries[idx].activated_at = Some(now_secs);

        // SECURITY (R234-SHIELD-1): Persist status change to disk so that
        // a crash cannot revert a consumed credential to Available.
        // SECURITY (R236-SHIELD-3): Rollback in-memory state if persist fails.
        // Without rollback, the credential is marked Active in memory but not
        // on disk, permanently draining it from the available pool.
        if let Err(e) = self.persist_entries(&entries) {
            entries[idx].status = CredentialStatus::Available;
            entries[idx].activated_at = None;
            return Err(e);
        }

        Ok((entries[idx].credential.clone(), idx))
    }

    /// Mark a credential as consumed (session ended normally).
    ///
    /// SECURITY (R238-SHLD-6): Only allows transitioning from `Active` to `Consumed`.
    /// Other statuses (Available, Consumed, Expired) should not transition to Consumed
    /// because: Available means it was never bound to a session, Consumed means
    /// double-consume, and Expired means it was already invalidated.
    pub fn mark_consumed(&self, index: usize) -> Result<(), ShieldError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|e| ShieldError::Encryption(format!("vault lock poisoned: {e}")))?;

        if index >= entries.len() {
            return Err(ShieldError::Config(format!(
                "credential index {} out of bounds (vault size {})",
                index,
                entries.len()
            )));
        }

        // SECURITY (R238-SHLD-6): Only Active credentials can transition to Consumed.
        if entries[index].status != CredentialStatus::Active {
            return Err(ShieldError::CredentialVault(format!(
                "credential at index {} has status {:?}, only Active credentials can be consumed",
                index, entries[index].status
            )));
        }

        let prev_status = entries[index].status;
        let prev_activated = entries[index].activated_at;
        entries[index].status = CredentialStatus::Consumed;
        entries[index].activated_at = None;

        // SECURITY (R234-SHIELD-1): Persist consumed status to prevent reuse after crash.
        // SECURITY (R236-SHIELD-3): Rollback on persist failure.
        if let Err(e) = self.persist_entries(&entries) {
            entries[index].status = prev_status;
            entries[index].activated_at = prev_activated;
            return Err(e);
        }

        Ok(())
    }

    /// Persist all vault entries to the encrypted store (atomic rewrite).
    fn persist_entries(&self, entries: &[VaultEntry]) -> Result<(), ShieldError> {
        let store = self
            .store
            .lock()
            .map_err(|e| ShieldError::Encryption(format!("store lock poisoned: {e}")))?;

        let serialized: Vec<Vec<u8>> = entries
            .iter()
            .map(|e| {
                let stored = StoredVaultEntry {
                    credential: e.credential.clone(),
                    status: e.status,
                    activated_at: e.activated_at,
                };
                serde_json::to_vec(&stored)
                    .map_err(|err| ShieldError::Encryption(format!("vault entry serialize: {err}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        store.rewrite_all_entries(&serialized)
    }

    /// Expire credentials from epochs older than the given epoch.
    pub fn expire_old_epochs(&self, current_epoch: u64) -> Result<usize, ShieldError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|e| ShieldError::Encryption(format!("vault lock poisoned: {e}")))?;

        // SECURITY (R237-SHIELD-3): Save original statuses before mutation
        // so we can rollback if persist fails, matching consume_credential pattern.
        let mut expired_indices = Vec::new();
        for (idx, entry) in entries.iter_mut().enumerate() {
            if entry.status == CredentialStatus::Available
                && entry.credential.issued_epoch < current_epoch
            {
                entry.status = CredentialStatus::Expired;
                expired_indices.push(idx);
            }
        }
        let expired_count = expired_indices.len();

        // SECURITY (R235-SHIELD-2): Persist expired status changes to disk.
        // Without persistence, a crash reverts expired credentials to Available,
        // allowing credential reuse across sessions.
        if expired_count > 0 {
            if let Err(e) = self.persist_entries(&entries) {
                // SECURITY (R237-SHIELD-3): Rollback in-memory state on persist failure.
                for &idx in &expired_indices {
                    entries[idx].status = CredentialStatus::Available;
                }
                return Err(e);
            }
        }

        // SECURITY (R233-SHIELD-5): Fail-closed on epoch lock poisoning.
        let mut epoch = self
            .current_epoch
            .lock()
            .map_err(|e| ShieldError::Encryption(format!("epoch lock poisoned: {e}")))?;
        if current_epoch > *epoch {
            *epoch = current_epoch;
        }

        Ok(expired_count)
    }

    /// Get the current vault status summary.
    pub fn status(&self) -> CredentialVaultStatus {
        let entries = match self.entries.lock() {
            Ok(e) => e,
            Err(_) => {
                // Fail-closed: poisoned lock returns empty status with needs_replenishment=true
                return CredentialVaultStatus {
                    total: 0,
                    available: 0,
                    active: 0,
                    consumed: 0,
                    needs_replenishment: true,
                    current_epoch: 0,
                };
            }
        };

        let available = entries
            .iter()
            .filter(|e| e.status == CredentialStatus::Available)
            .count();
        let active = entries
            .iter()
            .filter(|e| e.status == CredentialStatus::Active)
            .count();
        let consumed = entries
            .iter()
            .filter(|e| e.status == CredentialStatus::Consumed)
            .count();

        let current_epoch = match self.current_epoch.lock() {
            Ok(e) => *e,
            Err(_) => {
                tracing::error!(
                    "SECURITY (R233-SHIELD-5): epoch lock poisoned in status() — reporting epoch 0"
                );
                0
            }
        };

        CredentialVaultStatus {
            total: entries.len(),
            available,
            active,
            consumed,
            needs_replenishment: available < self.replenish_threshold,
            current_epoch,
        }
    }

    /// Get the number of available credentials.
    ///
    /// SECURITY (R236-SHIELD-6): Returns 0 on lock poisoning (fail-closed for
    /// callers that gate on availability) but logs a warning for observability.
    pub fn available_count(&self) -> usize {
        match self.entries.lock() {
            Ok(e) => e
                .iter()
                .filter(|v| v.status == CredentialStatus::Available)
                .count(),
            Err(e) => {
                tracing::error!("credential vault entries lock poisoned in available_count: {e}");
                0
            }
        }
    }

    /// Get the configured pool size.
    pub fn pool_size(&self) -> usize {
        self.pool_size
    }

    /// Generate a local blind credential for self-replenishment.
    ///
    /// Fills 32-byte credential and 64-byte signature from `rand::rng()`.
    /// These are locally generated (not from a blind signature issuer), so
    /// `provider_key_id` is set to `"self-generated"`.
    pub fn generate_local_credential(epoch: u64) -> BlindCredential {
        use rand::RngCore;
        let mut rng = rand::rng();

        let mut credential = vec![0u8; 32];
        rng.fill_bytes(&mut credential);

        let mut signature = vec![0u8; 64];
        rng.fill_bytes(&mut signature);

        BlindCredential {
            credential,
            signature,
            provider_key_id: "self-generated".to_string(),
            issued_epoch: epoch,
            credential_type: vellaveto_types::CredentialType::Subscriber,
        }
    }

    /// Test helper: set all Active credentials' `activated_at` to 0 (epoch start)
    /// so `reclaim_orphaned_active()` treats them as stale.
    #[cfg(test)]
    pub fn force_expire_active_for_test(&self) {
        let mut entries = self.entries.lock().expect("test lock");
        for entry in entries.iter_mut() {
            if entry.status == CredentialStatus::Active {
                entry.activated_at = Some(0);
            }
        }
    }

    /// Replenish the vault with locally generated credentials.
    ///
    /// Generates credentials until the vault has at least `replenish_threshold`
    /// available, up to `pool_size`. Returns the number of credentials added.
    /// No-op if the vault already has enough available credentials.
    pub fn replenish(&self) -> Result<usize, ShieldError> {
        // SECURITY (R233-SHIELD-5): Fail-closed on epoch lock poisoning.
        // unwrap_or(0) would produce born-expired credentials (epoch 0), which
        // causes a starvation cascade: replenish generates creds → expire_old_epochs
        // immediately expires them → replenish runs again → infinite loop.
        let current_epoch = self
            .current_epoch
            .lock()
            .map(|e| *e)
            .map_err(|e| ShieldError::Encryption(format!("epoch lock poisoned: {e}")))?;

        let mut added = 0usize;
        loop {
            let status = self.status();
            if !status.needs_replenishment {
                break;
            }
            if status.total >= self.pool_size {
                break;
            }

            let cred = Self::generate_local_credential(current_epoch);
            self.add_credential(cred)?;
            added = added.saturating_add(1);
        }

        Ok(added)
    }

    /// Reclaim orphaned Active credentials that have exceeded their TTL.
    ///
    /// SECURITY (R250-NHI-3): If a session crashes after `consume_credential()` without
    /// calling `mark_consumed()`, the credential stays Active forever, permanently
    /// draining the pool. This method transitions stale Active credentials to Expired,
    /// freeing them from the pool and preventing credential exhaustion DoS.
    ///
    /// Returns the number of credentials reclaimed.
    pub fn reclaim_orphaned_active(&self) -> Result<usize, ShieldError> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut entries = self
            .entries
            .lock()
            .map_err(|e| ShieldError::Encryption(format!("vault lock poisoned: {e}")))?;

        let mut reclaimed_indices = Vec::new();
        for (idx, entry) in entries.iter().enumerate() {
            if entry.status == CredentialStatus::Active {
                let orphaned = match entry.activated_at {
                    Some(ts) => now_secs.saturating_sub(ts) > MAX_ACTIVE_AGE_SECS,
                    // No timestamp means legacy entry — treat as orphaned if Active
                    None => true,
                };
                if orphaned {
                    reclaimed_indices.push(idx);
                }
            }
        }

        if reclaimed_indices.is_empty() {
            return Ok(0);
        }

        for &idx in &reclaimed_indices {
            entries[idx].status = CredentialStatus::Expired;
            entries[idx].activated_at = None;
        }

        let count = reclaimed_indices.len();

        if let Err(e) = self.persist_entries(&entries) {
            // Rollback on persist failure
            for &idx in &reclaimed_indices {
                entries[idx].status = CredentialStatus::Active;
                // Cannot restore original activated_at, but these were orphaned anyway
            }
            return Err(e);
        }

        Ok(count)
    }
}

impl std::fmt::Debug for CredentialVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = self.status();
        f.debug_struct("CredentialVault")
            .field("total", &status.total)
            .field("available", &status.available)
            .field("active", &status.active)
            .field("needs_replenishment", &status.needs_replenishment)
            .finish()
    }
}

/// Serializable vault entry for encrypted storage.
// SECURITY (R234-SHIELD-2): Reject unknown fields to prevent attacker-injected
// fields from surviving deserialization when loading from encrypted store.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredVaultEntry {
    credential: BlindCredential,
    status: CredentialStatus,
    /// SECURITY (R250-NHI-3): Timestamp when credential became Active.
    /// Default to None for backward compatibility with pre-R250 vault files.
    #[serde(default)]
    activated_at: Option<u64>,
}
