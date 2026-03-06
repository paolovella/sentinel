// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

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

/// A single vault entry: credential + status.
#[derive(Clone)]
struct VaultEntry {
    credential: BlindCredential,
    status: CredentialStatus,
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
                "vault capacity exhausted (max {})",
                MAX_VAULT_ENTRIES
            )));
        }

        // Update epoch tracker
        if let Ok(mut epoch) = self.current_epoch.lock() {
            if credential.issued_epoch > *epoch {
                *epoch = credential.issued_epoch;
            }
        }

        let stored = StoredVaultEntry {
            credential: credential.clone(),
            status: CredentialStatus::Available,
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
        });

        Ok(())
    }

    /// Consume the next available credential for a new session.
    ///
    /// Returns the credential and its vault index. The credential is
    /// marked as Active. Returns an error if no credentials are available
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
        Ok((entries[idx].credential.clone(), idx))
    }

    /// Mark a credential as consumed (session ended normally).
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

        entries[index].status = CredentialStatus::Consumed;
        Ok(())
    }

    /// Expire credentials from epochs older than the given epoch.
    pub fn expire_old_epochs(&self, current_epoch: u64) -> Result<usize, ShieldError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|e| ShieldError::Encryption(format!("vault lock poisoned: {e}")))?;

        let mut expired_count = 0usize;
        for entry in entries.iter_mut() {
            if entry.status == CredentialStatus::Available
                && entry.credential.issued_epoch < current_epoch
            {
                entry.status = CredentialStatus::Expired;
                expired_count = expired_count.saturating_add(1);
            }
        }

        // Update epoch
        if let Ok(mut epoch) = self.current_epoch.lock() {
            if current_epoch > *epoch {
                *epoch = current_epoch;
            }
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

        let current_epoch = self.current_epoch.lock().map(|e| *e).unwrap_or(0);

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
    pub fn available_count(&self) -> usize {
        self.entries
            .lock()
            .map(|e| {
                e.iter()
                    .filter(|v| v.status == CredentialStatus::Available)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Get the configured pool size.
    pub fn pool_size(&self) -> usize {
        self.pool_size
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
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredVaultEntry {
    credential: BlindCredential,
    status: CredentialStatus,
}
