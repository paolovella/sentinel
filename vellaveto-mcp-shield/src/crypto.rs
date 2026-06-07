// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Encrypted audit store using XChaCha20-Poly1305 with Argon2id key derivation.

use crate::error::ShieldError;
use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::Rng;
use std::path::PathBuf;
use zeroize::Zeroize;

/// File format version byte.
const FORMAT_VERSION: u8 = 1;

/// Argon2id salt length in bytes.
const SALT_LEN: usize = 16;

/// XChaCha20-Poly1305 nonce length in bytes.
const NONCE_LEN: usize = 24;

/// Argon2id parameters (OWASP recommended minimums).
const ARGON2_MEM_COST: u32 = 19_456; // 19 MiB
const ARGON2_TIME_COST: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;

/// Encrypted audit store with XChaCha20-Poly1305 encryption and Argon2id KDF.
pub struct EncryptedAuditStore {
    path: PathBuf,
    key: [u8; 32],
    #[allow(dead_code)]
    salt: [u8; SALT_LEN],
}

impl EncryptedAuditStore {
    /// Create a new encrypted store at the given path.
    ///
    /// If the file exists, reads the salt from it. Otherwise generates a new salt.
    /// Derives the encryption key from the passphrase via Argon2id.
    pub fn new(path: PathBuf, passphrase: &str) -> Result<Self, ShieldError> {
        // SECURITY (R240-SHLD-2): Reject path traversal in store path.
        // A malicious path could write encrypted audit data to sensitive locations.
        for component in path.components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(ShieldError::SessionIsolation(
                    "store path must not contain '..' path traversal components".to_string(),
                ));
            }
        }

        // SECURITY (R234-SHIELD-3): Reject empty/whitespace-only passphrases.
        // An empty passphrase produces a deterministic key (only salt-dependent),
        // which provides zero user-derived entropy.
        if passphrase.trim().is_empty() {
            return Err(ShieldError::KeyDerivation(
                "passphrase must not be empty or whitespace-only".to_string(),
            ));
        }
        // SECURITY (R259-SHLD-1): Enforce minimum passphrase length.
        // Even with Argon2id, short passphrases (1-11 chars) are vulnerable to
        // offline dictionary attacks if the encrypted store file is exfiltrated.
        const MIN_PASSPHRASE_LEN: usize = 12;
        if passphrase.len() < MIN_PASSPHRASE_LEN {
            return Err(ShieldError::KeyDerivation(format!(
                "passphrase must be at least {} characters, got {}",
                MIN_PASSPHRASE_LEN,
                passphrase.len()
            )));
        }

        let salt = if path.exists() {
            Self::read_salt(&path)?
        } else {
            let mut salt = [0u8; SALT_LEN];
            rand::rng().fill_bytes(&mut salt);
            // Write header: version + salt
            let mut header = vec![FORMAT_VERSION];
            header.extend_from_slice(&salt);
            std::fs::write(&path, &header).map_err(ShieldError::Io)?;
            salt
        };

        let key = Self::derive_key(passphrase, &salt)?;

        Ok(Self { path, key, salt })
    }

    /// Derive a 32-byte key from passphrase and salt via Argon2id.
    fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; 32], ShieldError> {
        let params = argon2::Params::new(
            ARGON2_MEM_COST,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(32),
        )
        .map_err(|e| ShieldError::KeyDerivation(format!("argon2 params: {e}")))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut output = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut output)
            .map_err(|e| ShieldError::KeyDerivation(format!("argon2 hash: {e}")))?;
        Ok(output)
    }

    /// Read salt from an existing file header.
    fn read_salt(path: &PathBuf) -> Result<[u8; SALT_LEN], ShieldError> {
        let data = std::fs::read(path).map_err(ShieldError::Io)?;
        if data.len() < 1 + SALT_LEN {
            return Err(ShieldError::Decryption(
                "file too short for header".to_string(),
            ));
        }
        if data[0] != FORMAT_VERSION {
            return Err(ShieldError::Decryption(format!(
                "unsupported format version: {}",
                data[0]
            )));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&data[1..1 + SALT_LEN]);
        Ok(salt)
    }

    /// Encrypt a plaintext entry.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, ShieldError> {
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| ShieldError::Encryption(format!("encrypt: {e}")))?;

        // nonce || ciphertext (includes tag)
        let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt a ciphertext entry (nonce || ciphertext || tag).
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, ShieldError> {
        if data.len() < NONCE_LEN {
            return Err(ShieldError::Decryption(
                "data too short for nonce".to_string(),
            ));
        }
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let nonce = XNonce::from_slice(&data[..NONCE_LEN]);
        let ciphertext = &data[NONCE_LEN..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| ShieldError::Decryption(format!("decrypt: {e}")))
    }

    /// Append an encrypted entry to the store file.
    pub fn write_encrypted_entry(&self, plaintext: &[u8]) -> Result<(), ShieldError> {
        let encrypted = self.encrypt(plaintext)?;
        // SECURITY (R234-SHIELD-5): Use try_from instead of `as u32` to prevent
        // silent truncation on entries larger than 4 GB.
        let len = u32::try_from(encrypted.len())
            .map_err(|_| {
                ShieldError::Encryption("encrypted entry too large for u32 length".to_string())
            })?
            .to_le_bytes();

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(ShieldError::Io)?;
        file.write_all(&len).map_err(ShieldError::Io)?;
        file.write_all(&encrypted).map_err(ShieldError::Io)?;
        // SECURITY (R237-SHIELD-6): Flush and fsync to ensure durability.
        // Without fsync, a power loss or crash can silently lose audit entries
        // even though the function returned Ok(()).
        file.flush().map_err(ShieldError::Io)?;
        file.sync_data().map_err(ShieldError::Io)?;
        Ok(())
    }

    /// Maximum number of entries to read from the store.
    /// Prevents unbounded memory growth from a maliciously large store file.
    const MAX_STORE_ENTRIES: usize = 100_000;

    /// Maximum store file size (256 MB).
    /// SECURITY (R238-SHLD-5): Prevents loading a maliciously large store file
    /// into memory. Checked before `std::fs::read()` to avoid the allocation.
    const MAX_STORE_FILE_SIZE: u64 = 256 * 1024 * 1024;

    /// Read and decrypt all entries from the store.
    pub fn read_all_entries(&self) -> Result<Vec<Vec<u8>>, ShieldError> {
        // SECURITY (R238-SHLD-5): Check file size before reading to prevent
        // unbounded memory allocation from a maliciously large store file.
        let metadata = std::fs::metadata(&self.path).map_err(ShieldError::Io)?;
        if metadata.len() > Self::MAX_STORE_FILE_SIZE {
            return Err(ShieldError::Decryption(format!(
                "store file too large ({} bytes, max {} bytes)",
                metadata.len(),
                Self::MAX_STORE_FILE_SIZE
            )));
        }

        let data = std::fs::read(&self.path).map_err(ShieldError::Io)?;
        let header_len = 1 + SALT_LEN;
        if data.len() < header_len {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let mut offset = header_len;
        while offset + 4 <= data.len() {
            // SECURITY (R234-SHIELD-10): Bound entry count to prevent DoS from
            // a maliciously crafted store file with millions of small entries.
            if entries.len() >= Self::MAX_STORE_ENTRIES {
                return Err(ShieldError::Decryption(format!(
                    "store contains more than {} entries (possible corruption or attack)",
                    Self::MAX_STORE_ENTRIES
                )));
            }
            let len = u32::from_le_bytes(
                data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| ShieldError::Decryption("invalid entry length".to_string()))?,
            ) as usize;
            offset += 4;
            if offset + len > data.len() {
                return Err(ShieldError::Decryption("truncated entry".to_string()));
            }
            let plaintext = self.decrypt(&data[offset..offset + len])?;
            entries.push(plaintext);
            offset += len;
        }
        Ok(entries)
    }

    /// Rewrite the store file with a new set of entries, replacing all existing data.
    ///
    /// SECURITY (R234-SHIELD-1): Used to persist credential status changes so
    /// that consumed credentials cannot be reused after a crash.
    /// Writes to a temp file and atomically renames to prevent data loss.
    pub fn rewrite_all_entries(&self, entries: &[Vec<u8>]) -> Result<(), ShieldError> {
        let temp_path = self.path.with_extension("tmp");

        // SECURITY (R237-SHLD-2): Cleanup guard removes temp file on error to prevent
        // partial encrypted data from persisting on disk after failed rewrites.
        let cleanup_result = (|| -> Result<(), ShieldError> {
            // Write header: version + salt
            let mut header = vec![FORMAT_VERSION];
            header.extend_from_slice(&self.salt);
            std::fs::write(&temp_path, &header).map_err(ShieldError::Io)?;

            // Append each entry
            {
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&temp_path)
                    .map_err(ShieldError::Io)?;
                for entry in entries {
                    let encrypted = self.encrypt(entry)?;
                    let len = u32::try_from(encrypted.len()).map_err(|_| {
                        ShieldError::Encryption(
                            "encrypted entry too large for u32 length".to_string(),
                        )
                    })?;
                    file.write_all(&len.to_le_bytes())
                        .map_err(ShieldError::Io)?;
                    file.write_all(&encrypted).map_err(ShieldError::Io)?;
                }
                // SECURITY (R237-SHIELD-6): Fsync temp file before atomic rename
                // to ensure data is durable before the old file is replaced.
                file.flush().map_err(ShieldError::Io)?;
                file.sync_data().map_err(ShieldError::Io)?;
            }

            // Atomic rename
            std::fs::rename(&temp_path, &self.path).map_err(ShieldError::Io)?;
            Ok(())
        })();

        if cleanup_result.is_err() {
            // Remove orphaned temp file on error
            let _ = std::fs::remove_file(&temp_path);
        }
        cleanup_result
    }

    /// Get the store file path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl std::fmt::Debug for EncryptedAuditStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedAuditStore")
            .field("path", &self.path)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for EncryptedAuditStore {
    fn drop(&mut self) {
        // SECURITY (R256-SHIELD-1): zeroize avoids optimizer-elided key clearing
        // without requiring manual unsafe volatile writes in this crate.
        self.key.zeroize();
    }
}
