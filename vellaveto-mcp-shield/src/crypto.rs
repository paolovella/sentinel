// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Encrypted audit store using XChaCha20-Poly1305 with Argon2id key derivation.

use crate::error::ShieldError;
use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use std::path::PathBuf;

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
        let salt = if path.exists() {
            Self::read_salt(&path)?
        } else {
            let mut salt = [0u8; SALT_LEN];
            rand::thread_rng().fill_bytes(&mut salt);
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
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
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
        let len = (encrypted.len() as u32).to_le_bytes();

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(ShieldError::Io)?;
        file.write_all(&len).map_err(ShieldError::Io)?;
        file.write_all(&encrypted).map_err(ShieldError::Io)?;
        Ok(())
    }

    /// Read and decrypt all entries from the store.
    pub fn read_all_entries(&self) -> Result<Vec<Vec<u8>>, ShieldError> {
        let data = std::fs::read(&self.path).map_err(ShieldError::Io)?;
        let header_len = 1 + SALT_LEN;
        if data.len() < header_len {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let mut offset = header_len;
        while offset + 4 <= data.len() {
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
        // Zeroize key material
        self.key.fill(0);
    }
}
