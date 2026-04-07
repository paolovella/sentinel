// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Persistent storage for ETDI state.
//!
//! Stores signatures, attestations, and version pins to disk using
//! HMAC-protected JSONL format (same pattern as tool_registry).

use crate::etdi::EtdiError;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;
use vellaveto_types::{ToolAttestation, ToolSignature, ToolVersionPin};

type HmacSha256 = Hmac<Sha256>;

/// SECURITY (FIND-R69-006): Maximum entries per ETDI store map to prevent OOM.
const MAX_ETDI_ENTRIES: usize = 50_000;

/// SECURITY (FIND-R69-006): Maximum attestations per tool.
const MAX_ATTESTATIONS_PER_TOOL: usize = 100;

/// Entry type marker for the store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
enum StoreEntry {
    #[serde(rename = "signature")]
    Signature { tool: String, data: ToolSignature },
    #[serde(rename = "attestation")]
    Attestation { tool: String, data: ToolAttestation },
    #[serde(rename = "pin")]
    Pin { tool: String, data: ToolVersionPin },
}

/// Persistent storage for ETDI state.
///
/// Uses JSONL format with optional HMAC protection for tamper detection.
pub struct EtdiStore {
    /// Path to the data directory.
    data_path: PathBuf,
    /// Tool signatures (tool_name -> signature).
    signatures: RwLock<HashMap<String, ToolSignature>>,
    /// Tool attestations (tool_name -> list of attestations).
    attestations: RwLock<HashMap<String, Vec<ToolAttestation>>>,
    /// Version pins (tool_name -> pin).
    pins: RwLock<HashMap<String, ToolVersionPin>>,
    /// HMAC key for integrity protection.
    hmac_key: Option<[u8; 32]>,
}

impl EtdiStore {
    /// Create a new store at the given path.
    pub fn new<P: AsRef<Path>>(data_path: P) -> Self {
        Self {
            data_path: data_path.as_ref().to_path_buf(),
            signatures: RwLock::new(HashMap::new()),
            attestations: RwLock::new(HashMap::new()),
            pins: RwLock::new(HashMap::new()),
            hmac_key: None,
        }
    }

    /// Set the HMAC key for integrity protection.
    pub fn with_hmac_key(mut self, key: [u8; 32]) -> Self {
        self.hmac_key = Some(key);
        self
    }

    /// Load all state from disk.
    pub async fn load(&self) -> Result<(), EtdiError> {
        let store_path = self.data_path.join("etdi_store.jsonl");
        if !store_path.exists() {
            return Ok(()); // No data yet
        }

        let file = fs::File::open(&store_path).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let mut signatures = self.signatures.write().await;
        let mut attestations = self.attestations.write().await;
        let mut pins = self.pins.write().await;

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }

            let (json_part, hmac_part) = self.split_line_hmac(&line);

            // Verify HMAC if key is set
            if let Some(ref key) = self.hmac_key {
                if let Some(hmac_hex) = hmac_part {
                    if !self.verify_hmac(key, json_part, hmac_hex) {
                        tracing::warn!("ETDI store line failed HMAC verification, skipping");
                        continue;
                    }
                } else {
                    tracing::warn!("ETDI store line missing HMAC, skipping");
                    continue;
                }
            }

            match serde_json::from_str::<StoreEntry>(json_part) {
                Ok(StoreEntry::Signature { tool, data }) => {
                    // SECURITY (FIND-R69-006): Cap loaded entries.
                    if signatures.len() < MAX_ETDI_ENTRIES {
                        signatures.insert(tool, data);
                    }
                }
                Ok(StoreEntry::Attestation { tool, data }) => {
                    if attestations.len() < MAX_ETDI_ENTRIES {
                        let entry = attestations.entry(tool).or_default();
                        if entry.len() < MAX_ATTESTATIONS_PER_TOOL {
                            entry.push(data);
                        }
                    }
                }
                Ok(StoreEntry::Pin { tool, data }) => {
                    if pins.len() < MAX_ETDI_ENTRIES {
                        pins.insert(tool, data);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to parse ETDI store entry: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Save a signature to the store.
    pub async fn save_signature(
        &self,
        tool: &str,
        signature: ToolSignature,
    ) -> Result<(), EtdiError> {
        let entry = StoreEntry::Signature {
            tool: tool.to_string(),
            data: signature.clone(),
        };
        let mut sigs = self.signatures.write().await;
        // SECURITY (FIND-R69-006): Reject new signatures at capacity.
        if !sigs.contains_key(tool) && sigs.len() >= MAX_ETDI_ENTRIES {
            return Err(EtdiError::StoreFull(format!(
                "ETDI signature store at capacity ({MAX_ETDI_ENTRIES})",
            )));
        }
        self.append_entry(&entry).await?;
        sigs.insert(tool.to_string(), signature);
        Ok(())
    }

    /// Save an attestation to the store.
    pub async fn save_attestation(
        &self,
        tool: &str,
        attestation: ToolAttestation,
    ) -> Result<(), EtdiError> {
        let entry = StoreEntry::Attestation {
            tool: tool.to_string(),
            data: attestation.clone(),
        };
        let mut atts = self.attestations.write().await;
        // SECURITY (FIND-R69-006): Reject new attestations at capacity.
        if !atts.contains_key(tool) && atts.len() >= MAX_ETDI_ENTRIES {
            return Err(EtdiError::StoreFull(format!(
                "ETDI attestation store at capacity ({MAX_ETDI_ENTRIES})",
            )));
        }
        let tool_atts = atts.entry(tool.to_string()).or_default();
        if tool_atts.len() >= MAX_ATTESTATIONS_PER_TOOL {
            return Err(EtdiError::StoreFull(format!(
                "ETDI attestations per tool at capacity ({MAX_ATTESTATIONS_PER_TOOL})",
            )));
        }
        self.append_entry(&entry).await?;
        tool_atts.push(attestation);
        Ok(())
    }

    /// Save a version pin to the store.
    pub async fn save_pin(&self, pin: ToolVersionPin) -> Result<(), EtdiError> {
        let entry = StoreEntry::Pin {
            tool: pin.tool_name.clone(),
            data: pin.clone(),
        };
        let mut pins = self.pins.write().await;
        // SECURITY (FIND-R69-006): Reject new pins at capacity.
        if !pins.contains_key(&pin.tool_name) && pins.len() >= MAX_ETDI_ENTRIES {
            return Err(EtdiError::StoreFull(format!(
                "ETDI pin store at capacity ({MAX_ETDI_ENTRIES})",
            )));
        }
        self.append_entry(&entry).await?;
        pins.insert(pin.tool_name.clone(), pin);
        Ok(())
    }

    /// Remove a version pin.
    pub async fn remove_pin(&self, tool: &str) -> Result<bool, EtdiError> {
        let removed = {
            let mut pins = self.pins.write().await;
            pins.remove(tool).is_some()
        }; // Write lock released here

        if removed {
            // Rewrite entire file without this pin
            self.rewrite_store().await?;
        }

        Ok(removed)
    }

    /// Get a signature for a tool.
    pub async fn get_signature(&self, tool: &str) -> Option<ToolSignature> {
        self.signatures.read().await.get(tool).cloned()
    }

    /// Get all signatures.
    pub async fn list_signatures(&self) -> Vec<(String, ToolSignature)> {
        self.signatures
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Get attestations for a tool.
    pub async fn get_attestations(&self, tool: &str) -> Vec<ToolAttestation> {
        self.attestations
            .read()
            .await
            .get(tool)
            .cloned()
            .unwrap_or_default()
    }

    /// Get all attestations.
    pub async fn list_attestations(&self) -> Vec<(String, Vec<ToolAttestation>)> {
        self.attestations
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Get a version pin for a tool.
    pub async fn get_pin(&self, tool: &str) -> Option<ToolVersionPin> {
        self.pins.read().await.get(tool).cloned()
    }

    /// Get all version pins.
    pub async fn list_pins(&self) -> Vec<ToolVersionPin> {
        self.pins.read().await.values().cloned().collect()
    }

    /// Append an entry to the store file.
    async fn append_entry(&self, entry: &StoreEntry) -> Result<(), EtdiError> {
        // Ensure directory exists
        fs::create_dir_all(&self.data_path).await?;

        let store_path = self.data_path.join("etdi_store.jsonl");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&store_path)
            .await?;

        let json = serde_json::to_string(entry)?;
        let line = if let Some(ref key) = self.hmac_key {
            let hmac = self.compute_hmac(key, &json)?;
            format!("{json}\t{hmac}\n")
        } else {
            format!("{json}\n")
        };

        file.write_all(line.as_bytes()).await?;
        file.flush().await?;

        Ok(())
    }

    /// Rewrite the entire store (used after deletions).
    async fn rewrite_store(&self) -> Result<(), EtdiError> {
        fs::create_dir_all(&self.data_path).await?;

        let store_path = self.data_path.join("etdi_store.jsonl");
        let temp_path = self.data_path.join("etdi_store.jsonl.tmp");

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)
            .await?;

        // Write signatures
        for (tool, sig) in self.signatures.read().await.iter() {
            let entry = StoreEntry::Signature {
                tool: tool.clone(),
                data: sig.clone(),
            };
            self.write_entry(&mut file, &entry).await?;
        }

        // Write attestations
        for (tool, atts) in self.attestations.read().await.iter() {
            for att in atts {
                let entry = StoreEntry::Attestation {
                    tool: tool.clone(),
                    data: att.clone(),
                };
                self.write_entry(&mut file, &entry).await?;
            }
        }

        // Write pins
        for pin in self.pins.read().await.values() {
            let entry = StoreEntry::Pin {
                tool: pin.tool_name.clone(),
                data: pin.clone(),
            };
            self.write_entry(&mut file, &entry).await?;
        }

        file.flush().await?;
        drop(file);

        // Atomic rename
        fs::rename(&temp_path, &store_path).await?;

        Ok(())
    }

    async fn write_entry(&self, file: &mut fs::File, entry: &StoreEntry) -> Result<(), EtdiError> {
        let json = serde_json::to_string(entry)?;
        let line = if let Some(ref key) = self.hmac_key {
            let hmac = self.compute_hmac(key, &json)?;
            format!("{json}\t{hmac}\n")
        } else {
            format!("{json}\n")
        };
        file.write_all(line.as_bytes()).await?;
        Ok(())
    }

    fn split_line_hmac<'a>(&self, line: &'a str) -> (&'a str, Option<&'a str>) {
        if let Some(tab_pos) = line.rfind('\t') {
            (&line[..tab_pos], Some(&line[tab_pos + 1..]))
        } else {
            (line, None)
        }
    }

    // SECURITY (FIND-027): Return Result instead of panicking on HMAC init failure.
    fn compute_hmac(&self, key: &[u8; 32], data: &str) -> Result<String, EtdiError> {
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| EtdiError::HmacInit)?;
        mac.update(data.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    // SECURITY (FIND-027): Fail-closed on HMAC init failure (returns false).
    fn verify_hmac(&self, key: &[u8; 32], data: &str, expected_hex: &str) -> bool {
        let Ok(expected) = hex::decode(expected_hex) else {
            return false;
        };
        let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
            // Fail-closed: treat HMAC init failure as verification failure
            return false;
        };
        mac.update(data.as_bytes());
        mac.verify_slice(&expected).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use vellaveto_types::SignatureAlgorithm;

    fn test_signature() -> ToolSignature {
        ToolSignature {
            signature_id: "sig-1".to_string(),
            signature: "abc123".to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: "key123".to_string(),
            key_fingerprint: Some("fp".to_string()),
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
            signer_spiffe_id: None,
            rekor_entry: None,
        }
    }

    fn test_pin() -> ToolVersionPin {
        ToolVersionPin {
            tool_name: "test_tool".to_string(),
            pinned_version: Some("1.0.0".to_string()),
            version_constraint: None,
            definition_hash: "hash123".to_string(),
            pinned_at: "2026-01-01T00:00:00Z".to_string(),
            pinned_by: "admin".to_string(),
        }
    }

    #[tokio::test]
    async fn test_store_save_and_load_signature() {
        let dir = TempDir::new().unwrap();
        let store = EtdiStore::new(dir.path());

        let sig = test_signature();
        store.save_signature("my_tool", sig.clone()).await.unwrap();

        // Create new store and load
        let store2 = EtdiStore::new(dir.path());
        store2.load().await.unwrap();

        let loaded = store2.get_signature("my_tool").await.unwrap();
        assert_eq!(loaded.signature_id, sig.signature_id);
    }

    #[tokio::test]
    async fn test_store_save_and_load_pin() {
        let dir = TempDir::new().unwrap();
        let store = EtdiStore::new(dir.path());

        let pin = test_pin();
        store.save_pin(pin.clone()).await.unwrap();

        let store2 = EtdiStore::new(dir.path());
        store2.load().await.unwrap();

        let loaded = store2.get_pin("test_tool").await.unwrap();
        assert_eq!(loaded.pinned_version, pin.pinned_version);
    }

    #[tokio::test]
    async fn test_store_remove_pin() {
        let dir = TempDir::new().unwrap();
        let store = EtdiStore::new(dir.path());

        let pin = test_pin();
        store.save_pin(pin).await.unwrap();
        assert!(store.get_pin("test_tool").await.is_some());

        store.remove_pin("test_tool").await.unwrap();
        assert!(store.get_pin("test_tool").await.is_none());

        // Verify persistence
        let store2 = EtdiStore::new(dir.path());
        store2.load().await.unwrap();
        assert!(store2.get_pin("test_tool").await.is_none());
    }

    #[tokio::test]
    async fn test_store_with_hmac() {
        let dir = TempDir::new().unwrap();
        let key = [0u8; 32];
        let store = EtdiStore::new(dir.path()).with_hmac_key(key);

        let sig = test_signature();
        store.save_signature("tool", sig.clone()).await.unwrap();

        // Load with same key should work
        let store2 = EtdiStore::new(dir.path()).with_hmac_key(key);
        store2.load().await.unwrap();
        assert!(store2.get_signature("tool").await.is_some());
    }

    #[tokio::test]
    async fn test_store_wrong_hmac_key_rejects() {
        let dir = TempDir::new().unwrap();
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];

        let store = EtdiStore::new(dir.path()).with_hmac_key(key1);
        let sig = test_signature();
        store.save_signature("tool", sig).await.unwrap();

        // Load with different key should reject
        let store2 = EtdiStore::new(dir.path()).with_hmac_key(key2);
        store2.load().await.unwrap();
        assert!(store2.get_signature("tool").await.is_none());
    }

    #[tokio::test]
    async fn test_list_signatures() {
        let dir = TempDir::new().unwrap();
        let store = EtdiStore::new(dir.path());

        store
            .save_signature("tool1", test_signature())
            .await
            .unwrap();
        let mut sig2 = test_signature();
        sig2.signature_id = "sig-2".to_string();
        store.save_signature("tool2", sig2).await.unwrap();

        let sigs = store.list_signatures().await;
        assert_eq!(sigs.len(), 2);
    }

    #[tokio::test]
    async fn test_list_pins() {
        let dir = TempDir::new().unwrap();
        let store = EtdiStore::new(dir.path());

        let mut pin1 = test_pin();
        pin1.tool_name = "tool1".to_string();
        let mut pin2 = test_pin();
        pin2.tool_name = "tool2".to_string();

        store.save_pin(pin1).await.unwrap();
        store.save_pin(pin2).await.unwrap();

        let pins = store.list_pins().await;
        assert_eq!(pins.len(), 2);
    }
}
