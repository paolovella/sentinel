// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tool Registry with Trust Scoring (P2.1).
//!
//! Implements a local tool registry that tracks tool definitions, their hashes,
//! and computes a trust score based on age, stability, and admin approval.
//! Tools below a configurable trust threshold require human approval regardless
//! of policy verdict.
//!
//! # Trust Score Calculation
//!
//! - Base: 0.5
//! - +0.1 for age > 7 days
//! - +0.1 for age > 30 days
//! - +0.2 for admin_approved = true
//! - -0.3 for each schema change (rug-pull)
//! - -0.2 if flagged for squatting
//! - Clamped to [0.0, 1.0]
//!
//! # Persistence
//!
//! The registry is persisted to a JSONL file (one entry per tool). On startup,
//! existing entries are loaded and trust scores recomputed from current timestamps.

use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;

type HmacSha256 = Hmac<Sha256>;

/// Errors that can occur in registry operations.
#[derive(Error, Debug)]
pub enum RegistryError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Tool not found: {0}")]
    NotFound(String),
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),
    #[error("HMAC initialization failed")]
    HmacInit,
}

/// Default trust threshold below which tools require approval.
pub const DEFAULT_TRUST_THRESHOLD: f32 = 0.3;

/// Maximum number of entries in the tool registry.
/// Prevents unbounded memory growth from auto-registration via evaluate endpoint.
pub const MAX_REGISTRY_ENTRIES: usize = 10_000;
/// Initial in-memory capacity for registry maps.
const INITIAL_REGISTRY_CAPACITY: usize = 512;

/// Result of checking a tool's trust level in the registry.
#[derive(Debug, Clone, PartialEq)]
pub enum TrustLevel {
    /// Tool is not in the registry at all.
    Unknown,
    /// Tool is in the registry but below the trust threshold.
    Untrusted { score: f32 },
    /// Tool is in the registry and at or above the trust threshold.
    Trusted,
}

/// A single tool entry in the registry.
/// SECURITY (FIND-R70-001): deny_unknown_fields on deserialized registry entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolEntry {
    /// Tool name (identifier).
    pub tool_id: String,
    /// SHA-256 hash of the tool's inputSchema (canonical JSON).
    pub schema_hash: String,
    /// When this tool was first seen.
    pub first_seen: String,
    /// When this tool was last seen in a tools/list response.
    pub last_seen: String,
    /// Number of times this tool has been called.
    pub call_count: u64,
    /// Number of times the schema has changed (rug-pull detection).
    pub schema_change_count: u64,
    /// Whether an admin has explicitly approved this tool.
    pub admin_approved: bool,
    /// Whether this tool has been flagged for squatting.
    #[serde(default)]
    pub flagged_for_squatting: bool,
    /// Computed trust score (0.0 to 1.0). Recomputed on load.
    #[serde(default = "default_trust_score")]
    pub trust_score: f32,

    // ═══════════════════════════════════════════════════
    // Server Origin Binding (SANDWORM-001)
    // ═══════════════════════════════════════════════════
    /// The MCP server that originally registered this tool.
    ///
    /// SECURITY (SANDWORM-001): Binds tools to their originating server so that
    /// squatting detection can distinguish identical tool names from different
    /// servers. A tool seen from multiple servers is suspicious and penalized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    /// Whether this tool has been seen from a different server than `server_id`.
    ///
    /// SECURITY (SANDWORM-001): Indicates a possible rogue MCP server attempting
    /// to shadow a legitimate tool. Penalized -0.3 in trust score.
    #[serde(default)]
    pub server_id_conflict: bool,

    // ═══════════════════════════════════════════════════
    // ETDI (Enhanced Tool Definition Interface) Fields
    // ═══════════════════════════════════════════════════
    /// ETDI signature for this tool (from tool provider).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<vellaveto_types::ToolSignature>,
    /// Whether the ETDI signature has been verified as cryptographically valid.
    #[serde(default)]
    pub signature_verified: bool,
    /// Whether the signer is in the trusted signers list.
    #[serde(default)]
    pub signer_trusted: bool,
    /// Tool version string (from tool metadata, if provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Whether this tool is version-pinned.
    #[serde(default)]
    pub version_pinned: bool,
}

fn default_trust_score() -> f32 {
    0.5
}

impl ToolEntry {
    /// Create a new tool entry with default values.
    pub fn new(tool_id: String, schema_hash: String) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            tool_id,
            schema_hash,
            first_seen: now.clone(),
            last_seen: now,
            call_count: 0,
            schema_change_count: 0,
            admin_approved: false,
            flagged_for_squatting: false,
            trust_score: 0.5, // Will be recomputed
            // Server origin binding (SANDWORM-001)
            server_id: None,
            server_id_conflict: false,
            // ETDI fields
            signature: None,
            signature_verified: false,
            signer_trusted: false,
            version: None,
            version_pinned: false,
        }
    }

    /// Create a new tool entry with ETDI signature.
    pub fn new_with_signature(
        tool_id: String,
        schema_hash: String,
        signature: vellaveto_types::ToolSignature,
        signature_verified: bool,
        signer_trusted: bool,
    ) -> Self {
        let mut entry = Self::new(tool_id, schema_hash);
        entry.signature = Some(signature);
        entry.signature_verified = signature_verified;
        entry.signer_trusted = signer_trusted;
        entry
    }

    /// Set the ETDI signature verification result.
    pub fn set_signature_verification(
        &mut self,
        signature: vellaveto_types::ToolSignature,
        verified: bool,
        trusted: bool,
    ) {
        self.signature = Some(signature);
        self.signature_verified = verified;
        self.signer_trusted = trusted;
    }

    /// Set the tool version.
    pub fn set_version(&mut self, version: String) {
        self.version = Some(version);
    }

    /// Mark this tool as version-pinned.
    pub fn set_version_pinned(&mut self, pinned: bool) {
        self.version_pinned = pinned;
    }

    /// Returns true if the tool has a valid, trusted signature.
    pub fn is_etdi_verified(&self) -> bool {
        self.signature_verified && self.signer_trusted
    }

    /// Compute the trust score based on current state and timestamps.
    ///
    /// # Trust Score Formula
    ///
    /// - Base: 0.5
    /// - +0.1 for age > 7 days
    /// - +0.1 for age > 30 days
    /// - +0.2 for admin_approved = true
    /// - +0.2 for ETDI verified and trusted signature
    /// - +0.1 for version_pinned = true
    /// - -0.3 for each schema change (rug-pull)
    /// - -0.2 if flagged for squatting
    /// - -0.3 if server_id_conflict (SANDWORM-001: seen from multiple servers)
    /// - Clamped to [0.0, 1.0]
    pub fn compute_trust_score(&mut self) {
        let mut score: f32 = 0.5;

        // Age bonuses
        if let Ok(first_seen) = DateTime::parse_from_rfc3339(&self.first_seen) {
            let age = Utc::now().signed_duration_since(first_seen);
            // SECURITY (R28-MCP-2): Reject future first_seen timestamps, which
            // indicate tampering of the persistence file to inflate trust scores.
            if age < Duration::zero() {
                tracing::warn!(
                    "Tool '{}' first_seen is in the future — possible tampering",
                    self.tool_id,
                );
                // SECURITY (R29-MCP-5): Penalize to minimum trust when tampering
                // detected — the entire persistence entry is untrustworthy.
                score = 0.0;
            } else {
                if age > Duration::days(7) {
                    score += 0.1;
                }
                if age > Duration::days(30) {
                    score += 0.1;
                }
            }
        }

        // Admin approval bonus
        if self.admin_approved {
            score += 0.2;
        }

        // ETDI signature verification bonus
        if self.is_etdi_verified() {
            score += 0.2;
        }

        // Version pinning bonus
        if self.version_pinned {
            score += 0.1;
        }

        // Schema change penalty (-0.3 per change)
        score -= 0.3 * self.schema_change_count as f32;

        // Squatting penalty
        if self.flagged_for_squatting {
            score -= 0.2;
        }

        // SECURITY (SANDWORM-001): Server origin conflict penalty.
        // A tool seen from multiple servers indicates a possible rogue MCP
        // server attempting to shadow a legitimate tool.
        if self.server_id_conflict {
            score -= 0.3;
        }

        // Clamp to [0.0, 1.0]
        self.trust_score = score.clamp(0.0, 1.0);
    }

    /// Update the last_seen timestamp to now.
    pub fn touch(&mut self) {
        self.last_seen = Utc::now().to_rfc3339();
    }

    /// Increment the call count.
    pub fn record_call(&mut self) {
        self.call_count = self.call_count.saturating_add(1);
    }

    /// Record a schema change (rug-pull detected).
    pub fn record_schema_change(&mut self, new_hash: String) {
        self.schema_hash = new_hash;
        self.schema_change_count = self.schema_change_count.saturating_add(1);
        self.compute_trust_score();
    }
}

/// Thread-safe tool registry with persistence.
pub struct ToolRegistry {
    /// In-memory tool entries (tool_id -> entry).
    entries: RwLock<HashMap<String, ToolEntry>>,
    /// Path to the persistence file.
    persistence_path: PathBuf,
    /// Trust threshold below which tools require approval.
    trust_threshold: f32,
    /// Optional HMAC-SHA256 key for persistence integrity.
    /// When set, each persisted line is signed and verified on load.
    hmac_key: Option<[u8; 32]>,
    /// R226: When true, tool namespace collisions (same tool name from different
    /// servers) are rejected outright instead of just penalizing the trust score.
    /// This is the fail-closed defense against cross-server tool shadowing (Acuvity).
    /// Corresponds to `governance.tool_namespace_strict` in config.
    tool_namespace_strict: bool,
}

impl ToolRegistry {
    /// Create a new registry with the given persistence path.
    pub fn new(persistence_path: impl AsRef<Path>) -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(INITIAL_REGISTRY_CAPACITY)),
            persistence_path: persistence_path.as_ref().to_path_buf(),
            trust_threshold: DEFAULT_TRUST_THRESHOLD,
            hmac_key: None,
            tool_namespace_strict: false,
        }
    }

    /// Create a new registry with a custom trust threshold.
    pub fn with_threshold(persistence_path: impl AsRef<Path>, threshold: f32) -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(INITIAL_REGISTRY_CAPACITY)),
            persistence_path: persistence_path.as_ref().to_path_buf(),
            trust_threshold: threshold.clamp(0.0, 1.0),
            hmac_key: None,
            tool_namespace_strict: false,
        }
    }

    /// R226: Enable strict tool namespace mode.
    ///
    /// When enabled, any tool name collision across different MCP servers
    /// results in the tool being rejected outright (Deny) rather than just
    /// penalized in trust score. This is the fail-closed defense against
    /// cross-server tool shadowing (Acuvity, Feb 2026).
    pub fn with_namespace_strict(mut self, strict: bool) -> Self {
        self.tool_namespace_strict = strict;
        self
    }

    /// Set an HMAC-SHA256 key for persistence integrity.
    ///
    /// When set, each line in the JSONL persistence file is signed on write
    /// and verified on load. Lines with invalid HMACs are rejected (fail-closed).
    pub fn with_hmac_key(mut self, key: [u8; 32]) -> Self {
        self.hmac_key = Some(key);
        self
    }

    /// Get the configured trust threshold.
    pub fn trust_threshold(&self) -> f32 {
        self.trust_threshold
    }

    /// Load entries from the persistence file.
    ///
    /// Existing in-memory entries are replaced. Trust scores are recomputed
    /// on load to account for elapsed time since last persistence.
    pub async fn load(&self) -> Result<usize, RegistryError> {
        let path = &self.persistence_path;
        if !path.exists() {
            tracing::debug!("Registry file does not exist, starting fresh: {:?}", path);
            return Ok(0);
        }

        let file = tokio::fs::File::open(path).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut loaded = HashMap::with_capacity(INITIAL_REGISTRY_CAPACITY);
        let mut rejected = 0usize;

        while let Some(raw_line) = lines.next_line().await? {
            let raw_line = raw_line.trim();
            if raw_line.is_empty() {
                continue;
            }

            // If HMAC key is configured, verify integrity of each line.
            // Format: <json>\t<64-char-hex-hmac>
            let json_part = if let Some(ref key) = self.hmac_key {
                if let Some((json, hmac_hex)) = raw_line.rsplit_once('\t') {
                    if !Self::verify_hmac(key, json.as_bytes(), hmac_hex)? {
                        tracing::warn!("Rejecting tampered registry entry (HMAC mismatch)");
                        rejected += 1;
                        continue;
                    }
                    json
                } else {
                    // HMAC key configured but line has no HMAC — reject (fail-closed)
                    tracing::warn!("Rejecting unsigned registry entry (HMAC key configured)");
                    rejected += 1;
                    continue;
                }
            } else {
                raw_line
            };

            // SECURITY (FIND-R205-002): Enforce MAX_REGISTRY_ENTRIES cap on load
            // to prevent OOM from oversized persistence files.
            if loaded.len() >= MAX_REGISTRY_ENTRIES {
                tracing::warn!(
                    max = MAX_REGISTRY_ENTRIES,
                    "Registry file exceeds MAX_REGISTRY_ENTRIES, truncating"
                );
                break;
            }

            match serde_json::from_str::<ToolEntry>(json_part) {
                Ok(mut entry) => {
                    entry.compute_trust_score();
                    loaded.insert(entry.tool_id.clone(), entry);
                }
                Err(e) => {
                    tracing::warn!("Skipping malformed registry entry: {}", e);
                }
            }
        }

        if rejected > 0 {
            tracing::warn!(
                "Rejected {} tampered/unsigned registry entries (fail-closed)",
                rejected
            );
        }

        let count = loaded.len();
        *self.entries.write().await = loaded;
        tracing::info!("Loaded {} tool registry entries from {:?}", count, path);
        Ok(count)
    }

    /// Persist all entries to the persistence file.
    ///
    /// Overwrites the file with current state (full rewrite, not append).
    pub async fn persist(&self) -> Result<(), RegistryError> {
        let entries = self.entries.read().await;
        let path = &self.persistence_path;

        // Write to a temp file and rename for atomicity
        let temp_path = path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)
            .await?;

        for entry in entries.values() {
            let json = serde_json::to_string(entry)?;
            if let Some(ref key) = self.hmac_key {
                // Sign each line: <json>\t<hmac_hex>\n
                let hmac_hex = Self::compute_hmac(key, json.as_bytes())?;
                file.write_all(json.as_bytes()).await?;
                file.write_all(b"\t").await?;
                file.write_all(hmac_hex.as_bytes()).await?;
            } else {
                file.write_all(json.as_bytes()).await?;
            }
            file.write_all(b"\n").await?;
        }
        file.flush().await?;
        drop(file);

        tokio::fs::rename(&temp_path, path).await?;
        Ok(())
    }

    /// Get a tool entry by ID.
    pub async fn get(&self, tool_id: &str) -> Option<ToolEntry> {
        self.entries.read().await.get(tool_id).cloned()
    }

    /// Get all tool entries.
    pub async fn list(&self) -> Vec<ToolEntry> {
        self.entries.read().await.values().cloned().collect()
    }

    /// Register or update a tool from a tools/list response.
    ///
    /// If the tool already exists and the schema hash changed, records a
    /// schema change (rug-pull). Returns true if this is a new tool.
    ///
    /// The `server_id` parameter binds the tool to its originating MCP server.
    /// If the same tool_id is later seen from a different server, the entry is
    /// flagged with `server_id_conflict` and penalized in the trust score.
    ///
    /// SECURITY (SANDWORM-001): Server origin binding prevents rogue MCP servers
    /// from silently shadowing legitimate tools.
    pub async fn register_tool(
        &self,
        tool_id: &str,
        schema: &serde_json::Value,
        flagged_for_squatting: bool,
        server_id: Option<&str>,
    ) -> bool {
        let schema_hash = compute_schema_hash(schema);
        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.get_mut(tool_id) {
            // Existing tool — check for schema change
            if entry.schema_hash != schema_hash {
                tracing::warn!(
                    "Tool '{}' schema changed (rug-pull): {} -> {}",
                    tool_id,
                    entry.schema_hash,
                    schema_hash
                );
                entry.record_schema_change(schema_hash);
            }
            // SECURITY (SANDWORM-001 + R226): Detect server origin conflict.
            // If the tool was previously registered from a different server,
            // flag the conflict and penalize the trust score.
            // When tool_namespace_strict is enabled, reject outright (fail-closed).
            if let Some(new_sid) = server_id {
                // Clone to avoid borrowing entry immutably across mutable updates.
                let existing_sid = entry.server_id.clone();
                match existing_sid.as_deref() {
                    Some(existing_sid) if existing_sid != new_sid => {
                        if !entry.server_id_conflict {
                            tracing::warn!(
                                "Tool '{}' seen from different server: '{}' (was '{}'). \
                                 Possible rogue MCP server (SANDWORM-001).",
                                tool_id,
                                new_sid,
                                existing_sid,
                            );
                            entry.server_id_conflict = true;
                            entry.compute_trust_score();
                        }
                        // R226: In strict namespace mode, reject the tool outright.
                        if self.tool_namespace_strict {
                            tracing::error!(
                                tool = tool_id,
                                new_server = new_sid,
                                existing_server = %existing_sid,
                                "R226: Tool namespace collision DENIED (strict mode). \
                                 Cross-server tool shadowing blocked."
                            );
                            return false;
                        }
                    }
                    None => {
                        entry.server_id = Some(new_sid.to_string());
                    }
                    _ => {} // Same server, no change
                }
            }
            entry.touch();
            if flagged_for_squatting && !entry.flagged_for_squatting {
                entry.flagged_for_squatting = true;
                entry.compute_trust_score();
            }
            false
        } else {
            // SECURITY (R28-MCP-1): Enforce capacity limit on register_tool(),
            // matching the cap already present in register_unknown().
            if entries.len() >= MAX_REGISTRY_ENTRIES {
                tracing::warn!(
                    "Tool registry at capacity ({max}), rejecting registration of '{tool}'",
                    max = MAX_REGISTRY_ENTRIES,
                    tool = tool_id,
                );
                return false;
            }
            // New tool
            let mut entry = ToolEntry::new(tool_id.to_string(), schema_hash);
            entry.flagged_for_squatting = flagged_for_squatting;
            entry.server_id = server_id.map(|s| s.to_string());
            entry.compute_trust_score();
            entries.insert(tool_id.to_string(), entry);
            true
        }
    }

    /// Record a tool call (increment call_count).
    pub async fn record_call(&self, tool_id: &str) {
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(tool_id) {
            entry.record_call();
        }
    }

    /// Set admin_approved = true for a tool.
    pub async fn approve(&self, tool_id: &str) -> Result<ToolEntry, RegistryError> {
        let mut entries = self.entries.write().await;
        let entry = entries
            .get_mut(tool_id)
            .ok_or_else(|| RegistryError::NotFound(tool_id.to_string()))?;
        entry.admin_approved = true;
        entry.compute_trust_score();
        Ok(entry.clone())
    }

    /// Set admin_approved = false for a tool.
    pub async fn revoke(&self, tool_id: &str) -> Result<ToolEntry, RegistryError> {
        let mut entries = self.entries.write().await;
        let entry = entries
            .get_mut(tool_id)
            .ok_or_else(|| RegistryError::NotFound(tool_id.to_string()))?;
        entry.admin_approved = false;
        entry.compute_trust_score();
        Ok(entry.clone())
    }

    /// Check if a tool is below the trust threshold.
    ///
    /// Returns `Some(trust_score)` if the tool exists and is below threshold,
    /// `None` if the tool is trusted or not in the registry.
    pub async fn check_trust(&self, tool_id: &str) -> Option<f32> {
        let entries = self.entries.read().await;
        entries.get(tool_id).and_then(|e| {
            if e.trust_score < self.trust_threshold {
                Some(e.trust_score)
            } else {
                None
            }
        })
    }

    /// R226: Check if a tool has a cross-server namespace conflict.
    ///
    /// In strict mode, this indicates the tool should be denied entirely.
    /// In non-strict mode, the trust score is merely penalized.
    pub async fn has_namespace_conflict(&self, tool_id: &str) -> bool {
        let entries = self.entries.read().await;
        entries
            .get(tool_id)
            .map(|e| e.server_id_conflict)
            .unwrap_or(false)
    }

    /// R226: Check if strict namespace mode would deny a tool.
    ///
    /// Returns true if the tool has a namespace conflict AND strict mode is on.
    pub async fn is_namespace_denied(&self, tool_id: &str) -> bool {
        self.tool_namespace_strict && self.has_namespace_conflict(tool_id).await
    }

    /// Check if a tool requires approval due to low trust score.
    ///
    /// Returns true for:
    /// - tools below the trust threshold
    /// - unknown tools (fail-closed default)
    ///
    /// Returns false only for trusted tools at or above threshold.
    ///
    /// SECURITY (FIND-R57-REG-001): Unknown tools must require approval by default.
    /// Treating unknown as trusted is a fail-open behavior that can bypass intent
    /// to gate first-seen tools.
    pub async fn requires_approval(&self, tool_id: &str) -> bool {
        matches!(
            self.check_trust_level(tool_id).await,
            TrustLevel::Unknown | TrustLevel::Untrusted { .. }
        )
    }

    /// Check a tool's trust level in the registry.
    ///
    /// Returns:
    /// - `TrustLevel::Unknown` if the tool is not in the registry
    /// - `TrustLevel::Untrusted { score }` if the tool exists but is below threshold
    /// - `TrustLevel::Trusted` if the tool exists and is at or above threshold
    pub async fn check_trust_level(&self, tool_id: &str) -> TrustLevel {
        let entries = self.entries.read().await;
        match entries.get(tool_id) {
            None => TrustLevel::Unknown,
            Some(entry) => {
                if entry.trust_score < self.trust_threshold {
                    TrustLevel::Untrusted {
                        score: entry.trust_score,
                    }
                } else {
                    TrustLevel::Trusted
                }
            }
        }
    }

    /// Compute HMAC-SHA256 over data, returning lowercase hex string.
    /// SECURITY (R23-MCP-6): Fallible — no `expect()` in library code.
    fn compute_hmac(key: &[u8; 32], data: &[u8]) -> Result<String, RegistryError> {
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| RegistryError::HmacInit)?;
        mac.update(data);
        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }

    /// Verify HMAC-SHA256 of data against expected hex string.
    /// SECURITY (R23-MCP-6): Fallible — no `expect()` in library code.
    fn verify_hmac(key: &[u8; 32], data: &[u8], expected_hex: &str) -> Result<bool, RegistryError> {
        let expected_bytes = match hex::decode(expected_hex) {
            Ok(b) => b,
            Err(_) => return Ok(false),
        };
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| RegistryError::HmacInit)?;
        mac.update(data);
        Ok(mac.verify_slice(&expected_bytes).is_ok())
    }

    /// Register an unknown tool with an empty schema hash.
    ///
    /// Used when a tool call arrives for a tool not in the registry.
    /// The tool gets a base trust score of 0.5 and requires approval
    /// if that's below the threshold.
    pub async fn register_unknown(&self, tool_id: &str) {
        let mut entries = self.entries.write().await;
        if entries.contains_key(tool_id) {
            return; // Already registered (possible race)
        }
        // SECURITY (R24-SRV-1): Cap registry size to prevent memory DoS
        // via unbounded auto-registration through the evaluate endpoint.
        if entries.len() >= MAX_REGISTRY_ENTRIES {
            tracing::warn!(
                tool_id = tool_id,
                max = MAX_REGISTRY_ENTRIES,
                "Tool registry at capacity, rejecting auto-registration"
            );
            return;
        }
        let mut entry = ToolEntry::new(tool_id.to_string(), String::new());
        entry.compute_trust_score();
        entries.insert(tool_id.to_string(), entry);
    }
}

/// Compute a SHA-256 hash of a JSON value using canonical serialization.
pub fn compute_schema_hash(schema: &serde_json::Value) -> String {
    if schema.is_null() {
        // Hash of empty string for null schemas
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let hex: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        return hex;
    }

    // Use canonical JSON serialization (RFC 8785).
    // SECURITY (R30-MCP-3): If both canonicalization and regular serialization
    // fail, return a deterministic vellaveto hash rather than hashing an empty
    // string. An empty string hash is identical across all failing schemas,
    // masking rug-pull mutations (attacker mutates schema, both old and new
    // fail serialization, producing the same hash → no rug-pull detected).
    let canonical = match serde_json_canonicalizer::to_string(schema) {
        Ok(s) => s,
        Err(_) => match serde_json::to_string(schema) {
            Ok(s) => s,
            Err(_) => {
                // Fail-closed: return a unique hash based on schema debug repr
                // so that any schema that can't be serialized gets a distinct hash.
                let debug_repr = format!("{schema:?}");
                let mut hasher = Sha256::new();
                hasher.update(b"__SERIALIZATION_FAILED__");
                hasher.update(debug_repr.as_bytes());
                let hex: String = hasher
                    .finalize()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                return hex;
            }
        },
    };
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn new_entry(tool_id: &str) -> ToolEntry {
        ToolEntry::new(tool_id.to_string(), "abc123".to_string())
    }

    // --- Trust Score Calculation Tests ---

    #[test]
    fn test_trust_score_base() {
        let mut entry = new_entry("test_tool");
        entry.compute_trust_score();
        assert!(
            (entry.trust_score - 0.5).abs() < 0.01,
            "Base score should be 0.5"
        );
    }

    #[test]
    fn test_trust_score_admin_approved() {
        let mut entry = new_entry("test_tool");
        entry.admin_approved = true;
        entry.compute_trust_score();
        assert!(
            (entry.trust_score - 0.7).abs() < 0.01,
            "Admin approved adds 0.2: expected 0.7, got {}",
            entry.trust_score
        );
    }

    #[test]
    fn test_trust_score_schema_change_penalty() {
        let mut entry = new_entry("test_tool");
        entry.schema_change_count = 1;
        entry.compute_trust_score();
        assert!(
            (entry.trust_score - 0.2).abs() < 0.01,
            "One schema change: expected 0.2, got {}",
            entry.trust_score
        );

        entry.schema_change_count = 2;
        entry.compute_trust_score();
        assert!(
            entry.trust_score < 0.01,
            "Two schema changes: expected 0.0 (clamped), got {}",
            entry.trust_score
        );
    }

    #[test]
    fn test_trust_score_squatting_penalty() {
        let mut entry = new_entry("test_tool");
        entry.flagged_for_squatting = true;
        entry.compute_trust_score();
        assert!(
            (entry.trust_score - 0.3).abs() < 0.01,
            "Squatting penalty: expected 0.3, got {}",
            entry.trust_score
        );
    }

    #[test]
    fn test_trust_score_age_bonus_7_days() {
        let mut entry = new_entry("test_tool");
        // Set first_seen to 8 days ago
        let eight_days_ago = (Utc::now() - Duration::days(8)).to_rfc3339();
        entry.first_seen = eight_days_ago;
        entry.compute_trust_score();
        assert!(
            (entry.trust_score - 0.6).abs() < 0.01,
            "7-day age bonus: expected 0.6, got {}",
            entry.trust_score
        );
    }

    #[test]
    fn test_trust_score_age_bonus_30_days() {
        let mut entry = new_entry("test_tool");
        // Set first_seen to 31 days ago
        let thirty_one_days_ago = (Utc::now() - Duration::days(31)).to_rfc3339();
        entry.first_seen = thirty_one_days_ago;
        entry.compute_trust_score();
        assert!(
            (entry.trust_score - 0.7).abs() < 0.01,
            "30-day age bonus: expected 0.7 (0.5 + 0.1 + 0.1), got {}",
            entry.trust_score
        );
    }

    #[test]
    fn test_trust_score_combined() {
        let mut entry = new_entry("test_tool");
        // 30+ days old (+0.2), admin approved (+0.2), but 1 schema change (-0.3)
        let old_date = (Utc::now() - Duration::days(35)).to_rfc3339();
        entry.first_seen = old_date;
        entry.admin_approved = true;
        entry.schema_change_count = 1;
        entry.compute_trust_score();
        // 0.5 + 0.1 + 0.1 + 0.2 - 0.3 = 0.6
        assert!(
            (entry.trust_score - 0.6).abs() < 0.01,
            "Combined score: expected 0.6, got {}",
            entry.trust_score
        );
    }

    #[test]
    fn test_trust_score_clamp_max() {
        let mut entry = new_entry("test_tool");
        let old_date = (Utc::now() - Duration::days(365)).to_rfc3339();
        entry.first_seen = old_date;
        entry.admin_approved = true;
        entry.compute_trust_score();
        // 0.5 + 0.1 + 0.1 + 0.2 = 0.9, still under 1.0
        assert!(
            entry.trust_score <= 1.0,
            "Score should be clamped to 1.0 max"
        );
    }

    #[test]
    fn test_trust_score_clamp_min() {
        let mut entry = new_entry("test_tool");
        entry.schema_change_count = 10; // -3.0
        entry.flagged_for_squatting = true; // -0.2
        entry.compute_trust_score();
        assert!(
            entry.trust_score >= 0.0,
            "Score should be clamped to 0.0 min"
        );
    }

    // --- Schema Hash Tests ---

    #[test]
    fn test_compute_schema_hash_null() {
        let hash = compute_schema_hash(&serde_json::Value::Null);
        assert_eq!(hash.len(), 64, "SHA-256 hex should be 64 chars");
    }

    #[test]
    fn test_compute_schema_hash_deterministic() {
        let schema = json!({"type": "object", "properties": {"x": {"type": "string"}}});
        let h1 = compute_schema_hash(&schema);
        let h2 = compute_schema_hash(&schema);
        assert_eq!(h1, h2, "Hash should be deterministic");
    }

    #[test]
    fn test_compute_schema_hash_canonical_key_order() {
        // Different key order should produce the same hash (canonical JSON)
        let schema1 = json!({"type": "object", "properties": {"a": 1, "b": 2}});
        let schema2: serde_json::Value =
            serde_json::from_str(r#"{"properties": {"b": 2, "a": 1}, "type": "object"}"#).unwrap();
        let h1 = compute_schema_hash(&schema1);
        let h2 = compute_schema_hash(&schema2);
        assert_eq!(h1, h2, "Canonical hash should be key-order independent");
    }

    // --- Registry Persistence Tests ---

    #[tokio::test]
    async fn test_registry_persist_and_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");

        // Create and populate registry
        let registry = ToolRegistry::new(&path);
        registry
            .register_tool("tool_a", &json!({"type": "object"}), false, None)
            .await;
        registry
            .register_tool("tool_b", &json!({"type": "string"}), true, None)
            .await;
        registry.approve("tool_a").await.unwrap();

        // Persist
        registry.persist().await.unwrap();

        // Load into new registry
        let registry2 = ToolRegistry::new(&path);
        let count = registry2.load().await.unwrap();
        assert_eq!(count, 2);

        let tool_a = registry2.get("tool_a").await.unwrap();
        assert!(tool_a.admin_approved);

        let tool_b = registry2.get("tool_b").await.unwrap();
        assert!(tool_b.flagged_for_squatting);
    }

    #[tokio::test]
    async fn test_registry_load_nonexistent_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.jsonl");
        let registry = ToolRegistry::new(&path);
        let count = registry.load().await.unwrap();
        assert_eq!(count, 0, "Loading nonexistent file should return 0");
    }

    // --- Registry Operations Tests ---

    #[tokio::test]
    async fn test_registry_register_new_tool() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path);

        let is_new = registry
            .register_tool("new_tool", &json!({"type": "object"}), false, None)
            .await;
        assert!(is_new, "Should report new tool");

        let entry = registry.get("new_tool").await.unwrap();
        assert_eq!(entry.tool_id, "new_tool");
        assert_eq!(entry.call_count, 0);
        assert!(!entry.admin_approved);
    }

    #[tokio::test]
    async fn test_registry_register_existing_tool_same_schema() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path);

        registry
            .register_tool("tool", &json!({"type": "object"}), false, None)
            .await;
        let is_new = registry
            .register_tool("tool", &json!({"type": "object"}), false, None)
            .await;
        assert!(!is_new, "Should not be new");

        let entry = registry.get("tool").await.unwrap();
        assert_eq!(entry.schema_change_count, 0, "No schema change");
    }

    #[tokio::test]
    async fn test_registry_register_existing_tool_changed_schema() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path);

        registry
            .register_tool("tool", &json!({"type": "object"}), false, None)
            .await;
        registry
            .register_tool("tool", &json!({"type": "string"}), false, None)
            .await;

        let entry = registry.get("tool").await.unwrap();
        assert_eq!(entry.schema_change_count, 1, "Should record schema change");
        assert!(
            entry.trust_score < 0.5,
            "Trust score should decrease on schema change"
        );
    }

    #[tokio::test]
    async fn test_registry_record_call() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path);

        registry
            .register_tool("tool", &json!({"type": "object"}), false, None)
            .await;
        registry.record_call("tool").await;
        registry.record_call("tool").await;

        let entry = registry.get("tool").await.unwrap();
        assert_eq!(entry.call_count, 2);
    }

    #[tokio::test]
    async fn test_registry_approve_revoke() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path);

        registry
            .register_tool("tool", &json!({"type": "object"}), false, None)
            .await;

        let entry = registry.approve("tool").await.unwrap();
        assert!(entry.admin_approved);
        assert!(entry.trust_score > 0.5, "Approval should boost trust");

        let entry = registry.revoke("tool").await.unwrap();
        assert!(!entry.admin_approved);
    }

    #[tokio::test]
    async fn test_registry_approve_not_found() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path);

        let result = registry.approve("nonexistent").await;
        assert!(matches!(result, Err(RegistryError::NotFound(_))));
    }

    // --- Threshold Tests ---

    #[tokio::test]
    async fn test_registry_check_trust_below_threshold() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::with_threshold(&path, 0.5);

        // New tool has base score 0.5, so at threshold (not below)
        registry
            .register_tool("tool", &json!({"type": "object"}), false, None)
            .await;
        assert!(
            registry.check_trust("tool").await.is_none(),
            "At threshold should pass"
        );

        // Add squatting flag to drop below threshold
        registry
            .register_tool("tool2", &json!({"type": "object"}), true, None)
            .await;
        assert!(
            registry.check_trust("tool2").await.is_some(),
            "Below threshold should fail"
        );
    }

    #[tokio::test]
    async fn test_registry_requires_approval() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::with_threshold(&path, 0.4);

        // Unknown tools should require approval (fail-closed).
        assert!(
            registry.requires_approval("unknown").await,
            "Unknown tools must require approval"
        );

        registry
            .register_tool("trusted", &json!({"type": "object"}), false, None)
            .await;
        assert!(
            !registry.requires_approval("trusted").await,
            "0.5 >= 0.4 threshold"
        );

        registry
            .register_tool("untrusted", &json!({"type": "object"}), true, None)
            .await;
        assert!(
            registry.requires_approval("untrusted").await,
            "0.3 < 0.4 threshold (squatting penalty)"
        );
    }

    #[tokio::test]
    async fn test_registry_list() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path);

        registry
            .register_tool("tool_a", &json!({}), false, None)
            .await;
        registry
            .register_tool("tool_b", &json!({}), false, None)
            .await;

        let list = registry.list().await;
        assert_eq!(list.len(), 2);
    }

    // --- HMAC Integrity Tests ---

    #[tokio::test]
    async fn test_registry_hmac_persist_and_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let key = [0xABu8; 32];

        let registry = ToolRegistry::new(&path).with_hmac_key(key);
        registry
            .register_tool("tool_a", &json!({"type": "object"}), false, None)
            .await;
        registry.persist().await.unwrap();

        // Load with same key — should succeed
        let registry2 = ToolRegistry::new(&path).with_hmac_key(key);
        let count = registry2.load().await.unwrap();
        assert_eq!(count, 1);
        assert!(registry2.get("tool_a").await.is_some());
    }

    #[tokio::test]
    async fn test_registry_hmac_rejects_tampered_data() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let key = [0xCDu8; 32];

        let registry = ToolRegistry::new(&path).with_hmac_key(key);
        registry
            .register_tool("tool_x", &json!({"type": "object"}), false, None)
            .await;
        registry.persist().await.unwrap();

        // Tamper with the file: modify the JSON but keep the old HMAC
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let tampered = content.replace("tool_x", "tool_y");
        tokio::fs::write(&path, tampered).await.unwrap();

        // Load should reject the tampered entry
        let registry2 = ToolRegistry::new(&path).with_hmac_key(key);
        let count = registry2.load().await.unwrap();
        assert_eq!(count, 0, "Tampered entry should be rejected");
    }

    #[tokio::test]
    async fn test_registry_hmac_rejects_wrong_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];

        let registry = ToolRegistry::new(&path).with_hmac_key(key1);
        registry
            .register_tool("tool_z", &json!({"type": "string"}), false, None)
            .await;
        registry.persist().await.unwrap();

        // Load with different key — should reject
        let registry2 = ToolRegistry::new(&path).with_hmac_key(key2);
        let count = registry2.load().await.unwrap();
        assert_eq!(count, 0, "Entry signed with wrong key should be rejected");
    }

    #[tokio::test]
    async fn test_registry_hmac_rejects_unsigned_when_key_configured() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");

        // Persist without HMAC
        let registry = ToolRegistry::new(&path);
        registry
            .register_tool("tool_plain", &json!({}), false, None)
            .await;
        registry.persist().await.unwrap();

        // Load with HMAC key — should reject unsigned entries (fail-closed)
        let key = [0xFFu8; 32];
        let registry2 = ToolRegistry::new(&path).with_hmac_key(key);
        let count = registry2.load().await.unwrap();
        assert_eq!(
            count, 0,
            "Unsigned entries should be rejected when HMAC key is set"
        );
    }

    #[tokio::test]
    async fn test_registry_no_hmac_loads_normally() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");

        // Persist without HMAC
        let registry = ToolRegistry::new(&path);
        registry
            .register_tool("tool_normal", &json!({}), false, None)
            .await;
        registry.persist().await.unwrap();

        // Load without HMAC — should work normally
        let registry2 = ToolRegistry::new(&path);
        let count = registry2.load().await.unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_tool_entry_serialization_roundtrip() {
        let entry = ToolEntry {
            tool_id: "test".to_string(),
            schema_hash: "abc123".to_string(),
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-02-01T00:00:00Z".to_string(),
            call_count: 42,
            schema_change_count: 1,
            admin_approved: true,
            flagged_for_squatting: false,
            trust_score: 0.75,
            server_id: Some("trusted-server".to_string()),
            server_id_conflict: false,
            signature: None,
            signature_verified: false,
            signer_trusted: false,
            version: None,
            version_pinned: false,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: ToolEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    #[tokio::test]
    async fn test_register_unknown_respects_capacity_limit() {
        // R24-SRV-1: Tool registry must cap entries to prevent memory DoS
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path);

        // Pre-fill the registry to capacity
        {
            let mut entries = registry.entries.write().await;
            for i in 0..MAX_REGISTRY_ENTRIES {
                let mut e = ToolEntry::new(format!("tool_{i}"), String::new());
                e.compute_trust_score();
                entries.insert(format!("tool_{i}"), e);
            }
            assert_eq!(entries.len(), MAX_REGISTRY_ENTRIES);
        }

        // Attempt to register one more — should be silently rejected
        registry.register_unknown("overflow_tool").await;

        let entries = registry.entries.read().await;
        assert_eq!(entries.len(), MAX_REGISTRY_ENTRIES);
        assert!(
            !entries.contains_key("overflow_tool"),
            "Overflow registration should be rejected"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SANDWORM-001: Server Origin Binding Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_register_tool_with_server_id() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path);

        registry
            .register_tool(
                "read_file",
                &json!({"type": "object"}),
                false,
                Some("legit-server"),
            )
            .await;

        let entry = registry.get("read_file").await.unwrap();
        assert_eq!(entry.server_id, Some("legit-server".to_string()));
        assert!(!entry.server_id_conflict);
    }

    #[tokio::test]
    async fn test_register_tool_server_id_conflict_detected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path);

        // First registration from legit server
        registry
            .register_tool(
                "read_file",
                &json!({"type": "object"}),
                false,
                Some("legit-server"),
            )
            .await;

        // Second registration from rogue server — SANDWORM_MODE attack
        registry
            .register_tool(
                "read_file",
                &json!({"type": "object"}),
                false,
                Some("rogue-server"),
            )
            .await;

        let entry = registry.get("read_file").await.unwrap();
        assert_eq!(
            entry.server_id,
            Some("legit-server".to_string()),
            "Original server preserved"
        );
        assert!(entry.server_id_conflict, "Conflict should be flagged");
        assert!(
            entry.trust_score < 0.3,
            "Trust should be penalized: got {}",
            entry.trust_score
        );
    }

    #[tokio::test]
    async fn test_register_tool_same_server_no_conflict() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path);

        registry
            .register_tool(
                "read_file",
                &json!({"type": "object"}),
                false,
                Some("server-1"),
            )
            .await;
        registry
            .register_tool(
                "read_file",
                &json!({"type": "object"}),
                false,
                Some("server-1"),
            )
            .await;

        let entry = registry.get("read_file").await.unwrap();
        assert!(!entry.server_id_conflict, "Same server should not conflict");
    }

    #[tokio::test]
    async fn test_register_tool_none_server_then_server_fills_in() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path);

        // First registration without server_id
        registry
            .register_tool("tool", &json!({}), false, None)
            .await;
        let entry = registry.get("tool").await.unwrap();
        assert_eq!(entry.server_id, None);

        // Later registration with server_id fills it in
        registry
            .register_tool("tool", &json!({}), false, Some("server-1"))
            .await;
        let entry = registry.get("tool").await.unwrap();
        assert_eq!(entry.server_id, Some("server-1".to_string()));
        assert!(!entry.server_id_conflict);
    }

    #[test]
    fn test_trust_score_server_id_conflict_penalty() {
        let mut entry = new_entry("test_tool");
        entry.server_id_conflict = true;
        entry.compute_trust_score();
        assert!(
            (entry.trust_score - 0.2).abs() < 0.01,
            "Server conflict penalty -0.3: expected 0.2, got {}",
            entry.trust_score
        );
    }

    #[tokio::test]
    async fn test_register_tool_server_id_conflict_persists_across_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");

        let registry = ToolRegistry::new(&path);
        registry
            .register_tool("tool", &json!({"type": "object"}), false, Some("server-a"))
            .await;
        registry
            .register_tool("tool", &json!({"type": "object"}), false, Some("server-b"))
            .await;
        registry.persist().await.unwrap();

        let registry2 = ToolRegistry::new(&path);
        registry2.load().await.unwrap();

        let entry = registry2.get("tool").await.unwrap();
        assert!(
            entry.server_id_conflict,
            "Conflict flag should survive persistence"
        );
        assert_eq!(entry.server_id, Some("server-a".to_string()));
    }

    // ── R226: Tool namespace strict mode tests ──

    #[tokio::test]
    async fn test_r226_namespace_strict_rejects_collision() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path).with_namespace_strict(true);

        // Register from server-a
        let is_new = registry
            .register_tool("shared_tool", &json!({}), false, Some("server-a"))
            .await;
        assert!(is_new, "First registration should succeed");

        // Register same tool from server-b — strict mode should reject
        let is_new = registry
            .register_tool("shared_tool", &json!({}), false, Some("server-b"))
            .await;
        assert!(
            !is_new,
            "R226: Namespace collision must be rejected in strict mode"
        );

        // Verify the tool is flagged
        assert!(
            registry.has_namespace_conflict("shared_tool").await,
            "Tool must be flagged as having namespace conflict"
        );
        assert!(
            registry.is_namespace_denied("shared_tool").await,
            "Tool must be denied in strict mode"
        );
    }

    #[tokio::test]
    async fn test_r226_namespace_non_strict_allows_collision() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path); // non-strict (default)

        registry
            .register_tool("shared_tool", &json!({}), false, Some("server-a"))
            .await;
        registry
            .register_tool("shared_tool", &json!({}), false, Some("server-b"))
            .await;

        // Conflict is flagged but not denied
        assert!(registry.has_namespace_conflict("shared_tool").await);
        assert!(
            !registry.is_namespace_denied("shared_tool").await,
            "Non-strict mode should not deny on conflict"
        );
    }

    #[tokio::test]
    async fn test_r226_namespace_same_server_no_conflict() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("registry.jsonl");
        let registry = ToolRegistry::new(&path).with_namespace_strict(true);

        registry
            .register_tool("safe_tool", &json!({}), false, Some("server-a"))
            .await;
        registry
            .register_tool("safe_tool", &json!({}), false, Some("server-a"))
            .await;

        assert!(
            !registry.has_namespace_conflict("safe_tool").await,
            "Same server re-registration must not flag conflict"
        );
    }
}
