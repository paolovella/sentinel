// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use serde::{Deserialize, Serialize};

use crate::default_true;
use crate::schema_canonical::manifest_input_schema_hash;

const MAX_MANIFEST_SCHEMA_VERSION_LEN: usize = 32;
const MAX_MANIFEST_TOOL_NAME_LEN: usize = 256;
const SHA256_HEX_LEN: usize = 64;
const ED25519_SIG_HEX_LEN: usize = 128;
const ED25519_VERIFYING_KEY_HEX_LEN: usize = 64;

/// Snapshot of MCP tool annotations at manifest creation time.
///
/// These hints describe behavioral properties of a tool. Changes to annotations
/// between manifest versions may indicate a rug-pull attack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct ManifestAnnotations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

/// A pinned tool manifest that records the expected tools and their schema hashes.
///
/// Created from a `tools/list` response, then persisted. On subsequent
/// `tools/list` responses, the live tools are compared against this manifest
/// to detect unexpected changes (new tools, removed tools, schema mutations).
///
/// SECURITY (IMP-R104-005): Custom Debug impl redacts `signature` and `verifying_key`.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolManifest {
    /// Schema version for forward compatibility.
    pub schema_version: String,
    /// Pinned tool entries with schema hashes.
    pub tools: Vec<ManifestToolEntry>,
    /// Optional Ed25519 signature over the canonical manifest content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// ISO 8601 timestamp when the manifest was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Hex-encoded Ed25519 verifying key (32 bytes) for signature verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifying_key: Option<String>,
}

impl std::fmt::Debug for ToolManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolManifest")
            .field("schema_version", &self.schema_version)
            .field("tools", &self.tools)
            .field("signature", &self.signature.as_ref().map(|_| "[REDACTED]"))
            .field("created_at", &self.created_at)
            .field(
                "verifying_key",
                &self.verifying_key.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// A single tool entry in a pinned manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManifestToolEntry {
    /// Tool name as reported by the MCP server.
    pub name: String,
    /// SHA-256 hex digest of the canonical JSON-serialized `inputSchema`.
    /// If the tool has no inputSchema, this is the hash of the empty string.
    pub input_schema_hash: String,
    /// SHA-256 hex digest of the tool's description string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description_hash: Option<String>,
    /// SHA-256 hex digest of the tool's `title` display field (MCP 2025-06-18).
    /// A changed title could be used for social engineering (rug-pull via UI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title_hash: Option<String>,
    /// Snapshot of tool annotations at manifest creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ManifestAnnotations>,
}

/// Result of manifest verification.
#[derive(Debug, Clone)]
pub struct ManifestVerification {
    /// Whether the manifest matched (no discrepancies).
    pub passed: bool,
    /// Human-readable discrepancy descriptions, empty if passed.
    pub discrepancies: Vec<String>,
}

/// Maximum tools in a manifest.
const MAX_MANIFEST_TOOLS: usize = 10_000;

impl ToolManifest {
    /// Build a manifest from a live `tools/list` JSON-RPC response.
    ///
    /// Expects `response` to contain `result.tools[]` with `name` and
    /// optional `inputSchema` fields per the MCP specification.
    /// Returns `None` if parsing fails or tool count exceeds `MAX_MANIFEST_TOOLS`.
    pub fn from_tools_list(response: &serde_json::Value) -> Option<Self> {
        let tools_array = response
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())?;

        // SECURITY (FIND-R102-005): Bound the tools Vec to prevent OOM.
        if tools_array.len() > MAX_MANIFEST_TOOLS {
            return None;
        }

        let mut entries: Vec<ManifestToolEntry> = Vec::with_capacity(tools_array.len());
        for tool in tools_array {
            let name = tool.get("name")?.as_str()?.to_string();
            let input_schema_hash = match manifest_input_schema_hash(tool.get("inputSchema")) {
                Ok(hash) => hash,
                Err(err) => {
                    tracing::warn!(
                        tool = %name,
                        error = %err,
                        "SECURITY: rejecting tools/list manifest with invalid inputSchema"
                    );
                    return None;
                }
            };

            // Hash the description if present
            let description_hash = tool.get("description").and_then(|d| d.as_str()).map(|d| {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(d.as_bytes());
                hex::encode(h.finalize())
            });

            // Hash the title if present (MCP 2025-06-18)
            let title_hash = tool.get("title").and_then(|t| t.as_str()).map(|t| {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(t.as_bytes());
                hex::encode(h.finalize())
            });

            // Snapshot annotations if present
            let annotations = tool.get("annotations").and_then(|a| {
                let ann = ManifestAnnotations {
                    read_only_hint: a.get("readOnlyHint").and_then(|v| v.as_bool()),
                    destructive_hint: a.get("destructiveHint").and_then(|v| v.as_bool()),
                    idempotent_hint: a.get("idempotentHint").and_then(|v| v.as_bool()),
                    open_world_hint: a.get("openWorldHint").and_then(|v| v.as_bool()),
                };
                // Only include if at least one field is set
                if ann.read_only_hint.is_some()
                    || ann.destructive_hint.is_some()
                    || ann.idempotent_hint.is_some()
                    || ann.open_world_hint.is_some()
                {
                    Some(ann)
                } else {
                    None
                }
            });

            entries.push(ManifestToolEntry {
                name,
                input_schema_hash,
                description_hash,
                title_hash,
                annotations,
            });
        }

        // Sort by name for deterministic comparison
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        Some(ToolManifest {
            schema_version: "2.0".to_string(),
            tools: entries,
            signature: None,
            created_at: None,
            verifying_key: None,
        })
    }

    /// Maximum manifest file size in bytes (16 MB).
    const MAX_MANIFEST_FILE_SIZE: u64 = 16 * 1024 * 1024;

    /// Load a pinned manifest from a JSON file.
    ///
    /// SECURITY (FIND-R104-005): Enforces file size limit and tools count bound
    /// to prevent OOM from crafted manifest files.
    pub fn load_pinned_manifest(
        path: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Check file size before reading into memory.
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > Self::MAX_MANIFEST_FILE_SIZE {
            return Err(format!(
                "Manifest file size {} exceeds maximum of {} bytes",
                metadata.len(),
                Self::MAX_MANIFEST_FILE_SIZE
            )
            .into());
        }
        let content = std::fs::read_to_string(path)?;
        let manifest: ToolManifest = serde_json::from_str(&content)?;
        // Enforce tools count bound (same as from_tools_list).
        if manifest.tools.len() > MAX_MANIFEST_TOOLS {
            return Err(format!(
                "Manifest tools count {} exceeds maximum of {}",
                manifest.tools.len(),
                MAX_MANIFEST_TOOLS
            )
            .into());
        }
        manifest
            .validate()
            .map_err(Box::<dyn std::error::Error + Send + Sync>::from)?;
        Ok(manifest)
    }

    /// Save this manifest to a JSON file.
    pub fn save_manifest(
        &self,
        path: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Compute the canonical content that is signed.
    ///
    /// Content = SHA-256(schema_version || created_at || sorted_tools[]).
    /// Each tool: name || input_schema_hash || description_hash || annotations_string.
    /// All fields are length-prefixed with u64 LE to prevent boundary collisions.
    pub fn signing_content(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        Self::hash_field(&mut hasher, self.schema_version.as_bytes());
        Self::hash_field(
            &mut hasher,
            self.created_at.as_deref().unwrap_or("").as_bytes(),
        );

        // Tools are already sorted by name in from_tools_list
        for tool in &self.tools {
            Self::hash_field(&mut hasher, tool.name.as_bytes());
            Self::hash_field(&mut hasher, tool.input_schema_hash.as_bytes());
            Self::hash_field(
                &mut hasher,
                tool.description_hash.as_deref().unwrap_or("").as_bytes(),
            );
            Self::hash_field(
                &mut hasher,
                tool.title_hash.as_deref().unwrap_or("").as_bytes(),
            );
            // SECURITY (R240-P3-CFG-1): Log serialization failure instead of silent empty.
            // A failed annotation serialization changes the signing content hash,
            // causing silent signature mismatch on verification.
            let ann_str = tool
                .annotations
                .as_ref()
                .map(|a| {
                    serde_json::to_string(a).unwrap_or_else(|e| {
                        tracing::warn!(error = %e, "manifest annotation serialization failed");
                        String::new()
                    })
                })
                .unwrap_or_default();
            Self::hash_field(&mut hasher, ann_str.as_bytes());
        }

        hasher.finalize().to_vec()
    }

    fn hash_field(hasher: &mut sha2::Sha256, data: &[u8]) {
        use sha2::Digest;
        hasher.update((data.len() as u64).to_le_bytes());
        hasher.update(data);
    }

    /// Sign this manifest with an Ed25519 signing key.
    ///
    /// Populates the `signature` and `verifying_key` fields.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        let content = self.signing_content();
        let signature = signing_key.sign(&content);
        self.signature = Some(hex::encode(signature.to_bytes()));
        let vk = signing_key.verifying_key();
        self.verifying_key = Some(hex::encode(vk.as_bytes()));
    }

    /// Verify the manifest signature against a trusted public key.
    ///
    /// Returns `Ok(())` if the signature is valid, or `Err(reason)` if verification fails.
    pub fn verify_signature(&self, trusted_key_hex: &str) -> Result<(), String> {
        use ed25519_dalek::{Verifier, VerifyingKey};

        let sig_hex = self
            .signature
            .as_ref()
            .ok_or_else(|| "Manifest has no signature".to_string())?;

        let sig_bytes: [u8; 64] = hex::decode(sig_hex)
            .map_err(|e| format!("Invalid signature hex: {e}"))?
            .try_into()
            .map_err(|_| "Signature must be 64 bytes".to_string())?;

        let key_bytes: [u8; 32] = hex::decode(trusted_key_hex)
            .map_err(|e| format!("Invalid key hex: {e}"))?
            .try_into()
            .map_err(|_| "Verifying key must be 32 bytes".to_string())?;

        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| format!("Invalid verifying key: {e}"))?;

        let content = self.signing_content();
        verifying_key
            .verify(&content, &signature)
            .map_err(|e| format!("Signature verification failed: {e}"))
    }

    /// Verify the manifest signature against any of the given trusted keys.
    ///
    /// Returns `Ok(())` if at least one key verifies the signature.
    pub fn verify_signature_any(&self, trusted_keys: &[String]) -> Result<(), String> {
        if trusted_keys.is_empty() {
            return Err("No trusted keys provided".to_string());
        }
        for key in trusted_keys {
            if self.verify_signature(key).is_ok() {
                return Ok(());
            }
        }
        Err("Signature does not match any trusted key".to_string())
    }

    /// Verify a live `tools/list` response against this pinned manifest.
    pub fn verify(&self, live_response: &serde_json::Value) -> ManifestVerification {
        let live = match Self::from_tools_list(live_response) {
            Some(m) => m,
            None => {
                return ManifestVerification {
                    passed: false,
                    discrepancies: vec![
                        "Failed to parse tools/list response for verification".to_string()
                    ],
                };
            }
        };

        let mut discrepancies = Vec::new();

        // Build lookup maps
        let live_map: std::collections::HashMap<&str, &str> = live
            .tools
            .iter()
            .map(|t| (t.name.as_str(), t.input_schema_hash.as_str()))
            .collect();

        // Check for removed tools
        for pinned in &self.tools {
            if !live_map.contains_key(pinned.name.as_str()) {
                discrepancies.push(format!("Tool '{}' removed from server", pinned.name));
            }
        }

        // Build pinned tool lookup for detailed comparison
        let pinned_tools_by_name: std::collections::HashMap<&str, &ManifestToolEntry> =
            self.tools.iter().map(|t| (t.name.as_str(), t)).collect();

        // Check for new or changed tools
        for live_tool in &live.tools {
            match pinned_tools_by_name.get(live_tool.name.as_str()) {
                None => {
                    discrepancies.push(format!(
                        "New tool '{}' not in pinned manifest",
                        live_tool.name
                    ));
                }
                Some(pinned_entry) => {
                    if pinned_entry.input_schema_hash != live_tool.input_schema_hash {
                        discrepancies.push(format!(
                            "Tool '{}' schema changed: expected {}, got {}",
                            live_tool.name,
                            pinned_entry.input_schema_hash,
                            live_tool.input_schema_hash
                        ));
                    }
                    // MCP 2025-06-18: Detect title changes (social engineering vector)
                    if pinned_entry.title_hash != live_tool.title_hash {
                        discrepancies.push(format!(
                            "Tool '{}' title changed (potential social engineering)",
                            live_tool.name
                        ));
                    }
                    // SECURITY (R28-SUP-2): Detect description changes (rug-pull vector).
                    // A malicious server can change "Read a file" to "Read a file and
                    // exfiltrate to evil.com" without changing the schema.
                    if pinned_entry.description_hash != live_tool.description_hash {
                        discrepancies.push(format!(
                            "Tool '{}' description changed (potential rug-pull)",
                            live_tool.name
                        ));
                    }
                    // SECURITY (R28-SUP-2): Detect annotation changes (behavioral hint
                    // manipulation). Changing destructiveHint from true to false lowers
                    // the agent's guard about a tool's actual behavior.
                    if pinned_entry.annotations != live_tool.annotations {
                        discrepancies.push(format!(
                            "Tool '{}' annotations changed (behavioral hint manipulation)",
                            live_tool.name
                        ));
                    }
                }
            }
        }

        ManifestVerification {
            passed: discrepancies.is_empty(),
            discrepancies,
        }
    }

    /// Validate manifest content loaded from disk before it influences runtime verification.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version.trim().is_empty() {
            return Err("manifest.schema_version must not be empty or whitespace-only".to_string());
        }
        if self.schema_version.len() > MAX_MANIFEST_SCHEMA_VERSION_LEN {
            return Err(format!(
                "manifest.schema_version length {} exceeds maximum {}",
                self.schema_version.len(),
                MAX_MANIFEST_SCHEMA_VERSION_LEN
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.schema_version) {
            return Err(
                "manifest.schema_version contains control or Unicode format characters".to_string(),
            );
        }
        if self.tools.len() > MAX_MANIFEST_TOOLS {
            return Err(format!(
                "manifest.tools count {} exceeds maximum {}",
                self.tools.len(),
                MAX_MANIFEST_TOOLS
            ));
        }

        let mut seen_names = std::collections::HashSet::new();
        for (index, tool) in self.tools.iter().enumerate() {
            if tool.name.trim().is_empty() {
                return Err(format!(
                    "manifest.tools[{index}].name must not be empty or whitespace-only"
                ));
            }
            if tool.name.len() > MAX_MANIFEST_TOOL_NAME_LEN {
                return Err(format!(
                    "manifest.tools[{index}].name length {} exceeds maximum {}",
                    tool.name.len(),
                    MAX_MANIFEST_TOOL_NAME_LEN
                ));
            }
            if vellaveto_types::has_dangerous_chars(&tool.name) {
                return Err(format!(
                    "manifest.tools[{index}].name contains control or Unicode format characters"
                ));
            }
            if !seen_names.insert(tool.name.as_str()) {
                return Err(format!(
                    "manifest.tools[{index}] duplicates tool name '{}'",
                    tool.name
                ));
            }

            validate_hex_len(
                &tool.input_schema_hash,
                SHA256_HEX_LEN,
                &format!("manifest.tools[{index}].input_schema_hash"),
            )?;
            if let Some(description_hash) = &tool.description_hash {
                validate_hex_len(
                    description_hash,
                    SHA256_HEX_LEN,
                    &format!("manifest.tools[{index}].description_hash"),
                )?;
            }
            if let Some(title_hash) = &tool.title_hash {
                validate_hex_len(
                    title_hash,
                    SHA256_HEX_LEN,
                    &format!("manifest.tools[{index}].title_hash"),
                )?;
            }
        }

        if let Some(signature) = &self.signature {
            validate_hex_len(signature, ED25519_SIG_HEX_LEN, "manifest.signature")?;
        }
        if let Some(verifying_key) = &self.verifying_key {
            validate_hex_len(
                verifying_key,
                ED25519_VERIFYING_KEY_HEX_LEN,
                "manifest.verifying_key",
            )?;
        }
        if let Some(created_at) = &self.created_at {
            if created_at.trim().is_empty() {
                return Err("manifest.created_at must not be empty or whitespace-only".to_string());
            }
            if vellaveto_types::has_dangerous_chars(created_at) {
                return Err(
                    "manifest.created_at contains control or Unicode format characters".to_string(),
                );
            }
        }

        Ok(())
    }
}

fn validate_hex_len(value: &str, expected_len: usize, field: &str) -> Result<(), String> {
    if value.len() != expected_len {
        return Err(format!(
            "{field} length {} must be exactly {} hex characters",
            value.len(),
            expected_len
        ));
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{field} must be ASCII hex"));
    }
    Ok(())
}

/// Enforcement mode for manifest verification failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ManifestEnforcement {
    /// Log discrepancies but allow the request (default).
    #[default]
    Warn,
    /// Block requests when manifest verification fails.
    Block,
}

/// Tool manifest verification configuration.
///
/// # TOML Example
///
/// ```toml
/// [manifest]
/// enabled = true
/// enforcement = "Warn"
/// require_signature = false
/// manifest_path = "/etc/vellaveto/manifest.json"
/// trusted_keys = ["hex-encoded-ed25519-public-key"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManifestConfig {
    /// Enable tool manifest schema pinning. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Trusted Ed25519 public keys (hex-encoded 32-byte) for manifest signatures.
    #[serde(default)]
    pub trusted_keys: Vec<String>,
    /// What to do when manifest verification fails. Default: Warn.
    #[serde(default)]
    pub enforcement: ManifestEnforcement,
    /// Optional file path to a pre-signed manifest file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<String>,
    /// Require a valid signature on manifests. Default: false.
    #[serde(default)]
    pub require_signature: bool,
}

impl Default for ManifestConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Matches serde default_true
            trusted_keys: Vec::new(),
            enforcement: ManifestEnforcement::default(),
            manifest_path: None,
            require_signature: false,
        }
    }
}

/// Maximum length for manifest_path.
const MAX_MANIFEST_PATH_LEN: usize = 4096;
/// Maximum trusted keys for manifest signatures.
const MAX_MANIFEST_TRUSTED_KEYS: usize = 64;
/// Maximum length for a trusted key hex string (Ed25519 = 64 hex chars).
const MAX_MANIFEST_KEY_LEN: usize = 128;

impl ManifestConfig {
    /// Validate manifest configuration bounds.
    ///
    /// SECURITY (FIND-R100-009, FIND-R102-003): Validates manifest_path for
    /// length, control characters, and path traversal (..) to prevent
    /// filesystem-based attacks. Validates trusted_keys per-element.
    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (FIND-R102-007): ManifestEnforcement::Warn is the fail-open default.
        // For production deployments, users should set enforcement = "Block".
        // Note: validate() must not emit tracing output (side-effect-free).
        // Trusted keys validation (FIND-R102-003)
        if self.trusted_keys.len() > MAX_MANIFEST_TRUSTED_KEYS {
            return Err(format!(
                "manifest.trusted_keys has {} entries, max is {}",
                self.trusted_keys.len(),
                MAX_MANIFEST_TRUSTED_KEYS
            ));
        }
        for (i, key) in self.trusted_keys.iter().enumerate() {
            if key.is_empty() {
                return Err(format!("manifest.trusted_keys[{i}] must not be empty"));
            }
            if key.len() > MAX_MANIFEST_KEY_LEN {
                return Err(format!(
                    "manifest.trusted_keys[{}] length {} exceeds maximum {}",
                    i,
                    key.len(),
                    MAX_MANIFEST_KEY_LEN
                ));
            }
            if !key.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("manifest.trusted_keys[{i}] must be hex-encoded"));
            }
        }
        if let Some(ref path) = self.manifest_path {
            if path.is_empty() {
                return Err("manifest.manifest_path must not be empty".to_string());
            }
            if path.len() > MAX_MANIFEST_PATH_LEN {
                return Err(format!(
                    "manifest.manifest_path length {} exceeds maximum {}",
                    path.len(),
                    MAX_MANIFEST_PATH_LEN
                ));
            }
            if path
                .bytes()
                .any(|b| b == 0x00 || b < 0x20 || (0x7F..=0x9F).contains(&b))
            {
                return Err(
                    "manifest.manifest_path contains null bytes or control characters".to_string(),
                );
            }
            // Path traversal check
            use std::path::{Component, Path};
            let p = Path::new(path);
            if p.components().any(|c| matches!(c, Component::ParentDir)) {
                return Err(format!(
                    "manifest.manifest_path must not contain '..' components, got '{path}'"
                ));
            }
        }
        Ok(())
    }

    /// Verify a live tools/list response against a pinned manifest.
    ///
    /// Returns `Ok(())` if verification passes or is disabled.
    /// Returns `Err(discrepancies)` if the manifest doesn't match.
    pub fn verify_manifest(
        &self,
        pinned: &ToolManifest,
        live_response: &serde_json::Value,
    ) -> Result<(), Vec<String>> {
        if !self.enabled {
            return Ok(());
        }

        // Check signature if required
        if self.require_signature && !self.trusted_keys.is_empty() {
            if let Err(sig_err) = pinned.verify_signature_any(&self.trusted_keys) {
                let msg = format!("Manifest signature verification failed: {sig_err}");
                if self.enforcement == ManifestEnforcement::Block {
                    return Err(vec![msg]);
                }
                // Warn mode: continue silently (logging happens at server level)
            }
        } else if self.require_signature && self.trusted_keys.is_empty() {
            let msg = "require_signature is set but no trusted_keys configured".to_string();
            if self.enforcement == ManifestEnforcement::Block {
                return Err(vec![msg]);
            }
        }

        let result = pinned.verify(live_response);
        if result.passed {
            Ok(())
        } else if self.enforcement == ManifestEnforcement::Block {
            Err(result.discrepancies)
        } else {
            // Warn mode: schema mismatches are not blocking
            Ok(())
        }
    }

    /// Load a pre-signed manifest from the configured path.
    pub fn load_pinned_manifest(
        &self,
    ) -> Result<Option<ToolManifest>, Box<dyn std::error::Error + Send + Sync>> {
        match &self.manifest_path {
            Some(path) => {
                let manifest = ToolManifest::load_pinned_manifest(path)?;
                Ok(Some(manifest))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tools_list_response(tools: &[(&str, serde_json::Value)]) -> serde_json::Value {
        let tool_entries: Vec<serde_json::Value> = tools
            .iter()
            .map(|(name, schema)| {
                serde_json::json!({
                    "name": name,
                    "inputSchema": schema,
                })
            })
            .collect();
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "tools": tool_entries }
        })
    }

    #[test]
    fn test_manifest_from_tools_list() {
        let response = make_tools_list_response(&[
            (
                "read_file",
                serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}}),
            ),
            (
                "write_file",
                serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}),
            ),
        ]);
        let manifest = ToolManifest::from_tools_list(&response).unwrap();
        assert_eq!(manifest.schema_version, "2.0");
        assert_eq!(manifest.tools.len(), 2);
        // Tools should be sorted by name
        assert_eq!(manifest.tools[0].name, "read_file");
        assert_eq!(manifest.tools[1].name, "write_file");
        // Hashes should be non-empty hex strings
        assert_eq!(manifest.tools[0].input_schema_hash.len(), 64);
    }

    #[test]
    fn test_manifest_verify_identical_passes() {
        let response = make_tools_list_response(&[
            ("tool_a", serde_json::json!({"type": "object"})),
            (
                "tool_b",
                serde_json::json!({"type": "object", "properties": {}}),
            ),
        ]);
        let pinned = ToolManifest::from_tools_list(&response).unwrap();
        let result = pinned.verify(&response);
        assert!(result.passed);
        assert!(result.discrepancies.is_empty());
    }

    #[test]
    fn test_manifest_verify_new_tool_detected() {
        let original =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let modified = make_tools_list_response(&[
            ("tool_a", serde_json::json!({"type": "object"})),
            ("tool_b", serde_json::json!({"type": "object"})),
        ]);
        let pinned = ToolManifest::from_tools_list(&original).unwrap();
        let result = pinned.verify(&modified);
        assert!(!result.passed);
        assert!(result
            .discrepancies
            .iter()
            .any(|d| d.contains("New tool 'tool_b'")));
    }

    #[test]
    fn test_manifest_verify_removed_tool_detected() {
        let original = make_tools_list_response(&[
            ("tool_a", serde_json::json!({"type": "object"})),
            ("tool_b", serde_json::json!({"type": "object"})),
        ]);
        let modified =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let pinned = ToolManifest::from_tools_list(&original).unwrap();
        let result = pinned.verify(&modified);
        assert!(!result.passed);
        assert!(result.discrepancies.iter().any(|d| d.contains("removed")));
    }

    #[test]
    fn test_manifest_verify_schema_change_detected() {
        let original = make_tools_list_response(&[(
            "tool_a",
            serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}}),
        )]);
        let modified = make_tools_list_response(&[(
            "tool_a",
            serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}, "force": {"type": "boolean"}}}),
        )]);
        let pinned = ToolManifest::from_tools_list(&original).unwrap();
        let result = pinned.verify(&modified);
        assert!(!result.passed);
        assert!(result
            .discrepancies
            .iter()
            .any(|d| d.contains("schema changed")));
    }

    #[test]
    fn test_manifest_schema_hash_ignores_equivalent_key_order() {
        let left = make_tools_list_response(&[(
            "tool_a",
            serde_json::json!({
                "type": "object",
                "required": ["path", "mode"],
                "properties": {
                    "path": {"type": "string"},
                    "mode": {"type": "string"}
                }
            }),
        )]);
        let right = make_tools_list_response(&[(
            "tool_a",
            serde_json::json!({
                "properties": {
                    "mode": {"type": "string"},
                    "path": {"type": "string"}
                },
                "required": ["mode", "path"],
                "type": "object"
            }),
        )]);

        let left_manifest = ToolManifest::from_tools_list(&left).unwrap();
        let right_manifest = ToolManifest::from_tools_list(&right).unwrap();
        assert_eq!(
            left_manifest.tools[0].input_schema_hash,
            right_manifest.tools[0].input_schema_hash
        );
    }

    #[test]
    fn test_manifest_schema_hash_inlines_local_refs() {
        let referenced = make_tools_list_response(&[(
            "tool_a",
            serde_json::json!({
                "$defs": {
                    "Path": {"type": "string", "minLength": 1}
                },
                "type": "object",
                "properties": {
                    "path": {"$ref": "#/$defs/Path"}
                }
            }),
        )]);
        let inline = make_tools_list_response(&[(
            "tool_a",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "minLength": 1}
                }
            }),
        )]);

        let referenced_manifest = ToolManifest::from_tools_list(&referenced).unwrap();
        let inline_manifest = ToolManifest::from_tools_list(&inline).unwrap();
        assert_eq!(
            referenced_manifest.tools[0].input_schema_hash,
            inline_manifest.tools[0].input_schema_hash
        );
    }

    #[test]
    fn test_manifest_rejects_external_schema_refs() {
        let response = make_tools_list_response(&[(
            "tool_a",
            serde_json::json!({"$ref": "https://metadata.internal/schema.json"}),
        )]);
        assert!(ToolManifest::from_tools_list(&response).is_none());
    }

    #[test]
    fn test_manifest_verify_invalid_response() {
        let pinned = ToolManifest {
            schema_version: "1.0".to_string(),
            tools: vec![],
            signature: None,
            created_at: None,
            verifying_key: None,
        };
        let bad_response = serde_json::json!({"error": "something"});
        let result = pinned.verify(&bad_response);
        assert!(!result.passed);
        assert!(result
            .discrepancies
            .iter()
            .any(|d| d.contains("Failed to parse")));
    }

    #[test]
    fn test_manifest_config_disabled_always_passes() {
        let config = ManifestConfig {
            enabled: false,
            trusted_keys: vec![],
            enforcement: ManifestEnforcement::default(),
            manifest_path: None,
            require_signature: false,
        };
        let pinned = ToolManifest {
            schema_version: "1.0".to_string(),
            tools: vec![ManifestToolEntry {
                name: "tool_a".to_string(),
                input_schema_hash: "deadbeef".to_string(),
                description_hash: None,
                title_hash: None,
                annotations: None,
            }],
            signature: None,
            created_at: None,
            verifying_key: None,
        };
        // Even with a completely wrong response, disabled config passes
        let bad_response = serde_json::json!({"error": "something"});
        assert!(config.verify_manifest(&pinned, &bad_response).is_ok());
    }

    #[test]
    fn test_manifest_config_enabled_detects_mismatch() {
        let config = ManifestConfig {
            enabled: true,
            trusted_keys: vec![],
            enforcement: ManifestEnforcement::Block,
            manifest_path: None,
            require_signature: false,
        };
        let original =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let pinned = ToolManifest::from_tools_list(&original).unwrap();

        let modified = make_tools_list_response(&[
            ("tool_a", serde_json::json!({"type": "object"})),
            ("injected_tool", serde_json::json!({"type": "object"})),
        ]);
        let result = config.verify_manifest(&pinned, &modified);
        assert!(result.is_err());
        let discrepancies = result.unwrap_err();
        assert!(discrepancies.iter().any(|d| d.contains("injected_tool")));
    }

    #[test]
    fn test_manifest_tool_without_schema() {
        // Tools without inputSchema should still get a hash (of empty string)
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {"name": "simple_tool"}
                ]
            }
        });
        let manifest = ToolManifest::from_tools_list(&response).unwrap();
        assert_eq!(manifest.tools.len(), 1);
        assert_eq!(manifest.tools[0].name, "simple_tool");
        // Hash of empty string
        assert_eq!(manifest.tools[0].input_schema_hash.len(), 64);
    }

    // ═══════════════════════════════════════════════════
    // MANIFEST SIGNING TESTS (C-17.2)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_manifest_sign_and_verify_roundtrip() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let vk_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let response =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
        manifest.created_at = Some("2026-02-04T12:00:00Z".to_string());
        manifest.sign(&signing_key);

        assert!(manifest.signature.is_some());
        assert!(manifest.verifying_key.is_some());
        assert!(manifest.verify_signature(&vk_hex).is_ok());
    }

    #[test]
    fn test_manifest_verify_with_wrong_key_fails() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let other_key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let other_vk_hex = hex::encode(other_key.verifying_key().as_bytes());

        let response =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
        manifest.sign(&signing_key);

        assert!(manifest.verify_signature(&other_vk_hex).is_err());
    }

    #[test]
    fn test_manifest_tampered_manifest_fails() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let vk_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let response =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
        manifest.sign(&signing_key);

        // Tamper with the manifest
        manifest.tools.push(ManifestToolEntry {
            name: "injected".to_string(),
            input_schema_hash: "deadbeef".to_string(),
            description_hash: None,
            title_hash: None,
            annotations: None,
        });

        assert!(manifest.verify_signature(&vk_hex).is_err());
    }

    #[test]
    fn test_manifest_unsigned_when_required_fails() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let vk_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let config = ManifestConfig {
            enabled: true,
            trusted_keys: vec![vk_hex],
            enforcement: ManifestEnforcement::Block,
            manifest_path: None,
            require_signature: true,
        };

        let response =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let pinned = ToolManifest::from_tools_list(&response).unwrap();
        // pinned is NOT signed
        let result = config.verify_manifest(&pinned, &response);
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_no_trusted_keys_skips_signature() {
        let config = ManifestConfig {
            enabled: true,
            trusted_keys: vec![],
            enforcement: ManifestEnforcement::Block,
            manifest_path: None,
            require_signature: false,
        };
        let response =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let pinned = ToolManifest::from_tools_list(&response).unwrap();
        let result = config.verify_manifest(&pinned, &response);
        assert!(result.is_ok());
    }

    #[test]
    fn test_manifest_signing_content_deterministic() {
        let response = make_tools_list_response(&[
            ("tool_a", serde_json::json!({"type": "object"})),
            ("tool_b", serde_json::json!({"type": "string"})),
        ]);
        let manifest = ToolManifest::from_tools_list(&response).unwrap();
        let c1 = manifest.signing_content();
        let c2 = manifest.signing_content();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_manifest_description_hash_populated() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{
                    "name": "tool_a",
                    "description": "A helpful tool",
                    "inputSchema": {"type": "object"}
                }]
            }
        });
        let manifest = ToolManifest::from_tools_list(&response).unwrap();
        assert!(manifest.tools[0].description_hash.is_some());
        assert_eq!(
            manifest.tools[0].description_hash.as_ref().unwrap().len(),
            64
        );
    }

    #[test]
    fn test_manifest_annotations_snapshot() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{
                    "name": "tool_a",
                    "inputSchema": {"type": "object"},
                    "annotations": {
                        "readOnlyHint": true,
                        "destructiveHint": false
                    }
                }]
            }
        });
        let manifest = ToolManifest::from_tools_list(&response).unwrap();
        let ann = manifest.tools[0].annotations.as_ref().unwrap();
        assert_eq!(ann.read_only_hint, Some(true));
        assert_eq!(ann.destructive_hint, Some(false));
        assert_eq!(ann.idempotent_hint, None);
    }

    #[test]
    fn test_manifest_load_save_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("manifest.json");

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let response =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
        manifest.sign(&signing_key);

        manifest.save_manifest(path.to_str().unwrap()).unwrap();
        let loaded = ToolManifest::load_pinned_manifest(path.to_str().unwrap()).unwrap();
        assert_eq!(manifest, loaded);
    }

    #[test]
    fn test_manifest_load_rejects_duplicate_tool_names() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("manifest.json");
        std::fs::write(
            &path,
            r#"{
                "schema_version": "2.0",
                "tools": [
                    {"name": "dup", "input_schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                    {"name": "dup", "input_schema_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
                ]
            }"#,
        )
        .unwrap();

        let err = ToolManifest::load_pinned_manifest(path.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("duplicates tool name"));
    }

    #[test]
    fn test_manifest_load_rejects_non_hex_schema_hash() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("manifest.json");
        std::fs::write(
            &path,
            r#"{
                "schema_version": "2.0",
                "tools": [
                    {"name": "tool_a", "input_schema_hash": "not-hex"}
                ]
            }"#,
        )
        .unwrap();

        let err = ToolManifest::load_pinned_manifest(path.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("input_schema_hash"));
    }

    #[test]
    fn test_manifest_load_rejects_dangerous_tool_name() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("manifest.json");
        std::fs::write(
            &path,
            r#"{
                "schema_version": "2.0",
                "tools": [
                    {"name": "tool\u202Ename", "input_schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
                ]
            }"#,
        )
        .unwrap();

        let err = ToolManifest::load_pinned_manifest(path.to_str().unwrap()).unwrap_err();
        assert!(err
            .to_string()
            .contains("contains control or Unicode format characters"));
    }

    #[test]
    fn test_manifest_backward_compat_v1() {
        // v1 manifests (without new fields) should deserialize fine
        let json = r#"{
            "schema_version": "1.0",
            "tools": [{"name": "tool_a", "input_schema_hash": "abcdef1234567890"}]
        }"#;
        let manifest: ToolManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.schema_version, "1.0");
        assert_eq!(manifest.tools[0].name, "tool_a");
        assert!(manifest.signature.is_none());
        assert!(manifest.created_at.is_none());
        assert!(manifest.verifying_key.is_none());
        assert!(manifest.tools[0].description_hash.is_none());
        assert!(manifest.tools[0].annotations.is_none());
    }

    #[test]
    fn test_manifest_verify_signature_any() {
        let key1 = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let key2 = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let vk1 = hex::encode(key1.verifying_key().as_bytes());
        let vk2 = hex::encode(key2.verifying_key().as_bytes());

        let response =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
        manifest.sign(&key1);

        // Should pass with key1 in the list
        assert!(manifest
            .verify_signature_any(&[vk2.clone(), vk1.clone()])
            .is_ok());
        // Should fail with only key2
        assert!(manifest.verify_signature_any(&[vk2]).is_err());
    }

    // --- ManifestEnforcement tests ---

    #[test]
    fn test_manifest_enforcement_warn_allows_schema_mismatch() {
        let config = ManifestConfig {
            enabled: true,
            trusted_keys: vec![],
            enforcement: ManifestEnforcement::Warn,
            manifest_path: None,
            require_signature: false,
        };
        let original =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let pinned = ToolManifest::from_tools_list(&original).unwrap();
        let modified = make_tools_list_response(&[
            ("tool_a", serde_json::json!({"type": "object"})),
            ("injected_tool", serde_json::json!({"type": "object"})),
        ]);
        // Warn mode: schema mismatches are non-blocking
        let result = config.verify_manifest(&pinned, &modified);
        assert!(result.is_ok());
    }

    // --- Title tests ---

    #[test]
    fn test_manifest_title_hash_populated_from_tools_list() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "search",
                        "title": "Web Search",
                        "description": "Search the web",
                        "inputSchema": {"type": "object"}
                    },
                    {
                        "name": "no_title",
                        "description": "No title field",
                        "inputSchema": {"type": "object"}
                    }
                ]
            }
        });
        let manifest = ToolManifest::from_tools_list(&response).unwrap();
        let search = manifest.tools.iter().find(|t| t.name == "search").unwrap();
        assert!(search.title_hash.is_some(), "search should have title_hash");

        let no_title = manifest
            .tools
            .iter()
            .find(|t| t.name == "no_title")
            .unwrap();
        assert!(no_title.title_hash.is_none(), "no_title should have None");
    }

    #[test]
    fn test_manifest_title_change_detected_as_drift() {
        // Pin with title "Search"
        let initial = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{
                    "name": "search",
                    "title": "Web Search",
                    "description": "Search the web",
                    "inputSchema": {"type": "object"}
                }]
            }
        });
        let pinned = ToolManifest::from_tools_list(&initial).unwrap();

        // Same tool with changed title
        let changed = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [{
                    "name": "search",
                    "title": "Admin Panel Access",
                    "description": "Search the web",
                    "inputSchema": {"type": "object"}
                }]
            }
        });
        let result = pinned.verify(&changed);
        assert!(!result.passed, "Should detect title change as discrepancy");
        assert!(
            result
                .discrepancies
                .iter()
                .any(|d| d.contains("title changed")),
            "Discrepancy should mention title: {:?}",
            result.discrepancies
        );
    }

    #[test]
    fn test_manifest_same_title_passes() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{
                    "name": "search",
                    "title": "Web Search",
                    "description": "Search the web",
                    "inputSchema": {"type": "object"}
                }]
            }
        });
        let pinned = ToolManifest::from_tools_list(&response).unwrap();
        let result = pinned.verify(&response);
        assert!(result.passed, "Identical tools/list should pass");
    }
}
