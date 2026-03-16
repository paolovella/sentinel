// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Phase 2: AI asset inventory types.
//!
//! Extends the MCP topology graph into an operator-facing AI BOM (Bill of
//! Materials) that catalogs servers, tools, and their security posture.

use serde::{Deserialize, Serialize};

/// A cataloged AI asset (MCP server or tool) with security metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AiAsset {
    /// Unique asset identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Asset type.
    pub asset_type: AiAssetType,
    /// Server that provides this asset (for tools).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    /// Current trust level.
    #[serde(default)]
    pub trust_level: AssetTrustLevel,
    /// Whether the asset is currently active/reachable.
    #[serde(default)]
    pub active: bool,
    /// ISO 8601 timestamp when first discovered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    /// ISO 8601 timestamp of last activity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// Security annotations.
    #[serde(default)]
    pub security: AssetSecurityMetadata,
    /// Operator-defined tags for grouping and filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Asset type classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AiAssetType {
    /// MCP server.
    Server,
    /// Individual tool provided by a server.
    Tool,
    /// Resource endpoint.
    Resource,
    /// Prompt template.
    Prompt,
}

/// Trust level for an asset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AssetTrustLevel {
    /// Trust has not been evaluated.
    #[default]
    Unknown,
    /// Asset has been flagged for security concerns.
    Blocked,
    /// Asset has low trust (negative signals).
    Low,
    /// Asset is trusted by default.
    Default,
    /// Asset has been explicitly verified.
    Verified,
}

/// Security metadata for an asset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AssetSecurityMetadata {
    /// Whether the asset has a signed tool definition (ETDI).
    #[serde(default)]
    pub has_signed_definition: bool,
    /// Whether schema drift has been detected.
    #[serde(default)]
    pub schema_drift_detected: bool,
    /// Number of injection findings associated with this asset.
    #[serde(default)]
    pub injection_finding_count: u32,
    /// Number of DLP findings associated with this asset.
    #[serde(default)]
    pub dlp_finding_count: u32,
    /// Reputation score (0-100, 100 = clean). None if not scored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation_score: Option<u32>,
    /// Applicable compliance frameworks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compliance_frameworks: Vec<String>,
}

/// A complete AI asset inventory snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AiAssetInventory {
    /// All cataloged assets.
    pub assets: Vec<AiAsset>,
    /// ISO 8601 timestamp when the inventory was generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    /// Total servers in the inventory.
    #[serde(default)]
    pub server_count: usize,
    /// Total tools in the inventory.
    #[serde(default)]
    pub tool_count: usize,
}

impl AiAssetInventory {
    /// Create a new empty inventory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an asset to the inventory.
    pub fn add_asset(&mut self, asset: AiAsset) {
        match asset.asset_type {
            AiAssetType::Server => self.server_count = self.server_count.saturating_add(1),
            AiAssetType::Tool => self.tool_count = self.tool_count.saturating_add(1),
            _ => {}
        }
        self.assets.push(asset);
    }

    /// Find an asset by ID.
    pub fn find_by_id(&self, id: &str) -> Option<&AiAsset> {
        self.assets.iter().find(|a| a.id == id)
    }

    /// List assets by type.
    pub fn by_type(&self, asset_type: AiAssetType) -> Vec<&AiAsset> {
        self.assets
            .iter()
            .filter(|a| a.asset_type == asset_type)
            .collect()
    }

    /// List assets below a trust threshold.
    pub fn below_trust(&self, max_level: AssetTrustLevel) -> Vec<&AiAsset> {
        let max_ord = trust_level_ord(&max_level);
        self.assets
            .iter()
            .filter(|a| trust_level_ord(&a.trust_level) <= max_ord)
            .collect()
    }
}

fn trust_level_ord(level: &AssetTrustLevel) -> u8 {
    match level {
        AssetTrustLevel::Blocked => 0,
        AssetTrustLevel::Low => 1,
        AssetTrustLevel::Unknown => 2,
        AssetTrustLevel::Default => 3,
        AssetTrustLevel::Verified => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tool(id: &str, server: &str, trust: AssetTrustLevel) -> AiAsset {
        AiAsset {
            id: id.to_string(),
            name: id.to_string(),
            asset_type: AiAssetType::Tool,
            server_id: Some(server.to_string()),
            trust_level: trust,
            active: true,
            first_seen: None,
            last_seen: None,
            security: AssetSecurityMetadata::default(),
            tags: Vec::new(),
        }
    }

    #[test]
    fn test_inventory_add_and_find() {
        let mut inv = AiAssetInventory::new();
        inv.add_asset(make_tool("read_file", "fs-server", AssetTrustLevel::Verified));
        inv.add_asset(make_tool("write_file", "fs-server", AssetTrustLevel::Default));
        assert_eq!(inv.tool_count, 2);
        assert!(inv.find_by_id("read_file").is_some());
        assert!(inv.find_by_id("unknown").is_none());
    }

    #[test]
    fn test_inventory_by_type() {
        let mut inv = AiAssetInventory::new();
        inv.add_asset(AiAsset {
            id: "srv".to_string(),
            name: "server".to_string(),
            asset_type: AiAssetType::Server,
            server_id: None,
            trust_level: AssetTrustLevel::Default,
            active: true,
            first_seen: None,
            last_seen: None,
            security: AssetSecurityMetadata::default(),
            tags: Vec::new(),
        });
        inv.add_asset(make_tool("t1", "srv", AssetTrustLevel::Default));
        assert_eq!(inv.by_type(AiAssetType::Server).len(), 1);
        assert_eq!(inv.by_type(AiAssetType::Tool).len(), 1);
    }

    #[test]
    fn test_inventory_below_trust() {
        let mut inv = AiAssetInventory::new();
        inv.add_asset(make_tool("good", "s", AssetTrustLevel::Verified));
        inv.add_asset(make_tool("ok", "s", AssetTrustLevel::Default));
        inv.add_asset(make_tool("bad", "s", AssetTrustLevel::Low));
        inv.add_asset(make_tool("blocked", "s", AssetTrustLevel::Blocked));

        let low = inv.below_trust(AssetTrustLevel::Low);
        assert_eq!(low.len(), 2); // Low + Blocked
        assert!(low.iter().any(|a| a.id == "bad"));
        assert!(low.iter().any(|a| a.id == "blocked"));
    }

    #[test]
    fn test_security_metadata_defaults() {
        let meta = AssetSecurityMetadata::default();
        assert!(!meta.has_signed_definition);
        assert!(!meta.schema_drift_detected);
        assert_eq!(meta.injection_finding_count, 0);
        assert_eq!(meta.reputation_score, None);
    }
}
