// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! MCP protocol version parsing and ordering.

use core::fmt;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// MCP protocol versions known to Vellaveto.
///
/// Variants are ordered from oldest to newest so policy floors can use normal
/// ordering comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum McpProtocolVersion {
    V2025_03_26,
    V2025_06_18,
    V2025_11_25,
    V2026_07_28,
}

impl McpProtocolVersion {
    /// Known versions, highest preference first.
    pub const SUPPORTED_DESCENDING: &'static [Self] = &[
        Self::V2026_07_28,
        Self::V2025_11_25,
        Self::V2025_06_18,
        Self::V2025_03_26,
    ];

    /// Version string used on the MCP wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2025_03_26 => "2025-03-26",
            Self::V2025_06_18 => "2025-06-18",
            Self::V2025_11_25 => "2025-11-25",
            Self::V2026_07_28 => "2026-07-28",
        }
    }
}

impl fmt::Display for McpProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when an MCP protocol version string is not recognized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseMcpProtocolVersionError;

impl fmt::Display for ParseMcpProtocolVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown MCP protocol version")
    }
}

impl std::error::Error for ParseMcpProtocolVersionError {}

impl FromStr for McpProtocolVersion {
    type Err = ParseMcpProtocolVersionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "2025-03-26" => Ok(Self::V2025_03_26),
            "2025-06-18" => Ok(Self::V2025_06_18),
            "2025-11-25" => Ok(Self::V2025_11_25),
            "2026-07-28" => Ok(Self::V2026_07_28),
            _ => Err(ParseMcpProtocolVersionError),
        }
    }
}

impl Serialize for McpProtocolVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for McpProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_order_matches_release_order() {
        assert!(McpProtocolVersion::V2026_07_28 > McpProtocolVersion::V2025_11_25);
        assert!(McpProtocolVersion::V2025_11_25 > McpProtocolVersion::V2025_06_18);
        assert!(McpProtocolVersion::V2025_06_18 > McpProtocolVersion::V2025_03_26);
    }

    #[test]
    fn protocol_version_serializes_as_wire_string() {
        let encoded =
            serde_json::to_string(&McpProtocolVersion::V2026_07_28).expect("serialize version");
        assert_eq!(encoded, "\"2026-07-28\"");
        let decoded: McpProtocolVersion =
            serde_json::from_str(&encoded).expect("deserialize version");
        assert_eq!(decoded, McpProtocolVersion::V2026_07_28);
    }

    #[test]
    fn protocol_version_rejects_unknown_values() {
        assert!("2026-07-29".parse::<McpProtocolVersion>().is_err());
    }
}
