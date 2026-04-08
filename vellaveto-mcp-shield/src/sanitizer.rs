// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Bidirectional PII sanitization using vellaveto-audit's PiiScanner.

use crate::error::ShieldError;
use rand::RngExt;
use std::collections::HashMap;
use std::sync::Mutex;
use vellaveto_audit::PiiScanner;

/// Maximum PII mappings before fail-closed.
const MAX_PII_MAPPINGS: usize = 50_000;

/// Maximum JSON recursion depth for sanitize_json/desanitize_json.
const MAX_JSON_DEPTH: usize = 20;

/// A recorded PII mapping for bidirectional restoration.
#[derive(Debug, Clone)]
struct PiiMapping {
    original: String,
    #[allow(dead_code)]
    category: String,
}

/// Bidirectional PII sanitizer that replaces PII with placeholders and
/// can restore original values from placeholders.
pub struct QuerySanitizer {
    scanner: PiiScanner,
    mappings: Mutex<HashMap<String, PiiMapping>>,
    sequence: Mutex<u64>,
}

impl QuerySanitizer {
    /// Create a new sanitizer using the given PII scanner.
    pub fn new(scanner: PiiScanner) -> Self {
        Self {
            scanner,
            mappings: Mutex::new(HashMap::new()),
            sequence: Mutex::new(0),
        }
    }

    /// Sanitize input text, replacing PII with `[PII_{CAT}_{TOKEN}]` placeholders.
    pub fn sanitize(&self, input: &str) -> Result<String, ShieldError> {
        let matches = self.scanner.find_matches(input);
        if matches.is_empty() {
            return Ok(input.to_string());
        }

        let mut mappings = self
            .mappings
            .lock()
            .map_err(|e| ShieldError::Sanitization(format!("lock poisoned: {e}")))?;
        let mut seq = self
            .sequence
            .lock()
            .map_err(|e| ShieldError::Sanitization(format!("lock poisoned: {e}")))?;

        let mut result = String::with_capacity(input.len());
        let mut last_end = 0;

        // Process matches in order (find_matches returns sorted by position)
        for m in &matches {
            if mappings.len() >= MAX_PII_MAPPINGS {
                return Err(ShieldError::Sanitization(
                    "PII mapping capacity exhausted (fail-closed)".to_string(),
                ));
            }

            result.push_str(&input[last_end..m.start]);
            // SECURITY (R242-SHLD-1): Use an unpredictable token instead of
            // a sequential counter so placeholders cannot be guessed and
            // probed as a desanitization oracle.
            let placeholder = loop {
                let token: u64 = rand::rng().random();
                let candidate = format!("[PII_{}_{:016X}]", m.category.to_uppercase(), token);
                if !mappings.contains_key(&candidate) {
                    break candidate;
                }
            };
            mappings.insert(
                placeholder.clone(),
                PiiMapping {
                    original: m.text.clone(),
                    category: m.category.clone(),
                },
            );
            *seq = seq.saturating_add(1);
            result.push_str(&placeholder);
            last_end = m.end;
        }
        result.push_str(&input[last_end..]);
        Ok(result)
    }

    /// Restore original PII values from placeholders in the text.
    pub fn desanitize(&self, input: &str) -> Result<String, ShieldError> {
        let mappings = self
            .mappings
            .lock()
            .map_err(|e| ShieldError::Desanitization(format!("lock poisoned: {e}")))?;

        if mappings.is_empty() {
            return Ok(input.to_string());
        }

        let mut result = input.to_string();
        for (placeholder, mapping) in mappings.iter() {
            result = result.replace(placeholder, &mapping.original);
        }
        Ok(result)
    }

    /// Recursively sanitize all string values in a JSON value.
    pub fn sanitize_json(
        &self,
        value: &serde_json::Value,
    ) -> Result<serde_json::Value, ShieldError> {
        self.walk_json(value, true, 0)
    }

    /// Recursively desanitize all string values in a JSON value.
    pub fn desanitize_json(
        &self,
        value: &serde_json::Value,
    ) -> Result<serde_json::Value, ShieldError> {
        self.walk_json(value, false, 0)
    }

    /// Recursive JSON walker for sanitize/desanitize.
    fn walk_json(
        &self,
        value: &serde_json::Value,
        sanitize: bool,
        depth: usize,
    ) -> Result<serde_json::Value, ShieldError> {
        if depth > MAX_JSON_DEPTH {
            return Err(ShieldError::Sanitization(
                "JSON recursion depth exceeded".to_string(),
            ));
        }

        match value {
            serde_json::Value::String(s) => {
                let processed = if sanitize {
                    self.sanitize(s)?
                } else {
                    self.desanitize(s)?
                };
                Ok(serde_json::Value::String(processed))
            }
            serde_json::Value::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len());
                for item in arr {
                    result.push(self.walk_json(item, sanitize, depth + 1)?);
                }
                Ok(serde_json::Value::Array(result))
            }
            // SECURITY (R242-SHLD-2): Sanitize/desanitize JSON object keys, not just
            // values. PII embedded in key names (e.g. dynamic keys from database columns,
            // filenames, usernames) would otherwise pass through unsanitized.
            serde_json::Value::Object(map) => {
                let mut result = serde_json::Map::new();
                for (key, val) in map {
                    let processed_key = if sanitize {
                        self.sanitize(key)?
                    } else {
                        self.desanitize(key)?
                    };
                    result.insert(processed_key, self.walk_json(val, sanitize, depth + 1)?);
                }
                Ok(serde_json::Value::Object(result))
            }
            other => Ok(other.clone()),
        }
    }

    /// Clear all PII mappings. Call this when a session ends.
    ///
    /// SECURITY (R234-SHIELD-12): Recover from lock poisoning via `into_inner()`
    /// and log the event. Silently skipping clear on poisoning would leave stale
    /// PII mappings from a previous (crashed) session.
    pub fn clear(&self) {
        match self.mappings.lock() {
            Ok(mut mappings) => mappings.clear(),
            Err(poisoned) => {
                tracing::error!(
                    "SECURITY: sanitizer mappings lock poisoned during clear — recovering"
                );
                poisoned.into_inner().clear();
            }
        }
        match self.sequence.lock() {
            Ok(mut seq) => *seq = 0,
            Err(poisoned) => {
                tracing::error!(
                    "SECURITY: sanitizer sequence lock poisoned during clear — recovering"
                );
                *poisoned.into_inner() = 0;
            }
        }
    }

    /// Check whether a placeholder key is known to this sanitizer's mapping table.
    ///
    /// SECURITY (R242-SHLD-3): Used by SessionIsolator to distinguish between
    /// placeholders that belong to THIS session (reject if stale) vs placeholders
    /// from OTHER sessions (pass through unchanged during desanitization).
    pub fn has_placeholder(&self, placeholder: &str) -> bool {
        match self.mappings.lock() {
            Ok(m) => m.contains_key(placeholder),
            Err(_) => {
                // Fail-closed: if lock poisoned, assume placeholder is known
                // (will be rejected by the staleness check → Deny).
                tracing::error!("QuerySanitizer lock poisoned in has_placeholder");
                true
            }
        }
    }

    /// Get the current number of PII mappings.
    pub fn mapping_count(&self) -> usize {
        match self.mappings.lock() {
            Ok(m) => m.len(),
            Err(_) => {
                // SECURITY (R240-P3-SHLD-3): Log poisoning instead of silent 0.
                tracing::error!("QuerySanitizer lock poisoned in mapping_count");
                0
            }
        }
    }
}

impl std::fmt::Debug for QuerySanitizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuerySanitizer")
            .field("mappings", &"[REDACTED]")
            .field("scanner", &self.scanner)
            .finish()
    }
}
