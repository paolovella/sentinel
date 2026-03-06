// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Bidirectional PII sanitization using vellaveto-audit's PiiScanner.

use crate::error::ShieldError;
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

    /// Sanitize input text, replacing PII with `[PII_{CAT}_{SEQ:06}]` placeholders.
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
            let placeholder = format!("[PII_{}_{:06}]", m.category.to_uppercase(), *seq);
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
            serde_json::Value::Object(map) => {
                let mut result = serde_json::Map::new();
                for (key, val) in map {
                    result.insert(key.clone(), self.walk_json(val, sanitize, depth + 1)?);
                }
                Ok(serde_json::Value::Object(result))
            }
            other => Ok(other.clone()),
        }
    }

    /// Clear all PII mappings. Call this when a session ends.
    pub fn clear(&self) {
        if let Ok(mut mappings) = self.mappings.lock() {
            mappings.clear();
        }
        if let Ok(mut seq) = self.sequence.lock() {
            *seq = 0;
        }
    }

    /// Get the current number of PII mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.lock().map(|m| m.len()).unwrap_or(0)
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
