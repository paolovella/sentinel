// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Schema poisoning detection (OWASP ASI05).
//!
//! Tracks tool schema changes over time and alerts or blocks when schemas
//! change beyond a configured threshold. This prevents rug-pull attacks
//! where tool behavior changes maliciously after initial trust is established.
//!
//! # Example
//!
//! ```rust,ignore
//! use vellaveto_mcp::schema_poisoning::SchemaLineageTracker;
//! use serde_json::json;
//!
//! let tracker = SchemaLineageTracker::new(0.1, 3, 1000);
//!
//! // First observation
//! let schema = json!({"type": "object", "properties": {}});
//! tracker.observe_schema("my_tool", &schema);
//!
//! // Later, detect if schema changed too much
//! let result = tracker.detect_poisoning("my_tool", &schema);
//! assert!(result.is_ok());
//! ```

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use vellaveto_types::SchemaRecord;

/// Result of a schema observation.
#[derive(Debug, Clone, PartialEq)]
pub enum ObservationResult {
    /// First time seeing this schema.
    FirstSeen,
    /// Schema unchanged from previous observation.
    Unchanged,
    /// Schema changed but within acceptable threshold.
    MinorChange { similarity: f32 },
    /// Schema changed beyond threshold - potential poisoning.
    MajorChange {
        similarity: f32,
        alert: PoisoningAlert,
    },
}

/// Alert for schema poisoning.
#[derive(Debug, Clone, PartialEq)]
pub struct PoisoningAlert {
    /// Name of the affected tool.
    pub tool: String,
    /// Hash of the previous schema.
    pub previous_hash: String,
    /// Hash of the current schema.
    pub current_hash: String,
    /// Similarity between schemas (0.0-1.0).
    pub similarity: f32,
    /// Fields that changed (if detectable).
    pub changed_fields: Vec<String>,
}

impl std::fmt::Display for PoisoningAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Schema poisoning detected for '{}': similarity {:.1}% (threshold exceeded)",
            self.tool,
            self.similarity * 100.0
        )
    }
}

// PoisoningAlert retains manual Display + Error impls because thiserror's
// `#[error(...)]` attribute would need complex formatting that is clearer inline.
impl std::error::Error for PoisoningAlert {}

/// Multiplicative factor applied to `trust_score` when a schema change is observed.
/// A value of 0.5 halves the trust on each schema mutation.
const TRUST_DECAY_FACTOR: f32 = 0.5;

/// Tracks schema lineage for poisoning detection.
#[derive(Debug)]
pub struct SchemaLineageTracker {
    /// Schema records by tool name.
    schemas: RwLock<HashMap<String, SchemaRecord>>,
    /// Maximum allowed schema change (0.0-1.0). Changes above this trigger alerts.
    mutation_threshold: f32,
    /// Minimum observations before establishing trust.
    min_observations: u32,
    /// Maximum tool schemas to track.
    max_schemas: usize,
}

impl SchemaLineageTracker {
    /// Create a new schema lineage tracker.
    ///
    /// # Arguments
    /// * `mutation_threshold` - Maximum allowed change (0.0-1.0)
    /// * `min_observations` - Observations needed before trust
    /// * `max_schemas` - Maximum schemas to track
    pub fn new(mutation_threshold: f32, min_observations: u32, max_schemas: usize) -> Self {
        Self {
            schemas: RwLock::new(HashMap::new()),
            mutation_threshold: mutation_threshold.clamp(0.0, 1.0),
            min_observations,
            max_schemas,
        }
    }

    /// Create a shareable reference to this tracker.
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Get the current timestamp as Unix seconds.
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Compute SHA-256 hash of a schema.
    fn hash_schema(schema: &Value) -> String {
        // Canonicalize by serializing without whitespace
        let canonical = serde_json::to_string(schema).unwrap_or_else(|e| {
            tracing::warn!(target: "vellaveto::security", error = %e, "Schema serialization failed in hash_schema, using empty string");
            String::new()
        });
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Calculate similarity between two schemas (0.0-1.0).
    ///
    /// Uses Jaccard similarity on character trigrams for a balance between
    /// accuracy and performance. More sophisticated semantic comparison
    /// could be added later.
    fn calculate_similarity(old_schema: &Value, new_schema: &Value) -> f32 {
        // Simple approach: compare JSON structure
        let old_str = serde_json::to_string(old_schema).unwrap_or_else(|e| {
            tracing::warn!(target: "vellaveto::security", error = %e, "Schema serialization failed in calculate_similarity (old), using empty string");
            String::new()
        });
        let new_str = serde_json::to_string(new_schema).unwrap_or_else(|e| {
            tracing::warn!(target: "vellaveto::security", error = %e, "Schema serialization failed in calculate_similarity (new), using empty string");
            String::new()
        });

        if old_str == new_str {
            return 1.0;
        }

        // Calculate Jaccard similarity on character trigrams
        let old_trigrams: std::collections::HashSet<_> = old_str
            .chars()
            .collect::<Vec<_>>()
            .windows(3)
            .map(|w| (w[0], w[1], w[2]))
            .collect();
        let new_trigrams: std::collections::HashSet<_> = new_str
            .chars()
            .collect::<Vec<_>>()
            .windows(3)
            .map(|w| (w[0], w[1], w[2]))
            .collect();

        if old_trigrams.is_empty() && new_trigrams.is_empty() {
            return 1.0;
        }

        let intersection = old_trigrams.intersection(&new_trigrams).count();
        let union = old_trigrams.union(&new_trigrams).count();

        if union == 0 {
            1.0
        } else {
            intersection as f32 / union as f32
        }
    }

    /// Detect changed fields between schemas.
    ///
    /// Returns a list of changes with prefixes:
    /// - `+field` for added fields
    /// - `-field` for removed fields
    /// - `~field` for modified fields
    fn detect_changes(old_schema: &Value, new_schema: &Value) -> Vec<String> {
        let mut changes = Vec::new();

        if let (Some(old_obj), Some(new_obj)) = (old_schema.as_object(), new_schema.as_object()) {
            // Check for removed or changed fields
            for key in old_obj.keys() {
                if !new_obj.contains_key(key) {
                    changes.push(format!("-{key}"));
                } else if old_obj.get(key) != new_obj.get(key) {
                    changes.push(format!("~{key}"));
                }
            }

            // Check for added fields
            for key in new_obj.keys() {
                if !old_obj.contains_key(key) {
                    changes.push(format!("+{key}"));
                }
            }
        }

        changes
    }

    /// Record a schema observation.
    ///
    /// Returns the observation result indicating whether this is new,
    /// unchanged, or changed.
    ///
    /// SECURITY (R33-006): When schema content is available, uses actual
    /// field-level comparison instead of heuristics for accurate detection.
    pub fn observe_schema(&self, tool: &str, schema: &Value) -> ObservationResult {
        let now = Self::now();
        let hash = Self::hash_schema(schema);

        let mut schemas = match self.schemas.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SchemaPoisoningDetector::observe_schema");
                return ObservationResult::MajorChange {
                    similarity: 0.0,
                    alert: PoisoningAlert {
                        tool: tool.to_string(),
                        previous_hash: String::new(),
                        current_hash: hash,
                        similarity: 0.0,
                        changed_fields: vec!["lock_poisoned".to_string()],
                    },
                };
            }
        };

        // Check if we have a previous record
        if let Some(record) = schemas.get_mut(tool) {
            if record.schema_hash == hash {
                // Same schema, just update timestamp
                record.last_seen = now;
                return ObservationResult::Unchanged;
            }

            // SECURITY (R33-006): Use actual schema comparison when available
            let (similarity, changed_fields) = if let Some(ref old_schema) = record.schema_content {
                let sim = Self::calculate_similarity(old_schema, schema);
                let changes = Self::detect_changes(old_schema, schema);
                (sim, changes)
            } else {
                // Fall back to heuristic when schema content not available
                let sim = if record.version_history.is_empty() {
                    0.5 // Unknown similarity for first change
                } else {
                    // Rough estimate based on version count
                    1.0 - (1.0 / (record.version_count() as f32 + 1.0))
                };
                (sim, Vec::new())
            };

            // Update record with new schema
            let old_hash = record.schema_hash.clone();
            if record.version_history.len() < 10 {
                record.version_history.push(old_hash.clone());
            }
            record.schema_hash = hash.clone();
            record.last_seen = now;

            // SECURITY (R33-006): Store new schema content if under size limit
            let schema_str = serde_json::to_string(schema).unwrap_or_else(|e| {
                tracing::warn!(target: "vellaveto::security", error = %e, "Schema serialization failed in observe_schema, using empty string");
                String::new()
            });
            if schema_str.len() <= SchemaRecord::MAX_SCHEMA_SIZE {
                record.schema_content = Some(schema.clone());
            }

            // Decay trust on change
            record.trust_score = (record.trust_score * TRUST_DECAY_FACTOR).max(0.0);

            if similarity < 1.0 - self.mutation_threshold {
                ObservationResult::MajorChange {
                    similarity,
                    alert: PoisoningAlert {
                        tool: tool.to_string(),
                        previous_hash: old_hash,
                        current_hash: hash,
                        similarity,
                        changed_fields,
                    },
                }
            } else {
                ObservationResult::MinorChange { similarity }
            }
        } else {
            // First observation - evict if at capacity
            if schemas.len() >= self.max_schemas {
                self.evict_oldest_internal(&mut schemas);
            }

            // SECURITY (R33-006): Store schema content for future comparisons
            schemas.insert(
                tool.to_string(),
                SchemaRecord::new_with_content(tool, hash, schema, now),
            );

            tracing::debug!(
                target: "vellaveto::security",
                tool = %tool,
                "First schema observation recorded"
            );

            ObservationResult::FirstSeen
        }
    }

    /// Evict the oldest (least recently seen) schema.
    fn evict_oldest_internal(&self, schemas: &mut HashMap<String, SchemaRecord>) {
        if let Some(oldest_tool) = schemas
            .iter()
            .min_by_key(|(_, r)| r.last_seen)
            .map(|(k, _)| k.clone())
        {
            schemas.remove(&oldest_tool);
            tracing::debug!(
                target: "vellaveto::security",
                tool = %oldest_tool,
                "Evicted oldest schema to make room"
            );
        }
    }

    /// Check for suspicious mutations.
    ///
    /// # Arguments
    /// * `tool` - Tool name to check
    /// * `schema` - Current schema to verify
    ///
    /// # Returns
    /// `Ok(())` if schema is acceptable, `Err(PoisoningAlert)` if poisoning detected.
    pub fn detect_poisoning(&self, tool: &str, schema: &Value) -> Result<(), PoisoningAlert> {
        let schemas = match self.schemas.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SchemaPoisoningDetector::detect_poisoning");
                return Err(PoisoningAlert {
                    tool: tool.to_string(),
                    previous_hash: String::new(),
                    current_hash: Self::hash_schema(schema),
                    similarity: 0.0,
                    changed_fields: vec!["lock_poisoned".to_string()],
                });
            }
        };

        let record = match schemas.get(tool) {
            Some(r) => r,
            None => return Ok(()), // No previous record, can't detect poisoning
        };

        let current_hash = Self::hash_schema(schema);

        // Same hash = no change
        if record.schema_hash == current_hash {
            return Ok(());
        }

        // Check if we have enough observations to establish trust
        if record.version_count() < self.min_observations as usize {
            // SECURITY: During cold-start, still detect dramatic schema changes.
            // A complete schema rewrite (similarity < 0.3) during warmup is
            // suspicious even without established trust baseline.
            if record.version_count() >= 2 {
                if let Some(ref old_schema) = record.schema_content {
                    let sim = Self::calculate_similarity(old_schema, schema);
                    if sim < 0.3 {
                        return Err(PoisoningAlert {
                            tool: tool.to_string(),
                            previous_hash: record.schema_hash.clone(),
                            current_hash,
                            similarity: sim,
                            changed_fields: Self::detect_changes(old_schema, schema),
                        });
                    }
                }
            }
            return Ok(());
        }

        // SECURITY (R228-MCP-2): Calculate actual schema similarity when previous
        // schema content is available, rather than using the decayed trust_score.
        // trust_score decays by 0.5 on every observed change, so after 3 changes
        // it reads 0.125 regardless of actual similarity — causing false positives
        // on tools with frequent minor updates and missing true poisoning attacks
        // that arrive in a single large change between observation windows.
        let (similarity, changed_fields) = if let Some(ref old_schema) = record.schema_content {
            let sim = Self::calculate_similarity(old_schema, schema);
            let changes = Self::detect_changes(old_schema, schema);
            (sim, changes)
        } else {
            // Fallback to trust_score when schema_content is unavailable
            (record.trust_score, Vec::new())
        };

        if similarity < 1.0 - self.mutation_threshold {
            return Err(PoisoningAlert {
                tool: tool.to_string(),
                previous_hash: record.schema_hash.clone(),
                current_hash,
                similarity,
                changed_fields,
            });
        }

        Ok(())
    }

    /// Get trust score for a tool based on schema stability.
    pub fn get_trust_score(&self, tool: &str) -> f32 {
        let schemas = match self.schemas.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SchemaPoisoningDetector::get_trust_score");
                return 0.0;
            }
        };

        schemas.get(tool).map(|r| r.trust_score).unwrap_or(0.0)
    }

    /// Get schema lineage history for a tool.
    pub fn get_lineage(&self, tool: &str) -> Option<SchemaRecord> {
        let schemas = match self.schemas.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SchemaPoisoningDetector::get_lineage");
                return None;
            }
        };
        schemas.get(tool).cloned()
    }

    /// Reset trust for a tool (after manual verification).
    pub fn reset_trust(&self, tool: &str, score: f32) {
        let mut schemas = match self.schemas.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SchemaPoisoningDetector::reset_trust");
                return;
            }
        };

        if let Some(record) = schemas.get_mut(tool) {
            record.trust_score = score.clamp(0.0, 1.0);
            tracing::info!(
                tool = %tool,
                score = %score,
                "Reset schema trust score"
            );
        }
    }

    /// Increment trust score for stable schemas.
    ///
    /// Call this after successful observations to build trust.
    pub fn increment_trust(&self, tool: &str, increment: f32) {
        let mut schemas = match self.schemas.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SchemaPoisoningDetector::increment_trust");
                return;
            }
        };

        if let Some(record) = schemas.get_mut(tool) {
            record.trust_score = (record.trust_score + increment).min(1.0);
        }
    }

    /// Get the number of tracked schemas.
    pub fn tracked_count(&self) -> usize {
        let schemas = match self.schemas.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SchemaPoisoningDetector::tracked_count");
                return 0;
            }
        };
        schemas.len()
    }

    /// Remove a tool's schema record.
    pub fn remove(&self, tool: &str) {
        let mut schemas = match self.schemas.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SchemaPoisoningDetector::remove");
                return;
            }
        };
        schemas.remove(tool);
    }
}

impl Default for SchemaLineageTracker {
    fn default() -> Self {
        Self::new(0.1, 3, 1_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_first_observation_recorded() {
        let tracker = SchemaLineageTracker::new(0.1, 3, 100);
        let schema = json!({"type": "object"});

        let result = tracker.observe_schema("my_tool", &schema);
        assert_eq!(result, ObservationResult::FirstSeen);
        assert_eq!(tracker.tracked_count(), 1);
    }

    #[test]
    fn test_unchanged_schema_no_alert() {
        let tracker = SchemaLineageTracker::new(0.1, 3, 100);
        let schema = json!({"type": "object", "properties": {}});

        tracker.observe_schema("my_tool", &schema);
        let result = tracker.observe_schema("my_tool", &schema);

        assert_eq!(result, ObservationResult::Unchanged);
    }

    #[test]
    fn test_minor_change_warning() {
        let tracker = SchemaLineageTracker::new(0.9, 3, 100); // High threshold

        let schema1 = json!({"type": "object", "properties": {"a": 1}});
        let schema2 = json!({"type": "object", "properties": {"a": 2}});

        tracker.observe_schema("my_tool", &schema1);
        let result = tracker.observe_schema("my_tool", &schema2);

        assert!(matches!(result, ObservationResult::MinorChange { .. }));
    }

    #[test]
    fn test_trust_score_calculation() {
        let tracker = SchemaLineageTracker::new(0.1, 3, 100);
        let schema = json!({"type": "object"});

        tracker.observe_schema("my_tool", &schema);

        // Initial trust is 0
        assert_eq!(tracker.get_trust_score("my_tool"), 0.0);

        // Increment trust
        tracker.increment_trust("my_tool", 0.5);
        assert_eq!(tracker.get_trust_score("my_tool"), 0.5);
    }

    #[test]
    fn test_lineage_tracking() {
        let tracker = SchemaLineageTracker::new(0.1, 3, 100);

        let schema1 = json!({"version": 1});
        let schema2 = json!({"version": 2});
        let schema3 = json!({"version": 3});

        tracker.observe_schema("my_tool", &schema1);
        tracker.observe_schema("my_tool", &schema2);
        tracker.observe_schema("my_tool", &schema3);

        let lineage = tracker.get_lineage("my_tool").unwrap();
        assert_eq!(lineage.version_count(), 3);
    }

    #[test]
    fn test_reset_trust() {
        let tracker = SchemaLineageTracker::new(0.1, 3, 100);
        let schema = json!({"type": "object"});

        tracker.observe_schema("my_tool", &schema);

        tracker.reset_trust("my_tool", 0.8);
        assert_eq!(tracker.get_trust_score("my_tool"), 0.8);
    }

    #[test]
    fn test_hash_consistency() {
        let schema = json!({"a": 1, "b": 2});
        let hash1 = SchemaLineageTracker::hash_schema(&schema);
        let hash2 = SchemaLineageTracker::hash_schema(&schema);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_similarity_identical() {
        let schema = json!({"type": "object"});
        let similarity = SchemaLineageTracker::calculate_similarity(&schema, &schema);

        assert_eq!(similarity, 1.0);
    }

    #[test]
    fn test_similarity_different() {
        let schema1 = json!({"type": "object"});
        let schema2 = json!({"type": "array"});

        let similarity = SchemaLineageTracker::calculate_similarity(&schema1, &schema2);

        assert!(similarity < 1.0);
        assert!(similarity > 0.0);
    }

    #[test]
    fn test_detect_changes() {
        let old = json!({"a": 1, "b": 2});
        let new = json!({"a": 1, "c": 3});

        let changes = SchemaLineageTracker::detect_changes(&old, &new);

        assert!(changes.contains(&"-b".to_string()));
        assert!(changes.contains(&"+c".to_string()));
    }

    #[test]
    fn test_max_schemas_eviction() {
        let tracker = SchemaLineageTracker::new(0.1, 3, 2);

        tracker.observe_schema("tool1", &json!({}));
        tracker.observe_schema("tool2", &json!({}));
        assert_eq!(tracker.tracked_count(), 2);

        tracker.observe_schema("tool3", &json!({}));
        assert_eq!(tracker.tracked_count(), 2);
    }

    // ═══════════════════════════════════════════════════
    // GAP-009: Concurrent access tests
    // ═══════════════════════════════════════════════════

    /// GAP-009: Test concurrent reads don't deadlock
    #[test]
    fn test_concurrent_reads() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(SchemaLineageTracker::new(0.1, 3, 100));
        let schema = json!({"type": "object"});

        // Pre-populate with some data
        tracker.observe_schema("tool1", &schema);
        tracker.observe_schema("tool2", &schema);

        // Spawn multiple reader threads
        let mut handles = vec![];
        for _ in 0..10 {
            let tracker = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = tracker.get_trust_score("tool1");
                    let _ = tracker.get_lineage("tool2");
                    let _ = tracker.tracked_count();
                }
            }));
        }

        // All threads should complete without deadlock
        for handle in handles {
            handle.join().expect("Thread should not panic");
        }
    }

    /// GAP-009: Test concurrent writes don't corrupt state
    #[test]
    fn test_concurrent_writes() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(SchemaLineageTracker::new(0.1, 3, 1000));

        // Spawn multiple writer threads, each writing to different tools
        let mut handles = vec![];
        for i in 0..10 {
            let tracker = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                for j in 0..20 {
                    let tool = format!("tool_{i}_{j}");
                    let schema = json!({"thread": i, "iteration": j});
                    tracker.observe_schema(&tool, &schema);
                }
            }));
        }

        // All threads should complete
        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        // Should have tracked 200 schemas (10 threads * 20 tools each)
        assert_eq!(tracker.tracked_count(), 200);
    }

    /// GAP-009: Test mixed read/write doesn't deadlock or corrupt
    #[test]
    fn test_concurrent_mixed_operations() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(SchemaLineageTracker::new(0.1, 3, 100));
        let schema = json!({"type": "object"});

        // Pre-populate
        for i in 0..10 {
            tracker.observe_schema(&format!("tool{i}"), &schema);
        }

        let mut handles = vec![];

        // Writer threads
        for i in 0..5 {
            let tracker = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                for j in 0..50 {
                    let tool = format!("new_tool_{}_{}", i, j % 10);
                    let schema = json!({"version": j});
                    tracker.observe_schema(&tool, &schema);
                }
            }));
        }

        // Reader threads
        for _ in 0..5 {
            let tracker = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let _ = tracker.get_trust_score(&format!("tool{}", i % 10));
                    let _ = tracker.get_lineage(&format!("tool{}", i % 10));
                }
            }));
        }

        // All threads should complete without deadlock
        for handle in handles {
            handle.join().expect("Thread should not panic");
        }
    }

    /// GAP-009: Test same tool updated from multiple threads
    #[test]
    fn test_concurrent_same_tool_updates() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(SchemaLineageTracker::new(0.5, 3, 100));

        // Initial schema
        let initial = json!({"version": 0});
        tracker.observe_schema("shared_tool", &initial);

        // Multiple threads try to update the same tool
        let mut handles = vec![];
        for i in 0..10 {
            let tracker = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                for j in 0..20 {
                    let schema = json!({"version": i * 100 + j});
                    tracker.observe_schema("shared_tool", &schema);
                    // Small sleep to increase chance of interleaving
                    std::thread::sleep(std::time::Duration::from_micros(10));
                }
            }));
        }

        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        // Tool should exist and have a valid lineage
        let lineage = tracker.get_lineage("shared_tool");
        assert!(lineage.is_some());

        // Should have multiple versions in history
        let record = lineage.unwrap();
        assert!(record.version_count() > 1);
    }

    /// GAP-009: Test concurrent trust score modifications
    #[test]
    fn test_concurrent_trust_modifications() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(SchemaLineageTracker::new(0.1, 3, 100));
        let schema = json!({"type": "object"});
        tracker.observe_schema("my_tool", &schema);

        // Multiple threads increment trust
        let mut handles = vec![];
        for _ in 0..10 {
            let tracker = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                for _ in 0..10 {
                    tracker.increment_trust("my_tool", 0.01);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        // Trust should have been incremented (may not be exactly 1.0 due to concurrent updates)
        let trust = tracker.get_trust_score("my_tool");
        assert!(trust > 0.0);
        assert!(trust <= 1.0);
    }

    /// GAP-009: Test concurrent detect_poisoning calls
    #[test]
    fn test_concurrent_detect_poisoning() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(SchemaLineageTracker::new(0.1, 3, 100));

        // Build up history
        for i in 0..5 {
            let schema = json!({"version": i});
            tracker.observe_schema("my_tool", &schema);
            tracker.increment_trust("my_tool", 0.3);
        }

        let current_schema = json!({"version": 5});

        // Multiple threads calling detect_poisoning
        let mut handles = vec![];
        for _ in 0..10 {
            let tracker = Arc::clone(&tracker);
            let schema = current_schema.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = tracker.detect_poisoning("my_tool", &schema);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("Thread should not panic");
        }
    }

    /// GAP-009: Test eviction under concurrent load
    #[test]
    fn test_concurrent_eviction() {
        use std::sync::Arc;
        use std::thread;

        // Small max to force frequent evictions
        let tracker = Arc::new(SchemaLineageTracker::new(0.1, 3, 10));

        // Multiple threads adding different tools
        let mut handles = vec![];
        for i in 0..5 {
            let tracker = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                for j in 0..50 {
                    let tool = format!("tool_{i}_{j}");
                    let schema = json!({"id": tool});
                    tracker.observe_schema(&tool, &schema);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        // Should never exceed max_schemas
        assert!(tracker.tracked_count() <= 10);
    }

    // ── R227: Tool capability drift detection tests ───────────────────

    /// R227: Minor schema change detected when properties are added.
    #[test]
    fn test_r227_drift_minor_change_detected() {
        let tracker = SchemaLineageTracker::new(0.3, 3, 100);
        let schema_v1 = json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            }
        });
        let schema_v2 = json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "encoding": {"type": "string"}
            }
        });
        // First observation
        let result = tracker.observe_schema("read_file", &schema_v1);
        assert_eq!(result, ObservationResult::FirstSeen);

        // Second observation with added property → minor change
        let result = tracker.observe_schema("read_file", &schema_v2);
        match result {
            ObservationResult::MinorChange { similarity } => {
                assert!(
                    similarity > 0.0 && similarity < 1.0,
                    "Similarity should be between 0 and 1, got {similarity}"
                );
            }
            other => panic!("Expected MinorChange, got {other:?}"),
        }
    }

    /// R227: Unchanged schema does not trigger drift.
    #[test]
    fn test_r227_drift_unchanged_schema_no_drift() {
        let tracker = SchemaLineageTracker::new(0.3, 3, 100);
        let schema = json!({
            "type": "object",
            "properties": {
                "url": {"type": "string"}
            }
        });
        let r1 = tracker.observe_schema("fetch_url", &schema);
        assert_eq!(r1, ObservationResult::FirstSeen);

        let r2 = tracker.observe_schema("fetch_url", &schema);
        assert_eq!(r2, ObservationResult::Unchanged);
    }

    /// R228-MCP-2: detect_poisoning uses actual schema similarity when content
    /// is stored, not the decayed trust_score.
    #[test]
    fn test_r228_detect_poisoning_uses_actual_similarity() {
        let tracker = SchemaLineageTracker::new(0.5, 2, 100);

        let schema_v1 = serde_json::json!({
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string"}
            }
        });
        let schema_v2 = serde_json::json!({
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string"},
                "timeout": {"type": "integer"}
            }
        });
        let schema_v3_malicious = serde_json::json!({
            "type": "object",
            "properties": {
                "exec_command": {"type": "string", "description": "run arbitrary code"}
            }
        });

        tracker.observe_schema("tool", &schema_v1);
        tracker.observe_schema("tool", &schema_v2);

        // Same schema as stored should pass
        let similar_result = tracker.detect_poisoning("tool", &schema_v2);
        assert!(
            similar_result.is_ok(),
            "Schema identical to stored content should not trigger poisoning"
        );

        // Drastically different schema should trigger poisoning
        let malicious_result = tracker.detect_poisoning("tool", &schema_v3_malicious);
        assert!(
            malicious_result.is_err(),
            "Drastically different schema must trigger poisoning alert"
        );
    }

    // ── Cold-start gap security tests ─────────────────────────────────

    /// SECURITY: During cold-start (version_count < min_observations), a
    /// dramatic schema rewrite (similarity < 0.3) must still be detected
    /// when at least 2 versions have been observed.
    #[test]
    fn test_cold_start_dramatic_change_detected() {
        // min_observations = 5 so cold-start window is wide
        let tracker = SchemaLineageTracker::new(0.5, 5, 100);

        let schema_v1 = json!({
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string"},
                "headers": {"type": "object"}
            }
        });

        // Completely different schema — simulates attacker rewrite
        let schema_v2 = json!({
            "type": "object",
            "properties": {
                "exec_command": {"type": "string", "description": "run arbitrary shell command"},
                "payload": {"type": "string", "description": "base64 encoded binary"}
            }
        });

        // Observe v1, then v2 to get version_count = 2
        tracker.observe_schema("target_tool", &schema_v1);
        tracker.observe_schema("target_tool", &schema_v2);

        // version_count is 2, which is < min_observations (5), so we're in cold-start.
        // But a dramatic rewrite (similarity < 0.3) should still be caught.
        let schema_v3_attack = json!({
            "execute": {"type": "string"},
            "root_shell": {"type": "boolean"}
        });

        let result = tracker.detect_poisoning("target_tool", &schema_v3_attack);
        assert!(
            result.is_err(),
            "Dramatic schema change during cold-start must be detected"
        );
        let alert = result.unwrap_err();
        assert_eq!(alert.tool, "target_tool");
        assert!(
            alert.similarity < 0.3,
            "Similarity should be below 0.3, got {}",
            alert.similarity
        );
    }

    /// SECURITY: During cold-start, a minor schema change (similarity >= 0.3)
    /// should still be allowed through — the cold-start guard only catches
    /// dramatic rewrites.
    #[test]
    fn test_cold_start_minor_change_allowed() {
        let tracker = SchemaLineageTracker::new(0.5, 5, 100);

        let schema_v1 = json!({
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string"},
                "headers": {"type": "object"}
            }
        });

        // Minor change: one field added
        let schema_v2 = json!({
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string"},
                "headers": {"type": "object"},
                "timeout": {"type": "integer"}
            }
        });

        tracker.observe_schema("safe_tool", &schema_v1);
        tracker.observe_schema("safe_tool", &schema_v2);

        // Another minor change — should be allowed during cold-start
        let schema_v3 = json!({
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string"},
                "headers": {"type": "object"},
                "timeout": {"type": "integer"},
                "retries": {"type": "integer"}
            }
        });

        let result = tracker.detect_poisoning("safe_tool", &schema_v3);
        assert!(
            result.is_ok(),
            "Minor schema change during cold-start should be allowed"
        );
    }

    /// SECURITY: With only 1 observation (version_count = 1), even a dramatic
    /// change must return Ok(()) because we need >= 2 versions to compare.
    #[test]
    fn test_cold_start_first_change_always_allowed() {
        let tracker = SchemaLineageTracker::new(0.5, 5, 100);

        let schema_v1 = json!({
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string"}
            }
        });

        // Only one observation
        tracker.observe_schema("new_tool", &schema_v1);

        // Completely different schema
        let schema_attack = json!({
            "exec": {"type": "string"},
            "root": {"type": "boolean"},
            "payload": {"type": "string"}
        });

        // version_count is 1, so cold-start guard requires >= 2
        let result = tracker.detect_poisoning("new_tool", &schema_attack);
        assert!(
            result.is_ok(),
            "With only 1 observation, even dramatic changes should be allowed (no baseline to compare)"
        );
    }
}
