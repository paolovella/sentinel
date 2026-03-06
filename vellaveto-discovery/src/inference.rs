// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Data flow edge inference from tool schemas.
//!
//! Analyzes tool input/output schemas to infer data flow relationships
//! between tools. Three heuristics are used:
//! 1. **Name matching** — parameter names match other tools' implied outputs.
//! 2. **Type matching** — compatible types between source outputs and target inputs.
//! 3. **Description matching** — keyword overlap in descriptions.

use crate::topology::{TopologyEdge, TopologyGraph, TopologyNode};

/// Configuration for the inference engine.
#[derive(Debug, Clone)]
pub struct InferenceConfig {
    /// Minimum confidence to create an edge.
    pub threshold: f32,
    /// Weight for name-based matching [0.0, 1.0].
    pub name_weight: f32,
    /// Weight for type-based matching [0.0, 1.0].
    pub type_weight: f32,
    /// Weight for description-based matching [0.0, 1.0].
    pub description_weight: f32,
}

impl Default for InferenceConfig {
    fn default() -> Self {
        Self {
            threshold: 0.7,
            name_weight: 0.5,
            type_weight: 0.3,
            description_weight: 0.2,
        }
    }
}

impl InferenceConfig {
    /// Validate that weights and threshold are in valid ranges.
    pub fn validate(&self) -> Result<(), String> {
        if !self.threshold.is_finite() || self.threshold < 0.0 || self.threshold > 1.0 {
            return Err(format!(
                "threshold must be in [0.0, 1.0], got {}",
                self.threshold
            ));
        }
        if !self.name_weight.is_finite() || self.name_weight < 0.0 || self.name_weight > 1.0 {
            return Err(format!(
                "name_weight must be in [0.0, 1.0], got {}",
                self.name_weight
            ));
        }
        if !self.type_weight.is_finite() || self.type_weight < 0.0 || self.type_weight > 1.0 {
            return Err(format!(
                "type_weight must be in [0.0, 1.0], got {}",
                self.type_weight
            ));
        }
        if !self.description_weight.is_finite()
            || self.description_weight < 0.0
            || self.description_weight > 1.0
        {
            return Err(format!(
                "description_weight must be in [0.0, 1.0], got {}",
                self.description_weight
            ));
        }
        Ok(())
    }
}

/// The inference engine that analyzes tool schemas.
pub struct InferenceEngine {
    config: InferenceConfig,
}

/// A single inferred match between two tools.
#[derive(Debug, Clone)]
pub struct InferredMatch {
    /// Target parameter name that matches.
    pub target_param: String,
    /// Confidence score [0.0, 1.0].
    pub confidence: f32,
    /// Human-readable reason for this match.
    pub reason: String,
}

impl InferenceEngine {
    /// Create a new inference engine with the given config.
    pub fn new(config: InferenceConfig) -> Self {
        Self { config }
    }

    /// Analyze all tools and add DataFlow edges to the graph.
    pub fn infer_edges(&self, graph: &mut TopologyGraph) {
        // Collect all tool nodes and their info
        let tools: Vec<(String, ToolAnalysis)> = graph
            .name_index()
            .iter()
            .filter_map(|(name, idx)| {
                let node = &graph.graph()[*idx];
                if let TopologyNode::Tool {
                    server,
                    name: tool_name,
                    description,
                    input_schema,
                    ..
                } = node
                {
                    Some((
                        name.clone(),
                        ToolAnalysis {
                            server: server.clone(),
                            name: tool_name.clone(),
                            description: description.clone(),
                            param_names: extract_param_names(input_schema),
                            param_types: extract_param_types(input_schema),
                            description_tokens: tokenize(description),
                            implied_outputs: infer_outputs(tool_name, description),
                        },
                    ))
                } else {
                    None
                }
            })
            .collect();

        // Compare all pairs (source → target)
        // SECURITY (R231-DISC-3): Cap total inferred edges to prevent O(N^2)
        // amplification with many tools having similar descriptions/params.
        const MAX_INFERRED_EDGES: usize = 50_000;
        let mut edges_to_add = Vec::new();
        'outer: for (source_qualified, source) in &tools {
            for (target_qualified, target) in &tools {
                // No self-edges
                if source_qualified == target_qualified {
                    continue;
                }

                let matches = self.match_tools(source, target);
                for m in matches {
                    if m.confidence >= self.config.threshold {
                        edges_to_add.push((
                            source_qualified.clone(),
                            target_qualified.clone(),
                            m.target_param.clone(),
                            m.confidence,
                            m.reason,
                        ));
                        if edges_to_add.len() >= MAX_INFERRED_EDGES {
                            tracing::warn!(
                                max = MAX_INFERRED_EDGES,
                                "Inference edge cap reached — stopping pair comparison"
                            );
                            break 'outer;
                        }
                    }
                }
            }
        }

        // Add edges to the graph
        let index = graph.name_index().clone();
        for (source, target, to_param, confidence, reason) in edges_to_add {
            if let (Some(&src_idx), Some(&tgt_idx)) = (index.get(&source), index.get(&target)) {
                let from_field = source.split("::").last().unwrap_or(&source).to_string();
                graph.graph_mut().add_edge(
                    src_idx,
                    tgt_idx,
                    TopologyEdge::DataFlow {
                        from_field,
                        to_param,
                        confidence,
                        reason,
                    },
                );
            }
        }

        // Recompute fingerprint after adding edges
        graph.recompute_fingerprint();
    }

    /// Compare two tool schemas for potential data flow.
    pub fn match_schemas(
        &self,
        source_tool: &TopologyNode,
        target_tool: &TopologyNode,
    ) -> Vec<InferredMatch> {
        let (source, target) = match (source_tool, target_tool) {
            (
                TopologyNode::Tool {
                    name: src_name,
                    description: src_desc,
                    input_schema: _src_schema,
                    ..
                },
                TopologyNode::Tool {
                    description: tgt_desc,
                    input_schema: tgt_schema,
                    ..
                },
            ) => {
                let source = ToolAnalysis {
                    server: String::new(),
                    name: src_name.clone(),
                    description: src_desc.clone(),
                    param_names: Vec::new(),
                    param_types: Vec::new(),
                    description_tokens: tokenize(src_desc),
                    implied_outputs: infer_outputs(src_name, src_desc),
                };
                let target = ToolAnalysis {
                    server: String::new(),
                    name: String::new(),
                    description: tgt_desc.clone(),
                    param_names: extract_param_names(tgt_schema),
                    param_types: extract_param_types(tgt_schema),
                    description_tokens: tokenize(tgt_desc),
                    implied_outputs: Vec::new(),
                };
                (source, target)
            }
            _ => return Vec::new(),
        };

        self.match_tools(&source, &target)
    }

    /// Core matching logic between two tools.
    fn match_tools(&self, source: &ToolAnalysis, target: &ToolAnalysis) -> Vec<InferredMatch> {
        let mut results = Vec::new();

        for param in &target.param_names {
            let name_score = self.name_match_score(source, param);
            let type_score = self.type_match_score(source, target, param);
            let desc_score = self.description_match_score(source, target);

            let combined = self.config.name_weight * name_score
                + self.config.type_weight * type_score
                + self.config.description_weight * desc_score;

            if combined >= self.config.threshold {
                let reason = build_reason(source, param, name_score, type_score, desc_score);
                results.push(InferredMatch {
                    target_param: param.clone(),
                    confidence: combined.min(1.0),
                    reason,
                });
            }
        }

        results
    }

    /// Name-based matching score.
    fn name_match_score(&self, source: &ToolAnalysis, target_param: &str) -> f32 {
        let param_lower = target_param.to_lowercase();

        // Check if source's implied outputs contain this param name
        for output in &source.implied_outputs {
            if output == &param_lower {
                return 0.9;
            }
            // Partial match (e.g., "file" in "file_path")
            if param_lower.contains(output) || output.contains(&param_lower) {
                return 0.6;
            }
        }

        // Check if source tool name is a prefix/stem of the param
        let name_lower = source.name.to_lowercase();
        let name_parts: Vec<&str> = name_lower.split('_').collect();
        for part in &name_parts {
            if !part.is_empty() && param_lower.contains(part) && part.len() >= 3 {
                return 0.4;
            }
        }

        0.0
    }

    /// Type-based matching score.
    fn type_match_score(
        &self,
        source: &ToolAnalysis,
        target: &ToolAnalysis,
        _target_param: &str,
    ) -> f32 {
        // If source description mentions returning arrays/strings/objects
        // and target expects compatible types
        let source_returns_strings = source.description_tokens.iter().any(|t| {
            matches!(
                t.as_str(),
                "returns" | "path" | "paths" | "file" | "url" | "name"
            )
        });

        let target_needs_strings = target
            .param_types
            .iter()
            .any(|t| matches!(t.as_str(), "string" | "array"));

        if source_returns_strings && target_needs_strings {
            0.5
        } else {
            0.0
        }
    }

    /// Description-based matching score via token intersection.
    fn description_match_score(&self, source: &ToolAnalysis, target: &ToolAnalysis) -> f32 {
        if source.description_tokens.is_empty() || target.description_tokens.is_empty() {
            return 0.0;
        }

        let common: usize = source
            .description_tokens
            .iter()
            .filter(|t| target.description_tokens.contains(t))
            .count();

        let total = source
            .description_tokens
            .len()
            .max(target.description_tokens.len());

        if total == 0 {
            return 0.0;
        }

        let ratio = common as f32 / total as f32;
        ratio.min(1.0)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/// Analysis of a single tool for matching purposes.
struct ToolAnalysis {
    #[allow(dead_code)]
    server: String,
    name: String,
    #[allow(dead_code)]
    description: String,
    param_names: Vec<String>,
    param_types: Vec<String>,
    description_tokens: Vec<String>,
    implied_outputs: Vec<String>,
}

/// Extract parameter names from a JSON Schema.
fn extract_param_names(schema: &serde_json::Value) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
        for key in properties.keys() {
            names.push(key.clone());
        }
    }
    names
}

/// Extract parameter types from a JSON Schema.
fn extract_param_types(schema: &serde_json::Value) -> Vec<String> {
    let mut types = Vec::new();
    if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
        for prop in properties.values() {
            if let Some(t) = prop.get("type").and_then(|v| v.as_str()) {
                types.push(t.to_string());
            }
        }
    }
    types
}

/// Tokenize a description into lowercase words, filtering stopwords.
fn tokenize(text: &str) -> Vec<String> {
    const STOPWORDS: &[&str] = &[
        "a", "an", "the", "is", "are", "was", "were", "be", "been", "being", "have", "has", "had",
        "do", "does", "did", "will", "would", "shall", "should", "may", "might", "can", "could",
        "must", "to", "of", "in", "for", "on", "with", "at", "by", "from", "as", "into", "through",
        "during", "before", "after", "above", "below", "between", "and", "but", "or", "nor", "not",
        "so", "yet", "both", "either", "neither", "each", "every", "all", "any", "few", "more",
        "most", "other", "some", "such", "no", "only", "own", "same", "than", "too", "very",
        "just", "because", "if", "when", "where", "how", "what", "which", "who", "whom", "this",
        "that", "these", "those", "it", "its",
    ];

    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|w| !w.is_empty() && w.len() >= 2 && !STOPWORDS.contains(w))
        .map(|w| w.to_string())
        .collect()
}

/// Infer what a tool likely produces based on its name and description.
fn infer_outputs(tool_name: &str, description: &str) -> Vec<String> {
    let mut outputs = Vec::new();
    let name_lower = tool_name.to_lowercase();
    let desc_lower = description.to_lowercase();

    // Common patterns: "file_search" → produces "file_path"
    let patterns: &[(&str, &[&str])] = &[
        ("search", &["path", "file_path", "result", "results"]),
        ("find", &["path", "file_path", "result", "results"]),
        ("list", &["items", "names", "paths", "results"]),
        ("read", &["content", "data", "text"]),
        ("get", &["data", "result", "value"]),
        ("create", &["id", "path", "url"]),
        ("fetch", &["data", "content", "response"]),
    ];

    for (keyword, implied) in patterns {
        if name_lower.contains(keyword) || desc_lower.contains(keyword) {
            for out in *implied {
                outputs.push((*out).to_string());
            }
        }
    }

    // Extract nouns from the tool name as potential output names
    for part in name_lower.split('_') {
        if part.len() >= 3 && !matches!(part, "get" | "set" | "the" | "and" | "for") {
            outputs.push(part.to_string());
        }
    }

    outputs.sort();
    outputs.dedup();
    outputs
}

/// Build a human-readable reason for an inferred edge.
fn build_reason(
    source: &ToolAnalysis,
    target_param: &str,
    name_score: f32,
    type_score: f32,
    desc_score: f32,
) -> String {
    let mut parts = Vec::new();

    if name_score > 0.0 {
        parts.push(format!(
            "tool '{}' output matches param '{target_param}' (name: {name_score:.2})",
            source.name
        ));
    }
    if type_score > 0.0 {
        parts.push(format!("compatible types (type: {type_score:.2})"));
    }
    if desc_score > 0.0 {
        parts.push(format!("description overlap (desc: {desc_score:.2})"));
    }

    if parts.is_empty() {
        format!(
            "inferred data flow from '{}' to param '{target_param}'",
            source.name
        )
    } else {
        parts.join("; ")
    }
}
