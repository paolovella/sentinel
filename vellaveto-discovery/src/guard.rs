// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Topology guard — pre-policy filter.
//!
//! The TopologyGuard sits in front of the policy engine and checks whether
//! a requested tool actually exists in the verified topology. This prevents
//! phantom tool attacks and catches misconfigured policies early.

use std::sync::{Arc, RwLock};

use crate::error::DiscoveryError;
use crate::topology::{StaticServerDecl, TopologyGraph};

/// Pre-policy topology verification result.
#[derive(Debug, Clone)]
pub enum TopologyVerdict {
    /// Tool exists in the verified topology.
    Known {
        /// The server that owns this tool.
        server: String,
        /// The tool name.
        tool: String,
        /// Tools reachable via downstream DataFlow edges.
        downstream: Vec<String>,
    },
    /// Tool not found in any registered MCP server — hard deny.
    Unknown {
        /// The tool name that was requested.
        requested_tool: String,
        /// A fuzzy-match suggestion, if one exists.
        suggestion: Option<String>,
        /// All available tool names for error reporting.
        available_tools: Vec<String>,
    },
    /// Multiple servers expose this tool name — require qualified name.
    Ambiguous {
        /// The tool name that was requested.
        requested_tool: String,
        /// Qualified names of all matches ("server::tool").
        matches: Vec<String>,
    },
    /// No topology loaded — pass through to policy evaluation unchanged.
    Bypassed,
}

/// The topology guard that checks tool existence before policy evaluation.
///
/// Thread-safe: uses `RwLock<Option<Arc<TopologyGraph>>>` for lock-free reads
/// during normal operation and atomic swaps during updates.
pub struct TopologyGuard {
    topology: RwLock<Option<Arc<TopologyGraph>>>,
}

impl TopologyGuard {
    /// Create a new guard with no topology loaded (bypass mode).
    pub fn new() -> Self {
        Self {
            topology: RwLock::new(None),
        }
    }

    /// Load an initial topology.
    pub fn load(&self, topology: TopologyGraph) {
        let arc = Arc::new(topology);
        // SECURITY (R235-DISC-2): Recover from poisoned lock via into_inner().
        // Silently remaining in bypass mode is fail-open — we must overwrite.
        let mut guard = match self.topology.write() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!(
                    "TopologyGuard RwLock poisoned during load — recovering via into_inner()"
                );
                poisoned.into_inner()
            }
        };
        *guard = Some(arc);
    }

    /// Hot-swap the topology (atomic replace, no downtime).
    ///
    /// In-flight `check()` calls will see either the old or new topology,
    /// never a torn state.
    pub fn update(&self, topology: TopologyGraph) {
        self.load(topology);
    }

    /// Check if a tool exists in the topology.
    ///
    /// The `tool_name` can be:
    /// - Qualified: "server::tool" — checked directly.
    /// - Unqualified: "tool" — searched across all servers.
    ///
    /// Returns [`TopologyVerdict::Bypassed`] if no topology is loaded.
    #[must_use = "topology verdicts must not be discarded"]
    pub fn check(&self, tool_name: &str) -> TopologyVerdict {
        let topology = match self.topology.read() {
            Ok(guard) => match guard.as_ref() {
                Some(t) => Arc::clone(t),
                None => return TopologyVerdict::Bypassed,
            },
            Err(_) => {
                // SECURITY (R235-DISC-1): Poisoned lock — fail-closed.
                // Returning Bypassed would skip topology verification entirely.
                tracing::error!(
                    "TopologyGuard RwLock poisoned during check — denying (fail-closed)"
                );
                // SECURITY (R256-DISC-1b): Sanitize tool_name in poisoned-lock
                // fail-closed path to prevent log injection from attacker-controlled input.
                return TopologyVerdict::Unknown {
                    requested_tool: vellaveto_types::sanitize_for_log(tool_name, 256),
                    suggestion: None,
                    available_tools: Vec::new(),
                };
            }
        };

        // Try qualified lookup first
        if tool_name.contains("::") {
            if let Some(node) = topology.find_tool(tool_name) {
                let (server, tool) = match node {
                    crate::topology::TopologyNode::Tool { server, name, .. } => {
                        (server.clone(), name.clone())
                    }
                    _ => {
                        // SECURITY (R245-DISC-2): Non-tool node match must return Unknown
                        // (fail-closed), not Bypassed (which skips policy enforcement).
                        return TopologyVerdict::Unknown {
                            requested_tool: vellaveto_types::sanitize_for_log(tool_name, 256),
                            suggestion: None,
                            available_tools: Vec::new(),
                        };
                    }
                };
                let downstream = topology.downstream(tool_name);
                return TopologyVerdict::Known {
                    server,
                    tool,
                    downstream,
                };
            }
        }

        // Try unqualified lookup
        let matches = topology.find_tool_unqualified(tool_name);

        match matches.len() {
            0 => {
                // Not found — generate suggestion via simple string distance
                let mut available = topology.tool_names();
                let suggestion = find_closest_match(tool_name, &available);
                // SECURITY (R245-DISC-3): Limit available_tools to prevent
                // full tool inventory disclosure to unauthenticated probers.
                available.truncate(5);
                // SECURITY (R238-DISC-1): Sanitize echoed tool name to prevent
                // log injection via control/bidi chars in attacker-supplied names.
                TopologyVerdict::Unknown {
                    requested_tool: vellaveto_types::sanitize_for_log(tool_name, 256),
                    suggestion,
                    available_tools: available,
                }
            }
            1 => {
                let (qualified, node) = &matches[0];
                let (server, tool) = match node {
                    crate::topology::TopologyNode::Tool { server, name, .. } => {
                        (server.clone(), name.clone())
                    }
                    _ => {
                        // SECURITY (R245-DISC-2): Non-tool node match must return Unknown
                        // (fail-closed), not Bypassed (which skips policy enforcement).
                        return TopologyVerdict::Unknown {
                            requested_tool: vellaveto_types::sanitize_for_log(tool_name, 256),
                            suggestion: None,
                            available_tools: Vec::new(),
                        };
                    }
                };
                let downstream = topology.downstream(qualified);
                TopologyVerdict::Known {
                    server,
                    tool,
                    downstream,
                }
            }
            _ => {
                let match_names: Vec<String> = matches.into_iter().map(|(q, _)| q).collect();
                // SECURITY (R256-DISC-1): Sanitize tool_name in Ambiguous verdict to
                // prevent log injection from attacker-controlled tool name strings.
                TopologyVerdict::Ambiguous {
                    requested_tool: vellaveto_types::sanitize_for_log(tool_name, 256),
                    matches: match_names,
                }
            }
        }
    }

    /// Get the current topology (for serialization/inspection).
    pub fn current(&self) -> Option<Arc<TopologyGraph>> {
        match self.topology.read() {
            Ok(guard) => guard.as_ref().cloned(),
            Err(_) => {
                // SECURITY (R240-P3-DISC-1): Log poisoning — parity with check().
                tracing::error!("TopologyGuard RwLock poisoned in current()");
                None
            }
        }
    }

    /// Clear the topology (revert to bypass mode).
    pub fn clear(&self) {
        // SECURITY (R235-DISC-3): Recover from poisoned lock via into_inner().
        // Silently failing to clear leaves stale topology data.
        let mut guard = match self.topology.write() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!(
                    "TopologyGuard RwLock poisoned during clear — recovering via into_inner()"
                );
                poisoned.into_inner()
            }
        };
        *guard = None;
    }

    /// Incrementally upsert a single server into the topology.
    ///
    /// Holds the write lock for the entire read-modify-write cycle to prevent
    /// TOCTOU race conditions (R230-DISC-1).
    /// If no topology is loaded, creates a new one from the single server.
    pub fn upsert_server(&self, decl: StaticServerDecl) -> Result<(), DiscoveryError> {
        let mut guard = self.topology.write().map_err(|_| {
            DiscoveryError::GraphError("TopologyGuard RwLock poisoned during upsert".to_string())
        })?;

        let mut decls = match guard.as_ref() {
            Some(topo) => topo.to_static(),
            None => Vec::new(),
        };

        // Replace existing or append
        if let Some(existing) = decls.iter_mut().find(|s| s.name == decl.name) {
            *existing = decl;
        } else {
            decls.push(decl);
        }

        let new_topology = TopologyGraph::from_static(decls)?;
        *guard = Some(Arc::new(new_topology));
        Ok(())
    }
}

impl Default for TopologyGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TopologyGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let loaded = self.topology.read().map(|g| g.is_some()).unwrap_or(false);
        f.debug_struct("TopologyGuard")
            .field("loaded", &loaded)
            .finish()
    }
}

/// Simple closest-match finder using Levenshtein-like character overlap.
///
/// Not a full edit-distance — just a cheap heuristic for suggestions.
fn find_closest_match(needle: &str, haystack: &[String]) -> Option<String> {
    if haystack.is_empty() {
        return None;
    }

    let needle_lower = needle.to_lowercase();
    let mut best_score = 0usize;
    let mut best_match = None;

    for candidate in haystack {
        // Extract the unqualified part if it's "server::tool"
        let unqualified = candidate
            .split("::")
            .last()
            .unwrap_or(candidate)
            .to_lowercase();

        // Score: count of common characters (order-independent)
        let score = common_char_count(&needle_lower, &unqualified);

        // Require at least 50% overlap to suggest
        let min_threshold = needle_lower.len() / 2;
        if score > best_score && score >= min_threshold.max(1) {
            best_score = score;
            best_match = Some(candidate.clone());
        }
    }

    best_match
}

/// Count common characters between two strings (bag-of-chars similarity).
fn common_char_count(a: &str, b: &str) -> usize {
    let mut b_chars: Vec<char> = b.chars().collect();
    let mut count = 0;
    for c in a.chars() {
        if let Some(pos) = b_chars.iter().position(|&bc| bc == c) {
            b_chars.remove(pos);
            count += 1;
        }
    }
    count
}
