// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! MCP server probing and topology crawling.
//!
//! Defines the [`McpServerProbe`] trait (implemented by `vellaveto-mcp`) and
//! the [`TopologyCrawler`] that uses it to build a topology graph from live data.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::error::DiscoveryError;
use crate::topology::{
    ServerCapabilities, StaticResourceDecl, StaticServerDecl, StaticToolDecl, TopologyGraph,
};

// ═══════════════════════════════════════════════════════════════════════════════
// PROBE INFO TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Information about a registered MCP server.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    /// Unique server identifier.
    pub id: String,
    /// Human-readable name (may differ from id).
    pub name: String,
    /// Server version, if reported.
    pub version: Option<String>,
}

/// Information about a tool from tools/list.
#[derive(Debug, Clone)]
pub struct ToolInfo {
    /// Tool name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for input parameters.
    pub input_schema: serde_json::Value,
}

/// Information about a resource from resources/list.
#[derive(Debug, Clone)]
pub struct ResourceInfo {
    /// URI template.
    pub uri_template: String,
    /// Human-readable name.
    pub name: String,
    /// MIME type, if known.
    pub mime_type: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROBE TRAIT
// ═══════════════════════════════════════════════════════════════════════════════

/// Abstraction for probing MCP servers.
///
/// Implemented by `vellaveto-mcp` using rmcp. For testing, use a mock implementation.
#[async_trait]
pub trait McpServerProbe: Send + Sync {
    /// List all registered MCP server identifiers.
    async fn list_servers(&self) -> Result<Vec<ServerInfo>, DiscoveryError>;

    /// Enumerate tools on a specific server (calls tools/list).
    async fn list_tools(&self, server_id: &str) -> Result<Vec<ToolInfo>, DiscoveryError>;

    /// Enumerate resources on a specific server (calls resources/list).
    async fn list_resources(&self, server_id: &str) -> Result<Vec<ResourceInfo>, DiscoveryError>;

    /// Get server capabilities from the initialize handshake.
    async fn server_capabilities(
        &self,
        server_id: &str,
    ) -> Result<ServerCapabilities, DiscoveryError>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRAWL CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

/// Configuration for the topology crawler.
#[derive(Debug, Clone)]
pub struct CrawlConfig {
    /// Timeout per individual server probe.
    pub server_timeout: Duration,
    /// Whether to continue crawling if a server fails.
    pub continue_on_error: bool,
    /// Maximum concurrent server probes.
    pub max_concurrent: usize,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            server_timeout: Duration::from_secs(10),
            continue_on_error: true,
            max_concurrent: 5,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRAWL RESULTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of a full topology crawl.
#[derive(Debug)]
pub struct CrawlResult {
    /// The built topology graph.
    pub topology: TopologyGraph,
    /// Number of servers successfully crawled.
    pub servers_crawled: usize,
    /// Servers that failed during crawling.
    pub servers_failed: Vec<(String, DiscoveryError)>,
    /// Total tools discovered.
    pub tools_found: usize,
    /// Total resources discovered.
    pub resources_found: usize,
    /// Total time taken for the crawl.
    pub duration: Duration,
}

/// Result of crawling a single server.
#[derive(Debug)]
pub struct ServerCrawlResult {
    /// The server declaration built from live data.
    pub server: StaticServerDecl,
    /// Number of tools found.
    pub tools_found: usize,
    /// Number of resources found.
    pub resources_found: usize,
    /// Time taken to crawl this server.
    pub duration: Duration,
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRAWLER
// ═══════════════════════════════════════════════════════════════════════════════

/// Crawls MCP servers to build a topology graph.
pub struct TopologyCrawler {
    probe: Arc<dyn McpServerProbe>,
    config: CrawlConfig,
}

impl TopologyCrawler {
    /// Create a new crawler with the given probe and config.
    pub fn new(probe: Arc<dyn McpServerProbe>, config: CrawlConfig) -> Self {
        Self { probe, config }
    }

    /// Full crawl: enumerate all servers, tools, resources. Build topology graph.
    pub async fn crawl(&self) -> Result<CrawlResult, DiscoveryError> {
        let start = Instant::now();

        let servers = self.probe.list_servers().await?;

        let mut server_decls = Vec::new();
        let mut servers_failed = Vec::new();
        let mut total_tools = 0usize;
        let mut total_resources = 0usize;

        // Crawl servers with bounded concurrency using semaphore
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.max_concurrent));

        let mut handles = Vec::new();
        for server_info in servers {
            let probe = Arc::clone(&self.probe);
            let timeout = self.config.server_timeout;
            let sem = Arc::clone(&semaphore);

            let handle: tokio::task::JoinHandle<
                Result<ServerCrawlResult, (String, DiscoveryError)>,
            > = tokio::spawn(async move {
                let _permit = sem.acquire().await.map_err(|_| {
                    (
                        server_info.id.clone(),
                        DiscoveryError::ServerError {
                            server: server_info.id.clone(),
                            reason: "Semaphore closed".to_string(),
                        },
                    )
                })?;

                let result =
                    tokio::time::timeout(timeout, crawl_single_server(&probe, &server_info)).await;

                match result {
                    Ok(Ok(server_result)) => Ok(server_result),
                    Ok(Err(e)) => Err((server_info.id.clone(), e)),
                    Err(_) => Err((
                        server_info.id.clone(),
                        DiscoveryError::ServerTimeout {
                            server: server_info.id,
                            timeout_ms: timeout.as_millis() as u64,
                        },
                    )),
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            match handle.await {
                Ok(Ok(result)) => {
                    total_tools = total_tools.saturating_add(result.tools_found);
                    total_resources = total_resources.saturating_add(result.resources_found);
                    server_decls.push(result.server);
                }
                Ok(Err((server_id, err))) => {
                    tracing::warn!(server = %server_id, error = %err, "Server crawl failed");
                    if !self.config.continue_on_error {
                        return Err(DiscoveryError::CrawlAborted {
                            server: server_id,
                            reason: err.to_string(),
                        });
                    }
                    servers_failed.push((server_id, err));
                }
                Err(join_err) => {
                    let msg = format!("Task join error: {join_err}");
                    tracing::error!("{}", msg);
                    if !self.config.continue_on_error {
                        return Err(DiscoveryError::GraphError(msg));
                    }
                }
            }
        }

        let topology = TopologyGraph::from_static(server_decls)?;
        let servers_crawled = topology.server_count();

        Ok(CrawlResult {
            topology,
            servers_crawled,
            servers_failed,
            tools_found: total_tools,
            resources_found: total_resources,
            duration: start.elapsed(),
        })
    }

    /// Crawl a single server (for targeted re-crawl after failure).
    pub async fn crawl_server(&self, server_id: &str) -> Result<ServerCrawlResult, DiscoveryError> {
        let start = Instant::now();

        let servers = self.probe.list_servers().await?;
        let server_info = servers
            .into_iter()
            .find(|s| s.id == server_id)
            .ok_or_else(|| DiscoveryError::ServerNotFound(server_id.to_string()))?;

        let result = tokio::time::timeout(
            self.config.server_timeout,
            crawl_single_server(&self.probe, &server_info),
        )
        .await
        .map_err(|_| DiscoveryError::ServerTimeout {
            server: server_id.to_string(),
            timeout_ms: self.config.server_timeout.as_millis() as u64,
        })??;

        Ok(ServerCrawlResult {
            server: result.server,
            tools_found: result.tools_found,
            resources_found: result.resources_found,
            duration: start.elapsed(),
        })
    }
}

impl std::fmt::Debug for TopologyCrawler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopologyCrawler")
            .field("config", &self.config)
            .finish()
    }
}

/// Crawl a single server, returning its declaration.
async fn crawl_single_server(
    probe: &Arc<dyn McpServerProbe>,
    server_info: &ServerInfo,
) -> Result<ServerCrawlResult, DiscoveryError> {
    let start = Instant::now();

    let capabilities = probe.server_capabilities(&server_info.id).await?;

    let tools = if capabilities.tools {
        probe.list_tools(&server_info.id).await?
    } else {
        Vec::new()
    };

    let resources = if capabilities.resources {
        probe.list_resources(&server_info.id).await?
    } else {
        Vec::new()
    };

    let tools_found = tools.len();
    let resources_found = resources.len();

    let server_decl = StaticServerDecl {
        name: server_info.id.clone(),
        tools: tools
            .into_iter()
            .map(|t| StaticToolDecl {
                name: t.name,
                description: t.description,
                input_schema: t.input_schema,
            })
            .collect(),
        resources: resources
            .into_iter()
            .map(|r| StaticResourceDecl {
                uri_template: r.uri_template,
                name: r.name,
                mime_type: r.mime_type,
            })
            .collect(),
    };

    Ok(ServerCrawlResult {
        server: server_decl,
        tools_found,
        resources_found,
        duration: start.elapsed(),
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATIC PROBE (in-memory McpServerProbe implementation)
// ═══════════════════════════════════════════════════════════════════════════════

/// A no-network [`McpServerProbe`] backed by in-memory [`StaticServerDecl`] data.
///
/// Used for wiring the topology crawler pipeline without live MCP connections.
/// The relay intercept can push live `tools/list` responses into this probe
/// via [`upsert_server()`](StaticProbe::upsert_server).
pub struct StaticProbe {
    servers: RwLock<Vec<StaticServerDecl>>,
}

impl StaticProbe {
    /// Create a new static probe with initial server declarations.
    pub fn new(servers: Vec<StaticServerDecl>) -> Self {
        Self {
            servers: RwLock::new(servers),
        }
    }

    /// Merge or replace a single server's declaration.
    ///
    /// If a server with the same name already exists, it is replaced.
    /// Otherwise the new declaration is appended.
    pub fn upsert_server(&self, decl: StaticServerDecl) {
        if let Ok(mut servers) = self.servers.write() {
            if let Some(existing) = servers.iter_mut().find(|s| s.name == decl.name) {
                *existing = decl;
            } else {
                // SECURITY (R230-DISC-4): Bound server list to MAX_SERVERS.
                if servers.len() >= crate::topology::MAX_SERVERS {
                    tracing::warn!(
                        max = crate::topology::MAX_SERVERS,
                        "StaticProbe at capacity, rejecting new server '{}'",
                        decl.name
                    );
                    return;
                }
                servers.push(decl);
            }
        }
    }

    /// Remove a server by name. Returns `true` if the server was found and removed.
    pub fn remove_server(&self, name: &str) -> bool {
        if let Ok(mut servers) = self.servers.write() {
            let before = servers.len();
            servers.retain(|s| s.name != name);
            servers.len() < before
        } else {
            false
        }
    }

    /// Returns the number of servers currently registered.
    pub fn server_count(&self) -> usize {
        self.servers.read().map(|s| s.len()).unwrap_or(0)
    }
}

#[async_trait]
impl McpServerProbe for StaticProbe {
    async fn list_servers(&self) -> Result<Vec<ServerInfo>, DiscoveryError> {
        let servers = self
            .servers
            .read()
            .map_err(|_| DiscoveryError::GraphError("StaticProbe RwLock poisoned".to_string()))?;
        Ok(servers
            .iter()
            .map(|s| ServerInfo {
                id: s.name.clone(),
                name: s.name.clone(),
                version: None,
            })
            .collect())
    }

    async fn list_tools(&self, server_id: &str) -> Result<Vec<ToolInfo>, DiscoveryError> {
        let servers = self
            .servers
            .read()
            .map_err(|_| DiscoveryError::GraphError("StaticProbe RwLock poisoned".to_string()))?;
        let server = servers
            .iter()
            .find(|s| s.name == server_id)
            .ok_or_else(|| DiscoveryError::ServerNotFound(server_id.to_string()))?;
        Ok(server
            .tools
            .iter()
            .map(|t| ToolInfo {
                name: t.name.clone(),
                description: t.description.clone(),
                input_schema: t.input_schema.clone(),
            })
            .collect())
    }

    async fn list_resources(&self, server_id: &str) -> Result<Vec<ResourceInfo>, DiscoveryError> {
        let servers = self
            .servers
            .read()
            .map_err(|_| DiscoveryError::GraphError("StaticProbe RwLock poisoned".to_string()))?;
        let server = servers
            .iter()
            .find(|s| s.name == server_id)
            .ok_or_else(|| DiscoveryError::ServerNotFound(server_id.to_string()))?;
        Ok(server
            .resources
            .iter()
            .map(|r| ResourceInfo {
                uri_template: r.uri_template.clone(),
                name: r.name.clone(),
                mime_type: r.mime_type.clone(),
            })
            .collect())
    }

    async fn server_capabilities(
        &self,
        server_id: &str,
    ) -> Result<ServerCapabilities, DiscoveryError> {
        let servers = self
            .servers
            .read()
            .map_err(|_| DiscoveryError::GraphError("StaticProbe RwLock poisoned".to_string()))?;
        let server = servers
            .iter()
            .find(|s| s.name == server_id)
            .ok_or_else(|| DiscoveryError::ServerNotFound(server_id.to_string()))?;
        Ok(ServerCapabilities {
            tools: !server.tools.is_empty(),
            resources: !server.resources.is_empty(),
            prompts: false,
            logging: false,
        })
    }
}

impl std::fmt::Debug for StaticProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.server_count();
        f.debug_struct("StaticProbe")
            .field("server_count", &count)
            .finish()
    }
}
