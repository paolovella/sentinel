// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Recrawl scheduler — periodic and event-triggered topology refreshes.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::crawler::TopologyCrawler;
use crate::diff::TopologyDiff;
use crate::error::DiscoveryError;
use crate::guard::TopologyGuard;

/// Configuration for the recrawl scheduler.
#[derive(Debug, Clone)]
pub struct RecrawlConfig {
    /// Interval between periodic re-crawls (Duration::ZERO = disabled).
    pub interval: Duration,
    /// Re-crawl when a tool-not-found event occurs.
    pub on_unknown_tool: bool,
    /// Minimum time between event-triggered re-crawls (debounce).
    pub debounce: Duration,
    /// Maximum consecutive failures before falling back to bypass.
    pub max_consecutive_failures: u32,
}

impl Default for RecrawlConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(300),
            on_unknown_tool: true,
            debounce: Duration::from_secs(30),
            max_consecutive_failures: 3,
        }
    }
}

/// Topology audit event (emitted for audit integration).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "event_type")]
pub enum TopologyAuditEvent {
    /// A crawl completed successfully.
    CrawlCompleted {
        servers: usize,
        tools: usize,
        resources: usize,
        fingerprint: String,
        duration_ms: u64,
    },
    /// The topology changed after a re-crawl.
    TopologyChanged {
        diff_summary: String,
        previous_fingerprint: String,
        new_fingerprint: String,
        trigger: String,
    },
    /// A topology violation was detected (unknown tool).
    TopologyViolation {
        tool: String,
        verdict: String,
        suggestion: Option<String>,
    },
    /// A crawl failed.
    CrawlFailed {
        error: String,
        retained_fingerprint: Option<String>,
    },
    /// A re-crawl was triggered.
    RecrawlTriggered { reason: String },
}

/// Callback type for topology change notifications.
pub type OnChangeCallback = Box<dyn Fn(TopologyDiff) + Send + Sync>;

/// Callback type for audit event notifications.
pub type OnAuditCallback = Box<dyn Fn(TopologyAuditEvent) + Send + Sync>;

/// The recrawl scheduler.
pub struct RecrawlScheduler {
    crawler: Arc<TopologyCrawler>,
    guard: Arc<TopologyGuard>,
    config: RecrawlConfig,
    consecutive_failures: AtomicU32,
    trigger: Arc<Notify>,
    on_change: Option<OnChangeCallback>,
    on_audit: Option<OnAuditCallback>,
}

impl RecrawlScheduler {
    /// Create a new scheduler.
    pub fn new(
        crawler: Arc<TopologyCrawler>,
        guard: Arc<TopologyGuard>,
        config: RecrawlConfig,
    ) -> Self {
        Self {
            crawler,
            guard,
            config,
            consecutive_failures: AtomicU32::new(0),
            trigger: Arc::new(Notify::new()),
            on_change: None,
            on_audit: None,
        }
    }

    /// Set the callback for topology changes.
    pub fn set_on_change(&mut self, callback: OnChangeCallback) {
        self.on_change = Some(callback);
    }

    /// Set the callback for audit events.
    pub fn set_on_audit(&mut self, callback: OnAuditCallback) {
        self.on_audit = Some(callback);
    }

    /// Run the scheduler loop until cancelled.
    pub async fn run(&self, shutdown: CancellationToken) {
        let mut last_event_crawl = Instant::now()
            .checked_sub(self.config.debounce)
            .unwrap_or_else(Instant::now);

        loop {
            let sleep_duration = if self.config.interval.is_zero() {
                // No periodic crawling — wait for manual trigger or shutdown
                Duration::from_secs(3600)
            } else {
                self.config.interval
            };

            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!("RecrawlScheduler shutting down");
                    return;
                }
                _ = tokio::time::sleep(sleep_duration) => {
                    if !self.config.interval.is_zero() {
                        self.emit_audit(TopologyAuditEvent::RecrawlTriggered {
                            reason: "periodic".to_string(),
                        });
                        let _ = self.do_recrawl("periodic").await;
                    }
                }
                _ = self.trigger.notified() => {
                    // Check debounce
                    let now = Instant::now();
                    if now.duration_since(last_event_crawl) >= self.config.debounce {
                        last_event_crawl = now;
                        self.emit_audit(TopologyAuditEvent::RecrawlTriggered {
                            reason: "event-triggered".to_string(),
                        });
                        let _ = self.do_recrawl("event-triggered").await;
                    } else {
                        tracing::debug!("Recrawl debounced — too soon since last event-triggered crawl");
                    }
                }
            }
        }
    }

    /// Trigger an immediate re-crawl (from external event).
    pub async fn trigger_recrawl(&self, reason: &str) -> Result<TopologyDiff, DiscoveryError> {
        self.emit_audit(TopologyAuditEvent::RecrawlTriggered {
            reason: reason.to_string(),
        });
        self.do_recrawl(reason).await
    }

    /// Notify the scheduler that an unknown tool was encountered.
    ///
    /// If `on_unknown_tool` is enabled, this queues a re-crawl (debounced).
    pub fn notify_unknown_tool(&self, tool: &str, suggestion: Option<String>) {
        self.emit_audit(TopologyAuditEvent::TopologyViolation {
            tool: tool.to_string(),
            verdict: "Unknown".to_string(),
            suggestion,
        });

        if self.config.on_unknown_tool {
            self.trigger.notify_one();
        }
    }

    /// Get a handle for triggering re-crawls externally.
    pub fn trigger_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.trigger)
    }

    /// Perform a re-crawl and update the guard.
    async fn do_recrawl(&self, trigger: &str) -> Result<TopologyDiff, DiscoveryError> {
        let old_topology = self.guard.current();
        let old_fingerprint = old_topology
            .as_ref()
            .map(|t| t.fingerprint_hex())
            .unwrap_or_default();

        match self.crawler.crawl().await {
            Ok(result) => {
                self.consecutive_failures.store(0, Ordering::Relaxed);

                let new_fingerprint = result.topology.fingerprint_hex();

                self.emit_audit(TopologyAuditEvent::CrawlCompleted {
                    servers: result.servers_crawled,
                    tools: result.tools_found,
                    resources: result.resources_found,
                    fingerprint: new_fingerprint.clone(),
                    duration_ms: result.duration.as_millis() as u64,
                });

                // Compute diff before updating
                let diff = if let Some(ref old) = old_topology {
                    old.diff(&result.topology)
                } else {
                    crate::diff::TopologyDiff {
                        added_servers: result.topology.server_names(),
                        removed_servers: Vec::new(),
                        added_tools: Vec::new(),
                        removed_tools: Vec::new(),
                        modified_tools: Vec::new(),
                        added_resources: Vec::new(),
                        removed_resources: Vec::new(),
                        added_data_flow_edges: Vec::new(),
                        removed_data_flow_edges: Vec::new(),
                        timestamp: std::time::SystemTime::now(),
                    }
                };

                if !diff.is_empty() {
                    self.emit_audit(TopologyAuditEvent::TopologyChanged {
                        diff_summary: diff.summary(),
                        previous_fingerprint: old_fingerprint,
                        new_fingerprint,
                        trigger: trigger.to_string(),
                    });

                    if let Some(ref on_change) = self.on_change {
                        on_change(diff.clone());
                    }
                }

                // Hot-swap topology
                self.guard.update(result.topology);

                Ok(diff)
            }
            Err(err) => {
                let failures = self
                    .consecutive_failures
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);

                self.emit_audit(TopologyAuditEvent::CrawlFailed {
                    error: err.to_string(),
                    retained_fingerprint: if old_fingerprint.is_empty() {
                        None
                    } else {
                        Some(old_fingerprint)
                    },
                });

                if failures >= self.config.max_consecutive_failures {
                    // SECURITY (R230-DISC-5): Retain stale topology instead of clearing.
                    // Clearing triggers bypass mode, which an attacker can force via
                    // deliberate crawl failures. Stale data is safer than no data.
                    tracing::error!(
                        failures = failures,
                        max = self.config.max_consecutive_failures,
                        "Max consecutive crawl failures reached — retaining stale topology (NOT clearing)"
                    );
                }

                Err(err)
            }
        }
    }

    fn emit_audit(&self, event: TopologyAuditEvent) {
        if let Some(ref on_audit) = self.on_audit {
            on_audit(event);
        }
    }
}

impl std::fmt::Debug for RecrawlScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecrawlScheduler")
            .field("config", &self.config)
            .field(
                "consecutive_failures",
                &self.consecutive_failures.load(Ordering::Relaxed),
            )
            .finish()
    }
}
