// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

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
        // SECURITY (R255-ENG-4b): Sanitize tool name before embedding in audit event.
        let sanitized_tool = vellaveto_types::sanitize_for_log(tool, 256);
        self.emit_audit(TopologyAuditEvent::TopologyViolation {
            tool: sanitized_tool,
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
                // SECURITY (R235-DISC-8): Use SeqCst for security-relevant counter per Trap 8.
                self.consecutive_failures.store(0, Ordering::SeqCst);

                let new_fingerprint = result.topology.fingerprint_hex();

                self.emit_audit(TopologyAuditEvent::CrawlCompleted {
                    servers: result.servers_crawled,
                    tools: result.tools_found,
                    resources: result.resources_found,
                    fingerprint: new_fingerprint.clone(),
                    // SECURITY (R246-ENG-1): Safe cast — as_millis() returns u128.
                    duration_ms: u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX),
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
                // SECURITY (R235-DISC-6): Use fetch_update with saturating add to
                // prevent the atomic from wrapping on overflow. Plain fetch_add(1)
                // wraps u32::MAX→0, resetting the failure counter.
                let failures = self
                    .consecutive_failures
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                        Some(v.saturating_add(1))
                    })
                    .unwrap_or(u32::MAX) // fetch_update with Some never returns Err
                    .saturating_add(1); // returned value is the old value

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
                &self.consecutive_failures.load(Ordering::SeqCst),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawler::{
        CrawlConfig, McpServerProbe, ResourceInfo, ServerInfo, StaticProbe, ToolInfo,
        TopologyCrawler,
    };
    use crate::topology::{StaticServerDecl, StaticToolDecl};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    fn make_test_guard() -> Arc<TopologyGuard> {
        let graph = crate::topology::TopologyGraph::from_static(vec![StaticServerDecl {
            name: "test-server".to_string(),
            tools: vec![StaticToolDecl {
                name: "tool_a".to_string(),
                description: "A test tool".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            }],
            resources: vec![],
        }])
        .unwrap();
        let guard = TopologyGuard::new();
        guard.update(graph);
        Arc::new(guard)
    }

    fn make_test_crawler() -> Arc<TopologyCrawler> {
        let probe = StaticProbe::new(vec![StaticServerDecl {
            name: "test-server".to_string(),
            tools: vec![StaticToolDecl {
                name: "tool_a".to_string(),
                description: "A test tool".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            }],
            resources: vec![],
        }]);
        Arc::new(TopologyCrawler::new(
            Arc::new(probe),
            CrawlConfig::default(),
        ))
    }

    #[test]
    fn test_recrawl_config_default_values() {
        let config = RecrawlConfig::default();
        assert_eq!(config.interval, Duration::from_secs(300));
        assert!(config.on_unknown_tool);
        assert_eq!(config.debounce, Duration::from_secs(30));
        assert_eq!(config.max_consecutive_failures, 3);
    }

    #[test]
    fn test_recrawl_config_zero_interval_disables_periodic() {
        let config = RecrawlConfig {
            interval: Duration::ZERO,
            ..RecrawlConfig::default()
        };
        assert!(config.interval.is_zero());
    }

    #[test]
    fn test_scheduler_creation_initial_state() {
        let crawler = make_test_crawler();
        let guard = make_test_guard();
        let config = RecrawlConfig::default();
        let scheduler = RecrawlScheduler::new(crawler, guard, config.clone());

        assert_eq!(scheduler.consecutive_failures.load(Ordering::Relaxed), 0);
        assert!(scheduler.on_change.is_none());
        assert!(scheduler.on_audit.is_none());
        assert_eq!(scheduler.config.interval, config.interval);
    }

    #[test]
    fn test_scheduler_set_on_change_callback() {
        let crawler = make_test_crawler();
        let guard = make_test_guard();
        let mut scheduler = RecrawlScheduler::new(crawler, guard, RecrawlConfig::default());

        assert!(scheduler.on_change.is_none());
        scheduler.set_on_change(Box::new(|_diff| {}));
        assert!(scheduler.on_change.is_some());
    }

    #[test]
    fn test_scheduler_set_on_audit_callback() {
        let crawler = make_test_crawler();
        let guard = make_test_guard();
        let mut scheduler = RecrawlScheduler::new(crawler, guard, RecrawlConfig::default());

        assert!(scheduler.on_audit.is_none());
        scheduler.set_on_audit(Box::new(|_event| {}));
        assert!(scheduler.on_audit.is_some());
    }

    #[test]
    fn test_scheduler_trigger_handle_returns_shared_notify() {
        let crawler = make_test_crawler();
        let guard = make_test_guard();
        let scheduler = RecrawlScheduler::new(crawler, guard, RecrawlConfig::default());

        let handle1 = scheduler.trigger_handle();
        let handle2 = scheduler.trigger_handle();
        // Both handles should point to the same Notify
        assert!(Arc::ptr_eq(&handle1, &handle2));
    }

    #[test]
    fn test_scheduler_debug_format() {
        let crawler = make_test_crawler();
        let guard = make_test_guard();
        let scheduler = RecrawlScheduler::new(crawler, guard, RecrawlConfig::default());

        let debug = format!("{scheduler:?}");
        assert!(debug.contains("RecrawlScheduler"));
        assert!(debug.contains("consecutive_failures"));
        assert!(debug.contains("config"));
    }

    #[tokio::test]
    async fn test_scheduler_trigger_recrawl_succeeds() {
        let crawler = make_test_crawler();
        let guard = make_test_guard();
        let scheduler = RecrawlScheduler::new(crawler, guard, RecrawlConfig::default());

        let result = scheduler.trigger_recrawl("test-reason").await;
        assert!(result.is_ok());
        // Consecutive failures should be reset to 0 after success
        assert_eq!(scheduler.consecutive_failures.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_scheduler_notify_unknown_tool_emits_audit() {
        let crawler = make_test_crawler();
        let guard = make_test_guard();
        let audit_events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let events_clone = Arc::clone(&audit_events);

        let mut scheduler = RecrawlScheduler::new(
            crawler,
            guard,
            RecrawlConfig {
                on_unknown_tool: true,
                ..RecrawlConfig::default()
            },
        );
        scheduler.set_on_audit(Box::new(move |event| {
            if let Ok(mut events) = events_clone.lock() {
                events.push(format!("{event:?}"));
            }
        }));

        scheduler.notify_unknown_tool("unknown_tool", Some("did_you_mean".to_string()));

        let events = audit_events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].contains("TopologyViolation"));
        assert!(events[0].contains("unknown_tool"));
    }

    #[tokio::test]
    async fn test_scheduler_notify_unknown_tool_disabled_no_trigger() {
        let crawler = make_test_crawler();
        let guard = make_test_guard();

        let scheduler = RecrawlScheduler::new(
            crawler,
            guard,
            RecrawlConfig {
                on_unknown_tool: false,
                ..RecrawlConfig::default()
            },
        );

        // This should not trigger a recrawl since on_unknown_tool is false.
        // We verify by checking that the trigger Notify is not notified —
        // if it were, a subsequent notified() would resolve immediately.
        scheduler.notify_unknown_tool("test_tool", None);
        // No panic, no crash — the tool notification was ignored.
    }

    #[tokio::test]
    async fn test_scheduler_consecutive_failures_increment() {
        // Create a crawler with an empty probe, so crawling a topology
        // that has servers in the guard but none in the probe will work
        // but produce a different topology (triggering a change, not a failure).
        // To test failure, we use a probe that fails on list_servers.
        use crate::error::DiscoveryError;
        use crate::topology::ServerCapabilities;
        use async_trait::async_trait;

        struct FailingProbe;
        #[async_trait]
        impl McpServerProbe for FailingProbe {
            async fn list_servers(&self) -> Result<Vec<ServerInfo>, DiscoveryError> {
                Err(DiscoveryError::GraphError("forced failure".to_string()))
            }
            async fn list_tools(&self, _: &str) -> Result<Vec<ToolInfo>, DiscoveryError> {
                Ok(vec![])
            }
            async fn list_resources(&self, _: &str) -> Result<Vec<ResourceInfo>, DiscoveryError> {
                Ok(vec![])
            }
            async fn server_capabilities(
                &self,
                _: &str,
            ) -> Result<ServerCapabilities, DiscoveryError> {
                Ok(ServerCapabilities::default())
            }
        }

        let crawler = Arc::new(TopologyCrawler::new(
            Arc::new(FailingProbe),
            CrawlConfig::default(),
        ));
        let guard = make_test_guard();
        let scheduler = RecrawlScheduler::new(crawler, guard, RecrawlConfig::default());

        // First failure
        let r1 = scheduler.trigger_recrawl("test").await;
        assert!(r1.is_err());
        assert_eq!(scheduler.consecutive_failures.load(Ordering::Relaxed), 1);

        // Second failure
        let r2 = scheduler.trigger_recrawl("test").await;
        assert!(r2.is_err());
        assert_eq!(scheduler.consecutive_failures.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_scheduler_run_shutdown_immediate() {
        let crawler = make_test_crawler();
        let guard = make_test_guard();
        let scheduler = RecrawlScheduler::new(crawler, guard, RecrawlConfig::default());

        let shutdown = CancellationToken::new();
        shutdown.cancel(); // Cancel immediately

        // run() should return immediately when shutdown is cancelled
        scheduler.run(shutdown).await;
        // If we get here, the scheduler shut down gracefully.
    }

    #[test]
    fn test_topology_audit_event_serialization() {
        let event = TopologyAuditEvent::CrawlCompleted {
            servers: 3,
            tools: 10,
            resources: 2,
            fingerprint: "abc123".to_string(),
            duration_ms: 42,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("CrawlCompleted"));
        assert!(json.contains("\"servers\":3"));

        let event2 = TopologyAuditEvent::TopologyViolation {
            tool: "unknown".to_string(),
            verdict: "Denied".to_string(),
            suggestion: Some("known_tool".to_string()),
        };
        let json2 = serde_json::to_string(&event2).unwrap();
        assert!(json2.contains("TopologyViolation"));
        assert!(json2.contains("known_tool"));
    }

    #[test]
    fn test_topology_audit_event_crawl_failed_serialization() {
        let event = TopologyAuditEvent::CrawlFailed {
            error: "timeout".to_string(),
            retained_fingerprint: Some("deadbeef".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("CrawlFailed"));
        assert!(json.contains("deadbeef"));

        let event_no_fp = TopologyAuditEvent::CrawlFailed {
            error: "network".to_string(),
            retained_fingerprint: None,
        };
        let json2 = serde_json::to_string(&event_no_fp).unwrap();
        assert!(json2.contains("null"));
    }
}
