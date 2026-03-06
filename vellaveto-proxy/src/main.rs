// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Vellaveto MCP Stdio Proxy
//!
//! Transparent proxy that sits between an agent and an MCP server,
//! intercepting `tools/call` requests and evaluating them against policies.
//!
//! Usage:
//! ```sh
//! vellaveto-proxy --config policy.toml -- /path/to/mcp-server [args...]
//! ```

use anyhow::{Context, Result};
use clap::Parser;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::Arc;
use tokio::process::Command;
use vellaveto_audit::AuditLogger;
use vellaveto_config::PolicyConfig;
use vellaveto_engine::PolicyEngine;
use vellaveto_mcp::proxy::ProxyBridge;
use vellaveto_types::command::resolve_executable;

#[derive(Parser)]
#[command(
    name = "vellaveto-proxy",
    about = "MCP stdio proxy with policy enforcement"
)]
struct Cli {
    /// Path to the policy configuration file (TOML)
    #[arg(short, long)]
    config: String,

    /// Enable strict mode for policy evaluation
    #[arg(long, default_value_t = false)]
    strict: bool,

    /// Request timeout in seconds (default: 30). Requests forwarded to the child
    /// server that don't receive a response within this time will be timed out.
    #[arg(long, default_value_t = 30)]
    timeout: u64,

    /// Enable evaluation trace logging. Traces include per-policy evaluation
    /// details and are emitted at DEBUG level.
    #[arg(long, default_value_t = false)]
    trace: bool,

    /// The MCP server command and arguments (after --)
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    if cli.command.is_empty() {
        anyhow::bail!("No MCP server command specified. Usage: vellaveto-proxy --config policy.toml -- /path/to/mcp-server [args...]");
    }

    // Load policies
    let policy_config = PolicyConfig::load_file(&cli.config)
        .map_err(|e| anyhow::anyhow!("Failed to load config '{}': {}", cli.config, e))?;
    let policies = policy_config.to_policies();
    tracing::info!("Loaded {} policies from {}", policies.len(), cli.config);

    // Set up audit logging next to config
    let config_dir = std::path::Path::new(&cli.config)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let audit_path = config_dir.join("proxy-audit.log");
    let audit = Arc::new(AuditLogger::new(audit_path.clone()));

    // SECURITY (R230-PROXY-1): Fail-closed — refuse to start with broken audit chain.
    audit.initialize_chain().await.context(
        "Failed to initialize audit chain — refusing to start with potentially tampered audit log",
    )?;
    tracing::info!("Audit log: {}", audit_path.display());

    // Verify child binary integrity before spawn (supply chain protection)
    let (child_cmd, child_args) = cli
        .command
        .split_first()
        .context("Command list is empty after validation")?;

    let path_env = std::env::var_os("PATH");
    let resolved_child_cmd = resolve_executable(child_cmd, path_env.as_deref()).map_err(|e| {
        anyhow::anyhow!(
            "Failed to resolve MCP server command '{}': {}",
            child_cmd,
            e
        )
    })?;

    let resolved_child_cmd_display = resolved_child_cmd.display().to_string();

    if let Err(reason) = policy_config
        .supply_chain
        .verify_binary(&resolved_child_cmd.to_string_lossy())
    {
        tracing::error!("Supply chain verification FAILED: {}", reason);
        anyhow::bail!(
            "Refusing to spawn MCP server '{}': supply chain verification failed — {}",
            resolved_child_cmd_display,
            reason
        );
    } else if policy_config.supply_chain.enabled {
        tracing::info!(
            "Supply chain verification passed for '{}'",
            resolved_child_cmd_display
        );
    }

    // Spawn child MCP server
    // SECURITY (FIND-GAP-011): Clear the environment of the child process to
    // prevent accidental leakage of secrets (e.g., API keys, tokens) from the
    // proxy's environment into the child. Only forward minimal required variables.
    let mut cmd = Command::new(&resolved_child_cmd);
    cmd.args(child_args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .env_clear();

    // Forward only minimal required environment variables
    for key in &["PATH", "HOME", "USER", "LANG", "TERM", "TMPDIR"] {
        if let Ok(val) = std::env::var(key) {
            cmd.env(key, val);
        }
    }
    // SECURITY (R231-PROXY-1): Force UTC timezone for child process to ensure
    // consistent timestamp behavior regardless of parent's TZ setting.
    cmd.env("TZ", "UTC");

    let mut child = cmd.spawn().context(format!(
        "Failed to spawn child MCP server: {}",
        resolved_child_cmd_display
    ))?;

    // FIND-R56-PROXY-002: Use descriptive string instead of PID 0 when child.id()
    // returns None (possible on some platforms before the child has started).
    let child_pid_display = child
        .id()
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    tracing::info!(
        "Spawned child MCP server (PID {}): {} {:?}",
        child_pid_display,
        resolved_child_cmd_display,
        child_args
    );

    // Fix #25: Brief startup check — detect immediate crashes (bad binary, missing
    // deps, wrong architecture) before entering the proxy loop.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    match child.try_wait() {
        Ok(Some(status)) => {
            anyhow::bail!(
                "Child MCP server exited immediately (PID {}, status: {}). \
                 Check that '{}' is a valid executable.",
                child_pid_display,
                status,
                resolved_child_cmd_display
            );
        }
        Ok(None) => {
            // Still running — good
            tracing::debug!("Child process {} is running", child_pid_display);
        }
        Err(e) => {
            tracing::warn!("Could not check child process status: {}", e);
        }
    }

    let child_stdin = child.stdin.take().context("Failed to get child stdin")?;
    let child_stdout = child.stdout.take().context("Failed to get child stdout")?;

    // Create proxy bridge with pre-compiled policies and configurable timeout
    let mut engine = PolicyEngine::with_policies(cli.strict, &policies).map_err(|errors| {
        for e in &errors {
            tracing::error!("Policy validation error: {}", e);
        }
        anyhow::anyhow!("{} policy validation errors", errors.len())
    })?;
    if let Some(max_iter) = policy_config.max_path_decode_iterations {
        engine.set_max_path_decode_iterations(max_iter);
        tracing::info!(
            max_path_decode_iterations = max_iter,
            "custom path decode iteration limit"
        );
    }
    let timeout = std::time::Duration::from_secs(cli.timeout);
    let mut bridge = ProxyBridge::new(engine, policies, audit)
        .with_timeout(timeout)
        .with_trace(cli.trace);

    // Build injection scanner from config (supports extra/disabled patterns)
    let injection_config = &policy_config.injection;
    if injection_config.enabled {
        if !injection_config.extra_patterns.is_empty()
            || !injection_config.disabled_patterns.is_empty()
        {
            if let Some(scanner) = vellaveto_mcp::inspection::InjectionScanner::from_config(
                &injection_config.extra_patterns,
                &injection_config.disabled_patterns,
            ) {
                tracing::info!(
                    "Injection scanner: {} active patterns ({} extra, {} disabled)",
                    scanner.patterns().len(),
                    injection_config.extra_patterns.len(),
                    injection_config.disabled_patterns.len(),
                );
                bridge = bridge.with_injection_scanner(scanner);
            }
        } else {
            tracing::info!("Injection scanner: default patterns");
        }
    } else {
        tracing::info!("Injection scanner: DISABLED by configuration");
        bridge = bridge.with_injection_disabled(true);
    }

    // SECURITY (FIND-R78-001): MCP 2025-11-25 tool name validation parity with HTTP proxy.
    if policy_config.streamable_http.strict_tool_name_validation {
        bridge = bridge.with_strict_tool_name_validation(true);
        tracing::info!("MCP tool name validation: ENABLED (strict)");
    }

    // SECURITY (GAP-R60-016): Wire ABAC engine for attribute-based access control.
    // Without this, ABAC forbid-override policies are completely inactive in stdio mode,
    // allowing actions that should be denied by ABAC rules.
    if policy_config.abac.enabled {
        match vellaveto_engine::abac::AbacEngine::new(
            &policy_config.abac.policies,
            &policy_config.abac.entities,
        ) {
            Ok(abac_engine) => {
                tracing::info!(
                    "ABAC engine: {} policies, {} entities",
                    policy_config.abac.policies.len(),
                    policy_config.abac.entities.len()
                );
                bridge = bridge.with_abac_engine(Arc::new(abac_engine));
            }
            Err(e) => {
                // Fail-closed: invalid ABAC config prevents startup
                anyhow::bail!("ABAC config error: {}", e);
            }
        }
    }

    // SECURITY (GAP-R60-017): Wire circuit breaker for cascading failure prevention (ASI08).
    if policy_config.circuit_breaker.enabled {
        let cb = vellaveto_engine::circuit_breaker::CircuitBreakerManager::with_config(
            policy_config.circuit_breaker.failure_threshold,
            policy_config.circuit_breaker.success_threshold,
            policy_config.circuit_breaker.open_duration_secs,
            policy_config.circuit_breaker.half_open_max_requests,
        );
        tracing::info!("Circuit breaker: ENABLED");
        bridge = bridge.with_circuit_breaker(Arc::new(cb));
    }

    // SECURITY (GAP-R60-017): Wire deputy validator for confused deputy prevention (ASI02).
    if policy_config.deputy.enabled {
        let deputy = vellaveto_engine::deputy::DeputyValidator::new(
            policy_config.deputy.max_delegation_depth,
        );
        tracing::info!(
            "Deputy validator: ENABLED (max depth: {})",
            policy_config.deputy.max_delegation_depth
        );
        bridge = bridge.with_deputy(Arc::new(deputy));
    }

    // SECURITY (GAP-R60-017): Wire schema lineage tracker for schema poisoning detection (ASI05).
    if policy_config.schema_poisoning.enabled {
        let tracker = vellaveto_mcp::schema_poisoning::SchemaLineageTracker::new(
            policy_config.schema_poisoning.mutation_threshold,
            policy_config.schema_poisoning.min_observations,
            policy_config.schema_poisoning.max_tracked_schemas,
        );
        tracing::info!("Schema lineage tracker: ENABLED");
        bridge = bridge.with_schema_lineage(Arc::new(tracker));
    }

    // SECURITY (GAP-R60-017): Wire shadow agent detector for rogue agent detection (ASI10).
    if policy_config.shadow_agent.enabled {
        let detector = vellaveto_mcp::shadow_agent::ShadowAgentDetector::new(
            policy_config.shadow_agent.max_known_agents,
        );
        tracing::info!(
            "Shadow agent detector: ENABLED (max known: {})",
            policy_config.shadow_agent.max_known_agents
        );
        bridge = bridge.with_shadow_agent(Arc::new(detector));
    }

    // Wire topology guard into ProxyBridge for live topology updates from tools/list.
    #[cfg(feature = "discovery")]
    if policy_config.topology.enabled {
        let guard = Arc::new(vellaveto_discovery::guard::TopologyGuard::new());
        bridge = bridge.with_topology_guard(Arc::clone(&guard));
        tracing::info!("Topology guard: ENABLED (stdio proxy)");
    }

    tracing::info!("Request timeout: {}s, trace: {}", cli.timeout, cli.trace);

    // Run the proxy
    let agent_stdin = tokio::io::stdin();
    let agent_stdout = tokio::io::stdout();

    let proxy_result = bridge
        .run(agent_stdin, agent_stdout, child_stdin, child_stdout)
        .await;

    // Clean up child process — kill and then reap to prevent zombies
    let _ = child.kill().await;
    let _ = child.wait().await;

    match proxy_result {
        Ok(()) => {
            tracing::info!("Proxy shut down cleanly");
            Ok(())
        }
        Err(e) => {
            tracing::error!("Proxy error: {}", e);
            Err(anyhow::anyhow!("Proxy error: {}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsString;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_nanos(),
            Err(_) => 0,
        };
        dir.push(format!("{}_{}_{}", prefix, std::process::id(), nanos));
        dir
    }

    #[test]
    fn resolve_child_command_keeps_explicit_relative_path() {
        let temp_dir = unique_temp_dir("relative-path");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let candidate = temp_dir.join("mock-server");
        std::fs::write(&candidate, b"#!/bin/sh\necho ok\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut perms = std::fs::metadata(&candidate)
                .unwrap_or_else(|e| panic!("metadata failed: {e}"))
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&candidate, perms)
                .unwrap_or_else(|e| panic!("set executable bit failed: {e}"));
        }

        let relative = "./mock-server";
        let original_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp_dir).unwrap();
        let resolved = resolve_executable(relative, None)
            .unwrap_or_else(|e| panic!("relative path should not require PATH: {e}"));
        std::env::set_current_dir(original_cwd).unwrap();

        assert_eq!(resolved, candidate);

        let _ = std::fs::remove_file(&candidate);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn resolve_child_command_resolves_bare_name_from_path() {
        let temp_dir = unique_temp_dir("vellaveto_proxy_path_resolve");
        std::fs::create_dir_all(&temp_dir)
            .unwrap_or_else(|e| panic!("create temp dir failed: {e}"));

        let candidate = temp_dir.join("mock-mcp-server");
        std::fs::write(&candidate, b"#!/bin/sh\necho ok\n")
            .unwrap_or_else(|e| panic!("write candidate command failed: {e}"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut perms = std::fs::metadata(&candidate)
                .unwrap_or_else(|e| panic!("metadata failed: {e}"))
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&candidate, perms)
                .unwrap_or_else(|e| panic!("set executable bit failed: {e}"));
        }

        let path_env = std::env::join_paths([temp_dir.clone()])
            .unwrap_or_else(|e| panic!("join_paths failed: {e}"));
        let resolved = resolve_executable("mock-mcp-server", Some(path_env.as_os_str()))
            .unwrap_or_else(|e| panic!("expected command to resolve from PATH: {e}"));

        assert_eq!(resolved, candidate);

        let _ = std::fs::remove_file(&candidate);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn resolve_child_command_rejects_missing_bare_name() {
        let temp_dir = unique_temp_dir("vellaveto_proxy_path_missing");
        std::fs::create_dir_all(&temp_dir)
            .unwrap_or_else(|e| panic!("create temp dir failed: {e}"));

        let path_env: OsString = std::env::join_paths([temp_dir.clone()])
            .unwrap_or_else(|e| panic!("join_paths failed: {e}"));
        let err = resolve_executable("definitely-not-present", Some(path_env.as_os_str()))
            .expect_err("missing command should fail");

        assert!(
            err.to_string().contains("not found in PATH"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn resolve_child_command_rejects_non_executable_candidate_on_unix() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let temp_dir = unique_temp_dir("vellaveto_proxy_path_nonexec");
            std::fs::create_dir_all(&temp_dir)
                .unwrap_or_else(|e| panic!("create temp dir failed: {e}"));

            let candidate = temp_dir.join("mock-mcp-server");
            std::fs::write(&candidate, b"not executable")
                .unwrap_or_else(|e| panic!("write candidate command failed: {e}"));

            let mut perms = std::fs::metadata(&candidate)
                .unwrap_or_else(|e| panic!("metadata failed: {e}"))
                .permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&candidate, perms)
                .unwrap_or_else(|e| panic!("set permissions failed: {e}"));

            let path_env = std::env::join_paths([temp_dir.clone()])
                .unwrap_or_else(|e| panic!("join_paths failed: {e}"));

            let err = resolve_executable("mock-mcp-server", Some(path_env.as_os_str()))
                .expect_err("non-executable command should not resolve");
            assert!(
                err.to_string().contains("not found in PATH"),
                "unexpected error: {err}"
            );

            let _ = std::fs::remove_file(&candidate);
            let _ = std::fs::remove_dir_all(&temp_dir);
        }
    }
}
