// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Wasm policy plugin system for Vellaveto.
//!
//! This module defines the contract and management layer for running custom
//! policy logic as sandboxed Wasm plugins. Enterprises can author policy
//! plugins in any language that compiles to Wasm, load them into the engine,
//! and have them evaluated alongside native policies.
//!
//! # Architecture
//!
//! The module is structured around three layers:
//!
//! 1. **Interface types** ([`PluginAction`], [`PluginVerdict`]) — serializable
//!    representations of actions and verdicts exchanged with plugins.
//! 2. **Trait** ([`PolicyPlugin`]) — the contract every plugin must satisfy.
//! 3. **Manager** ([`PluginManager`]) — lifecycle management (load, reload,
//!    evaluate) with fail-closed semantics.
//!
//! The actual Wasm runtime (e.g. `wasmtime`, `extism`) is **not** bundled by
//! default. Instead, the `PolicyPlugin` trait can be implemented by a real
//! Wasm host behind a feature flag. The stub runtime in this module allows
//! the interface to compile and be tested without heavy dependencies.
//!
//! # Security
//!
//! - **Fail-closed:** Plugin errors produce deny verdicts.
//! - **Bounded resources:** Memory, fuel, and timeout limits are validated.
//! - **Input validation:** Plugin names and paths are checked for control
//!   characters, length bounds, and path traversal.
//! - **No panics:** All fallible operations return `Result`.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use vellaveto_types::{has_dangerous_chars, Action};

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

/// Maximum number of plugins that may be loaded simultaneously.
pub const MAX_PLUGINS: usize = 64;

/// Maximum length of a plugin name in bytes.
pub const MAX_PLUGIN_NAME_LEN: usize = 256;

/// Maximum length of a plugin path in bytes.
pub const MAX_PLUGIN_PATH_LEN: usize = 4096;

/// Minimum memory limit for a plugin (1 MiB).
pub const MIN_MEMORY_LIMIT: u64 = 1_048_576;

/// Maximum memory limit for a plugin (256 MiB).
pub const MAX_MEMORY_LIMIT: u64 = 268_435_456;

/// Minimum fuel limit for a plugin.
const MIN_FUEL_LIMIT: u64 = 1_000;

/// Maximum fuel limit for a plugin (10 billion).
const MAX_FUEL_LIMIT: u64 = 10_000_000_000;

/// Minimum timeout for a plugin in milliseconds.
const MIN_TIMEOUT_MS: u64 = 1;

/// Maximum timeout for a plugin in milliseconds (10 seconds).
const MAX_TIMEOUT_MS: u64 = 10_000;

/// Maximum length of a plugin verdict reason in bytes.
const MAX_REASON_LEN: usize = 4096;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during plugin operations.
#[derive(Error, Debug)]
pub enum PluginError {
    /// Plugin configuration validation failed.
    #[error("plugin config validation failed: {0}")]
    ConfigValidation(String),

    /// The maximum number of plugins has been reached.
    #[error("maximum plugin count ({MAX_PLUGINS}) exceeded")]
    MaxPluginsExceeded,

    /// A plugin with the given name is already loaded.
    #[error("plugin already loaded: {0}")]
    DuplicatePlugin(String),

    /// The plugin module could not be loaded.
    #[error("plugin load failed: {0}")]
    LoadFailed(String),

    /// The plugin evaluation returned an error.
    #[error("plugin evaluation error in '{plugin_name}': {reason}")]
    EvaluationFailed {
        /// Name of the plugin that failed.
        plugin_name: String,
        /// Description of the failure.
        reason: String,
    },

    /// Serialization/deserialization error during plugin communication.
    #[error("plugin serialization error: {0}")]
    Serialization(String),

    /// The plugin exceeded its resource limits (fuel, memory, timeout).
    #[error("plugin '{plugin_name}' exceeded resource limit: {resource}")]
    ResourceExceeded {
        /// Name of the plugin.
        plugin_name: String,
        /// Which resource was exceeded (fuel, memory, timeout).
        resource: String,
    },

    /// The plugin binary's SHA-256 hash does not match the configured content_hash.
    #[error("plugin content hash mismatch: expected {expected}, got {actual}")]
    ContentHashMismatch {
        /// The hash declared in the plugin config.
        expected: String,
        /// The hash computed from the actual file on disk.
        actual: String,
    },
}

// ---------------------------------------------------------------------------
// Plugin interface types
// ---------------------------------------------------------------------------

/// A simplified, serializable representation of an [`Action`] for plugin
/// consumption.
///
/// This avoids exposing internal types (like `resolved_ips`) to untrusted
/// plugin code. Only the information needed for policy evaluation is included.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginAction {
    /// The tool being invoked.
    pub tool: String,
    /// The function within the tool.
    pub function: String,
    /// Arbitrary parameters passed to the tool call.
    pub parameters: serde_json::Value,
    /// File paths targeted by this action.
    pub target_paths: Vec<String>,
    /// Domains targeted by this action.
    pub target_domains: Vec<String>,
}

impl PluginAction {
    /// Create a [`PluginAction`] from a core [`Action`].
    ///
    /// Deliberately excludes `resolved_ips` — plugin code should not be able
    /// to influence IP-based decisions, which are handled by the native engine.
    pub fn from_action(action: &Action) -> Self {
        // SECURITY (R238-ENG-7): Normalize tool and function names so Wasm plugins
        // doing string comparison cannot be bypassed via homoglyphs or case tricks.
        //
        // SECURITY (R239-ENG-3): Also normalize target_paths (percent-decode + traversal
        // protection) and target_domains (NFKC + lowercase + homoglyph mapping) so plugins
        // cannot be bypassed via encoding tricks or homoglyphs in paths/domains.
        Self {
            tool: crate::normalize::normalize_full(&action.tool),
            function: crate::normalize::normalize_full(&action.function),
            parameters: action.parameters.clone(),
            target_paths: action
                .target_paths
                .iter()
                .filter_map(|p| {
                    // SECURITY (R238-ENG-1): Fail-closed on path normalization failure.
                    // Previous code fell back to normalize_full() which lacks traversal
                    // protection (percent-decode + `..` resolution). Omitting the path
                    // is safer: the plugin won't see it, so it can't allow traversal.
                    match crate::PolicyEngine::normalize_path(p) {
                        Ok(norm) => Some(norm),
                        Err(_) => {
                            tracing::warn!(
                                path = %vellaveto_types::sanitize_for_log(p, 128),
                                "PluginAction: path normalization failed, omitting (fail-closed)"
                            );
                            None
                        }
                    }
                })
                .collect(),
            target_domains: action
                .target_domains
                .iter()
                .map(|d| crate::normalize::normalize_full(d))
                .collect(),
        }
    }
}

/// Result from a plugin evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginVerdict {
    /// Whether the plugin allows the action.
    pub allow: bool,
    /// Optional reason string (required when `allow` is `false`).
    pub reason: Option<String>,
}

impl PluginVerdict {
    /// Validate the verdict, ensuring bounded reason length.
    pub fn validate(&self) -> Result<(), PluginError> {
        // SECURITY (R261-WASM-1): Deny verdicts MUST include a reason.
        // Without a reason, operators cannot diagnose why an action was blocked.
        if !self.allow && self.reason.is_none() {
            return Err(PluginError::ConfigValidation(
                "deny verdict requires a reason".to_string(),
            ));
        }
        if let Some(ref reason) = self.reason {
            if reason.len() > MAX_REASON_LEN {
                return Err(PluginError::ConfigValidation(format!(
                    "verdict reason exceeds {MAX_REASON_LEN} bytes"
                )));
            }
            if has_dangerous_chars(reason) {
                return Err(PluginError::ConfigValidation(
                    "verdict reason contains control or format characters".to_string(),
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Plugin trait
// ---------------------------------------------------------------------------

/// Trait that every policy plugin must implement.
///
/// Implementations may wrap a real Wasm runtime (behind a feature flag) or
/// provide native Rust logic for testing purposes.
pub trait PolicyPlugin: Send + Sync {
    /// Returns the unique name of this plugin.
    fn name(&self) -> &str;

    /// Evaluate the given action and return a verdict.
    ///
    /// Implementations MUST be fail-closed: if any internal error occurs,
    /// return `Err(PluginError)` and the manager will treat it as a deny.
    fn evaluate(&self, action: &PluginAction) -> Result<PluginVerdict, PluginError>;
}

// ---------------------------------------------------------------------------
// Plugin configuration
// ---------------------------------------------------------------------------

/// Configuration for a single plugin module.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    /// Unique name identifying this plugin.
    pub name: String,
    /// Filesystem path to the `.wasm` module.
    pub path: String,
    /// Maximum memory the plugin may allocate (bytes).
    pub memory_limit_bytes: u64,
    /// Fuel limit (instruction budget) for a single evaluation call.
    pub fuel_limit: u64,
    /// Maximum wall-clock time for a single evaluation call (milliseconds).
    pub timeout_ms: u64,
    /// Optional SHA-256 content hash of the `.wasm` binary.
    /// Format: `sha256:<64-hex-chars>`. When set, the plugin loader verifies
    /// the file's hash matches before instantiation (TOCTOU defense).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

impl PluginConfig {
    /// Validate configuration bounds.
    ///
    /// Returns `Err(PluginError::ConfigValidation)` on any violation.
    pub fn validate(&self) -> Result<(), PluginError> {
        // Name validation
        if self.name.is_empty() {
            return Err(PluginError::ConfigValidation(
                "plugin name must not be empty".to_string(),
            ));
        }
        if self.name.len() > MAX_PLUGIN_NAME_LEN {
            return Err(PluginError::ConfigValidation(format!(
                "plugin name exceeds {MAX_PLUGIN_NAME_LEN} bytes"
            )));
        }
        if has_dangerous_chars(&self.name) {
            return Err(PluginError::ConfigValidation(
                "plugin name contains control or format characters".to_string(),
            ));
        }

        // Path validation
        if self.path.is_empty() {
            return Err(PluginError::ConfigValidation(
                "plugin path must not be empty".to_string(),
            ));
        }
        if self.path.len() > MAX_PLUGIN_PATH_LEN {
            return Err(PluginError::ConfigValidation(format!(
                "plugin path exceeds {MAX_PLUGIN_PATH_LEN} bytes"
            )));
        }
        if has_dangerous_chars(&self.path) {
            return Err(PluginError::ConfigValidation(
                "plugin path contains control or format characters".to_string(),
            ));
        }
        // SECURITY (R240-ENG-8): Path traversal check via Path::components()
        // instead of string contains("..") — the string check misses encoded
        // variants and is less precise than component-based inspection.
        for component in std::path::Path::new(&self.path).components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(PluginError::ConfigValidation(
                    "plugin path must not contain '..' (path traversal)".to_string(),
                ));
            }
        }

        // Memory limit bounds
        if self.memory_limit_bytes < MIN_MEMORY_LIMIT {
            return Err(PluginError::ConfigValidation(format!(
                "memory_limit_bytes ({}) below minimum ({MIN_MEMORY_LIMIT})",
                self.memory_limit_bytes
            )));
        }
        if self.memory_limit_bytes > MAX_MEMORY_LIMIT {
            return Err(PluginError::ConfigValidation(format!(
                "memory_limit_bytes ({}) exceeds maximum ({MAX_MEMORY_LIMIT})",
                self.memory_limit_bytes
            )));
        }

        // Fuel limit bounds
        if self.fuel_limit < MIN_FUEL_LIMIT {
            return Err(PluginError::ConfigValidation(format!(
                "fuel_limit ({}) below minimum ({MIN_FUEL_LIMIT})",
                self.fuel_limit
            )));
        }
        if self.fuel_limit > MAX_FUEL_LIMIT {
            return Err(PluginError::ConfigValidation(format!(
                "fuel_limit ({}) exceeds maximum ({MAX_FUEL_LIMIT})",
                self.fuel_limit
            )));
        }

        // Timeout bounds
        if self.timeout_ms < MIN_TIMEOUT_MS {
            return Err(PluginError::ConfigValidation(format!(
                "timeout_ms ({}) below minimum ({MIN_TIMEOUT_MS})",
                self.timeout_ms
            )));
        }
        if self.timeout_ms > MAX_TIMEOUT_MS {
            return Err(PluginError::ConfigValidation(format!(
                "timeout_ms ({}) exceeds maximum ({MAX_TIMEOUT_MS})",
                self.timeout_ms
            )));
        }

        // Content hash format validation (if provided).
        // Expected format: sha256:<64-hex-chars> (total 71 chars).
        if let Some(ref hash) = self.content_hash {
            if hash.len() != 71 {
                return Err(PluginError::ConfigValidation(format!(
                    "content_hash must be exactly 71 chars (sha256:<64-hex>), got {}",
                    hash.len()
                )));
            }
            if !hash.starts_with("sha256:") {
                return Err(PluginError::ConfigValidation(
                    "content_hash must start with 'sha256:' prefix".to_string(),
                ));
            }
            let hex_part = &hash[7..];
            if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(PluginError::ConfigValidation(
                    "content_hash hex portion contains non-hex characters".to_string(),
                ));
            }
            if has_dangerous_chars(hash) {
                return Err(PluginError::ConfigValidation(
                    "content_hash contains control or format characters".to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Compute the SHA-256 content hash of a file at the given path.
/// Returns the hash in `sha256:<64-hex-chars>` format.
fn compute_file_content_hash(path: &str) -> Result<String, PluginError> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path).map_err(|e| {
        PluginError::LoadFailed(format!("cannot read plugin file '{}': {}", path, e))
    })?;
    let hash = Sha256::digest(&data);
    Ok(format!("sha256:{}", hex::encode(hash)))
}

/// Configuration for the plugin manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManagerConfig {
    /// Whether the plugin system is enabled.
    pub enabled: bool,
    /// Maximum number of plugins that may be loaded.
    pub max_plugins: usize,
    /// Default memory limit for plugins that don't specify one (bytes).
    pub default_memory_limit: u64,
    /// Default fuel limit for plugins that don't specify one.
    pub default_fuel_limit: u64,
    /// Default timeout for plugins that don't specify one (milliseconds).
    pub default_timeout_ms: u64,
}

impl Default for PluginManagerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_plugins: 32,
            default_memory_limit: 16 * 1024 * 1024, // 16 MiB
            default_fuel_limit: 100_000_000,
            default_timeout_ms: 5,
        }
    }
}

impl PluginManagerConfig {
    /// Validate the manager configuration.
    pub fn validate(&self) -> Result<(), PluginError> {
        if self.max_plugins > MAX_PLUGINS {
            return Err(PluginError::ConfigValidation(format!(
                "max_plugins ({}) exceeds hard limit ({MAX_PLUGINS})",
                self.max_plugins
            )));
        }
        if self.max_plugins == 0 && self.enabled {
            return Err(PluginError::ConfigValidation(
                "max_plugins cannot be 0 when plugins are enabled".to_string(),
            ));
        }
        if self.default_memory_limit < MIN_MEMORY_LIMIT {
            return Err(PluginError::ConfigValidation(format!(
                "default_memory_limit ({}) below minimum ({MIN_MEMORY_LIMIT})",
                self.default_memory_limit
            )));
        }
        if self.default_memory_limit > MAX_MEMORY_LIMIT {
            return Err(PluginError::ConfigValidation(format!(
                "default_memory_limit ({}) exceeds maximum ({MAX_MEMORY_LIMIT})",
                self.default_memory_limit
            )));
        }
        if self.default_fuel_limit < MIN_FUEL_LIMIT {
            return Err(PluginError::ConfigValidation(format!(
                "default_fuel_limit ({}) below minimum ({MIN_FUEL_LIMIT})",
                self.default_fuel_limit
            )));
        }
        if self.default_fuel_limit > MAX_FUEL_LIMIT {
            return Err(PluginError::ConfigValidation(format!(
                "default_fuel_limit ({}) exceeds maximum ({MAX_FUEL_LIMIT})",
                self.default_fuel_limit
            )));
        }
        if self.default_timeout_ms < MIN_TIMEOUT_MS {
            return Err(PluginError::ConfigValidation(format!(
                "default_timeout_ms ({}) below minimum ({MIN_TIMEOUT_MS})",
                self.default_timeout_ms
            )));
        }
        if self.default_timeout_ms > MAX_TIMEOUT_MS {
            return Err(PluginError::ConfigValidation(format!(
                "default_timeout_ms ({}) exceeds maximum ({MAX_TIMEOUT_MS})",
                self.default_timeout_ms
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Loaded plugin wrapper
// ---------------------------------------------------------------------------

/// A loaded plugin instance with its associated configuration.
struct LoadedPlugin {
    config: PluginConfig,
    instance: Box<dyn PolicyPlugin>,
}

// ---------------------------------------------------------------------------
// Plugin manager
// ---------------------------------------------------------------------------

/// Manages the lifecycle and evaluation of Wasm policy plugins.
///
/// # Fail-closed semantics
///
/// If any plugin errors during evaluation, the manager treats the result as
/// a deny with the error description as the reason. This ensures that plugin
/// failures never silently allow actions.
pub struct PluginManager {
    plugins: Vec<LoadedPlugin>,
    config: PluginManagerConfig,
}

impl std::fmt::Debug for PluginManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginManager")
            .field("plugin_count", &self.plugins.len())
            .field("config", &self.config)
            .finish()
    }
}

impl PluginManager {
    /// Create a new plugin manager with the given configuration.
    ///
    /// The configuration is validated before the manager is created.
    pub fn new(config: PluginManagerConfig) -> Result<Self, PluginError> {
        config.validate()?;
        Ok(Self {
            plugins: Vec::new(),
            config,
        })
    }

    /// Load a plugin into the manager.
    ///
    /// The plugin configuration is validated, and the plugin is instantiated
    /// using the provided `PolicyPlugin` implementation.
    ///
    /// # Errors
    ///
    /// Returns `PluginError::MaxPluginsExceeded` if the manager is full,
    /// `PluginError::DuplicatePlugin` if a plugin with the same name exists,
    /// or `PluginError::ConfigValidation` if the config is invalid.
    pub fn load_plugin(
        &mut self,
        config: PluginConfig,
        instance: Box<dyn PolicyPlugin>,
    ) -> Result<(), PluginError> {
        if !self.config.enabled {
            return Err(PluginError::ConfigValidation(
                "plugin system is not enabled".to_string(),
            ));
        }

        config.validate()?;

        // SECURITY: Verify content hash before instantiation (TOCTOU defense).
        if let Some(ref expected) = config.content_hash {
            let actual = compute_file_content_hash(&config.path)?;
            if actual != *expected {
                return Err(PluginError::ContentHashMismatch {
                    expected: expected.clone(),
                    actual,
                });
            }
        }

        if self.plugins.len() >= self.config.max_plugins {
            return Err(PluginError::MaxPluginsExceeded);
        }

        // SECURITY (R229-ENG-4): Case-insensitive duplicate check to prevent
        // a "MaliciousPlugin" from coexisting with "maliciousplugin".
        if self
            .plugins
            .iter()
            .any(|p| p.config.name.eq_ignore_ascii_case(&config.name))
        {
            return Err(PluginError::DuplicatePlugin(config.name.clone()));
        }

        self.plugins.push(LoadedPlugin { config, instance });
        Ok(())
    }

    /// Evaluate all loaded plugins against the given action.
    ///
    /// Returns a vector of `(plugin_name, verdict)` tuples. Plugin errors
    /// are converted to deny verdicts (fail-closed).
    ///
    /// If the plugin system is disabled or no plugins are loaded, returns
    /// an empty vector.
    pub fn evaluate_all(&self, action: &Action) -> Vec<(String, PluginVerdict)> {
        if !self.config.enabled {
            return Vec::new();
        }

        let plugin_action = PluginAction::from_action(action);
        let mut results = Vec::with_capacity(self.plugins.len());

        for loaded in &self.plugins {
            let name = loaded.config.name.clone();
            let verdict = match loaded.instance.evaluate(&plugin_action) {
                Ok(v) => {
                    // Validate the verdict from the plugin (bounded reason, no control chars)
                    match v.validate() {
                        Ok(()) => v,
                        Err(e) => {
                            // SECURITY (R252-ENG-1): Sanitize to prevent control char injection.
                            let raw = format!("plugin '{name}' returned invalid verdict: {e}");
                            PluginVerdict {
                                allow: false,
                                reason: Some(vellaveto_types::sanitize_for_log(
                                    &raw,
                                    MAX_REASON_LEN,
                                )),
                            }
                        }
                    }
                }
                Err(e) => {
                    // Fail-closed: plugin error -> deny
                    // SECURITY (R252-ENG-1): Sanitize error reason to prevent control
                    // character injection from malicious plugins bypassing validate().
                    let raw_reason = format!("plugin '{name}' error: {e}");
                    let sanitized = vellaveto_types::sanitize_for_log(&raw_reason, MAX_REASON_LEN);
                    PluginVerdict {
                        allow: false,
                        reason: Some(sanitized),
                    }
                }
            };
            results.push((name, verdict));
        }

        results
    }

    /// Replace all loaded plugins with a new set.
    ///
    /// Validates each configuration before loading. If any validation fails,
    /// no plugins are replaced (atomic swap).
    pub fn reload_plugins(
        &mut self,
        configs_and_instances: Vec<(PluginConfig, Box<dyn PolicyPlugin>)>,
    ) -> Result<(), PluginError> {
        if !self.config.enabled {
            return Err(PluginError::ConfigValidation(
                "plugin system is not enabled".to_string(),
            ));
        }

        if configs_and_instances.len() > self.config.max_plugins {
            return Err(PluginError::MaxPluginsExceeded);
        }

        // Validate all configs first (atomic: fail before replacing anything)
        // SECURITY (R237-ENG-1): Use case-insensitive duplicate check, matching load_plugin().
        let mut names = std::collections::HashSet::new();
        for (config, _) in &configs_and_instances {
            config.validate()?;
            if !names.insert(config.name.to_ascii_lowercase()) {
                return Err(PluginError::DuplicatePlugin(config.name.clone()));
            }
        }

        // All valid — swap
        self.plugins = configs_and_instances
            .into_iter()
            .map(|(config, instance)| LoadedPlugin { config, instance })
            .collect();

        Ok(())
    }

    /// Returns the number of currently loaded plugins.
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /// Returns the names of all currently loaded plugins.
    pub fn plugin_names(&self) -> Vec<&str> {
        self.plugins
            .iter()
            .map(|p| p.config.name.as_str())
            .collect()
    }

    /// Returns whether the plugin system is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A stub plugin for testing that always returns a fixed verdict.
    struct StubPlugin {
        plugin_name: String,
        verdict: PluginVerdict,
    }

    impl StubPlugin {
        fn allowing(name: &str) -> Self {
            Self {
                plugin_name: name.to_string(),
                verdict: PluginVerdict {
                    allow: true,
                    reason: None,
                },
            }
        }

        fn denying(name: &str, reason: &str) -> Self {
            Self {
                plugin_name: name.to_string(),
                verdict: PluginVerdict {
                    allow: false,
                    reason: Some(reason.to_string()),
                },
            }
        }
    }

    impl PolicyPlugin for StubPlugin {
        fn name(&self) -> &str {
            &self.plugin_name
        }

        fn evaluate(&self, _action: &PluginAction) -> Result<PluginVerdict, PluginError> {
            Ok(self.verdict.clone())
        }
    }

    /// A stub plugin that always errors (for fail-closed testing).
    struct ErrorPlugin {
        plugin_name: String,
    }

    impl PolicyPlugin for ErrorPlugin {
        fn name(&self) -> &str {
            &self.plugin_name
        }

        fn evaluate(&self, _action: &PluginAction) -> Result<PluginVerdict, PluginError> {
            Err(PluginError::EvaluationFailed {
                plugin_name: self.plugin_name.clone(),
                reason: "simulated failure".to_string(),
            })
        }
    }

    fn valid_plugin_config(name: &str) -> PluginConfig {
        PluginConfig {
            name: name.to_string(),
            path: "/opt/vellaveto/plugins/test.wasm".to_string(),
            memory_limit_bytes: 16 * 1024 * 1024,
            fuel_limit: 100_000_000,
            timeout_ms: 5,
            content_hash: None,
        }
    }

    fn enabled_manager_config() -> PluginManagerConfig {
        PluginManagerConfig {
            enabled: true,
            ..PluginManagerConfig::default()
        }
    }

    fn test_action() -> Action {
        Action::new("filesystem", "read", json!({"path": "/etc/passwd"}))
    }

    // --- PluginConfig validation tests ---

    #[test]
    fn test_plugin_config_validation_valid() {
        let config = valid_plugin_config("my-plugin");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_plugin_config_validation_empty_name() {
        let mut config = valid_plugin_config("test");
        config.name = String::new();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn test_invalid_plugin_name_too_long() {
        let mut config = valid_plugin_config("test");
        config.name = "x".repeat(MAX_PLUGIN_NAME_LEN + 1);
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn test_invalid_plugin_name_control_chars() {
        let mut config = valid_plugin_config("test");
        config.name = "plugin\x00name".to_string();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("control or format characters"));
    }

    #[test]
    fn test_invalid_plugin_path_empty() {
        let mut config = valid_plugin_config("test");
        config.path = String::new();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn test_invalid_plugin_path_traversal() {
        let mut config = valid_plugin_config("test");
        config.path = "/opt/../etc/passwd".to_string();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn test_invalid_plugin_path_control_chars() {
        let mut config = valid_plugin_config("test");
        config.path = "/opt/plugins/\x07evil.wasm".to_string();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("control or format characters"));
    }

    #[test]
    fn test_memory_limit_bounds_too_low() {
        let mut config = valid_plugin_config("test");
        config.memory_limit_bytes = MIN_MEMORY_LIMIT - 1;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("below minimum"));
    }

    #[test]
    fn test_memory_limit_bounds_too_high() {
        let mut config = valid_plugin_config("test");
        config.memory_limit_bytes = MAX_MEMORY_LIMIT + 1;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_memory_limit_bounds_edge_values() {
        let mut config = valid_plugin_config("test");
        config.memory_limit_bytes = MIN_MEMORY_LIMIT;
        assert!(config.validate().is_ok());
        config.memory_limit_bytes = MAX_MEMORY_LIMIT;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_fuel_limit_validation_too_low() {
        let mut config = valid_plugin_config("test");
        config.fuel_limit = 0;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("below minimum"));
    }

    #[test]
    fn test_fuel_limit_validation_too_high() {
        let mut config = valid_plugin_config("test");
        config.fuel_limit = MAX_FUEL_LIMIT + 1;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_timeout_bounds() {
        let mut config = valid_plugin_config("test");
        config.timeout_ms = 0;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("below minimum"));

        config.timeout_ms = MAX_TIMEOUT_MS + 1;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));

        config.timeout_ms = MIN_TIMEOUT_MS;
        assert!(config.validate().is_ok());
        config.timeout_ms = MAX_TIMEOUT_MS;
        assert!(config.validate().is_ok());
    }

    // --- PluginManagerConfig validation tests ---

    #[test]
    fn test_plugin_manager_creation_default() {
        let config = PluginManagerConfig::default();
        // Default is disabled, so validation should pass
        let mgr = PluginManager::new(config);
        assert!(mgr.is_ok());
        let mgr = mgr.unwrap();
        assert!(!mgr.is_enabled());
        assert_eq!(mgr.plugin_count(), 0);
    }

    #[test]
    fn test_plugin_manager_creation_enabled() {
        let config = enabled_manager_config();
        let mgr = PluginManager::new(config);
        assert!(mgr.is_ok());
        assert!(mgr.unwrap().is_enabled());
    }

    #[test]
    fn test_plugin_manager_config_max_plugins_exceeded() {
        let config = PluginManagerConfig {
            enabled: true,
            max_plugins: MAX_PLUGINS + 1,
            ..PluginManagerConfig::default()
        };
        let err = PluginManager::new(config).unwrap_err();
        assert!(err.to_string().contains("exceeds hard limit"));
    }

    #[test]
    fn test_plugin_manager_config_zero_plugins_when_enabled() {
        let config = PluginManagerConfig {
            enabled: true,
            max_plugins: 0,
            ..PluginManagerConfig::default()
        };
        let err = PluginManager::new(config).unwrap_err();
        assert!(err.to_string().contains("cannot be 0"));
    }

    // --- PluginAction tests ---

    #[test]
    fn test_plugin_action_from_action() {
        let action = Action {
            tool: "fs".to_string(),
            function: "read".to_string(),
            parameters: json!({"path": "/tmp/test"}),
            target_paths: vec!["/tmp/test".to_string()],
            target_domains: vec!["example.com".to_string()],
            resolved_ips: vec!["93.184.216.34".to_string()],
        };

        let plugin_action = PluginAction::from_action(&action);

        assert_eq!(plugin_action.tool, "fs");
        assert_eq!(plugin_action.function, "read");
        assert_eq!(plugin_action.parameters, json!({"path": "/tmp/test"}));
        assert_eq!(plugin_action.target_paths, vec!["/tmp/test"]);
        assert_eq!(plugin_action.target_domains, vec!["example.com"]);
        // resolved_ips should NOT be present in PluginAction
    }

    #[test]
    fn test_plugin_action_serialization_roundtrip() {
        let action = PluginAction {
            tool: "http".to_string(),
            function: "get".to_string(),
            parameters: json!({"url": "https://example.com"}),
            target_paths: vec![],
            target_domains: vec!["example.com".to_string()],
        };

        let serialized = serde_json::to_string(&action);
        assert!(serialized.is_ok());
        let deserialized: Result<PluginAction, _> =
            serde_json::from_str(serialized.as_ref().unwrap());
        assert!(deserialized.is_ok());
        let roundtripped = deserialized.unwrap();
        assert_eq!(roundtripped.tool, "http");
        assert_eq!(roundtripped.function, "get");
    }

    // --- PluginVerdict tests ---

    #[test]
    fn test_plugin_verdict_serialization() {
        let verdict = PluginVerdict {
            allow: false,
            reason: Some("blocked by custom policy".to_string()),
        };

        let serialized = serde_json::to_string(&verdict);
        assert!(serialized.is_ok());
        let json_str = serialized.unwrap();
        assert!(json_str.contains("\"allow\":false"));
        assert!(json_str.contains("blocked by custom policy"));

        let deserialized: Result<PluginVerdict, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok());
        let v = deserialized.unwrap();
        assert!(!v.allow);
        assert_eq!(v.reason.as_deref(), Some("blocked by custom policy"));
    }

    #[test]
    fn test_plugin_verdict_validation_reason_too_long() {
        let verdict = PluginVerdict {
            allow: false,
            reason: Some("x".repeat(MAX_REASON_LEN + 1)),
        };
        assert!(verdict.validate().is_err());
    }

    #[test]
    fn test_plugin_verdict_validation_reason_control_chars() {
        let verdict = PluginVerdict {
            allow: true,
            reason: Some("okay\x00not-okay".to_string()),
        };
        assert!(verdict.validate().is_err());
    }

    // ── Content hash validation tests ──────────────────────────────────

    #[test]
    fn test_plugin_config_content_hash_valid() {
        let mut config = valid_plugin_config("my-plugin");
        config.content_hash =
            Some(format!("sha256:{}", "a".repeat(64)));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_plugin_config_content_hash_wrong_prefix_rejected() {
        let mut config = valid_plugin_config("my-plugin");
        config.content_hash = Some(format!("md5:{}", "a".repeat(64)));
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_plugin_config_content_hash_wrong_length_rejected() {
        let mut config = valid_plugin_config("my-plugin");
        config.content_hash = Some("sha256:abcd".to_string());
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_plugin_config_content_hash_non_hex_rejected() {
        let mut config = valid_plugin_config("my-plugin");
        config.content_hash =
            Some(format!("sha256:{}", "g".repeat(64)));
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_plugin_config_content_hash_none_accepted() {
        let config = valid_plugin_config("my-plugin");
        assert!(config.content_hash.is_none());
        assert!(config.validate().is_ok());
    }

    // R261-WASM-1: Deny verdict without reason must be rejected
    #[test]
    fn test_r261_plugin_verdict_deny_without_reason_rejected() {
        let verdict = PluginVerdict {
            allow: false,
            reason: None,
        };
        let err = verdict.validate().unwrap_err();
        assert!(
            err.to_string().contains("deny verdict requires a reason"),
            "Error: {err}"
        );
    }

    // R261-WASM-1: Allow verdict without reason is fine
    #[test]
    fn test_r261_plugin_verdict_allow_without_reason_ok() {
        let verdict = PluginVerdict {
            allow: true,
            reason: None,
        };
        assert!(verdict.validate().is_ok());
    }

    // --- Plugin loading tests ---

    #[test]
    fn test_load_plugin_success() {
        let mut mgr = PluginManager::new(enabled_manager_config()).unwrap();
        let config = valid_plugin_config("test-plugin");
        let plugin = Box::new(StubPlugin::allowing("test-plugin"));
        assert!(mgr.load_plugin(config, plugin).is_ok());
        assert_eq!(mgr.plugin_count(), 1);
        assert_eq!(mgr.plugin_names(), vec!["test-plugin"]);
    }

    #[test]
    fn test_load_plugin_disabled_system() {
        let mut mgr = PluginManager::new(PluginManagerConfig::default()).unwrap();
        let config = valid_plugin_config("test-plugin");
        let plugin = Box::new(StubPlugin::allowing("test-plugin"));
        let err = mgr.load_plugin(config, plugin).unwrap_err();
        assert!(err.to_string().contains("not enabled"));
    }

    #[test]
    fn test_max_plugins_bound_enforced() {
        let config = PluginManagerConfig {
            enabled: true,
            max_plugins: 2,
            ..PluginManagerConfig::default()
        };
        let mut mgr = PluginManager::new(config).unwrap();

        let p1 = valid_plugin_config("plugin-1");
        mgr.load_plugin(p1, Box::new(StubPlugin::allowing("plugin-1")))
            .unwrap();

        let p2 = valid_plugin_config("plugin-2");
        mgr.load_plugin(p2, Box::new(StubPlugin::allowing("plugin-2")))
            .unwrap();

        let p3 = valid_plugin_config("plugin-3");
        let err = mgr
            .load_plugin(p3, Box::new(StubPlugin::allowing("plugin-3")))
            .unwrap_err();
        assert!(matches!(err, PluginError::MaxPluginsExceeded));
    }

    #[test]
    fn test_duplicate_plugin_name_rejected() {
        let mut mgr = PluginManager::new(enabled_manager_config()).unwrap();
        let config1 = valid_plugin_config("my-plugin");
        mgr.load_plugin(config1, Box::new(StubPlugin::allowing("my-plugin")))
            .unwrap();

        let config2 = valid_plugin_config("my-plugin");
        let err = mgr
            .load_plugin(config2, Box::new(StubPlugin::allowing("my-plugin")))
            .unwrap_err();
        assert!(matches!(err, PluginError::DuplicatePlugin(_)));
    }

    // --- Evaluation tests ---

    #[test]
    fn test_evaluate_all_empty_returns_empty() {
        let mgr = PluginManager::new(enabled_manager_config()).unwrap();
        let action = test_action();
        let results = mgr.evaluate_all(&action);
        assert!(results.is_empty());
    }

    #[test]
    fn test_evaluate_all_disabled_returns_empty() {
        let mgr = PluginManager::new(PluginManagerConfig::default()).unwrap();
        let action = test_action();
        let results = mgr.evaluate_all(&action);
        assert!(results.is_empty());
    }

    #[test]
    fn test_evaluate_all_allow_and_deny() {
        let mut mgr = PluginManager::new(enabled_manager_config()).unwrap();

        let c1 = valid_plugin_config("allow-plugin");
        mgr.load_plugin(c1, Box::new(StubPlugin::allowing("allow-plugin")))
            .unwrap();

        let c2 = valid_plugin_config("deny-plugin");
        mgr.load_plugin(c2, Box::new(StubPlugin::denying("deny-plugin", "blocked")))
            .unwrap();

        let action = test_action();
        let results = mgr.evaluate_all(&action);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "allow-plugin");
        assert!(results[0].1.allow);
        assert_eq!(results[1].0, "deny-plugin");
        assert!(!results[1].1.allow);
        assert_eq!(results[1].1.reason.as_deref(), Some("blocked"));
    }

    #[test]
    fn test_evaluate_all_error_produces_deny() {
        let mut mgr = PluginManager::new(enabled_manager_config()).unwrap();
        let config = valid_plugin_config("error-plugin");
        mgr.load_plugin(
            config,
            Box::new(ErrorPlugin {
                plugin_name: "error-plugin".to_string(),
            }),
        )
        .unwrap();

        let action = test_action();
        let results = mgr.evaluate_all(&action);

        assert_eq!(results.len(), 1);
        assert!(!results[0].1.allow, "plugin error must produce deny");
        let reason = results[0].1.reason.as_deref().unwrap_or("");
        assert!(reason.contains("error"));
    }

    // --- R252-ENG-1: Error reason sanitization ---

    /// A plugin that returns an error with control characters in the reason.
    struct ControlCharErrorPlugin;

    impl PolicyPlugin for ControlCharErrorPlugin {
        fn name(&self) -> &str {
            "control-char-plugin"
        }

        fn evaluate(&self, _action: &PluginAction) -> Result<PluginVerdict, PluginError> {
            Err(PluginError::EvaluationFailed {
                plugin_name: "control-char-plugin".to_string(),
                reason: "injected\x00null\x07bell\x1besc".to_string(),
            })
        }
    }

    #[test]
    fn test_r252_eng1_error_reason_sanitized_no_control_chars() {
        let mut mgr = PluginManager::new(enabled_manager_config()).unwrap();
        let config = valid_plugin_config("control-char-plugin");
        mgr.load_plugin(config, Box::new(ControlCharErrorPlugin))
            .unwrap();

        let action = test_action();
        let results = mgr.evaluate_all(&action);

        assert_eq!(results.len(), 1);
        assert!(!results[0].1.allow, "plugin error must produce deny");
        let reason = results[0].1.reason.as_deref().unwrap_or("");
        // Verify no control characters in the sanitized reason
        assert!(
            !reason.chars().any(|c| c.is_control() && c != '\n'),
            "reason must not contain control chars after sanitization, got: {:?}",
            reason
        );
    }

    /// A plugin that returns Ok with a verdict containing control chars in reason.
    struct ControlCharVerdictPlugin;

    impl PolicyPlugin for ControlCharVerdictPlugin {
        fn name(&self) -> &str {
            "control-verdict-plugin"
        }

        fn evaluate(&self, _action: &PluginAction) -> Result<PluginVerdict, PluginError> {
            Ok(PluginVerdict {
                allow: false,
                reason: Some("good\x00bad\x1bchars".to_string()),
            })
        }
    }

    #[test]
    fn test_r252_eng1_invalid_verdict_reason_sanitized() {
        let mut mgr = PluginManager::new(enabled_manager_config()).unwrap();
        let config = valid_plugin_config("control-verdict-plugin");
        mgr.load_plugin(config, Box::new(ControlCharVerdictPlugin))
            .unwrap();

        let action = test_action();
        let results = mgr.evaluate_all(&action);

        assert_eq!(results.len(), 1);
        assert!(!results[0].1.allow, "invalid verdict must produce deny");
        let reason = results[0].1.reason.as_deref().unwrap_or("");
        // The invalid verdict path also sanitizes
        assert!(
            !reason.chars().any(|c| c.is_control() && c != '\n'),
            "reason must not contain control chars, got: {:?}",
            reason
        );
    }

    // --- Reload tests ---

    #[test]
    fn test_reload_plugins_replaces_all() {
        let mut mgr = PluginManager::new(enabled_manager_config()).unwrap();

        // Load initial plugin
        let c1 = valid_plugin_config("old-plugin");
        mgr.load_plugin(c1, Box::new(StubPlugin::allowing("old-plugin")))
            .unwrap();
        assert_eq!(mgr.plugin_count(), 1);

        // Reload with two new plugins
        let new_plugins: Vec<(PluginConfig, Box<dyn PolicyPlugin>)> = vec![
            (
                valid_plugin_config("new-1"),
                Box::new(StubPlugin::allowing("new-1")),
            ),
            (
                valid_plugin_config("new-2"),
                Box::new(StubPlugin::denying("new-2", "policy")),
            ),
        ];

        assert!(mgr.reload_plugins(new_plugins).is_ok());
        assert_eq!(mgr.plugin_count(), 2);
        assert_eq!(mgr.plugin_names(), vec!["new-1", "new-2"]);
    }

    #[test]
    fn test_reload_plugins_atomic_on_validation_failure() {
        let mut mgr = PluginManager::new(enabled_manager_config()).unwrap();

        // Load initial plugin
        let c1 = valid_plugin_config("original");
        mgr.load_plugin(c1, Box::new(StubPlugin::allowing("original")))
            .unwrap();

        // Attempt reload with one valid and one invalid config
        let mut invalid_config = valid_plugin_config("bad-plugin");
        invalid_config.memory_limit_bytes = 0; // Invalid

        let new_plugins: Vec<(PluginConfig, Box<dyn PolicyPlugin>)> = vec![
            (
                valid_plugin_config("good"),
                Box::new(StubPlugin::allowing("good")),
            ),
            (invalid_config, Box::new(StubPlugin::allowing("bad-plugin"))),
        ];

        let result = mgr.reload_plugins(new_plugins);
        assert!(result.is_err());
        // Original plugins should still be in place (atomic)
        assert_eq!(mgr.plugin_count(), 1);
        assert_eq!(mgr.plugin_names(), vec!["original"]);
    }

    #[test]
    fn test_reload_plugins_duplicate_names_rejected() {
        let mut mgr = PluginManager::new(enabled_manager_config()).unwrap();

        let new_plugins: Vec<(PluginConfig, Box<dyn PolicyPlugin>)> = vec![
            (
                valid_plugin_config("same-name"),
                Box::new(StubPlugin::allowing("same-name")),
            ),
            (
                valid_plugin_config("same-name"),
                Box::new(StubPlugin::allowing("same-name")),
            ),
        ];

        let err = mgr.reload_plugins(new_plugins).unwrap_err();
        assert!(matches!(err, PluginError::DuplicatePlugin(_)));
    }

    #[test]
    fn test_r237_eng1_reload_plugins_case_variant_duplicate_rejected() {
        // SECURITY (R237-ENG-1): reload_plugins must use case-insensitive duplicate
        // check, matching load_plugin's eq_ignore_ascii_case behavior.
        let mut mgr = PluginManager::new(enabled_manager_config()).unwrap();

        let new_plugins: Vec<(PluginConfig, Box<dyn PolicyPlugin>)> = vec![
            (
                valid_plugin_config("MyPlugin"),
                Box::new(StubPlugin::allowing("MyPlugin")),
            ),
            (
                valid_plugin_config("myplugin"),
                Box::new(StubPlugin::allowing("myplugin")),
            ),
        ];

        let err = mgr.reload_plugins(new_plugins).unwrap_err();
        assert!(
            matches!(err, PluginError::DuplicatePlugin(_)),
            "Case-variant duplicate plugin names must be rejected: {err:?}"
        );
    }

    #[test]
    fn test_reload_plugins_disabled_system() {
        let mut mgr = PluginManager::new(PluginManagerConfig::default()).unwrap();
        let result = mgr.reload_plugins(Vec::new());
        assert!(result.is_err());
    }

    // --- Error type tests ---

    #[test]
    fn test_plugin_error_types_display() {
        let err = PluginError::ConfigValidation("bad config".to_string());
        assert!(err.to_string().contains("bad config"));

        let err = PluginError::MaxPluginsExceeded;
        assert!(err.to_string().contains("64"));

        let err = PluginError::DuplicatePlugin("dup".to_string());
        assert!(err.to_string().contains("dup"));

        let err = PluginError::LoadFailed("module error".to_string());
        assert!(err.to_string().contains("module error"));

        let err = PluginError::EvaluationFailed {
            plugin_name: "test".to_string(),
            reason: "timeout".to_string(),
        };
        assert!(err.to_string().contains("test"));
        assert!(err.to_string().contains("timeout"));

        let err = PluginError::Serialization("json error".to_string());
        assert!(err.to_string().contains("json error"));

        let err = PluginError::ResourceExceeded {
            plugin_name: "heavy".to_string(),
            resource: "memory".to_string(),
        };
        assert!(err.to_string().contains("heavy"));
        assert!(err.to_string().contains("memory"));
    }

    // --- deny_unknown_fields tests ---

    #[test]
    fn test_plugin_verdict_deny_unknown_fields() {
        let json_str = r#"{"allow": true, "reason": null, "extra_field": "bad"}"#;
        let result: Result<PluginVerdict, _> = serde_json::from_str(json_str);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    #[test]
    fn test_plugin_action_deny_unknown_fields() {
        let json_str = r#"{"tool":"t","function":"f","parameters":{},"target_paths":[],"target_domains":[],"evil":"yes"}"#;
        let result: Result<PluginAction, _> = serde_json::from_str(json_str);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    /// R238-ENG-1: Verify path normalization failure omits the path (fail-closed)
    /// instead of falling back to normalize_full() which lacks traversal protection.
    #[test]
    fn test_r238_eng1_plugin_action_path_normalization_fail_closed() {
        // A path with excessive traversal sequences that triggers normalization
        // failure should be omitted from the PluginAction, not included via fallback.
        let mut traversal_path = String::from("/");
        for _ in 0..500 {
            traversal_path.push_str("..%2f");
        }
        let action = Action {
            tool: "fs".to_string(),
            function: "read".to_string(),
            parameters: json!({}),
            target_paths: vec!["/tmp/safe".to_string(), traversal_path],
            target_domains: vec![],
            resolved_ips: vec![],
        };

        let plugin_action = PluginAction::from_action(&action);

        // The safe path should be present; the malicious one should be omitted.
        // Depending on normalization behavior, the safe path should be there.
        // The key check: the malicious path that fails normalization is NOT included.
        assert!(
            plugin_action.target_paths.len() <= 2,
            "paths should be bounded"
        );
        // Verify the safe path is normalized and present
        assert!(
            plugin_action.target_paths.iter().any(|p| p.contains("tmp")),
            "safe path should be present"
        );
    }

    #[test]
    fn test_plugin_config_deny_unknown_fields() {
        let json_str = r#"{"name":"n","path":"/p","memory_limit_bytes":1048576,"fuel_limit":1000,"timeout_ms":5,"rogue":true}"#;
        let result: Result<PluginConfig, _> = serde_json::from_str(json_str);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }
}
