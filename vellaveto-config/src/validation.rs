// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Policy Configuration Validation
//!
//! Provides comprehensive validation for policy configurations including:
//! - Syntax validation (TOML parsing)
//! - Schema validation (required fields, valid types)
//! - Semantic validation (no conflicts, valid references)
//! - Best practice recommendations

use crate::{PolicyConfig, PolicyRule, PolicyType};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Severity level for validation findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSeverity {
    /// Informational - best practice recommendations
    Info,
    /// Warning - potential issues that may cause unexpected behavior
    Warning,
    /// Error - configuration is invalid and will fail at runtime
    Error,
}

/// Category of validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCategory {
    /// Syntax errors (TOML parsing)
    Syntax,
    /// Schema errors (required fields, types)
    Schema,
    /// Semantic errors (conflicts, references)
    Semantic,
    /// Security issues
    Security,
    /// Best practices
    BestPractice,
}

/// A single validation finding.
// SECURITY (R256-CFG-1): Reject unknown fields from deserialized input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationFinding {
    /// Severity of the finding.
    pub severity: ValidationSeverity,
    /// Category of the finding.
    pub category: ValidationCategory,
    /// Error code for programmatic handling.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Location in the config (policy name or path).
    pub location: Option<String>,
    /// Suggested fix.
    pub suggestion: Option<String>,
}

impl ValidationFinding {
    /// Create a new error finding.
    pub fn error(code: &str, message: &str) -> Self {
        ValidationFinding {
            severity: ValidationSeverity::Error,
            category: ValidationCategory::Schema,
            code: code.to_string(),
            message: message.to_string(),
            location: None,
            suggestion: None,
        }
    }

    /// Create a new warning finding.
    pub fn warning(code: &str, message: &str) -> Self {
        ValidationFinding {
            severity: ValidationSeverity::Warning,
            category: ValidationCategory::Semantic,
            code: code.to_string(),
            message: message.to_string(),
            location: None,
            suggestion: None,
        }
    }

    /// Create a new info finding.
    pub fn info(code: &str, message: &str) -> Self {
        ValidationFinding {
            severity: ValidationSeverity::Info,
            category: ValidationCategory::BestPractice,
            code: code.to_string(),
            message: message.to_string(),
            location: None,
            suggestion: None,
        }
    }

    /// Set the location.
    pub fn at(mut self, location: &str) -> Self {
        self.location = Some(location.to_string());
        self
    }

    /// Set the category.
    pub fn with_category(mut self, category: ValidationCategory) -> Self {
        self.category = category;
        self
    }

    /// Set the suggestion.
    pub fn with_suggestion(mut self, suggestion: &str) -> Self {
        self.suggestion = Some(suggestion.to_string());
        self
    }
}

/// Result of policy configuration validation.
// SECURITY (R256-CFG-1): Reject unknown fields from deserialized input.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationResult {
    /// All findings from validation.
    pub findings: Vec<ValidationFinding>,
    /// Summary statistics.
    pub summary: ValidationSummary,
}

/// Summary of validation results.
// SECURITY (R256-CFG-1): Reject unknown fields from deserialized input.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationSummary {
    /// Total number of policies.
    pub total_policies: usize,
    /// Number of error findings.
    pub errors: usize,
    /// Number of warning findings.
    pub warnings: usize,
    /// Number of info findings.
    pub infos: usize,
    /// Whether the configuration is valid (no errors).
    pub valid: bool,
}

impl ValidationResult {
    /// Create a new empty validation result.
    pub fn new() -> Self {
        ValidationResult::default()
    }

    /// Add a finding.
    pub fn add(&mut self, finding: ValidationFinding) {
        match finding.severity {
            ValidationSeverity::Error => self.summary.errors += 1,
            ValidationSeverity::Warning => self.summary.warnings += 1,
            ValidationSeverity::Info => self.summary.infos += 1,
        }
        self.findings.push(finding);
    }

    /// Check if there are any errors.
    pub fn has_errors(&self) -> bool {
        self.summary.errors > 0
    }

    /// Check if there are any warnings.
    pub fn has_warnings(&self) -> bool {
        self.summary.warnings > 0
    }

    /// Finalize the result.
    pub fn finalize(mut self) -> Self {
        self.summary.valid = self.summary.errors == 0;
        self.findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        self
    }

    /// Get findings by severity.
    pub fn by_severity(&self, severity: ValidationSeverity) -> Vec<&ValidationFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .collect()
    }

    /// Format as human-readable text.
    pub fn to_text(&self) -> String {
        let mut output = String::new();

        for finding in &self.findings {
            let severity = match finding.severity {
                ValidationSeverity::Error => "ERROR",
                ValidationSeverity::Warning => "WARNING",
                ValidationSeverity::Info => "INFO",
            };

            let location = finding
                .location
                .as_ref()
                .map(|l| format!(" at {l}"))
                .unwrap_or_default();

            output.push_str(&format!(
                "[{}] {}{}: {}\n",
                severity, finding.code, location, finding.message
            ));

            if let Some(ref suggestion) = finding.suggestion {
                output.push_str(&format!("  Suggestion: {suggestion}\n"));
            }
        }

        output.push_str(&format!(
            "\nSummary: {} errors, {} warnings, {} info\n",
            self.summary.errors, self.summary.warnings, self.summary.infos
        ));

        if self.summary.valid {
            output.push_str("Configuration is VALID\n");
        } else {
            output.push_str("Configuration is INVALID\n");
        }

        output
    }
}

/// Policy configuration validator.
pub struct PolicyValidator {
    /// Check for security issues.
    check_security: bool,
    /// Check for best practices.
    check_best_practices: bool,
    /// Strict mode (treat warnings as errors).
    strict: bool,
}

impl Default for PolicyValidator {
    fn default() -> Self {
        PolicyValidator {
            check_security: true,
            check_best_practices: true,
            strict: false,
        }
    }
}

impl PolicyValidator {
    /// Create a new validator.
    pub fn new() -> Self {
        PolicyValidator::default()
    }

    /// Enable/disable security checks.
    pub fn with_security_checks(mut self, enabled: bool) -> Self {
        self.check_security = enabled;
        self
    }

    /// Enable/disable best practice checks.
    pub fn with_best_practices(mut self, enabled: bool) -> Self {
        self.check_best_practices = enabled;
        self
    }

    /// Enable strict mode.
    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Validate a policy configuration.
    pub fn validate(&self, config: &PolicyConfig) -> ValidationResult {
        let mut result = ValidationResult::new();
        let policies = &config.policies;

        result.summary.total_policies = policies.len();

        // Check for empty configuration
        if policies.is_empty() {
            result.add(
                ValidationFinding::warning("EMPTY_CONFIG", "No policies defined")
                    .with_suggestion("Add at least one policy rule"),
            );
        }

        // Validate each policy
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut seen_priorities: HashMap<i32, Vec<String>> = HashMap::new();

        for (idx, policy) in policies.iter().enumerate() {
            let location = if policy.name.is_empty() {
                format!("policies[{idx}]")
            } else {
                policy.name.clone()
            };

            // Check for duplicate IDs
            if let Some(ref id) = policy.id {
                if seen_ids.contains(id) {
                    result.add(
                        ValidationFinding::error(
                            "DUPLICATE_ID",
                            &format!("Duplicate policy ID: {id}"),
                        )
                        .at(&location),
                    );
                }
                seen_ids.insert(id.clone());
            }

            // Track priorities for conflict detection
            let priority = policy.effective_priority();
            seen_priorities
                .entry(priority)
                .or_default()
                .push(location.clone());

            // Validate policy fields
            self.validate_policy(policy, &location, &mut result);
        }

        // Check for priority conflicts
        for (priority, names) in seen_priorities {
            if names.len() > 1 {
                result.add(
                    ValidationFinding::warning(
                        "PRIORITY_CONFLICT",
                        &format!(
                            "Multiple policies with priority {}: {}",
                            priority,
                            names.join(", ")
                        ),
                    )
                    .with_suggestion(
                        "Consider using different priorities to ensure deterministic evaluation",
                    ),
                );
            }
        }

        // Security checks
        if self.check_security {
            self.check_security_issues(config, &mut result);
        }

        // Best practice checks
        if self.check_best_practices {
            self.check_best_practices_fn(config, &mut result);
        }

        // Convert warnings to errors in strict mode
        if self.strict {
            for finding in &mut result.findings {
                if finding.severity == ValidationSeverity::Warning {
                    finding.severity = ValidationSeverity::Error;
                    result.summary.errors += 1;
                    result.summary.warnings -= 1;
                }
            }
        }

        result.finalize()
    }

    /// Validate a single policy.
    fn validate_policy(&self, policy: &PolicyRule, location: &str, result: &mut ValidationResult) {
        // Check tool pattern
        if policy.tool_pattern.is_empty() {
            result
                .add(ValidationFinding::error("EMPTY_PATTERN", "Empty tool pattern").at(location));
        }

        if policy.tool_pattern == "*" && policy.policy_type == PolicyType::Allow {
            result.add(
                ValidationFinding::warning(
                    "WILDCARD_ALLOW",
                    "Policy allows all tools with wildcard",
                )
                .at(location)
                .with_category(ValidationCategory::Security)
                .with_suggestion("Consider using more specific tool patterns"),
            );
        }

        // Check function pattern
        if policy.function_pattern.is_empty() {
            result.add(
                ValidationFinding::error("EMPTY_PATTERN", "Empty function pattern").at(location),
            );
        }

        // Check path rules
        if let Some(ref path_rules) = policy.path_rules {
            if path_rules.allowed.is_empty() && path_rules.blocked.is_empty() {
                result.add(
                    ValidationFinding::warning(
                        "EMPTY_PATH_RULES",
                        "Path rules defined but no patterns specified",
                    )
                    .at(location),
                );
            }

            // Check for overlapping patterns
            for allow_pattern in &path_rules.allowed {
                for block_pattern in &path_rules.blocked {
                    if patterns_overlap(allow_pattern, block_pattern) {
                        result.add(
                            ValidationFinding::warning(
                                "OVERLAPPING_PATHS",
                                &format!(
                                    "Allowed pattern '{allow_pattern}' may overlap with blocked pattern '{block_pattern}'"
                                ),
                            )
                            .at(location),
                        );
                    }
                }
            }
        }

        // Check network rules
        if let Some(ref network_rules) = policy.network_rules {
            if network_rules.allowed_domains.is_empty() && network_rules.blocked_domains.is_empty()
            {
                result.add(
                    ValidationFinding::warning(
                        "EMPTY_NETWORK_RULES",
                        "Network rules defined but no domains specified",
                    )
                    .at(location),
                );
            }

            // Check for invalid domain patterns
            for domain in &network_rules.allowed_domains {
                if !is_valid_domain_pattern(domain) {
                    result.add(
                        ValidationFinding::error(
                            "INVALID_DOMAIN",
                            &format!("Invalid domain pattern: {domain}"),
                        )
                        .at(location),
                    );
                }
            }

            for domain in &network_rules.blocked_domains {
                if !is_valid_domain_pattern(domain) {
                    result.add(
                        ValidationFinding::error(
                            "INVALID_DOMAIN",
                            &format!("Invalid domain pattern: {domain}"),
                        )
                        .at(location),
                    );
                }
            }
        }
    }

    /// Check for security issues.
    fn check_security_issues(&self, config: &PolicyConfig, result: &mut ValidationResult) {
        let policies = &config.policies;

        // Check for overly permissive policies
        let has_deny_all = policies
            .iter()
            .any(|p| p.policy_type == PolicyType::Deny && p.tool_pattern == "*");

        if !has_deny_all {
            result.add(
                ValidationFinding::info("NO_DENY_ALL", "No default deny-all policy found")
                    .with_category(ValidationCategory::Security)
                    .with_suggestion(
                        "Consider adding a low-priority deny-all policy as a safety net",
                    ),
            );
        }

        // Check for sensitive path exposure
        for policy in policies {
            if policy.policy_type == PolicyType::Allow {
                if let Some(ref path_rules) = policy.path_rules {
                    for pattern in &path_rules.allowed {
                        if is_sensitive_path(pattern) {
                            result.add(
                                ValidationFinding::warning(
                                    "SENSITIVE_PATH",
                                    &format!("Policy allows access to sensitive path: {pattern}"),
                                )
                                .at(&policy.name)
                                .with_category(ValidationCategory::Security),
                            );
                        }
                    }
                }
            }
        }

        // Check rate limiting
        let has_rate_limits = config.rate_limit.evaluate_rps.is_some()
            || config.rate_limit.admin_rps.is_some()
            || config.rate_limit.per_ip_rps.is_some();

        if !has_rate_limits {
            result.add(
                ValidationFinding::warning("NO_RATE_LIMITS", "No rate limits configured")
                    .with_category(ValidationCategory::Security)
                    .with_suggestion("Consider enabling rate limiting to prevent abuse"),
            );
        }
    }

    /// Check for best practices.
    fn check_best_practices_fn(&self, config: &PolicyConfig, result: &mut ValidationResult) {
        let policies = &config.policies;

        // Check for missing policy names
        for (idx, policy) in policies.iter().enumerate() {
            if policy.name.is_empty() {
                result.add(
                    ValidationFinding::info(
                        "MISSING_NAME",
                        &format!("Policy at index {idx} has no name"),
                    )
                    .with_suggestion("Add descriptive names to policies for easier debugging"),
                );
            }
        }

        // Check for missing policy IDs
        for (idx, policy) in policies.iter().enumerate() {
            if policy.id.is_none() {
                let location = if policy.name.is_empty() {
                    format!("policies[{idx}]")
                } else {
                    policy.name.clone()
                };
                result.add(
                    ValidationFinding::info("MISSING_ID", "Policy has no ID")
                        .at(&location)
                        .with_suggestion("Add unique IDs for policy management"),
                );
            }
        }

        // Check for injection scanning
        if !config.injection.enabled {
            result.add(
                ValidationFinding::info("INJECTION_DISABLED", "Injection scanning is disabled")
                    .with_suggestion("Consider enabling injection scanning for better security"),
            );
        }
    }
}

/// Check if two glob patterns might overlap.
fn patterns_overlap(pattern1: &str, pattern2: &str) -> bool {
    // Simple overlap detection - check if one is a prefix/suffix of the other
    if pattern1.starts_with(pattern2.trim_end_matches('*'))
        || pattern2.starts_with(pattern1.trim_end_matches('*'))
    {
        return true;
    }

    // Check for common directory prefixes
    let parts1: Vec<&str> = pattern1.split('/').collect();
    let parts2: Vec<&str> = pattern2.split('/').collect();

    let common_len = parts1.len().min(parts2.len());
    for i in 0..common_len {
        if parts1[i] != parts2[i]
            && parts1[i] != "*"
            && parts1[i] != "**"
            && parts2[i] != "*"
            && parts2[i] != "**"
        {
            return false;
        }
    }

    true
}

/// Check if a domain pattern is valid.
fn is_valid_domain_pattern(pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }

    // Allow wildcards
    if pattern == "*" {
        return true;
    }

    // Allow wildcard prefix
    let check_pattern = pattern.strip_prefix("*.").unwrap_or(pattern);

    // Basic domain validation
    if check_pattern.is_empty() {
        return false;
    }

    // Check for valid characters
    check_pattern
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// Check if a path pattern points to sensitive locations.
fn is_sensitive_path(pattern: &str) -> bool {
    let sensitive_patterns = [
        "~/.ssh",
        "~/.aws",
        "~/.gnupg",
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "**/.env",
        "**/credentials",
        "**/secrets",
        "**/private",
        "**/*.pem",
        "**/*.key",
        "**/id_rsa",
        "**/id_ed25519",
    ];

    for sensitive in sensitive_patterns {
        if pattern.contains(sensitive) || glob_matches(sensitive, pattern) {
            return true;
        }
    }

    false
}

/// Simple glob matching for pattern comparison.
fn glob_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" || pattern == "**" {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("**/") {
        return path.contains(suffix);
    }

    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path.starts_with(prefix);
    }

    pattern == path
}

// ═══════════════════════════════════════════════════════════════════════════
// Configuration Value Validators (P1 item 2.3)
// ═══════════════════════════════════════════════════════════════════════════

/// Error type for configuration validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigValueError {
    /// Invalid hex encoding.
    InvalidHex(String),
    /// Invalid key length or format.
    InvalidKey(String),
    /// Invalid URL format or scheme.
    InvalidUrl(String),
    /// Invalid domain name format.
    InvalidDomain(String),
}

impl std::fmt::Display for ConfigValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigValueError::InvalidHex(msg) => write!(f, "Invalid hex encoding: {msg}"),
            ConfigValueError::InvalidKey(msg) => write!(f, "Invalid key: {msg}"),
            ConfigValueError::InvalidUrl(msg) => write!(f, "Invalid URL: {msg}"),
            ConfigValueError::InvalidDomain(msg) => write!(f, "Invalid domain: {msg}"),
        }
    }
}

impl std::error::Error for ConfigValueError {}

/// Validate an Ed25519 public key (hex-encoded, 32 bytes).
///
/// Ed25519 public keys are 32 bytes (256 bits). When hex-encoded, they are
/// 64 characters. This validator ensures the key is valid hex and the correct length.
///
/// # Example
/// ```
/// use vellaveto_config::validation::validate_ed25519_pubkey;
///
/// // Valid 32-byte key (64 hex chars)
/// let valid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// assert!(validate_ed25519_pubkey(valid).is_ok());
///
/// // Invalid: too short
/// assert!(validate_ed25519_pubkey("0123456789abcdef").is_err());
///
/// // Invalid: not hex
/// assert!(validate_ed25519_pubkey("not-valid-hex-string").is_err());
/// ```
pub fn validate_ed25519_pubkey(key: &str) -> Result<(), ConfigValueError> {
    let bytes = hex::decode(key).map_err(|e| ConfigValueError::InvalidHex(e.to_string()))?;

    if bytes.len() != 32 {
        return Err(ConfigValueError::InvalidKey(format!(
            "Ed25519 public key must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        )));
    }

    // Check for all-zeros key which is cryptographically invalid
    if bytes.iter().all(|&b| b == 0) {
        return Err(ConfigValueError::InvalidKey(
            "Ed25519 public key cannot be all zeros".to_string(),
        ));
    }

    Ok(())
}

/// Validate a Redis URL format.
///
/// Validates that the URL:
/// - Starts with `redis://` or `rediss://` (TLS)
/// - Is parseable as a valid URL
///
/// # Example
/// ```
/// use vellaveto_config::validation::validate_redis_url;
///
/// // Valid URLs
/// assert!(validate_redis_url("redis://localhost:6379").is_ok());
/// assert!(validate_redis_url("rediss://user:pass@redis.example.com:6380/0").is_ok());
///
/// // Invalid: wrong scheme
/// assert!(validate_redis_url("http://localhost:6379").is_err());
///
/// // Invalid: malformed
/// assert!(validate_redis_url("not a url").is_err());
/// ```
pub fn validate_redis_url(url_str: &str) -> Result<(), ConfigValueError> {
    // Check scheme
    if !url_str.starts_with("redis://") && !url_str.starts_with("rediss://") {
        return Err(ConfigValueError::InvalidUrl(
            "Redis URL must start with redis:// or rediss://".to_string(),
        ));
    }

    // Parse URL
    url::Url::parse(url_str).map_err(|e| ConfigValueError::InvalidUrl(e.to_string()))?;

    Ok(())
}

/// Validate a domain name per RFC 1035.
///
/// Domain names must:
/// - Be non-empty and at most 253 characters
/// - Contain only alphanumeric characters, hyphens, and dots
/// - Not start or end with a hyphen in any label
/// - Have labels between 1 and 63 characters
///
/// # Example
/// ```
/// use vellaveto_config::validation::validate_domain_name;
///
/// // Valid domains
/// assert!(validate_domain_name("example.com").is_ok());
/// assert!(validate_domain_name("sub.example.co.uk").is_ok());
/// assert!(validate_domain_name("my-service.internal").is_ok());
///
/// // Invalid: starts with hyphen
/// assert!(validate_domain_name("-invalid.com").is_err());
///
/// // Invalid: label too long (>63 chars)
/// let long_label = "a".repeat(64);
/// assert!(validate_domain_name(&format!("{}.com", long_label)).is_err());
/// ```
pub fn validate_domain_name(domain: &str) -> Result<(), ConfigValueError> {
    // Check overall length
    if domain.is_empty() {
        return Err(ConfigValueError::InvalidDomain(
            "Domain name cannot be empty".to_string(),
        ));
    }

    if domain.len() > 253 {
        return Err(ConfigValueError::InvalidDomain(format!(
            "Domain name exceeds 253 characters: {} chars",
            domain.len()
        )));
    }

    // Validate each label
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(ConfigValueError::InvalidDomain(
                "Domain contains empty label (consecutive dots)".to_string(),
            ));
        }

        if label.len() > 63 {
            return Err(ConfigValueError::InvalidDomain(format!(
                "Domain label '{label}' exceeds 63 characters"
            )));
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err(ConfigValueError::InvalidDomain(format!(
                "Domain label '{label}' cannot start or end with hyphen"
            )));
        }

        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ConfigValueError::InvalidDomain(format!(
                "Domain label '{label}' contains invalid characters (only alphanumeric and hyphen allowed)"
            )));
        }
    }

    Ok(())
}

/// Check whether a URL points to localhost or a loopback address.
///
/// SECURITY (BUG-R110-004/005/006): `starts_with("http://localhost")` is SSRF-vulnerable
/// because it matches `http://localhost.evil.com`. This function parses the URL properly
/// and checks the host component. Covers the full `127.0.0.0/8` loopback range,
/// IPv6 loopback (`::1`), and `localhost`.
///
/// # Example
/// ```
/// use vellaveto_config::validation::is_localhost_url;
///
/// assert!(is_localhost_url("http://localhost:8080/path"));
/// assert!(is_localhost_url("http://127.0.0.1:3000"));
/// assert!(is_localhost_url("http://127.0.0.2:3000"));
/// assert!(is_localhost_url("http://[::1]:8080"));
/// assert!(!is_localhost_url("http://localhost.evil.com"));
/// assert!(!is_localhost_url("http://not-localhost"));
/// ```
pub fn is_localhost_url(url_str: &str) -> bool {
    match url::Url::parse(url_str) {
        Ok(parsed) => match parsed.host_str() {
            Some(host) => {
                if host == "localhost" {
                    return true;
                }
                // SECURITY (FIND-R114-001): Check entire 127.0.0.0/8 loopback range,
                // not just 127.0.0.1. All addresses in this range route to loopback.
                if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                    return ip.is_loopback();
                }
                // IPv6 loopback: ::1 (may appear as "::1" or "[::1]")
                let ipv6_host = host.trim_start_matches('[').trim_end_matches(']');
                if let Ok(ip6) = ipv6_host.parse::<std::net::Ipv6Addr>() {
                    return ip6.is_loopback();
                }
                false
            }
            None => false,
        },
        Err(_) => false,
    }
}

/// Check that a URL uses `http://` or `https://` scheme AND points to localhost.
///
/// SECURITY (FIND-R114-005): `is_localhost_url()` is scheme-agnostic — it returns
/// `true` for `ftp://localhost` which callers intend to allow only for HTTP/HTTPS.
/// Use this function when the goal is "allow HTTP for localhost, require HTTPS for
/// non-localhost".
pub fn is_http_localhost_url(url_str: &str) -> bool {
    match url::Url::parse(url_str) {
        Ok(parsed) => {
            let scheme = parsed.scheme();
            if scheme != "http" && scheme != "https" {
                return false;
            }
            is_localhost_url(url_str)
        }
        Err(_) => false,
    }
}

/// Validate a webhook URL (HTTP/HTTPS).
///
/// # Example
/// ```
/// use vellaveto_config::validation::validate_webhook_url;
///
/// // Valid
/// assert!(validate_webhook_url("https://hooks.example.com/webhook").is_ok());
///
/// // Invalid scheme
/// assert!(validate_webhook_url("ftp://example.com").is_err());
/// ```
pub fn validate_webhook_url(url_str: &str) -> Result<(), ConfigValueError> {
    let parsed =
        url::Url::parse(url_str).map_err(|e| ConfigValueError::InvalidUrl(e.to_string()))?;

    match parsed.scheme() {
        "http" | "https" => Ok(()),
        scheme => Err(ConfigValueError::InvalidUrl(format!(
            "Webhook URL must use http or https scheme, got '{scheme}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_finding_creation() {
        let finding = ValidationFinding::error("TEST_ERROR", "Test error message")
            .at("test_location")
            .with_suggestion("Fix it");

        assert_eq!(finding.severity, ValidationSeverity::Error);
        assert_eq!(finding.code, "TEST_ERROR");
        assert_eq!(finding.location, Some("test_location".to_string()));
        assert_eq!(finding.suggestion, Some("Fix it".to_string()));
    }

    #[test]
    fn test_validation_result_add() {
        let mut result = ValidationResult::new();
        result.add(ValidationFinding::error("E1", "Error 1"));
        result.add(ValidationFinding::warning("W1", "Warning 1"));
        result.add(ValidationFinding::info("I1", "Info 1"));

        assert_eq!(result.summary.errors, 1);
        assert_eq!(result.summary.warnings, 1);
        assert_eq!(result.summary.infos, 1);
    }

    #[test]
    fn test_validation_result_has_errors() {
        let mut result = ValidationResult::new();
        assert!(!result.has_errors());

        result.add(ValidationFinding::error("E1", "Error 1"));
        assert!(result.has_errors());
    }

    #[test]
    fn test_patterns_overlap() {
        assert!(patterns_overlap("/home/*", "/home/user"));
        assert!(patterns_overlap("/var/log/**", "/var/log/app.log"));
        assert!(!patterns_overlap("/home/*", "/etc/*"));
    }

    #[test]
    fn test_is_valid_domain_pattern() {
        assert!(is_valid_domain_pattern("example.com"));
        assert!(is_valid_domain_pattern("*.example.com"));
        assert!(is_valid_domain_pattern("sub.example.com"));
        assert!(is_valid_domain_pattern("*"));
        assert!(!is_valid_domain_pattern(""));
        assert!(!is_valid_domain_pattern("*."));
    }

    #[test]
    fn test_is_sensitive_path() {
        assert!(is_sensitive_path("~/.ssh/id_rsa"));
        assert!(is_sensitive_path("~/.aws/credentials"));
        assert!(is_sensitive_path("/etc/shadow"));
        assert!(is_sensitive_path("**/.env"));
        assert!(!is_sensitive_path("/home/user/documents"));
    }

    fn empty_config() -> PolicyConfig {
        PolicyConfig::from_toml("policies = []").unwrap()
    }

    fn minimal_config() -> PolicyConfig {
        PolicyConfig::from_toml(
            r#"
[[policies]]
name = "test"
tool_pattern = "test"
function_pattern = "*"
policy_type = "Allow"
"#,
        )
        .unwrap()
    }

    #[test]
    fn test_validator_empty_config() {
        let config = empty_config();
        let validator = PolicyValidator::new();
        let result = validator.validate(&config);

        assert!(result.has_warnings());
        assert!(result.findings.iter().any(|f| f.code == "EMPTY_CONFIG"));
    }

    #[test]
    fn test_validator_strict_mode() {
        let config = minimal_config();

        let validator = PolicyValidator::new().strict();
        let result = validator.validate(&config);

        // In strict mode, warnings become errors
        assert!(result.summary.warnings == 0);
    }

    #[test]
    fn test_validation_result_to_text() {
        let mut result = ValidationResult::new();
        result.add(ValidationFinding::error("E1", "Error 1").at("policy1"));
        result.add(ValidationFinding::warning("W1", "Warning 1").with_suggestion("Fix it"));

        let result = result.finalize();
        let text = result.to_text();

        assert!(text.contains("[ERROR]"));
        assert!(text.contains("[WARNING]"));
        assert!(text.contains("Suggestion: Fix it"));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Configuration Value Validator Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_ed25519_pubkey_valid() {
        // Valid 32-byte key (64 hex chars)
        let valid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(validate_ed25519_pubkey(valid).is_ok());

        // Another valid key with uppercase
        let valid_upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert!(validate_ed25519_pubkey(valid_upper).is_ok());
    }

    #[test]
    fn test_validate_ed25519_pubkey_invalid_length() {
        // Too short
        let short = "0123456789abcdef";
        let result = validate_ed25519_pubkey(short);
        assert!(matches!(result, Err(ConfigValueError::InvalidKey(_))));

        // Too long
        let long = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00";
        let result = validate_ed25519_pubkey(long);
        assert!(matches!(result, Err(ConfigValueError::InvalidKey(_))));
    }

    #[test]
    fn test_validate_ed25519_pubkey_invalid_hex() {
        // Contains non-hex characters
        let invalid = "xyz3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let result = validate_ed25519_pubkey(invalid);
        assert!(matches!(result, Err(ConfigValueError::InvalidHex(_))));
    }

    #[test]
    fn test_validate_ed25519_pubkey_all_zeros_rejected() {
        // All zeros is cryptographically invalid
        let zeros = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = validate_ed25519_pubkey(zeros);
        assert!(matches!(result, Err(ConfigValueError::InvalidKey(_))));
    }

    #[test]
    fn test_validate_redis_url_valid() {
        // Standard Redis URL
        assert!(validate_redis_url("redis://localhost:6379").is_ok());

        // With auth
        assert!(validate_redis_url("redis://user:password@localhost:6379").is_ok());

        // TLS Redis
        assert!(validate_redis_url("rediss://redis.example.com:6380").is_ok());

        // With database
        assert!(validate_redis_url("redis://localhost:6379/0").is_ok());
    }

    #[test]
    fn test_validate_redis_url_wrong_scheme() {
        // HTTP is not valid for Redis
        let result = validate_redis_url("http://localhost:6379");
        assert!(matches!(result, Err(ConfigValueError::InvalidUrl(_))));

        // HTTPS is not valid for Redis
        let result = validate_redis_url("https://localhost:6379");
        assert!(matches!(result, Err(ConfigValueError::InvalidUrl(_))));
    }

    #[test]
    fn test_validate_redis_url_malformed() {
        // Not a URL at all
        let result = validate_redis_url("not a url");
        assert!(matches!(result, Err(ConfigValueError::InvalidUrl(_))));
    }

    #[test]
    fn test_validate_domain_name_valid() {
        assert!(validate_domain_name("example.com").is_ok());
        assert!(validate_domain_name("sub.example.com").is_ok());
        assert!(validate_domain_name("my-service.internal").is_ok());
        assert!(validate_domain_name("a.b.c.d.e.com").is_ok());
        assert!(validate_domain_name("localhost").is_ok());
    }

    #[test]
    fn test_validate_domain_name_empty() {
        let result = validate_domain_name("");
        assert!(matches!(result, Err(ConfigValueError::InvalidDomain(_))));
    }

    #[test]
    fn test_validate_domain_name_too_long() {
        // Total length > 253
        let long_domain = format!("{}.com", "a".repeat(250));
        let result = validate_domain_name(&long_domain);
        assert!(matches!(result, Err(ConfigValueError::InvalidDomain(_))));
    }

    #[test]
    fn test_validate_domain_name_label_too_long() {
        // Label > 63 chars
        let long_label = format!("{}.com", "a".repeat(64));
        let result = validate_domain_name(&long_label);
        assert!(matches!(result, Err(ConfigValueError::InvalidDomain(_))));
    }

    #[test]
    fn test_validate_domain_name_hyphen_rules() {
        // Starts with hyphen
        let result = validate_domain_name("-invalid.com");
        assert!(matches!(result, Err(ConfigValueError::InvalidDomain(_))));

        // Ends with hyphen
        let result = validate_domain_name("invalid-.com");
        assert!(matches!(result, Err(ConfigValueError::InvalidDomain(_))));

        // Hyphen in middle is OK
        assert!(validate_domain_name("valid-name.com").is_ok());
    }

    #[test]
    fn test_validate_domain_name_invalid_chars() {
        // Underscore not allowed
        let result = validate_domain_name("invalid_name.com");
        assert!(matches!(result, Err(ConfigValueError::InvalidDomain(_))));

        // Space not allowed
        let result = validate_domain_name("invalid name.com");
        assert!(matches!(result, Err(ConfigValueError::InvalidDomain(_))));
    }

    #[test]
    fn test_validate_domain_name_consecutive_dots() {
        let result = validate_domain_name("invalid..com");
        assert!(matches!(result, Err(ConfigValueError::InvalidDomain(_))));
    }

    #[test]
    fn test_validate_webhook_url_valid() {
        assert!(validate_webhook_url("https://hooks.example.com/webhook").is_ok());
        assert!(validate_webhook_url("http://localhost:8080/hook").is_ok());
    }

    #[test]
    fn test_validate_webhook_url_invalid_scheme() {
        let result = validate_webhook_url("ftp://example.com/file");
        assert!(matches!(result, Err(ConfigValueError::InvalidUrl(_))));

        let result = validate_webhook_url("redis://localhost:6379");
        assert!(matches!(result, Err(ConfigValueError::InvalidUrl(_))));
    }

    #[test]
    fn test_config_value_error_display() {
        let err = ConfigValueError::InvalidKey("test".to_string());
        assert!(err.to_string().contains("Invalid key"));

        let err = ConfigValueError::InvalidUrl("test".to_string());
        assert!(err.to_string().contains("Invalid URL"));

        let err = ConfigValueError::InvalidDomain("test".to_string());
        assert!(err.to_string().contains("Invalid domain"));

        let err = ConfigValueError::InvalidHex("test".to_string());
        assert!(err.to_string().contains("Invalid hex"));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SSRF localhost validation tests (BUG-R110-004/005/006)
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_is_localhost_url_valid_localhost() {
        assert!(is_localhost_url("http://localhost"));
        assert!(is_localhost_url("http://localhost:8080"));
        assert!(is_localhost_url("http://localhost:8080/path"));
        assert!(is_localhost_url("http://localhost/path?query=1"));
    }

    #[test]
    fn test_is_localhost_url_valid_loopback() {
        assert!(is_localhost_url("http://127.0.0.1"));
        assert!(is_localhost_url("http://127.0.0.1:3000"));
        assert!(is_localhost_url("http://[::1]:8080"));
        assert!(is_localhost_url("https://localhost:443"));
    }

    /// SECURITY (FIND-R114-001): Full 127.0.0.0/8 loopback range.
    #[test]
    fn test_is_localhost_url_full_loopback_range() {
        assert!(is_localhost_url("http://127.0.0.2"));
        assert!(is_localhost_url("http://127.0.0.2:8080"));
        assert!(is_localhost_url("http://127.255.255.254"));
        assert!(is_localhost_url("http://127.255.255.255"));
        // 128.x.x.x is NOT loopback
        assert!(!is_localhost_url("http://128.0.0.1"));
    }

    /// SECURITY: This is the exact attack vector from BUG-R110-004.
    /// `starts_with("http://localhost")` would match this.
    #[test]
    fn test_is_localhost_url_rejects_ssrf_via_subdomain() {
        assert!(!is_localhost_url("http://localhost.evil.com"));
        assert!(!is_localhost_url("http://localhost.evil.com:8080"));
        assert!(!is_localhost_url("http://localhost.attacker.org/steal"));
    }

    #[test]
    fn test_is_localhost_url_rejects_non_local() {
        assert!(!is_localhost_url("http://example.com"));
        assert!(!is_localhost_url("https://api.example.com"));
        assert!(!is_localhost_url("not a url"));
        assert!(!is_localhost_url(""));
    }

    /// SECURITY (FIND-R114-005): is_localhost_url is scheme-agnostic.
    /// Non-HTTP schemes still match if host is localhost.
    #[test]
    fn test_is_localhost_url_scheme_agnostic() {
        // is_localhost_url only checks the host, not the scheme
        assert!(is_localhost_url("ftp://localhost:21"));
        assert!(is_localhost_url("gopher://127.0.0.1:70"));
    }

    /// SECURITY (FIND-R114-005): is_http_localhost_url rejects non-HTTP schemes.
    #[test]
    fn test_is_http_localhost_url_rejects_non_http_schemes() {
        assert!(!is_http_localhost_url("ftp://localhost:21"));
        assert!(!is_http_localhost_url("gopher://localhost:70"));
        assert!(!is_http_localhost_url("ftp://127.0.0.1:21/steal"));
        // HTTP and HTTPS are allowed for localhost
        assert!(is_http_localhost_url("http://localhost:8080"));
        assert!(is_http_localhost_url("https://localhost:443"));
        assert!(is_http_localhost_url("http://127.0.0.2:8080"));
        // Non-localhost always returns false (not its job to enforce HTTPS)
        assert!(!is_http_localhost_url("http://example.com"));
    }
}
