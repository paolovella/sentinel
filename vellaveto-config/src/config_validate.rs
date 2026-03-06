// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! PolicyConfig validation and file loading — bounds checks and MAX_* constants.

use crate::*;

/// Maximum number of custom PII patterns allowed in config.
/// Prevents memory exhaustion from excessively large pattern arrays.
pub const MAX_CUSTOM_PII_PATTERNS: usize = 100;

/// Maximum number of extra injection patterns allowed in config.
pub const MAX_EXTRA_INJECTION_PATTERNS: usize = 100;

/// Maximum number of disabled injection patterns allowed in config.
pub const MAX_DISABLED_INJECTION_PATTERNS: usize = 100;

/// Maximum number of policies allowed in a single config file.
pub const MAX_POLICIES: usize = 10_000;

/// Maximum number of trusted keys for manifest verification.
pub const MAX_TRUSTED_KEYS: usize = 50;

/// Maximum number of known tool names for squatting detection.
pub const MAX_KNOWN_TOOL_NAMES: usize = 1_000;

/// Maximum number of allowed servers in supply chain configuration.
///
/// SECURITY (R39-SUP-4): Prevents memory exhaustion from excessively large
/// allowed_servers maps in config files.
pub const MAX_ALLOWED_SERVERS: usize = 1_000;

/// Maximum allowed behavioral baseline sessions before rejecting config.
const MAX_BEHAVIORAL_MIN_SESSIONS: u32 = 10_000;
/// Maximum allowed cross-agent privilege gap.
const MAX_CROSS_AGENT_PRIVILEGE_GAP: u8 = 10;
/// Maximum length for a trusted cross-agent identifier.
const MAX_CROSS_AGENT_TRUSTED_AGENT_LEN: usize = 256;
/// Maximum minimum observations for schema poisoning baseline.
const MAX_SCHEMA_POISONING_MIN_OBSERVATIONS: u32 = 10_000;
/// Maximum semantic min text length before rejecting config.
const MAX_SEMANTIC_MIN_TEXT_LENGTH: usize = 100_000;
/// Maximum per-template length for semantic templates.
const MAX_SEMANTIC_TEMPLATE_LEN: usize = 4096;
/// Maximum memory entries retained per session.
const MAX_MEMORY_ENTRIES_PER_SESSION: usize = 100_000;
/// Maximum provenance nodes retained in memory security.
const MAX_MEMORY_PROVENANCE_NODES: usize = 1_000_000;
/// Maximum memory poisoning fingerprints retained per session.
const MAX_MEMORY_FINGERPRINTS: usize = 100_000;
/// Maximum memory age in hours (one year).
const MAX_MEMORY_AGE_HOURS: u64 = 8_760;
/// Maximum namespace count for memory isolation.
const MAX_MEMORY_NAMESPACES: usize = 100_000;

/// SECURITY (IMP-R130-001): Delegate to canonical `has_dangerous_chars()` which
/// checks both control characters AND Unicode format characters (zero-width,
/// bidi overrides, BOM, etc.). The previous `char::is_control` check missed
/// format chars that could bypass security checks.
fn contains_control_chars(s: &str) -> bool {
    vellaveto_types::has_dangerous_chars(s)
}

impl PolicyConfig {
    /// Validate config bounds. Returns an error describing the first violation found.
    ///
    /// Checks that unbounded collection fields do not exceed safe limits,
    /// preventing memory exhaustion from maliciously crafted config files.
    pub fn validate(&self) -> Result<(), String> {
        if self.policies.len() > MAX_POLICIES {
            return Err(format!(
                "policies array has {} entries, max is {}",
                self.policies.len(),
                MAX_POLICIES
            ));
        }
        if self.injection.extra_patterns.len() > MAX_EXTRA_INJECTION_PATTERNS {
            return Err(format!(
                "injection.extra_patterns has {} entries, max is {}",
                self.injection.extra_patterns.len(),
                MAX_EXTRA_INJECTION_PATTERNS
            ));
        }
        // SECURITY (FIND-R46-010): Validate per-string length of injection.extra_patterns.
        // Unbounded patterns can cause excessive compile-time memory usage or ReDoS.
        const MAX_INJECTION_PATTERN_LEN: usize = 1024;
        for (i, pattern) in self.injection.extra_patterns.iter().enumerate() {
            if pattern.len() > MAX_INJECTION_PATTERN_LEN {
                return Err(format!(
                    "injection.extra_patterns[{}] exceeds max length ({} > {})",
                    i,
                    pattern.len(),
                    MAX_INJECTION_PATTERN_LEN
                ));
            }
        }
        if self.injection.disabled_patterns.len() > MAX_DISABLED_INJECTION_PATTERNS {
            return Err(format!(
                "injection.disabled_patterns has {} entries, max is {}",
                self.injection.disabled_patterns.len(),
                MAX_DISABLED_INJECTION_PATTERNS
            ));
        }
        // SECURITY (FIND-R46-011): Validate per-string length of injection.disabled_patterns.
        // Unbounded patterns can cause excessive memory usage during matching.
        for (i, pattern) in self.injection.disabled_patterns.iter().enumerate() {
            if pattern.len() > MAX_INJECTION_PATTERN_LEN {
                return Err(format!(
                    "injection.disabled_patterns[{}] exceeds max length ({} > {})",
                    i,
                    pattern.len(),
                    MAX_INJECTION_PATTERN_LEN
                ));
            }
        }
        // SECURITY (FIND-R46-012): Reject empty strings in injection.extra_patterns.
        // Empty patterns match everything, which would cause excessive false positives.
        for (i, pattern) in self.injection.extra_patterns.iter().enumerate() {
            if pattern.is_empty() {
                return Err(format!("injection.extra_patterns[{}] must not be empty", i));
            }
            // SECURITY (FIND-R216-001): Reject control/format characters in injection
            // extra_patterns — zero-width chars could bypass pattern matching or inject
            // invisible text into audit logs.
            if contains_control_chars(pattern) {
                return Err(format!(
                    "injection.extra_patterns[{}] contains control or format characters",
                    i
                ));
            }
        }
        // SECURITY (FIND-R216-001): Reject control/format characters in injection
        // disabled_patterns — zero-width chars could cause pattern-name comparison
        // to silently fail, leaving dangerous patterns enabled.
        for (i, pattern) in self.injection.disabled_patterns.iter().enumerate() {
            if contains_control_chars(pattern) {
                return Err(format!(
                    "injection.disabled_patterns[{}] contains control or format characters",
                    i
                ));
            }
        }
        // SECURITY (FIND-R216-002): Validate audit config fields (redaction_level).
        self.audit.validate()?;

        // SECURITY: Validate DLP numeric field bounds (max_depth, time_budget_ms, max_string_size).
        self.dlp.validate()?;

        // SECURITY: Validate rate limit configuration bounds (per_ip_max_capacity upper bound).
        self.rate_limit.validate()?;

        // SECURITY (FIND-R72-CFG-002): Validate dlp.disabled_patterns bounds.
        // Unbounded disabled_patterns can cause excessive memory usage during matching.
        const MAX_DLP_DISABLED_PATTERNS: usize = 100;
        const MAX_DLP_DISABLED_PATTERN_LEN: usize = 1024;
        if self.dlp.disabled_patterns.len() > MAX_DLP_DISABLED_PATTERNS {
            return Err(format!(
                "dlp.disabled_patterns has {} entries, max is {}",
                self.dlp.disabled_patterns.len(),
                MAX_DLP_DISABLED_PATTERNS
            ));
        }
        for (i, pattern) in self.dlp.disabled_patterns.iter().enumerate() {
            if pattern.is_empty() {
                return Err(format!("dlp.disabled_patterns[{}] must not be empty", i));
            }
            if pattern.len() > MAX_DLP_DISABLED_PATTERN_LEN {
                return Err(format!(
                    "dlp.disabled_patterns[{}] exceeds max length ({} > {})",
                    i,
                    pattern.len(),
                    MAX_DLP_DISABLED_PATTERN_LEN
                ));
            }
        }

        // FIND-002: Validate DLP extra_patterns compile as valid regex at config load time.
        // This ensures fail-closed behavior: invalid patterns are rejected upfront rather
        // than silently skipped at runtime.
        if self.dlp.extra_patterns.len() > MAX_EXTRA_INJECTION_PATTERNS {
            return Err(format!(
                "dlp.extra_patterns has {} entries, max is {}",
                self.dlp.extra_patterns.len(),
                MAX_EXTRA_INJECTION_PATTERNS
            ));
        }
        // SECURITY (FIND-063): Bound pattern length before regex compilation.
        // Unbounded patterns can cause ReDoS or excessive compile-time memory usage.
        const MAX_PATTERN_LEN: usize = 2048;
        const MAX_DLP_PATTERN_NAME_LEN: usize = 256;
        for (i, (name, pattern)) in self.dlp.extra_patterns.iter().enumerate() {
            // SECURITY: Validate DLP pattern name — reject empty, oversized,
            // and control-character-containing names.
            if name.is_empty() {
                return Err(format!("dlp.extra_patterns[{}] name must not be empty", i));
            }
            if name.len() > MAX_DLP_PATTERN_NAME_LEN {
                return Err(format!(
                    "dlp.extra_patterns[{}] name exceeds max length ({} > {})",
                    i,
                    name.len(),
                    MAX_DLP_PATTERN_NAME_LEN
                ));
            }
            if contains_control_chars(name) {
                return Err(format!(
                    "dlp.extra_patterns[{}] name contains control or format characters",
                    i
                ));
            }
            // SECURITY (FIND-R216-014): Validate DLP pattern string for control/format
            // characters — zero-width chars in regex could alter matching behavior.
            if contains_control_chars(pattern) {
                return Err(format!(
                    "dlp.extra_patterns[{}] pattern contains control or format characters",
                    i
                ));
            }
            if pattern.len() > MAX_PATTERN_LEN {
                return Err(format!(
                    "dlp.extra_patterns[{}] '{}' exceeds max pattern length ({} > {})",
                    i,
                    name,
                    pattern.len(),
                    MAX_PATTERN_LEN
                ));
            }
            if let Err(e) = regex::Regex::new(pattern) {
                return Err(format!(
                    "dlp.extra_patterns[{}] '{}' has invalid regex: {}",
                    i, name, e
                ));
            }
        }
        if self.audit.custom_pii_patterns.len() > MAX_CUSTOM_PII_PATTERNS {
            return Err(format!(
                "audit.custom_pii_patterns has {} entries, max is {}",
                self.audit.custom_pii_patterns.len(),
                MAX_CUSTOM_PII_PATTERNS
            ));
        }
        for (i, pattern) in self.audit.custom_pii_patterns.iter().enumerate() {
            // SECURITY (FIND-R137-002): Validate pattern.name for empty, length,
            // and control characters. The name appears in error messages and logs.
            if pattern.name.is_empty() {
                return Err(format!("audit.custom_pii_patterns[{}].name is empty", i));
            }
            if pattern.name.len() > 256 {
                return Err(format!(
                    "audit.custom_pii_patterns[{}].name length {} exceeds max 256",
                    i,
                    pattern.name.len()
                ));
            }
            if contains_control_chars(&pattern.name) {
                return Err(format!(
                    "audit.custom_pii_patterns[{}].name contains control or format characters",
                    i
                ));
            }
            // SECURITY (FIND-R216-013): Validate pattern.pattern for control/format chars.
            // Zero-width chars in regex patterns could alter matching behavior or inject
            // invisible content into compiled patterns.
            if contains_control_chars(&pattern.pattern) {
                return Err(format!(
                    "audit.custom_pii_patterns[{}].pattern contains control or format characters",
                    i
                ));
            }
            if pattern.pattern.len() > MAX_PATTERN_LEN {
                return Err(format!(
                    "audit.custom_pii_patterns[{}] '{}' exceeds max pattern length ({} > {})",
                    i,
                    pattern.name,
                    pattern.pattern.len(),
                    MAX_PATTERN_LEN
                ));
            }
            if let Err(e) = regex::Regex::new(&pattern.pattern) {
                return Err(format!(
                    "audit.custom_pii_patterns[{}] '{}' has invalid regex: {}",
                    i, pattern.name, e
                ));
            }
        }
        if self.manifest.trusted_keys.len() > MAX_TRUSTED_KEYS {
            return Err(format!(
                "manifest.trusted_keys has {} entries, max is {}",
                self.manifest.trusted_keys.len(),
                MAX_TRUSTED_KEYS
            ));
        }
        // Validate Ed25519 key format: hex-encoded, 32 bytes (64 hex chars)
        for (i, key) in self.manifest.trusted_keys.iter().enumerate() {
            let key_trimmed = key.trim();
            if key_trimmed.len() != 64 {
                return Err(format!(
                    "manifest.trusted_keys[{}] must be 64 hex characters (32 bytes), got {} characters",
                    i,
                    key_trimmed.len()
                ));
            }
            if !key_trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "manifest.trusted_keys[{}] must be hex-encoded (0-9, a-f, A-F only)",
                    i
                ));
            }
        }
        if self.known_tool_names.len() > MAX_KNOWN_TOOL_NAMES {
            return Err(format!(
                "known_tool_names has {} entries, max is {}",
                self.known_tool_names.len(),
                MAX_KNOWN_TOOL_NAMES
            ));
        }
        // SECURITY: Per-element validation of known_tool_names entries.
        // Empty names, names exceeding 256 bytes, and names containing control
        // characters are rejected to prevent squatting-detector bypass and log injection.
        const MAX_KNOWN_TOOL_NAME_LEN: usize = 256;
        for (i, name) in self.known_tool_names.iter().enumerate() {
            if name.is_empty() {
                return Err(format!("known_tool_names[{}] must not be empty", i));
            }
            if name.len() > MAX_KNOWN_TOOL_NAME_LEN {
                return Err(format!(
                    "known_tool_names[{}] exceeds max length ({} > {})",
                    i,
                    name.len(),
                    MAX_KNOWN_TOOL_NAME_LEN,
                ));
            }
            if contains_control_chars(name) {
                return Err(format!(
                    "known_tool_names[{}] contains control or format characters",
                    i,
                ));
            }
        }
        if self.elicitation.blocked_field_types.len() > MAX_BLOCKED_FIELD_TYPES {
            return Err(format!(
                "elicitation.blocked_field_types has {} entries, max is {}",
                self.elicitation.blocked_field_types.len(),
                MAX_BLOCKED_FIELD_TYPES
            ));
        }
        if self.sampling.allowed_models.len() > MAX_ALLOWED_MODELS {
            return Err(format!(
                "sampling.allowed_models has {} entries, max is {}",
                self.sampling.allowed_models.len(),
                MAX_ALLOWED_MODELS
            ));
        }
        // SECURITY (R39-SUP-4): Bound supply_chain.allowed_servers to prevent
        // memory exhaustion from excessively large server maps in config files.
        if self.supply_chain.allowed_servers.len() > MAX_ALLOWED_SERVERS {
            return Err(format!(
                "supply_chain.allowed_servers has {} entries, max is {}",
                self.supply_chain.allowed_servers.len(),
                MAX_ALLOWED_SERVERS
            ));
        }

        // SECURITY (FIND-R72-CFG-003): Validate allowed_origins bounds.
        // Unbounded origins can cause excessive memory usage and CORS misconfiguration.
        const MAX_ALLOWED_ORIGINS: usize = 100;
        const MAX_ORIGIN_LEN: usize = 2048;
        if self.allowed_origins.len() > MAX_ALLOWED_ORIGINS {
            return Err(format!(
                "allowed_origins has {} entries, max is {}",
                self.allowed_origins.len(),
                MAX_ALLOWED_ORIGINS
            ));
        }
        for (i, origin) in self.allowed_origins.iter().enumerate() {
            if origin.is_empty() {
                return Err(format!("allowed_origins[{}] must not be empty", i));
            }
            if origin.len() > MAX_ORIGIN_LEN {
                return Err(format!(
                    "allowed_origins[{}] exceeds max length ({} > {})",
                    i,
                    origin.len(),
                    MAX_ORIGIN_LEN
                ));
            }
            if contains_control_chars(origin) {
                return Err(format!(
                    "allowed_origins[{}] contains control or format characters",
                    i
                ));
            }
        }

        // SECURITY (FIND-R63-CFG-001): Delegate to ToolRegistryConfig::validate()
        // instead of inlining the trust_threshold checks here. This ensures
        // the validation logic is not duplicated as dead code.
        self.tool_registry.validate()?;

        // SECURITY (R24-SUP-6): Validate webhook_url scheme to prevent SSRF.
        // Only HTTPS is allowed for webhook destinations.
        if let Some(ref wh_url) = self.audit_export.webhook_url {
            let trimmed = wh_url.trim();
            if !trimmed.is_empty() {
                if !trimmed.starts_with("https://") {
                    return Err("audit_export.webhook_url must use HTTPS scheme".to_string());
                }
                // Extract host portion (after "https://", before next "/" or ":")
                let after_scheme = &trimmed["https://".len()..];
                // SECURITY (R25-SUP-2): Strip userinfo (credentials) before @.
                // RFC 3986 §3.2.1: authority = [userinfo@]host[:port]
                // Without this, "https://evil.com@localhost/path" would extract
                // "evil.com" as the host, bypassing localhost SSRF checks.
                let authority = after_scheme
                    .find('/')
                    .map_or(after_scheme, |i| &after_scheme[..i]);
                let host_portion = match authority.rfind('@') {
                    Some(at) => &after_scheme[at + 1..],
                    None => after_scheme,
                };
                // SECURITY (R41-SUP-3): Percent-decode brackets in authority before
                // IPv6 detection. An attacker can use %5B and %5D (percent-encoded
                // '[' and ']') to bypass the bracket check below, e.g.,
                // "https://%5Bfe80::1%5D/webhook" would not be recognized as IPv6.
                let host_portion_decoded = host_portion
                    .replace("%5B", "[")
                    .replace("%5b", "[")
                    .replace("%5D", "]")
                    .replace("%5d", "]");
                let host_portion = host_portion_decoded.as_str();
                // SECURITY (R26-SUP-4): Handle bracketed IPv6 addresses.
                // For "[::1]:8080/path", the host is "[::1]", not "[" (which
                // naive find(':') would produce by splitting on the first colon).
                let host = if host_portion.starts_with('[') {
                    // IPv6: extract up to and including the closing bracket
                    if let Some(bracket_end) = host_portion.find(']') {
                        let mut addr = host_portion[..bracket_end + 1].to_lowercase();
                        // SECURITY (R40-SUP-2): Strip IPv6 zone identifier (RFC 4007 §11).
                        // Zone IDs like %eth0 or %25eth0 cause IP parsing failures that
                        // bypass private IP checks. E.g., [fe80::1%eth0] fails to parse
                        // as Ipv6Addr, skipping the link-local rejection below.
                        if let Some(zone_start) = addr.find('%') {
                            if let Some(bracket_pos) = addr.rfind(']') {
                                if zone_start < bracket_pos {
                                    addr = format!("{}]", &addr[..zone_start]);
                                }
                            }
                        }
                        addr
                    } else {
                        // Malformed IPv6 — no closing bracket
                        return Err(
                            "audit_export.webhook_url has malformed IPv6 address (missing ']')"
                                .to_string(),
                        );
                    }
                } else {
                    let host_end = host_portion
                        .find(['/', ':', '?', '#'])
                        .unwrap_or(host_portion.len());
                    host_portion[..host_end].to_lowercase()
                };
                if host.is_empty() {
                    return Err("audit_export.webhook_url has no host".to_string());
                }
                // SECURITY (R42-CFG-1): Percent-decode host before localhost/loopback comparison.
                // An attacker can use %6c%6f%63%61%6c%68%6f%73%74 to encode "localhost"
                // which bypasses string comparison but HTTP clients will decode.
                let host_for_check = {
                    let mut decoded = String::with_capacity(host.len());
                    let bytes = host.as_bytes();
                    let mut i = 0;
                    while i < bytes.len() {
                        if bytes[i] == b'%' && i + 2 < bytes.len() {
                            if let (Some(hi), Some(lo)) = (
                                (bytes[i + 1] as char).to_digit(16),
                                (bytes[i + 2] as char).to_digit(16),
                            ) {
                                decoded.push((hi * 16 + lo) as u8 as char);
                                i += 3;
                                continue;
                            }
                        }
                        decoded.push(bytes[i] as char);
                        i += 1;
                    }
                    decoded.to_lowercase()
                };
                // SECURITY (R228-TYP-3): Strip trailing DNS dot before loopback check.
                let host_stripped = host_for_check.trim_end_matches('.');
                let loopbacks = ["localhost", "127.0.0.1", "[::1]", "0.0.0.0"];
                if loopbacks.contains(&host_stripped) {
                    return Err(format!(
                        "audit_export.webhook_url must not target localhost/loopback, got '{}'",
                        host
                    ));
                }
                // SECURITY (R31-SUP-1): Reject private/cloud-metadata IP ranges to prevent
                // SSRF attacks that target internal infrastructure. The loopback check above
                // only catches 127.0.0.1 and localhost, but an attacker could use 10.x.x.x,
                // 172.16.x.x, 192.168.x.x, or 169.254.169.254 (cloud metadata endpoint).
                if let Ok(ip) = host_for_check.parse::<std::net::Ipv4Addr>() {
                    let is_private = ip.is_loopback()
                        || ip.octets()[0] == 10                          // 10.0.0.0/8
                        || (ip.octets()[0] == 172 && (ip.octets()[1] & 0xf0) == 16) // 172.16.0.0/12
                        || (ip.octets()[0] == 192 && ip.octets()[1] == 168)         // 192.168.0.0/16
                        || (ip.octets()[0] == 169 && ip.octets()[1] == 254)         // 169.254.0.0/16 (link-local/metadata)
                        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64) // 100.64.0.0/10 (CGNAT)
                        || ip.octets()[0] == 0                           // 0.0.0.0/8
                        || ip.is_broadcast(); // 255.255.255.255
                    if is_private {
                        return Err(format!(
                            "audit_export.webhook_url must not target private/internal IP ranges, got '{}'",
                            host
                        ));
                    }
                }
                // Also check IPv6 private ranges (stripped brackets already handled above)
                let ipv6_host = host_for_check.trim_start_matches('[').trim_end_matches(']');
                if let Ok(ip6) = ipv6_host.parse::<std::net::Ipv6Addr>() {
                    // SECURITY (R32-SSRF-1): Check IPv4-mapped IPv6 (::ffff:x.x.x.x)
                    // against IPv4 private ranges. Without this, ::ffff:169.254.169.254
                    // bypasses the IPv4 cloud metadata SSRF check above.
                    let segs = ip6.segments();
                    let is_ipv4_mapped = segs[0] == 0
                        && segs[1] == 0
                        && segs[2] == 0
                        && segs[3] == 0
                        && segs[4] == 0
                        && segs[5] == 0xffff;
                    if is_ipv4_mapped {
                        let mapped_ip = std::net::Ipv4Addr::new(
                            (segs[6] >> 8) as u8,
                            segs[6] as u8,
                            (segs[7] >> 8) as u8,
                            segs[7] as u8,
                        );
                        let is_private_v4 = mapped_ip.is_loopback()
                            || mapped_ip.octets()[0] == 10
                            || (mapped_ip.octets()[0] == 172
                                && (mapped_ip.octets()[1] & 0xf0) == 16)
                            || (mapped_ip.octets()[0] == 192 && mapped_ip.octets()[1] == 168)
                            || (mapped_ip.octets()[0] == 169 && mapped_ip.octets()[1] == 254)
                            || (mapped_ip.octets()[0] == 100
                                && (mapped_ip.octets()[1] & 0xc0) == 64)
                            || mapped_ip.octets()[0] == 0
                            || mapped_ip.is_broadcast();
                        if is_private_v4 {
                            return Err(format!(
                                "audit_export.webhook_url must not target private/internal IP ranges (IPv4-mapped IPv6), got '{}'",
                                host
                            ));
                        }
                    }
                    // SECURITY (R33-SUP-3): Use proper bitmask for fe80::/10 — the
                    // prefix is 10 bits, not 16. Previous check (segs[0] == 0xfe80)
                    // missed fe80::1 through febf::ffff (all link-local addresses
                    // with non-zero bits in positions 11-16).
                    let is_private = ip6.is_loopback()
                        || ip6.is_unspecified()
                        || (segs[0] & 0xfe00) == 0xfc00  // fc00::/7 (ULA)
                        || (segs[0] & 0xffc0) == 0xfe80; // fe80::/10 (link-local)
                    if is_private {
                        return Err(format!(
                            "audit_export.webhook_url must not target private/internal IPv6 ranges, got '{}'",
                            host
                        ));
                    }
                }
            }
        }

        // SECURITY (R25-SUP-7, R26-SUP-1): Reject path traversal in persistence_path.
        // Uses Path::components() to detect ParentDir (..) components, which is more
        // robust than simple .contains("..") — handles "foo/./bar/../../../etc" etc.
        // SECURITY (R41-SUP-7): Also reject absolute paths to prevent writing to
        // arbitrary system locations (e.g., /etc/cron.d/backdoor).
        {
            use std::path::{Component, Path};
            // SECURITY: Reject null bytes and control characters in persistence_path
            // to prevent filesystem confusion and log injection.
            if self
                .tool_registry
                .persistence_path
                .bytes()
                .any(|b| b == 0x00 || b < 0x20 || (0x7F..=0x9F).contains(&b))
            {
                return Err(
                    "tool_registry.persistence_path contains null bytes or control characters"
                        .to_string(),
                );
            }
            // SECURITY: Cap path length to prevent OS-level path length limit bypasses
            // and memory abuse from excessively long paths.
            const MAX_PERSISTENCE_PATH_LEN: usize = 4096;
            if self.tool_registry.persistence_path.len() > MAX_PERSISTENCE_PATH_LEN {
                return Err(format!(
                    "tool_registry.persistence_path exceeds max length ({} > {})",
                    self.tool_registry.persistence_path.len(),
                    MAX_PERSISTENCE_PATH_LEN,
                ));
            }
            let p = Path::new(&self.tool_registry.persistence_path);
            if p.is_absolute() {
                return Err(format!(
                    "tool_registry.persistence_path must be a relative path, got '{}'",
                    self.tool_registry.persistence_path
                ));
            }
            if p.components().any(|c| matches!(c, Component::ParentDir)) {
                return Err(format!(
                    "tool_registry.persistence_path must not contain '..' components, got '{}'",
                    self.tool_registry.persistence_path
                ));
            }
        }

        // SECURITY (R24-SUP-10): Bound batch_size to prevent excessive memory usage
        if self.audit_export.batch_size > 10_000 {
            return Err(format!(
                "audit_export.batch_size must be <= 10000, got {}",
                self.audit_export.batch_size
            ));
        }
        // SECURITY (FIND-R46-015): Reject zero batch_size which would cause
        // infinite loops or no-op exports.
        if self.audit_export.batch_size == 0 {
            return Err("audit_export.batch_size must be > 0".to_string());
        }

        // SECURITY (FIND-R72-CFG-006): Validate audit_export.format is a recognized value.
        // Unrecognized values could cause silent export failures or unexpected behavior.
        // SECURITY (FIND-R75-004): Accept all aliases recognized by ExportFormat::parse_format()
        // ("cef", "jsonl", "json_lines", "jsonlines", "ocsf") to avoid breaking valid configurations.
        {
            let valid_formats = ["cef", "jsonl", "json_lines", "jsonlines", "ocsf"];
            let format_lower = self.audit_export.format.to_lowercase();
            if !valid_formats.contains(&format_lower.as_str()) {
                return Err(format!(
                    "audit_export.format must be one of {:?}, got '{}'",
                    valid_formats, self.audit_export.format
                ));
            }
        }

        // Validate behavioral detection config
        if self.behavioral.enabled
            && (!self.behavioral.alpha.is_finite()
                || self.behavioral.alpha <= 0.0
                || self.behavioral.alpha > 1.0)
        {
            return Err(format!(
                "behavioral.alpha must be in (0.0, 1.0], got {}",
                self.behavioral.alpha
            ));
        }
        if self.behavioral.enabled
            && (!self.behavioral.threshold.is_finite() || self.behavioral.threshold <= 0.0)
        {
            return Err(format!(
                "behavioral.threshold must be finite and positive, got {}",
                self.behavioral.threshold
            ));
        }
        if self.behavioral.max_agents > MAX_BEHAVIORAL_AGENTS {
            return Err(format!(
                "behavioral.max_agents must be <= {}, got {}",
                MAX_BEHAVIORAL_AGENTS, self.behavioral.max_agents
            ));
        }
        if self.behavioral.max_tools_per_agent > MAX_BEHAVIORAL_TOOLS_PER_AGENT {
            return Err(format!(
                "behavioral.max_tools_per_agent must be <= {}, got {}",
                MAX_BEHAVIORAL_TOOLS_PER_AGENT, self.behavioral.max_tools_per_agent
            ));
        }
        if self.behavioral.min_sessions > MAX_BEHAVIORAL_MIN_SESSIONS {
            return Err(format!(
                "behavioral.min_sessions must be <= {}, got {}",
                MAX_BEHAVIORAL_MIN_SESSIONS, self.behavioral.min_sessions
            ));
        }

        // Validate data flow tracking config
        if self.data_flow.max_findings > MAX_DATA_FLOW_FINDINGS {
            return Err(format!(
                "data_flow.max_findings must be <= {}, got {}",
                MAX_DATA_FLOW_FINDINGS, self.data_flow.max_findings
            ));
        }
        if self.data_flow.max_fingerprints_per_pattern > MAX_DATA_FLOW_FINGERPRINTS {
            return Err(format!(
                "data_flow.max_fingerprints_per_pattern must be <= {}, got {}",
                MAX_DATA_FLOW_FINGERPRINTS, self.data_flow.max_fingerprints_per_pattern
            ));
        }
        // SECURITY (FIND-R216-009): Reject zero max_findings / max_fingerprints_per_pattern
        // when data_flow tracking is enabled. Zero values would disable tracking entirely,
        // silently defeating the exfiltration detection purpose.
        if self.data_flow.enabled {
            if self.data_flow.max_findings == 0 {
                return Err("data_flow.max_findings must be > 0 when enabled".to_string());
            }
            if self.data_flow.max_fingerprints_per_pattern == 0 {
                return Err(
                    "data_flow.max_fingerprints_per_pattern must be > 0 when enabled".to_string(),
                );
            }
        }

        // Validate semantic detection config
        if self.semantic_detection.enabled
            && (!self.semantic_detection.threshold.is_finite()
                || self.semantic_detection.threshold <= 0.0
                || self.semantic_detection.threshold > 1.0)
        {
            return Err(format!(
                "semantic_detection.threshold must be in (0.0, 1.0], got {}",
                self.semantic_detection.threshold
            ));
        }
        if self.semantic_detection.extra_templates.len() > MAX_SEMANTIC_EXTRA_TEMPLATES {
            return Err(format!(
                "semantic_detection.extra_templates has {} entries, max is {}",
                self.semantic_detection.extra_templates.len(),
                MAX_SEMANTIC_EXTRA_TEMPLATES
            ));
        }
        if self.semantic_detection.min_text_length > MAX_SEMANTIC_MIN_TEXT_LENGTH {
            return Err(format!(
                "semantic_detection.min_text_length must be <= {}, got {}",
                MAX_SEMANTIC_MIN_TEXT_LENGTH, self.semantic_detection.min_text_length
            ));
        }
        for (i, template) in self.semantic_detection.extra_templates.iter().enumerate() {
            if template.is_empty() {
                return Err(format!(
                    "semantic_detection.extra_templates[{}] must not be empty",
                    i
                ));
            }
            if template.len() > MAX_SEMANTIC_TEMPLATE_LEN {
                return Err(format!(
                    "semantic_detection.extra_templates[{}] exceeds max length ({} > {})",
                    i,
                    template.len(),
                    MAX_SEMANTIC_TEMPLATE_LEN
                ));
            }
            if contains_control_chars(template) {
                return Err(format!(
                    "semantic_detection.extra_templates[{}] contains control or format characters",
                    i
                ));
            }
        }

        // SECURITY (FIND-R111-005): Cluster validation is fully delegated to
        // `ClusterConfig::validate()` which is called unconditionally below
        // (line ~1508). This removes the previous inline duplicate block that
        // used different constants (MAX_CLUSTER_REDIS_POOL_SIZE=128 from
        // threat_detection.rs instead of 512 from cluster.rs, and
        // MAX_CLUSTER_KEY_PREFIX_LEN from threat_detection.rs) and produced
        // different error messages for the same conditions, creating a
        // divergence risk where the two paths could reach different verdicts
        // for the same input. Single source of truth: `ClusterConfig::validate()`.

        // ═══════════════════════════════════════════════════
        // PHASE 2: ADVANCED THREAT DETECTION VALIDATION
        // ═══════════════════════════════════════════════════

        // Validate circuit breaker config
        if self.circuit_breaker.enabled {
            if self.circuit_breaker.failure_threshold == 0 {
                return Err(
                    "circuit_breaker.failure_threshold must be > 0 when enabled".to_string()
                );
            }
            if self.circuit_breaker.success_threshold == 0 {
                return Err(
                    "circuit_breaker.success_threshold must be > 0 when enabled".to_string()
                );
            }
            if self.circuit_breaker.open_duration_secs == 0 {
                return Err(
                    "circuit_breaker.open_duration_secs must be > 0 when enabled".to_string(),
                );
            }
        }

        // Validate deputy config
        if self.deputy.non_delegatable_tools.len() > MAX_NON_DELEGATABLE_TOOLS {
            return Err(format!(
                "deputy.non_delegatable_tools has {} entries, max is {}",
                self.deputy.non_delegatable_tools.len(),
                MAX_NON_DELEGATABLE_TOOLS
            ));
        }

        // Validate shadow agent config
        if self.shadow_agent.max_known_agents > MAX_KNOWN_AGENTS {
            return Err(format!(
                "shadow_agent.max_known_agents must be <= {}, got {}",
                MAX_KNOWN_AGENTS, self.shadow_agent.max_known_agents
            ));
        }
        // SECURITY (FIND-R216-006): Per-entry validation of fingerprint_components
        // runs unconditionally — structural checks (known-set, control chars) must
        // run even on disabled configs to prevent malicious values from activating
        // without validation when later enabled via hot-reload.
        {
            let valid_components = ["jwt_sub", "jwt_iss", "client_id", "ip_hash"];
            for comp in &self.shadow_agent.fingerprint_components {
                if !valid_components.contains(&comp.as_str()) {
                    return Err(format!(
                        "shadow_agent.fingerprint_components has invalid component '{}', valid values are {:?}",
                        comp, valid_components
                    ));
                }
                if contains_control_chars(comp) {
                    return Err(format!(
                        "shadow_agent.fingerprint_components contains control or format characters in '{}'",
                        comp
                    ));
                }
            }
        }
        if self.shadow_agent.enabled && self.shadow_agent.fingerprint_components.is_empty() {
            return Err(
                "shadow_agent.fingerprint_components must have at least one component when enabled"
                    .to_string(),
            );
        }
        // SECURITY (FIND-R146-CS-002): Validate min_trust_level range (documented as 0-4)
        // and trust_decay_hours bounds to prevent unchecked values.
        if self.shadow_agent.min_trust_level > 4 {
            return Err(format!(
                "shadow_agent.min_trust_level must be in [0, 4], got {}",
                self.shadow_agent.min_trust_level
            ));
        }
        if self.shadow_agent.trust_decay_hours == 0 {
            return Err("shadow_agent.trust_decay_hours must be > 0".to_string());
        }
        if self.shadow_agent.trust_decay_hours > 8760 {
            return Err(format!(
                "shadow_agent.trust_decay_hours must be <= 8760, got {}",
                self.shadow_agent.trust_decay_hours
            ));
        }

        // Validate schema poisoning config
        if self.schema_poisoning.enabled
            && (!self.schema_poisoning.mutation_threshold.is_finite()
                || self.schema_poisoning.mutation_threshold < 0.0
                || self.schema_poisoning.mutation_threshold > 1.0)
        {
            return Err(format!(
                "schema_poisoning.mutation_threshold must be in [0.0, 1.0], got {}",
                self.schema_poisoning.mutation_threshold
            ));
        }
        if self.schema_poisoning.max_tracked_schemas > MAX_TRACKED_SCHEMAS {
            return Err(format!(
                "schema_poisoning.max_tracked_schemas must be <= {}, got {}",
                MAX_TRACKED_SCHEMAS, self.schema_poisoning.max_tracked_schemas
            ));
        }
        if self.schema_poisoning.min_observations > MAX_SCHEMA_POISONING_MIN_OBSERVATIONS {
            return Err(format!(
                "schema_poisoning.min_observations must be <= {}, got {}",
                MAX_SCHEMA_POISONING_MIN_OBSERVATIONS, self.schema_poisoning.min_observations
            ));
        }

        // Validate sampling detection config
        if self.sampling_detection.allowed_models.len() > MAX_ALLOWED_SAMPLING_MODELS {
            return Err(format!(
                "sampling_detection.allowed_models has {} entries, max is {}",
                self.sampling_detection.allowed_models.len(),
                MAX_ALLOWED_SAMPLING_MODELS
            ));
        }
        if self.sampling_detection.enabled && self.sampling_detection.window_secs == 0 {
            return Err("sampling_detection.window_secs must be > 0 when enabled".to_string());
        }
        // SECURITY (FIND-R146-CS-003): Validate max_prompt_length upper bound and
        // per-string validation on allowed_models entries.
        const MAX_SAMPLING_PROMPT_LENGTH: usize = 1_000_000;
        if self.sampling_detection.max_prompt_length > MAX_SAMPLING_PROMPT_LENGTH {
            return Err(format!(
                "sampling_detection.max_prompt_length {} exceeds maximum {}",
                self.sampling_detection.max_prompt_length, MAX_SAMPLING_PROMPT_LENGTH
            ));
        }
        for (i, model) in self.sampling_detection.allowed_models.iter().enumerate() {
            if model.len() > 256 {
                return Err(format!(
                    "sampling_detection.allowed_models[{}] length {} exceeds maximum 256",
                    i,
                    model.len()
                ));
            }
            if vellaveto_types::has_dangerous_chars(model) {
                return Err(format!(
                    "sampling_detection.allowed_models[{}] contains control or format characters",
                    i
                ));
            }
        }

        // Validate cross-agent security config
        if self.cross_agent.trusted_agents.len() > MAX_CROSS_AGENT_TRUSTED_AGENTS {
            return Err(format!(
                "cross_agent.trusted_agents has {} entries, max is {}",
                self.cross_agent.trusted_agents.len(),
                MAX_CROSS_AGENT_TRUSTED_AGENTS
            ));
        }
        for (i, agent) in self.cross_agent.trusted_agents.iter().enumerate() {
            if agent.is_empty() {
                return Err(format!(
                    "cross_agent.trusted_agents[{}] must not be empty",
                    i
                ));
            }
            if agent.len() > MAX_CROSS_AGENT_TRUSTED_AGENT_LEN {
                return Err(format!(
                    "cross_agent.trusted_agents[{}] exceeds max length ({} > {})",
                    i,
                    agent.len(),
                    MAX_CROSS_AGENT_TRUSTED_AGENT_LEN
                ));
            }
            if contains_control_chars(agent) {
                return Err(format!(
                    "cross_agent.trusted_agents[{}] contains control or format characters",
                    i
                ));
            }
        }
        if !self.cross_agent.escalation_deny_threshold.is_finite()
            || self.cross_agent.escalation_deny_threshold < 0.0
            || self.cross_agent.escalation_deny_threshold > 1.0
        {
            return Err(format!(
                "cross_agent.escalation_deny_threshold must be in [0.0, 1.0], got {}",
                self.cross_agent.escalation_deny_threshold
            ));
        }
        if !self.cross_agent.escalation_alert_threshold.is_finite()
            || self.cross_agent.escalation_alert_threshold < 0.0
            || self.cross_agent.escalation_alert_threshold > 1.0
        {
            return Err(format!(
                "cross_agent.escalation_alert_threshold must be in [0.0, 1.0], got {}",
                self.cross_agent.escalation_alert_threshold
            ));
        }
        if self.cross_agent.escalation_alert_threshold > self.cross_agent.escalation_deny_threshold
        {
            return Err(format!(
                "cross_agent.escalation_alert_threshold ({}) must be <= escalation_deny_threshold ({})",
                self.cross_agent.escalation_alert_threshold,
                self.cross_agent.escalation_deny_threshold
            ));
        }
        if self.cross_agent.max_chain_depth == 0 {
            return Err("cross_agent.max_chain_depth must be > 0".to_string());
        }
        if self.cross_agent.enabled && self.cross_agent.nonce_expiry_secs == 0 {
            return Err("cross_agent.nonce_expiry_secs must be > 0 when enabled".to_string());
        }
        if self.cross_agent.max_privilege_gap > MAX_CROSS_AGENT_PRIVILEGE_GAP {
            return Err(format!(
                "cross_agent.max_privilege_gap must be <= {}, got {}",
                MAX_CROSS_AGENT_PRIVILEGE_GAP, self.cross_agent.max_privilege_gap
            ));
        }

        // PHASE 3.3: Advanced Threat Detection validation
        if self.advanced_threat.protected_tool_patterns.len() > MAX_PROTECTED_TOOL_PATTERNS {
            return Err(format!(
                "advanced_threat.protected_tool_patterns has {} entries, max is {}",
                self.advanced_threat.protected_tool_patterns.len(),
                MAX_PROTECTED_TOOL_PATTERNS
            ));
        }
        // SECURITY (FIND-R146-CS-004): Per-string validation of protected_tool_patterns --
        // reject oversized entries and entries containing control/format characters.
        for (i, pat) in self
            .advanced_threat
            .protected_tool_patterns
            .iter()
            .enumerate()
        {
            if pat.len() > 256 {
                return Err(format!(
                    "advanced_threat.protected_tool_patterns[{}] length {} exceeds maximum 256",
                    i,
                    pat.len()
                ));
            }
            if vellaveto_types::has_dangerous_chars(pat) {
                return Err(format!(
                    "advanced_threat.protected_tool_patterns[{}] contains control or format characters",
                    i
                ));
            }
        }
        if !self.advanced_threat.goal_drift_threshold.is_finite()
            || self.advanced_threat.goal_drift_threshold < 0.0
            || self.advanced_threat.goal_drift_threshold > 1.0
        {
            return Err(format!(
                "advanced_threat.goal_drift_threshold must be in [0.0, 1.0], got {}",
                self.advanced_threat.goal_drift_threshold
            ));
        }
        const MAX_WORKFLOW_STEP_BUDGET: usize = 10_000;
        if self.advanced_threat.workflow_step_budget == 0
            || self.advanced_threat.workflow_step_budget > MAX_WORKFLOW_STEP_BUDGET
        {
            return Err(format!(
                "advanced_threat.workflow_step_budget must be in [1, {}], got {}",
                MAX_WORKFLOW_STEP_BUDGET, self.advanced_threat.workflow_step_budget
            ));
        }
        const MAX_DEFAULT_CONTEXT_BUDGET: usize = 10_000_000;
        if self.advanced_threat.default_context_budget == 0
            || self.advanced_threat.default_context_budget > MAX_DEFAULT_CONTEXT_BUDGET
        {
            return Err(format!(
                "advanced_threat.default_context_budget must be in [1, {}], got {}",
                MAX_DEFAULT_CONTEXT_BUDGET, self.advanced_threat.default_context_budget
            ));
        }

        // ── Enterprise hardening validation ────────────────────────────────
        // TLS validation
        if matches!(self.tls.mode, TlsMode::Tls | TlsMode::Mtls) {
            if self.tls.cert_path.is_none() {
                return Err("tls.cert_path is required when TLS is enabled".to_string());
            }
            if self.tls.key_path.is_none() {
                return Err("tls.key_path is required when TLS is enabled".to_string());
            }
        }
        if self.tls.mode == TlsMode::Mtls && self.tls.client_ca_path.is_none() {
            return Err("tls.client_ca_path is required when mTLS is enabled".to_string());
        }
        if !matches!(self.tls.min_version.as_str(), "1.2" | "1.3") {
            return Err(format!(
                "tls.min_version must be \"1.2\" or \"1.3\", got {:?}",
                self.tls.min_version
            ));
        }
        if self.tls.kex_policy != TlsKexPolicy::ClassicalOnly {
            if self.tls.mode == TlsMode::None {
                return Err(
                    "tls.kex_policy requires tls.mode to be \"tls\" or \"mtls\"".to_string()
                );
            }
            if self.tls.min_version != "1.3" {
                return Err(format!(
                    "tls.kex_policy {:?} requires tls.min_version = \"1.3\"",
                    self.tls.kex_policy
                ));
            }
        }
        // SECURITY (FIND-R81-CFG-001): Bound cipher_suites to prevent OOM
        // and reject empty/oversized/control-char entries.
        const MAX_CIPHER_SUITES: usize = 64;
        const MAX_CIPHER_SUITE_LEN: usize = 128;
        if self.tls.cipher_suites.len() > MAX_CIPHER_SUITES {
            return Err(format!(
                "tls.cipher_suites has {} entries, max is {}",
                self.tls.cipher_suites.len(),
                MAX_CIPHER_SUITES
            ));
        }
        for (i, suite) in self.tls.cipher_suites.iter().enumerate() {
            if suite.is_empty() {
                return Err(format!("tls.cipher_suites[{}] is empty", i));
            }
            if suite.len() > MAX_CIPHER_SUITE_LEN {
                return Err(format!(
                    "tls.cipher_suites[{}] length {} exceeds maximum {}",
                    i,
                    suite.len(),
                    MAX_CIPHER_SUITE_LEN
                ));
            }
            if contains_control_chars(suite) {
                return Err(format!(
                    "tls.cipher_suites[{}] contains control or format characters",
                    i
                ));
            }
        }

        // SPIFFE validation
        if self.spiffe.enabled && self.spiffe.trust_domain.is_none() {
            return Err("spiffe.trust_domain is required when SPIFFE is enabled".to_string());
        }
        // SECURITY (FIND-R71-CFG-007): Bound SPIFFE collections to prevent OOM
        // from excessively large config files.
        const MAX_SPIFFE_ID_TO_ROLE: usize = 1_000;
        const MAX_SPIFFE_ALLOWED_IDS: usize = 1_000;
        if self.spiffe.id_to_role.len() > MAX_SPIFFE_ID_TO_ROLE {
            return Err(format!(
                "spiffe.id_to_role has {} entries, max is {}",
                self.spiffe.id_to_role.len(),
                MAX_SPIFFE_ID_TO_ROLE
            ));
        }
        if self.spiffe.allowed_spiffe_ids.len() > MAX_SPIFFE_ALLOWED_IDS {
            return Err(format!(
                "spiffe.allowed_spiffe_ids has {} entries, max is {}",
                self.spiffe.allowed_spiffe_ids.len(),
                MAX_SPIFFE_ALLOWED_IDS
            ));
        }
        // SECURITY (FIND-R102-003): Reject zero SVID cache TTL when enabled —
        // zero disables SVID caching, causing re-verification on every request.
        if self.spiffe.enabled && self.spiffe.svid_cache_ttl_secs == 0 {
            return Err("spiffe.svid_cache_ttl_secs must be > 0".to_string());
        }

        // SECURITY (FIND-R71-CFG-012): Validate ETDI version_pinning.enforcement is a
        // recognized value. Unrecognized values could silently fail-open.
        if self.etdi.version_pinning.enabled {
            let enforcement_lower = self.etdi.version_pinning.enforcement.to_lowercase();
            let valid_enforcements = ["warn", "block"];
            if !valid_enforcements.contains(&enforcement_lower.as_str()) {
                return Err(format!(
                    "etdi.version_pinning.enforcement must be one of {:?}, got '{}'",
                    valid_enforcements, self.etdi.version_pinning.enforcement
                ));
            }
        }

        // SECURITY (FIND-R72-CFG-005): Validate etdi.allowed_signers bounds.
        // Unbounded fingerprint/SPIFFE ID lists can cause excessive memory usage.
        const MAX_ETDI_ALLOWED_FINGERPRINTS: usize = 100;
        const MAX_ETDI_ALLOWED_SPIFFE_IDS: usize = 100;
        if self.etdi.allowed_signers.fingerprints.len() > MAX_ETDI_ALLOWED_FINGERPRINTS {
            return Err(format!(
                "etdi.allowed_signers.fingerprints has {} entries, max is {}",
                self.etdi.allowed_signers.fingerprints.len(),
                MAX_ETDI_ALLOWED_FINGERPRINTS
            ));
        }
        if self.etdi.allowed_signers.spiffe_ids.len() > MAX_ETDI_ALLOWED_SPIFFE_IDS {
            return Err(format!(
                "etdi.allowed_signers.spiffe_ids has {} entries, max is {}",
                self.etdi.allowed_signers.spiffe_ids.len(),
                MAX_ETDI_ALLOWED_SPIFFE_IDS
            ));
        }

        // SECURITY (FIND-R80-007): Validate etdi.data_path for path traversal, control
        // characters, and length — same pattern as tool_registry.persistence_path.
        if let Some(ref data_path) = self.etdi.data_path {
            const MAX_ETDI_DATA_PATH_LEN: usize = 4096;
            if data_path
                .bytes()
                .any(|b| b == 0x00 || b < 0x20 || (0x7F..=0x9F).contains(&b))
            {
                return Err("etdi.data_path contains null bytes or control characters".to_string());
            }
            if data_path.len() > MAX_ETDI_DATA_PATH_LEN {
                return Err(format!(
                    "etdi.data_path exceeds max length ({} > {})",
                    data_path.len(),
                    MAX_ETDI_DATA_PATH_LEN,
                ));
            }
            use std::path::{Component, Path};
            let p = Path::new(data_path);
            if p.is_absolute() {
                return Err(format!(
                    "etdi.data_path must be a relative path, got '{}'",
                    data_path
                ));
            }
            if p.components().any(|c| matches!(c, Component::ParentDir)) {
                return Err(format!(
                    "etdi.data_path must not contain '..' components, got '{}'",
                    data_path
                ));
            }
        }

        // SECURITY (FIND-R80-007): Validate etdi.version_pinning.pins_path for path traversal,
        // control characters, and length — same pattern as etdi.data_path above.
        if let Some(ref pins_path) = self.etdi.version_pinning.pins_path {
            const MAX_ETDI_PINS_PATH_LEN: usize = 4096;
            if pins_path
                .bytes()
                .any(|b| b == 0x00 || b < 0x20 || (0x7F..=0x9F).contains(&b))
            {
                return Err(
                    "etdi.version_pinning.pins_path contains null bytes or control characters"
                        .to_string(),
                );
            }
            if pins_path.len() > MAX_ETDI_PINS_PATH_LEN {
                return Err(format!(
                    "etdi.version_pinning.pins_path exceeds max length ({} > {})",
                    pins_path.len(),
                    MAX_ETDI_PINS_PATH_LEN,
                ));
            }
            use std::path::{Component, Path};
            let p = Path::new(pins_path);
            if p.is_absolute() {
                return Err(format!(
                    "etdi.version_pinning.pins_path must be a relative path, got '{}'",
                    pins_path
                ));
            }
            if p.components().any(|c| matches!(c, Component::ParentDir)) {
                return Err(format!(
                    "etdi.version_pinning.pins_path must not contain '..' components, got '{}'",
                    pins_path
                ));
            }
        }

        // SECURITY (FIND-R80-007): Validate etdi.attestation.rekor_url for HTTPS scheme,
        // control characters, and length.
        if let Some(ref rekor_url) = self.etdi.attestation.rekor_url {
            const MAX_REKOR_URL_LEN: usize = 2048;
            if rekor_url
                .bytes()
                .any(|b| b == 0x00 || b < 0x20 || (0x7F..=0x9F).contains(&b))
            {
                return Err(
                    "etdi.attestation.rekor_url contains null bytes or control characters"
                        .to_string(),
                );
            }
            if rekor_url.len() > MAX_REKOR_URL_LEN {
                return Err(format!(
                    "etdi.attestation.rekor_url exceeds max length ({} > {})",
                    rekor_url.len(),
                    MAX_REKOR_URL_LEN,
                ));
            }
            let parsed = url::Url::parse(rekor_url)
                .map_err(|e| format!("etdi.attestation.rekor_url must be a valid URL: {e}"))?;
            if parsed.scheme() != "https" {
                return Err("etdi.attestation.rekor_url must use https:// scheme".to_string());
            }
            if parsed.host_str().map(str::is_empty).unwrap_or(true) {
                return Err("etdi.attestation.rekor_url must include a host".to_string());
            }
        }

        // OPA validation
        if self.opa.enabled {
            if self.opa.endpoint.is_none() && self.opa.bundle_path.is_none() {
                return Err(
                    "opa.endpoint or opa.bundle_path is required when OPA is enabled".to_string(),
                );
            }
            if let Some(ref endpoint) = self.opa.endpoint {
                let endpoint = endpoint.trim();
                if endpoint.is_empty() {
                    return Err("opa.endpoint must not be empty when provided".to_string());
                }
                let parsed = url::Url::parse(endpoint)
                    .map_err(|e| format!("opa.endpoint must be a valid URL: {e}"))?;
                let is_http = parsed.scheme() == "http";
                let is_https = parsed.scheme() == "https";
                if !is_http && !is_https {
                    return Err("opa.endpoint must start with http:// or https://".to_string());
                }
                if parsed.host_str().map(str::is_empty).unwrap_or(true) {
                    return Err("opa.endpoint must include a host".to_string());
                }
                if !parsed.username().is_empty() || parsed.password().is_some() {
                    return Err(
                        "opa.endpoint must not include URL userinfo credentials".to_string()
                    );
                }
                if self.opa.require_https && !is_https {
                    return Err(
                        "opa.require_https=true requires opa.endpoint to use https://".to_string(),
                    );
                }
            }
            if self.opa.timeout_ms == 0 {
                return Err("opa.timeout_ms must be > 0".to_string());
            }
            // SECURITY (FIND-041): Cap OPA timeout to prevent misconfiguration
            // where an enormous value effectively disables timeout protection.
            if self.opa.timeout_ms > 300_000 {
                return Err("opa.timeout_ms must be <= 300000 (5 minutes)".to_string());
            }
        }
        // SECURITY (FIND-R71-CFG-009): Bound OPA headers to prevent OOM from
        // excessively large config files.
        const MAX_OPA_HEADERS: usize = 50;
        if self.opa.headers.len() > MAX_OPA_HEADERS {
            return Err(format!(
                "opa.headers has {} entries, max is {}",
                self.opa.headers.len(),
                MAX_OPA_HEADERS
            ));
        }
        // SECURITY (FIND-R80-008): Validate OPA header keys and values for CRLF injection
        // and control characters. Malicious header values with \r\n could inject additional
        // HTTP headers into upstream OPA requests.
        const MAX_OPA_HEADER_KEY_LEN: usize = 256;
        const MAX_OPA_HEADER_VALUE_LEN: usize = 4096;
        for (key, value) in &self.opa.headers {
            if key.len() > MAX_OPA_HEADER_KEY_LEN {
                return Err(format!(
                    "opa.headers key '{}...' exceeds max length ({} > {})",
                    &key[..key.len().min(32)],
                    key.len(),
                    MAX_OPA_HEADER_KEY_LEN,
                ));
            }
            if key.bytes().any(|b| b < 0x20 || b == 0x7F) {
                return Err(
                    "opa.headers key contains control or format characters (including CR/LF)"
                        .to_string(),
                );
            }
            if value.len() > MAX_OPA_HEADER_VALUE_LEN {
                return Err(format!(
                    "opa.headers value for key '{}' exceeds max length ({} > {})",
                    &key[..key.len().min(32)],
                    value.len(),
                    MAX_OPA_HEADER_VALUE_LEN,
                ));
            }
            if value.bytes().any(|b| b < 0x20 || b == 0x7F) {
                return Err(format!(
                    "opa.headers value for key '{}' contains control or format characters (including CR/LF)",
                    &key[..key.len().min(32)],
                ));
            }
        }

        // Threat intel validation
        if self.threat_intel.enabled {
            if self.threat_intel.provider.is_none() {
                return Err(
                    "threat_intel.provider is required when threat intel is enabled".to_string(),
                );
            }
            if self.threat_intel.endpoint.is_none() {
                return Err(
                    "threat_intel.endpoint is required when threat intel is enabled".to_string(),
                );
            }
            if self.threat_intel.min_confidence > 100 {
                return Err("threat_intel.min_confidence must be <= 100".to_string());
            }
            // SECURITY (FIND-R71-CFG-013): Validate on_match is a recognized action.
            // Unrecognized values could silently default to no-op, bypassing threat response.
            // SECURITY (BUG-R110-001): Case-insensitive, consistent with standalone validate().
            let valid_on_match = ["deny", "alert", "require_approval"];
            if !valid_on_match.contains(&self.threat_intel.on_match.to_lowercase().as_str()) {
                return Err(format!(
                    "threat_intel.on_match must be one of {:?}, got '{}'",
                    valid_on_match, self.threat_intel.on_match
                ));
            }
            // SECURITY (FIND-R102-004): Reject zero cache/refresh TTLs.
            // Zero cache_ttl means IOCs expire immediately, bypassing threat detection.
            // Zero refresh_interval means infinite-loop polling against feed endpoint.
            if self.threat_intel.cache_ttl_secs == 0 {
                return Err("threat_intel.cache_ttl_secs must be > 0".to_string());
            }
            if self.threat_intel.refresh_interval_secs == 0 {
                return Err("threat_intel.refresh_interval_secs must be > 0".to_string());
            }
        }

        // JIT access validation
        if self.jit_access.enabled {
            if self.jit_access.default_ttl_secs == 0 {
                return Err("jit_access.default_ttl_secs must be > 0".to_string());
            }
            if self.jit_access.max_ttl_secs < self.jit_access.default_ttl_secs {
                return Err(
                    "jit_access.max_ttl_secs must be >= jit_access.default_ttl_secs".to_string(),
                );
            }
            if self.jit_access.max_sessions_per_principal == 0 {
                return Err("jit_access.max_sessions_per_principal must be > 0".to_string());
            }
        }
        // SECURITY (FIND-R71-CFG-008): Bound allowed_elevations to prevent OOM.
        const MAX_JIT_ALLOWED_ELEVATIONS: usize = 100;
        if self.jit_access.allowed_elevations.len() > MAX_JIT_ALLOWED_ELEVATIONS {
            return Err(format!(
                "jit_access.allowed_elevations has {} entries, max is {}",
                self.jit_access.allowed_elevations.len(),
                MAX_JIT_ALLOWED_ELEVATIONS
            ));
        }
        // SECURITY (FIND-R71-CFG-011): Validate notification_webhook URL to prevent SSRF.
        // Require https:// scheme and reject private/loopback addresses.
        if let Some(ref webhook_url) = self.jit_access.notification_webhook {
            let trimmed = webhook_url.trim();
            if !trimmed.is_empty() {
                if !trimmed.starts_with("https://") {
                    return Err(
                        "jit_access.notification_webhook must use https:// scheme".to_string()
                    );
                }
                // SECURITY (IMP-R128-001): Delegate to canonical SSRF validation.
                // Previous inline code was missing IPv4-mapped IPv6 detection
                // (::ffff:10.x.x.x, ::ffff:169.254.x.x, etc.).
                vellaveto_types::validate_url_no_ssrf(trimmed)
                    .map_err(|e| format!("jit_access.notification_webhook {}", e))?;
            }
        }

        // Memory security validation
        // SECURITY (FIND-R174-002): Aligned with MemorySecurityConfig::validate()
        // in memory_nhi.rs which requires (0.0, 10.0]. The prior check allowed
        // zero and had no upper bound, creating a divergent validation path.
        if !self.memory_security.trust_decay_rate.is_finite()
            || self.memory_security.trust_decay_rate <= 0.0
            || self.memory_security.trust_decay_rate > 10.0
        {
            return Err(format!(
                "memory_security.trust_decay_rate must be in (0.0, 10.0], got {}",
                self.memory_security.trust_decay_rate
            ));
        }
        if !self.memory_security.trust_threshold.is_finite()
            || self.memory_security.trust_threshold < 0.0
            || self.memory_security.trust_threshold > 1.0
        {
            return Err(format!(
                "memory_security.trust_threshold must be in [0.0, 1.0], got {}",
                self.memory_security.trust_threshold
            ));
        }
        if self.memory_security.max_entries_per_session > MAX_MEMORY_ENTRIES_PER_SESSION {
            return Err(format!(
                "memory_security.max_entries_per_session must be <= {}, got {}",
                MAX_MEMORY_ENTRIES_PER_SESSION, self.memory_security.max_entries_per_session
            ));
        }
        if self.memory_security.max_provenance_nodes > MAX_MEMORY_PROVENANCE_NODES {
            return Err(format!(
                "memory_security.max_provenance_nodes must be <= {}, got {}",
                MAX_MEMORY_PROVENANCE_NODES, self.memory_security.max_provenance_nodes
            ));
        }
        if self.memory_security.max_fingerprints > MAX_MEMORY_FINGERPRINTS {
            return Err(format!(
                "memory_security.max_fingerprints must be <= {}, got {}",
                MAX_MEMORY_FINGERPRINTS, self.memory_security.max_fingerprints
            ));
        }
        if self.memory_security.max_memory_age_hours > MAX_MEMORY_AGE_HOURS {
            return Err(format!(
                "memory_security.max_memory_age_hours must be <= {}, got {}",
                MAX_MEMORY_AGE_HOURS, self.memory_security.max_memory_age_hours
            ));
        }
        if self.memory_security.enabled && self.memory_security.max_memory_age_hours == 0 {
            return Err(
                "memory_security.max_memory_age_hours must be > 0 when enabled".to_string(),
            );
        }
        if self.memory_security.namespaces.max_namespaces > MAX_MEMORY_NAMESPACES {
            return Err(format!(
                "memory_security.namespaces.max_namespaces must be <= {}, got {}",
                MAX_MEMORY_NAMESPACES, self.memory_security.namespaces.max_namespaces
            ));
        }
        if self.memory_security.namespaces.enabled {
            let valid_isolations = ["session", "agent", "shared"];
            if !valid_isolations
                .contains(&self.memory_security.namespaces.default_isolation.as_str())
            {
                return Err(format!(
                    "memory_security.namespaces.default_isolation must be one of {:?}, got '{}'",
                    valid_isolations, self.memory_security.namespaces.default_isolation
                ));
            }
        }

        // ═══════════════════════════════════════════════════
        // NHI VERIFICATION CONFIG VALIDATION
        // ═══════════════════════════════════════════════════
        if self.nhi.verification.enabled {
            let valid_tiers = [
                "unverified",
                "email_verified",
                "phone_verified",
                "did_verified",
                "fully_verified",
            ];
            if !valid_tiers.contains(&self.nhi.verification.default_tier.as_str()) {
                return Err(format!(
                    "nhi.verification.default_tier must be one of {:?}, got '{}'",
                    valid_tiers, self.nhi.verification.default_tier
                ));
            }
            if !valid_tiers.contains(&self.nhi.verification.global_minimum_tier.as_str()) {
                return Err(format!(
                    "nhi.verification.global_minimum_tier must be one of {:?}, got '{}'",
                    valid_tiers, self.nhi.verification.global_minimum_tier
                ));
            }
            if self.nhi.verification.max_attestations_per_identity == 0 {
                return Err(
                    "nhi.verification.max_attestations_per_identity must be > 0".to_string()
                );
            }
            if self.nhi.verification.attestation_ttl_secs == 0 {
                return Err("nhi.verification.attestation_ttl_secs must be > 0".to_string());
            }
        }

        // ═══════════════════════════════════════════════════
        // LIMITS VALIDATION (FIND-032 / FIND-036)
        // ═══════════════════════════════════════════════════
        // SECURITY (FIND-032): Reject zero values that would disable safety constraints.
        // SECURITY (FIND-036): Reject excessively large values that could cause OOM.
        self.limits.validate()?;

        // ═══════════════════════════════════════════════════
        // PHASE 15: OBSERVABILITY VALIDATION
        // ═══════════════════════════════════════════════════
        self.observability.validate()?;

        // ═══════════════════════════════════════════════════
        // OPA FAIL-OPEN SAFETY VALIDATION
        // ═══════════════════════════════════════════════════
        // SECURITY (R43-OPA-1): fail_open=true violates fail-closed principle.
        // Require explicit acknowledgment to prevent accidental misconfiguration.
        if self.opa.fail_open && !self.opa.fail_open_acknowledged {
            return Err(
                "opa.fail_open=true requires opa.fail_open_acknowledged=true. \
                 This ensures operators consciously accept that OPA unavailability \
                 will allow ALL requests to pass. Set fail_open_acknowledged=true \
                 only if you understand and accept this security risk."
                    .to_string(),
            );
        }

        // Compliance evidence configuration bounds
        self.compliance.validate()?;

        // Transport discovery & negotiation bounds
        self.transport.validate()?;

        // Gateway configuration bounds
        self.gateway.validate()?;

        // ABAC configuration bounds (Phase 21)
        self.abac.validate()?;

        // Governance configuration bounds (Phase 26)
        self.governance.validate()?;

        // Deployment configuration bounds (Phase 27)
        self.deployment.validate()?;

        // Discovery configuration bounds (Phase 34)
        self.discovery.validate()?;

        // Topology crawling configuration bounds
        self.topology.validate()?;

        // Projector configuration bounds (Phase 35.1)
        self.projector.validate()?;

        // ZK audit configuration bounds (Phase 37)
        self.zk_audit.validate()?;

        // Licensing and billing configuration bounds
        self.licensing.validate()?;
        self.billing.validate()?;

        // FIPS configuration validation (P4-001)
        self.fips.validate()?;

        // Extension registry configuration bounds
        self.extension.validate()?;

        // SECURITY (FIND-R75-005): MCP protocol configuration bounds.
        // Validate collection sizes on all MCP protocol config structs.
        self.elicitation.validate()?;
        self.sampling.validate()?;
        self.async_tasks.validate()?;
        self.resource_indicator.validate()?;
        self.cimd.validate()?;
        self.step_up_auth.validate()?;

        // MCP Streamable HTTP configuration bounds (Phase 30)
        self.streamable_http.validate()?;

        // Semantic guardrails configuration bounds (Phase 12)
        self.semantic_guardrails.validate()?;

        // RAG defense configuration bounds
        self.rag_defense.validate()?;

        // A2A protocol configuration bounds
        self.a2a.validate()?;

        // Cluster configuration bounds
        self.cluster.validate()?;

        // Supply chain configuration bounds
        self.supply_chain.validate()?;

        // Multimodal policy configuration bounds
        self.multimodal.validate()?;

        // SECURITY (IMP-R100-003): Memory security configuration bounds.
        self.memory_security.validate()?;

        // SECURITY (IMP-R100-004): Threat detection sub-config bounds.
        self.behavioral.validate()?;
        self.semantic_detection.validate()?;
        self.schema_poisoning.validate()?;
        self.cross_agent.validate()?;

        // SECURITY (FIND-R112-013): Circuit breaker and deputy sub-config bounds.
        self.circuit_breaker.validate()?;
        self.deputy.validate()?;

        // SECURITY (IMP-R100-005): NHI configuration bounds — anomaly_threshold
        // float range, Vec bounds, TTL consistency, string field validation.
        self.nhi.validate()?;

        // SECURITY (FIND-R100-009): Manifest path validation — length, control
        // characters, path traversal prevention.
        self.manifest.validate()?;

        // SECURITY (FIND-R100-012): Per-policy rule validation — field bounds
        // and control character rejection.
        for (i, rule) in self.policies.iter().enumerate() {
            rule.validate()
                .map_err(|e| format!("policies[{}]: {}", i, e))?;
        }

        // SECURITY (FIND-R180-001, FIND-R211-001): Wire sub-config validate()
        // methods unconditionally. Structural checks (SSRF, char validation, bounds)
        // must run even on disabled configs to prevent malicious values from
        // activating without validation when later enabled via hot-reload.
        // Individual validate() methods gate enabled-specific checks internally.
        self.tls.validate().map_err(|e| format!("tls: {e}"))?;
        // SECURITY (FIND-R211-001): Always run sub-config validate() regardless of
        // `enabled` flag. Structural checks (SSRF, char validation, bounds) must run
        // even on disabled configs to prevent malicious values from activating without
        // validation when later enabled via hot-reload. Each validate() method already
        // guards enabled-specific checks (like "endpoint is required when enabled")
        // internally.
        self.spiffe.validate().map_err(|e| format!("spiffe: {e}"))?;
        self.opa.validate().map_err(|e| format!("opa: {e}"))?;
        self.threat_intel
            .validate()
            .map_err(|e| format!("threat_intel: {e}"))?;
        self.jit_access
            .validate()
            .map_err(|e| format!("jit_access: {e}"))?;
        self.audit_export
            .validate()
            .map_err(|e| format!("audit_export: {e}"))?;

        // Centralized audit store configuration bounds (Phase 43)
        self.audit_store
            .validate()
            .map_err(|e| format!("audit_store: {e}"))?;

        self.iam.validate().map_err(|e| format!("iam: {e}"))?;

        // Policy lifecycle configuration bounds (Phase 47)
        self.policy_lifecycle
            .validate()
            .map_err(|e| format!("policy_lifecycle: {e}"))?;

        // Metering configuration bounds (Phase 50)
        self.metering
            .validate()
            .map_err(|e| format!("metering: {e}"))?;

        // Consumer shield configuration bounds
        self.shield.validate().map_err(|e| format!("shield: {e}"))?;

        Ok(())
    }

    /// Load config from a file path. Selects parser based on extension.
    ///
    /// Validates config bounds after parsing to prevent memory exhaustion
    /// from excessively large arrays.
    pub fn load_file(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // SECURITY (R9-5): Check file size before reading to prevent OOM
        // from maliciously large config files. 10 MB is generous for any
        // realistic policy configuration.
        const MAX_CONFIG_FILE_SIZE: u64 = 10 * 1024 * 1024;
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > MAX_CONFIG_FILE_SIZE {
            return Err(format!(
                "Config file '{}' is too large ({} bytes, max {} bytes)",
                path,
                metadata.len(),
                MAX_CONFIG_FILE_SIZE
            )
            .into());
        }
        let content = std::fs::read_to_string(path)?;
        // SECURITY: Empty/whitespace-only config files are almost always operator error.
        // Reject them explicitly instead of silently loading defaults.
        if content.trim().is_empty() {
            return Err(format!("Config file '{}' is empty", path).into());
        }
        // SECURITY (FIND-R46-014): Reject unknown file extensions instead of silently
        // falling back to TOML. Silent fallback can mask misconfiguration — e.g., a
        // YAML file being parsed as TOML without error but producing wrong results.
        let config = if path.ends_with(".toml") {
            Self::from_toml(&content)?
        } else if path.ends_with(".json") {
            Self::from_json(&content)?
        } else {
            return Err(format!(
                "Config file '{}' has unsupported extension. \
                 Supported extensions: .toml, .json",
                path
            )
            .into());
        };
        config
            .validate()
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
        Ok(config)
    }
}
