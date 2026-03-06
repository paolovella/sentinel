// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Core policy types — Action, Verdict, PolicyType, PathRules, NetworkRules,
//! IpRules, Policy, evaluation trace types, and validation.

use crate::threat::ValidationError;
use serde::{Deserialize, Serialize};

/// Maximum length for tool and function names (bytes).
const MAX_NAME_LEN: usize = 256;

/// Maximum length for individual path or domain strings (bytes).
const MAX_TARGET_LEN: usize = 4096;

/// Maximum number of combined `target_paths` + `target_domains` entries.
const MAX_TARGETS: usize = 256;

/// Maximum serialized size of `parameters` in bytes (1 MiB).
///
/// SECURITY (FIND-P3-016): Prevents memory exhaustion from oversized
/// parameter payloads. 1 MiB is generous for tool call parameters
/// while still bounding memory usage per-action.
const MAX_PARAMETERS_SIZE: usize = 1_048_576;

/// Returns true if the character is a Unicode format character (category Cf)
/// that could cause identity confusion or log injection.
///
/// SECURITY (FIND-R55-CORE-001, FIND-R56-CORE-001, FIND-R84-002): Covers zero-width
/// chars, bidi overrides, BOM, interlinear annotations, TAG characters, and soft
/// hyphen. Canonical implementation — other crates should import this via
/// `vellaveto_types::is_unicode_format_char()` instead of duplicating.
pub fn is_unicode_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}'              |  // soft hyphen
        '\u{0600}'..='\u{0605}' |  // R228-TYP-1: Arabic number/sign marks (Cf)
        '\u{061C}'              |  // R228-TYP-1: Arabic Letter Mark (invisible bidi)
        '\u{06DD}'              |  // R228-TYP-1: Arabic End of Ayah (Cf)
        '\u{070F}'              |  // R228-TYP-1: Syriac Abbreviation Mark (Cf)
        '\u{0890}'..='\u{0891}' |  // R228-TYP-1: Arabic Pound/Piastre Mark (Cf, Unicode 15.0+)
        '\u{08E2}'              |  // R228-TYP-1: Arabic Disputed End of Ayah (Cf)
        '\u{200B}'..='\u{200F}' |  // zero-width space, ZWNJ, ZWJ, LRM, RLM
        '\u{202A}'..='\u{202E}' |  // bidi overrides (LRE, RLE, PDF, LRO, RLO)
        '\u{2060}'..='\u{2069}' |  // word joiner, invisible separators, bidi isolates
        '\u{FEFF}'              |  // BOM / zero-width no-break space
        '\u{FFF9}'..='\u{FFFB}' |  // interlinear annotation anchors
        '\u{110BD}'             |  // R228-TYP-1: Kaithi Number Sign (Cf)
        '\u{110CD}'             |  // R228-TYP-1: Kaithi Number Sign Above (Cf)
        '\u{17B4}'..='\u{17B5}'    | // R230-TYP-2: Khmer invisible Cf chars
        '\u{180B}'..='\u{180F}'    | // R229-TYP-4: Mongolian Free Variation Selectors (Cf)
        '\u{1D173}'..='\u{1D17A}' | // R228-TYP-1: Musical Symbol format chars (Cf)
        '\u{FE00}'..='\u{FE0F}'   | // R230-TYP-1: Variation Selectors (VS1-VS16, Mn/Cf)
        '\u{E0001}'..='\u{E007F}'  // TAG characters
    )
}

/// Check whether a string contains control characters or Unicode format characters.
///
/// Returns `true` if the string contains any character that is control (`is_control()`)
/// or a Unicode format character (`is_unicode_format_char()`).
///
/// SECURITY (IMP-R120-008): Canonical predicate extracted from duplicate
/// `validate_no_dangerous_chars()` implementations in `accountability.rs`
/// and `capability_token.rs`.
pub fn has_dangerous_chars(s: &str) -> bool {
    s.chars()
        .any(|c| c.is_control() || is_unicode_format_char(c))
}

/// Sanitize a string for safe inclusion in log messages by stripping control
/// characters and Unicode format characters, then truncating to `max_len` chars.
///
/// SECURITY (IMP-R154-001): Extracted from 9+ duplicate sites in relay.rs,
/// federation.rs, and websocket handler. Canonical implementation prevents
/// log injection via control characters, bidi overrides, and zero-width chars.
///
/// # Examples
/// ```
/// assert_eq!(vellaveto_types::sanitize_for_log("hello\x00world", 128), "helloworld");
/// assert_eq!(vellaveto_types::sanitize_for_log("long string", 4), "long");
/// ```
pub fn sanitize_for_log(s: &str, max_len: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !is_unicode_format_char(*c))
        .take(max_len)
        .collect()
}

/// Recursively check a JSON value for control or Unicode format characters
/// in string values and object keys. Bounded by depth to prevent stack overflow.
///
/// SECURITY (IMP-R166-001): Canonical implementation extracted from duplicate
/// copies in gRPC service.rs and A2A proxy.rs. Returns `true` (fail-closed)
/// on excessive nesting (>64 levels).
///
/// # Examples
/// ```
/// use serde_json::json;
/// assert!(!vellaveto_types::json_has_dangerous_chars(&json!({"key": "safe"}), 0));
/// assert!(vellaveto_types::json_has_dangerous_chars(&json!({"key": "bad\x00"}), 0));
/// ```
pub fn json_has_dangerous_chars(val: &serde_json::Value, depth: usize) -> bool {
    if depth > 64 {
        return true; // fail-closed on excessive nesting
    }
    match val {
        serde_json::Value::String(s) => has_dangerous_chars(s),
        serde_json::Value::Array(arr) => arr.iter().any(|v| json_has_dangerous_chars(v, depth + 1)),
        serde_json::Value::Object(map) => {
            map.keys().any(|k| has_dangerous_chars(k))
                || map.values().any(|v| json_has_dangerous_chars(v, depth + 1))
        }
        _ => false,
    }
}

/// Check whether an IPv4 address is private/reserved for SSRF prevention.
///
/// SECURITY (FIND-R116-TE-001): Shared helper used by `validate_url_no_ssrf` for
/// both direct IPv4 checks and embedded IPv4 extraction from IPv6 transition
/// mechanisms (mapped, compatible, 6to4, Teredo, NAT64).
fn is_ssrf_private_ipv4(ip: &std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || o[0] == 10
        || (o[0] == 172 && (o[1] & 0xf0) == 16)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 169 && o[1] == 254)
        || o[0] == 0
        // IMP-R122-006: CGNAT range (100.64.0.0/10, RFC 6598)
        || (o[0] == 100 && (o[1] & 0xC0) == 64)
        // R229-TYP-3: Benchmarking range (198.18.0.0/15, RFC 2544)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        // R230-TYP-2: Multicast range (224.0.0.0/4, RFC 5771)
        // Includes all-hosts (224.0.0.1), all-routers (224.0.0.2), and SSM (232.0.0.0/8).
        // No legitimate webhook target uses multicast.
        || (o[0] >= 224 && o[0] <= 239)
        // R229-TYP-3: Reserved range (240.0.0.0/4, RFC 1112 §4)
        || o[0] >= 240
        || ip.is_broadcast()
}

/// R231-TYP-6: Percent-decode a host string for SSRF checks.
/// Decodes %XX sequences so that encoded IPs (e.g., %31%36%39.%32%35%34...)
/// are resolved to their literal form before validation.
fn percent_decode_host(host: &str) -> String {
    let bytes = host.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                out.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| host.to_string())
}

/// Convert an ASCII hex digit to its numeric value.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Validate a URL against SSRF vectors.
///
/// Rejects localhost, loopback, link-local, and private IP ranges in the
/// host portion of the URL. Requires `http://` or `https://` scheme.
///
/// SECURITY (IMP-R120-009): Canonical implementation extracted from duplicate
/// copies in `UpstreamBackend::validate_url_ssrf` (gateway.rs) and
/// `FederationTrustAnchor::validate_jwks_uri_ssrf` (abac.rs).
pub fn validate_url_no_ssrf(url: &str) -> Result<(), String> {
    // Extract the scheme-relative portion
    let after_scheme = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else {
        return Err("must use http(s) scheme".to_string());
    };

    // Extract authority (before first '/')
    let authority = after_scheme
        .find('/')
        .map_or(after_scheme, |i| &after_scheme[..i]);

    // Strip userinfo before '@'
    let host_portion = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };

    // Extract host (handle IPv6 brackets and port)
    let host = if host_portion.starts_with('[') {
        if let Some(bracket_end) = host_portion.find(']') {
            host_portion[1..bracket_end].to_lowercase()
        } else {
            return Err("malformed IPv6 address (missing ']')".to_string());
        }
    } else {
        let host_end = host_portion
            .find([':', '/', '?', '#'])
            .unwrap_or(host_portion.len());
        host_portion[..host_end].to_lowercase()
    };

    if host.is_empty() {
        return Err("has no host".to_string());
    }

    // R231-TYP-6: Percent-decode host before SSRF checks.
    // Without this, an attacker can encode the IP (e.g., %31%36%39.%32%35%34...)
    // to bypass private/metadata IP detection.
    let host = percent_decode_host(&host);

    // SECURITY (R228-TYP-3): Strip trailing DNS dot before loopback check.
    // RFC 1034 §3.1 permits FQDN trailing dots; "localhost." resolves to 127.0.0.1.
    let host_stripped = host.trim_end_matches('.');
    let loopbacks = ["localhost", "127.0.0.1", "::1", "0.0.0.0"];
    if loopbacks.contains(&host_stripped) {
        return Err(format!(
            "must not target localhost/loopback, got '{}'",
            host
        ));
    }

    // Reject private IPv4 ranges
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        if is_ssrf_private_ipv4(&ip) {
            return Err(format!(
                "must not target private/internal IPs, got '{}'",
                host
            ));
        }
    }

    // Reject private IPv6 ranges
    if let Ok(ip6) = host.parse::<std::net::Ipv6Addr>() {
        let segs = ip6.segments();
        let is_private = ip6.is_loopback()
            || ip6.is_unspecified()
            || (segs[0] & 0xfe00) == 0xfc00
            || (segs[0] & 0xffc0) == 0xfe80
            // R230-TYP-1: IPv6 multicast (ff00::/8, RFC 4291 §2.7).
            // Includes link-local multicast (ff02::), site-local (ff05::),
            // and organization-scope (ff08::). No legitimate webhook target.
            || (segs[0] & 0xff00) == 0xff00;
        if is_private {
            return Err(format!(
                "must not target private/internal IPv6 ranges, got '{}'",
                host
            ));
        }

        // SECURITY (IMP-R126-004): Reject IPv4-mapped IPv6 addresses
        // (::ffff:x.x.x.x) that wrap private IPv4 ranges to bypass the
        // IPv4 checks above.
        let is_ipv4_mapped = segs[0] == 0
            && segs[1] == 0
            && segs[2] == 0
            && segs[3] == 0
            && segs[4] == 0
            && segs[5] == 0xffff;
        if is_ipv4_mapped {
            let mapped = std::net::Ipv4Addr::new(
                (segs[6] >> 8) as u8,
                segs[6] as u8,
                (segs[7] >> 8) as u8,
                segs[7] as u8,
            );
            if is_ssrf_private_ipv4(&mapped) {
                return Err(format!(
                    "must not target IPv4-mapped private addresses, got '{}'",
                    host
                ));
            }
        }

        // SECURITY (FIND-R116-TE-001): IPv4-compatible IPv6 (::x.x.x.x)
        // Deprecated (RFC 4291 §2.5.5.1) but still routable on some systems.
        // First 96 bits zero, last 32 bits are IPv4.
        let is_ipv4_compatible = segs[0] == 0
            && segs[1] == 0
            && segs[2] == 0
            && segs[3] == 0
            && segs[4] == 0
            && segs[5] == 0
            && !(segs[6] == 0 && segs[7] <= 1); // Skip ::0 and ::1
        if is_ipv4_compatible {
            let embedded = std::net::Ipv4Addr::new(
                (segs[6] >> 8) as u8,
                (segs[6] & 0xff) as u8,
                (segs[7] >> 8) as u8,
                (segs[7] & 0xff) as u8,
            );
            if is_ssrf_private_ipv4(&embedded) {
                return Err(format!(
                    "must not target IPv4-compatible private addresses, got '{}'",
                    host
                ));
            }
        }

        // SECURITY (FIND-R116-TE-001): 6to4 addresses (2002::/16, RFC 3056)
        // Embedded IPv4 is in segments 1-2 (bits 16-47).
        if segs[0] == 0x2002 {
            let embedded = std::net::Ipv4Addr::new(
                (segs[1] >> 8) as u8,
                (segs[1] & 0xff) as u8,
                (segs[2] >> 8) as u8,
                (segs[2] & 0xff) as u8,
            );
            if is_ssrf_private_ipv4(&embedded) {
                return Err(format!(
                    "must not target 6to4 addresses with embedded private IPv4, got '{}'",
                    host
                ));
            }
        }

        // SECURITY (FIND-R116-TE-001): Teredo addresses (2001:0000::/32, RFC 4380)
        // Embedded client IPv4 is in segments 6-7, XORed with 0xFFFF per RFC 4380.
        if segs[0] == 0x2001 && segs[1] == 0 {
            let embedded = std::net::Ipv4Addr::new(
                ((segs[6] >> 8) ^ 0xff) as u8,
                ((segs[6] & 0xff) ^ 0xff) as u8,
                ((segs[7] >> 8) ^ 0xff) as u8,
                ((segs[7] & 0xff) ^ 0xff) as u8,
            );
            if is_ssrf_private_ipv4(&embedded) {
                return Err(format!(
                    "must not target Teredo addresses with embedded private IPv4, got '{}'",
                    host
                ));
            }
        }

        // SECURITY (FIND-R116-TE-001): NAT64 well-known prefix (64:ff9b::/96, RFC 6052)
        // Embedded IPv4 is in segments 6-7.
        if segs[0] == 0x0064
            && segs[1] == 0xff9b
            && segs[2] == 0
            && segs[3] == 0
            && segs[4] == 0
            && segs[5] == 0
        {
            let embedded = std::net::Ipv4Addr::new(
                (segs[6] >> 8) as u8,
                (segs[6] & 0xff) as u8,
                (segs[7] >> 8) as u8,
                (segs[7] & 0xff) as u8,
            );
            if is_ssrf_private_ipv4(&embedded) {
                return Err(format!(
                    "must not target NAT64 addresses with embedded private IPv4, got '{}'",
                    host
                ));
            }
        }

        // SECURITY (FIND-R116-TE-001): NAT64 local-use prefix (64:ff9b:1::/48, RFC 8215)
        // Embedded IPv4 is in segments 6-7.
        if segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2] == 0x0001 {
            let embedded = std::net::Ipv4Addr::new(
                (segs[6] >> 8) as u8,
                (segs[6] & 0xff) as u8,
                (segs[7] >> 8) as u8,
                (segs[7] & 0xff) as u8,
            );
            if is_ssrf_private_ipv4(&embedded) {
                return Err(format!(
                    "must not target NAT64 local-use addresses with embedded private IPv4, got '{}'",
                    host
                ));
            }
        }
    }

    Ok(())
}

/// Validate a single name field (tool or function).
///
/// This is `pub(crate)` intentionally — external callers should use
/// [`Action::validated`] or [`Action::validate`] which call this internally.
/// Keeping it crate-private avoids exposing an internal validation primitive
/// in the public API surface.
pub(crate) fn validate_name(value: &str, field: &'static str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::EmptyField { field });
    }
    if value.contains('\0') {
        return Err(ValidationError::NullByte { field });
    }
    if value.len() > MAX_NAME_LEN {
        return Err(ValidationError::TooLong {
            field,
            len: value.len(),
            max: MAX_NAME_LEN,
        });
    }
    // SECURITY (R12-TYPES-1): Reject names with control characters or
    // that are whitespace-only. Prevents homoglyph/invisible-char bypass
    // and log confusion.
    if value.trim().is_empty() {
        return Err(ValidationError::EmptyField { field });
    }
    // SECURITY (R16-TYPES-1, FIND-R55-CORE-001): Reject control characters
    // and Unicode format characters (zero-width, bidi overrides, BOM) that
    // could cause identity confusion or bypass pattern matching.
    // Note: '\0' is excluded from the control char check here because null
    // bytes are caught above with the specific NullByte error variant (FIND-R56-CORE-005).
    if value
        .chars()
        .any(|c| (c.is_control() && c != '\0') || is_unicode_format_char(c))
    {
        return Err(ValidationError::ControlCharacter { field });
    }
    Ok(())
}

/// A tool-call action submitted for policy evaluation.
///
/// Represents a single invocation of a tool function with its parameters
/// and optional target paths/domains. This is the primary input to the
/// policy engine's `evaluate()` method.
///
/// Use [`Action::validated`] or [`Action::validate`] at trust boundaries
/// (MCP extractor, HTTP proxy) to enforce structural invariants before
/// evaluation.
/// SECURITY (FIND-R224-001): deny_unknown_fields prevents deserialization of
/// payloads with unexpected fields, which could indicate misconfiguration or
/// injection of attacker-controlled data that would silently be ignored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub tool: String,
    pub function: String,
    pub parameters: serde_json::Value,
    /// File paths targeted by this action (e.g. from `file://` URIs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_paths: Vec<String>,
    /// Domains targeted by this action (e.g. from `https://` URIs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_domains: Vec<String>,
    /// IP addresses resolved from `target_domains` (populated by proxy layer).
    /// Used by the engine for DNS rebinding protection when [`IpRules`] are configured.
    ///
    /// # Security
    ///
    /// This field MUST only be set by the proxy layer after performing DNS resolution.
    /// If set by an untrusted client, an attacker could provide fake resolved IPs to
    /// bypass IP-based access controls (e.g., claiming a private IP is a public one).
    /// The proxy layer should always overwrite any client-supplied `resolved_ips`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_ips: Vec<String>,
}

impl Action {
    /// Create an Action with only tool, function, and parameters.
    /// `target_paths` and `target_domains` default to empty.
    ///
    /// Does NOT validate inputs — use [`Action::validated`] or [`Action::validate`]
    /// at trust boundaries (MCP extractor, HTTP proxy).
    pub fn new(
        tool: impl Into<String>,
        function: impl Into<String>,
        parameters: serde_json::Value,
    ) -> Self {
        Self {
            tool: tool.into(),
            function: function.into(),
            parameters,
            target_paths: Vec::new(),
            target_domains: Vec::new(),
            resolved_ips: Vec::new(),
        }
    }

    /// Create an Action with validation on tool and function names.
    ///
    /// Rejects empty names, null bytes, and names exceeding 256 bytes.
    /// Use this at trust boundaries where inputs come from external sources.
    pub fn validated(
        tool: impl Into<String>,
        function: impl Into<String>,
        parameters: serde_json::Value,
    ) -> Result<Self, ValidationError> {
        let tool = tool.into();
        let function = function.into();
        validate_name(&tool, "tool")?;
        validate_name(&function, "function")?;
        Ok(Self {
            tool,
            function,
            parameters,
            target_paths: Vec::new(),
            target_domains: Vec::new(),
            resolved_ips: Vec::new(),
        })
    }

    /// Validate an existing Action's fields.
    ///
    /// Checks tool/function names, parameters size, and
    /// `target_paths`/`target_domains` for null bytes, excessive length,
    /// and total count.
    ///
    /// # Error type
    ///
    /// Returns [`ValidationError`] (a structured enum) rather than `String`
    /// so callers can programmatically match on specific failure kinds
    /// (e.g., `NullByte`, `TooLong`, `ParametersTooLarge`). Other `validate()`
    /// methods in this crate return `Result<(), String>` because they were
    /// added later and their errors are purely diagnostic.
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_name(&self.tool, "tool")?;
        validate_name(&self.function, "function")?;

        // SECURITY (FIND-P3-016): Bound parameters size to prevent memory exhaustion.
        // SECURITY (FIND-R48-001): Fail-closed when serialization fails — reject rather
        // than silently skipping the size check.
        match serde_json::to_string(&self.parameters) {
            Ok(serialized) => {
                if serialized.len() > MAX_PARAMETERS_SIZE {
                    return Err(ValidationError::ParametersTooLarge {
                        size: serialized.len(),
                        max: MAX_PARAMETERS_SIZE,
                    });
                }
            }
            Err(_) => {
                return Err(ValidationError::ParametersTooLarge {
                    size: 0,
                    max: MAX_PARAMETERS_SIZE,
                });
            }
        }

        // Check combined target count (R39-ENG-4: include resolved_ips)
        let total_targets =
            self.target_paths.len() + self.target_domains.len() + self.resolved_ips.len();
        if total_targets > MAX_TARGETS {
            return Err(ValidationError::TooManyTargets {
                count: total_targets,
                max: MAX_TARGETS,
            });
        }

        // Validate individual target_paths
        for (i, path) in self.target_paths.iter().enumerate() {
            if path.contains('\0') {
                return Err(ValidationError::TargetNullByte {
                    field: "target_paths",
                    index: i,
                });
            }
            if path.len() > MAX_TARGET_LEN {
                return Err(ValidationError::TargetTooLong {
                    field: "target_paths",
                    index: i,
                    len: path.len(),
                    max: MAX_TARGET_LEN,
                });
            }
            // SECURITY (P3-CORE-002): Reject control characters and Unicode format
            // characters (zero-width, bidi overrides, BOM) in target paths.
            // A path like "/tmp/\x0Afoo" could bypass path-matching policies that
            // do not expect control characters in the middle of a path string.
            if path
                .chars()
                .any(|c| (c.is_control() && c != '\0') || is_unicode_format_char(c))
            {
                return Err(ValidationError::ControlCharacter {
                    field: "target_paths",
                });
            }
        }

        // Validate individual target_domains
        for (i, domain) in self.target_domains.iter().enumerate() {
            if domain.contains('\0') {
                return Err(ValidationError::TargetNullByte {
                    field: "target_domains",
                    index: i,
                });
            }
            if domain.len() > MAX_TARGET_LEN {
                return Err(ValidationError::TargetTooLong {
                    field: "target_domains",
                    index: i,
                    len: domain.len(),
                    max: MAX_TARGET_LEN,
                });
            }
            // SECURITY (P3-CORE-002): Reject control characters and Unicode format
            // characters in target domains. A domain like "evil\x0ahost.com" could
            // bypass domain-matching policies or cause log injection.
            if domain
                .chars()
                .any(|c| (c.is_control() && c != '\0') || is_unicode_format_char(c))
            {
                return Err(ValidationError::ControlCharacter {
                    field: "target_domains",
                });
            }
        }

        // SECURITY (R42-TYPES-1): Validate resolved_ips contents (null bytes, length).
        // Previously only counted toward MAX_TARGETS but contents were not checked,
        // unlike target_paths and target_domains which validate null bytes and length.
        for (i, ip) in self.resolved_ips.iter().enumerate() {
            if ip.contains('\0') {
                return Err(ValidationError::TargetNullByte {
                    field: "resolved_ips",
                    index: i,
                });
            }
            if ip.len() > MAX_TARGET_LEN {
                return Err(ValidationError::TargetTooLong {
                    field: "resolved_ips",
                    index: i,
                    len: ip.len(),
                    max: MAX_TARGET_LEN,
                });
            }
            // SECURITY (FIND-R116-TE-002): Reject control characters and Unicode format
            // characters in resolved_ips, matching the validation applied to target_paths
            // and target_domains. An IP like "10.0.0\x0a.1" could bypass IP-matching
            // policies or cause log injection.
            if ip
                .chars()
                .any(|c| (c.is_control() && c != '\0') || is_unicode_format_char(c))
            {
                return Err(ValidationError::ControlCharacter {
                    field: "resolved_ips",
                });
            }
        }

        Ok(())
    }
}

/// Result of policy evaluation for an [`Action`].
///
/// - `Allow` — the action is permitted.
/// - `Deny` — the action is blocked, with a human-readable reason.
/// - `RequireApproval` — the action needs explicit operator approval before proceeding.
///
/// Marked `#[non_exhaustive]` to allow future variants without breaking downstream matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
#[must_use = "security verdicts must not be discarded"]
pub enum Verdict {
    Allow,
    Deny { reason: String },
    RequireApproval { reason: String },
}

/// The disposition of a [`Policy`] — whether it allows, denies, or conditionally
/// gates actions.
///
/// - `Allow` — matching actions are permitted.
/// - `Deny` — matching actions are blocked.
/// - `Conditional` — matching actions are evaluated against a JSON condition tree
///   (see context-aware policy evaluation in the engine).
///
/// Marked `#[non_exhaustive]` to allow future variants without breaking downstream matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum PolicyType {
    Allow,
    Deny,
    Conditional { conditions: serde_json::Value },
}

/// Path-based access control rules for file system operations.
/// SECURITY (FIND-R46-015): deny_unknown_fields prevents misconfiguration
/// where a typo (e.g. "allow" instead of "allowed") would silently produce
/// an empty allowlist, which is a fail-open condition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct PathRules {
    /// Glob patterns for allowed paths. If non-empty, only matching paths are allowed.
    #[serde(default)]
    pub allowed: Vec<String>,
    /// Glob patterns for blocked paths. Any match results in denial.
    #[serde(default)]
    pub blocked: Vec<String>,
}

/// Network-based access control rules for outbound connections.
/// SECURITY (FIND-R46-015): deny_unknown_fields prevents misconfiguration
/// where a typo (e.g. "allowed_domain" instead of "allowed_domains") would
/// silently produce an empty allowlist, which is a fail-open condition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkRules {
    /// Domain patterns for allowed destinations. If non-empty, only matching domains are allowed.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Domain patterns for blocked destinations. Any match results in denial.
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    /// IP-level access control for DNS rebinding protection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_rules: Option<IpRules>,
}

/// IP-level access control rules (DNS rebinding protection).
///
/// When configured, the proxy layer resolves target domains to IP addresses
/// and the engine checks them against these rules. This prevents attacks
/// where an allowed domain's DNS record changes to point at a private IP.
/// SECURITY (FIND-R46-015): deny_unknown_fields prevents misconfiguration
/// where a typo (e.g. "blocked_cidr" instead of "blocked_cidrs") would
/// silently skip IP blocking rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct IpRules {
    /// Block connections to private/reserved IPs (RFC 1918, loopback, link-local).
    #[serde(default)]
    pub block_private: bool,
    /// CIDR ranges to block (e.g. "10.0.0.0/8").
    #[serde(default)]
    pub blocked_cidrs: Vec<String>,
    /// CIDR ranges to allow. If non-empty, only matching IPs are allowed.
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
}

/// A security policy that governs whether an [`Action`] is allowed, denied,
/// or requires approval.
///
/// Policies are matched against actions by the engine in priority order
/// (higher `priority` value = evaluated first). Each policy may include
/// optional [`PathRules`] and [`NetworkRules`] for fine-grained access control.
///
/// # Validation
///
/// Call [`Policy::validate()`] after deserialization to enforce structural
/// invariants (non-empty id/name, non-negative priority, bounded conditions).
// SECURITY (FIND-R48-011): deny_unknown_fields catches typos like "network_rule"
// that would silently result in missing security rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub policy_type: PolicyType,
    pub priority: i32,
    /// Optional path-based access control rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_rules: Option<PathRules>,
    /// Optional network-based access control rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_rules: Option<NetworkRules>,
}

/// Maximum length for policy id (bytes).
/// SECURITY (FIND-R55-CORE-012): Bounds policy identifier length.
const MAX_POLICY_ID_LEN: usize = 256;
/// Maximum length for policy name (bytes).
/// SECURITY (FIND-R55-CORE-012): Bounds policy display name length.
const MAX_POLICY_NAME_LEN: usize = 512;

/// Maximum serialized size of `Conditional` conditions in bytes (64 KiB).
///
/// SECURITY (FIND-R49-003, FIND-R56-CORE-003, FIND-R111-004): Prevents memory exhaustion
/// via deeply nested or excessively large JSON condition values. Published so that
/// `vellaveto-engine`'s compile_conditions() uses the same canonical limit as
/// `Policy::validate()`, preventing a dual-limit bypass via the compile path.
pub const MAX_CONDITIONS_SIZE: usize = 65_536;

/// Maximum number of entries in `PathRules.allowed` or `PathRules.blocked`.
///
/// SECURITY (P3-CORE-001): Prevents memory exhaustion from operator-supplied
/// configurations with pathologically many path rules.
const MAX_PATH_RULES: usize = 1_000;

/// Maximum number of entries in `NetworkRules.allowed_domains` or
/// `NetworkRules.blocked_domains`.
///
/// SECURITY (P3-CORE-001): Prevents memory exhaustion from operator-supplied
/// configurations with pathologically many domain rules.
const MAX_DOMAIN_RULES: usize = 1_000;

/// Maximum number of entries in `IpRules.blocked_cidrs` or `IpRules.allowed_cidrs`.
///
/// SECURITY (P3-CORE-001): Prevents memory exhaustion from operator-supplied
/// configurations with pathologically many CIDR rules.
const MAX_CIDR_RULES: usize = 500;

impl Policy {
    /// Validate structural invariants of a `Policy`.
    ///
    /// Checks:
    /// - `id` is not empty, max 256 bytes, no control/format chars
    /// - `name` is not empty, max 512 bytes, no control/format chars
    /// - `priority` is non-negative (>= 0)
    ///
    /// SECURITY (FIND-P2-008): Policies with empty IDs could collide in
    /// lookups; empty names hamper audit legibility; negative priorities
    /// could invert evaluation ordering expectations.
    /// SECURITY (FIND-R55-CORE-012): Validate id and name for control characters,
    /// Unicode format characters, and length bounds to prevent log injection
    /// and memory abuse via oversized policy identifiers.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("Policy id must not be empty".to_string());
        }
        if self.id.len() > MAX_POLICY_ID_LEN {
            return Err(format!(
                "Policy id length {} exceeds max {}",
                self.id.len(),
                MAX_POLICY_ID_LEN
            ));
        }
        if self
            .id
            .chars()
            .any(|c| c.is_control() || is_unicode_format_char(c))
        {
            return Err("Policy id contains control or format characters".to_string());
        }
        if self.name.is_empty() {
            return Err(format!("Policy '{}' name must not be empty", self.id));
        }
        if self.name.len() > MAX_POLICY_NAME_LEN {
            return Err(format!(
                "Policy '{}' name length {} exceeds max {}",
                self.id,
                self.name.len(),
                MAX_POLICY_NAME_LEN
            ));
        }
        if self
            .name
            .chars()
            .any(|c| c.is_control() || is_unicode_format_char(c))
        {
            return Err(format!(
                "Policy '{}' name contains control or format characters",
                self.id
            ));
        }
        // NOTE: Negative priorities are valid — they indicate lower precedence.
        // The engine's 3-level deterministic tiebreaker handles priority ordering.
        // SECURITY (FIND-R49-003): Reject oversized Conditional conditions to prevent
        // memory exhaustion via deeply nested or excessively large JSON values.
        if let PolicyType::Conditional { ref conditions } = self.policy_type {
            let serialized = serde_json::to_string(conditions).map_err(|e| {
                format!(
                    "Policy '{}' Conditional conditions failed to serialize: {}",
                    self.id, e
                )
            })?;
            if serialized.len() > MAX_CONDITIONS_SIZE {
                return Err(format!(
                    "Policy '{}' Conditional conditions exceed {} bytes (got {})",
                    self.id,
                    MAX_CONDITIONS_SIZE,
                    serialized.len()
                ));
            }
        }
        // SECURITY (P3-CORE-001): Validate path_rules and network_rules collection sizes
        // to prevent memory exhaustion from operator-supplied configurations with
        // pathologically many rules. These checks are at validate() time (config load)
        // so they do not affect hot-path evaluation latency.
        if let Some(ref pr) = self.path_rules {
            if pr.allowed.len() > MAX_PATH_RULES {
                return Err(format!(
                    "Policy '{}' path_rules.allowed exceeds {} entries (got {})",
                    self.id,
                    MAX_PATH_RULES,
                    pr.allowed.len()
                ));
            }
            if pr.blocked.len() > MAX_PATH_RULES {
                return Err(format!(
                    "Policy '{}' path_rules.blocked exceeds {} entries (got {})",
                    self.id,
                    MAX_PATH_RULES,
                    pr.blocked.len()
                ));
            }
            // SECURITY (R229-TYP-1): Per-entry content validation for path rules.
            for (i, entry) in pr.allowed.iter().enumerate() {
                if has_dangerous_chars(entry) {
                    return Err(format!(
                        "Policy '{}' path_rules.allowed[{}] contains control or format characters",
                        self.id, i,
                    ));
                }
            }
            for (i, entry) in pr.blocked.iter().enumerate() {
                if has_dangerous_chars(entry) {
                    return Err(format!(
                        "Policy '{}' path_rules.blocked[{}] contains control or format characters",
                        self.id, i,
                    ));
                }
            }
        }
        if let Some(ref nr) = self.network_rules {
            if nr.allowed_domains.len() > MAX_DOMAIN_RULES {
                return Err(format!(
                    "Policy '{}' network_rules.allowed_domains exceeds {} entries (got {})",
                    self.id,
                    MAX_DOMAIN_RULES,
                    nr.allowed_domains.len()
                ));
            }
            if nr.blocked_domains.len() > MAX_DOMAIN_RULES {
                return Err(format!(
                    "Policy '{}' network_rules.blocked_domains exceeds {} entries (got {})",
                    self.id,
                    MAX_DOMAIN_RULES,
                    nr.blocked_domains.len()
                ));
            }
            // SECURITY (R229-TYP-1): Per-entry content validation for domain rules.
            for (i, entry) in nr.allowed_domains.iter().enumerate() {
                if has_dangerous_chars(entry) {
                    return Err(format!(
                        "Policy '{}' network_rules.allowed_domains[{}] contains control or format characters",
                        self.id, i,
                    ));
                }
            }
            for (i, entry) in nr.blocked_domains.iter().enumerate() {
                if has_dangerous_chars(entry) {
                    return Err(format!(
                        "Policy '{}' network_rules.blocked_domains[{}] contains control or format characters",
                        self.id, i,
                    ));
                }
            }
            if let Some(ref ip) = nr.ip_rules {
                if ip.blocked_cidrs.len() > MAX_CIDR_RULES {
                    return Err(format!(
                        "Policy '{}' ip_rules.blocked_cidrs exceeds {} entries (got {})",
                        self.id,
                        MAX_CIDR_RULES,
                        ip.blocked_cidrs.len()
                    ));
                }
                if ip.allowed_cidrs.len() > MAX_CIDR_RULES {
                    return Err(format!(
                        "Policy '{}' ip_rules.allowed_cidrs exceeds {} entries (got {})",
                        self.id,
                        MAX_CIDR_RULES,
                        ip.allowed_cidrs.len()
                    ));
                }
                // SECURITY (R229-TYP-1): Per-entry content validation for CIDR rules.
                for (i, entry) in ip.blocked_cidrs.iter().enumerate() {
                    if has_dangerous_chars(entry) {
                        return Err(format!(
                            "Policy '{}' ip_rules.blocked_cidrs[{}] contains control or format characters",
                            self.id, i,
                        ));
                    }
                }
                for (i, entry) in ip.allowed_cidrs.iter().enumerate() {
                    if has_dangerous_chars(entry) {
                        return Err(format!(
                            "Policy '{}' ip_rules.allowed_cidrs[{}] contains control or format characters",
                            self.id, i,
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// MCP 2025-11-25 TOOL NAME VALIDATION (Phase 30)
// ═══════════════════════════════════════════════════

/// Maximum length for MCP 2025-11-25 tool names.
const MCP_TOOL_NAME_MAX_LEN: usize = 64;

/// Validate a tool name per MCP 2025-11-25 specification.
///
/// Rules:
/// - Length: 1–64 characters
/// - Charset: `[a-zA-Z0-9_\-./]`
/// - No leading/trailing dots or slashes
/// - No consecutive dots (`..`) — prevents path traversal in tool namespaces
///
/// Returns `Ok(())` on valid names, `Err(description)` on invalid.
pub fn validate_mcp_tool_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("tool name must not be empty".to_string());
    }
    if name.len() > MCP_TOOL_NAME_MAX_LEN {
        return Err(format!(
            "tool name exceeds {} characters (got {})",
            MCP_TOOL_NAME_MAX_LEN,
            name.len()
        ));
    }
    // Charset: only [a-zA-Z0-9_\-./]
    for (i, ch) in name.chars().enumerate() {
        if !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '.' | '/') {
            // SECURITY (FIND-R73-002): Use escape_debug to prevent control char injection
            // into error messages (log injection, terminal escape codes).
            return Err(format!(
                "invalid character '{}' at position {} (allowed: a-zA-Z0-9_-./)",
                ch.escape_debug(),
                i
            ));
        }
    }
    // No leading/trailing dots or slashes
    if name.starts_with('.') || name.starts_with('/') {
        return Err("tool name must not start with '.' or '/'".to_string());
    }
    if name.ends_with('.') || name.ends_with('/') {
        return Err("tool name must not end with '.' or '/'".to_string());
    }
    // No consecutive dots (path traversal prevention)
    if name.contains("..") {
        return Err("tool name must not contain consecutive dots '..'".to_string());
    }
    // No consecutive slashes (path normalization ambiguity)
    if name.contains("//") {
        return Err("tool name must not contain consecutive slashes '//'".to_string());
    }
    Ok(())
}

// ═══════════════════════════════════════════════════
// EVALUATION TRACE TYPES (Phase 10.4)
// ═══════════════════════════════════════════════════

/// Full evaluation trace for a single action evaluation.
///
/// Returned by `PolicyEngine::evaluate_action_traced()` when callers need
/// OPA-style decision explanations (e.g. `?trace=true` on the HTTP proxy).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationTrace {
    pub action_summary: ActionSummary,
    pub policies_checked: usize,
    pub policies_matched: usize,
    pub matches: Vec<PolicyMatch>,
    pub verdict: Verdict,
    pub duration_us: u64,
}

/// Summary of the action being evaluated (no raw parameter values for security).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSummary {
    pub tool: String,
    pub function: String,
    pub param_count: usize,
    pub param_keys: Vec<String>,
}

/// Per-policy evaluation result within a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMatch {
    pub policy_id: String,
    pub policy_name: String,
    pub policy_type: String,
    pub priority: i32,
    pub tool_matched: bool,
    pub constraint_results: Vec<ConstraintResult>,
    pub verdict_contribution: Option<Verdict>,
}

/// Individual constraint evaluation result within a policy match.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintResult {
    pub constraint_type: String,
    pub param: String,
    pub expected: String,
    pub actual: String,
    pub passed: bool,
}

// ═══════════════════════════════════════════════════
// VERDICT EXPLANATION (Phase 24 — Art 50(2))
// ═══════════════════════════════════════════════════

/// Structured decision explanation for Art 50(2) transparency.
///
/// Transforms an `EvaluationTrace` into a consumer-facing explanation
/// at configurable verbosity levels.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictExplanation {
    /// Final verdict string ("Allow", "Deny", "RequireApproval").
    pub verdict: String,
    /// Human-readable reason (from Deny/RequireApproval).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Number of policies checked.
    pub policies_checked: usize,
    /// Number of policies that matched.
    pub policies_matched: usize,
    /// Evaluation duration in microseconds.
    pub duration_us: u64,
    /// Per-policy match details (only present at Full verbosity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_details: Option<Vec<PolicyMatchDetail>>,
}

/// Per-policy match detail within a verdict explanation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMatchDetail {
    /// Policy identifier.
    pub policy_id: String,
    /// Policy display name.
    pub policy_name: String,
    /// Policy priority.
    pub priority: i32,
    /// How this policy contributed to the final verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_contribution: Option<String>,
    /// Constraints that failed evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_constraints: Option<Vec<String>>,
}

impl VerdictExplanation {
    /// Build a summary explanation (verdict + reason + counts, no policy details).
    pub fn summary(trace: &EvaluationTrace) -> Self {
        let (verdict_str, reason) = Self::extract_verdict_info(&trace.verdict);
        Self {
            verdict: verdict_str,
            reason,
            policies_checked: trace.policies_checked,
            policies_matched: trace.policies_matched,
            duration_us: trace.duration_us,
            policy_details: None,
        }
    }

    /// Build a full explanation including per-policy match details.
    pub fn full(trace: &EvaluationTrace) -> Self {
        let (verdict_str, reason) = Self::extract_verdict_info(&trace.verdict);
        let details: Vec<PolicyMatchDetail> = trace
            .matches
            .iter()
            .map(|m| {
                let failed: Vec<String> = m
                    .constraint_results
                    .iter()
                    .filter(|c| !c.passed)
                    .map(|c| {
                        format!(
                            "{}: expected {} got {}",
                            c.constraint_type, c.expected, c.actual
                        )
                    })
                    .collect();
                let contribution = m.verdict_contribution.as_ref().map(|v| format!("{:?}", v));
                PolicyMatchDetail {
                    policy_id: m.policy_id.clone(),
                    policy_name: m.policy_name.clone(),
                    priority: m.priority,
                    verdict_contribution: contribution,
                    failed_constraints: if failed.is_empty() {
                        None
                    } else {
                        Some(failed)
                    },
                }
            })
            .collect();
        Self {
            verdict: verdict_str,
            reason,
            policies_checked: trace.policies_checked,
            policies_matched: trace.policies_matched,
            duration_us: trace.duration_us,
            policy_details: Some(details),
        }
    }

    #[allow(unreachable_patterns)] // Verdict is #[non_exhaustive]
    fn extract_verdict_info(verdict: &Verdict) -> (String, Option<String>) {
        match verdict {
            Verdict::Allow => ("Allow".to_string(), None),
            Verdict::Deny { reason } => ("Deny".to_string(), Some(reason.clone())),
            Verdict::RequireApproval { reason } => {
                ("RequireApproval".to_string(), Some(reason.clone()))
            }
            _ => ("Unknown".to_string(), None),
        }
    }
}
