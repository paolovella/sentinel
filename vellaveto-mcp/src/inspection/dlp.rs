// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Data Loss Prevention (DLP) scanning for secret detection.
//!
//! This module provides pattern-based detection of secrets (API keys, tokens,
//! credentials) in MCP tool call parameters and responses. Addresses OWASP ASI03
//! (Privilege Abuse) where a compromised agent attempts to exfiltrate credentials.

use std::collections::HashSet;
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

/// Shared compiled DLP regexes (FIND-009: single instance for all scanning functions).
///
/// Previously each scanning function had its own OnceLock, causing:
/// 1. Duplicate "CRITICAL" log messages if a pattern fails to compile
/// 2. Risk of divergent pattern coverage if initialization logic differed
/// 3. ~4x memory usage for identical compiled regex automata
///
/// This single shared static eliminates all three issues.
static DLP_REGEXES: OnceLock<Vec<(&'static str, regex::Regex)>> = OnceLock::new();
/// Count of DLP patterns that failed to compile (FIND-047: detect silent degradation).
///
/// SECURITY (FIND-R111-001): This is a separate OnceLock initialized atomically
/// inside the DLP_REGEXES initializer closure. Because `OnceLock::get_or_init` is
/// guaranteed to run the closure at most once and the closure sets both values,
/// `DLP_FAILED_COUNT` is always consistent with `DLP_REGEXES`. There is no window
/// where `DLP_REGEXES` is initialized but `DLP_FAILED_COUNT` is not, because the
/// `DLP_FAILED_COUNT.get_or_init(|| failed_count)` call inside the outer closure
/// completes before the outer `get_or_init` returns.
static DLP_FAILED_COUNT: OnceLock<usize> = OnceLock::new();

/// Get or initialize the shared DLP regex patterns.
///
/// SECURITY (FIND-047): Tracks failed pattern count so callers can detect
/// silent degradation. Use `dlp_pattern_health()` to check.
///
/// SECURITY (FIND-R111-001): The failed count is set inside the same `get_or_init`
/// closure that compiles the patterns, guaranteeing atomic initialization of both
/// statics. A second caller racing to call `get_dlp_regexes()` will either wait for
/// the first caller's closure to complete (Rust's `OnceLock` guarantee) or observe
/// the already-initialized values — never a partial state.
fn get_dlp_regexes() -> &'static [(&'static str, regex::Regex)] {
    DLP_REGEXES.get_or_init(|| {
        let mut failed_count = 0usize;
        let compiled: Vec<_> = DLP_PATTERNS
            .iter()
            .filter_map(|(name, pat)| match regex::Regex::new(pat) {
                Ok(re) => Some((*name, re)),
                Err(e) => {
                    // SECURITY (R35-MCP-2): Log error if DLP pattern fails to compile.
                    tracing::error!(
                        "CRITICAL: Failed to compile DLP pattern '{}': {}. \
                         This pattern will be SKIPPED — DLP coverage degraded.",
                        name,
                        e
                    );
                    failed_count += 1;
                    None
                }
            })
            .collect();
        // SECURITY (FIND-R111-001): Set the failed count inside the same closure so
        // it is guaranteed to be set before any caller can observe DLP_REGEXES as
        // initialized. If DLP_FAILED_COUNT was already set (impossible in practice
        // since this is the only place it is set), retain the existing value.
        let _ = DLP_FAILED_COUNT.get_or_init(|| failed_count);
        compiled
    })
}

/// Returns `(active_patterns, total_patterns)`.
///
/// If `active < total`, DLP is silently degraded — some secret types
/// will not be detected. Callers should treat this as a fail-closed
/// condition or at minimum emit a prominent warning.
pub fn dlp_pattern_health() -> (usize, usize) {
    let regexes = get_dlp_regexes();
    (regexes.len(), DLP_PATTERNS.len())
}

/// Validate all DLP patterns compile successfully at startup.
///
/// # Security (SEC-006)
///
/// This function should be called during application startup to ensure all
/// DLP patterns are valid. If any pattern fails to compile, the application
/// should fail to start rather than silently skipping secret detection.
///
/// # Returns
///
/// - `Ok(count)` - Number of successfully compiled patterns
/// - `Err(failures)` - List of pattern names that failed to compile with errors
///
/// # Example
///
/// ```ignore
/// match validate_dlp_patterns() {
///     Ok(count) => info!("DLP: {} patterns compiled successfully", count),
///     Err(failures) => {
///         for (name, error) in &failures {
///             error!("DLP pattern '{}' failed: {}", name, error);
///         }
///         panic!("DLP pattern validation failed");
///     }
/// }
/// ```
pub fn validate_dlp_patterns() -> Result<usize, Vec<(String, String)>> {
    let mut failures = Vec::new();
    let mut success_count = 0;

    for (name, pattern) in DLP_PATTERNS {
        match regex::Regex::new(pattern) {
            Ok(_) => success_count += 1,
            Err(e) => {
                failures.push((name.to_string(), e.to_string()));
            }
        }
    }

    if failures.is_empty() {
        Ok(success_count)
    } else {
        Err(failures)
    }
}

/// Check if DLP scanning is available (all patterns compiled successfully).
///
/// Returns `true` if at least one DLP pattern is available for scanning.
/// This can be used for health checks.
pub fn is_dlp_available() -> bool {
    !get_dlp_regexes().is_empty()
}

/// Get the count of active DLP patterns.
///
/// Returns the number of patterns that successfully compiled and are
/// available for secret detection.
pub fn active_pattern_count() -> usize {
    get_dlp_regexes().len()
}

/// DLP (Data Loss Prevention) patterns for detecting secrets in tool call parameters.
///
/// These patterns detect common secret formats that should not be exfiltrated
/// via tool call arguments. Addresses OWASP ASI03 (Privilege Abuse) where a
/// compromised agent attempts to send credentials through tool parameters.
pub const DLP_PATTERNS: &[(&str, &str)] = &[
    ("aws_access_key", r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    (
        "aws_secret_key",
        r"(?:aws_secret_access_key|secret_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}",
    ),
    ("github_token", r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
    // R261-DLP-1: GitHub fine-grained personal access tokens (introduced 2022)
    // use a distinct prefix from classic tokens (ghp_, ghs_, etc.).
    (
        "github_fine_grained_pat",
        r"github_pat_[A-Za-z0-9_]{22,255}",
    ),
    (
        "generic_api_key",
        // Bounded quantifier {20,512} prevents ReDoS from unbounded backtracking.
        r"(?i)(?:api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*[A-Za-z0-9_\-]{20,512}",
    ),
    (
        "private_key_header",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    ),
    // Bounded quantifier {1,512} prevents ReDoS on crafted Slack-like tokens.
    (
        "slack_token",
        r"xox[bporas]-[0-9]{10,13}-[A-Za-z0-9-]{1,512}",
    ),
    (
        "jwt_token",
        // Bounded quantifiers {1,8192} prevent ReDoS while covering realistic JWT sizes.
        // JWTs can be large (especially with many claims) but >8KB per segment is abnormal.
        // SECURITY: Match both 3-part (header.payload.signature) and 2-part (header.payload)
        // JWTs. A 2-part JWT without signature still contains sensitive claims that could
        // be exfiltrated and re-signed by an attacker.
        r"eyJ[A-Za-z0-9_-]{1,8192}\.eyJ[A-Za-z0-9_-]{1,8192}(?:\.[A-Za-z0-9_-]{1,8192})?",
    ),
    // Stripe API keys (secret, publishable, restricted)
    (
        "stripe_key",
        r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,255}",
    ),
    // Google Cloud Platform / Gemini API key
    // SECURITY (R226-DLP-1): AIza keys now authenticate Gemini API (Truffle Security
    // Feb 2026). Historically public-only, leaked keys now enable attacker to run
    // Gemini at victim's expense. Severity upgraded to HIGH.
    ("gcp_api_key", r"AIza[A-Za-z0-9_\-]{35}"),
    // Azure storage/service bus connection string key component
    (
        "azure_connection_string",
        r"(?i)(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{40,88}",
    ),
    // Discord bot token (starts with M or N, base64-encoded user ID.timestamp.hmac)
    (
        "discord_token",
        r"[MN][A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}",
    ),
    // Twilio API key (starts with SK, 32 hex chars)
    ("twilio_api_key", r"SK[a-f0-9]{32}"),
    // SendGrid API key
    (
        "sendgrid_api_key",
        r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    ),
    // npm access token
    ("npm_token", r"npm_[A-Za-z0-9]{36}"),
    // PyPI API token (bounded lower: real tokens are ~150+ chars)
    ("pypi_token", r"pypi-[A-Za-z0-9_-]{100,250}"),
    // Mailchimp API key (32 hex chars followed by datacenter suffix)
    ("mailchimp_api_key", r"[a-f0-9]{32}-us[0-9]{1,2}"),
    // Database connection URI (MongoDB, PostgreSQL, MySQL, Redis)
    (
        "database_uri",
        r"(?:mongodb|postgres|mysql|redis)://[^\s]{10,512}",
    ),
    // --- AI/ML Service Credentials (OWASP ASI03 - primary threat model) ---
    // Anthropic API key (sk-ant-api + 2 digits + hyphen + 90-100 chars)
    (
        "anthropic_api_key",
        r"sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{90,100}",
    ),
    // OpenAI API key (sk- optionally followed by proj- prefix, then 40-60 alphanumeric)
    ("openai_api_key", r"sk-(?:proj-)?[A-Za-z0-9]{40,60}"),
    // HuggingFace token (hf_ prefix + 34-40 alphanumeric)
    ("huggingface_token", r"hf_[A-Za-z0-9]{34,40}"),
    // Cohere API key (key-value format, case insensitive)
    (
        "cohere_api_key",
        r"(?i)cohere[_-]?(?:api)?[_-]?key[=:\s]+[A-Za-z0-9]{35,45}",
    ),
    // Replicate API token (r8_ prefix + 37-42 alphanumeric)
    ("replicate_token", r"r8_[A-Za-z0-9]{37,42}"),
    // Together.ai API key (key-value format, case insensitive)
    (
        "together_api_key",
        r"(?i)together[_-]?(?:api)?[_-]?key[=:\s]+[A-Za-z0-9]{50,70}",
    ),
    // Groq API key (gsk_ prefix + 50-60 alphanumeric)
    ("groq_api_key", r"gsk_[A-Za-z0-9]{50,60}"),
    // --- Additional Modern Service Credentials (FIND-008) ---
    // Supabase API key (sbp_ prefix + alphanumeric)
    ("supabase_api_key", r"sbp_[A-Za-z0-9]{40,60}"),
    // Vercel token (vercel_ prefix or vc_ prefix)
    ("vercel_token", r"(?:vercel_|vc_)[A-Za-z0-9]{24,40}"),
    // Databricks token (dapi prefix + alphanumeric)
    ("databricks_token", r"dapi[a-f0-9]{32,40}"),
    // Linear API key (lin_api_ prefix + alphanumeric)
    ("linear_api_key", r"lin_api_[A-Za-z0-9]{40,50}"),
    // Planetscale token (pscale_ prefix)
    ("planetscale_token", r"pscale_[A-Za-z0-9_]{40,60}"),
    // Neon database token
    ("neon_token", r"neon_[A-Za-z0-9_]{30,50}"),
    // ── R226-DLP: New service credential patterns (Feb 2026 threats) ──
    // Supabase service-role secret key (sb_secret_ prefix, distinct from sbp_ public key)
    ("supabase_secret_key", r"sb_secret_[A-Za-z0-9_-]{20,80}"),
    // Weights & Biases API key (wandb_ prefix + observed 32-64 alphanumeric payload)
    // SECURITY (R226-DLP-2): Keep bounded to reduce false positives.
    ("wandb_api_key", r"wandb_[A-Za-z0-9]{32,64}"),
    // Mistral AI API key
    (
        "mistral_api_key",
        r"(?i)mistral[_-]?(?:api)?[_-]?key[=:\s]+[A-Za-z0-9]{30,50}",
    ),
];

/// A finding from DLP scanning of tool call parameters.
#[derive(Debug, Clone)]
pub struct DlpFinding {
    /// Name of the DLP pattern that matched.
    pub pattern_name: String,
    /// The JSON path where the secret was found (e.g., "arguments.content").
    pub location: String,
}

impl DlpFinding {
    /// Convert to the unified ScanFinding type (IMP-002).
    ///
    /// Enables consistent handling of findings across scanner types while
    /// maintaining backwards compatibility with code using DlpFinding.
    pub fn to_scan_finding(&self) -> super::scanner_base::ScanFinding {
        super::scanner_base::ScanFinding::dlp(&self.pattern_name, &self.location)
    }
}

impl From<DlpFinding> for super::scanner_base::ScanFinding {
    fn from(finding: DlpFinding) -> Self {
        finding.to_scan_finding()
    }
}

/// Minimum segment length to consider for entropy analysis.
const URL_EXFIL_MIN_SEGMENT_LEN: usize = 32;
/// Minimum hex segment length that is suspicious for exfiltration.
/// 32-char UUID-like IDs are common; require >=40 to reduce false positives.
const URL_EXFIL_MIN_HEX_SEGMENT_LEN: usize = 40;

/// Shannon entropy threshold (bits/byte) above which a URL segment is suspicious.
/// Base64-encoded random data has ~6.0 bits/byte; natural language is ~3.5-4.5.
/// Threshold of 4.5 balances false positives vs detection rate.
const URL_EXFIL_ENTROPY_THRESHOLD: f64 = 4.5;

/// Calculate Shannon entropy of a byte string in bits per byte.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] = counts[b as usize].saturating_add(1);
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Heuristic for suspicious URL payload segments.
///
/// Flags either:
/// - high-entropy long segments (base64/base64url-like), or
/// - long all-hex segments commonly used to exfiltrate encoded secrets.
fn is_suspicious_url_segment(decoded: &str) -> bool {
    if decoded.len() < URL_EXFIL_MIN_SEGMENT_LEN {
        return false;
    }

    if shannon_entropy(decoded.as_bytes()) > URL_EXFIL_ENTROPY_THRESHOLD {
        return true;
    }

    decoded.len() >= URL_EXFIL_MIN_HEX_SEGMENT_LEN && decoded.bytes().all(|b| b.is_ascii_hexdigit())
}

/// R226-DLP-EXFIL: Detect potential data exfiltration via URL query/path segments.
///
/// Agents can exfiltrate secrets by embedding them in outbound URLs — e.g., in
/// query parameters or path segments.  Messaging platform link previews trigger
/// zero-click exfiltration (PromptArmor, Feb 2026).
///
/// Returns a DLP finding if any URL segment contains high-entropy data (likely
/// base64 or hex-encoded secrets) above the entropy threshold.
pub fn detect_url_data_exfiltration(url: &str) -> Option<DlpFinding> {
    // SECURITY (R228-DLP-1): Inspect all network-capable URL schemes, not just
    // HTTP(S). Attackers can exfiltrate secrets via ftp://, ftps://, ws://, wss://,
    // or protocol-relative // URLs that still reach external networks.
    // R232-DLP-2: Added ws:// and wss:// (WebSocket) scheme check.
    let lower = url.to_ascii_lowercase();
    let has_network_scheme = lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ftp://")
        || lower.starts_with("ftps://")
        || lower.starts_with("ws://")
        || lower.starts_with("wss://")
        || lower.starts_with("//");
    if !has_network_scheme {
        return None;
    }

    // Split on '?' to separate path from query
    let parts: Vec<&str> = url.splitn(2, '?').collect();

    // Check query string segments
    if let Some(query) = parts.get(1) {
        // Remove fragment
        let query = query.split('#').next().unwrap_or(query);
        for param in query.split('&') {
            // Check the value part (after '=')
            if let Some(value) = param.split('=').nth(1) {
                let decoded = percent_encoding::percent_decode_str(value).decode_utf8_lossy();
                if is_suspicious_url_segment(&decoded) {
                    return Some(DlpFinding {
                        pattern_name: "url_data_exfiltration".to_string(),
                        location: "query_parameter".to_string(),
                    });
                }
            }
        }
    }

    // Check path segments for high-entropy data
    let path = parts
        .first()
        .and_then(|p| p.split("://").nth(1))
        .and_then(|p| p.split('/').nth(1).map(|_| p))
        .unwrap_or("");
    // Skip the authority (host:port), only check path segments
    if let Some(path_part) = path
        .split('/')
        .nth(1)
        .map(|_| path.find('/').map(|i| &path[i..]).unwrap_or(""))
    {
        for segment in path_part.split('/') {
            let decoded = percent_encoding::percent_decode_str(segment).decode_utf8_lossy();
            if is_suspicious_url_segment(&decoded) {
                return Some(DlpFinding {
                    pattern_name: "url_data_exfiltration".to_string(),
                    location: "path_segment".to_string(),
                });
            }
        }
    }

    None
}

/// Scan tool call parameters for potential secret exfiltration.
///
/// Recursively inspects all string values in the parameters JSON for DLP patterns.
/// Returns findings indicating which secrets were detected and where.
pub fn scan_parameters_for_secrets(parameters: &serde_json::Value) -> Vec<DlpFinding> {
    // FIND-009: Use shared DLP regex instance
    let regexes = get_dlp_regexes();

    let mut findings = Vec::new();
    scan_value_for_secrets(parameters, "$", regexes, &mut findings, 0);

    // IMPROVEMENT_PLAN 1.1: Log DLP findings for observability
    if !findings.is_empty() {
        let patterns: Vec<&str> = findings.iter().map(|f| f.pattern_name.as_str()).collect();
        tracing::warn!(
            patterns = ?patterns,
            finding_count = findings.len(),
            "DLP: Detected secrets in request parameters"
        );
    }

    findings
}

// IMP-002: Use shared max scan depth from scanner_base module.
use super::scanner_base::MAX_SCAN_DEPTH;

/// Maximum number of DLP findings per scan to prevent unbounded Vec growth.
/// SECURITY (FIND-R56-MCP-005): Caps findings to prevent OOM from adversarial
/// inputs that trigger many patterns across deeply nested JSON structures.
const MAX_DLP_FINDINGS: usize = 1000;

fn scan_value_for_secrets(
    value: &serde_json::Value,
    path: &str,
    regexes: &[(&str, regex::Regex)],
    findings: &mut Vec<DlpFinding>,
    depth: usize,
) {
    if depth > MAX_SCAN_DEPTH {
        return;
    }

    // SECURITY (FIND-R56-MCP-005): Cap findings to prevent unbounded Vec growth.
    if findings.len() >= MAX_DLP_FINDINGS {
        return;
    }

    match value {
        serde_json::Value::String(s) => {
            scan_string_for_secrets(s, path, regexes, findings);
        }
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                if findings.len() >= MAX_DLP_FINDINGS {
                    break;
                }
                // SECURITY (FIND-R128-002): Scan object keys for secrets, not just values.
                // A malicious tool response could encode secrets in JSON key names
                // to bypass DLP scanning of values only.
                let key_path = format!("{path}.<key:{key}>");
                scan_string_for_secrets(key, &key_path, regexes, findings);
                let child_path = format!("{path}.{key}");
                scan_value_for_secrets(val, &child_path, regexes, findings, depth + 1);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                if findings.len() >= MAX_DLP_FINDINGS {
                    break;
                }
                let child_path = format!("{path}[{i}]");
                scan_value_for_secrets(val, &child_path, regexes, findings, depth + 1);
            }
        }
        _ => {}
    }
}

/// Maximum time budget for multi-layer DLP decoding per string value.
/// If decoding takes longer than this, remaining layers are skipped.
/// Debug builds use a generous budget (200ms) because unoptimized regex
/// matching is ~10-50x slower than release and parallel test threads
/// cause heavy CPU contention. Release builds use 5ms which is ample for the
/// 5-layer decode pipeline (typically <1ms).
#[cfg(debug_assertions)]
const DLP_DECODE_BUDGET: std::time::Duration = std::time::Duration::from_millis(200);
#[cfg(not(debug_assertions))]
const DLP_DECODE_BUDGET: std::time::Duration = std::time::Duration::from_millis(5);

/// Maximum string size for DLP scanning (1 MB).
///
/// SECURITY: Prevents CPU exhaustion from scanning very large strings with all
/// DLP patterns. Secrets are unlikely to be > 1MB, so this limit doesn't affect
/// detection while protecting against DoS attacks. When exceeded, only the first
/// MAX_DLP_STRING_SIZE bytes are scanned and a warning is logged.
const MAX_DLP_STRING_SIZE: usize = 1024 * 1024; // 1 MB

/// Attempt base64 decoding across standard and URL-safe variants (with and without padding).
/// Returns `Some(decoded_string)` on success, `None` if no variant produces valid UTF-8.
///
// IMP-003: Use shared try_base64_decode from util module
pub(crate) use super::util::try_base64_decode;

/// FIND-R44-003: Attempt hex decoding of a string.
///
/// If the string contains only hex characters (0-9, a-f, A-F) and has even
/// length >= 32, attempt to decode hex pairs to bytes and interpret as UTF-8.
/// This catches secrets encoded as plain hex strings to bypass DLP detection.
///
/// Implemented without the `hex` crate to avoid adding a dependency.
fn try_hex_decode(s: &str) -> Option<String> {
    // SECURITY (FIND-R154-001): Lowered from 32 to 16 hex chars (8 decoded bytes)
    // for consistency with try_base64_decode threshold (>8 chars ≈ 6 decoded bytes).
    // Previous 32-char minimum allowed short hex-encoded secrets (e.g., 12-char AWS
    // AKIA prefix = 24 hex chars) to bypass DLP detection entirely.
    if s.len() < 16 || !s.len().is_multiple_of(2) {
        return None;
    }
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    let bytes: Vec<u8> = (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect();

    // Ensure we decoded all pairs
    if bytes.len() != s.len() / 2 {
        return None;
    }

    // Must be valid UTF-8
    std::str::from_utf8(&bytes).ok().map(|d| d.to_string())
}

/// Attempt percent-decoding. Returns `Some(decoded_string)` if decoding changed the input,
/// `None` if unchanged or invalid UTF-8.
fn try_percent_decode(s: &str) -> Option<String> {
    if !s.contains('%') {
        return None;
    }
    let decoded = percent_encoding::percent_decode_str(s).decode_utf8().ok()?;
    if decoded == s {
        return None;
    }
    Some(decoded.into_owned())
}

/// Scan a decoded string against DLP regexes, adding findings with the given location suffix.
/// Only adds findings for patterns not already in `matched_patterns`.
fn scan_decoded_layer<'a>(
    decoded: &str,
    path: &str,
    layer_suffix: &str,
    regexes: &[(&'a str, regex::Regex)],
    matched_patterns: &mut HashSet<&'a str>,
    findings: &mut Vec<DlpFinding>,
) {
    // SECURITY (FIND-R128-001): Use NFKD (compatibility decomposition WITHOUT
    // recomposition) to normalize Unicode for secret detection. NFKD is chosen
    // over NFKC because:
    // 1. It converts fullwidth chars to ASCII (e.g., "Ａ" → "A") — same as NFKC
    // 2. It decomposes precomposed chars (e.g., "Ḱ" → "K" + U+0301) — unlike NFKC
    //    which would keep them composed, making combining marks unstrippable
    // After NFKD, we strip combining marks so that "AK\u{0301}IA..." → "AKIA..."
    // and the regex can match. This prevents evasion via inserted diacritical marks.
    let nfkd: String = decoded.nfkd().collect();
    // SECURITY (FIND-R142-009): Strip all Unicode combining character ranges,
    // including extended/supplemental sets. Previously only U+0300-U+036F and
    // U+034F were stripped, allowing evasion via U+1AB0-U+1AFF, U+1DC0-U+1DFF,
    // U+20D0-U+20FF, and U+FE20-U+FE2F combining marks.
    let normalized: String = nfkd
        .chars()
        .filter(|c| {
            let cp = *c as u32;
            !((0x0300..=0x036F).contains(&cp)
                || cp == 0x034F
                || (0x1AB0..=0x1AFF).contains(&cp) // Combining Diacritical Marks Extended
                || (0x1DC0..=0x1DFF).contains(&cp) // Combining Diacritical Marks Supplement
                || (0x20D0..=0x20FF).contains(&cp) // Combining Marks for Symbols
                || (0xFE20..=0xFE2F).contains(&cp) // Combining Half Marks
                || (0xFE00..=0xFE0F).contains(&cp) // Variation Selectors
                || (0xE0100..=0xE01EF).contains(&cp)) // Variation Selectors Supplement
        })
        .collect();

    for (name, re) in regexes {
        // Check both original and normalized forms to catch all cases
        if !matched_patterns.contains(name) && (re.is_match(decoded) || re.is_match(&normalized)) {
            matched_patterns.insert(*name);
            findings.push(DlpFinding {
                pattern_name: name.to_string(),
                location: format!("{path}{layer_suffix}"),
            });
        }
    }
}

/// Scan a single string value for DLP patterns, including multi-layer decoded forms.
///
/// R4-14 FIX: Secrets can be base64-encoded or URL-encoded to evade DLP detection.
/// This function checks up to 5 decode layers:
///   1. Raw string
///   2. base64(raw)
///   3. percent(raw)
///   4. percent(base64(raw))  — catches base64-then-URL-encoded secrets
///   5. base64(percent(raw))  — catches URL-then-base64-encoded secrets
///
/// Combinatorial depth is capped at 2 layers to prevent explosion.
/// A 2ms time budget prevents DoS from large or adversarial inputs.
fn scan_string_for_secrets(
    s: &str,
    path: &str,
    regexes: &[(&str, regex::Regex)],
    findings: &mut Vec<DlpFinding>,
) {
    // SECURITY: Limit string size to prevent CPU exhaustion from regex scanning.
    // Secrets are unlikely to exceed 1MB, so truncation doesn't affect detection.
    let scan_str = if s.len() > MAX_DLP_STRING_SIZE {
        tracing::warn!(
            "DLP: String at path '{}' exceeds {} bytes ({} bytes), truncating for scan",
            path,
            MAX_DLP_STRING_SIZE,
            s.len()
        );
        // SECURITY (R250-DLP-2): Emit a synthetic finding when truncation occurs.
        // An attacker could place a secret after the truncation point to evade DLP.
        // This finding makes truncation visible in the audit trail.
        findings.push(DlpFinding {
            pattern_name: "dlp_string_truncated".to_string(),
            location: format!(
                "{path}(truncated at {MAX_DLP_STRING_SIZE} of {} bytes)",
                s.len()
            ),
        });
        // Find a char boundary to avoid panics on multi-byte UTF-8
        let mut end = MAX_DLP_STRING_SIZE;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    } else {
        s
    };

    let start = std::time::Instant::now();
    let mut matched_patterns = HashSet::new();

    // Layer 1: Scan the raw string directly (always runs)
    scan_decoded_layer(scan_str, path, "", regexes, &mut matched_patterns, findings);

    // Layer 2: base64(raw) — always attempted (existing behavior, no budget gate)
    // Use scan_str (size-limited) to prevent DoS from decoding huge strings.
    let base64_decoded = try_base64_decode(scan_str);
    if let Some(ref decoded) = base64_decoded {
        scan_decoded_layer(
            decoded,
            path,
            "(base64)",
            regexes,
            &mut matched_patterns,
            findings,
        );
    }

    // Layer 3: percent(raw) — always attempted (existing behavior, no budget gate)
    // Use scan_str (size-limited) to prevent DoS from decoding huge strings.
    let percent_decoded = try_percent_decode(scan_str);
    if let Some(ref decoded) = percent_decoded {
        scan_decoded_layer(
            decoded,
            path,
            "(url_encoded)",
            regexes,
            &mut matched_patterns,
            findings,
        );
    }

    // FIND-R44-003: Layer 3.5 — hex decode. Always attempted (core layer, no budget gate).
    // Detects secrets encoded as plain hex strings (e.g., "414b4941494f53464f444e4e374558414d504c45").
    let hex_decoded = try_hex_decode(scan_str);
    if let Some(ref decoded) = hex_decoded {
        scan_decoded_layer(
            decoded,
            path,
            "(hex)",
            regexes,
            &mut matched_patterns,
            findings,
        );
    }

    // SECURITY (R253-DLP-1): Layer 3.75 — HTML entity decode. Catches secrets
    // encoded as HTML entities (e.g., &#65;KIA... = AKIA...). Reuses the injection
    // scanner's decode_html_entities which handles numeric (&#NNN;, &#xHH;) and
    // named (&lt;, &amp;, etc.) entities. Always attempted (core layer).
    let html_decoded = super::injection::decode_html_entities(scan_str);
    if let Some(ref decoded) = html_decoded {
        scan_decoded_layer(
            decoded,
            path,
            "(html_entity)",
            regexes,
            &mut matched_patterns,
            findings,
        );
    }

    // FIND-R44-024: Layers 4-5.5 (double encoding) always run regardless of time budget.
    // Previously, a wall-clock time budget could cause these essential layers to be
    // skipped in release builds (5ms budget). Only layers 6-9 (triple encoding) are
    // time-gated since they are the most expensive combinatorial layers.

    // Layer 4: percent(base64(raw)) — base64 decode first, then percent decode the result
    if let Some(ref b64) = base64_decoded {
        if let Some(ref decoded) = try_percent_decode(b64) {
            scan_decoded_layer(
                decoded,
                path,
                "(base64+url_encoded)",
                regexes,
                &mut matched_patterns,
                findings,
            );
        }
    }

    // Layer 5: base64(percent(raw)) — percent decode first, then base64 decode the result
    if let Some(ref pct) = percent_decoded {
        if let Some(ref decoded) = try_base64_decode(pct) {
            scan_decoded_layer(
                decoded,
                path,
                "(url_encoded+base64)",
                regexes,
                &mut matched_patterns,
                findings,
            );
        }
    }

    // SECURITY (FIND-R213-003): Layer 5.5 — hex(hex(raw)). Double hex encoding
    // evasion: attacker hex-encodes a secret, then hex-encodes the result. The
    // outer hex decode (layer 3.5) produces the inner hex string, and this layer
    // decodes it to the original secret. Always attempted (essential double-encoding
    // layer, same priority as layers 4-5).
    if let Some(ref hex_outer) = hex_decoded {
        if let Some(ref decoded) = try_hex_decode(hex_outer) {
            scan_decoded_layer(
                decoded,
                path,
                "(hex+hex)",
                regexes,
                &mut matched_patterns,
                findings,
            );
        }
    }

    // SECURITY (R33-005): Layers 6-9 add triple-encoding detection.
    // Attackers may use triple encoding to evade double-layer detection.
    // FIND-R44-024: Only these triple-encoding layers are time-gated.

    // Layer 6: base64(base64(raw)) — double base64 encoding
    if let Some(ref b64) = base64_decoded {
        if start.elapsed() >= DLP_DECODE_BUDGET {
            return;
        }
        if let Some(ref decoded) = try_base64_decode(b64) {
            scan_decoded_layer(
                decoded,
                path,
                "(base64+base64)",
                regexes,
                &mut matched_patterns,
                findings,
            );
        }
    }

    // Layer 7: percent(percent(raw)) — double URL encoding
    if let Some(ref pct) = percent_decoded {
        if start.elapsed() >= DLP_DECODE_BUDGET {
            return;
        }
        if let Some(ref decoded) = try_percent_decode(pct) {
            scan_decoded_layer(
                decoded,
                path,
                "(url_encoded+url_encoded)",
                regexes,
                &mut matched_patterns,
                findings,
            );
        }
    }

    // Layer 8: base64(percent(base64(raw))) — triple mixed encoding
    if let Some(ref b64) = base64_decoded {
        if start.elapsed() >= DLP_DECODE_BUDGET {
            return;
        }
        if let Some(ref pct) = try_percent_decode(b64) {
            if let Some(ref decoded) = try_base64_decode(pct) {
                scan_decoded_layer(
                    decoded,
                    path,
                    "(base64+url_encoded+base64)",
                    regexes,
                    &mut matched_patterns,
                    findings,
                );
            }
        }
    }

    // SECURITY (FIND-R213-003): Layer 9 — hex(base64(raw)). Attacker base64-encodes
    // a secret then hex-encodes the result. Time-gated as a triple-equivalent layer.
    if let Some(ref b64) = base64_decoded {
        if start.elapsed() >= DLP_DECODE_BUDGET {
            return;
        }
        if let Some(ref decoded) = try_hex_decode(b64) {
            scan_decoded_layer(
                decoded,
                path,
                "(base64+hex)",
                regexes,
                &mut matched_patterns,
                findings,
            );
        }
    }

    // R232-DLP-1 FIX: Wire URL data exfiltration detection into the DLP pipeline.
    // This entropy-based analysis catches exfiltration via high-entropy URL query
    // parameters and path segments that don't match any specific regex pattern.
    if findings.len() < MAX_DLP_FINDINGS && (scan_str.contains("://") || scan_str.starts_with("//"))
    {
        if let Some(finding) = detect_url_data_exfiltration(scan_str) {
            if !matched_patterns.contains(&finding.pattern_name.as_str()) {
                findings.push(finding);
            }
        }
    }
}

/// Scan a JSON-RPC tool response for secrets in the result content.
///
/// Extracts text from `result.content[].text` and `result.structuredContent`,
/// scanning each for DLP patterns. Detects when a compromised tool returns
/// secrets (e.g., AWS keys, tokens) in its output — which a subsequent tool
/// call could then exfiltrate.
///
/// Returns findings indicating which secrets were detected and where in the response.
pub fn scan_response_for_secrets(response: &serde_json::Value) -> Vec<DlpFinding> {
    // FIND-009: Use shared DLP regex instance
    let regexes = get_dlp_regexes();

    let mut findings = Vec::new();

    // Scan result.content[].text and result.content[].resource.text
    // SECURITY (R17-DLP-1): Use multi-layer decode pipeline (scan_string_for_secrets)
    // instead of raw regex matching, so base64/percent-encoded secrets in responses
    // are detected the same way as in request parameters.
    // SECURITY (FIND-R172-001): Bound content array iteration and total findings
    // to prevent CPU exhaustion from malicious responses with 100K+ content items.
    const MAX_RESPONSE_CONTENT_ITEMS: usize = 1000;
    if let Some(content) = response
        .get("result")
        .and_then(|r| r.get("content"))
        .and_then(|c| c.as_array())
    {
        for (i, item) in content.iter().take(MAX_RESPONSE_CONTENT_ITEMS).enumerate() {
            if findings.len() >= MAX_DLP_FINDINGS {
                break;
            }
            if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                scan_string_for_secrets(
                    text,
                    &format!("result.content[{i}].text"),
                    regexes,
                    &mut findings,
                );
            }
            // SECURITY (R17-DLP-2): Also scan resource.text (embedded MCP resource content).
            // A malicious server can embed secrets in resource content items to bypass
            // DLP that only scans top-level text fields.
            if let Some(resource) = item.get("resource") {
                if let Some(text) = resource.get("text").and_then(|t| t.as_str()) {
                    scan_string_for_secrets(
                        text,
                        &format!("result.content[{i}].resource.text"),
                        regexes,
                        &mut findings,
                    );
                }
                // SECURITY (R32-PROXY-1): Also scan resource.blob — base64-encoded
                // binary content that may contain secrets. Decode before scanning.
                if let Some(blob) = resource.get("blob").and_then(|b| b.as_str()) {
                    // Try base64 decode (standard + URL-safe variants)
                    if let Some(decoded) = try_base64_decode(blob) {
                        scan_string_for_secrets(
                            &decoded,
                            &format!("result.content[{i}].resource.blob(decoded)"),
                            regexes,
                            &mut findings,
                        );
                    }
                    // Also scan the raw blob — secrets may be in unencoded form
                    scan_string_for_secrets(
                        blob,
                        &format!("result.content[{i}].resource.blob"),
                        regexes,
                        &mut findings,
                    );
                }
            }
            // SECURITY (R34-MCP-8): Scan content[].annotations for secrets.
            // MCP content items can carry annotation fields with arbitrary metadata.
            // A malicious server can embed secrets (AWS keys, JWTs) in annotations
            // to bypass DLP that only checks text/resource fields.
            if let Some(annotations) = item.get("annotations") {
                scan_value_for_secrets(
                    annotations,
                    &format!("result.content[{i}].annotations"),
                    regexes,
                    &mut findings,
                    0,
                );
            }
        }
    }

    // SECURITY (R246-RELAY-5): Scan result.contents[] — MCP resources/read responses.
    // The MCP spec uses "contents" (not "content") for resource read results.
    // Without this, resource read responses bypass DLP scanning entirely.
    if findings.len() < MAX_DLP_FINDINGS {
        if let Some(contents) = response
            .get("result")
            .and_then(|r| r.get("contents"))
            .and_then(|c| c.as_array())
        {
            for (i, item) in contents.iter().take(MAX_RESPONSE_CONTENT_ITEMS).enumerate() {
                if findings.len() >= MAX_DLP_FINDINGS {
                    break;
                }
                // contents[].text — the primary content field
                if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                    scan_string_for_secrets(
                        text,
                        &format!("result.contents[{i}].text"),
                        regexes,
                        &mut findings,
                    );
                }
                // contents[].blob — base64-encoded binary content
                if let Some(blob) = item.get("blob").and_then(|b| b.as_str()) {
                    if let Some(decoded) = try_base64_decode(blob) {
                        scan_string_for_secrets(
                            &decoded,
                            &format!("result.contents[{i}].blob(decoded)"),
                            regexes,
                            &mut findings,
                        );
                    }
                    scan_string_for_secrets(
                        blob,
                        &format!("result.contents[{i}].blob"),
                        regexes,
                        &mut findings,
                    );
                }
                // contents[].uri — could contain exfiltrated secrets
                if let Some(uri) = item.get("uri").and_then(|u| u.as_str()) {
                    scan_string_for_secrets(
                        uri,
                        &format!("result.contents[{i}].uri"),
                        regexes,
                        &mut findings,
                    );
                }
                // contents[].name — metadata field
                if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                    scan_string_for_secrets(
                        name,
                        &format!("result.contents[{i}].name"),
                        regexes,
                        &mut findings,
                    );
                }
                // contents[].description — metadata field
                if let Some(desc) = item.get("description").and_then(|d| d.as_str()) {
                    scan_string_for_secrets(
                        desc,
                        &format!("result.contents[{i}].description"),
                        regexes,
                        &mut findings,
                    );
                }
                // contents[].mimeType — metadata field (unlikely but defensive)
                if let Some(mime) = item.get("mimeType").and_then(|m| m.as_str()) {
                    scan_string_for_secrets(
                        mime,
                        &format!("result.contents[{i}].mimeType"),
                        regexes,
                        &mut findings,
                    );
                }
                // contents[].annotations
                if let Some(annotations) = item.get("annotations") {
                    scan_value_for_secrets(
                        annotations,
                        &format!("result.contents[{i}].annotations"),
                        regexes,
                        &mut findings,
                        0,
                    );
                }
            }
        }
    }

    // SECURITY (R32-PROXY-3): Scan instructionsForUser — this MCP 2025-06-18 field
    // is displayed to the user and could contain exfiltrated secrets.
    // SECURITY (FIND-R172-001): Check findings cap before each scan block.
    if findings.len() < MAX_DLP_FINDINGS {
        if let Some(instructions) = response
            .get("result")
            .and_then(|r| r.get("instructionsForUser"))
            .and_then(|i| i.as_str())
        {
            scan_string_for_secrets(
                instructions,
                "result.instructionsForUser",
                regexes,
                &mut findings,
            );
        }
    }

    // SECURITY (R33-MCP-2): Scan result._meta for secrets — this field can contain
    // arbitrary server metadata that could embed exfiltrated secrets. The injection
    // scanner already covers _meta but DLP scanning was missing.
    if findings.len() < MAX_DLP_FINDINGS {
        if let Some(meta) = response.get("result").and_then(|r| r.get("_meta")) {
            scan_value_for_secrets(meta, "result._meta", regexes, &mut findings, 0);
        }
    }

    // Scan result.structuredContent recursively
    if findings.len() < MAX_DLP_FINDINGS {
        if let Some(structured) = response
            .get("result")
            .and_then(|r| r.get("structuredContent"))
        {
            scan_value_for_secrets(
                structured,
                "result.structuredContent",
                regexes,
                &mut findings,
                0,
            );
        }
    }

    // SECURITY (R8-MCP-9): Also scan error.message and error.data for secrets.
    // A malicious server could embed secrets in error responses, and a subsequent
    // agent action could exfiltrate them.
    // SECURITY (R17-DLP-1): Use multi-layer decode for error.message too.
    if findings.len() < MAX_DLP_FINDINGS {
        if let Some(error) = response.get("error") {
            if let Some(msg) = error.get("message").and_then(|m| m.as_str()) {
                scan_string_for_secrets(msg, "error.message", regexes, &mut findings);
            }
            if findings.len() < MAX_DLP_FINDINGS {
                if let Some(data) = error.get("data") {
                    scan_value_for_secrets(data, "error.data", regexes, &mut findings, 0);
                }
            }
        }
    }

    // IMPROVEMENT_PLAN 1.1: Log DLP findings for observability
    if !findings.is_empty() {
        let patterns: Vec<&str> = findings.iter().map(|f| f.pattern_name.as_str()).collect();
        tracing::warn!(
            patterns = ?patterns,
            finding_count = findings.len(),
            "DLP: Detected secrets in response content"
        );
    }

    findings
}

/// Scan a notification message's params for DLP secret patterns.
///
/// SECURITY (R18-NOTIF-DLP): Notifications (server→client messages with `method`
/// but no `id`) bypass `scan_response_for_secrets` because they have no `result`
/// or `error` fields. A malicious server can embed secrets in notification params
/// (e.g., `notifications/resources/updated` with a URI containing an AWS key, or
/// `notifications/progress` with secrets in the `message` field).
pub fn scan_notification_for_secrets(notification: &serde_json::Value) -> Vec<DlpFinding> {
    // FIND-009: Use shared DLP regex instance
    let regexes = get_dlp_regexes();

    let mut findings = Vec::new();

    // Scan params recursively — notifications carry data in params
    if let Some(params) = notification.get("params") {
        scan_value_for_secrets(params, "params", regexes, &mut findings, 0);
    }

    // Also scan the method name itself (unlikely but defensive)
    // SECURITY (FIND-R172-003): Check findings cap before additional scanning.
    if findings.len() < MAX_DLP_FINDINGS {
        if let Some(method) = notification.get("method").and_then(|m| m.as_str()) {
            scan_string_for_secrets(method, "method", regexes, &mut findings);
        }
    }

    // IMPROVEMENT_PLAN 1.1: Log DLP findings for observability
    if !findings.is_empty() {
        let patterns: Vec<&str> = findings.iter().map(|f| f.pattern_name.as_str()).collect();
        tracing::warn!(
            patterns = ?patterns,
            finding_count = findings.len(),
            "DLP: Detected secrets in notification"
        );
    }

    findings
}

/// Scan a raw text string for DLP secret patterns, using the full multi-layer
/// decode pipeline (base64, percent-encoding, and combinatorial chains).
///
/// SECURITY (R17-SSE-4): Needed for SSE DLP scanning when the event payload
/// is not valid JSON. Without this, a malicious upstream can embed secrets
/// in non-JSON SSE data lines to bypass DLP detection entirely.
pub fn scan_text_for_secrets(text: &str, location: &str) -> Vec<DlpFinding> {
    // FIND-009: Use shared DLP regex instance
    let regexes = get_dlp_regexes();

    let mut findings = Vec::new();
    scan_string_for_secrets(text, location, regexes, &mut findings);
    // SECURITY (FIND-R172-005): Cap findings per call.
    findings.truncate(MAX_DLP_FINDINGS);

    // IMPROVEMENT_PLAN 1.1: Log DLP findings for observability
    if !findings.is_empty() {
        let patterns: Vec<&str> = findings.iter().map(|f| f.pattern_name.as_str()).collect();
        tracing::warn!(
            patterns = ?patterns,
            location = %location,
            finding_count = findings.len(),
            "DLP: Detected secrets in text content"
        );
    }

    findings
}

// ═══════════════════════════════════════════════════════════════════════════
// R231/TI-2026-001: Sharded Exfiltration Tracker
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum recorded fragments to prevent unbounded memory growth.
const MAX_EXFIL_FRAGMENTS: usize = 500;

/// Default window in seconds for sharded exfiltration detection.
const DEFAULT_EXFIL_WINDOW_SECS: u64 = 300;

/// Default cumulative high-entropy byte threshold.
const DEFAULT_EXFIL_BYTE_THRESHOLD: usize = 256;

/// Entropy threshold (bits/byte) for individual parameter values.
const FRAGMENT_ENTROPY_THRESHOLD: f64 = 4.0;

/// Minimum fragment length to consider for entropy analysis.
const MIN_FRAGMENT_LEN: usize = 16;

/// Per-session tracker for sharded exfiltration detection.
///
/// Attackers can split secrets across multiple small tool call parameters
/// to evade per-request DLP regex matching. This tracker records
/// high-entropy parameter fragments within a time window and alerts when
/// the cumulative suspicious byte count exceeds a configurable threshold.
///
/// # SECURITY (R231/TI-2026-001)
/// Addresses HiddenLayer research on sharded secret exfiltration via
/// MCP tool parameters (Feb 2026).
pub struct ShardedExfilTracker {
    fragments: std::collections::VecDeque<(u64, usize)>,
    window_secs: u64,
    byte_threshold: usize,
    enabled: bool,
}

impl ShardedExfilTracker {
    /// Create a new tracker with default settings.
    pub fn new() -> Self {
        Self {
            fragments: std::collections::VecDeque::new(),
            window_secs: DEFAULT_EXFIL_WINDOW_SECS,
            byte_threshold: DEFAULT_EXFIL_BYTE_THRESHOLD,
            enabled: true,
        }
    }

    /// Create a disabled tracker (no-op).
    pub fn disabled() -> Self {
        Self {
            fragments: std::collections::VecDeque::new(),
            window_secs: DEFAULT_EXFIL_WINDOW_SECS,
            byte_threshold: DEFAULT_EXFIL_BYTE_THRESHOLD,
            enabled: false,
        }
    }

    /// Create with custom thresholds.
    pub fn with_config(window_secs: u64, byte_threshold: usize) -> Self {
        Self {
            fragments: std::collections::VecDeque::new(),
            window_secs: window_secs.max(1),
            byte_threshold: byte_threshold.max(1),
            enabled: true,
        }
    }

    /// Record parameter values from a tool call. Extracts high-entropy
    /// string fragments and records their byte counts.
    ///
    /// Returns the number of suspicious fragments found in this call.
    pub fn record_parameters(&mut self, params: &serde_json::Value) -> usize {
        if !self.enabled {
            return 0;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut count = 0usize;
        self.scan_value(params, now, &mut count, 0);
        count
    }

    fn scan_value(&mut self, value: &serde_json::Value, now: u64, count: &mut usize, depth: usize) {
        if depth > 16 {
            return;
        }
        match value {
            serde_json::Value::String(s) => {
                if s.len() >= MIN_FRAGMENT_LEN {
                    let entropy = shannon_entropy(s.as_bytes());
                    // SECURITY (R236-EXFIL-3): Use >= so hex-encoded secrets
                    // (exactly 4.0 bits/byte = log2(16)) are not excluded.
                    if entropy >= FRAGMENT_ENTROPY_THRESHOLD {
                        if self.fragments.len() >= MAX_EXFIL_FRAGMENTS {
                            self.fragments.pop_front();
                        }
                        self.fragments.push_back((now, s.len()));
                        *count = count.saturating_add(1);
                    }
                }
            }
            serde_json::Value::Object(map) => {
                for v in map.values() {
                    self.scan_value(v, now, count, depth.saturating_add(1));
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr.iter().take(1000) {
                    self.scan_value(v, now, count, depth.saturating_add(1));
                }
            }
            _ => {}
        }
    }

    /// Evict entries outside the time window and check if cumulative
    /// high-entropy bytes exceed the threshold.
    ///
    /// Returns `Some(cumulative_bytes)` if the threshold is exceeded.
    pub fn check_exfiltration(&mut self) -> Option<usize> {
        if !self.enabled {
            return None;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cutoff = now.saturating_sub(self.window_secs);

        // Evict old entries
        while let Some(&(ts, _)) = self.fragments.front() {
            if ts < cutoff {
                self.fragments.pop_front();
            } else {
                break;
            }
        }

        let total: usize = self
            .fragments
            .iter()
            .map(|&(_, bytes)| bytes)
            .fold(0usize, |acc, b| acc.saturating_add(b));

        if total >= self.byte_threshold {
            Some(total)
        } else {
            None
        }
    }

    /// Returns whether tracking is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the current fragment count in the window.
    pub fn fragment_count(&self) -> usize {
        self.fragments.len()
    }
}

impl Default for ShardedExfilTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// SECURITY (R239-DLP-1): Safe summary for DLP findings in test assertions.
    /// Only shows pattern names — never matched text (which may contain secrets).
    fn findings_summary(findings: &[DlpFinding]) -> String {
        let names: Vec<&str> = findings.iter().map(|f| f.pattern_name.as_str()).collect();
        format!("[count={}, patterns={names:?}]", findings.len())
    }

    #[test]
    fn test_dlp_detects_aws_access_key() {
        let params = json!({
            "content": "Here is the key: AKIAIOSFODNN7EXAMPLE for access"
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect AWS access key");
        assert!(findings.iter().any(|f| f.pattern_name == "aws_access_key"));
    }

    #[test]
    fn test_dlp_detects_aws_key_with_fullwidth_unicode() {
        // SECURITY: Test that fullwidth Unicode characters don't bypass DLP detection.
        // Using fullwidth 'Ａ' (U+FF21), 'Ｋ' (U+FF2B), 'Ｉ' (U+FF29), 'Ａ' (U+FF21).
        // After NFKC normalization, "ＡＫＩＡ" becomes "AKIA" and matches the pattern.
        let params = json!({
            "content": "Key: ＡＫＩＡIOSFODNN7EXAMPLE"  // First 4 chars are fullwidth
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            !findings.is_empty(),
            "Should detect AWS key with fullwidth Unicode after NFKC normalization"
        );
        assert!(findings.iter().any(|f| f.pattern_name == "aws_access_key"));
    }

    // R261-DLP-1: GitHub fine-grained PAT detection
    #[test]
    fn test_dlp_detects_github_fine_grained_pat() {
        // github_pat_ prefix + 22-255 alphanumeric chars
        let token = "github_pat_11ABCDEFGH0123456789abcdef";
        let params = json!({ "auth": { "token": token } });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "github_fine_grained_pat"),
            "Should detect GitHub fine-grained PAT, findings: {:?}",
            findings.iter().map(|f| &f.pattern_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_dlp_detects_github_token() {
        let token = ["ghp_", "ABCDEFGHIJKLMNOPQRST", "UVWXYZabcdefghijk"].concat();
        let params = json!({
            "auth": {
                "token": token
            }
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect GitHub token");
        assert!(findings.iter().any(|f| f.pattern_name == "github_token"));
        assert!(findings[0].location.contains("auth.token"));
    }

    #[test]
    fn test_dlp_detects_private_key() {
        let params = json!({
            "file_content": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect private key header");
        assert!(findings
            .iter()
            .any(|f| f.pattern_name == "private_key_header"));
    }

    #[test]
    fn test_dlp_detects_jwt() {
        let params = json!({
            "data": "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123_def456"
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect JWT");
        assert!(findings.iter().any(|f| f.pattern_name == "jwt_token"));
    }

    #[test]
    fn test_dlp_detects_jwt_without_signature() {
        // SECURITY: 2-part JWTs (header.payload) without signature still contain
        // sensitive claims that can be exfiltrated and re-signed by an attacker.
        let params = json!({
            "data": "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6ImFkbWluIn0"
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            !findings.is_empty(),
            "Should detect 2-part JWT without signature"
        );
        assert!(findings.iter().any(|f| f.pattern_name == "jwt_token"));
    }

    #[test]
    fn test_dlp_detects_generic_api_key() {
        let config = ["api_key=sk_live_", "1234567890ab", "cdefghij"].concat();
        let params = json!({
            "config": config
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect generic API key");
        assert!(findings.iter().any(|f| f.pattern_name == "generic_api_key"));
    }

    #[test]
    fn test_dlp_clean_parameters() {
        let params = json!({
            "path": "/tmp/test.txt",
            "content": "Hello, world!",
            "options": {"recursive": true}
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(findings.is_empty(), "Clean parameters should not trigger");
    }

    #[test]
    fn test_dlp_nested_detection() {
        let params = json!({
            "outer": {
                "inner": {
                    "deep": "AKIAIOSFODNN7EXAMPLE"
                }
            }
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].location, "$.outer.inner.deep");
    }

    #[test]
    fn test_dlp_array_detection() {
        let params = json!({
            "items": ["safe", "AKIAIOSFODNN7EXAMPLE", "also safe"]
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].location, "$.items[1]");
    }

    #[test]
    fn test_dlp_respects_depth_limit() {
        // Build a deeply nested structure
        let mut val = json!("AKIAIOSFODNN7EXAMPLE");
        for i in 0..20 {
            val = json!({ format!("level{i}"): val });
        }
        let findings = scan_parameters_for_secrets(&val);
        // Should not panic or stack overflow even with deep nesting
        // Due to depth limit, the deeply nested key may not be found
        // but the function should complete safely
        let _ = findings;
    }

    #[test]
    fn test_dlp_detects_slack_token() {
        let webhook = ["xoxb-", "1234567890-", "abcdefghijklmnop"].concat();
        let params = json!({
            "webhook": webhook
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect Slack token");
        assert!(findings.iter().any(|f| f.pattern_name == "slack_token"));
    }

    #[test]
    fn test_dlp_detects_stripe_live_secret_key() {
        let payment = ["sk_live_", "4eC39HqLyjWDarjt", "T1zdp7dc"].concat();
        let params = json!({
            "payment": payment
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect Stripe live secret key");
        assert!(findings.iter().any(|f| f.pattern_name == "stripe_key"));
    }

    #[test]
    fn test_dlp_detects_stripe_test_publishable_key() {
        let config = ["pk_test_", "TYooMQauvdEDq54N", "iTphI7jx"].concat();
        let params = json!({
            "config": config
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            !findings.is_empty(),
            "Should detect Stripe test publishable key"
        );
        assert!(findings.iter().any(|f| f.pattern_name == "stripe_key"));
    }

    #[test]
    fn test_dlp_detects_stripe_restricted_key() {
        let key = ["rk_live_", "abcdefghijklmnop", "qrstuv"].concat();
        let params = json!({
            "key": key
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect Stripe restricted key");
        assert!(findings.iter().any(|f| f.pattern_name == "stripe_key"));
    }

    #[test]
    fn test_dlp_detects_gcp_api_key() {
        let api_config = ["AIzaSy", "DaGmWKa4JsXZ-HjGw", "7ISLn_3namBGewQe"].concat();
        let params = json!({
            "api_config": api_config
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect GCP API key");
        assert!(findings.iter().any(|f| f.pattern_name == "gcp_api_key"));
    }

    #[test]
    fn test_dlp_detects_azure_connection_string() {
        let connection = [
            "AccountKey=",
            "lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Yg",
            "w0NGe170Mc6MHMiGWBDAfwLkCz45TFnBLlOWUIlIHSln+AStoHIYXQ==",
        ]
        .concat();
        let params = json!({
            "connection": connection
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            !findings.is_empty(),
            "Should detect Azure connection string key"
        );
        assert!(findings
            .iter()
            .any(|f| f.pattern_name == "azure_connection_string"));
    }

    #[test]
    fn test_dlp_detects_azure_shared_access_key() {
        let config = [
            "SharedAccessKey=",
            "aB1cD2eF3gH4iJ5kL6mN7oP8",
            "qR9sT0uV1wX2yZ3aB4=",
        ]
        .concat();
        let params = json!({
            "config": config
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect Azure SharedAccessKey");
        assert!(findings
            .iter()
            .any(|f| f.pattern_name == "azure_connection_string"));
    }

    #[test]
    fn test_dlp_detects_discord_bot_token() {
        let bot_token = [
            "MTAxNTYxMjE2MjI4MDI5NDkz.",
            "G0WFAR.",
            "xhGA5hGqLdFi3E6MRm0xN5W3sfwjde6AqfVabc",
        ]
        .concat();
        let params = json!({
            "bot_token": bot_token
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect Discord bot token");
        assert!(findings.iter().any(|f| f.pattern_name == "discord_token"));
    }

    #[test]
    fn test_dlp_detects_twilio_api_key() {
        let twilio_key = ["SK", "1234567890abcdef", "1234567890abcdef"].concat();
        let params = json!({
            "twilio_key": twilio_key
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect Twilio API key");
        assert!(findings.iter().any(|f| f.pattern_name == "twilio_api_key"));
    }

    #[test]
    fn test_dlp_detects_sendgrid_api_key() {
        let mail_key = [
            "SG.",
            "ngeVfQFYQlKU0ufo8x5d1A.",
            "TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr",
        ]
        .concat();
        let params = json!({
            "mail_key": mail_key
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect SendGrid API key");
        assert!(findings
            .iter()
            .any(|f| f.pattern_name == "sendgrid_api_key"));
    }

    #[test]
    fn test_dlp_detects_npm_token() {
        let registry_auth = ["npm_", "aBcDeFgHiJkLmNoPqRsT", "uVwXyZ0123456789"].concat();
        let params = json!({
            "registry_auth": registry_auth
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect npm token");
        assert!(findings.iter().any(|f| f.pattern_name == "npm_token"));
    }

    #[test]
    fn test_dlp_detects_pypi_token() {
        let upload_token = [
            "pypi-AgEIcHlwaS5vcmcCJGY1YTUzMjMwLWRkMzQtNGVhOC1iMGU1L",
            "WUzMDJhZjE0YTdiOAACKlszLCJjMGU3OTk1NS01MjBhLTQ3ZmMtOGFmMS",
            "1hODkyOWY3MDJiMTki",
        ]
        .concat();
        let params = json!({
            "upload_token": upload_token
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect PyPI token");
        assert!(findings.iter().any(|f| f.pattern_name == "pypi_token"));
    }

    #[test]
    fn test_dlp_detects_mailchimp_api_key() {
        let mc_key = ["6dc7e3ef710b40e8", "889e959f9ad9a171", "-us21"].concat();
        let params = json!({
            "mc_key": mc_key
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect Mailchimp API key");
        assert!(findings
            .iter()
            .any(|f| f.pattern_name == "mailchimp_api_key"));
    }

    #[test]
    fn test_dlp_detects_database_uri_postgres() {
        let params = json!({
            "db_url": "postgres://user:password@host.example.com:5432/mydb"
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            !findings.is_empty(),
            "Should detect PostgreSQL connection URI"
        );
        assert!(findings.iter().any(|f| f.pattern_name == "database_uri"));
    }

    #[test]
    fn test_dlp_detects_database_uri_mongodb() {
        // Split to avoid GitHub secret scanning false positive on test fixture
        let uri = [
            "mongodb://admin:s3cret@",
            "cluster0.mongodb.net:27017/prod?retryWrites=true",
        ]
        .concat();
        let params = json!({
            "connection_string": uri
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect MongoDB connection URI");
        assert!(findings.iter().any(|f| f.pattern_name == "database_uri"));
    }

    #[test]
    fn test_dlp_detects_database_uri_mysql() {
        let params = json!({
            "dsn": "mysql://root:password@localhost:3306/appdb"
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect MySQL connection URI");
        assert!(findings.iter().any(|f| f.pattern_name == "database_uri"));
    }

    #[test]
    fn test_dlp_detects_database_uri_redis() {
        let params = json!({
            "cache_url": "redis://default:mypassword@redis.example.com:6379/0"
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(!findings.is_empty(), "Should detect Redis connection URI");
        assert!(findings.iter().any(|f| f.pattern_name == "database_uri"));
    }

    // DLP response scanning tests
    #[test]
    fn test_response_dlp_detects_aws_key_in_content() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "Found credential: AKIAIOSFODNN7EXAMPLE"
                    }
                ]
            }
        });
        let findings = scan_response_for_secrets(&response);
        assert!(
            !findings.is_empty(),
            "Should detect AWS key in response content"
        );
        assert!(findings.iter().any(|f| f.pattern_name == "aws_access_key"));
        assert!(findings
            .iter()
            .any(|f| f.location.contains("result.content")));
    }

    #[test]
    fn test_response_dlp_detects_secret_in_structured_content() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "structuredContent": {
                    "data": "Here is the key: AKIAIOSFODNN7EXAMPLE"
                }
            }
        });
        let findings = scan_response_for_secrets(&response);
        assert!(
            !findings.is_empty(),
            "Should detect AWS key in structuredContent"
        );
        assert!(findings
            .iter()
            .any(|f| f.location.contains("structuredContent")));
    }

    #[test]
    fn test_response_dlp_clean_response_passes() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "The weather is sunny and 72 degrees."
                    }
                ]
            }
        });
        let findings = scan_response_for_secrets(&response);
        assert!(
            findings.is_empty(),
            "Clean response should have no findings"
        );
    }

    #[test]
    fn test_response_dlp_detects_github_token() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": format!(
                            "Token: {}",
                            ["ghp_", "ABCDEFGHIJKLMNOPQRST", "UVWXYZabcdefghijkl"].concat()
                        )
                    }
                ]
            }
        });
        let findings = scan_response_for_secrets(&response);
        assert!(
            !findings.is_empty(),
            "Should detect GitHub token in response"
        );
        assert!(findings.iter().any(|f| f.pattern_name == "github_token"));
    }

    /// R17-DLP-1: Response DLP must use multi-layer decode pipeline.
    /// Previously, response scanning used raw regex only, allowing
    /// base64-encoded secrets to bypass detection.
    #[test]
    fn test_response_dlp_detects_base64_encoded_secret() {
        use base64::Engine;
        let raw_key = "AKIAIOSFODNN7EXAMPLE";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw_key);
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{
                    "type": "text",
                    "text": encoded
                }]
            }
        });
        let findings = scan_response_for_secrets(&response);
        assert!(
            !findings.is_empty(),
            "Response DLP must detect base64-encoded AWS key: {encoded}"
        );
    }

    /// R17-DLP-2: Response DLP must scan resource.text fields.
    #[test]
    fn test_response_dlp_detects_secret_in_resource_text() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{
                    "type": "resource",
                    "resource": {
                        "uri": "file:///etc/credentials",
                        "text": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                    }
                }]
            }
        });
        let findings = scan_response_for_secrets(&response);
        assert!(
            !findings.is_empty(),
            "Response DLP must scan resource.text for secrets"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.location.contains("resource.text")),
            "Finding location must indicate resource.text. Got: {}",
            findings_summary(&findings)
        );
    }

    /// R246-RELAY-5: DLP must scan result.contents[] (resource read responses).
    /// MCP resources/read uses "contents" (not "content").
    #[test]
    fn test_response_dlp_detects_secret_in_resource_read_contents_text() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "contents": [{
                    "uri": "file:///etc/credentials",
                    "mimeType": "text/plain",
                    "text": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                }]
            }
        });
        let findings = scan_response_for_secrets(&response);
        assert!(
            !findings.is_empty(),
            "DLP must scan result.contents[].text for secrets"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.location.contains("result.contents")),
            "Finding location must indicate result.contents"
        );
    }

    /// R246-RELAY-5: DLP must scan metadata fields (name, description) in
    /// resource read responses. A malicious server can embed secrets there.
    #[test]
    fn test_response_dlp_detects_secret_in_resource_read_metadata() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "contents": [{
                    "uri": "file:///tmp/report.txt",
                    "name": "AKIAIOSFODNN7EXAMPLE",
                    "description": "A safe file",
                    "text": "nothing here"
                }]
            }
        });
        let findings = scan_response_for_secrets(&response);
        assert!(
            !findings.is_empty(),
            "DLP must scan result.contents[].name for secrets"
        );
        assert!(
            findings.iter().any(|f| f.location.contains("name")),
            "Finding location must indicate name field"
        );
    }

    /// R246-RELAY-5: DLP must scan blob field in resource read responses.
    #[test]
    fn test_response_dlp_detects_secret_in_resource_read_blob() {
        use base64::Engine;
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let blob = base64::engine::general_purpose::STANDARD.encode(secret);
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "contents": [{
                    "uri": "file:///data.bin",
                    "mimeType": "application/octet-stream",
                    "blob": blob
                }]
            }
        });
        let findings = scan_response_for_secrets(&response);
        assert!(
            !findings.is_empty(),
            "DLP must scan result.contents[].blob for secrets"
        );
    }

    /// R17-SSE-4: scan_text_for_secrets must detect secrets in raw text
    /// using the multi-layer decode pipeline.
    #[test]
    fn test_scan_text_for_secrets_detects_raw_key() {
        let findings = scan_text_for_secrets("Here is a key: AKIAIOSFODNN7EXAMPLE", "sse_data");
        assert!(
            !findings.is_empty(),
            "scan_text_for_secrets must detect AWS key in raw text"
        );
    }

    #[test]
    fn test_scan_text_for_secrets_detects_base64_key() {
        use base64::Engine;
        let raw_key = "AKIAIOSFODNN7EXAMPLE";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw_key);
        let findings = scan_text_for_secrets(&encoded, "sse_data");
        assert!(
            !findings.is_empty(),
            "scan_text_for_secrets must detect base64-encoded AWS key"
        );
    }

    // ── R4-14: DLP Encoding Bypass Tests ─────────────────────

    #[test]
    fn test_dlp_base64_encoded_aws_key_detected() {
        // R4-14: Base64-encoded AWS key should be detected.
        use base64::Engine;
        let raw_key = "AKIAIOSFODNN7EXAMPLE";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw_key);
        let params = json!({"data": encoded});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            !findings.is_empty(),
            "Base64-encoded AWS key should be detected, encoded as: {encoded}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "aws_access_key" && f.location.contains("base64")),
            "Finding should indicate base64 decoding, got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_base64_encoded_github_token_detected() {
        // R4-14: Base64-encoded GitHub token should be detected.
        use base64::Engine;
        let raw_token = ["ghp_", "ABCDEFGHIJKLMNOPQRST", "UVWXYZabcdefghijk"].concat();
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw_token);
        let params = json!({"token": encoded});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            !findings.is_empty(),
            "Base64-encoded GitHub token should be detected"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "github_token" && f.location.contains("base64")),
            "Finding should indicate base64 decoding"
        );
    }

    #[test]
    fn test_dlp_url_encoded_aws_key_detected() {
        // R4-14: URL-encoded AWS key should be detected.
        // URL-encode each character as %XX
        let raw_key = "AKIAIOSFODNN7EXAMPLE";
        let encoded: String = raw_key.bytes().map(|b| format!("%{b:02X}")).collect();
        let params = json!({"data": encoded});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            !findings.is_empty(),
            "URL-encoded AWS key should be detected, encoded as: {encoded}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "aws_access_key" && f.location.contains("url_encoded")),
            "Finding should indicate URL decoding, got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_url_encoded_private_key_header_detected() {
        // R4-14: URL-encoded private key header should be detected.
        let raw = "-----BEGIN RSA PRIVATE KEY-----";
        let encoded: String = raw
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        let params = json!({"content": encoded});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            !findings.is_empty(),
            "URL-encoded private key header should be detected, encoded as: {encoded}"
        );
        assert!(findings
            .iter()
            .any(|f| f.pattern_name == "private_key_header"));
    }

    #[test]
    fn test_dlp_base64_url_safe_encoded_detected() {
        // R4-14: URL-safe base64 (no padding) should also be decoded.
        use base64::Engine;
        let raw_key = "AKIAIOSFODNN7EXAMPLE";
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_key);
        let params = json!({"data": encoded});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            !findings.is_empty(),
            "URL-safe base64-encoded AWS key should be detected"
        );
    }

    #[test]
    fn test_dlp_clean_base64_no_false_positive() {
        // R4-14: Base64 that decodes to non-secret data should not trigger.
        use base64::Engine;
        let clean_data = "This is perfectly normal text with no secrets at all.";
        let encoded = base64::engine::general_purpose::STANDARD.encode(clean_data);
        let params = json!({"data": encoded});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.is_empty(),
            "Clean base64 data should not trigger DLP, got: {:?}",
            findings.iter().map(|f| &f.pattern_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_dlp_raw_match_not_duplicated_with_encoding() {
        // R4-14: When a secret matches directly, don't duplicate with encoding match.
        let params = json!({"key": "AKIAIOSFODNN7EXAMPLE"});
        let findings = scan_parameters_for_secrets(&params);
        // Should have exactly one finding (raw match), not duplicated
        let aws_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.pattern_name == "aws_access_key")
            .collect();
        assert_eq!(
            aws_findings.len(),
            1,
            "Direct match should produce exactly one finding, got: {aws_findings:?}"
        );
        assert!(
            !aws_findings[0].location.contains("base64"),
            "Direct match should not be tagged as base64"
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // 11.4: Two-layer combinatorial DLP decode chains
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_dlp_base64_then_percent_encoded_detected() {
        // 11.4: base64(raw) then percent-encode the result → should be detected
        // Attacker base64-encodes the secret, then percent-encodes the base64 string
        use base64::Engine;
        let raw_key = "AKIAIOSFODNN7EXAMPLE";
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw_key);
        // Percent-encode the base64 string
        let double_encoded: String = b64.bytes().map(|b| format!("%{b:02X}")).collect();
        let params = json!({"data": double_encoded});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "aws_access_key"),
            "percent(base64(secret)) should be detected, encoded as: {}, findings: {:?}",
            &double_encoded[..40.min(double_encoded.len())],
            findings
        );
    }

    #[test]
    fn test_dlp_percent_then_base64_encoded_detected() {
        // 11.4: percent(raw) then base64 the result → should be detected
        // Attacker percent-encodes the secret, then base64-encodes the result
        use base64::Engine;
        let raw_key = "AKIAIOSFODNN7EXAMPLE";
        let pct: String = raw_key.bytes().map(|b| format!("%{b:02X}")).collect();
        let double_encoded = base64::engine::general_purpose::STANDARD.encode(&pct);
        let params = json!({"data": double_encoded});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "aws_access_key"),
            "base64(percent(secret)) should be detected, encoded as: {}, findings: {:?}",
            &double_encoded[..40.min(double_encoded.len())],
            findings
        );
    }

    #[test]
    fn test_dlp_double_encoded_github_token_detected() {
        // 11.4: GitHub token double-encoded (base64 then percent)
        use base64::Engine;
        let raw = ["ghp_", "ABCDEFGHIJKLMNOPQRST", "UVWXYZabcdefghijk"].concat();
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let double: String = b64.bytes().map(|b| format!("%{b:02X}")).collect();
        let params = json!({"token": double});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "github_token"),
            "Double-encoded GitHub token should be detected, findings: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_double_encoding_location_labels() {
        // 11.4: Verify location labels for two-layer chains
        use base64::Engine;
        let raw_key = "AKIAIOSFODNN7EXAMPLE";

        // base64 then percent → should show "base64+url_encoded" or "url_encoded+base64"
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw_key);
        let pct_of_b64: String = b64.bytes().map(|b| format!("%{b:02X}")).collect();
        let params = json!({"k": pct_of_b64});
        let findings = scan_parameters_for_secrets(&params);
        // The percent-decode happens first (layer 3), producing the base64 string.
        // Then layer 5 (base64 of percent) would try base64-decoding the percent-decoded result.
        // But actually: the input is percent-encoded base64, so:
        //   Layer 3: percent(input) = base64 string → scan (no match, it's just base64)
        //   Layer 5: base64(percent(input)) = raw key → MATCH with "url_encoded+base64" label
        assert!(
            findings
                .iter()
                .any(|f| f.location.contains("url_encoded+base64")
                    || f.location.contains("base64+url_encoded")),
            "Two-layer finding should have combinatorial location label, got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_no_false_positive_on_clean_double_encoding() {
        // 11.4: Clean string that happens to be double-encoded should not trigger
        use base64::Engine;
        let clean = "Hello, this is a perfectly normal message with no secrets";
        let b64 = base64::engine::general_purpose::STANDARD.encode(clean);
        let double: String = b64.bytes().map(|b| format!("%{b:02X}")).collect();
        let params = json!({"msg": double});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.is_empty(),
            "Clean double-encoded string should not trigger DLP, findings: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_scan_notification_detects_secret_in_params() {
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": {
                "uri": "file:///tmp/AKIAIOSFODNN7EXAMPLE.txt"
            }
        });
        let findings = scan_notification_for_secrets(&notification);
        assert!(
            !findings.is_empty(),
            "Should detect AWS key in notification params"
        );
    }

    #[test]
    fn test_scan_notification_detects_secret_in_progress_message() {
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {
                "progressToken": "tok_123",
                "progress": 50,
                "total": 100,
                "message": format!(
                    "Processing {}",
                    ["ghp_", "ABCDEFGHIJKLMNOPQRST", "UVWXYZabcdefgh1234"].concat()
                )
            }
        });
        let findings = scan_notification_for_secrets(&notification);
        assert!(
            !findings.is_empty(),
            "Should detect GitHub PAT in notification progress message"
        );
    }

    #[test]
    fn test_scan_notification_clean_is_empty() {
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": {
                "uri": "file:///tmp/safe.txt"
            }
        });
        let findings = scan_notification_for_secrets(&notification);
        assert!(
            findings.is_empty(),
            "Clean notification should have no DLP findings"
        );
    }

    // R32-PROXY-1: scan_response_for_secrets must scan resource.blob
    #[test]
    fn test_dlp_scans_resource_blob() {
        use base64::Engine;
        // Encode an AWS key in base64
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{
                    "type": "resource",
                    "resource": {
                        "blob": encoded,
                        "uri": "file:///data"
                    }
                }]
            }
        });
        let findings = scan_response_for_secrets(&response);
        assert!(
            !findings.is_empty(),
            "DLP must detect secrets in base64-decoded resource.blob"
        );
    }

    // R32-PROXY-3: scan_response_for_secrets must scan instructionsForUser
    #[test]
    fn test_dlp_scans_instructions_for_user() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": "safe text"}],
                "instructionsForUser": "Your API key is AKIAIOSFODNN7EXAMPLE with secret aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            }
        });
        let findings = scan_response_for_secrets(&response);
        assert!(
            !findings.is_empty(),
            "DLP must detect secrets in instructionsForUser"
        );
    }

    // R34-MCP-8: scan_response_for_secrets must scan content[].annotations
    #[test]
    fn test_dlp_scans_content_annotations_for_secrets() {
        // A malicious server embeds an AWS key in content annotations
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{
                    "type": "text",
                    "text": "Here is the result",
                    "annotations": {
                        "metadata": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                    }
                }]
            }
        });
        let findings = scan_response_for_secrets(&response);
        assert!(
            !findings.is_empty(),
            "DLP must detect secrets hidden in content annotations"
        );
        assert!(
            findings.iter().any(|f| f.location.contains("annotations")),
            "Finding location should reference annotations, got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_annotations_clean_no_false_positive() {
        // Clean annotations should not trigger DLP findings
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{
                    "type": "text",
                    "text": "Hello world",
                    "annotations": {
                        "priority": "0.8",
                        "audience": ["user"]
                    }
                }]
            }
        });
        let findings = scan_response_for_secrets(&response);
        assert!(
            findings.is_empty(),
            "Clean annotations should not produce DLP findings, got: {}",
            findings_summary(&findings)
        );
    }

    // ---- R40-MCP-1: Base64 URL-safe variant DLP detection ----

    #[test]
    fn test_dlp_base64url_encoded_aws_key_detected_in_params() {
        // R40-MCP-1: An AWS key encoded with URL-safe base64 (RFC 4648 §5) must be
        // detected by DLP scanning. The URL-safe variant uses '-' and '_' instead
        // of '+' and '/', which could previously evade detection if the or_else
        // chain returned non-UTF8 garbage from STANDARD before trying URL_SAFE.
        use base64::Engine;
        let aws_key = "AKIAIOSFODNN7EXAMPLE";
        let encoded = base64::engine::general_purpose::URL_SAFE.encode(aws_key);
        let params = json!({"payload": encoded});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "aws_access_key"),
            "DLP must detect AWS key encoded with base64url (URL_SAFE with padding), got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_base64url_no_pad_encoded_aws_key_detected_in_params() {
        // R40-MCP-1: URL-safe base64 WITHOUT padding (common in JWTs and web APIs).
        use base64::Engine;
        let aws_key = "AKIAIOSFODNN7EXAMPLE";
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(aws_key);
        let params = json!({"token": encoded});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "aws_access_key"),
            "DLP must detect AWS key encoded with base64url-nopad (URL_SAFE_NO_PAD), got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_base64url_encoded_secret_detected_in_response() {
        // R40-MCP-1: URL-safe base64-encoded secrets must be detected in tool responses too.
        use base64::Engine;
        let aws_key = "AKIAIOSFODNN7EXAMPLE";
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(aws_key);
        let response = json!({
            "result": {
                "content": [{
                    "type": "text",
                    "text": encoded,
                }]
            }
        });
        let findings = scan_response_for_secrets(&response);
        assert!(
            findings.iter().any(|f| f.pattern_name == "aws_access_key"),
            "DLP must detect base64url-encoded AWS key in response, got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_try_base64_decode_url_safe_variant() {
        // R40-MCP-1: Directly test that try_base64_decode handles URL-safe input.
        use base64::Engine;
        let original = "Hello+World/Test==";
        // URL-safe encoding converts +->-, /->_
        let url_safe_encoded = base64::engine::general_purpose::URL_SAFE.encode(original);
        let result = try_base64_decode(&url_safe_encoded);
        assert_eq!(
            result,
            Some(original.to_string()),
            "try_base64_decode must handle URL-safe base64 encoding"
        );
    }

    #[test]
    fn test_try_base64_decode_all_variants_produce_valid_result() {
        // R40-MCP-1: Verify all 4 engine variants work independently.
        use base64::Engine;
        let original = "AKIAIOSFODNN7EXAMPLE_secret_data";
        let engines: &[(&str, &base64::engine::GeneralPurpose)] = &[
            ("STANDARD", &base64::engine::general_purpose::STANDARD),
            ("URL_SAFE", &base64::engine::general_purpose::URL_SAFE),
            (
                "STANDARD_NO_PAD",
                &base64::engine::general_purpose::STANDARD_NO_PAD,
            ),
            (
                "URL_SAFE_NO_PAD",
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            ),
        ];
        for (name, engine) in engines {
            let encoded = engine.encode(original);
            let decoded = try_base64_decode(&encoded);
            assert_eq!(
                decoded,
                Some(original.to_string()),
                "try_base64_decode must decode {name} variant correctly"
            );
        }
    }

    // --- AI/ML Service Credential Detection Tests ---

    #[test]
    fn test_dlp_detects_anthropic_api_key() {
        // Real format: sk-ant-api03-<90-100 chars>
        let key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz12";
        let params = serde_json::json!({ "api_key": key });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "anthropic_api_key"),
            "Should detect Anthropic API key, got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_detects_openai_api_key() {
        // Standard format: sk-<48 chars>
        let key = "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL123456";
        let params = serde_json::json!({ "api_key": key });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "openai_api_key"),
            "Should detect OpenAI API key, got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_detects_openai_project_api_key() {
        // Project format: sk-proj-<48 chars>
        let key = ["sk-proj-", "abcdefghijklmnopqrstuvwx", "yzABCDEFGHIJKL1234"].concat();
        let params = serde_json::json!({ "api_key": key });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "openai_api_key"),
            "Should detect OpenAI project API key, got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_detects_huggingface_token() {
        // Format: hf_<34-40 chars>
        let token = ["hf_", "abcdefghijklmnopqrstu", "vwxyzABCDEFGH"].concat();
        let params = serde_json::json!({ "token": token });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "huggingface_token"),
            "Should detect HuggingFace token, got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_detects_replicate_token() {
        // Format: r8_<37-42 chars>
        let token = "r8_abcdefghijklmnopqrstuvwxyzABCDEFGH12345";
        let params = serde_json::json!({ "token": token });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "replicate_token"),
            "Should detect Replicate token, got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_detects_groq_api_key() {
        // Format: gsk_<50-60 chars>
        let key = "gsk_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR123456";
        let params = serde_json::json!({ "api_key": key });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "groq_api_key"),
            "Should detect Groq API key, got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_detects_cohere_api_key() {
        // Format: cohere_api_key=<35-45 chars>
        let text = "cohere_api_key=abcdefghijklmnopqrstuvwxyzABC123456";
        let params = serde_json::json!({ "config": text });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "cohere_api_key"),
            "Should detect Cohere API key, got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_detects_together_api_key() {
        // Format: together_api_key=<50-70 chars>
        let text = "together_api_key=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let params = serde_json::json!({ "config": text });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "together_api_key"),
            "Should detect Together.ai API key, got: {}",
            findings_summary(&findings)
        );
    }

    // --- SEC-006: DLP Pattern Validation Tests ---

    #[test]
    fn test_validate_dlp_patterns_all_compile() {
        // SEC-006: All default DLP patterns must compile successfully
        let result = validate_dlp_patterns();
        assert!(
            result.is_ok(),
            "All DLP patterns should compile, failures: {:?}",
            result.err()
        );

        let count = result.unwrap();
        assert!(count > 0, "Should have at least one compiled DLP pattern");
        assert_eq!(
            count,
            DLP_PATTERNS.len(),
            "All {} patterns should compile",
            DLP_PATTERNS.len()
        );
    }

    #[test]
    fn test_is_dlp_available() {
        // SEC-006: DLP should be available when patterns compile
        assert!(
            is_dlp_available(),
            "DLP should be available with valid patterns"
        );
    }

    #[test]
    fn test_active_pattern_count() {
        // SEC-006: Active pattern count should match DLP_PATTERNS
        let count = active_pattern_count();
        assert_eq!(
            count,
            DLP_PATTERNS.len(),
            "Active pattern count should equal total patterns"
        );
    }

    // ── FIND-R44-003: Hex encoding DLP bypass tests ─────────────

    #[test]
    fn test_dlp_hex_encoded_aws_key_detected() {
        // FIND-R44-003: AWS key hex-encoded should be detected
        let raw_key = "AKIAIOSFODNN7EXAMPLE";
        let hex_encoded: String = raw_key.bytes().map(|b| format!("{b:02x}")).collect();
        let params = json!({"data": hex_encoded});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "aws_access_key"),
            "Hex-encoded AWS key should be detected, encoded as: {hex_encoded}, findings: {}",
            findings_summary(&findings)
        );
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "aws_access_key" && f.location.contains("hex")),
            "Finding should indicate hex decoding, got: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_hex_encoded_github_token_detected() {
        // FIND-R44-003: GitHub token hex-encoded should be detected
        let raw = ["ghp_", "ABCDEFGHIJKLMNOPQRST", "UVWXYZabcdefghijk"].concat();
        let hex_encoded: String = raw.bytes().map(|b| format!("{b:02x}")).collect();
        let params = json!({"data": hex_encoded});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "github_token"),
            "Hex-encoded GitHub token should be detected, findings: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_hex_encoded_uppercase_detected() {
        // FIND-R44-003: Uppercase hex should also work
        let raw_key = "AKIAIOSFODNN7EXAMPLE";
        let hex_encoded: String = raw_key.bytes().map(|b| format!("{b:02X}")).collect();
        let params = json!({"data": hex_encoded});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "aws_access_key"),
            "Uppercase hex-encoded AWS key should be detected, findings: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_try_hex_decode_valid() {
        // FIND-R44-003: Test the hex decode function directly
        let input = "414b4941494f53464f444e4e374558414d504c45"; // "AKIAIOSFODNN7EXAMPLE"
        let result = try_hex_decode(input);
        assert_eq!(result, Some("AKIAIOSFODNN7EXAMPLE".to_string()));
    }

    #[test]
    fn test_try_hex_decode_too_short() {
        // FIND-R154-001: Threshold lowered from 32 to 16; use 12-char input (below threshold)
        let input = "414b494f5346"; // 12 chars, below 16 threshold
        let result = try_hex_decode(input);
        assert_eq!(result, None);
    }

    #[test]
    fn test_try_hex_decode_at_16_char_threshold() {
        // FIND-R154-001: 16 hex chars (8 decoded bytes) should now decode
        let input = "414b49414f53464f"; // 16 chars = "AKIAOSFO"
        let result = try_hex_decode(input);
        assert_eq!(result, Some("AKIAOSFO".to_string()));
    }

    #[test]
    fn test_try_hex_decode_odd_length() {
        // FIND-R44-003: Odd-length strings are not valid hex pairs
        let input = "414b4941494f53464f444e4e3745584"; // 31 chars (odd)
        let result = try_hex_decode(input);
        assert_eq!(result, None);
    }

    #[test]
    fn test_try_hex_decode_non_hex_chars() {
        // FIND-R44-003: Non-hex characters should return None
        let input = "414b4941494f53464f444e4e374558414d504c45xyz";
        let result = try_hex_decode(input);
        assert_eq!(result, None);
    }

    #[test]
    fn test_dlp_hex_clean_no_false_positive() {
        // FIND-R44-003: Clean hex string should not trigger DLP
        // "Hello, World! No secrets here at all" in hex
        let clean = "48656c6c6f2c20576f726c6421204e6f2073656372657473206865726520617420616c6c";
        let params = json!({"data": clean});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.is_empty(),
            "Clean hex data should not trigger DLP, got: {}",
            findings_summary(&findings)
        );
    }

    // ── FIND-R213-003: Double-hex encoding evasion ─────────────

    #[test]
    fn test_dlp_double_hex_encoded_aws_key_detected() {
        // SECURITY (FIND-R213-003): Attacker hex-encodes a secret, then hex-encodes the result.
        // Layer 3.5 (hex) decodes the outer layer, layer 5.5 (hex+hex) decodes the inner layer.
        let raw_key = "AKIAIOSFODNN7EXAMPLE";
        // First hex encode
        let hex_once: String = raw_key.bytes().map(|b| format!("{b:02x}")).collect();
        // Second hex encode
        let hex_twice: String = hex_once.bytes().map(|b| format!("{b:02x}")).collect();

        let params = json!({"data": hex_twice});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "aws_access_key" && f.location.contains("(hex+hex)")),
            "FIND-R213-003: Double-hex-encoded AWS key must be detected via (hex+hex) layer, findings: {}", findings_summary(&findings)
        );
    }

    // ── FIND-R44-024: DLP time-budget bypass test ─────────────

    // ── FIND-R128-001: Combining mark stripping in DLP ─────────────

    #[test]
    fn test_dlp_detects_aws_key_through_combining_marks() {
        // SECURITY: Combining marks inserted between characters of a secret
        // should be stripped after NFKD decomposition, allowing the regex to match.
        // U+0301 = COMBINING ACUTE ACCENT, U+034F = COMBINING GRAPHEME JOINER
        let params = json!({
            "content": "AK\u{0301}IA\u{034F}IOSFODNN7EXAMPLE"
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "aws_access_key"),
            "Should detect AWS key with combining marks stripped: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_detects_github_token_through_combining_marks() {
        // Combining Diacritical Marks (U+0300-U+036F range) in a GitHub token
        let params = json!({
            "token": "gh\u{0300}p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "github_token"),
            "Should detect GitHub token with combining grave accent stripped: {}",
            findings_summary(&findings)
        );
    }

    // ── FIND-R142-009: Extended combining mark ranges ─────────────

    #[test]
    fn test_dlp_detects_aws_key_through_extended_combining_marks() {
        // U+1DC0 = COMBINING DOTTED GRAVE ACCENT (Supplement range)
        // U+20D0 = COMBINING LEFT HARPOON ABOVE (Marks for Symbols range)
        // U+FE20 = COMBINING LIGATURE LEFT HALF (Half Marks range)
        let params = json!({
            "key": "AK\u{1DC0}IA\u{20D0}IOSFODNN7EXAMPLE"
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "aws_access_key"),
            "Should detect AWS key with extended combining marks stripped: {}",
            findings_summary(&findings)
        );
    }

    // ── FIND-R128-002: DLP scans JSON object keys ─────────────

    #[test]
    fn test_dlp_detects_secret_in_json_object_key() {
        // A malicious response could hide a secret in the JSON key name
        let params = json!({
            "AKIAIOSFODNN7EXAMPLE": "some_value"
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "aws_access_key"),
            "Should detect AWS key hidden in JSON object key: {}",
            findings_summary(&findings)
        );
        // Verify location shows it was found in a key
        assert!(
            findings.iter().any(|f| f.location.contains("<key:")),
            "Finding location should indicate it was in a key: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_detects_github_token_in_nested_key() {
        let token = ["ghp_", "ABCDEFGHIJKLMNOPQRST", "UVWXYZabcdefghijk"].concat();
        let params = json!({
            "data": {
                token.clone(): true
            }
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "github_token"),
            "Should detect GitHub token in nested object key: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_dlp_clean_keys_no_false_positive() {
        // Normal keys should not trigger findings
        let params = json!({
            "name": "test",
            "config": { "timeout": 30, "retries": 3 },
            "items": ["a", "b"]
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.is_empty(),
            "Clean keys should not trigger DLP: {}",
            findings_summary(&findings)
        );
    }

    // ── FIND-R44-024: DLP time-budget bypass test ─────────────

    #[test]
    fn test_dlp_double_encoded_always_runs() {
        // FIND-R44-024: Layers 4-5 (double encoding) must always run,
        // even if the time budget would have been exceeded.
        // This test verifies that percent(base64(secret)) is detected.
        use base64::Engine;
        let raw_key = "AKIAIOSFODNN7EXAMPLE";
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw_key);
        let double_encoded: String = b64.bytes().map(|b| format!("%{b:02X}")).collect();
        let params = json!({"data": double_encoded});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "aws_access_key"),
            "Double-encoded secret must always be detected (no time budget gate), findings: {}",
            findings_summary(&findings)
        );
    }

    // ── R226-DLP: New pattern detection tests ──

    #[test]
    fn test_r226_dlp_supabase_secret_key() {
        let params = json!({"key": "sb_secret_Abc123Def456Ghi789Jkl012Mno345Pqr678"});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "supabase_secret_key"),
            "Supabase service-role secret key must be detected, findings: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_r226_dlp_wandb_api_key() {
        let params = json!({"key": "wandb_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ab"});
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "wandb_api_key"),
            "Weights & Biases API key must be detected, findings: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_r226_dlp_gcp_aiza_key() {
        // R226-DLP-1: AIza keys (now HIGH severity for Gemini API)
        let key = ["AIzaSy", "A1234567890abcdef", "ghijklmnopqrstuvw"].concat();
        let params = json!({
            "key": key
        });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings.iter().any(|f| f.pattern_name == "gcp_api_key"),
            "Google AIza (Gemini) key must be detected, findings: {}",
            findings_summary(&findings)
        );
    }

    // ── R226-DLP-EXFIL: URL data exfiltration detection tests ──

    #[test]
    fn test_r226_url_exfil_high_entropy_query() {
        // Base64-encoded secret in URL query parameter
        use base64::Engine;
        let secret = "sk-ant-api03-ThisIsAVeryLongSecretKeyThatShouldBeDetectedByEntropy";
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
        let url = format!("https://attacker.com/callback?data={encoded}");
        let result = detect_url_data_exfiltration(&url);
        assert!(
            result.is_some(),
            "High-entropy URL query parameter must trigger exfiltration detection"
        );
        assert_eq!(result.unwrap().pattern_name, "url_data_exfiltration");
    }

    #[test]
    fn test_r226_url_exfil_normal_url_no_false_positive() {
        let url = "https://api.example.com/v1/files?path=/home/user/docs&format=json";
        let result = detect_url_data_exfiltration(url);
        assert!(
            result.is_none(),
            "Normal URL with short/low-entropy params must not trigger"
        );
    }

    #[test]
    fn test_r226_url_exfil_high_entropy_path() {
        // Hex-encoded secret in URL path segment
        let hex_data = "a1b2c3d4e5f6789012345678901234567890abcdef";
        let url = format!("https://evil.com/exfil/{hex_data}");
        let result = detect_url_data_exfiltration(&url);
        assert!(
            result.is_some(),
            "High-entropy path segment must trigger exfiltration detection"
        );
    }

    #[test]
    fn test_r228_url_exfil_ftp_inspected() {
        // R228-DLP-1: ftp:// is now inspected. Use a segment long enough to trigger.
        let url = "ftp://server.com/data?key=sUpErSeCrEtVaLuE1234567890ABCDEFghijklmnop";
        let result = detect_url_data_exfiltration(url);
        assert!(
            result.is_some(),
            "ftp:// URLs with high-entropy segments must be inspected"
        );
    }

    #[test]
    fn test_r232_url_exfil_websocket_inspected() {
        // R232-DLP-2: ws:// and wss:// must be inspected
        let url = "wss://attacker.com/exfil?data=sUpErSeCrEtVaLuE1234567890ABCDEFghijklmnop";
        let result = detect_url_data_exfiltration(url);
        assert!(
            result.is_some(),
            "wss:// URLs with high-entropy segments must be inspected"
        );
    }

    #[test]
    fn test_r232_url_exfil_ws_inspected() {
        let url = "ws://attacker.com/collect?token=aB3dEfGhI1jK2lMnOpQrStUvWxYz0123456789AB";
        let result = detect_url_data_exfiltration(url);
        assert!(
            result.is_some(),
            "ws:// URLs with high-entropy segments must be inspected"
        );
    }

    #[test]
    fn test_r232_url_exfil_wired_into_dlp_pipeline() {
        // R232-DLP-1: verify detect_url_data_exfiltration is called from scan_parameters_for_secrets
        let params = serde_json::json!({
            "url": "https://attacker.com/exfil?data=sUpErSeCrEtVaLuE1234567890ABCDEFghijklmnop"
        });
        let findings = scan_parameters_for_secrets(&params);
        let has_url_exfil = findings
            .iter()
            .any(|f| f.pattern_name == "url_data_exfiltration");
        assert!(
            has_url_exfil,
            "URL exfiltration should be detected via DLP pipeline: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_r226_shannon_entropy_calculation() {
        // All same bytes → entropy = 0
        assert_eq!(shannon_entropy(&[0u8; 100]), 0.0);
        // Random-looking data → high entropy
        let random_ish: Vec<u8> = (0..=255).collect();
        let entropy = shannon_entropy(&random_ish);
        assert!(
            entropy > 7.0,
            "256 unique bytes should have ~8 bits entropy, got {entropy}"
        );
        // Repeated pattern → low entropy
        let pattern = b"aaabbbccc";
        let entropy = shannon_entropy(pattern);
        assert!(
            entropy < 2.0,
            "Simple repeated pattern should have low entropy, got {entropy}"
        );
    }

    // ── R231/TI-2026-001: Sharded exfiltration tracker tests ──

    #[test]
    fn test_r231_sharded_exfil_below_threshold_no_alert() {
        let mut tracker = ShardedExfilTracker::with_config(300, 256);
        // Single small high-entropy fragment (< threshold)
        let params = json!({"data": "aK9xZ2wQ7rT5mN3jL8"});
        tracker.record_parameters(&params);
        assert!(
            tracker.check_exfiltration().is_none(),
            "Below threshold should not alert"
        );
    }

    #[test]
    fn test_r231_sharded_exfil_above_threshold_alerts() {
        // Use a low threshold so test data reliably exceeds it
        let mut tracker = ShardedExfilTracker::with_config(300, 80);
        // Base64-like strings with high character diversity (> 4.0 bits/byte entropy)
        let shards = [
            "aK9xZ2wQ7rT5mN3jL8vB4pY6cF1sD0hG",
            "bR8yW3eU6tI5oP2aS9dF4gH7jK1lZ0xC",
            "cV7mN4bX2qW8eR5tY1uI6oP3aS9dF0gH",
        ];
        for shard in &shards {
            let params = json!({"shard": shard});
            tracker.record_parameters(&params);
        }
        let result = tracker.check_exfiltration();
        assert!(
            result.is_some(),
            "Cumulative high-entropy data above threshold should alert, count={}",
            tracker.fragment_count()
        );
    }

    #[test]
    fn test_r231_sharded_exfil_low_entropy_not_counted() {
        let mut tracker = ShardedExfilTracker::with_config(300, 50);
        // Low-entropy data (repeated chars)
        let params = json!({"data": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"});
        tracker.record_parameters(&params);
        tracker.record_parameters(&params);
        tracker.record_parameters(&params);
        assert!(
            tracker.check_exfiltration().is_none(),
            "Low-entropy data should not trigger sharded exfil"
        );
    }

    #[test]
    fn test_r231_sharded_exfil_disabled_no_tracking() {
        let mut tracker = ShardedExfilTracker::disabled();
        let params = json!({"secret": "aK9xZ2wQ7rT5mN3jL8vB4pY6cF1sD0hGbR8yW3eU6"});
        tracker.record_parameters(&params);
        assert!(tracker.check_exfiltration().is_none());
        assert_eq!(tracker.fragment_count(), 0);
    }

    #[test]
    fn test_r231_sharded_exfil_fragment_count_bounded() {
        let mut tracker = ShardedExfilTracker::with_config(300, 1_000_000);
        for i in 0u32..600 {
            // Generate unique high-entropy strings
            let data: String = (0..20)
                .map(|j| {
                    let v = ((i.wrapping_mul(31).wrapping_add(j * 7)) % 62) as u8;
                    match v {
                        0..=9 => (b'0' + v) as char,
                        10..=35 => (b'a' + v - 10) as char,
                        _ => (b'A' + v - 36) as char,
                    }
                })
                .collect();
            let params = json!({"shard": data});
            tracker.record_parameters(&params);
        }
        assert!(
            tracker.fragment_count() <= 500,
            "Fragment count should be bounded, got {}",
            tracker.fragment_count()
        );
    }

    #[test]
    fn test_r236_exfil3_hex_entropy_not_excluded() {
        // R236-EXFIL-3: Hex-encoded secrets have exactly 4.0 bits/byte entropy
        // (log2(16) = 4.0). With strict > 4.0 they were excluded; with >= 4.0
        // they should be tracked.
        //
        // Generate a balanced hex string with uniform distribution over 16 chars
        // to get entropy as close to 4.0 as possible.
        let balanced_hex: String = "0123456789abcdef".chars().cycle().take(64).collect();
        let entropy = shannon_entropy(balanced_hex.as_bytes());
        // Balanced hex should give exactly 4.0 bits/byte
        assert!(
            (entropy - 4.0).abs() < 0.01,
            "Balanced hex should have ~4.0 entropy, got {entropy}"
        );
        // This string should now pass the >= threshold
        assert!(
            entropy >= FRAGMENT_ENTROPY_THRESHOLD,
            "Hex entropy {entropy} should pass >= {FRAGMENT_ENTROPY_THRESHOLD}"
        );

        let mut tracker = ShardedExfilTracker::with_config(300, 64);
        // Record balanced hex shards
        for chunk in balanced_hex.as_bytes().chunks(32) {
            let shard: String = chunk.iter().map(|&b| b as char).collect();
            let params = json!({"data": shard});
            tracker.record_parameters(&params);
        }
        assert!(
            tracker.fragment_count() > 0,
            "Hex-encoded shards should be tracked with >= threshold"
        );
    }

    // ── R253-DLP-1: HTML entity decode layer ──

    #[test]
    fn test_r253_dlp_detects_html_entity_encoded_aws_key() {
        // AKIAIOSFODNN7EXAMPLE encoded as HTML numeric entities
        let encoded = "&#65;&#75;&#73;&#65;IOSFODNN7EXAMPLE";
        let params = json!({ "data": encoded });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "aws_access_key" && f.location.contains("html_entity")),
            "HTML-entity-encoded AWS key should be detected via html_entity layer: {}",
            findings_summary(&findings)
        );
    }

    #[test]
    fn test_r253_dlp_detects_named_html_entity_encoded_secret() {
        // Use numeric entities for a GitHub PAT prefix: ghp_
        // g=&#103; h=&#104; p=&#112; _=&#95;
        let encoded = "&#103;&#104;&#112;&#95;ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let params = json!({ "data": encoded });
        let findings = scan_parameters_for_secrets(&params);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_name == "github_token" && f.location.contains("html_entity")),
            "HTML-entity-encoded GitHub token should be detected: {}",
            findings_summary(&findings)
        );
    }
}
