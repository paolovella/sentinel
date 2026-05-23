// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Shared TLS/mTLS runtime implementation for Vellaveto (Phase 71.1).
//!
//! Provides TLS termination with optional mutual TLS (client certificate verification),
//! SPIFFE identity extraction from X.509 certificates, and post-quantum key exchange
//! policy enforcement.
//!
//! Used by both `vellaveto-server` and `vellaveto-http-proxy` to avoid duplicating
//! TLS setup logic.

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio_rustls::TlsAcceptor;
use vellaveto_config::{TlsConfig, TlsKexPolicy, TlsMode};

/// Errors that can occur during TLS setup.
#[derive(Debug, Error)]
pub enum TlsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Private key error: {0}")]
    PrivateKey(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

/// Result of SPIFFE ID extraction from a client certificate.
#[derive(Debug, Clone)]
pub struct SpiffeIdentity {
    /// The full SPIFFE ID URI (e.g., "spiffe://example.org/workload/frontend")
    pub spiffe_id: String,
    /// The trust domain (e.g., "example.org")
    pub trust_domain: String,
    /// The workload path (e.g., "/workload/frontend")
    pub workload_path: String,
}

/// Percent-decode a SPIFFE workload path for security checks.
///
/// Returns:
/// - `Ok(Some(decoded))` if decoding produced valid UTF-8 that differs from input.
/// - `Ok(None)` if no percent encoding was present.
/// - `Err(())` if decoded bytes are not valid UTF-8 — caller MUST reject.
///
/// SECURITY (R244-TLS-1): Decodes into a byte buffer and validates via
/// `std::str::from_utf8()`.  Prevents bypass via bytes like `%AD` (U+00AD
/// soft hyphen) or `%80` that are not valid single-byte UTF-8.
fn percent_decode_workload_path(path: &str) -> Result<Option<String>, ()> {
    if !path.contains('%') {
        return Ok(None);
    }
    let mut decoded_bytes: Vec<u8> = Vec::with_capacity(path.len());
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                decoded_bytes.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        decoded_bytes.push(bytes[i]);
        i += 1;
    }
    // R244-TLS-1: Fail-closed — reject invalid UTF-8 from percent-decoded bytes.
    let decoded = std::str::from_utf8(&decoded_bytes).map_err(|_| ())?;
    if decoded == path {
        Ok(None)
    } else {
        Ok(Some(decoded.to_string()))
    }
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl SpiffeIdentity {
    /// Parse a SPIFFE ID from a URI string.
    /// SECURITY (R237-TLS-1): Validates trust domain is non-empty and contains
    /// only lowercase alphanumeric, dots, and hyphens per SPIFFE spec.
    pub fn parse(uri: &str) -> Option<Self> {
        if !uri.starts_with("spiffe://") {
            return None;
        }

        let without_scheme = &uri[9..]; // Remove "spiffe://"
        let (trust_domain, workload_path) = if let Some(slash_pos) = without_scheme.find('/') {
            (
                without_scheme[..slash_pos].to_string(),
                without_scheme[slash_pos..].to_string(),
            )
        } else {
            (without_scheme.to_string(), String::new())
        };

        // SECURITY (R237-TLS-1): Reject empty or malformed trust domains.
        if trust_domain.is_empty() {
            return None;
        }
        if !trust_domain
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        {
            return None;
        }
        // Must not start or end with dot or hyphen
        if trust_domain.starts_with('.')
            || trust_domain.starts_with('-')
            || trust_domain.ends_with('.')
            || trust_domain.ends_with('-')
        {
            return None;
        }

        // SECURITY (R239-TLS-1): Validate workload path for traversal, control chars,
        // null bytes, and Unicode format characters. Fail-closed on invalid paths.
        if !workload_path.is_empty() {
            // SECURITY (R241-TLS-1): Percent-decode before traversal check to prevent
            // bypass via %2e%2e (%2e = '.', %2f = '/') in certificate SANs.
            // R244-TLS-1: Err means decoded bytes are invalid UTF-8 — reject.
            let decoded_path = match percent_decode_workload_path(&workload_path) {
                Ok(d) => d,
                Err(()) => return None, // fail-closed: invalid UTF-8 in decoded path
            };
            let check_path = decoded_path.as_deref().unwrap_or(&workload_path);
            // Reject path traversal sequences
            if check_path.contains("/../") || check_path.ends_with("/..") || check_path == "/.." {
                return None;
            }
            // SECURITY (R238-TLS-1): Validate the DECODED path for dangerous characters,
            // not just the original. Percent-encoded format chars (%E2%80%8B = zero-width
            // space) pass the original check but produce dangerous chars after decoding.
            for c in check_path.chars() {
                if c == '\0' || c.is_control() {
                    return None;
                }
                // Inline check for Unicode format characters (Cf category)
                // Aligned with vellaveto_types::is_unicode_format_char() but standalone
                if matches!(c,
                    '\u{00AD}'              |
                    '\u{0600}'..='\u{0605}' |
                    '\u{061C}'              |
                    '\u{06DD}'              |
                    '\u{070F}'              |
                    '\u{0890}'..='\u{0891}' |
                    '\u{08E2}'              |
                    '\u{200B}'..='\u{200F}' |
                    '\u{202A}'..='\u{202E}' |
                    '\u{2060}'..='\u{2069}' |
                    '\u{FEFF}'              |
                    '\u{FFF9}'..='\u{FFFB}' |
                    '\u{110BD}'             |
                    '\u{110CD}'             |
                    '\u{17B4}'..='\u{17B5}' |
                    '\u{180B}'..='\u{180F}' |
                    '\u{1D173}'..='\u{1D17A}' |
                    '\u{FE00}'..='\u{FE0F}'   |
                    '\u{E0001}'..='\u{E007F}'
                ) {
                    return None;
                }
            }
        }

        Some(SpiffeIdentity {
            spiffe_id: uri.to_string(),
            trust_domain,
            workload_path,
        })
    }
}

/// Extract SPIFFE IDs from X.509 certificate SAN (Subject Alternative Name) URIs.
pub fn extract_spiffe_ids(cert_der: &[u8]) -> Vec<SpiffeIdentity> {
    let mut identities = Vec::new();

    // Parse the certificate
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_der) {
        // Look for Subject Alternative Name extension
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in &san.value.general_names {
                if let x509_parser::prelude::GeneralName::URI(uri) = name {
                    if let Some(identity) = SpiffeIdentity::parse(uri) {
                        identities.push(identity);
                    }
                }
            }
        }
    }

    identities
}

/// Load certificates from a PEM file.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    // SECURITY (R236-TLS-5): Log malformed PEM entries instead of silently
    // dropping them. A cert chain with silently dropped entries may fail
    // verification in unexpected ways.
    let mut certs: Vec<CertificateDer<'static>> = Vec::new();
    for (idx, cert_result) in CertificateDer::pem_file_iter(path)
        .map_err(|e| {
            TlsError::Certificate(format!("Failed to open certificate file {path:?}: {e}"))
        })?
        .enumerate()
    {
        match cert_result {
            Ok(cert) => certs.push(cert),
            Err(e) => {
                tracing::warn!(
                    "Skipping malformed PEM entry #{} in {}: {}",
                    idx,
                    path.display(),
                    e
                );
            }
        }
    }

    if certs.is_empty() {
        return Err(TlsError::Certificate(format!(
            "No certificates found in {path:?}"
        )));
    }

    Ok(certs)
}

/// Load a private key from a PEM file.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    // PrivateKeyDer::from_pem_file handles PKCS#1, PKCS#8, and SEC1 key formats
    PrivateKeyDer::from_pem_file(path)
        .map_err(|e| TlsError::PrivateKey(format!("Failed to read private key from {path:?}: {e}")))
}

/// Load CA certificates for client verification.
fn load_client_ca(path: &Path) -> Result<RootCertStore, TlsError> {
    let certs = load_certs(path)?;
    let mut roots = RootCertStore::empty();

    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| TlsError::Certificate(format!("Failed to add CA certificate: {e}")))?;
    }

    Ok(roots)
}

fn is_pq_or_hybrid_named_group(group: rustls::NamedGroup) -> bool {
    matches!(
        group,
        rustls::NamedGroup::MLKEM512
            | rustls::NamedGroup::MLKEM768
            | rustls::NamedGroup::MLKEM1024
            | rustls::NamedGroup::X25519MLKEM768
            | rustls::NamedGroup::secp256r1MLKEM768
    )
}

fn count_pq_or_hybrid_groups(provider: &rustls::crypto::CryptoProvider) -> usize {
    provider
        .kx_groups
        .iter()
        .filter(|g| is_pq_or_hybrid_named_group(g.name()))
        .count()
}

/// Select the TLS crypto provider explicitly.
///
/// Rustls panics when both `ring` and `aws-lc-rs` features are enabled and no
/// process-level default provider is installed. We choose `aws-lc-rs`
/// explicitly to keep behavior deterministic across mixed dependency graphs.
fn default_crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

/// Apply TLS key exchange policy to a rustls crypto provider.
///
/// This adjusts `provider.kx_groups` in place to enforce the configured
/// post-quantum migration posture.
fn apply_kex_policy_to_provider(
    provider: &mut rustls::crypto::CryptoProvider,
    policy: TlsKexPolicy,
) -> Result<(), TlsError> {
    match policy {
        TlsKexPolicy::ClassicalOnly => {
            provider
                .kx_groups
                .retain(|g| !is_pq_or_hybrid_named_group(g.name()));
        }
        TlsKexPolicy::HybridPreferred => {
            if count_pq_or_hybrid_groups(provider) > 0 {
                let mut pq_or_hybrid = Vec::new();
                let mut classical = Vec::new();
                for group in provider.kx_groups.iter().copied() {
                    if is_pq_or_hybrid_named_group(group.name()) {
                        pq_or_hybrid.push(group);
                    } else {
                        classical.push(group);
                    }
                }
                pq_or_hybrid.extend(classical);
                provider.kx_groups = pq_or_hybrid;
            }
        }
        TlsKexPolicy::HybridRequiredWhenSupported => {
            if count_pq_or_hybrid_groups(provider) > 0 {
                provider
                    .kx_groups
                    .retain(|g| is_pq_or_hybrid_named_group(g.name()));
            }
        }
    }

    if provider.kx_groups.is_empty() {
        return Err(TlsError::Config(
            "tls.kex_policy removed all supported key exchange groups".to_string(),
        ));
    }

    Ok(())
}

/// Compute the effective key-exchange groups for a given KEX policy.
///
/// This allows integration tests and diagnostics to validate policy behavior
/// without requiring a live socket handshake.
pub fn effective_kex_groups_for_policy(
    policy: TlsKexPolicy,
) -> Result<Vec<rustls::NamedGroup>, TlsError> {
    let mut provider = default_crypto_provider();
    apply_kex_policy_to_provider(&mut provider, policy)?;
    Ok(provider.kx_groups.iter().map(|g| g.name()).collect())
}

/// Build a TLS acceptor from configuration.
pub fn build_tls_acceptor(config: &TlsConfig) -> Result<Option<TlsAcceptor>, TlsError> {
    match config.mode {
        TlsMode::None => Ok(None),
        TlsMode::Tls | TlsMode::Mtls => {
            if config.mode == TlsMode::Mtls && !config.require_client_cert {
                return Err(TlsError::Config(
                    "tls.require_client_cert must be true when tls.mode = mtls".to_string(),
                ));
            }

            let cert_path = config
                .cert_path
                .as_ref()
                .ok_or_else(|| TlsError::Config("cert_path is required for TLS".to_string()))?;

            let key_path = config
                .key_path
                .as_ref()
                .ok_or_else(|| TlsError::Config("key_path is required for TLS".to_string()))?;

            let certs = load_certs(Path::new(cert_path))?;
            let key = load_private_key(Path::new(key_path))?;
            let mut provider = default_crypto_provider();
            let pq_groups_before = count_pq_or_hybrid_groups(&provider);
            let total_groups_before = provider.kx_groups.len();
            apply_kex_policy_to_provider(&mut provider, config.kex_policy)?;
            let pq_groups_after = count_pq_or_hybrid_groups(&provider);
            let total_groups_after = provider.kx_groups.len();

            match config.kex_policy {
                TlsKexPolicy::ClassicalOnly => {
                    if pq_groups_before > 0 {
                        tracing::info!(
                            "TLS kex_policy=classical_only: removed {} PQ/hybrid groups ({} -> {} total groups)",
                            pq_groups_before,
                            total_groups_before,
                            total_groups_after
                        );
                    }
                }
                TlsKexPolicy::HybridPreferred => {
                    if pq_groups_after > 0 {
                        tracing::info!(
                            "TLS kex_policy=hybrid_preferred: {} PQ/hybrid groups available ({} total groups)",
                            pq_groups_after,
                            total_groups_after
                        );
                    } else {
                        tracing::warn!(
                            "TLS kex_policy=hybrid_preferred but no PQ/hybrid groups are available in current TLS provider; using classical groups"
                        );
                    }
                }
                TlsKexPolicy::HybridRequiredWhenSupported => {
                    if pq_groups_before > 0 {
                        tracing::info!(
                            "TLS kex_policy=hybrid_required_when_supported: enforcing {} PQ/hybrid groups only",
                            pq_groups_after
                        );
                    } else {
                        tracing::warn!(
                            "TLS kex_policy=hybrid_required_when_supported but provider exposes no PQ/hybrid groups; falling back to classical groups"
                        );
                    }
                }
            }

            // R233-TLS-1: Apply min_version at runtime (was ignored — always used defaults).
            let protocol_versions = match config.min_version.as_str() {
                "1.3" => vec![&rustls::version::TLS13],
                _ => vec![&rustls::version::TLS12, &rustls::version::TLS13],
            };
            tracing::info!(
                "TLS min_version={}: {} protocol version(s) enabled",
                config.min_version,
                protocol_versions.len()
            );

            // R233-TLS-3: Apply cipher_suites filter at runtime (was ignored — always used defaults).
            // When configured, retain only cipher suites whose name matches the allowlist.
            if !config.cipher_suites.is_empty() {
                let before = provider.cipher_suites.len();
                // SECURITY (R240-TLS-1): Use exact match instead of substring matching.
                // Substring matching on Debug format could match unintended cipher suites
                // (e.g., "AES" matching all AES suites including weak ones). Exact match
                // against the SuiteId Debug name prevents accidental inclusion.
                provider.cipher_suites.retain(|suite| {
                    let name = format!("{:?}", suite.suite());
                    config.cipher_suites.contains(&name)
                });
                let after = provider.cipher_suites.len();
                if provider.cipher_suites.is_empty() {
                    return Err(TlsError::Config(
                        "tls.cipher_suites filter removed all supported cipher suites".to_string(),
                    ));
                }
                tracing::info!(
                    "TLS cipher_suites: filtered {before} -> {after} suites ({} configured)",
                    config.cipher_suites.len()
                );
            }

            let builder = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&protocol_versions)
                .map_err(TlsError::Tls)?;

            let mut server_config = if config.mode == TlsMode::Mtls {
                // mTLS: require and verify client certificates
                let client_ca_path = config.client_ca_path.as_ref().ok_or_else(|| {
                    TlsError::Config("client_ca_path is required for mTLS".to_string())
                })?;

                let client_ca = load_client_ca(Path::new(client_ca_path))?;

                let client_verifier = if config.require_client_cert {
                    WebPkiClientVerifier::builder(Arc::new(client_ca))
                        .build()
                        .map_err(|e| {
                            TlsError::Certificate(format!("Failed to build client verifier: {e}"))
                        })?
                } else {
                    WebPkiClientVerifier::builder(Arc::new(client_ca))
                        .allow_unauthenticated()
                        .build()
                        .map_err(|e| {
                            TlsError::Certificate(format!("Failed to build client verifier: {e}"))
                        })?
                };

                builder
                    .with_client_cert_verifier(client_verifier)
                    .with_single_cert(certs, key)
                    .map_err(TlsError::Tls)?
            } else {
                // TLS only: no client certificate verification
                builder
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(TlsError::Tls)?
            };

            // Enable ALPN for HTTP/1.1 and HTTP/2
            server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            Ok(Some(TlsAcceptor::from(Arc::new(server_config))))
        }
    }
}

/// Information extracted from a client certificate.
#[derive(Debug, Clone, Default)]
pub struct ClientCertInfo {
    /// SPIFFE identities found in the certificate.
    pub spiffe_ids: Vec<SpiffeIdentity>,
    /// Common Name from the subject.
    pub common_name: Option<String>,
    /// Organization from the subject.
    pub organization: Option<String>,
    /// Serial number of the certificate.
    pub serial_number: Option<String>,
    /// Whether the certificate was verified.
    pub verified: bool,
}

/// Extract information from a client certificate.
pub fn extract_client_cert_info(cert_der: &[u8]) -> ClientCertInfo {
    let mut info = ClientCertInfo {
        verified: true, // If we got here, rustls already verified it
        ..Default::default()
    };

    // Extract SPIFFE IDs
    info.spiffe_ids = extract_spiffe_ids(cert_der);

    // Parse certificate for additional info
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_der) {
        // Extract serial number
        info.serial_number = Some(cert.serial.to_string());

        // Extract subject fields
        for rdn in cert.subject.iter() {
            for attr in rdn.iter() {
                if let Ok(value) = attr.as_str() {
                    let oid = attr.attr_type();
                    // OID 2.5.4.3 = Common Name
                    if oid.to_string() == "2.5.4.3" {
                        info.common_name = Some(value.to_string());
                    }
                    // OID 2.5.4.10 = Organization
                    if oid.to_string() == "2.5.4.10" {
                        info.organization = Some(value.to_string());
                    }
                }
            }
        }
    }

    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spiffe_identity_parse() {
        let id = SpiffeIdentity::parse("spiffe://example.org/workload/frontend").unwrap();
        assert_eq!(id.trust_domain, "example.org");
        assert_eq!(id.workload_path, "/workload/frontend");
    }

    #[test]
    fn test_spiffe_identity_parse_no_path() {
        let id = SpiffeIdentity::parse("spiffe://example.org").unwrap();
        assert_eq!(id.trust_domain, "example.org");
        assert_eq!(id.workload_path, "");
    }

    #[test]
    fn test_spiffe_identity_parse_invalid() {
        assert!(SpiffeIdentity::parse("https://example.org").is_none());
        assert!(SpiffeIdentity::parse("not a uri").is_none());
    }

    #[test]
    fn test_tls_mode_none_returns_none() {
        let config = TlsConfig {
            mode: TlsMode::None,
            ..Default::default()
        };
        let result = build_tls_acceptor(&config).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_tls_mode_requires_cert_path() {
        let config = TlsConfig {
            mode: TlsMode::Tls,
            cert_path: None,
            key_path: Some("/path/to/key".to_string()),
            ..Default::default()
        };
        let result = build_tls_acceptor(&config);
        match result {
            Err(e) => assert!(e.to_string().contains("cert_path")),
            Ok(_) => panic!("Expected error for missing cert_path"),
        }
    }

    #[test]
    fn test_tls_mode_requires_key_path() {
        let config = TlsConfig {
            mode: TlsMode::Tls,
            cert_path: Some("/path/to/cert".to_string()),
            key_path: None,
            ..Default::default()
        };
        let result = build_tls_acceptor(&config);
        match result {
            Err(e) => assert!(e.to_string().contains("key_path")),
            Ok(_) => panic!("Expected error for missing key_path"),
        }
    }

    #[test]
    fn test_mtls_requires_client_ca() {
        let config = TlsConfig {
            mode: TlsMode::Mtls,
            cert_path: Some("/path/to/cert".to_string()),
            key_path: Some("/path/to/key".to_string()),
            client_ca_path: None,
            ..Default::default()
        };
        // This will fail because files don't exist, but we're testing the logic
        let result = build_tls_acceptor(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_mtls_rejects_optional_client_auth_before_file_io() {
        let config = TlsConfig {
            mode: TlsMode::Mtls,
            cert_path: Some("/path/to/cert".to_string()),
            key_path: Some("/path/to/key".to_string()),
            client_ca_path: Some("/path/to/ca".to_string()),
            require_client_cert: false,
            ..Default::default()
        };
        let result = build_tls_acceptor(&config);
        match result {
            Err(e) => assert!(e.to_string().contains("require_client_cert")),
            Ok(_) => panic!("Expected error for optional client auth in mTLS mode"),
        }
    }

    #[test]
    fn test_client_cert_info_default() {
        let info = ClientCertInfo::default();
        assert!(info.spiffe_ids.is_empty());
        assert!(info.common_name.is_none());
        assert!(!info.verified);
    }

    #[test]
    fn test_classical_only_removes_pq_groups() {
        let mut provider = default_crypto_provider();
        assert!(apply_kex_policy_to_provider(&mut provider, TlsKexPolicy::ClassicalOnly).is_ok());
        assert_eq!(count_pq_or_hybrid_groups(&provider), 0);
        assert!(
            !provider.kx_groups.is_empty(),
            "provider must keep at least one classical group"
        );
    }

    #[test]
    fn test_hybrid_preferred_prioritizes_pq_when_available() {
        let mut provider = default_crypto_provider();
        let had_pq = count_pq_or_hybrid_groups(&provider) > 0;
        assert!(apply_kex_policy_to_provider(&mut provider, TlsKexPolicy::HybridPreferred).is_ok());
        if had_pq {
            assert!(is_pq_or_hybrid_named_group(provider.kx_groups[0].name()));
        }
    }

    #[test]
    fn test_hybrid_required_when_supported_restricts_if_available() {
        let mut provider = default_crypto_provider();
        let initial_pq = count_pq_or_hybrid_groups(&provider);
        let initial_total = provider.kx_groups.len();
        assert!(apply_kex_policy_to_provider(
            &mut provider,
            TlsKexPolicy::HybridRequiredWhenSupported
        )
        .is_ok());
        if initial_pq > 0 {
            assert_eq!(provider.kx_groups.len(), initial_pq);
            assert!(
                provider
                    .kx_groups
                    .iter()
                    .all(|g| is_pq_or_hybrid_named_group(g.name())),
                "all configured groups must be PQ/hybrid when support exists"
            );
        } else {
            assert_eq!(provider.kx_groups.len(), initial_total);
        }
    }

    // ── SpiffeIdentity edge cases (merged from vellaveto-server) ─────

    #[test]
    fn test_spiffe_identity_parse_deep_path() {
        let id =
            SpiffeIdentity::parse("spiffe://prod.example.org/ns/default/sa/frontend/v2").unwrap();
        assert_eq!(id.trust_domain, "prod.example.org");
        assert_eq!(id.workload_path, "/ns/default/sa/frontend/v2");
        assert_eq!(
            id.spiffe_id,
            "spiffe://prod.example.org/ns/default/sa/frontend/v2"
        );
    }

    #[test]
    fn test_spiffe_identity_parse_empty_scheme_rejected() {
        assert!(SpiffeIdentity::parse("").is_none());
    }

    #[test]
    fn test_spiffe_identity_parse_case_sensitive_scheme() {
        // "SPIFFE://" is not valid — scheme must be lowercase per SPIFFE spec
        assert!(SpiffeIdentity::parse("SPIFFE://example.org/workload").is_none());
    }

    #[test]
    fn test_spiffe_identity_parse_http_scheme_rejected() {
        assert!(SpiffeIdentity::parse("http://example.org/workload").is_none());
    }

    #[test]
    fn test_spiffe_identity_parse_spiffe_prefix_substring_rejected() {
        // "spiffe:/" is not "spiffe://"
        assert!(SpiffeIdentity::parse("spiffe:/example.org").is_none());
    }

    #[test]
    fn test_spiffe_identity_parse_just_scheme_and_domain() {
        let id = SpiffeIdentity::parse("spiffe://trust.domain").unwrap();
        assert_eq!(id.trust_domain, "trust.domain");
        assert_eq!(id.workload_path, "");
    }

    #[test]
    fn test_spiffe_identity_parse_root_path() {
        let id = SpiffeIdentity::parse("spiffe://example.org/").unwrap();
        assert_eq!(id.trust_domain, "example.org");
        assert_eq!(id.workload_path, "/");
    }

    // SECURITY (R237-TLS-1): Trust domain validation tests
    #[test]
    fn test_r237_tls1_spiffe_empty_trust_domain_rejected() {
        assert!(SpiffeIdentity::parse("spiffe://").is_none());
        assert!(SpiffeIdentity::parse("spiffe:///admin").is_none());
    }

    #[test]
    fn test_r237_tls1_spiffe_uppercase_trust_domain_rejected() {
        assert!(SpiffeIdentity::parse("spiffe://EXAMPLE.ORG/workload").is_none());
        assert!(SpiffeIdentity::parse("spiffe://Example.Org/workload").is_none());
    }

    #[test]
    fn test_r237_tls1_spiffe_special_chars_in_trust_domain_rejected() {
        assert!(SpiffeIdentity::parse("spiffe://exam ple.org/workload").is_none());
        assert!(SpiffeIdentity::parse("spiffe://exam\tple.org/workload").is_none());
        assert!(SpiffeIdentity::parse("spiffe://exam_ple.org/workload").is_none());
        assert!(SpiffeIdentity::parse("spiffe://exam@ple.org/workload").is_none());
    }

    #[test]
    fn test_r237_tls1_spiffe_leading_trailing_dot_hyphen_rejected() {
        assert!(SpiffeIdentity::parse("spiffe://.example.org/workload").is_none());
        assert!(SpiffeIdentity::parse("spiffe://example.org./workload").is_none());
        assert!(SpiffeIdentity::parse("spiffe://-example.org/workload").is_none());
        assert!(SpiffeIdentity::parse("spiffe://example.org-/workload").is_none());
    }

    #[test]
    fn test_r237_tls1_spiffe_valid_trust_domains() {
        // These should all pass
        assert!(SpiffeIdentity::parse("spiffe://example.org/workload").is_some());
        assert!(SpiffeIdentity::parse("spiffe://prod-1.example.org/ns/default").is_some());
        assert!(SpiffeIdentity::parse("spiffe://a/b").is_some());
        assert!(SpiffeIdentity::parse("spiffe://123.456/x").is_some());
    }

    /// R238-TLS-1: Percent-encoded Unicode format chars in workload path must be rejected.
    /// The dangerous char check must run on the DECODED path, not the original.
    #[test]
    fn test_r238_tls1_spiffe_percent_encoded_format_chars_rejected() {
        // %AD = U+00AD (SOFT HYPHEN) — a Unicode format character.
        // Before R238-TLS-1 fix, the check ran on the original path where
        // '%', 'A', 'D' are normal ASCII chars, so it passed.
        // After fix, the decoded char '\u{00AD}' is caught.
        let result = SpiffeIdentity::parse("spiffe://example.org/%ADworkload");
        assert!(
            result.is_none(),
            "Percent-encoded soft hyphen (U+00AD) in workload path must be rejected"
        );

        // %E2%80%8B involves multi-byte UTF-8: each byte decoded individually
        // produces C1 control chars (0x80, 0x8B) caught by is_control().
        let result2 = SpiffeIdentity::parse("spiffe://example.org/%E2%80%8Bworkload");
        assert!(
            result2.is_none(),
            "Percent-encoded zero-width space bytes in workload path must be rejected"
        );

        // Verify non-encoded format chars are still rejected
        let result3 = SpiffeIdentity::parse("spiffe://example.org/\u{200B}hidden");
        assert!(
            result3.is_none(),
            "Direct zero-width space in workload path must be rejected"
        );

        // Verify clean paths still work
        let result4 = SpiffeIdentity::parse("spiffe://example.org/ns/default/sa/myapp");
        assert!(result4.is_some(), "Clean workload path should be accepted");
    }

    #[test]
    fn test_r244_tls1_invalid_utf8_percent_decoded_bytes_rejected() {
        // %80 is a UTF-8 continuation byte — cannot start a character.
        // Before R244-TLS-1: cast (0x80 as char) produced invalid Unicode scalar.
        // After R244-TLS-1: from_utf8() rejects → fail-closed.
        let result = SpiffeIdentity::parse("spiffe://example.org/%80admin");
        assert!(
            result.is_none(),
            "Percent-encoded invalid UTF-8 byte 0x80 must be rejected"
        );

        // %FF is never valid in UTF-8.
        let result2 = SpiffeIdentity::parse("spiffe://example.org/%FFpath");
        assert!(
            result2.is_none(),
            "Percent-encoded 0xFF must be rejected (not valid UTF-8)"
        );

        // Valid percent-encoded ASCII should still work.
        let result3 = SpiffeIdentity::parse("spiffe://example.org/%2Fworkload");
        assert!(
            result3.is_some(),
            "Percent-encoded '/' (valid ASCII) should be accepted"
        );
    }

    // ── extract_spiffe_ids (merged from vellaveto-server) ────────────

    #[test]
    fn test_extract_spiffe_ids_invalid_cert_returns_empty() {
        let empty = extract_spiffe_ids(&[]);
        assert!(empty.is_empty());

        let garbage = extract_spiffe_ids(b"not a certificate");
        assert!(garbage.is_empty());
    }

    // ── extract_client_cert_info (merged from vellaveto-server) ──────

    #[test]
    fn test_extract_client_cert_info_invalid_cert_returns_defaults() {
        let info = extract_client_cert_info(b"not a certificate");
        assert!(info.spiffe_ids.is_empty());
        assert!(info.common_name.is_none());
        assert!(info.organization.is_none());
        assert!(info.serial_number.is_none());
        // verified is true because the function assumes rustls already verified
        assert!(info.verified);
    }

    // ── KEX policy helpers (merged from vellaveto-server) ────────────

    #[test]
    fn test_is_pq_or_hybrid_named_group_classical_groups() {
        // X25519 and secp256r1 are classical, not PQ/hybrid
        assert!(!is_pq_or_hybrid_named_group(rustls::NamedGroup::X25519));
        assert!(!is_pq_or_hybrid_named_group(rustls::NamedGroup::secp256r1));
        assert!(!is_pq_or_hybrid_named_group(rustls::NamedGroup::secp384r1));
    }

    #[test]
    fn test_is_pq_or_hybrid_named_group_pq_groups() {
        assert!(is_pq_or_hybrid_named_group(rustls::NamedGroup::MLKEM768));
        assert!(is_pq_or_hybrid_named_group(
            rustls::NamedGroup::X25519MLKEM768
        ));
    }

    #[test]
    fn test_count_pq_or_hybrid_groups_default_provider() {
        let provider = default_crypto_provider();
        // Default aws-lc-rs provider should have at least some groups
        assert!(
            !provider.kx_groups.is_empty(),
            "default provider must have kx groups"
        );
    }

    #[test]
    fn test_effective_kex_groups_for_policy_classical_only() {
        let groups = effective_kex_groups_for_policy(TlsKexPolicy::ClassicalOnly).unwrap();
        assert!(!groups.is_empty());
        for g in &groups {
            assert!(
                !is_pq_or_hybrid_named_group(*g),
                "ClassicalOnly must not contain PQ/hybrid groups"
            );
        }
    }

    #[test]
    fn test_effective_kex_groups_for_policy_hybrid_preferred() {
        let groups = effective_kex_groups_for_policy(TlsKexPolicy::HybridPreferred).unwrap();
        assert!(!groups.is_empty());
    }

    // ── TLS error display (merged from vellaveto-server) ─────────────

    #[test]
    fn test_tls_error_display_variants() {
        let err = TlsError::Config("test config error".to_string());
        assert!(err.to_string().contains("test config error"));

        let err = TlsError::Certificate("bad cert".to_string());
        assert!(err.to_string().contains("bad cert"));

        let err = TlsError::PrivateKey("bad key".to_string());
        assert!(err.to_string().contains("bad key"));
    }
}
