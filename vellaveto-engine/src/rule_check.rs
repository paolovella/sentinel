// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Rule checking methods for path, network, and IP rules.
//!
//! This module handles evaluation of:
//! - Path rules (allowed/blocked globs)
//! - Network rules (allowed/blocked domains with DNS rebinding protection)
//! - IP rules (CIDR allowlists/blocklists, private IP blocking)

use crate::compiled::CompiledPolicy;
use crate::ip;
use crate::PolicyEngine;
use std::net::IpAddr;
use vellaveto_types::{Action, Verdict};

impl PolicyEngine {
    /// Check action target_paths against compiled path rules.
    /// Returns Some(Deny) if any path is blocked or not in the allowed set.
    pub(crate) fn check_path_rules(&self, action: &Action, cp: &CompiledPolicy) -> Option<Verdict> {
        let rules = match &cp.compiled_path_rules {
            Some(r) => r,
            None => return None,
        };

        // R230-ENG-1: Parity with legacy check_path_rules_legacy —
        // early return when both allowed and blocked are empty.
        if rules.allowed.is_empty() && rules.blocked.is_empty() {
            return None;
        }

        if action.target_paths.is_empty() {
            // SECURITY (R28-ENG-1): When an allowlist is configured but no
            // target paths were extracted, fail-closed. The absence of paths
            // means the extractor could not identify what the tool accesses,
            // so we cannot verify it's within the allowlist.
            if !rules.allowed.is_empty() {
                return Some(Verdict::Deny {
                    reason: format!(
                        "No target paths provided but path allowlist is configured for policy '{}'",
                        cp.policy.name
                    ),
                });
            }
            return None; // Blocklist-only mode: nothing to block
        }

        for raw_path in &action.target_paths {
            let normalized =
                match Self::normalize_path_bounded(raw_path, self.max_path_decode_iterations) {
                    Ok(n) => n,
                    Err(e) => {
                        return Some(Verdict::Deny {
                            reason: format!("Path normalization failed: {}", e),
                        })
                    }
                };

            // Check blocked patterns first (blocked takes precedence)
            for (pattern, matcher) in &rules.blocked {
                if matcher.is_match(&normalized) {
                    // R230-ENG-4: Log pattern server-side; do not expose to clients
                    tracing::debug!(path = %normalized, pattern = %pattern, policy = %cp.policy.name, "Path blocked by pattern");
                    return Some(Verdict::Deny {
                        reason: format!(
                            "Path '{}' blocked by policy '{}'",
                            normalized, cp.policy.name
                        ),
                    });
                }
            }

            // If allowed list is non-empty, path must match at least one
            if !rules.allowed.is_empty()
                && !rules.allowed.iter().any(|(_, m)| m.is_match(&normalized))
            {
                return Some(Verdict::Deny {
                    reason: format!(
                        "Path '{}' not in allowed paths for policy '{}'",
                        normalized, cp.policy.name
                    ),
                });
            }
        }

        None
    }

    /// Check action target_domains against compiled network rules.
    /// Returns Some(Deny) if any domain is blocked or not in the allowed set.
    pub(crate) fn check_network_rules(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
    ) -> Option<Verdict> {
        let rules = match &cp.compiled_network_rules {
            Some(r) => r,
            None => return None,
        };

        if action.target_domains.is_empty() {
            // SECURITY (R28-ENG-1): When an allowed_domains list is configured
            // but no target domains were extracted, fail-closed. The absence of
            // domains means the extractor could not determine where the tool
            // connects, so we cannot verify it's within the allowlist.
            if !rules.allowed_domains.is_empty() {
                return Some(Verdict::Deny {
                    reason: format!(
                        "No target domains provided but domain allowlist is configured for policy '{}'",
                        cp.policy.name
                    ),
                });
            }
            return None; // Blocklist-only mode: nothing to block
        }

        for raw_domain in &action.target_domains {
            let domain = raw_domain.to_lowercase();

            // SECURITY (R30-ENG-2): Fail-closed for non-ASCII domains that fail
            // IDNA normalization. Without this, match_domain_pattern returns false
            // for both allowed and blocked patterns → the domain bypasses blocklists.
            // If IDNA normalization fails for the domain and there are any network
            // rules configured, deny it rather than letting it through unchecked.
            if Self::normalize_domain_for_match(&domain).is_none() {
                return Some(Verdict::Deny {
                    reason: format!(
                        "Domain '{}' cannot be normalized (IDNA failure) — blocked by policy '{}'",
                        domain, cp.policy.name
                    ),
                });
            }

            // Check blocked domains first
            for pattern in &rules.blocked_domains {
                if Self::match_domain_pattern(&domain, pattern) {
                    tracing::debug!(domain = %domain, pattern = %pattern, policy = %cp.policy.name, "Domain blocked by pattern");
                    return Some(Verdict::Deny {
                        reason: format!(
                            "Domain '{}' blocked by policy '{}'",
                            domain, cp.policy.name
                        ),
                    });
                }
            }

            // If allowed list is non-empty, domain must match at least one
            if !rules.allowed_domains.is_empty()
                && !rules
                    .allowed_domains
                    .iter()
                    .any(|p| Self::match_domain_pattern(&domain, p))
            {
                return Some(Verdict::Deny {
                    reason: format!(
                        "Domain '{}' not in allowed domains for policy '{}'",
                        domain, cp.policy.name
                    ),
                });
            }
        }

        None
    }

    /// Check resolved IPs against compiled IP rules (DNS rebinding protection).
    ///
    /// Returns `Some(Deny)` if any resolved IP violates the rules.
    /// Returns `None` if all IPs pass or no IP rules are configured.
    pub(crate) fn check_ip_rules(&self, action: &Action, cp: &CompiledPolicy) -> Option<Verdict> {
        let ip_rules = match &cp.compiled_ip_rules {
            Some(r) => r,
            None => return None,
        };

        // Fail-closed: if ip_rules are configured but no resolved IPs provided
        // and the action has target domains, deny (caller didn't perform DNS resolution).
        if action.resolved_ips.is_empty() && !action.target_domains.is_empty() {
            return Some(Verdict::Deny {
                reason: format!(
                    "IP rules configured but no resolved IPs provided for policy '{}'",
                    cp.policy.name
                ),
            });
        }

        for ip_str in &action.resolved_ips {
            let raw_ip: IpAddr = match ip_str.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    return Some(Verdict::Deny {
                        reason: format!("Invalid resolved IP '{}'", ip_str),
                    })
                }
            };

            // SECURITY (R24-ENG-1, R29-ENG-1): Canonicalize IPv6 transition
            // mechanism addresses to their embedded IPv4 form so that IPv4
            // CIDRs correctly match. This covers: mapped (::ffff:), compatible
            // (::x.x.x.x), 6to4 (2002::), Teredo (2001:0000::), NAT64
            // (64:ff9b::), and NAT64 local-use (64:ff9b:1::).
            let ip = match raw_ip {
                IpAddr::V6(ref v6) => {
                    if let Some(v4) = ip::extract_embedded_ipv4(v6) {
                        IpAddr::V4(v4)
                    } else {
                        raw_ip
                    }
                }
                _ => raw_ip,
            };

            // Check private IP blocking
            if ip_rules.block_private && ip::is_private_ip(ip) {
                return Some(Verdict::Deny {
                    reason: format!(
                        "Resolved IP '{}' is a private/reserved address (DNS rebinding protection) in policy '{}'",
                        ip, cp.policy.name
                    ),
                });
            }

            // Check blocked CIDRs
            for cidr in &ip_rules.blocked_cidrs {
                if cidr.contains(&ip) {
                    tracing::debug!(ip = %ip, cidr = %cidr, policy = %cp.policy.name, "IP in blocked CIDR");
                    return Some(Verdict::Deny {
                        reason: format!(
                            "Resolved IP '{}' in blocked CIDR for policy '{}'",
                            ip, cp.policy.name
                        ),
                    });
                }
            }

            // Check allowed CIDRs (allowlist mode)
            if !ip_rules.allowed_cidrs.is_empty()
                && !ip_rules.allowed_cidrs.iter().any(|c| c.contains(&ip))
            {
                return Some(Verdict::Deny {
                    reason: format!(
                        "Resolved IP '{}' not in allowed CIDRs for policy '{}'",
                        ip, cp.policy.name
                    ),
                });
            }
        }

        None
    }
}
