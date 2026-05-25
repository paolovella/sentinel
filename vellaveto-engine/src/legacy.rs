// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Legacy policy evaluation methods.
//!
//! These methods provide backward-compatible policy evaluation using runtime
//! pattern matching (rather than pre-compiled policies). They are used by
//! [`PolicyEngine::evaluate_action`] when passed a slice of [`Policy`] objects
//! instead of using pre-compiled policies.
//!
//! The legacy path is slower than the compiled path but maintains API compatibility.

use crate::domain::{extract_domain, match_domain_pattern, normalize_domain_for_match};
use crate::error::EngineError;
use crate::ip;
use crate::path::normalize_path_bounded;
use crate::PolicyEngine;
use ipnet::IpNet;
use std::net::IpAddr;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

impl PolicyEngine {
    /// Check if a policy matches an action.
    ///
    /// Policy ID convention: `"tool:function"`, `"tool:*"`, `"*:function"`, or `"*"`.
    pub(crate) fn matches_action(&self, action: &Action, policy: &Policy) -> bool {
        let id = &policy.id;

        if id == "*" {
            return true;
        }

        if let Some((tool_pat, func_remainder)) = id.split_once(':') {
            // Support qualifier suffixes: "tool:func:qualifier" → match on "tool:func" only
            let func_pat = func_remainder
                .split_once(':')
                .map_or(func_remainder, |(f, _)| f);
            self.match_pattern(tool_pat, &action.tool)
                && self.match_pattern(func_pat, &action.function)
        } else {
            self.match_pattern(id, &action.tool)
        }
    }

    /// Match a pattern against a value. Supports `"*"` (match all),
    /// prefix wildcards (`"*suffix"`), suffix wildcards (`"prefix*"`), and exact match.
    ///
    /// **Known limitation (FIND-R46-004):** Infix wildcards like `"foo*bar"` are NOT
    /// supported by this legacy matcher. An infix wildcard pattern will be treated as
    /// a prefix match on `"foo"` (the `*` is found by `strip_suffix`, leaving `"foo"`).
    /// For correct infix wildcard support, use the compiled path (`with_policies()`)
    /// which delegates to [`PatternMatcher::compile`] and treats unsupported infix
    /// wildcards as match-all (fail-closed).
    fn match_pattern(&self, pattern: &str, value: &str) -> bool {
        // SECURITY (FIND-R206-003, R228-ENG-1): Normalize both pattern and value
        // through the full pipeline (NFKC + lowercase + homoglyph mapping) to
        // prevent Cyrillic/Greek/fullwidth/circled characters from bypassing legacy
        // Deny policies. Parity with PatternMatcher::compile() (normalize_full).
        let norm_pattern = crate::normalize::normalize_full(pattern);
        let norm_value = crate::normalize::normalize_full(value);

        if norm_pattern == "*" {
            return true;
        }
        if let Some(suffix) = norm_pattern.strip_prefix('*') {
            return norm_value.ends_with(suffix);
        }
        if let Some(prefix) = norm_pattern.strip_suffix('*') {
            // SECURITY (FIND-P2-006): Detect infix wildcards (e.g., "foo*bar") which
            // are not supported by the legacy matcher. After stripping the trailing `*`,
            // if the remaining prefix still contains `*`, this is an infix wildcard.
            // Warn operators so they know the pattern is being treated as a prefix match.
            // SECURITY (FIND-R49-005): Fail-closed for infix wildcards.
            // Infix wildcards (e.g., "foo*bar*") are not supported by the legacy
            // matcher. Instead of partial prefix matching (fail-open), match all
            // values so the policy still applies.
            if prefix.contains('*') {
                tracing::warn!(
                    pattern = %pattern,
                    "Legacy matcher detected infix wildcard pattern — treating as match-all \
                     (fail-closed). Use compiled policies (with_policies()) for correct infix support.",
                );
                return true;
            }
            return norm_value.starts_with(prefix);
        }
        norm_pattern == norm_value
    }

    /// Apply a matched policy to produce a verdict.
    /// Returns `None` when a Conditional policy with `on_no_match: "continue"` has no
    /// conditions fire, signaling the evaluation loop to try the next policy.
    ///
    /// SECURITY (P0-FIX): This legacy path now checks path_rules, network_rules, and
    /// ip_rules before returning the verdict, matching the behavior of the compiled
    /// policy path. Previously, these checks were skipped, allowing policy bypass.
    pub(crate) fn apply_policy(
        &self,
        action: &Action,
        policy: &Policy,
    ) -> Result<Option<Verdict>, EngineError> {
        // Check path rules before policy type dispatch (same as compiled path).
        if let Some(denial) = self.check_path_rules_legacy(action, policy)? {
            return Ok(Some(denial));
        }
        // Check network rules before policy type dispatch.
        if let Some(denial) = self.check_network_rules_legacy(action, policy) {
            return Ok(Some(denial));
        }
        // Check IP rules (DNS rebinding protection) after network rules.
        if let Some(denial) = self.check_ip_rules_legacy(action, policy) {
            return Ok(Some(denial));
        }

        match &policy.policy_type {
            PolicyType::Allow => Ok(Some(Verdict::Allow)),
            PolicyType::Deny => {
                // SECURITY (R239-XCUT-5): Genericize deny reason — policy name only in debug log.
                tracing::debug!(policy = %policy.name, "Request denied by policy");
                Ok(Some(Verdict::Deny {
                    reason: "Request denied by policy".to_string(),
                }))
            }
            PolicyType::Conditional { conditions } => {
                self.evaluate_conditions(action, policy, conditions)
            }
            // Handle future variants - fail closed (deny)
            _ => {
                tracing::debug!(policy = %policy.name, "Request denied (unknown policy type)");
                Ok(Some(Verdict::Deny {
                    reason: "Request denied (unknown policy type)".to_string(),
                }))
            }
        }
    }

    /// Check action target_paths against raw path rules (legacy path).
    ///
    /// SECURITY (P0-FIX): This is the legacy equivalent of `check_path_rules()` for
    /// the compiled path. It compiles glob patterns on each call (slower, but correct).
    fn check_path_rules_legacy(
        &self,
        action: &Action,
        policy: &Policy,
    ) -> Result<Option<Verdict>, EngineError> {
        let rules = match &policy.path_rules {
            Some(r) => r,
            None => return Ok(None),
        };

        // If both allowed and blocked are empty, no path rules to check
        if rules.allowed.is_empty() && rules.blocked.is_empty() {
            return Ok(None);
        }

        if action.target_paths.is_empty() {
            // SECURITY (R28-ENG-1): When an allowlist is configured but no
            // target paths were extracted, fail-closed.
            if !rules.allowed.is_empty() {
                return Ok(Some(Verdict::Deny {
                    reason: format!(
                        "No target paths provided but path allowlist is configured for policy '{}'",
                        policy.name
                    ),
                }));
            }
            return Ok(None); // Blocklist-only mode: nothing to block
        }

        for raw_path in &action.target_paths {
            let normalized = match normalize_path_bounded(raw_path, self.max_path_decode_iterations)
            {
                Ok(n) => n,
                Err(e) => {
                    return Ok(Some(Verdict::Deny {
                        reason: format!("Path normalization failed: {e}"),
                    }))
                }
            };

            // Check blocked patterns first (blocked takes precedence)
            for pattern in &rules.blocked {
                // SECURITY: Invalid glob patterns are treated as fail-closed (Deny),
                // not as errors. This ensures malformed policies don't cause 500s.
                match self.glob_is_match(pattern, &normalized, &policy.id) {
                    Ok(true) => {
                        tracing::debug!(path = %normalized, pattern = %pattern, policy = %policy.name, "Path blocked (legacy)");
                        return Ok(Some(Verdict::Deny {
                            reason: format!(
                                "Path '{}' blocked by policy '{}'",
                                normalized, policy.name
                            ),
                        }));
                    }
                    Ok(false) => {}
                    Err(e) => {
                        tracing::debug!(pattern = %pattern, policy = %policy.name, error = %e, "Invalid glob (legacy)");
                        return Ok(Some(Verdict::Deny {
                            reason: format!(
                                "Path rule error in policy '{}' (fail-closed)",
                                policy.name
                            ),
                        }));
                    }
                }
            }

            // If allowed list is non-empty, path must match at least one
            if !rules.allowed.is_empty() {
                let mut any_allowed = false;
                for pattern in &rules.allowed {
                    // SECURITY: Invalid glob patterns in allowlist are fail-closed.
                    match self.glob_is_match(pattern, &normalized, &policy.id) {
                        Ok(true) => {
                            any_allowed = true;
                            break;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            return Ok(Some(Verdict::Deny {
                                reason: format!(
                                    "Invalid glob pattern '{}' in policy '{}': {} (fail-closed)",
                                    pattern, policy.name, e
                                ),
                            }));
                        }
                    }
                }
                if !any_allowed {
                    return Ok(Some(Verdict::Deny {
                        reason: format!(
                            "Path '{}' not in allowed paths for policy '{}'",
                            normalized, policy.name
                        ),
                    }));
                }
            }
        }

        Ok(None)
    }

    /// Check action target_domains against raw network rules (legacy path).
    ///
    /// SECURITY (P0-FIX): This is the legacy equivalent of `check_network_rules()` for
    /// the compiled path.
    fn check_network_rules_legacy(&self, action: &Action, policy: &Policy) -> Option<Verdict> {
        let rules = match &policy.network_rules {
            Some(r) => r,
            None => return None,
        };

        // If both allowed and blocked domains are empty, no network rules to check
        if rules.allowed_domains.is_empty() && rules.blocked_domains.is_empty() {
            return None;
        }

        if action.target_domains.is_empty() {
            // SECURITY (R28-ENG-1): When an allowed_domains list is configured
            // but no target domains were extracted, fail-closed.
            if !rules.allowed_domains.is_empty() {
                return Some(Verdict::Deny {
                    reason: format!(
                        "No target domains provided but domain allowlist is configured for policy '{}'",
                        policy.name
                    ),
                });
            }
            return None; // Blocklist-only mode: nothing to block
        }

        for raw_domain in &action.target_domains {
            let domain = raw_domain.to_lowercase();

            // SECURITY (R30-ENG-2): Fail-closed for non-ASCII domains that fail
            // IDNA normalization.
            if normalize_domain_for_match(&domain).is_none() {
                // SECURITY (R239-XCUT-5): Genericize — domain/policy name in debug only.
                tracing::debug!(domain = %domain, policy = %policy.name, "IDNA normalization failed — blocked");
                return Some(Verdict::Deny {
                    reason: "Domain blocked by policy".to_string(),
                });
            }

            // Check blocked domains first
            for pattern in &rules.blocked_domains {
                if match_domain_pattern(&domain, pattern) {
                    tracing::debug!(domain = %domain, pattern = %pattern, policy = %policy.name, "Domain blocked (legacy)");
                    // SECURITY (R239-XCUT-5): Genericize — domain/policy name in debug only.
                    return Some(Verdict::Deny {
                        reason: "Domain blocked by policy".to_string(),
                    });
                }
            }

            // If allowed list is non-empty, domain must match at least one
            if !rules.allowed_domains.is_empty()
                && !rules
                    .allowed_domains
                    .iter()
                    .any(|p| match_domain_pattern(&domain, p))
            {
                // SECURITY (R239-XCUT-5): Genericize — domain/policy name in debug only.
                tracing::debug!(domain = %domain, policy = %policy.name, "Domain not in allowed list");
                return Some(Verdict::Deny {
                    reason: "Domain blocked by policy".to_string(),
                });
            }
        }

        None
    }

    /// Check resolved IPs against raw IP rules (legacy path).
    ///
    /// SECURITY (P0-FIX): This is the legacy equivalent of `check_ip_rules()` for
    /// the compiled path.
    fn check_ip_rules_legacy(&self, action: &Action, policy: &Policy) -> Option<Verdict> {
        let network_rules = match &policy.network_rules {
            Some(r) => r,
            None => return None,
        };
        let ip_rules = match &network_rules.ip_rules {
            Some(r) => r,
            None => return None,
        };

        // Fail-closed: if ip_rules are configured but no resolved IPs provided
        // and the action has target domains, deny.
        if action.resolved_ips.is_empty() && !action.target_domains.is_empty() {
            return Some(Verdict::Deny {
                reason: format!(
                    "IP rules configured but no resolved IPs provided for policy '{}'",
                    policy.name
                ),
            });
        }

        for ip_str in &action.resolved_ips {
            // Parse the IP address
            let raw_ip: IpAddr = match ip_str.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    return Some(Verdict::Deny {
                        reason: format!(
                            "Invalid resolved IP '{}' in policy '{}'",
                            ip_str, policy.name
                        ),
                    })
                }
            };

            // SECURITY (R24-ENG-1, R29-ENG-1): Canonicalize IPv6 transition
            // mechanism addresses to their embedded IPv4 form.
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

            // Check block_private
            if ip_rules.block_private && ip::is_private_ip(ip) {
                return Some(Verdict::Deny {
                    reason: format!(
                        "Resolved IP '{}' is a private/reserved address (DNS rebinding protection) in policy '{}'",
                        ip, policy.name
                    ),
                });
            }

            // Check blocked_cidrs
            // SECURITY (FIND-050): Fail-closed on CIDR parse errors. The compiled
            // path rejects invalid CIDRs at compile time, but the legacy path
            // parses at evaluation time. A typo like "10.0.0.0/33" must deny
            // rather than silently skip, otherwise the blocklist has a hole.
            for cidr_str in &ip_rules.blocked_cidrs {
                match cidr_str.parse::<IpNet>() {
                    Ok(cidr) if cidr.contains(&ip) => {
                        return Some(Verdict::Deny {
                            reason: format!(
                                "Resolved IP '{}' in blocked CIDR '{}' in policy '{}'",
                                ip, cidr_str, policy.name
                            ),
                        });
                    }
                    Err(_) => {
                        tracing::error!(
                            cidr = %cidr_str,
                            policy = %policy.name,
                            "Invalid blocked CIDR in policy (fail-closed)"
                        );
                        return Some(Verdict::Deny {
                            reason: format!(
                                "Invalid blocked CIDR '{}' in policy '{}' (fail-closed)",
                                cidr_str, policy.name
                            ),
                        });
                    }
                    _ => {}
                }
            }

            // Check allowed_cidrs (if non-empty, must match at least one)
            // SECURITY (FIND-050): Fail-closed on CIDR parse errors in allowlist too.
            // An invalid allowed CIDR should deny (cannot confirm IP is allowed)
            // rather than silently return false which happens to be correct but
            // masks configuration errors.
            if !ip_rules.allowed_cidrs.is_empty() {
                let mut found_invalid = false;
                let allowed =
                    ip_rules
                        .allowed_cidrs
                        .iter()
                        .any(|cidr_str| match cidr_str.parse::<IpNet>() {
                            Ok(cidr) => cidr.contains(&ip),
                            Err(_) => {
                                tracing::error!(
                                    cidr = %cidr_str,
                                    policy = %policy.name,
                                    "Invalid allowed CIDR in policy (fail-closed)"
                                );
                                found_invalid = true;
                                false
                            }
                        });
                if found_invalid && !allowed {
                    return Some(Verdict::Deny {
                        reason: format!(
                            "Invalid allowed CIDR in policy '{}' (fail-closed)",
                            policy.name
                        ),
                    });
                }
                if !allowed {
                    return Some(Verdict::Deny {
                        reason: format!(
                            "Resolved IP '{}' not in allowed CIDRs for policy '{}'",
                            ip, policy.name
                        ),
                    });
                }
            }
        }

        None
    }

    /// Evaluate conditional policy rules.
    ///
    /// Supported condition keys:
    /// - `forbidden_parameters`: array of parameter keys that must not be present
    /// - `required_parameters`: array of parameter keys that must be present
    /// - `require_approval`: if true, returns RequireApproval verdict
    fn evaluate_conditions(
        &self,
        action: &Action,
        policy: &Policy,
        conditions: &serde_json::Value,
    ) -> Result<Option<Verdict>, EngineError> {
        // JSON depth protection
        if Self::json_depth(conditions) > 10 {
            return Err(EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "Condition JSON exceeds maximum nesting depth of 10".to_string(),
            });
        }

        // SECURITY (R230-ENG-1): Use canonical MAX_CONDITIONS_SIZE, matching compiled path.
        let size = conditions.to_string().len();
        if size > vellaveto_types::MAX_CONDITIONS_SIZE {
            return Err(EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: format!(
                    "Condition JSON too large: {} bytes (max {})",
                    size,
                    vellaveto_types::MAX_CONDITIONS_SIZE
                ),
            });
        }

        // In strict mode, reject unrecognized condition keys with an explicit
        // validation error before the broader non-strict fail-closed path.
        if self.strict_mode {
            if let Some(obj) = conditions.as_object() {
                for key in obj.keys() {
                    if !Self::condition_key_is_known(key) {
                        return Err(EngineError::InvalidCondition {
                            policy_id: policy.id.clone(),
                            reason: format!("Unknown condition key '{key}' in strict mode"),
                        });
                    }
                }
            }
        }

        if crate::verified_constraint_eval::unrecognized_condition_payload(
            Self::condition_payload_is_non_empty(conditions),
            Self::condition_has_known_key(conditions),
        ) {
            tracing::warn!(
                policy = %policy.name,
                "Conditional policy has no recognized condition keys — fail-closed"
            );
            return Ok(Some(Verdict::Deny {
                reason: format!(
                    "Policy '{}' has no recognized condition keys (fail-closed)",
                    policy.name
                ),
            }));
        }

        // Check require_approval first
        // SECURITY (FIND-IMP-013): Fail-closed — non-boolean values default to
        // requiring approval rather than silently bypassing it.
        if let Some(require_approval) = conditions.get("require_approval") {
            if require_approval.as_bool().unwrap_or(true) {
                // SECURITY (R239-XCUT-5): Genericize — policy name in debug only.
                tracing::debug!(policy = %policy.name, "Approval required by policy");
                return Ok(Some(Verdict::RequireApproval {
                    reason: "Approval required by policy".to_string(),
                }));
            }
        }

        // Check forbidden parameters
        // R231-ENG-3: Fail-closed if value is present but not an array.
        if let Some(forbidden) = conditions.get("forbidden_parameters") {
            if let Some(forbidden_arr) = forbidden.as_array() {
                for param in forbidden_arr {
                    if let Some(param_str) = param.as_str() {
                        if action.parameters.get(param_str).is_some() {
                            return Ok(Some(Verdict::Deny {
                                reason: format!(
                                    "Parameter '{}' is forbidden by policy '{}'",
                                    param_str, policy.name
                                ),
                            }));
                        }
                    }
                }
            } else {
                tracing::warn!(policy = %policy.name, "forbidden_parameters is not an array — fail-closed");
                return Ok(Some(Verdict::Deny {
                    reason: format!(
                        "Malformed forbidden_parameters in policy '{}' (fail-closed)",
                        policy.name
                    ),
                }));
            }
        }

        // Check required parameters
        // R231-ENG-3: Fail-closed if value is present but not an array.
        if let Some(required) = conditions.get("required_parameters") {
            if let Some(required_arr) = required.as_array() {
                for param in required_arr {
                    if let Some(param_str) = param.as_str() {
                        if action.parameters.get(param_str).is_none() {
                            return Ok(Some(Verdict::Deny {
                                reason: format!(
                                    "Required parameter '{}' missing (policy '{}')",
                                    param_str, policy.name
                                ),
                            }));
                        }
                    }
                }
            } else {
                tracing::warn!(policy = %policy.name, "required_parameters is not an array — fail-closed");
                return Ok(Some(Verdict::Deny {
                    reason: format!(
                        "Malformed required_parameters in policy '{}' (fail-closed)",
                        policy.name
                    ),
                }));
            }
        }

        let on_no_match_continue =
            conditions.get("on_no_match").and_then(|v| v.as_str()) == Some("continue");

        // Evaluate parameter constraints
        if let Some(constraints) = conditions.get("parameter_constraints") {
            if let Some(arr) = constraints.as_array() {
                if let Some(verdict) =
                    self.evaluate_parameter_constraints(action, policy, arr, on_no_match_continue)?
                {
                    return Ok(Some(verdict));
                }
            } else {
                return Err(EngineError::InvalidCondition {
                    policy_id: policy.id.clone(),
                    reason: "parameter_constraints must be an array".to_string(),
                });
            }
        }

        // No conditions triggered. Check on_no_match setting.
        if on_no_match_continue {
            Ok(None)
        } else {
            Ok(Some(Verdict::Allow))
        }
    }

    /// Evaluate an array of parameter constraints against the action.
    ///
    /// Returns `Ok(Some(verdict))` if a constraint fires, `Ok(None)` if all pass.
    /// If ALL constraints are skipped due to missing parameters, returns a Deny
    /// verdict (fail-closed) instead of `None`.
    fn evaluate_parameter_constraints(
        &self,
        action: &Action,
        policy: &Policy,
        constraints: &[serde_json::Value],
        on_no_match_continue: bool,
    ) -> Result<Option<Verdict>, EngineError> {
        let mut any_evaluated = false;
        let total_constraints = constraints.len();

        for constraint in constraints {
            let obj = constraint
                .as_object()
                .ok_or_else(|| EngineError::InvalidCondition {
                    policy_id: policy.id.clone(),
                    reason: "Each parameter constraint must be a JSON object".to_string(),
                })?;

            let param_name = obj.get("param").and_then(|v| v.as_str()).ok_or_else(|| {
                EngineError::InvalidCondition {
                    policy_id: policy.id.clone(),
                    reason: "Constraint missing required 'param' string field".to_string(),
                }
            })?;

            let op = obj.get("op").and_then(|v| v.as_str()).ok_or_else(|| {
                EngineError::InvalidCondition {
                    policy_id: policy.id.clone(),
                    reason: "Constraint missing required 'op' string field".to_string(),
                }
            })?;

            let on_match = obj
                .get("on_match")
                .and_then(|v| v.as_str())
                .unwrap_or("deny");

            let on_missing = obj
                .get("on_missing")
                .and_then(|v| v.as_str())
                .unwrap_or("deny");

            // Wildcard param "*": recursively scan ALL string values in parameters
            if param_name == "*" {
                let (all_values, truncated) = Self::collect_all_string_values(&action.parameters);
                if all_values.is_empty() {
                    if on_missing == "skip" {
                        continue;
                    }
                    return Ok(Some(Self::make_constraint_verdict(
                        "deny",
                        &format!(
                            "No string values found in parameters (fail-closed) in policy '{}'",
                            policy.name
                        ),
                    )?));
                }
                any_evaluated = true;
                for (value_path, value_str) in &all_values {
                    let json_val = serde_json::Value::String((*value_str).to_string());
                    if let Some(verdict) = self.evaluate_single_constraint(
                        policy, value_path, op, on_match, &json_val, obj,
                    )? {
                        return Ok(Some(verdict));
                    }
                }
                // SECURITY (R234-ENG-4): Fail-closed on truncated scan.
                if truncated {
                    return Ok(Some(Verdict::Deny {
                        reason: format!(
                            "Parameter scan truncated at {} values — deny (fail-closed) in policy '{}'",
                            Self::MAX_SCAN_VALUES,
                            policy.name,
                        ),
                    }));
                }
                continue;
            }

            // Get the parameter value from the action, supporting dot-separated paths
            // e.g. "config.output.path" traverses into nested objects
            let param_value = match Self::get_param_by_path(&action.parameters, param_name) {
                Some(v) => v,
                None => {
                    if on_missing == "skip" {
                        continue;
                    }
                    // Fail-closed: missing parameter → deny
                    return Ok(Some(Self::make_constraint_verdict(
                        "deny",
                        &format!(
                            "Parameter '{}' missing (fail-closed) in policy '{}'",
                            param_name, policy.name
                        ),
                    )?));
                }
            };

            any_evaluated = true;
            if let Some(verdict) =
                self.evaluate_single_constraint(policy, param_name, op, on_match, param_value, obj)?
            {
                return Ok(Some(verdict));
            }
        }

        // Fail-closed: if ALL constraints were skipped, deny (unless on_no_match="continue")
        if total_constraints > 0 && !any_evaluated && !on_no_match_continue {
            return Ok(Some(Verdict::Deny {
                reason: format!(
                    "All {} constraints skipped (parameters missing) in policy '{}' — fail-closed",
                    total_constraints, policy.name
                ),
            }));
        }

        Ok(None)
    }

    /// Dispatch a single constraint by operator.
    fn evaluate_single_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        op: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        match op {
            "glob" => self.eval_glob_constraint(policy, param_name, on_match, value, constraint),
            "not_glob" => {
                self.eval_not_glob_constraint(policy, param_name, on_match, value, constraint)
            }
            "domain_match" => {
                self.eval_domain_match_constraint(policy, param_name, on_match, value, constraint)
            }
            "domain_not_in" => {
                self.eval_domain_not_in_constraint(policy, param_name, on_match, value, constraint)
            }
            "regex" => self.eval_regex_constraint(policy, param_name, on_match, value, constraint),
            "eq" => self.eval_eq_constraint(policy, param_name, on_match, value, constraint),
            "ne" => self.eval_ne_constraint(policy, param_name, on_match, value, constraint),
            "one_of" => {
                self.eval_one_of_constraint(policy, param_name, on_match, value, constraint)
            }
            "none_of" => {
                self.eval_none_of_constraint(policy, param_name, on_match, value, constraint)
            }
            _ => Err(EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: format!("Unknown constraint operator '{op}'"),
            }),
        }
    }

    /// Glob match: fires when normalized path matches the glob pattern.
    fn eval_glob_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let raw = match value.as_str() {
            Some(s) => s,
            None => {
                if self.strict_mode {
                    return Err(EngineError::InvalidCondition {
                        policy_id: policy.id.clone(),
                        reason: format!(
                            "Parameter '{param_name}' is not a string for glob operator"
                        ),
                    });
                }
                // Non-strict: non-string on string operator → deny
                return Ok(Some(Self::make_constraint_verdict(
                    "deny",
                    &format!(
                        "Parameter '{}' is not a string (policy '{}')",
                        param_name, policy.name
                    ),
                )?));
            }
        };

        let pattern_str = constraint
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "glob constraint missing 'pattern' string".to_string(),
            })?;

        let normalized = match normalize_path_bounded(raw, self.max_path_decode_iterations) {
            Ok(n) => n,
            Err(e) => {
                return Ok(Some(Verdict::Deny {
                    reason: format!("Path normalization failed: {e}"),
                }))
            }
        };

        if self.glob_is_match(pattern_str, &normalized, &policy.id)? {
            Ok(Some(Self::make_constraint_verdict(
                on_match,
                &format!(
                    "Parameter '{}' path '{}' matches glob '{}' (policy '{}')",
                    param_name, normalized, pattern_str, policy.name
                ),
            )?))
        } else {
            Ok(None)
        }
    }

    /// Not-glob: fires when path matches NONE of the allowlist glob patterns.
    fn eval_not_glob_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let raw = match value.as_str() {
            Some(s) => s,
            None => {
                if self.strict_mode {
                    return Err(EngineError::InvalidCondition {
                        policy_id: policy.id.clone(),
                        reason: format!(
                            "Parameter '{param_name}' is not a string for not_glob operator"
                        ),
                    });
                }
                return Ok(Some(Self::make_constraint_verdict(
                    "deny",
                    &format!(
                        "Parameter '{}' is not a string (policy '{}')",
                        param_name, policy.name
                    ),
                )?));
            }
        };

        let patterns = constraint
            .get("patterns")
            .and_then(|v| v.as_array())
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "not_glob constraint missing 'patterns' array".to_string(),
            })?;

        let normalized = match normalize_path_bounded(raw, self.max_path_decode_iterations) {
            Ok(n) => n,
            Err(e) => {
                return Ok(Some(Verdict::Deny {
                    reason: format!("Path normalization failed: {e}"),
                }))
            }
        };

        for pat_val in patterns {
            let pat_str = pat_val
                .as_str()
                .ok_or_else(|| EngineError::InvalidCondition {
                    policy_id: policy.id.clone(),
                    reason: "not_glob patterns must be strings".to_string(),
                })?;
            if self.glob_is_match(pat_str, &normalized, &policy.id)? {
                return Ok(None); // Matched allowlist, no fire
            }
        }

        // Matched NONE → fire
        Ok(Some(Self::make_constraint_verdict(
            on_match,
            &format!(
                "Parameter '{}' path '{}' not in allowlist (policy '{}')",
                param_name, normalized, policy.name
            ),
        )?))
    }

    /// Domain match: fires when extracted domain matches a `*.example.com` style pattern.
    fn eval_domain_match_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let raw = match value.as_str() {
            Some(s) => s,
            None => {
                if self.strict_mode {
                    return Err(EngineError::InvalidCondition {
                        policy_id: policy.id.clone(),
                        reason: format!(
                            "Parameter '{param_name}' is not a string for domain_match operator"
                        ),
                    });
                }
                return Ok(Some(Self::make_constraint_verdict(
                    "deny",
                    &format!(
                        "Parameter '{}' is not a string (policy '{}')",
                        param_name, policy.name
                    ),
                )?));
            }
        };

        let pattern = constraint
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "domain_match constraint missing 'pattern' string".to_string(),
            })?;

        let domain = extract_domain(raw);

        // SECURITY (R34-ENG-3): IDNA fail-closed guard matching compiled path (R31-ENG-1).
        if !domain.is_ascii() && normalize_domain_for_match(&domain).is_none() {
            return Ok(Some(Self::make_constraint_verdict(
                "deny",
                &format!(
                    "Parameter '{}' domain '{}' cannot be normalized (IDNA failure) (policy '{}')",
                    param_name, domain, policy.name
                ),
            )?));
        }

        if match_domain_pattern(&domain, pattern) {
            Ok(Some(Self::make_constraint_verdict(
                on_match,
                &format!(
                    "Parameter '{}' domain '{}' matches '{}' (policy '{}')",
                    param_name, domain, pattern, policy.name
                ),
            )?))
        } else {
            Ok(None)
        }
    }

    /// Domain not-in: fires when extracted domain matches NONE of the allowlist patterns.
    fn eval_domain_not_in_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let raw = match value.as_str() {
            Some(s) => s,
            None => {
                if self.strict_mode {
                    return Err(EngineError::InvalidCondition {
                        policy_id: policy.id.clone(),
                        reason: format!(
                            "Parameter '{param_name}' is not a string for domain_not_in operator"
                        ),
                    });
                }
                return Ok(Some(Self::make_constraint_verdict(
                    "deny",
                    &format!(
                        "Parameter '{}' is not a string (policy '{}')",
                        param_name, policy.name
                    ),
                )?));
            }
        };

        let patterns = constraint
            .get("patterns")
            .and_then(|v| v.as_array())
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "domain_not_in constraint missing 'patterns' array".to_string(),
            })?;

        let domain = extract_domain(raw);

        // SECURITY (R34-ENG-3): IDNA fail-closed guard matching compiled path (R31-ENG-1).
        if !domain.is_ascii() && normalize_domain_for_match(&domain).is_none() {
            return Ok(Some(Self::make_constraint_verdict(
                "deny",
                &format!(
                    "Parameter '{}' domain '{}' cannot be normalized (IDNA failure) (policy '{}')",
                    param_name, domain, policy.name
                ),
            )?));
        }

        for pat_val in patterns {
            let pat_str = pat_val
                .as_str()
                .ok_or_else(|| EngineError::InvalidCondition {
                    policy_id: policy.id.clone(),
                    reason: "domain_not_in patterns must be strings".to_string(),
                })?;
            if match_domain_pattern(&domain, pat_str) {
                return Ok(None); // Matched allowlist
            }
        }

        Ok(Some(Self::make_constraint_verdict(
            on_match,
            &format!(
                "Parameter '{}' domain '{}' not in allowlist (policy '{}')",
                param_name, domain, policy.name
            ),
        )?))
    }

    /// Regex: fires when value matches the regex pattern.
    fn eval_regex_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let raw = match value.as_str() {
            Some(s) => s,
            None => {
                if self.strict_mode {
                    return Err(EngineError::InvalidCondition {
                        policy_id: policy.id.clone(),
                        reason: format!(
                            "Parameter '{param_name}' is not a string for regex operator"
                        ),
                    });
                }
                return Ok(Some(Self::make_constraint_verdict(
                    "deny",
                    &format!(
                        "Parameter '{}' is not a string (policy '{}')",
                        param_name, policy.name
                    ),
                )?));
            }
        };

        let pattern = constraint
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "regex constraint missing 'pattern' string".to_string(),
            })?;

        let matched = self.regex_is_match(pattern, raw, &policy.id)?;

        if matched {
            Ok(Some(Self::make_constraint_verdict(
                on_match,
                &format!(
                    "Parameter '{}' matches regex '{}' (policy '{}')",
                    param_name, pattern, policy.name
                ),
            )?))
        } else {
            Ok(None)
        }
    }

    /// Eq: fires when value equals the specified value exactly.
    fn eval_eq_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let expected = constraint
            .get("value")
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "eq constraint missing 'value' field".to_string(),
            })?;

        if value == expected {
            Ok(Some(Self::make_constraint_verdict(
                on_match,
                &format!(
                    "Parameter '{}' equals {:?} (policy '{}')",
                    param_name, expected, policy.name
                ),
            )?))
        } else {
            Ok(None)
        }
    }

    /// Ne: fires when value does NOT equal the specified value.
    fn eval_ne_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let expected = constraint
            .get("value")
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "ne constraint missing 'value' field".to_string(),
            })?;

        if value != expected {
            Ok(Some(Self::make_constraint_verdict(
                on_match,
                &format!(
                    "Parameter '{}' != {:?} (policy '{}')",
                    param_name, expected, policy.name
                ),
            )?))
        } else {
            Ok(None)
        }
    }

    /// One-of: fires when value is in the specified set.
    fn eval_one_of_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let values = constraint
            .get("values")
            .and_then(|v| v.as_array())
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "one_of constraint missing 'values' array".to_string(),
            })?;

        if values.contains(value) {
            Ok(Some(Self::make_constraint_verdict(
                on_match,
                &format!(
                    "Parameter '{}' is in the specified set (policy '{}')",
                    param_name, policy.name
                ),
            )?))
        } else {
            Ok(None)
        }
    }

    /// None-of: fires when value is NOT in the specified set.
    fn eval_none_of_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let values = constraint
            .get("values")
            .and_then(|v| v.as_array())
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "none_of constraint missing 'values' array".to_string(),
            })?;

        if !values.contains(value) {
            Ok(Some(Self::make_constraint_verdict(
                on_match,
                &format!(
                    "Parameter '{}' is not in the allowed set (policy '{}')",
                    param_name, policy.name
                ),
            )?))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_policy(id: &str, name: &str, policy_type: PolicyType) -> Policy {
        Policy {
            id: id.to_string(),
            name: name.to_string(),
            policy_type,
            priority: 100,
            path_rules: None,
            network_rules: None,
        }
    }

    // ---- matches_action tests ----

    #[test]
    fn test_matches_action_wildcard() {
        let engine = PolicyEngine::new(false);
        let action = Action::new("any_tool", "any_func", json!({}));
        let policy = make_policy("*", "match-all", PolicyType::Allow);
        assert!(engine.matches_action(&action, &policy));
    }

    #[test]
    fn test_matches_action_exact_tool_function() {
        let engine = PolicyEngine::new(false);
        let action = Action::new("file_system", "read_file", json!({}));
        let policy = make_policy("file_system:read_file", "exact", PolicyType::Allow);
        assert!(engine.matches_action(&action, &policy));
    }

    #[test]
    fn test_matches_action_exact_tool_function_mismatch() {
        let engine = PolicyEngine::new(false);
        let action = Action::new("file_system", "write_file", json!({}));
        let policy = make_policy("file_system:read_file", "exact", PolicyType::Allow);
        assert!(!engine.matches_action(&action, &policy));
    }

    #[test]
    fn test_matches_action_tool_wildcard_function() {
        let engine = PolicyEngine::new(false);
        let action = Action::new("bash", "execute", json!({}));
        let policy = make_policy("bash:*", "bash-all", PolicyType::Deny);
        assert!(engine.matches_action(&action, &policy));
    }

    #[test]
    fn test_matches_action_wildcard_tool_specific_function() {
        let engine = PolicyEngine::new(false);
        let action = Action::new("any_tool", "delete", json!({}));
        let policy = make_policy("*:delete", "deny-delete", PolicyType::Deny);
        assert!(engine.matches_action(&action, &policy));
    }

    #[test]
    fn test_matches_action_tool_only_no_colon() {
        let engine = PolicyEngine::new(false);
        let action = Action::new("bash", "execute", json!({}));
        let policy = make_policy("bash", "tool-only", PolicyType::Deny);
        assert!(engine.matches_action(&action, &policy));
    }

    #[test]
    fn test_matches_action_tool_only_mismatch() {
        let engine = PolicyEngine::new(false);
        let action = Action::new("python", "execute", json!({}));
        let policy = make_policy("bash", "tool-only", PolicyType::Deny);
        assert!(!engine.matches_action(&action, &policy));
    }

    #[test]
    fn test_matches_action_qualifier_suffix_ignored() {
        let engine = PolicyEngine::new(false);
        let action = Action::new("file_system", "read_file", json!({}));
        // "tool:func:qualifier" -> match on "tool:func" only
        let policy = make_policy("file_system:read_file:v2", "qualified", PolicyType::Allow);
        assert!(engine.matches_action(&action, &policy));
    }

    // ---- match_pattern tests ----

    #[test]
    fn test_match_pattern_exact() {
        let engine = PolicyEngine::new(false);
        assert!(engine.match_pattern("bash", "bash"));
        assert!(!engine.match_pattern("bash", "python"));
    }

    #[test]
    fn test_match_pattern_wildcard_all() {
        let engine = PolicyEngine::new(false);
        assert!(engine.match_pattern("*", "anything"));
        assert!(engine.match_pattern("*", ""));
    }

    #[test]
    fn test_match_pattern_prefix_wildcard() {
        let engine = PolicyEngine::new(false);
        assert!(engine.match_pattern("file_*", "file_system"));
        assert!(engine.match_pattern("file_*", "file_read"));
        assert!(!engine.match_pattern("file_*", "bash"));
    }

    #[test]
    fn test_match_pattern_suffix_wildcard() {
        let engine = PolicyEngine::new(false);
        assert!(engine.match_pattern("*_file", "read_file"));
        assert!(engine.match_pattern("*_file", "write_file"));
        assert!(!engine.match_pattern("*_file", "read_dir"));
    }

    #[test]
    fn test_match_pattern_case_insensitive_via_normalize() {
        let engine = PolicyEngine::new(false);
        // normalize_full lowercases both sides
        assert!(engine.match_pattern("BASH", "bash"));
        assert!(engine.match_pattern("bash", "BASH"));
    }

    #[test]
    fn test_match_pattern_infix_wildcard_fail_closed() {
        let engine = PolicyEngine::new(false);
        // Infix wildcards (e.g., "foo*bar*") should be treated as match-all (fail-closed)
        assert!(engine.match_pattern("foo*bar*", "anything"));
        assert!(engine.match_pattern("a*b*c*", "xyz"));
    }

    // ---- apply_policy tests ----

    #[test]
    fn test_apply_policy_allow() {
        let engine = PolicyEngine::new(false);
        let policy = make_policy("*", "allow-all", PolicyType::Allow);
        let action = Action::new("tool", "func", json!({}));
        let result = engine.apply_policy(&action, &policy).unwrap();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Verdict::Allow));
    }

    #[test]
    fn test_apply_policy_deny() {
        let engine = PolicyEngine::new(false);
        let policy = make_policy("bash:*", "deny-bash", PolicyType::Deny);
        let action = Action::new("bash", "execute", json!({}));
        let result = engine.apply_policy(&action, &policy).unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            Verdict::Deny { reason } => {
                assert!(reason.contains("Request denied by policy"));
            }
            _ => panic!("Expected Deny"),
        }
    }

    // ---- evaluate_conditions tests ----

    #[test]
    fn test_evaluate_conditions_require_approval() {
        let engine = PolicyEngine::new(false);
        let policy = make_policy("*", "approval", PolicyType::Allow);
        let conditions = json!({ "require_approval": true });
        let action = Action::new("tool", "func", json!({}));
        let result = engine
            .evaluate_conditions(&action, &policy, &conditions)
            .unwrap();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Verdict::RequireApproval { .. }));
    }

    #[test]
    fn test_evaluate_conditions_forbidden_params() {
        let engine = PolicyEngine::new(false);
        let policy = make_policy("*", "no-secret", PolicyType::Allow);
        let conditions = json!({ "forbidden_parameters": ["password"] });
        let action = Action::new("tool", "func", json!({ "password": "abc" }));
        let result = engine
            .evaluate_conditions(&action, &policy, &conditions)
            .unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            Verdict::Deny { reason } => assert!(reason.contains("forbidden")),
            _ => panic!("Expected Deny"),
        }
    }

    #[test]
    fn test_evaluate_conditions_required_params_missing() {
        let engine = PolicyEngine::new(false);
        let policy = make_policy("*", "need-token", PolicyType::Allow);
        let conditions = json!({ "required_parameters": ["api_key"] });
        let action = Action::new("tool", "func", json!({}));
        let result = engine
            .evaluate_conditions(&action, &policy, &conditions)
            .unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            Verdict::Deny { reason } => assert!(reason.contains("Required parameter")),
            _ => panic!("Expected Deny"),
        }
    }

    #[test]
    fn test_evaluate_conditions_deep_json_rejected() {
        let engine = PolicyEngine::new(false);
        let policy = make_policy("*", "deep", PolicyType::Allow);
        // Build JSON with depth > 10
        let mut deep = json!({"a": 1});
        for _ in 0..15 {
            deep = json!({"nested": deep});
        }
        let result =
            engine.evaluate_conditions(&Action::new("tool", "func", json!({})), &policy, &deep);
        assert!(result.is_err());
    }

    #[test]
    fn test_evaluate_conditions_on_no_match_continue() {
        let engine = PolicyEngine::new(false);
        let policy = make_policy("*", "continue", PolicyType::Allow);
        let conditions = json!({ "on_no_match": "continue" });
        let action = Action::new("tool", "func", json!({}));
        let result = engine
            .evaluate_conditions(&action, &policy, &conditions)
            .unwrap();
        // on_no_match="continue" -> None (skip to next policy)
        assert!(result.is_none());
    }

    #[test]
    fn test_evaluate_conditions_no_conditions_allow() {
        let engine = PolicyEngine::new(false);
        let policy = make_policy("*", "empty", PolicyType::Allow);
        let conditions = json!({});
        let action = Action::new("tool", "func", json!({}));
        let result = engine
            .evaluate_conditions(&action, &policy, &conditions)
            .unwrap();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Verdict::Allow));
    }

    #[test]
    fn test_evaluate_conditions_strict_mode_unknown_key() {
        let engine = PolicyEngine::new(true); // strict mode
        let policy = make_policy("*", "strict", PolicyType::Allow);
        let conditions = json!({ "unknown_key": "value" });
        let action = Action::new("tool", "func", json!({}));
        let result = engine.evaluate_conditions(&action, &policy, &conditions);
        assert!(result.is_err());
    }

    // ---- evaluate_conditions fail-closed for non-array forbidden/required ----

    #[test]
    fn test_evaluate_conditions_forbidden_params_non_array_fail_closed() {
        let engine = PolicyEngine::new(false);
        let policy = make_policy("*", "bad-config", PolicyType::Allow);
        let conditions = json!({ "forbidden_parameters": "not-an-array" });
        let action = Action::new("tool", "func", json!({}));
        let result = engine
            .evaluate_conditions(&action, &policy, &conditions)
            .unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            Verdict::Deny { reason } => assert!(reason.contains("Malformed")),
            _ => panic!("Expected Deny for non-array forbidden_parameters"),
        }
    }

    #[test]
    fn test_evaluate_conditions_required_params_non_array_fail_closed() {
        let engine = PolicyEngine::new(false);
        let policy = make_policy("*", "bad-config", PolicyType::Allow);
        let conditions = json!({ "required_parameters": 42 });
        let action = Action::new("tool", "func", json!({}));
        let result = engine
            .evaluate_conditions(&action, &policy, &conditions)
            .unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            Verdict::Deny { reason } => assert!(reason.contains("Malformed")),
            _ => panic!("Expected Deny for non-array required_parameters"),
        }
    }

    // ---- Legacy path rules tests ----

    #[test]
    fn test_check_path_rules_legacy_blocked_path() {
        let engine = PolicyEngine::new(false);
        let policy = Policy {
            id: "*".to_string(),
            name: "block-etc".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: Some(vellaveto_types::PathRules {
                allowed: vec![],
                blocked: vec!["/etc/**".to_string()],
            }),
            network_rules: None,
        };
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = vec!["/etc/passwd".to_string()];
        let result = engine.check_path_rules_legacy(&action, &policy).unwrap();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Verdict::Deny { .. }));
    }

    #[test]
    fn test_check_path_rules_legacy_no_path_rules() {
        let engine = PolicyEngine::new(false);
        let policy = make_policy("*", "no-rules", PolicyType::Allow);
        let action = Action::new("tool", "func", json!({}));
        let result = engine.check_path_rules_legacy(&action, &policy).unwrap();
        assert!(result.is_none());
    }

    // ---- Legacy network rules tests ----

    #[test]
    fn test_check_network_rules_legacy_blocked_domain() {
        let engine = PolicyEngine::new(false);
        let policy = Policy {
            id: "*".to_string(),
            name: "block-evil".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: Some(vellaveto_types::NetworkRules {
                allowed_domains: vec![],
                blocked_domains: vec!["evil.com".to_string()],
                ip_rules: None,
            }),
        };
        let mut action = Action::new("tool", "func", json!({}));
        action.target_domains = vec!["evil.com".to_string()];
        let result = engine.check_network_rules_legacy(&action, &policy);
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Verdict::Deny { .. }));
    }

    #[test]
    fn test_check_network_rules_legacy_no_network_rules() {
        let engine = PolicyEngine::new(false);
        let policy = make_policy("*", "no-net", PolicyType::Allow);
        let action = Action::new("tool", "func", json!({}));
        let result = engine.check_network_rules_legacy(&action, &policy);
        assert!(result.is_none());
    }
}
