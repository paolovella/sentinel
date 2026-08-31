// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Differential binding for `PARITY-HAND-2` — path rule fail-closed decisions.
//!
//! `formal/kani/src/rule_check.rs` reduces the rule checks to pure boolean
//! predicates, abstracting glob matching to `matches: bool` because globset is
//! third-party. K41-K45 are the fail-closed properties proved on top: no target
//! paths with an allowlist configured denies, a blocked match denies even when
//! also allowed, and so on.
//!
//! The abstraction is reasonable. What was never checked is whether the
//! predicate the proofs explore agrees with the decision production makes.
//!
//! The booleans here are **derived from constructed policies and actions**
//! rather than enumerated freely, because most of the 2^5 combinations are not
//! realisable — a path cannot be blocked when there are no paths. Enumerating
//! the free product would compare production against inputs that cannot occur
//! and prove nothing about the ones that can.

#[cfg(test)]
// Suppressed rather than satisfied: linting the extraction would edit the copy
// the Kani proofs run against.
#[allow(clippy::manual_range_contains, dead_code, unused_imports)]
mod extracted {
    include!(concat!(env!("OUT_DIR"), "/kani_rule_check_extraction.rs"));
}

#[cfg(test)]
mod kani_parity_differential_rule_check {
    use super::extracted;
    use crate::PolicyEngine;
    use vellaveto_types::{Action, PathRules, Policy, PolicyType, Verdict};

    fn policy_with_path_rules(allowed: &[&str], blocked: &[&str]) -> Policy {
        Policy {
            id: "p1".to_string(),
            name: "path rules under test".to_string(),
            policy_type: PolicyType::Allow,
            priority: 0,
            path_rules: Some(PathRules {
                allowed: allowed.iter().map(|s| (*s).to_string()).collect(),
                blocked: blocked.iter().map(|s| (*s).to_string()).collect(),
            }),
            network_rules: None,
        }
    }

    fn action_with_paths(paths: &[&str]) -> Action {
        let mut action = Action::new("fs", "read", serde_json::json!({}));
        action.target_paths = paths.iter().map(|s| (*s).to_string()).collect();
        action
    }

    /// Every combination of allowlist/blocklist configuration crossed with a
    /// set of target paths chosen so each realisable shape is reached: no
    /// paths, a path that only matches the allowlist, one that only matches the
    /// blocklist, one that matches both, and one that matches neither.
    #[test]
    fn test_path_rule_decision_matches_production() {
        const ALLOWED: [&[&str]; 2] = [&[], &["/srv/**"]];
        const BLOCKED: [&[&str]; 2] = [&[], &["/srv/secret/**"]];
        const PATH_SETS: [&[&str]; 6] = [
            &[],
            &["/srv/data.txt"],                        // allowed only
            &["/srv/secret/key.pem"],                  // allowed and blocked
            &["/etc/passwd"],                          // neither
            &["/srv/data.txt", "/etc/x"],              // one allowed, one not
            &["/srv/data.txt", "/srv/secret/key.pem"], // one allowed, one blocked
        ];

        let engine = PolicyEngine::new(false);
        let mut checked = 0usize;
        let mut denied = 0usize;

        for allowed in ALLOWED {
            for blocked in BLOCKED {
                let policy = policy_with_path_rules(allowed, blocked);
                let compiled = match PolicyEngine::compile_policies(&[policy], false) {
                    Ok(mut v) if !v.is_empty() => v.remove(0),
                    _ => panic!("the policy under test must compile"),
                };
                let rules = compiled
                    .compiled_path_rules
                    .as_ref()
                    .expect("path rules were configured");

                for paths in PATH_SETS {
                    let action = action_with_paths(paths);

                    // Derive the model's inputs from the same compiled rules
                    // production is about to use, so the two are given the same
                    // world rather than the same guess about it.
                    let has_allowed_paths = !rules.allowed.is_empty();
                    let has_blocked_paths = !rules.blocked.is_empty();
                    let target_paths_empty = action.target_paths.is_empty();
                    let normalized: Vec<String> = action
                        .target_paths
                        .iter()
                        .filter_map(|p| PolicyEngine::normalize_path_bounded(p, 20).ok())
                        .collect();
                    // `CompiledPathRules` holds `Vec<(String, GlobMatcher)>`,
                    // so matching is a scan rather than a globset lookup.
                    let matches_any = |patterns: &[(String, globset::GlobMatcher)], p: &str| {
                        patterns.iter().any(|(_, m)| m.is_match(p))
                    };
                    let any_path_blocked =
                        normalized.iter().any(|p| matches_any(&rules.blocked, p));
                    let all_paths_allowed =
                        normalized.iter().all(|p| matches_any(&rules.allowed, p));

                    let production_denies = matches!(
                        engine.check_path_rules(&action, &compiled),
                        Some(Verdict::Deny { .. })
                    );
                    let model_denies = extracted::check_path_rules_decision(
                        has_allowed_paths,
                        has_blocked_paths,
                        target_paths_empty,
                        any_path_blocked,
                        all_paths_allowed,
                    );

                    assert_eq!(
                        production_denies, model_denies,
                        "PARITY-HAND-2: production and the Kani rule model disagree for \
                         allowed={allowed:?} blocked={blocked:?} paths={paths:?} \
                         (production denies={production_denies}, model={model_denies}) \
                         — K41-K45 are fail-closed properties of a predicate that is \
                         not the one deciding"
                    );

                    if production_denies {
                        denied += 1;
                    }
                    checked += 1;
                }
            }
        }

        assert_eq!(checked, 2 * 2 * 6, "enumeration collapsed");
        assert!(
            denied > 0 && denied < checked,
            "the scenarios are one-sided ({denied} of {checked} denied); they cannot \
             distinguish a predicate that always denies from one that never does"
        );
    }

    /// K41 restated against production: an allowlist with no target paths must
    /// deny. R28-ENG-1 is the finding — absent paths mean the extractor could
    /// not identify what the tool touches, so the allowlist cannot be checked.
    #[test]
    fn test_k41_no_paths_with_allowlist_denies_in_production() {
        let engine = PolicyEngine::new(false);
        let compiled =
            PolicyEngine::compile_policies(&[policy_with_path_rules(&["/srv/**"], &[])], false)
                .map(|mut v| v.remove(0))
                .expect("policy compiles");

        assert!(
            matches!(
                engine.check_path_rules(&action_with_paths(&[]), &compiled),
                Some(Verdict::Deny { .. })
            ),
            "K41 / R28-ENG-1: an allowlist with no target paths did not deny, so a \
             tool whose paths could not be extracted passes the allowlist"
        );
        assert!(extracted::check_path_rules_decision(
            true, false, true, false, false
        ));
    }

    /// K42 restated against production: blocked beats allowed.
    #[test]
    fn test_k42_blocked_beats_allowed_in_production() {
        let engine = PolicyEngine::new(false);
        let compiled = PolicyEngine::compile_policies(
            &[policy_with_path_rules(&["/srv/**"], &["/srv/secret/**"])],
            false,
        )
        .map(|mut v| v.remove(0))
        .expect("policy compiles");

        assert!(
            matches!(
                engine.check_path_rules(&action_with_paths(&["/srv/secret/key.pem"]), &compiled),
                Some(Verdict::Deny { .. })
            ),
            "K42: a path matching both the allowlist and the blocklist was not denied"
        );
        assert!(extracted::check_path_rules_decision(
            true, true, false, true, true
        ));
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/rule_check.rs was not found, so this binding compared nothing"
        );
    }
}
