// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Kani bounded model checking proofs for Vellaveto security invariants.
//!
//! This crate extracts security-critical algorithms from the production
//! codebase and verifies them using Kani's CBMC backend.
//!
//! # Why a separate crate?
//!
//! Kani 0.67 hits an internal compiler error on the `icu_normalizer` crate
//! (transitive dependency: `idna` → `icu_normalizer` → `zerovec`). Since
//! the verified algorithms — path normalization, verdict computation, DLP
//! buffer arithmetic — do not use IDNA functionality, we extract them here
//! with minimal dependencies to make verification tractable.
//!
//! # Verified Properties
//!
//! | ID | Property | Corresponds To |
//! |----|----------|----------------|
//! | K1 | Empty policies → Deny (fail-closed) | S1, MCPPolicyEngine.tla |
//! | K2 | normalize(normalize(x)) == normalize(x) | PathNormalization.lean/v |
//! | K3 | normalize(x) has no ".." component | PathNormalization.lean/v |
//! | K4 | saturating_add never wraps | Trap #9, counter monotonicity |
//! | K5 | No policies + any input → never Allow | S5, MCPPolicyEngine.tla |
//! | K6 | ABAC forbid dominance | S7, AbacForbidOverride.lean/v |
//! | K7 | ABAC no-match → NoMatch | S10, AbacForbidOverride.lean/v |
//! | K8 | Evaluation determinism | Determinism.lean/v |
//! | K9 | Simplified domain normalization idempotent | Lowercase + trim (NOT full IDNA) |
//! | K10 | extract_tail no panic for arbitrary input | D1-D2, Verus bridge |
//! | K11 | UTF-8 char boundary exhaustive (all 256 bytes) | D1, Verus bridge |
//! | K12 | can_track_field fail-closed at capacity | D4, Verus bridge |
//! | K13 | update_total_bytes saturating correctness | D3/D5, Verus bridge |
//! | K14 | compute_verdict fail-closed empty | V1, Verus bridge |
//! | K15 | compute_verdict allow requires matching allow | V3, Verus bridge |
//! | K16 | compute_verdict rule_override forces deny | V4, Verus bridge |
//! | K17 | compute_verdict conditional pass-through | V8, Verus bridge |
//! | K18 | sort produces sorted output (Verus bridge) | V6/V7, is_sorted |
//! | K19 | ABAC forbid ignores priority order | S8, AbacForbidOverride |
//! | K20 | ABAC permit requires no prior forbid | S9, AbacForbidOverride |
//! | K21 | overlap_covers_secret for small secrets within retained overlap | D6, Verus bridge |
//! | K22 | compute_overlap_region_size saturating | D6, region arithmetic |
//! | K23 | extract_tail multibyte boundary (4-byte emoji) | D1, UTF-8 safety |
//! | K24 | context_deny overrides allow | V3, context conditions |
//! | K25 | all_constraints_skipped fail-closed | V8, conditional handling |
//! | K26 | 127.x.x.x always private (loopback) | IP verification |
//! | K27 | RFC 1918 ranges always private | IP verification |
//! | K28 | CGNAT 100.64.0.0/10 always private | IP verification |
//! | K29 | is_embedded_ipv4_reserved parity with is_private_ipv4 | IP verification |
//! | K30 | IPv4-mapped ::ffff:x.x.x.x extraction correct | IP verification |
//! | K31 | Teredo XOR inversion round-trip correct | IP verification |
//! | K32 | Known public IPs (8.8.8.8, 1.1.1.1) NOT private | IP verification |
//! | K33 | is_cacheable == true → all session fields empty/None | Cache safety |
//! | K34 | Cache key case-insensitive | Cache safety |
//! | K35 | Entry invalid after TTL or generation bump | Cache safety |
//! | K36 | grant_is_subset reflexive | Capability delegation, S11 |
//! | K37 | No escalation (child ⊆ parent) | Capability delegation, S11 |
//! | K38 | pattern_is_subset correctness | Capability delegation, S11 |
//! | K39 | glob_match("*", any) == true | Capability delegation |
//! | K40 | normalize_path_for_grant: no ".." in output | Capability delegation, S11 |
//! | K41 | No target_paths + allowlist → Deny | Rule checking |
//! | K42 | Blocked pattern → Deny even if also allowed | Rule checking |
//! | K43 | IDNA normalization failure → Deny | Rule checking |
//! | K44 | IP rules + no resolved IPs → Deny | Rule checking |
//! | K45 | block_private + private IP → Deny | Rule checking |
//! | K46 | Path deny → rule_override_deny in ResolvedMatch | ResolvedMatch equivalence |
//! | K47 | Context deny → context_deny in ResolvedMatch | ResolvedMatch equivalence |
//! | K48 | Inline verdict == compute_single_verdict(ResolvedMatch) | ResolvedMatch equivalence |
//! | K49 | NaN/Infinity in cascading config → rejected | Cascading failure |
//! | K50 | Chain depth increment never wraps | Cascading failure |
//! | K51 | At MAX capacity → Deny | Cascading failure |
//! | K52 | Error rate ∈ [0.0, 1.0] | Cascading failure |
//! | K53 | All constraints skipped → detected | Constraint evaluation |
//! | K54 | Forbidden parameter match → Deny | Constraint evaluation |
//! | K55 | require_approval → RequireApproval verdict | Constraint evaluation |
//! | K55A | Unknown-only condition payload detected | Constraint evaluation |
//! | K56 | Terminal state → no further transitions | Task lifecycle |
//! | K57 | At max tasks → reject new registration | Task lifecycle |
//! | K58 | Self-cancel + different requester → reject | Task lifecycle |
//! | K59 | Entropy finite, non-negative, ≤ 8.0, empty → 0.0 | Collusion detection |
//! | K60 | grant_covers_action fail-closed (paths/domains) | Capability delegation |
//! | K61 | IDNA failure on non-ASCII → None (fail-closed) | Domain normalization |
//! | K62 | IDNA failure on ASCII → lowercase fallback | Domain normalization |
//! | K63 | Wildcard prefix preserved through IDNA | Domain normalization |
//! | K64 | normalize_homoglyphs idempotent | Unicode security |
//! | K65 | Confusable chars collapse to ASCII | Unicode security |
//! | K66 | Cache lock poison → cache miss (never stale Allow) | Lock safety |
//! | K67 | Deputy lock poison → InternalError (Deny) | Lock safety |
//! | K68 | All lock poison handlers produce safe outcome | Lock safety |
//! | K69 | PII token insertion + replacement round-trip (inversion) | Sanitizer bidirectional |
//! | K70 | PII token uniqueness from monotonic sequence counter | Sanitizer bidirectional |
//! | K71 | Temporal window: events outside window expired (no stale) | Collusion temporal |
//! | K72 | Temporal window: boundary precision (>= cutoff included) | Collusion temporal |
//! | K73 | Cascading FSM: Closed→Open requires threshold AND min_events | Cascading FSM |
//! | K74 | Cascading FSM: half-open probe after break_duration | Cascading FSM |
//! | K75 | Cascading FSM: recovery requires error_rate < threshold | Cascading FSM |
//! | K76 | Injection decode pipeline completeness (7 stages ordered) | Injection completeness |
//! | K77 | Injection: known patterns detected after decode chain | Injection completeness |
//! | K78 | Trust containment: insufficient trust requires explicit gate | Trust containment |
//! | K79 | Trust containment: sufficient trust does not require gate | Trust containment |
//! | K80 | Data output contracts block privilege-escalating drift | Semantic output contracts |
//! | K81 | Free-text/tool-output contracts block URL/command/approval drift | Semantic output contracts |
//! | K82 | Resource/URL contracts only escalate on command/approval drift | Semantic output contracts |
//! | K83 | Counterfactual gate requires security-relevant taint | Counterfactual containment |
//! | K84 | Quarantined command-like privileged flows force counterfactual gate | Counterfactual containment |
//! | K85 | Verified untrusted tool output stays below counterfactual gate | Counterfactual containment |
//! | K86 | Entropy wrapper output always in [0, 8000] (no u16 overflow) | Entropy float-to-fixed |
//! | K87 | Entropy NaN/Infinity map to 0 (fail-safe) | Entropy float-to-fixed |
//! | K88 | Entropy negative values map to 0 (clamped) | Entropy float-to-fixed |
//! | K89 | Entropy monotonicity: a <= b ⟹ f(a) <= f(b) | Entropy float-to-fixed |
//! | K90 | Entropy ceil >= floor for same input | Entropy float-to-fixed |
//! | K91 | Full injection pipeline has all 13 decode stages | Injection completeness |
//! | K92 | Full injection pipeline ordering constraints hold | Injection completeness |
//! | K93 | Leetspeak-encoded injection detected after decode | Injection composition |
//! | K94 | HTML comment-wrapped injection detected after strip | Injection composition |
//! | K95 | Double URL-encoded injection detected after 2 passes | Injection composition |
//! | K96 | Compound ROT13+URL encoding detected after decode chain | Injection composition |
//! | K97 | Full pipeline detects multi-layer URL+HTML encoding | Injection composition |
//! | K98 | Collusion config NaN/Infinity rejection on all f64 fields | Collusion detection |
//! | K99 | Collusion config out-of-range value rejection | Collusion detection |
//! | K100 | Capacity exhaustion produces alert (never silent skip) | Collusion detection |
//! | K101 | Error rate always in [0.0, 1.0] and fail-closed | Collusion detection |
//! | K102 | Denial rate half-open interval: no double-counting | Collusion detection |
//! | K103 | sort_resolved_matches output satisfies is_sorted (Verus bridge) | Sorting correctness |
//! | K104 | Sort stable: deny-first at equal priority | Sorting correctness |
//! | K105 | Sort idempotent: sort(sort(x)) == sort(x) | Sorting correctness |
//! | K106 | Empty input trivially sorted | Sorting correctness |
//! | K107 | Single element always sorted | Sorting correctness |
//! | K108 | Consumed credential cannot be re-consumed (single-use) | Credential vault |
//! | K109 | Epoch monotonicity: current_epoch never decreases | Credential vault |
//! | K110 | Capacity bounded: vault never exceeds MAX_VAULT_ENTRIES | Credential vault |
//! | K111 | Fail-closed on exhaustion: no Available → None (never silent) | Credential vault |
//! | K112 | State transitions: only Available→Active→Consumed, Available→Expired | Credential vault |
//! | K113 | hex_digit: 0-9,a-f,A-F → Some(0-15), else None | TLS SPIFFE |
//! | K114 | hex_digit exhaustive: all 256 byte values correct | TLS SPIFFE |
//! | K115 | SPIFFE parse: non-spiffe URI → None | TLS SPIFFE |
//! | K116 | SPIFFE parse: empty trust domain → None | TLS SPIFFE |
//! | K117 | SPIFFE parse: invalid domain chars → None | TLS SPIFFE |
//! | K118 | SPIFFE parse: path traversal /../ → None | TLS SPIFFE |
//! | K119 | SPIFFE parse: valid URI → Some with correct fields | TLS SPIFFE |
//! | K120 | percent_decode: no % → Ok(None), invalid UTF-8 → Err | TLS SPIFFE |
//! | K121 | SHA-256 always produces 32 bytes (bridges MERKLE-HASH-1) | Merkle sanity |
//! | K122 | SHA-256 is deterministic: same input → same output | Merkle sanity |
//! | K123 | RFC 6962 domain separation: leaf prefix ≠ internal prefix | Merkle sanity |
//! | K124 | Hex encoding of 32-byte hash is always 64 chars | Merkle sanity |
//! | K125 | Different inputs → different hashes (collision sanity) | Merkle sanity |
//!
//! # Source Correspondence
//!
//! - `path.rs`: Verbatim from `vellaveto-engine/src/path.rs`
//! - `verified_core.rs`: Verbatim from `vellaveto-engine/src/verified_core.rs`
//! - `dlp_core.rs`: Verbatim from `vellaveto-mcp/src/inspection/verified_dlp_core.rs`
//! - `ip.rs`: Extracted from `vellaveto-engine/src/ip.rs`
//! - `cache.rs`: Extracted from `vellaveto-engine/src/cache.rs`
//! - `capability.rs`: Extracted from `vellaveto-mcp/src/capability_token.rs`
//! - `rule_check.rs`: Extracted from `vellaveto-engine/src/rule_check.rs`
//! - `resolve.rs`: Extracted from `vellaveto-engine/src/lib.rs` (ResolvedMatch construction)
//! - `cascading.rs`: Extracted from `vellaveto-engine/src/cascading.rs`
//! - `constraint.rs`: Extracted from `vellaveto-engine/src/constraint_eval.rs`
//! - `task.rs`: Extracted from `vellaveto-mcp/src/task_state.rs`
//! - `entropy.rs`: Extracted from `vellaveto-engine/src/collusion.rs`
//! - `domain.rs`: Extracted from `vellaveto-engine/src/domain.rs` (IDNA wrapper)
//! - `unicode.rs`: Extracted from `vellaveto-types/src/unicode.rs` (homoglyph mapping)
//! - `lock_safety.rs`: Models RwLock poisoning handlers across engine/MCP
//! - `sanitizer.rs`: Extracted from `vellaveto-mcp-shield/src/sanitizer.rs` (PII inversion)
//! - `temporal_window.rs`: Extracted from `vellaveto-engine/src/collusion.rs` (sliding window)
//! - `cascading_fsm.rs`: Extracted from `vellaveto-engine/src/cascading.rs` (circuit breaker FSM)
//! - `injection_pipeline.rs`: Extracted from `vellaveto-mcp/src/inspection/injection.rs` (13-stage decode chain)
//! - `entropy_wrapper.rs`: Extracted from `vellaveto-engine/src/entropy_gate.rs` (float-to-fixed wrapper)
//! - `collusion_detection.rs`: Extracted from `vellaveto-engine/src/collusion.rs` (config validation, capacity, denial rate)
//! - `sort_bridge.rs`: Kani→Verus bridge proving sort_resolved_matches satisfies Verus is_sorted precondition
//! - `credential_vault.rs`: Extracted from `vellaveto-mcp-shield/src/credential_vault.rs` (state machine, single-use, epoch)
//! - `tls_spiffe.rs`: Extracted from `vellaveto-tls/src/lib.rs` (SPIFFE parsing, hex_digit, percent_decode, PQ KEX)
//! - `merkle_sanity.rs`: SHA-256 property sanity checks bridging Verus merkle_boundary_axioms
//! - `output_contracts.rs`: Extracted from `vellaveto-types/src/provenance.rs` + `vellaveto-mcp/src/output_contracts.rs`
//! - `counterfactual_containment.rs`: Extracted from `vellaveto-types/src/provenance.rs`

pub mod path;
pub mod verified_core;
pub mod dlp_core;
pub mod ip;
pub mod cache;
pub mod capability;
pub mod rule_check;
pub mod resolve;
pub mod cascading;
pub mod constraint;
pub mod task;
pub mod entropy;
pub mod domain;
pub mod unicode;
pub mod lock_safety;
pub mod sanitizer;
pub mod temporal_window;
pub mod cascading_fsm;
pub mod injection_pipeline;
pub mod output_contracts;
pub mod counterfactual_containment;
pub mod trust_containment;
pub mod entropy_wrapper;
pub mod collusion_detection;
pub mod sort_bridge;
pub mod credential_vault;
pub mod tls_spiffe;
pub mod merkle_sanity;
pub mod evidence_signing;
pub mod merkle_codec;
pub mod transitive_revoke;
pub mod webhook_dedup;
pub mod approval_drift;

#[cfg(kani)]
mod proofs;

/// Error type for path normalization (mirrors `EngineError::PathNormalization`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathError {
    pub reason: String,
}

/// Verdict type (mirrors `vellaveto_types::Verdict`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny { reason: String },
}

/// Evaluate an action against an empty policy set.
///
/// This is the fail-closed default path extracted from
/// `PolicyEngine::evaluate_action` (vellaveto-engine/src/lib.rs:367-371).
///
/// With no policies defined, the engine MUST return Deny.
pub fn evaluate_empty_policies() -> Verdict {
    Verdict::Deny {
        reason: "No policies defined".to_string(),
    }
}

// =========================================================================
// ABAC forbid-override combining (extracted from abac.rs:322-364)
// =========================================================================

/// ABAC policy effect — Permit or Forbid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbacEffect {
    Permit,
    Forbid,
}

/// ABAC policy entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbacPolicy {
    pub id: String,
    pub effect: AbacEffect,
}

/// ABAC combining result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbacDecision {
    Deny(String),
    Allow(String),
    NoMatch,
}

/// ABAC forbid-override combining algorithm.
///
/// Extracted from `vellaveto-engine/src/abac.rs:322-364`.
/// The core rule: scan all policies; first forbid match wins immediately.
pub fn abac_evaluate(policies: &[AbacPolicy], matches: &dyn Fn(&AbacPolicy) -> bool) -> AbacDecision {
    let mut best_permit: Option<&str> = None;
    for policy in policies {
        if matches(policy) {
            match policy.effect {
                AbacEffect::Forbid => {
                    return AbacDecision::Deny(policy.id.clone());
                }
                AbacEffect::Permit => {
                    if best_permit.is_none() {
                        best_permit = Some(&policy.id);
                    }
                }
            }
        }
    }
    match best_permit {
        Some(pid) => AbacDecision::Allow(pid.to_string()),
        None => AbacDecision::NoMatch,
    }
}

/// Kani-friendly ABAC combining result using u8 IDs instead of String.
///
/// Avoids String heap allocations that create SAT formulas too large for CBMC.
/// Production uses `AbacDecision` with String IDs; this proves the same
/// forbid-override property for small fixed-size policy sets.
/// Correspondence verified by unit tests in `abac_evaluate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbacDecisionKani {
    Deny(u8),
    Allow(u8),
    NoMatch,
}

/// Kani-friendly ABAC forbid-override combining over fixed-size policy arrays.
///
/// Same algorithm as `abac_evaluate` but uses `u8` policy IDs and `[bool; N]`
/// match arrays instead of `String` IDs and `dyn Fn` closures.
/// Production uses `abac_evaluate`; this proves the same property for small sets.
pub fn abac_evaluate_kani(
    effects: &[AbacEffect],
    matches: &[bool],
    ids: &[u8],
) -> AbacDecisionKani {
    let mut best_permit: Option<u8> = None;
    let len = effects.len().min(matches.len()).min(ids.len());
    let mut i = 0;
    while i < len {
        if matches[i] {
            match effects[i] {
                AbacEffect::Forbid => {
                    return AbacDecisionKani::Deny(ids[i]);
                }
                AbacEffect::Permit => {
                    if best_permit.is_none() {
                        best_permit = Some(ids[i]);
                    }
                }
            }
        }
        i += 1;
    }
    match best_permit {
        Some(pid) => AbacDecisionKani::Allow(pid),
        None => AbacDecisionKani::NoMatch,
    }
}

// =========================================================================
// Domain normalization (extracted from engine domain handling)
// =========================================================================

/// Normalize a domain name: ASCII lowercase, strip trailing dots.
///
/// **Simplified extraction** from domain handling in `vellaveto-engine/src/lib.rs`.
/// Production uses full IDNA normalization (74 lines: punycode, homoglyph mapping,
/// Unicode confusable resolution). This function verifies only the post-IDNA
/// ASCII lowercase + trim subset. This is a pure function — calling it twice
/// yields the same result.
pub fn normalize_domain(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == b'.' {
        end -= 1;
    }
    raw[..end].to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the Kani byte-level ABAC evaluator produces the same results as
    /// the production String-based evaluator on all 64 combinations of 3 policies
    /// with 2 effects × 2 match states.
    #[test]
    fn test_abac_evaluate_kani_parity() {
        let ids_str = ["p0", "p1", "p2"];
        let ids_u8: [u8; 3] = [0, 1, 2];
        // Exhaustive: 2^6 = 64 combinations
        for bits in 0u8..64 {
            let e0 = bits & 1 != 0;
            let e1 = bits & 2 != 0;
            let e2 = bits & 4 != 0;
            let m0 = bits & 8 != 0;
            let m1 = bits & 16 != 0;
            let m2 = bits & 32 != 0;

            let effects_enum = [
                if e0 { AbacEffect::Forbid } else { AbacEffect::Permit },
                if e1 { AbacEffect::Forbid } else { AbacEffect::Permit },
                if e2 { AbacEffect::Forbid } else { AbacEffect::Permit },
            ];
            let matches_arr = [m0, m1, m2];

            // Production version
            let policies: Vec<AbacPolicy> = ids_str
                .iter()
                .zip(effects_enum.iter())
                .map(|(id, eff)| AbacPolicy {
                    id: id.to_string(),
                    effect: *eff,
                })
                .collect();
            let prod = abac_evaluate(&policies, &|p| {
                let idx = ids_str.iter().position(|&s| s == p.id).unwrap();
                matches_arr[idx]
            });

            // Kani version
            let kani = abac_evaluate_kani(&effects_enum, &matches_arr, &ids_u8);

            // Compare
            match (&prod, &kani) {
                (AbacDecision::Deny(pid), AbacDecisionKani::Deny(kid)) => {
                    let expected_idx = ids_str.iter().position(|&s| s == pid).unwrap();
                    assert_eq!(expected_idx, *kid as usize, "Deny ID mismatch for bits={bits}");
                }
                (AbacDecision::Allow(pid), AbacDecisionKani::Allow(kid)) => {
                    let expected_idx = ids_str.iter().position(|&s| s == pid).unwrap();
                    assert_eq!(expected_idx, *kid as usize, "Allow ID mismatch for bits={bits}");
                }
                (AbacDecision::NoMatch, AbacDecisionKani::NoMatch) => {}
                _ => panic!(
                    "Decision kind mismatch for bits={bits}: prod={prod:?}, kani={kani:?}"
                ),
            }
        }
    }
}
