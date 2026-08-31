// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified core verdict computation.
//!
//! This module contains the pure verdict computation logic that is verified
//! by Verus (deductive, all inputs) and tested by Kani (bounded model checking).
//!
//! The key abstraction is [`ResolvedMatch`]: the unverified wrapper code resolves
//! whether each policy matches the action (String operations, glob matching,
//! Unicode normalization, HashMap lookups) and produces a `Vec<ResolvedMatch>`.
//! This module computes the verdict from that Vec using pure logic — no String,
//! no HashMap, no serde, no glob.
//!
//! # Verification Properties (V1-V8)
//!
//! | ID | Property | Meaning |
//! |----|----------|---------|
//! | V1 | Fail-closed empty | Empty input → Deny |
//! | V2 | Fail-closed no match | All `!matched` → Deny |
//! | V3 | Allow requires match | Allow → ∃ matching Allow policy with no override |
//! | V4 | Rule override forces Deny | Path/network/IP override on first match → Deny |
//! | V5 | Totality | Function always terminates |
//! | V6 | Priority ordering | Higher-priority match wins (requires sorted input) |
//! | V7 | Deny-dominance at equal priority | Deny beats Allow at same priority (sorted) |
//! | V8 | Conditional pass-through | Unfired condition → evaluation continues |
//!
//! # Trust Boundary
//!
//! The wrapper (unverified) builds `Vec<ResolvedMatch>` from the action and policies.
//! The core (verified) computes the verdict from that Vec. The trust boundary is:
//! "the wrapper correctly resolves matches; the core correctly computes verdicts."
//!
//! See `docs/TRUSTED_COMPUTING_BASE.md` for the full trust model.
//! See `formal/verus/verified_core.rs` for the Verus-annotated version with specs.

/// The result of the core verdict computation.
///
/// This enum mirrors `Verdict` but without String payloads — the verified core
/// determines the verdict *kind*, and the caller attaches the reason string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictKind {
    /// Action is allowed.
    Allow,
    /// Action is denied.
    Deny,
    /// Action requires human approval.
    RequireApproval,
}

impl VerdictKind {
    /// Returns true if this verdict is Deny.
    #[inline]
    pub fn is_deny(self) -> bool {
        matches!(self, VerdictKind::Deny)
    }

    /// Returns true if this verdict is Allow.
    #[inline]
    pub fn is_allow(self) -> bool {
        matches!(self, VerdictKind::Allow)
    }
}

/// A pre-resolved policy match with all verdict-relevant information.
///
/// The unverified wrapper produces this struct from the action and a compiled
/// policy. The verified core consumes it. No String, HashMap, glob, or serde
/// operations are needed to compute the verdict from this struct.
///
/// # Fields
///
/// - `matched`: Whether the policy's tool/function pattern matched the action.
/// - `is_deny`: Whether the policy type is `Deny`.
/// - `is_conditional`: Whether the policy type is `Conditional`.
/// - `priority`: The policy's priority (higher = evaluated first).
/// - `rule_override_deny`: Whether path/network/IP rules forced a Deny.
/// - `context_deny`: Whether context conditions produced a Deny.
/// - `require_approval`: Whether the policy requires human approval.
/// - `condition_fired`: For Conditional policies, whether any constraint matched.
/// - `condition_verdict`: The verdict from the fired constraint (if any).
/// - `on_no_match_continue`: For Conditional policies, whether to skip to next
///   policy when no constraints fire (vs. implicit Allow).
/// - `all_constraints_skipped`: For Conditional policies, whether every constraint
///   was skipped due to missing parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMatch {
    /// Whether the policy's tool/function pattern matched the action.
    pub matched: bool,
    /// Whether the policy type is `Deny`.
    pub is_deny: bool,
    /// Whether the policy type is `Conditional`.
    pub is_conditional: bool,
    /// Policy priority (higher = evaluated first in sorted order).
    pub priority: u32,
    /// Whether path/network/IP rules forced a Deny on this policy.
    pub rule_override_deny: bool,
    /// Whether context conditions produced a Deny.
    pub context_deny: bool,
    /// Whether the policy requires human approval (Conditional with require_approval).
    pub require_approval: bool,
    /// For Conditional policies: whether any constraint fired.
    pub condition_fired: bool,
    /// For Conditional policies: the verdict from the fired constraint.
    pub condition_verdict: VerdictKind,
    /// For Conditional policies: skip to next policy when no constraint fires.
    pub on_no_match_continue: bool,
    /// For Conditional policies: all constraints were skipped (missing params).
    pub all_constraints_skipped: bool,
}

/// Outcome of verdict computation.
///
/// `Decided(VerdictKind)` means a final verdict was reached.
/// `Continue` means a Conditional policy with `on_no_match="continue"` had
/// no constraints fire, and the evaluation loop should try the next policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictOutcome {
    /// A final verdict was reached.
    Decided(VerdictKind),
    /// No verdict from this policy — continue to the next one.
    Continue,
}

/// Compute the verdict for a single resolved policy match.
///
/// This is the innermost verdict decision function. Given a fully-resolved
/// match, it determines whether the match produces a verdict or should be
/// skipped (Continue).
///
/// # Properties (per-policy)
///
/// - V4: `rule_override_deny == true` → `Decided(Deny)`
/// - V3: `Allow` only when `!is_deny && !rule_override_deny && !context_deny`
/// - V8: Conditional with unfired condition + `on_no_match_continue` → `Continue`
#[inline]
#[must_use = "security verdicts must not be discarded"]
pub fn compute_single_verdict(rm: &ResolvedMatch) -> VerdictOutcome {
    if !rm.matched {
        return VerdictOutcome::Continue;
    }

    // V4: Rule override denials checked first (path/network/IP)
    if rm.rule_override_deny {
        return VerdictOutcome::Decided(VerdictKind::Deny);
    }

    // Context condition denials checked next
    if rm.context_deny {
        return VerdictOutcome::Decided(VerdictKind::Deny);
    }

    // Policy type dispatch
    if rm.is_deny {
        return VerdictOutcome::Decided(VerdictKind::Deny);
    }

    if rm.is_conditional {
        // Require approval takes precedence
        if rm.require_approval {
            return VerdictOutcome::Decided(VerdictKind::RequireApproval);
        }

        // All constraints skipped (missing params) → fail-closed
        if rm.all_constraints_skipped {
            if rm.on_no_match_continue {
                return VerdictOutcome::Continue;
            }
            return VerdictOutcome::Decided(VerdictKind::Deny);
        }

        if rm.condition_fired {
            return VerdictOutcome::Decided(rm.condition_verdict);
        }

        // V8: No constraint fired — continue or implicit Allow
        if rm.on_no_match_continue {
            return VerdictOutcome::Continue;
        }
        return VerdictOutcome::Decided(VerdictKind::Allow);
    }

    // Allow policy — V3
    VerdictOutcome::Decided(VerdictKind::Allow)
}

/// Compute the final verdict from a sequence of resolved policy matches.
///
/// The matches are expected to be in priority order (highest priority first,
/// deny-first at equal priority). This function implements first-match-wins:
/// it returns the first `Decided` verdict, or `Deny` if no policy produces one.
///
/// # Properties (V1-V8)
///
/// - **V1 (S1):** Empty `resolved` → Deny
/// - **V2 (S1):** All `!matched` → Deny
/// - **V3 (S5):** Allow → ∃ matching Allow policy with no override
/// - **V4 (S3/S4):** Rule override on first match → Deny
/// - **V5 (L1):** Always terminates (bounded by `resolved.len()`)
/// - **V6 (S2):** First matching policy in sorted order determines verdict
/// - **V7 (S3):** At equal priority, deny-sorted-first means Deny wins
/// - **V8:** Conditional with unfired condition → skipped to next policy
#[must_use = "security verdicts must not be discarded"]
pub fn compute_verdict(resolved: &[ResolvedMatch]) -> VerdictKind {
    // V1: Empty → Deny
    // V5: Loop bounded by resolved.len()
    for rm in resolved {
        match compute_single_verdict(rm) {
            VerdictOutcome::Decided(kind) => return kind,
            VerdictOutcome::Continue => continue,
        }
    }
    // V2: No match produced a verdict → Deny (fail-closed)
    VerdictKind::Deny
}

#[cfg(test)]
mod verus_refinement_differential {
    //! Differential binding for `PARITY-HAND-1`, refinement kernels
    //! `formal/verus/verified_refinement_safety.rs` and
    //! `formal/verus/verified_refinement_completeness.rs`.
    //!
    //! Neither kernel models a new function. Both describe the abstract
    //! evaluation state machine that `compute_verdict` realises: safety says
    //! what the verdict must be in the terminal cases, completeness says how
    //! the state advances. `verified_core` already binds the function itself,
    //! so these two are bound as **properties of that same function** — the
    //! composition-kernel shape, where the risk is the abstract model drifting
    //! from the concrete one it is supposed to describe.
    //!
    //! `AbstractVerdict` maps to `VerdictKind`, and `EngineState`'s
    //! `Matching`/`Applying` to the loop position: `Continue` advances the
    //! index, `Decided` stops.

    use super::*;

    fn rm(matched: bool, is_deny: bool, is_conditional: bool) -> ResolvedMatch {
        ResolvedMatch {
            matched,
            is_deny,
            is_conditional,
            priority: 0,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: false,
            condition_verdict: VerdictKind::Allow,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        }
    }

    // ── verified_refinement_safety ────────────────────────────────────────

    /// SAFETY-1: `spec_empty_policy_verdict() == Deny`. The fail-closed base
    /// case — an empty policy set denies.
    #[test]
    fn test_empty_policy_set_denies() {
        assert_eq!(
            compute_verdict(&[]),
            VerdictKind::Deny,
            "PARITY-HAND-1 (SAFETY-1): an empty policy set did not deny"
        );
    }

    /// SAFETY-2: `spec_exhausted_no_match_verdict() == Deny`, and
    /// `spec_no_match_in_trace` is the precondition. A trace in which nothing
    /// matched must exhaust to Deny, however long it is.
    #[test]
    fn test_exhausted_trace_with_no_match_denies() {
        for len in 0..8usize {
            let trace: Vec<ResolvedMatch> = (0..len).map(|_| rm(false, false, false)).collect();
            assert!(
                trace.iter().all(|m| !m.matched),
                "spec_no_match_in_trace precondition does not hold of the fixture"
            );
            assert_eq!(
                compute_verdict(&trace),
                VerdictKind::Deny,
                "PARITY-HAND-1 (SAFETY-2): a {len}-entry trace with no match did not deny"
            );
        }
    }

    /// SAFETY-3: `spec_deny_contribution_produces_deny`. If the first matching
    /// entry contributes Deny, the verdict is Deny — regardless of what
    /// follows it. This is the property that stops a later allow overriding an
    /// earlier deny.
    #[test]
    fn test_first_matching_deny_contribution_produces_deny() {
        let deny = rm(true, true, false);
        let allow = rm(true, false, false);
        let skip = rm(false, false, false);

        assert!(
            matches!(
                compute_single_verdict(&deny),
                VerdictOutcome::Decided(VerdictKind::Deny)
            ),
            "the fixture is not a deny contribution"
        );

        // The deny at the first *matching* position, with any number of
        // non-matching entries before it and allows after.
        for lead in 0..4usize {
            for trail in 0..4usize {
                let mut trace: Vec<ResolvedMatch> = (0..lead).map(|_| skip.clone()).collect();
                trace.push(deny.clone());
                trace.extend((0..trail).map(|_| allow.clone()));
                assert_eq!(
                    compute_verdict(&trace),
                    VerdictKind::Deny,
                    "PARITY-HAND-1 (SAFETY-3): a first-matching deny contribution did not \
                     produce Deny with {lead} skips before and {trail} allows after"
                );
            }
        }
    }

    // ── verified_refinement_completeness ──────────────────────────────────

    /// COMPLETENESS-1/2: `spec_match_miss` advances the index and stays in
    /// `Matching`; `spec_match_hit` holds the index and moves to `Applying`.
    /// Concretely: a non-matching entry yields `Continue` (advance), and a
    /// matching one yields `Decided` (stop).
    #[test]
    fn test_state_transitions_match_the_abstract_machine() {
        // Miss: not matched -> Continue, so evaluation advances past it.
        assert!(
            matches!(
                compute_single_verdict(&rm(false, false, false)),
                VerdictOutcome::Continue
            ),
            "PARITY-HAND-1 (COMPLETENESS-1): a miss did not advance"
        );
        // Hit: matched and decisive -> Decided, so evaluation stops here.
        assert!(
            matches!(
                compute_single_verdict(&rm(true, true, false)),
                VerdictOutcome::Decided(_)
            ),
            "PARITY-HAND-1 (COMPLETENESS-2): a hit did not reach a decision"
        );
    }

    /// COMPLETENESS-3/4: `spec_apply_allow_verdict` and
    /// `spec_apply_require_approval_verdict` — the two non-deny terminal
    /// verdicts the abstract machine can apply.
    #[test]
    fn test_apply_verdicts_match_the_abstract_machine() {
        let allow = rm(true, false, false);
        assert_eq!(compute_verdict(&[allow]), VerdictKind::Allow);

        let mut approval = rm(true, false, true);
        approval.require_approval = true;
        assert_eq!(compute_verdict(&[approval]), VerdictKind::RequireApproval);
    }

    /// COMPLETENESS-5: `spec_continue_to_next` advances by exactly one, so the
    /// first entry that decides is the one whose verdict is returned. Checked
    /// by placing the decisive entry at every position in a run of skips.
    #[test]
    fn test_evaluation_stops_at_the_first_deciding_entry() {
        let skip = rm(false, false, false);
        let allow = rm(true, false, false);
        let deny = rm(true, true, false);

        for pos in 0..5usize {
            let mut trace: Vec<ResolvedMatch> = (0..pos).map(|_| skip.clone()).collect();
            trace.push(allow.clone());
            trace.push(deny.clone()); // a later deny must NOT win
            assert_eq!(
                compute_verdict(&trace),
                VerdictKind::Allow,
                "PARITY-HAND-1 (COMPLETENESS-5): evaluation did not stop at the first deciding \
                 entry (allow at index {pos}, deny after it)"
            );
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // The safety properties are only meaningful if the fixtures really do
        // decide differently.
        assert_eq!(compute_verdict(&[rm(true, true, false)]), VerdictKind::Deny);
        assert_eq!(
            compute_verdict(&[rm(true, false, false)]),
            VerdictKind::Allow
        );
        assert_eq!(
            compute_verdict(&[rm(false, false, false)]),
            VerdictKind::Deny
        );
    }
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_core.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function. Symbol parity cannot see this:
    //! `check-verus-parity.sh` greps for names.
    //!
    //! TOTAL discharge for `compute_single_verdict`: `ResolvedMatch` carries
    //! nine booleans and a three-valued `condition_verdict`, so all 1,536
    //! inhabitants of the domain the spec reads are enumerated. `priority` is
    //! the tenth field and the spec does not read it; the enumeration varies
    //! it anyway so that a production version which *did* read it would be
    //! caught.
    //!
    //! `compute_verdict` is BOUNDED: every single-element list is checked
    //! against the full domain, then all lists of length 0..=4 drawn from one
    //! representative per outcome. That covers the two properties the kernel
    //! exists for — first decided verdict wins, and an empty or
    //! all-Continue list denies.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    // The kernel keeps `rule_override_deny`, `context_deny` and `is_deny` as
    // three separate branches even though each yields `Deny`, because each is a
    // distinct policy reason and their order is part of what V4 establishes.
    // Collapsing them into one condition — which is what clippy suggests —
    // would make this transcription structurally different from the kernel and
    // defeat the comparison it exists to make.
    #[allow(clippy::if_same_then_else)]
    fn spec_single_verdict(rm: &ResolvedMatch) -> VerdictOutcome {
        if !rm.matched {
            VerdictOutcome::Continue
        } else if rm.rule_override_deny {
            VerdictOutcome::Decided(VerdictKind::Deny)
        } else if rm.context_deny {
            VerdictOutcome::Decided(VerdictKind::Deny)
        } else if rm.is_deny {
            VerdictOutcome::Decided(VerdictKind::Deny)
        } else if rm.is_conditional {
            if rm.require_approval {
                VerdictOutcome::Decided(VerdictKind::RequireApproval)
            } else if rm.all_constraints_skipped {
                if rm.on_no_match_continue {
                    VerdictOutcome::Continue
                } else {
                    VerdictOutcome::Decided(VerdictKind::Deny)
                }
            } else if rm.condition_fired {
                VerdictOutcome::Decided(rm.condition_verdict)
            } else if rm.on_no_match_continue {
                VerdictOutcome::Continue
            } else {
                VerdictOutcome::Decided(VerdictKind::Allow)
            }
        } else {
            VerdictOutcome::Decided(VerdictKind::Allow)
        }
    }

    fn spec_compute_verdict_from(resolved: &[ResolvedMatch], start: usize) -> VerdictKind {
        if start >= resolved.len() {
            VerdictKind::Deny
        } else {
            match spec_single_verdict(&resolved[start]) {
                VerdictOutcome::Decided(kind) => kind,
                VerdictOutcome::Continue => spec_compute_verdict_from(resolved, start + 1),
            }
        }
    }

    const VERDICTS: [VerdictKind; 3] = [
        VerdictKind::Allow,
        VerdictKind::Deny,
        VerdictKind::RequireApproval,
    ];

    /// Every `ResolvedMatch` the spec can distinguish, at one `priority`.
    fn enumerate_matches(priority: u32) -> Vec<ResolvedMatch> {
        let mut out = Vec::with_capacity(1536);
        for bits in 0u16..512 {
            let f = |i: u16| bits & (1 << i) != 0;
            for condition_verdict in VERDICTS {
                out.push(ResolvedMatch {
                    matched: f(0),
                    is_deny: f(1),
                    is_conditional: f(2),
                    priority,
                    rule_override_deny: f(3),
                    context_deny: f(4),
                    require_approval: f(5),
                    condition_fired: f(6),
                    condition_verdict,
                    on_no_match_continue: f(7),
                    all_constraints_skipped: f(8),
                });
            }
        }
        out
    }

    #[test]
    fn test_compute_single_verdict_matches_verus_spec_total_domain() {
        for priority in [0u32, 7, u32::MAX] {
            let all = enumerate_matches(priority);
            assert_eq!(all.len(), 1536, "enumeration collapsed");
            for rm in &all {
                assert_eq!(
                    compute_single_verdict(rm),
                    spec_single_verdict(rm),
                    "PARITY-HAND-1: compute_single_verdict disagrees for {rm:?}"
                );
            }
        }
    }

    #[test]
    fn test_compute_verdict_matches_verus_spec() {
        // Empty input must deny — the fail-closed base case.
        assert_eq!(
            compute_verdict(&[]),
            spec_compute_verdict_from(&[], 0),
            "PARITY-HAND-1: compute_verdict disagrees on the empty list"
        );

        // Every single-element list, over the full single-verdict domain.
        let all = enumerate_matches(1);
        for rm in &all {
            let list = [rm.clone()];
            assert_eq!(
                compute_verdict(&list),
                spec_compute_verdict_from(&list, 0),
                "PARITY-HAND-1: compute_verdict disagrees on [{rm:?}]"
            );
        }

        // One representative per outcome, over all lists of length 0..=4, so
        // ordering and the all-Continue case are both exercised.
        let reps: Vec<ResolvedMatch> = {
            let mut seen_continue = None;
            let mut seen: Vec<(VerdictKind, ResolvedMatch)> = Vec::new();
            for rm in &all {
                match spec_single_verdict(rm) {
                    VerdictOutcome::Continue => {
                        if seen_continue.is_none() {
                            seen_continue = Some(rm.clone());
                        }
                    }
                    VerdictOutcome::Decided(kind) => {
                        if !seen.iter().any(|(k, _)| *k == kind) {
                            seen.push((kind, rm.clone()));
                        }
                    }
                }
            }
            let mut reps: Vec<ResolvedMatch> = seen_continue.into_iter().collect();
            reps.extend(seen.into_iter().map(|(_, rm)| rm));
            reps
        };
        assert_eq!(reps.len(), 4, "expected one representative per outcome");

        let mut frontier: Vec<Vec<ResolvedMatch>> = vec![Vec::new()];
        let mut checked = 0usize;
        for _ in 0..4 {
            let mut next = Vec::new();
            for prefix in &frontier {
                for rep in &reps {
                    let mut list = prefix.clone();
                    list.push(rep.clone());
                    assert_eq!(
                        compute_verdict(&list),
                        spec_compute_verdict_from(&list, 0),
                        "PARITY-HAND-1: compute_verdict disagrees on {list:?}"
                    );
                    checked += 1;
                    next.push(list);
                }
            }
            frontier = next;
        }
        assert_eq!(checked, 4 + 16 + 64 + 256, "enumeration collapsed");
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // The two properties this kernel exists for.
        assert_eq!(spec_compute_verdict_from(&[], 0), VerdictKind::Deny);
        let unmatched = ResolvedMatch {
            matched: false,
            is_deny: false,
            is_conditional: false,
            priority: 0,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: false,
            condition_verdict: VerdictKind::Allow,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        };
        // A list that never decides still denies.
        assert_eq!(
            spec_compute_verdict_from(&[unmatched.clone(), unmatched.clone()], 0),
            VerdictKind::Deny
        );
        // A rule override denies even when the policy type would allow.
        let overridden = ResolvedMatch {
            matched: true,
            rule_override_deny: true,
            ..unmatched
        };
        assert_eq!(
            spec_single_verdict(&overridden),
            VerdictOutcome::Decided(VerdictKind::Deny)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_policy(priority: u32) -> ResolvedMatch {
        ResolvedMatch {
            matched: true,
            is_deny: false,
            is_conditional: false,
            priority,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: false,
            condition_verdict: VerdictKind::Deny,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        }
    }

    fn deny_policy(priority: u32) -> ResolvedMatch {
        ResolvedMatch {
            matched: true,
            is_deny: true,
            is_conditional: false,
            priority,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: false,
            condition_verdict: VerdictKind::Deny,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        }
    }

    fn unmatched_policy(priority: u32) -> ResolvedMatch {
        ResolvedMatch {
            matched: false,
            is_deny: false,
            is_conditional: false,
            priority,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: false,
            condition_verdict: VerdictKind::Deny,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        }
    }

    fn conditional_continue(priority: u32) -> ResolvedMatch {
        ResolvedMatch {
            matched: true,
            is_deny: false,
            is_conditional: true,
            priority,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: false,
            condition_verdict: VerdictKind::Deny,
            on_no_match_continue: true,
            all_constraints_skipped: false,
        }
    }

    fn conditional_fired_allow(priority: u32) -> ResolvedMatch {
        ResolvedMatch {
            matched: true,
            is_deny: false,
            is_conditional: true,
            priority,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: true,
            condition_verdict: VerdictKind::Allow,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        }
    }

    fn conditional_fired_deny(priority: u32) -> ResolvedMatch {
        ResolvedMatch {
            matched: true,
            is_deny: false,
            is_conditional: true,
            priority,
            rule_override_deny: false,
            context_deny: false,
            require_approval: false,
            condition_fired: true,
            condition_verdict: VerdictKind::Deny,
            on_no_match_continue: false,
            all_constraints_skipped: false,
        }
    }

    // === V1: Empty → Deny ===

    #[test]
    fn test_v1_empty_produces_deny() {
        assert_eq!(compute_verdict(&[]), VerdictKind::Deny);
    }

    // === V2: All unmatched → Deny ===

    #[test]
    fn test_v2_all_unmatched_produces_deny() {
        let resolved = vec![unmatched_policy(100), unmatched_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    // === V3: Allow requires matching Allow policy ===

    #[test]
    fn test_v3_allow_from_allow_policy() {
        let resolved = vec![allow_policy(100)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    #[test]
    fn test_v3_allow_not_from_deny_policy() {
        let resolved = vec![deny_policy(100)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_v3_allow_not_from_rule_override() {
        let mut rm = allow_policy(100);
        rm.rule_override_deny = true;
        assert_eq!(compute_verdict(&[rm]), VerdictKind::Deny);
    }

    #[test]
    fn test_v3_allow_not_from_context_deny() {
        let mut rm = allow_policy(100);
        rm.context_deny = true;
        assert_eq!(compute_verdict(&[rm]), VerdictKind::Deny);
    }

    // === V4: Rule override → Deny ===

    #[test]
    fn test_v4_rule_override_forces_deny() {
        let mut rm = allow_policy(100);
        rm.rule_override_deny = true;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::Deny)
        );
    }

    #[test]
    fn test_v4_rule_override_on_deny_policy() {
        let mut rm = deny_policy(100);
        rm.rule_override_deny = true;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::Deny)
        );
    }

    #[test]
    fn test_v4_rule_override_on_conditional() {
        let mut rm = conditional_fired_allow(100);
        rm.rule_override_deny = true;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::Deny)
        );
    }

    // === V5: Totality (always terminates) ===
    // Implicitly tested by all tests completing.

    // === V6: Priority ordering (first-match-wins in sorted order) ===

    #[test]
    fn test_v6_higher_priority_deny_wins() {
        // Sorted: deny(100) before allow(50)
        let resolved = vec![deny_policy(100), allow_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_v6_higher_priority_allow_wins() {
        // Sorted: allow(100) before deny(50)
        let resolved = vec![allow_policy(100), deny_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    // === V7: Deny-dominance at equal priority ===

    #[test]
    fn test_v7_deny_before_allow_at_equal_priority() {
        // When sorted correctly: deny(100) before allow(100) at same priority
        let resolved = vec![deny_policy(100), allow_policy(100)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    // === V8: Conditional pass-through ===

    #[test]
    fn test_v8_conditional_continue_skips_to_next() {
        assert_eq!(
            compute_single_verdict(&conditional_continue(100)),
            VerdictOutcome::Continue,
        );
    }

    #[test]
    fn test_v8_conditional_continue_then_allow() {
        let resolved = vec![conditional_continue(100), allow_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    #[test]
    fn test_v8_conditional_continue_then_deny() {
        let resolved = vec![conditional_continue(100), deny_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_v8_all_conditional_continue_produces_deny() {
        let resolved = vec![conditional_continue(100), conditional_continue(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    // === Conditional constraint fired ===

    #[test]
    fn test_conditional_fired_allow() {
        let resolved = vec![conditional_fired_allow(100)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    #[test]
    fn test_conditional_fired_deny() {
        let resolved = vec![conditional_fired_deny(100)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    // === Conditional without on_no_match_continue: implicit Allow ===

    #[test]
    fn test_conditional_no_fire_no_continue_implicit_allow() {
        let mut rm = conditional_continue(100);
        rm.on_no_match_continue = false;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::Allow),
        );
    }

    // === Require approval ===

    #[test]
    fn test_require_approval_verdict() {
        let mut rm = conditional_continue(100);
        rm.require_approval = true;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::RequireApproval),
        );
    }

    // === All constraints skipped (fail-closed) ===

    #[test]
    fn test_all_constraints_skipped_continue() {
        let mut rm = conditional_continue(100);
        rm.all_constraints_skipped = true;
        assert_eq!(compute_single_verdict(&rm), VerdictOutcome::Continue,);
    }

    #[test]
    fn test_all_constraints_skipped_no_continue_deny() {
        let mut rm = conditional_continue(100);
        rm.all_constraints_skipped = true;
        rm.on_no_match_continue = false;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::Deny),
        );
    }

    // === Context deny ===

    #[test]
    fn test_context_deny_overrides_allow() {
        let mut rm = allow_policy(100);
        rm.context_deny = true;
        assert_eq!(compute_verdict(&[rm]), VerdictKind::Deny);
    }

    #[test]
    fn test_context_deny_on_conditional_overrides_fired_allow() {
        let mut rm = conditional_fired_allow(100);
        rm.context_deny = true;
        assert_eq!(compute_verdict(&[rm]), VerdictKind::Deny);
    }

    // === Mixed sequences ===

    #[test]
    fn test_mixed_unmatched_then_allow() {
        let resolved = vec![unmatched_policy(200), allow_policy(100)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    #[test]
    fn test_mixed_continue_then_continue_then_deny() {
        let resolved = vec![
            conditional_continue(100),
            conditional_continue(90),
            deny_policy(80),
        ];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_conditional_fired_require_approval() {
        let mut rm = conditional_continue(100);
        rm.condition_fired = true;
        rm.condition_verdict = VerdictKind::RequireApproval;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::RequireApproval),
        );
    }

    #[test]
    fn test_rule_override_before_context_deny() {
        let mut rm = allow_policy(100);
        rm.rule_override_deny = true;
        rm.context_deny = true;
        // Rule override checked first
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::Deny),
        );
    }

    // === Complex multi-policy scenarios ===

    #[test]
    fn test_many_unmatched_then_conditional_fired_allow() {
        let resolved = vec![
            unmatched_policy(200),
            unmatched_policy(150),
            unmatched_policy(100),
            conditional_fired_allow(50),
        ];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    #[test]
    fn test_conditional_chain_with_fired_deny_at_end() {
        let resolved = vec![
            conditional_continue(100),
            conditional_continue(90),
            conditional_continue(80),
            conditional_fired_deny(70),
        ];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_rule_override_on_first_match_skips_later_allow() {
        let mut overridden = allow_policy(100);
        overridden.rule_override_deny = true;
        let resolved = vec![overridden, allow_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_context_deny_on_first_match_skips_later_allow() {
        let mut ctx_deny = allow_policy(100);
        ctx_deny.context_deny = true;
        let resolved = vec![ctx_deny, allow_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_require_approval_in_conditional_chain() {
        let mut approval = conditional_continue(90);
        approval.require_approval = true;
        let resolved = vec![conditional_continue(100), approval];
        assert_eq!(compute_verdict(&resolved), VerdictKind::RequireApproval);
    }

    #[test]
    fn test_mixed_unmatched_continue_deny() {
        let resolved = vec![
            unmatched_policy(200),
            conditional_continue(150),
            unmatched_policy(100),
            deny_policy(50),
        ];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_all_constraints_skipped_in_chain_then_allow() {
        let mut skipped = conditional_continue(100);
        skipped.all_constraints_skipped = true;
        let resolved = vec![skipped, allow_policy(50)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    #[test]
    fn test_all_constraints_skipped_no_continue_in_chain() {
        let mut skipped = conditional_continue(100);
        skipped.all_constraints_skipped = true;
        skipped.on_no_match_continue = false;
        let resolved = vec![skipped, allow_policy(50)];
        // Fail-closed: all_constraints_skipped + no continue = Deny
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_single_unmatched_produces_deny() {
        let resolved = vec![unmatched_policy(100)];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_conditional_implicit_allow_when_no_continue() {
        let mut rm = conditional_continue(100);
        rm.on_no_match_continue = false;
        // No constraint fired, no continue → implicit Allow
        let resolved = vec![rm];
        assert_eq!(compute_verdict(&resolved), VerdictKind::Allow);
    }

    #[test]
    fn test_large_policy_set_first_match_deny() {
        let mut resolved: Vec<ResolvedMatch> = (0..50).map(|i| unmatched_policy(200 - i)).collect();
        resolved.push(deny_policy(100));
        // Add some more unmatched after
        for i in 0..20 {
            resolved.push(unmatched_policy(50 - i));
        }
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_large_policy_set_all_unmatched() {
        let resolved: Vec<ResolvedMatch> = (0..100).map(|i| unmatched_policy(200 - i)).collect();
        assert_eq!(compute_verdict(&resolved), VerdictKind::Deny);
    }

    #[test]
    fn test_conditional_fired_deny_verdict_from_constraint() {
        let mut rm = conditional_continue(100);
        rm.condition_fired = true;
        rm.condition_verdict = VerdictKind::Deny;
        assert_eq!(
            compute_single_verdict(&rm),
            VerdictOutcome::Decided(VerdictKind::Deny),
        );
    }
}

#[cfg(test)]
// Suppressed rather than satisfied: linting the extraction would edit the copy
// the Kani proofs run against.
#[allow(clippy::manual_range_contains, dead_code, unused_imports)]
mod kani_verified_core_extraction {
    include!(concat!(
        env!("OUT_DIR"),
        "/kani_verified_core_extraction.rs"
    ));
}

#[cfg(test)]
mod kani_parity_differential_verified_core {
    //! Differential binding for `PARITY-HAND-2` — the policy verdict function.
    //!
    //! This is the most consequential correspondence in the crate. Under
    //! `PARITY-HAND-1` the Verus kernel was discharged **totally** against this
    //! module — all 1,536 `ResolvedMatch` inhabitants — which made it the one
    //! complete discharge of the verdict function. The Kani copy proved its own
    //! version of the same decision and was connected to nothing.
    //!
    //! Until this campaign the extraction's header claimed the algorithm was
    //! identical "verified by unit tests and CI diff checks". That was corrected
    //! earlier to say plainly that nothing checked it. This is the check.
    //!
    //! Bound over the **same total domain** as the Verus discharge, so all three
    //! — Verus kernel, production, Kani copy — are now demonstrably one
    //! function on every input it can receive.

    use super::kani_verified_core_extraction as extracted;
    use super::{compute_single_verdict, compute_verdict, ResolvedMatch, VerdictKind};

    const ALL_VERDICTS: [VerdictKind; 3] = [
        VerdictKind::Allow,
        VerdictKind::Deny,
        VerdictKind::RequireApproval,
    ];

    fn model_verdict(v: VerdictKind) -> extracted::VerdictKind {
        match v {
            VerdictKind::Allow => extracted::VerdictKind::Allow,
            VerdictKind::Deny => extracted::VerdictKind::Deny,
            VerdictKind::RequireApproval => extracted::VerdictKind::RequireApproval,
        }
    }

    /// Every `ResolvedMatch` inhabitant: ten booleans plus a three-valued
    /// verdict. Priority is excluded because `compute_single_verdict` does not
    /// read it — it orders policies, it does not decide them.
    fn all_inhabitants() -> Vec<ResolvedMatch> {
        let mut out = Vec::with_capacity(1_536);
        for bits in 0u16..(1 << 9) {
            let f = |i: u8| bits & (1 << i) != 0;
            for condition_verdict in ALL_VERDICTS {
                out.push(ResolvedMatch {
                    matched: f(0),
                    is_deny: f(1),
                    is_conditional: f(2),
                    priority: 0,
                    rule_override_deny: f(3),
                    context_deny: f(4),
                    require_approval: f(5),
                    condition_fired: f(6),
                    condition_verdict,
                    on_no_match_continue: f(7),
                    all_constraints_skipped: f(8),
                });
            }
        }
        out
    }

    fn to_model(rm: &ResolvedMatch) -> extracted::ResolvedMatch {
        extracted::ResolvedMatch {
            matched: rm.matched,
            is_deny: rm.is_deny,
            is_conditional: rm.is_conditional,
            priority: rm.priority,
            rule_override_deny: rm.rule_override_deny,
            context_deny: rm.context_deny,
            require_approval: rm.require_approval,
            condition_fired: rm.condition_fired,
            condition_verdict: model_verdict(rm.condition_verdict),
            on_no_match_continue: rm.on_no_match_continue,
            all_constraints_skipped: rm.all_constraints_skipped,
        }
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/verified_core.rs was not found, so this binding \
             compared nothing"
        );
    }

    /// TOTAL over all 1,536 inhabitants — the same domain the Verus discharge
    /// covers under `PARITY-HAND-1`.
    #[test]
    fn test_single_verdict_matches_production_total_domain() {
        let inhabitants = all_inhabitants();
        assert_eq!(
            inhabitants.len(),
            1_536,
            "the inhabitant enumeration changed"
        );

        let mut outcomes = std::collections::HashSet::new();
        for rm in &inhabitants {
            let production = compute_single_verdict(rm);
            let model = extracted::compute_single_verdict(&to_model(rm));
            assert_eq!(
                format!("{production:?}"),
                format!("{model:?}"),
                "PARITY-HAND-2: the Kani copy and production disagree on the \
                 verdict for {rm:?} — this is the policy decision itself, and the \
                 Verus kernel is discharged against production's version of it"
            );
            outcomes.insert(format!("{production:?}"));
        }
        assert!(
            outcomes.len() >= 3,
            "the enumeration produced only {} distinct outcomes; it cannot \
             distinguish a verdict function that always returns the same thing",
            outcomes.len()
        );
    }

    /// The fail-closed property the whole engine rests on: no match, or an
    /// empty policy set, produces Deny — never Allow.
    #[test]
    fn test_fail_closed_holds_in_both() {
        assert_eq!(
            compute_verdict(&[]),
            VerdictKind::Deny,
            "an empty policy set did not produce Deny"
        );
        assert_eq!(
            format!("{:?}", extracted::compute_verdict(&[])),
            "Deny",
            "the Kani copy does not fail closed on an empty policy set"
        );

        // And an unmatched policy cannot produce Allow, in either.
        for rm in all_inhabitants().iter().filter(|rm| !rm.matched) {
            assert_ne!(
                compute_single_verdict(rm),
                super::VerdictOutcome::Decided(VerdictKind::Allow),
                "an unmatched policy produced Allow in production: {rm:?}"
            );
            assert_ne!(
                format!("{:?}", extracted::compute_single_verdict(&to_model(rm))),
                "Decided(Allow)",
                "an unmatched policy produced Allow in the Kani copy"
            );
        }
    }

    /// Deny precedence: a rule override or context deny wins regardless of what
    /// the rest of the record says.
    #[test]
    fn test_deny_precedence_holds_in_both() {
        for rm in all_inhabitants()
            .iter()
            .filter(|rm| rm.matched && (rm.rule_override_deny || rm.context_deny))
        {
            assert_eq!(
                compute_single_verdict(rm),
                super::VerdictOutcome::Decided(VerdictKind::Deny),
                "production did not deny despite a rule/context override: {rm:?}"
            );
            assert_eq!(
                format!("{:?}", extracted::compute_single_verdict(&to_model(rm))),
                "Decided(Deny)",
                "the Kani copy did not deny despite a rule/context override"
            );
        }
    }
}

#[cfg(test)]
// Suppressed rather than satisfied: linting the extraction would edit the copy
// the Kani proofs run against.
#[allow(
    clippy::manual_range_contains,
    clippy::nonminimal_bool,
    clippy::too_many_arguments,
    dead_code,
    unused_imports
)]
mod kani_resolve_extraction {
    // The extraction imports the verdict types from its sibling
    // `crate::verified_core`; that module is reproduced at the engine crate
    // root under `#[cfg(test)]` so this file compiles exactly as written.
    include!(concat!(env!("OUT_DIR"), "/kani_resolve_extraction.rs"));
}

#[cfg(test)]
mod kani_parity_differential_resolve {
    //! Differential binding for `PARITY-HAND-2` — the inlined policy decision.
    //!
    //! This extraction exists because of a **declared structural divergence**:
    //! production's `apply_compiled_policy_ctx` does not call
    //! `compute_verdict`, it inlines an equivalent decision tree. K48 is the
    //! claim that the two agree.
    //!
    //! That claim was previously checked only against the Kani crate's *own*
    //! copy of `compute_single_verdict`. Here it is checked against
    //! **production's**, over the total 2¹² × 4 = 16,384 input domain — and the
    //! preceding binding (`kani_parity_differential_verified_core`) established
    //! that production's version and the Kani copy are the same function on all
    //! 1,536 `ResolvedMatch` inhabitants. The two together chain: the inline
    //! tree agrees with the verdict function, and the verdict function is the
    //! one three systems now share.
    //!
    //! Two implementations of one decision, kept in step by hand, is the
    //! highest-risk shape in this crate — it is how `KANI-GLOB-ORDER-1`
    //! happened.

    use super::kani_resolve_extraction as extracted;

    /// Every input combination: twelve booleans and a four-valued condition
    /// result.
    #[test]
    fn test_inline_tree_agrees_with_production_verdict_total_domain() {
        use extracted::InlineVerdict;

        const CONDITION_RESULTS: [Option<InlineVerdict>; 4] = [
            None,
            Some(InlineVerdict::Allow),
            Some(InlineVerdict::Deny),
            Some(InlineVerdict::RequireApproval),
        ];

        let mut checked = 0usize;
        let mut outcomes = std::collections::HashSet::new();

        for bits in 0u16..(1 << 11) {
            let f = |i: u8| bits & (1 << i) != 0;
            let (
                path_deny,
                network_deny,
                ip_deny,
                context_deny,
                has_context_conditions,
                context_provided,
                is_allow_type,
                is_deny_type,
                is_conditional,
                all_constraints_skipped,
                on_no_match_continue,
            ) = (
                f(0),
                f(1),
                f(2),
                f(3),
                f(4),
                f(5),
                f(6),
                f(7),
                f(8),
                f(9),
                f(10),
            );

            for require_approval in [false, true] {
                for condition_result in CONDITION_RESULTS {
                    let condition_label = format!("{condition_result:?}");
                    // Derive before the call: `apply_policy_inline` consumes
                    // `condition_result`, and `InlineVerdict` is not `Copy`.
                    let (condition_fired, condition_verdict) = match &condition_result {
                        None => (false, super::VerdictKind::Allow),
                        Some(InlineVerdict::Allow) => (true, super::VerdictKind::Allow),
                        Some(InlineVerdict::Deny) => (true, super::VerdictKind::Deny),
                        Some(InlineVerdict::RequireApproval) => {
                            (true, super::VerdictKind::RequireApproval)
                        }
                        Some(InlineVerdict::Continue) => (false, super::VerdictKind::Allow),
                    };
                    let inline = extracted::apply_policy_inline(
                        path_deny,
                        network_deny,
                        ip_deny,
                        context_deny,
                        has_context_conditions,
                        context_provided,
                        is_allow_type,
                        is_deny_type,
                        is_conditional,
                        condition_result,
                        all_constraints_skipped,
                        on_no_match_continue,
                        require_approval,
                    );

                    // The same decision, routed through the ResolvedMatch the
                    // extraction constructs and production's verdict function.
                    let verified = extracted::apply_policy_verified(
                        path_deny,
                        network_deny,
                        ip_deny,
                        context_deny,
                        has_context_conditions,
                        context_provided,
                        is_allow_type,
                        is_deny_type,
                        is_conditional,
                        condition_fired,
                        condition_verdict,
                        all_constraints_skipped,
                        on_no_match_continue,
                        require_approval,
                    );

                    assert_eq!(
                        format!("{inline:?}"),
                        format!("{verified:?}"),
                        "K48: the inlined decision tree and the ResolvedMatch path \
                         disagree at (path={path_deny}, net={network_deny}, \
                         ip={ip_deny}, ctx_deny={context_deny}, \
                         has_ctx={has_context_conditions}, \
                         ctx_provided={context_provided}, allow={is_allow_type}, \
                         deny={is_deny_type}, cond={is_conditional}, \
                         skipped={all_constraints_skipped}, \
                         continue={on_no_match_continue}, \
                         approval={require_approval}, result={condition_label}) \
                         — production inlines this tree, so a disagreement is a \
                         policy decision the verified core never sanctioned"
                    );

                    outcomes.insert(format!("{inline:?}"));
                    checked += 1;
                }
            }
        }

        assert_eq!(checked, 2048 * 2 * 4, "the input enumeration collapsed");
        assert!(
            outcomes.len() >= 4,
            "only {} distinct verdicts were produced; the sweep cannot \
             distinguish a decision tree that always answers the same way",
            outcomes.len()
        );
    }

    /// The fail-closed ordering production depends on: rule overrides are
    /// checked *before* policy type, so an Allow policy whose path rules deny
    /// still denies.
    #[test]
    fn test_rule_overrides_precede_policy_type() {
        use extracted::InlineVerdict;
        for (label, path, network, ip) in [
            ("path", true, false, false),
            ("network", false, true, false),
            ("ip", false, false, true),
        ] {
            let verdict = extracted::apply_policy_inline(
                path, network, ip, false, false, false, /* is_allow_type */ true, false,
                false, None, false, false, false,
            );
            assert_eq!(
                format!("{verdict:?}"),
                format!("{:?}", InlineVerdict::Deny),
                "an Allow policy with a {label} rule denial did not deny — rule \
                 overrides must precede policy type dispatch"
            );
        }
    }

    /// K46/K47 and the missing-context case: a policy declaring context
    /// conditions with no context provided must deny, or the conditions are
    /// bypassable by omitting the context.
    #[test]
    fn test_missing_context_fails_closed() {
        use extracted::InlineVerdict;
        let verdict = extracted::apply_policy_inline(
            false, false, false, false, /* has_context_conditions */ true,
            /* context_provided */ false, /* is_allow_type */ true, false, false, None,
            false, false, false,
        );
        assert_eq!(
            format!("{verdict:?}"),
            format!("{:?}", InlineVerdict::Deny),
            "a policy requiring context was evaluated without it and did not \
             deny — time-window and max-calls restrictions would be bypassable \
             by omitting the context"
        );
    }
}
