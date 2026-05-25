// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified constraint-evaluation kernel.
//!
//! This file proves the pure fail-closed control-flow extracted into
//! `vellaveto-engine/src/verified_constraint_eval.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_constraint_eval.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

#[derive(Structural, PartialEq, Eq, Clone, Copy)]
pub enum ConstraintVerdict {
    Allow,
    Deny,
    RequireApproval,
    Continue,
}

#[derive(Structural, PartialEq, Eq, Clone, Copy)]
pub enum MatchedConstraintVerdict {
    Allow,
    Deny,
    RequireApproval,
}

pub open spec fn spec_all_constraints_skipped(total_constraints: nat, any_evaluated: bool) -> bool {
    total_constraints > 0 && !any_evaluated
}

pub fn all_constraints_skipped(total_constraints: usize, any_evaluated: bool) -> (result: bool)
    ensures
        result == spec_all_constraints_skipped(total_constraints as nat, any_evaluated),
        total_constraints == 0 ==> !result,
        any_evaluated ==> !result,
        result ==> total_constraints > 0,
{
    total_constraints > 0 && !any_evaluated
}

pub open spec fn spec_has_known_condition_key(
    has_require_approval: bool,
    has_forbidden_parameters: bool,
    has_required_parameters: bool,
    has_parameter_constraints: bool,
    has_context_conditions: bool,
    has_on_no_match: bool,
) -> bool {
    has_require_approval
        || has_forbidden_parameters
        || has_required_parameters
        || has_parameter_constraints
        || has_context_conditions
        || has_on_no_match
}

pub fn has_known_condition_key(
    has_require_approval: bool,
    has_forbidden_parameters: bool,
    has_required_parameters: bool,
    has_parameter_constraints: bool,
    has_context_conditions: bool,
    has_on_no_match: bool,
) -> (result: bool)
    ensures
        result == spec_has_known_condition_key(
            has_require_approval,
            has_forbidden_parameters,
            has_required_parameters,
            has_parameter_constraints,
            has_context_conditions,
            has_on_no_match,
        ),
        result ==> has_require_approval
            || has_forbidden_parameters
            || has_required_parameters
            || has_parameter_constraints
            || has_context_conditions
            || has_on_no_match,
        !result ==> !has_require_approval
            && !has_forbidden_parameters
            && !has_required_parameters
            && !has_parameter_constraints
            && !has_context_conditions
            && !has_on_no_match,
{
    has_require_approval
        || has_forbidden_parameters
        || has_required_parameters
        || has_parameter_constraints
        || has_context_conditions
        || has_on_no_match
}

pub open spec fn spec_unrecognized_condition_payload(
    has_condition_payload: bool,
    has_known_condition_key: bool,
) -> bool {
    has_condition_payload && !has_known_condition_key
}

pub fn unrecognized_condition_payload(
    has_condition_payload: bool,
    has_known_condition_key: bool,
) -> (result: bool)
    ensures
        result == spec_unrecognized_condition_payload(
            has_condition_payload,
            has_known_condition_key,
        ),
        result ==> has_condition_payload,
        result ==> !has_known_condition_key,
        !has_condition_payload ==> !result,
        has_known_condition_key ==> !result,
{
    has_condition_payload && !has_known_condition_key
}

pub open spec fn spec_has_forbidden_parameter(flags: Seq<bool>) -> bool {
    exists|i: int| 0 <= i < flags.len() && #[trigger] flags[i]
}

pub fn has_forbidden_parameter(flags: &Vec<bool>) -> (result: bool)
    ensures
        result == spec_has_forbidden_parameter(flags@),
        result ==> exists|i: int| 0 <= i < flags.len() && #[trigger] flags[i],
        !result ==> forall|i: int| 0 <= i < flags.len() ==> !(#[trigger] flags[i]),
{
    let mut idx: usize = 0;
    while idx < flags.len()
        invariant
            0 <= idx <= flags.len(),
            forall|j: int| 0 <= j < idx as int ==> !(#[trigger] flags[j]),
        decreases flags.len() - idx,
    {
        if flags[idx] {
            return true;
        }
        idx = idx + 1;
    }
    false
}

pub open spec fn spec_skipped_constraints_verdict(on_no_match_continue: bool) -> ConstraintVerdict {
    if on_no_match_continue {
        ConstraintVerdict::Continue
    } else {
        ConstraintVerdict::Deny
    }
}

pub fn skipped_constraints_verdict(on_no_match_continue: bool) -> (result: ConstraintVerdict)
    ensures
        result == spec_skipped_constraints_verdict(on_no_match_continue),
        on_no_match_continue ==> result == ConstraintVerdict::Continue,
        !on_no_match_continue ==> result == ConstraintVerdict::Deny,
{
    if on_no_match_continue {
        ConstraintVerdict::Continue
    } else {
        ConstraintVerdict::Deny
    }
}

pub open spec fn spec_no_match_verdict(on_no_match_continue: bool) -> ConstraintVerdict {
    if on_no_match_continue {
        ConstraintVerdict::Continue
    } else {
        ConstraintVerdict::Allow
    }
}

pub fn no_match_verdict(on_no_match_continue: bool) -> (result: ConstraintVerdict)
    ensures
        result == spec_no_match_verdict(on_no_match_continue),
        on_no_match_continue ==> result == ConstraintVerdict::Continue,
        !on_no_match_continue ==> result == ConstraintVerdict::Allow,
{
    if on_no_match_continue {
        ConstraintVerdict::Continue
    } else {
        ConstraintVerdict::Allow
    }
}

pub open spec fn spec_matched_constraint_verdict(
    condition_verdict: MatchedConstraintVerdict,
) -> ConstraintVerdict {
    match condition_verdict {
        MatchedConstraintVerdict::Allow => ConstraintVerdict::Allow,
        MatchedConstraintVerdict::Deny => ConstraintVerdict::Deny,
        MatchedConstraintVerdict::RequireApproval => ConstraintVerdict::RequireApproval,
    }
}

pub open spec fn spec_conditional_verdict(
    require_approval: bool,
    all_constraints_skipped: bool,
    on_no_match_continue: bool,
    any_forbidden_present: bool,
    condition_fired: bool,
    condition_verdict: MatchedConstraintVerdict,
) -> ConstraintVerdict {
    if any_forbidden_present {
        ConstraintVerdict::Deny
    } else if require_approval {
        ConstraintVerdict::RequireApproval
    } else if all_constraints_skipped {
        spec_skipped_constraints_verdict(on_no_match_continue)
    } else if condition_fired {
        spec_matched_constraint_verdict(condition_verdict)
    } else {
        spec_no_match_verdict(on_no_match_continue)
    }
}

pub fn conditional_verdict(
    require_approval: bool,
    all_constraints_skipped: bool,
    on_no_match_continue: bool,
    any_forbidden_present: bool,
    condition_fired: bool,
    condition_verdict: MatchedConstraintVerdict,
) -> (result: ConstraintVerdict)
    ensures
        result == spec_conditional_verdict(
            require_approval,
            all_constraints_skipped,
            on_no_match_continue,
            any_forbidden_present,
            condition_fired,
            condition_verdict,
        ),
        any_forbidden_present ==> result == ConstraintVerdict::Deny,
        !any_forbidden_present && require_approval ==> result == ConstraintVerdict::RequireApproval,
        !any_forbidden_present && !require_approval && all_constraints_skipped && on_no_match_continue
            ==> result == ConstraintVerdict::Continue,
        !any_forbidden_present && !require_approval && all_constraints_skipped && !on_no_match_continue
            ==> result == ConstraintVerdict::Deny,
        !any_forbidden_present && !require_approval && !all_constraints_skipped && !condition_fired
            && on_no_match_continue ==> result == ConstraintVerdict::Continue,
        !any_forbidden_present && !require_approval && !all_constraints_skipped && !condition_fired
            && !on_no_match_continue ==> result == ConstraintVerdict::Allow,
{
    if any_forbidden_present {
        return ConstraintVerdict::Deny;
    }

    if require_approval {
        return ConstraintVerdict::RequireApproval;
    }

    if all_constraints_skipped {
        return skipped_constraints_verdict(on_no_match_continue);
    }

    if condition_fired {
        return match condition_verdict {
            MatchedConstraintVerdict::Allow => ConstraintVerdict::Allow,
            MatchedConstraintVerdict::Deny => ConstraintVerdict::Deny,
            MatchedConstraintVerdict::RequireApproval => ConstraintVerdict::RequireApproval,
        };
    }

    no_match_verdict(on_no_match_continue)
}

pub proof fn lemma_all_skipped_is_fail_closed(total_constraints: nat)
    requires total_constraints > 0,
    ensures
        spec_all_constraints_skipped(total_constraints, false),
        !spec_all_constraints_skipped(total_constraints, true),
{
}

pub proof fn lemma_unrecognized_condition_payload_is_fail_closed()
    ensures
        spec_unrecognized_condition_payload(true, false),
        !spec_unrecognized_condition_payload(false, false),
        !spec_unrecognized_condition_payload(true, true),
{
}

pub proof fn lemma_forbidden_precedes_approval(
    require_approval: bool,
    all_constraints_skipped: bool,
    on_no_match_continue: bool,
    condition_fired: bool,
    condition_verdict: MatchedConstraintVerdict,
)
    ensures
        spec_conditional_verdict(
            require_approval,
            all_constraints_skipped,
            on_no_match_continue,
            true,
            condition_fired,
            condition_verdict,
        ) == ConstraintVerdict::Deny,
{
}

pub proof fn lemma_no_match_continue_is_only_continue(
    require_approval: bool,
    any_forbidden_present: bool,
    condition_verdict: MatchedConstraintVerdict,
)
    ensures
        spec_conditional_verdict(
            require_approval,
            false,
            true,
            any_forbidden_present,
            false,
            condition_verdict,
        )
        == if any_forbidden_present {
            ConstraintVerdict::Deny
        } else if require_approval {
            ConstraintVerdict::RequireApproval
        } else {
            ConstraintVerdict::Continue
        },
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::constraint_eval_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
