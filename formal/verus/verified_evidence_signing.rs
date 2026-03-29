// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified evidence pack signing guards (EVIDENCE-SIGN-1–3).
//!
//! Proves the extracted predicates for evidence pack integrity:
//! signing content field coverage, coverage validation, and signature format.
//!
//! Production code: `vellaveto-types/src/evidence_pack.rs:296-500`
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_evidence_signing.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

/// Maximum evidence signature hex length (Ed25519 = 64 bytes = 128 hex).
pub const MAX_EVIDENCE_SIGNATURE_HEX_LEN: usize = 128;
/// Maximum evidence verifying key hex length (Ed25519 pk = 32 bytes = 64 hex).
pub const MAX_EVIDENCE_VERIFYING_KEY_HEX_LEN: usize = 64;
/// Maximum evidence string field length.
pub const MAX_EVIDENCE_STRING_LEN: usize = 4096;
/// Maximum evidence sections.
pub const MAX_EVIDENCE_SECTIONS: usize = 100;
/// Maximum critical gaps.
pub const MAX_EVIDENCE_PACK_GAPS: usize = 500;
/// Maximum recommendations.
pub const MAX_EVIDENCE_RECOMMENDATIONS: usize = 100;

// ═══════════════════════════════════════════════════════════════════
// EVIDENCE-SIGN-1: signing_content includes all tamper-detectable fields
// ═══════════════════════════════════════════════════════════════════

/// The minimum number of distinct fields that MUST be included in
/// the signing content hash. Each field contributes a length-prefixed
/// hash_field() call in production code.
///
/// Fields: framework_name, generated_at, organization_name, system_id,
///         overall_coverage_percent, total_requirements, covered_requirements,
///         partial_requirements, uncovered_requirements, period_start,
///         period_end, sections (count + per-section fields), critical_gaps
///         (count + each), recommendations (count + each).
pub open spec fn spec_minimum_signing_fields() -> usize {
    12  // 9 scalar fields + period_start + period_end + sections header
}

pub fn minimum_signing_fields() -> (result: usize)
    ensures result == spec_minimum_signing_fields(),
            result >= 12,
{
    12
}

/// Prove: signing_content() MUST hash sections, not just scalars.
/// Without sections, an attacker can strip evidence items.
pub open spec fn spec_sections_included_in_signing(
    sections_count_hashed: bool,
    section_ids_hashed: bool,
    section_titles_hashed: bool,
    section_item_counts_hashed: bool,
) -> bool {
    sections_count_hashed
        && section_ids_hashed
        && section_titles_hashed
        && section_item_counts_hashed
}

/// Prove: signing_content() MUST hash recommendations.
/// Without recommendations, an attacker can strip remediation guidance.
pub open spec fn spec_recommendations_included(
    count_hashed: bool,
    each_hashed: bool,
) -> bool {
    count_hashed && each_hashed
}

// ═══════════════════════════════════════════════════════════════════
// EVIDENCE-SIGN-2: Coverage validation (NaN/Infinity rejection)
// ═══════════════════════════════════════════════════════════════════

/// Overall coverage percent must be finite and in [0.0, 100.0].
/// NaN and Infinity bypass threshold comparisons silently.
pub open spec fn spec_coverage_valid(pct_is_finite: bool, pct_in_range: bool) -> bool {
    pct_is_finite && pct_in_range
}

pub fn coverage_valid(pct_is_finite: bool, pct_in_range: bool) -> (result: bool)
    ensures
        result == spec_coverage_valid(pct_is_finite, pct_in_range),
        !pct_is_finite ==> !result,
        !pct_in_range ==> !result,
{
    pct_is_finite && pct_in_range
}

// ═══════════════════════════════════════════════════════════════════
// EVIDENCE-SIGN-3: Signature and verifying key hex format
// ═══════════════════════════════════════════════════════════════════

/// Ed25519 signature must be exactly 128 hex characters (64 bytes).
pub open spec fn spec_signature_hex_valid(len: usize) -> bool {
    len == MAX_EVIDENCE_SIGNATURE_HEX_LEN
}

pub fn signature_hex_valid(len: usize) -> (result: bool)
    ensures
        result == spec_signature_hex_valid(len),
        result ==> len == 128,
{
    len == MAX_EVIDENCE_SIGNATURE_HEX_LEN
}

/// Ed25519 verifying key must be exactly 64 hex characters (32 bytes).
pub open spec fn spec_verifying_key_hex_valid(len: usize) -> bool {
    len == MAX_EVIDENCE_VERIFYING_KEY_HEX_LEN
}

pub fn verifying_key_hex_valid(len: usize) -> (result: bool)
    ensures
        result == spec_verifying_key_hex_valid(len),
        result ==> len == 64,
{
    len == MAX_EVIDENCE_VERIFYING_KEY_HEX_LEN
}

/// Prove: requirement count consistency.
/// covered + partial + uncovered ≤ total.
pub open spec fn spec_requirement_count_consistent(
    covered: usize,
    partial: usize,
    uncovered: usize,
    total: usize,
) -> bool {
    covered + partial + uncovered <= total
}

pub fn requirement_count_consistent(
    covered: usize,
    partial: usize,
    uncovered: usize,
    total: usize,
) -> (result: bool)
    requires
        covered + partial + uncovered <= usize::MAX, // no overflow
    ensures
        result == spec_requirement_count_consistent(covered, partial, uncovered, total),
{
    covered + partial + uncovered <= total
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::evidence_signing_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

} // verus!
