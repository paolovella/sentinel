// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified cross-call DLP split-detection completeness.
//!
//! Proves that the overlap-buffer concatenation in
//! `vellaveto-mcp/src/inspection/cross_call_dlp.rs` correctly assembles
//! the combined scanning window so that secrets split across two consecutive
//! tool calls are presented intact to the DLP scanner.
//!
//! These are pure `Seq<u8>` concatenation lemmas — no f64, no regex. The
//! DLP pattern-matching correctness is handled by Kani harnesses K69-K77
//! (per the design decision in `LOCAL_VERIFICATION_PLAN.md`, Phase 2).
//!
//! # Production correspondence
//!
//! The production code in `cross_call_dlp.rs::scan_with_overlap` does:
//!
//! ```rust
//! let combined = format!("{tail_str}{current_value}");
//! //   combined  = tail ++ current  (concatenation)
//! ```
//!
//! These lemmas prove that this concatenation preserves:
//! - the tail bytes verbatim in the first `tail_len` positions
//! - the current bytes verbatim starting at position `tail_len`
//! - any contiguous sub-range spanning the junction
//!
//! # Properties Verified
//!
//! | ID | Property |
//! |----|----------|
//! | CC-SPLIT-1 | Combined length = tail_len + current_len |
//! | CC-SPLIT-2 | Tail is preserved verbatim in combined[0..tail_len] |
//! | CC-SPLIT-3 | Current is preserved verbatim in combined[tail_len..] |
//! | CC-SPLIT-4 | Any sub-range crossing the junction is a contiguous substring of combined |
//!
//! # Trust boundary
//!
//! These proofs are about `Seq<u8>` concatenation in Verus spec mode.
//! The only trusted assumption is VERUS-ESCAPE-1 (shared proof escape hatch
//! inventory). No new trusted assumptions are introduced.
//!
//! # To verify
//!
//! ```sh
//! verus --triggers-mode silent formal/verus/verified_cross_call_split.rs
//! ```

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

// ── Spec model ────────────────────────────────────────────────────────────────

/// Spec: the combined scanning window is the concatenation of `tail` and `current`.
pub open spec fn spec_combined(tail: Seq<u8>, current: Seq<u8>) -> Seq<u8> {
    tail + current
}

/// Spec: byte `i` is within the tail region.
pub open spec fn spec_in_tail_region(i: nat, tail_len: nat) -> bool {
    i < tail_len
}

/// Spec: byte `i` is within the current region.
pub open spec fn spec_in_current_region(i: nat, tail_len: nat, combined_len: nat) -> bool {
    i >= tail_len && i < combined_len
}

/// Spec: a contiguous range [start..start+len] spans the junction
/// (i.e., it contains at least one byte from tail and one from current).
pub open spec fn spec_spans_junction(
    start: nat,
    len: nat,
    tail_len: nat,
    combined_len: nat,
) -> bool {
    start < tail_len
        && start + len > tail_len
        && start + len <= combined_len
}

/// Spec: seq `s` is a substring of `t` starting at position `pos`.
pub open spec fn spec_is_substring_at(s: Seq<u8>, t: Seq<u8>, pos: nat) -> bool {
    pos + s.len() <= t.len()
        && forall|i: nat| i < s.len() ==> #[trigger] t[pos as int + i as int] == s[i as int]
}

// ── CC-SPLIT-1: Length invariant ──────────────────────────────────────────────

/// The combined scanning window has exactly `tail.len() + current.len()` bytes.
pub proof fn lemma_combined_length(tail: Seq<u8>, current: Seq<u8>)
    ensures
        spec_combined(tail, current).len() == tail.len() + current.len(),
{
    // Seq addition length is definitional in vstd.
}

// ── CC-SPLIT-2: Tail preservation ─────────────────────────────────────────────

/// Every byte in the tail region of `combined` matches the corresponding
/// byte in `tail` — the overlap buffer is copied verbatim.
pub proof fn lemma_tail_preserved_in_combined(tail: Seq<u8>, current: Seq<u8>, i: nat)
    requires
        i < tail.len(),
    ensures
        spec_combined(tail, current)[i as int] == tail[i as int],
{
    // Index into the first operand of (tail + current) equals tail[i].
}

/// The first `tail.len()` bytes of `combined` are exactly `tail`.
pub proof fn lemma_combined_prefix_eq_tail(tail: Seq<u8>, current: Seq<u8>)
    ensures
        spec_combined(tail, current).take(tail.len() as int) =~= tail,
{
    let combined = spec_combined(tail, current);
    assert(combined.take(tail.len() as int).len() == tail.len());
    assert forall|i: nat| i < tail.len()
        implies combined.take(tail.len() as int)[i as int] == tail[i as int]
    by {
        lemma_tail_preserved_in_combined(tail, current, i);
    };
    assert(combined.take(tail.len() as int) =~= tail);
}

// ── CC-SPLIT-3: Current preservation ─────────────────────────────────────────

/// Every byte in the current region of `combined` matches the corresponding
/// byte in `current` — the current call's value is copied verbatim starting
/// at position `tail.len()`.
pub proof fn lemma_current_preserved_in_combined(
    tail: Seq<u8>,
    current: Seq<u8>,
    i: nat,
)
    requires
        i < current.len(),
    ensures
        spec_combined(tail, current)[(tail.len() + i) as int] == current[i as int],
{
    // Index into the second operand of (tail + current) at offset tail.len() + i
    // equals current[i].
}

/// The bytes of `combined` from position `tail.len()` onward are exactly `current`.
pub proof fn lemma_combined_suffix_eq_current(tail: Seq<u8>, current: Seq<u8>)
    ensures
        spec_combined(tail, current).skip(tail.len() as int) =~= current,
{
    let combined = spec_combined(tail, current);
    assert(combined.skip(tail.len() as int).len() == current.len());
    assert forall|i: nat| i < current.len()
        implies combined.skip(tail.len() as int)[i as int] == current[i as int]
    by {
        lemma_current_preserved_in_combined(tail, current, i);
    };
    assert(combined.skip(tail.len() as int) =~= current);
}

// ── CC-SPLIT-4: Junction completeness ────────────────────────────────────────

/// The core split-detection completeness lemma: any contiguous range that
/// spans the tail/current junction is present as a substring of `combined`.
///
/// This means: if a secret is split with its first `k` bytes at the end of
/// `tail` and its remaining bytes at the start of `current`, the DLP scanner
/// will encounter the full secret contiguously in `combined`.
pub proof fn lemma_junction_range_is_substring(
    tail: Seq<u8>,
    current: Seq<u8>,
    start: nat,
    len: nat,
)
    requires
        spec_spans_junction(start, len, tail.len(), tail.len() + current.len()),
    ensures
        spec_is_substring_at(
            spec_combined(tail, current).subrange(start as int, (start + len) as int),
            spec_combined(tail, current),
            start,
        ),
{
    let combined = spec_combined(tail, current);
    let sub = combined.subrange(start as int, (start + len) as int);
    assert(sub.len() == len);
    assert forall|i: nat| i < sub.len()
        implies #[trigger] combined[start as int + i as int] == sub[i as int]
    by {
        // subrange[i] == combined[start + i] by definition.
    };
}

/// Split-secret completeness: if a secret of length `secret_len` ends at
/// position `end_pos` in `combined`, and its first byte appears at position
/// `start_pos`, then the secret is entirely within `combined`.
///
/// Concretely: if `secret_len ≤ tail.len() + current.len()` and the secret
/// starts in the tail region and ends in the current region, the overlap
/// window contains the full secret.
pub proof fn lemma_split_secret_in_combined(
    tail: Seq<u8>,
    current: Seq<u8>,
    secret_len: nat,
    split_pos: nat,    // bytes of secret that fall in tail (prefix length in tail)
)
    requires
        secret_len > 0,
        split_pos > 0,                          // prefix in tail
        split_pos < secret_len,                 // suffix in current
        split_pos <= tail.len(),                // prefix fits within tail
        secret_len - split_pos <= current.len(), // suffix fits within current
    ensures
        // The secret occupies combined[tail.len()-split_pos .. tail.len()-split_pos+secret_len]
        spec_spans_junction(
            tail.len() - split_pos,
            secret_len,
            tail.len(),
            tail.len() + current.len(),
        ),
        spec_is_substring_at(
            spec_combined(tail, current).subrange(
                (tail.len() - split_pos) as int,
                (tail.len() - split_pos + secret_len) as int,
            ),
            spec_combined(tail, current),
            tail.len() - split_pos,
        ),
{
    let combined = spec_combined(tail, current);
    let start = tail.len() - split_pos;
    let end = start + secret_len;

    // 1. Show the range spans the junction.
    assert(start < tail.len()) by { /* start = tail.len() - split_pos < tail.len() since split_pos > 0 */ };
    assert(end > tail.len()) by { /* end = start + secret_len > tail.len() since split_pos < secret_len */ };
    assert(end <= tail.len() + current.len()) by {
        /* end = tail.len() - split_pos + secret_len
                = tail.len() + (secret_len - split_pos)
                ≤ tail.len() + current.len() */
    };

    // 2. Apply junction completeness.
    lemma_junction_range_is_substring(tail, current, start, secret_len);
}

// ── Overlap buffer size bound ──────────────────────────────────────────────────

/// The overlap buffer for a given field is bounded by `overlap_size`.
/// The tail passed to `scan_with_overlap` has at most `overlap_size` bytes.
pub proof fn lemma_tail_bounded_by_overlap_size(tail: Seq<u8>, overlap_size: nat)
    requires
        tail.len() <= overlap_size,
    ensures
        // Any split_pos ≤ overlap_size is provably within the tail.
        forall|split_pos: nat|
            split_pos <= overlap_size && split_pos <= tail.len()
            ==> split_pos <= tail.len(),
{
    // Trivial from the precondition.
}

/// Consequence: secrets of length ≤ 2 * overlap_size split at any position
/// within the tail can always be assembled in `combined` when:
///  - `tail.len() == overlap_size` (full overlap buffer)
///  - `current.len() ≥ secret_len - split_pos`
pub proof fn lemma_bounded_secret_always_covered(
    tail: Seq<u8>,
    current: Seq<u8>,
    overlap_size: nat,
    secret_len: nat,
    split_pos: nat,
)
    requires
        tail.len() == overlap_size,        // full overlap buffer
        secret_len > 0,
        split_pos > 0,
        split_pos < secret_len,
        split_pos <= overlap_size,         // split within the tail
        secret_len <= 2 * overlap_size,    // secret bounded by 2 × overlap
        current.len() >= secret_len - split_pos,
    ensures
        spec_spans_junction(
            tail.len() - split_pos,
            secret_len,
            tail.len(),
            tail.len() + current.len(),
        ),
{
    let start = tail.len() - split_pos;
    assert(start < tail.len());
    assert(start + secret_len > tail.len()) by {
        // start + secret_len = tail.len() - split_pos + secret_len
        //                    = tail.len() + (secret_len - split_pos)
        //                    > tail.len() since secret_len > split_pos.
    };
    assert(start + secret_len <= tail.len() + current.len()) by {
        // start + secret_len = tail.len() + (secret_len - split_pos)
        //                    ≤ tail.len() + current.len()
        // because current.len() ≥ secret_len - split_pos.
    };
}

// ── Assumption registration ────────────────────────────────────────────────────

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::cross_call_split_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
