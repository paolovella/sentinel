// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified DLP buffer arithmetic (Phase 2).
//!
//! Pure functions for cross-call DLP buffer management, factored from
//! `cross_call_dlp.rs` for Verus formal verification. These functions
//! operate on `&[u8]` and `usize` — no HashMap, String, VecDeque, or I/O.
//!
//! # Verified Properties (D1-D6)
//!
//! | ID | Property | Meaning |
//! |----|----------|---------|
//! | D1 | UTF-8 char boundary safety | `extract_tail` never returns a start in mid-character |
//! | D2 | Single buffer size bounded | Extracted tail never exceeds `max_size` bytes |
//! | D3 | Total byte accounting correct | `update_total_bytes` is monotonically correct |
//! | D4 | Capacity check fail-closed | At `max_fields`, `can_track_field` returns false |
//! | D5 | No arithmetic underflow | Saturating subtraction prevents wrapping |
//! | D6 | Overlap completeness | Secret <= 2 * overlap_size with split_point <= overlap_size is fully covered |
//!
//! The Verus-annotated version at `formal/verus/verified_dlp_core.rs`
//! proves these properties for ALL possible inputs.
//!
//! # Trust Boundary
//!
//! This module proves correctness of the buffer arithmetic. The HashMap
//! wrapper in `cross_call_dlp.rs` that keys buffers by field name is
//! NOT verified — it is a lookup table, not security logic.

/// Check if a byte is a UTF-8 character boundary.
///
/// A byte is a character boundary if it is NOT a continuation byte (10xxxxxx).
/// This matches `str::is_char_boundary()` for interior bytes.
///
/// # Property D1 (partial)
/// This function correctly identifies UTF-8 continuation bytes.
#[inline]
pub fn is_utf8_char_boundary(b: u8) -> bool {
    (b & 0xC0) != 0x80
}

/// Extract the tail of a byte slice, adjusted to a valid UTF-8 character boundary.
///
/// Returns `(start, end)` indices into `value` such that:
/// - `value[start..end]` is at most `max_size` bytes (D2)
/// - `start` is at a UTF-8 character boundary (D1)
/// - `end == value.len()`
///
/// If `value` is shorter than `max_size`, the entire slice is returned.
/// If adjusting to a char boundary consumes all bytes, returns `(value.len(), value.len())`.
///
/// # Panics
/// Never panics. All arithmetic is bounds-checked.
pub fn extract_tail(value: &[u8], max_size: usize) -> (usize, usize) {
    if value.is_empty() || max_size == 0 {
        return (value.len(), value.len());
    }

    let raw_start = value.len().saturating_sub(max_size);
    let mut start = raw_start;

    // Advance past any continuation bytes to land on a char boundary
    while start < value.len() && !is_utf8_char_boundary(value[start]) {
        start = start.saturating_add(1);
    }

    (start, value.len())
}

/// Check if a new field can be tracked without exceeding limits.
///
/// Returns `true` only if:
/// - `current_fields < max_fields` (D4: fail-closed at capacity)
/// - `current_bytes + new_buffer_bytes <= max_total_bytes` (no overflow via checked_add)
///
/// # Property D4
/// At `max_fields`, this always returns `false` — no field is silently dropped.
pub fn can_track_field(
    current_fields: usize,
    max_fields: usize,
    current_bytes: usize,
    new_buffer_bytes: usize,
    max_total_bytes: usize,
) -> bool {
    if current_fields >= max_fields {
        return false;
    }
    match current_bytes.checked_add(new_buffer_bytes) {
        Some(total) => total <= max_total_bytes,
        None => false, // Overflow → fail-closed
    }
}

/// Update total byte accounting after replacing a buffer.
///
/// Uses saturating arithmetic to prevent underflow (D5) even if
/// accounting is inconsistent (defensive programming).
///
/// # Property D3
/// When `old_total >= old_buffer_len`:
///   `result == old_total - old_buffer_len + new_buffer_len`
///
/// # Property D5
/// When `old_total < old_buffer_len` (inconsistent state):
///   `result == new_buffer_len` (saturating_sub floors at 0)
pub fn update_total_bytes(old_total: usize, old_buffer_len: usize, new_buffer_len: usize) -> usize {
    old_total
        .saturating_sub(old_buffer_len)
        .saturating_add(new_buffer_len)
}

/// Compute the overlap scan region size.
///
/// Given the previous tail buffer and current value, returns the size
/// of the combined scan region.
///
/// # Property D6 (overlap completeness)
/// If `secret_len <= 2 * overlap_size` and the secret is split with
/// `split_point <= overlap_size` between two consecutive calls, the combined
/// region `(prev_tail ++ current_value)` contains the entire secret.
pub fn compute_overlap_region_size(prev_tail_len: usize, current_value_len: usize) -> usize {
    prev_tail_len.saturating_add(current_value_len)
}

/// Check overlap completeness: can a secret of `secret_len` bytes,
/// split at `split_point` between previous and current values, be
/// fully contained in the combined scan buffer?
///
/// # Property D6
/// Returns `true` when the combined buffer covers the entire secret.
/// This is guaranteed when `secret_len <= 2 * overlap_size` and the first
/// fragment fits in the retained overlap (`split_point <= overlap_size`).
pub fn overlap_covers_secret(
    prev_value_len: usize,
    current_value_len: usize,
    overlap_size: usize,
    secret_len: usize,
    split_point: usize,
) -> bool {
    // The previous tail is at most overlap_size bytes
    let prev_tail_len = prev_value_len.min(overlap_size);
    // Combined region = prev_tail + current_value
    let combined_len = prev_tail_len.saturating_add(current_value_len);

    // The secret spans from (prev_value_len - split_point) in the tail
    // to split_point in the current value. Check if combined covers it.
    // For secrets <= 2 * overlap_size, this is always true when:
    //   split_point > 0 && split_point < secret_len
    //   prev_tail_len >= split_point
    //   current_value_len >= secret_len - split_point
    if split_point == 0 || split_point >= secret_len {
        return false; // Not actually split
    }
    if prev_tail_len < split_point || current_value_len < secret_len.saturating_sub(split_point) {
        return false; // Values too short to contain secret parts
    }

    combined_len >= secret_len
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_dlp_core.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function. Symbol parity cannot see this:
    //! `check-verus-parity.sh` greps for names.
    //!
    //! MIXED: `is_utf8_char_boundary` is discharged TOTALLY — all 256 `u8`
    //! values. `extract_tail` is bounded-exhaustive over byte strings drawn
    //! from an alphabet holding ASCII, a UTF-8 lead byte and two continuation
    //! bytes, which is what the boundary scan exists to skip. `can_track_field`
    //! uses a boundary set built around the addition overflow the spec
    //! forbids.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_is_char_boundary(b: u8) -> bool {
        (b & 0xC0u8) != 0x80u8
    }

    fn spec_advance_to_boundary(value: &[u8], start: usize) -> usize {
        if start >= value.len() {
            value.len()
        } else if spec_is_char_boundary(value[start]) {
            start
        } else {
            spec_advance_to_boundary(value, start + 1)
        }
    }

    fn spec_extract_tail_start(value: &[u8], max_size: usize) -> usize {
        if value.is_empty() || max_size == 0 {
            value.len()
        } else {
            let raw_start = if value.len() > max_size {
                value.len() - max_size
            } else {
                0
            };
            spec_advance_to_boundary(value, raw_start)
        }
    }

    fn spec_can_track_field(
        current_fields: usize,
        max_fields: usize,
        current_bytes: usize,
        new_buffer_bytes: usize,
        max_total_bytes: usize,
    ) -> bool {
        current_fields < max_fields
            && match current_bytes.checked_add(new_buffer_bytes) {
                // The kernel writes the no-overflow condition as
                // `current + new >= current`, which over unbounded `nat` is
                // vacuous and over `usize` is exactly "the addition did not
                // wrap". `checked_add` is that condition, stated directly.
                Some(total) => total <= max_total_bytes,
                None => false,
            }
    }

    #[test]
    fn test_is_char_boundary_matches_verus_spec_total_domain() {
        for b in 0u8..=u8::MAX {
            assert_eq!(
                is_utf8_char_boundary(b),
                spec_is_char_boundary(b),
                "PARITY-HAND-1: is_utf8_char_boundary disagrees at {b:#04x}"
            );
        }
    }

    #[test]
    fn test_extract_tail_matches_verus_spec_bounded_exhaustive() {
        // 0x41 is ASCII, 0xC3 a two-byte lead, 0x80/0xBF continuation bytes —
        // the scan exists to walk off the last two.
        const ALPHABET: &[u8] = &[0x41, 0xC3, 0x80, 0xBF];
        const MAX_LEN: usize = 4;

        let mut all: Vec<Vec<u8>> = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..MAX_LEN {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &symbol in ALPHABET {
                    let mut candidate: Vec<u8> = prefix.clone();
                    candidate.push(symbol);
                    next.push(candidate);
                }
            }
            all.extend(next.iter().cloned());
            frontier = next;
        }
        assert_eq!(all.len(), 341, "enumeration size changed; recount");

        for value in &all {
            for max_size in 0usize..=5 {
                let (start, end) = extract_tail(value, max_size);
                assert_eq!(
                    start,
                    spec_extract_tail_start(value, max_size),
                    "PARITY-HAND-1: extract_tail start disagrees for {value:?} max={max_size}"
                );
                assert_eq!(
                    end,
                    value.len(),
                    "PARITY-HAND-1: extract_tail end must always be the input length"
                );
            }
        }
    }

    #[test]
    fn test_can_track_field_matches_verus_spec_at_boundaries() {
        let values = [0usize, 1, 2, 16, usize::MAX - 1, usize::MAX];
        for &current_fields in &values {
            for &max_fields in &values {
                for &current_bytes in &values {
                    for &new_buffer_bytes in &values {
                        for &max_total_bytes in &values {
                            assert_eq!(
                                can_track_field(
                                    current_fields,
                                    max_fields,
                                    current_bytes,
                                    new_buffer_bytes,
                                    max_total_bytes
                                ),
                                spec_can_track_field(
                                    current_fields,
                                    max_fields,
                                    current_bytes,
                                    new_buffer_bytes,
                                    max_total_bytes
                                ),
                                "PARITY-HAND-1: can_track_field disagrees at \
                                 ({current_fields}, {max_fields}, {current_bytes}, \
                                 {new_buffer_bytes}, {max_total_bytes})"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Continuation bytes are not boundaries; everything else is.
        assert!(!spec_is_char_boundary(0x80));
        assert!(!spec_is_char_boundary(0xBF));
        assert!(spec_is_char_boundary(0x41));
        assert!(spec_is_char_boundary(0xC3));
        // A byte budget that would overflow must fail closed, not wrap.
        assert!(!spec_can_track_field(0, 1, usize::MAX, 1, usize::MAX));
        assert!(spec_can_track_field(0, 1, 1, 1, 2));
        // At the field cap nothing more is tracked.
        assert!(!spec_can_track_field(1, 1, 0, 0, 0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === D1: UTF-8 character boundary safety ===

    #[test]
    fn test_d1_ascii_all_boundaries() {
        // All ASCII bytes are char boundaries
        for b in 0..128u8 {
            assert!(
                is_utf8_char_boundary(b),
                "ASCII byte {b:#04x} should be a char boundary"
            );
        }
    }

    #[test]
    fn test_d1_continuation_bytes_not_boundaries() {
        // Continuation bytes (10xxxxxx) are NOT char boundaries
        for b in 0x80..=0xBFu8 {
            assert!(
                !is_utf8_char_boundary(b),
                "Continuation byte {b:#04x} should NOT be a char boundary"
            );
        }
    }

    #[test]
    fn test_d1_leading_bytes_are_boundaries() {
        // 2-byte leading (110xxxxx): 0xC0-0xDF
        for b in 0xC0..=0xDFu8 {
            assert!(
                is_utf8_char_boundary(b),
                "2-byte leading {b:#04x} should be a char boundary"
            );
        }
        // 3-byte leading (1110xxxx): 0xE0-0xEF
        for b in 0xE0..=0xEFu8 {
            assert!(
                is_utf8_char_boundary(b),
                "3-byte leading {b:#04x} should be a char boundary"
            );
        }
        // 4-byte leading (11110xxx): 0xF0-0xF7
        for b in 0xF0..=0xF7u8 {
            assert!(
                is_utf8_char_boundary(b),
                "4-byte leading {b:#04x} should be a char boundary"
            );
        }
    }

    #[test]
    fn test_d1_extract_tail_lands_on_boundary() {
        // "日本語" = [E6 97 A5] [E6 9C AC] [E8 AA 9E] — 9 bytes, 3 chars
        let value = "日本語".as_bytes();
        assert_eq!(value.len(), 9);

        // max_size=5 → raw_start=4, but byte 4 is 0x9C (continuation)
        // Should advance to byte 6 (0xE8, start of '語')
        let (start, end) = extract_tail(value, 5);
        assert_eq!(end, 9);
        assert!(
            is_utf8_char_boundary(value[start]),
            "start={start} should be a char boundary"
        );
        // The tail should be valid UTF-8
        assert!(std::str::from_utf8(&value[start..end]).is_ok());
    }

    #[test]
    fn test_d1_extract_tail_4byte_emoji() {
        // "A😀B" = [41] [F0 9F 98 80] [42] — 6 bytes
        let value = "A😀B".as_bytes();
        assert_eq!(value.len(), 6);

        // max_size=4 → raw_start=2, byte 2 is 0x9F (continuation of emoji)
        // Should advance past 0x9F, 0x98, 0x80 to byte 5 (0x42 = 'B')
        let (start, end) = extract_tail(value, 4);
        assert!(
            is_utf8_char_boundary(value[start]),
            "start={start} should be a char boundary, got byte {:#04x}",
            value[start]
        );
        assert!(std::str::from_utf8(&value[start..end]).is_ok());
    }

    // === D2: Single buffer size bounded ===

    #[test]
    fn test_d2_tail_never_exceeds_max_size() {
        let value = b"Hello, this is a long string for testing buffer extraction limits";
        for max_size in 1..=value.len() + 5 {
            let (start, end) = extract_tail(value, max_size);
            let tail_len = end - start;
            assert!(
                tail_len <= max_size,
                "max_size={max_size}, tail_len={tail_len}"
            );
        }
    }

    #[test]
    fn test_d2_empty_value() {
        let (start, end) = extract_tail(b"", 100);
        assert_eq!(start, 0);
        assert_eq!(end, 0);
    }

    #[test]
    fn test_d2_zero_max_size() {
        let (start, end) = extract_tail(b"hello", 0);
        assert_eq!(start, 5);
        assert_eq!(end, 5);
    }

    #[test]
    fn test_d2_value_shorter_than_max() {
        let value = b"short";
        let (start, end) = extract_tail(value, 100);
        assert_eq!(start, 0);
        assert_eq!(end, 5);
    }

    // === D3: Total byte accounting correct ===

    #[test]
    fn test_d3_normal_accounting() {
        // Old total 100, replace 30-byte buffer with 50-byte buffer
        assert_eq!(update_total_bytes(100, 30, 50), 120);
    }

    #[test]
    fn test_d3_remove_buffer() {
        // Old total 100, remove 30-byte buffer, add nothing
        assert_eq!(update_total_bytes(100, 30, 0), 70);
    }

    #[test]
    fn test_d3_add_first_buffer() {
        // No previous buffer (old_total=0, old_buffer_len=0)
        assert_eq!(update_total_bytes(0, 0, 50), 50);
    }

    // === D4: Capacity check fail-closed ===

    #[test]
    fn test_d4_at_max_fields_rejects() {
        assert!(!can_track_field(256, 256, 0, 100, 100_000));
    }

    #[test]
    fn test_d4_above_max_fields_rejects() {
        assert!(!can_track_field(300, 256, 0, 100, 100_000));
    }

    #[test]
    fn test_d4_below_max_fields_accepts() {
        assert!(can_track_field(255, 256, 0, 100, 100_000));
    }

    #[test]
    fn test_d4_byte_overflow_rejects() {
        assert!(!can_track_field(0, 256, usize::MAX, 1, usize::MAX));
    }

    #[test]
    fn test_d4_byte_limit_rejects() {
        assert!(!can_track_field(0, 256, 38_000, 500, 38_400));
    }

    #[test]
    fn test_d4_byte_limit_exact_accepts() {
        assert!(can_track_field(0, 256, 38_000, 400, 38_400));
    }

    // === D5: No arithmetic underflow ===

    #[test]
    fn test_d5_saturating_sub_prevents_underflow() {
        // Inconsistent state: old_total < old_buffer_len
        let result = update_total_bytes(10, 50, 30);
        assert_eq!(result, 30); // saturating_sub(10, 50) = 0, + 30 = 30
    }

    #[test]
    fn test_d5_zero_old_total() {
        let result = update_total_bytes(0, 100, 50);
        assert_eq!(result, 50); // 0.saturating_sub(100) = 0, + 50 = 50
    }

    #[test]
    fn test_d5_max_values() {
        let result = update_total_bytes(usize::MAX, 0, 0);
        assert_eq!(result, usize::MAX);
    }

    #[test]
    fn test_d5_saturating_add_near_max() {
        let result = update_total_bytes(usize::MAX, 0, 1);
        assert_eq!(result, usize::MAX); // saturating_add caps at MAX
    }

    // === D6: Overlap completeness ===

    #[test]
    fn test_d6_secret_fully_in_overlap() {
        // Secret of 20 bytes, overlap_size 150, split at byte 10
        assert!(overlap_covers_secret(100, 100, 150, 20, 10));
    }

    #[test]
    fn test_d6_secret_split_at_start() {
        // Split at byte 1 (almost all in current value)
        assert!(overlap_covers_secret(100, 100, 150, 20, 1));
    }

    #[test]
    fn test_d6_secret_split_at_end() {
        // Split at byte 19 (almost all in previous value)
        assert!(overlap_covers_secret(100, 100, 150, 20, 19));
    }

    #[test]
    fn test_d6_secret_equals_2x_overlap() {
        // Boundary case: secret exactly 2 * overlap_size
        assert!(overlap_covers_secret(300, 300, 150, 300, 150));
    }

    #[test]
    fn test_d6_not_split_returns_false() {
        // split_point=0 means not actually split
        assert!(!overlap_covers_secret(100, 100, 150, 20, 0));
    }

    #[test]
    fn test_d6_prev_too_short() {
        // Previous value shorter than split_point
        assert!(!overlap_covers_secret(5, 100, 150, 20, 10));
    }

    #[test]
    fn test_d6_current_too_short() {
        // Current value shorter than remaining secret
        assert!(!overlap_covers_secret(100, 5, 150, 20, 10));
    }

    #[test]
    fn test_d6_split_beyond_overlap_returns_false() {
        // The first fragment cannot fit in the retained overlap tail.
        assert!(!overlap_covers_secret(100, 100, 32, 40, 33));
    }

    #[test]
    fn test_d6_overlap_region_size() {
        assert_eq!(compute_overlap_region_size(150, 1000), 1150);
        assert_eq!(compute_overlap_region_size(0, 1000), 1000);
        assert_eq!(compute_overlap_region_size(150, 0), 150);
    }

    #[test]
    fn test_d6_overlap_region_saturating() {
        // No overflow
        assert_eq!(compute_overlap_region_size(usize::MAX, 1), usize::MAX);
    }

    // === Exhaustive property: D6 for all splits of small secrets ===

    #[test]
    fn test_d6_exhaustive_small_secrets() {
        let overlap_size = 32;
        let max_pattern = 2 * overlap_size;
        let prev_len = 100;
        let curr_len = 100;

        for pattern_len in 2..=max_pattern {
            for split_point in 1..pattern_len {
                let expected = split_point <= overlap_size;
                assert_eq!(
                    overlap_covers_secret(
                        prev_len,
                        curr_len,
                        overlap_size,
                        pattern_len,
                        split_point
                    ),
                    expected,
                    "Failed for pattern_len={pattern_len}, split_point={split_point}"
                );
            }
        }
    }
}
