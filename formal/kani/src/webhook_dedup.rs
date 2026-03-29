// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Webhook deduplication verification extracted from
//! `vellaveto-server/src/routes/billing.rs:68-112`.
//!
//! # Verified Properties (K138-K139)
//!
//! | ID   | Property |
//! |------|----------|
//! | K138 | check_or_insert returns false on second call with same ID |
//! | K139 | Empty/oversized/dangerous event IDs rejected |

const MAX_EVENT_ID_LEN: usize = 512;

/// Input validation for webhook event IDs.
/// Returns true if the event ID is valid, false if malformed.
pub fn event_id_valid(len: usize, is_empty: bool, has_dangerous_chars: bool) -> bool {
    !is_empty && len <= MAX_EVENT_ID_LEN && !has_dangerous_chars
}

/// Dedup check: returns false (duplicate) if the event was already
/// seen within the TTL window.
pub fn is_duplicate(already_seen: bool, within_ttl: bool) -> bool {
    already_seen && within_ttl
}

/// Combined check_or_insert logic: returns true (first occurrence)
/// only if the event ID is valid AND not a duplicate.
pub fn check_or_insert_result(
    id_valid: bool,
    already_seen: bool,
    within_ttl: bool,
) -> bool {
    if !id_valid {
        return false; // Malformed → treated as duplicate
    }
    !is_duplicate(already_seen, within_ttl)
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn k138_second_call_returns_false() {
        let id_valid = true;
        let already_seen = true;
        let within_ttl = true;
        let result = check_or_insert_result(id_valid, already_seen, within_ttl);
        assert!(!result, "K138: duplicate within TTL must return false");
    }

    #[kani::proof]
    fn k139_empty_id_rejected() {
        let result = event_id_valid(0, true, false);
        assert!(!result, "K139: empty event ID must be rejected");
    }

    #[kani::proof]
    fn k139_oversized_id_rejected() {
        let len: usize = kani::any();
        kani::assume(len > MAX_EVENT_ID_LEN);
        let result = event_id_valid(len, false, false);
        assert!(!result, "K139: oversized event ID must be rejected");
    }

    #[kani::proof]
    fn k139_dangerous_chars_rejected() {
        let result = event_id_valid(10, false, true);
        assert!(
            !result,
            "K139: event ID with dangerous chars must be rejected"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_event_id() {
        assert!(event_id_valid(36, false, false));
    }

    #[test]
    fn test_empty_event_id_rejected() {
        assert!(!event_id_valid(0, true, false));
    }

    #[test]
    fn test_oversized_event_id_rejected() {
        assert!(!event_id_valid(513, false, false));
    }

    #[test]
    fn test_dangerous_chars_rejected() {
        assert!(!event_id_valid(10, false, true));
    }

    #[test]
    fn test_duplicate_within_ttl_returns_false() {
        assert!(!check_or_insert_result(true, true, true));
    }

    #[test]
    fn test_first_occurrence_returns_true() {
        assert!(check_or_insert_result(true, false, false));
    }

    #[test]
    fn test_expired_duplicate_returns_true() {
        assert!(check_or_insert_result(true, true, false));
    }

    #[test]
    fn test_invalid_id_returns_false() {
        assert!(!check_or_insert_result(false, false, false));
    }
}
