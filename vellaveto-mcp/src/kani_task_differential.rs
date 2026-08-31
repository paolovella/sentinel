// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Differential binding for `PARITY-HAND-2` — MCP task lifecycle.
//!
//! `formal/kani/src/task.rs` reduces the task tracker to four predicates and
//! proves K56 (terminal states admit no further transition), K57 (registration
//! is rejected at capacity) and K58 (self-cancel rejects a different requester).
//!
//! Following the lesson from `credential_vault`, the state predicates are
//! compared over their **whole domain** — `is_terminal` across all six states,
//! `can_transition` across all thirty-six ordered pairs — rather than over a
//! sample. `can_cancel` is compared over its total boolean/option domain and
//! then driven through the real `TaskStateManager`.

#[cfg(test)]
// Suppressed rather than satisfied: linting the extraction would edit the copy
// the Kani proofs run against.
#[allow(clippy::manual_range_contains, dead_code, unused_imports)]
mod extracted {
    include!(concat!(env!("OUT_DIR"), "/kani_task_extraction.rs"));
}

#[cfg(test)]
mod kani_parity_differential_task {
    use super::extracted;
    use vellaveto_types::task::{TaskStatus, TrackedTask};

    const MODEL_STATES: [extracted::TaskState; 6] = [
        extracted::TaskState::Pending,
        extracted::TaskState::Running,
        extracted::TaskState::Completed,
        extracted::TaskState::Failed,
        extracted::TaskState::Cancelled,
        extracted::TaskState::Expired,
    ];

    fn production_status(state: extracted::TaskState) -> TaskStatus {
        match state {
            extracted::TaskState::Pending => TaskStatus::Pending,
            extracted::TaskState::Running => TaskStatus::Running,
            extracted::TaskState::Completed => TaskStatus::Completed,
            extracted::TaskState::Failed => TaskStatus::Failed {
                reason: "test".to_string(),
            },
            extracted::TaskState::Cancelled => TaskStatus::Cancelled,
            extracted::TaskState::Expired => TaskStatus::Expired,
        }
    }

    fn task_in(state: extracted::TaskState, created_by: Option<&str>) -> TrackedTask {
        TrackedTask {
            task_id: "task-1".to_string(),
            tool: "tool".to_string(),
            function: "fn".to_string(),
            status: production_status(state),
            created_at: "2026-08-30T00:00:00Z".to_string(),
            expires_at: None,
            created_by: created_by.map(str::to_string),
            session_id: None,
        }
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/task.rs was not found, so this binding compared nothing"
        );
    }

    /// K56, TOTAL over all six states: the model and production must agree on
    /// which states are terminal. A state production calls terminal and the
    /// model does not would let the proof permit a transition production
    /// forbids (FIND-R60-004 enforces terminal immutability).
    #[test]
    fn test_is_terminal_matches_production_total_domain() {
        for state in MODEL_STATES {
            let task = task_in(state, None);
            assert_eq!(
                extracted::is_terminal(state),
                task.is_terminal(),
                "PARITY-HAND-2: model and production disagree on whether {state:?} \
                 is terminal"
            );
        }
        // And the set is what K56 names.
        assert!(!extracted::is_terminal(extracted::TaskState::Pending));
        assert!(!extracted::is_terminal(extracted::TaskState::Running));
        for terminal in [
            extracted::TaskState::Completed,
            extracted::TaskState::Failed,
            extracted::TaskState::Cancelled,
            extracted::TaskState::Expired,
        ] {
            assert!(
                extracted::is_terminal(terminal),
                "K56: {terminal:?} must be terminal"
            );
        }
    }

    /// K56 as a transition table: all 36 ordered pairs.
    #[test]
    fn test_transition_table_total() {
        let mut checked = 0usize;
        for from in MODEL_STATES {
            for to in MODEL_STATES {
                let allowed = extracted::can_transition(from, to);
                assert_eq!(
                    allowed,
                    !task_in(from, None).is_terminal(),
                    "K56: transition {from:?} -> {to:?} should be {} — a terminal \
                     task that accepts a transition can be un-cancelled or moved \
                     back to Running, which FIND-R60-004 forbids",
                    if task_in(from, None).is_terminal() {
                        "rejected"
                    } else {
                        "allowed"
                    }
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 36, "transition table collapsed");
    }

    /// K57: the capacity constant must be production's, pinned on both sides
    /// independently rather than compared to itself.
    #[test]
    fn test_capacity_bound_and_eviction_match_production() {
        assert_eq!(
            extracted::MAX_TRACKED_TASKS,
            100_000,
            "the model's task capacity bound moved"
        );

        // Below the bound: always admitted.
        assert!(extracted::check_capacity(0, 0));
        assert!(extracted::check_capacity(99_999, 0));
        // At the bound with nothing to evict: rejected. This is K57.
        assert!(!extracted::check_capacity(100_000, 0));
        // At the bound, but terminal tasks can be evicted first — production
        // evicts then re-checks, which is what the second branch models.
        assert!(extracted::check_capacity(100_000, 1));
        assert!(!extracted::check_capacity(200_000, 1));
        // Saturation rather than underflow when more terminals are reported
        // than tasks exist.
        assert!(extracted::check_capacity(100_000, usize::MAX));
    }

    /// K58, TOTAL over the model's domain: 2 x 3 x 3 x 2.
    #[test]
    fn test_cancel_authorization_total_domain() {
        const AGENTS: [Option<&str>; 3] = [None, Some("alice"), Some("bob")];
        let mut checked = 0usize;
        for require_self_cancel in [false, true] {
            for creator in AGENTS {
                for requester in AGENTS {
                    for in_allow_list in [false, true] {
                        let got = extracted::can_cancel(
                            require_self_cancel,
                            creator,
                            requester,
                            in_allow_list,
                        );
                        // The rule production implements, restated.
                        let expected = if require_self_cancel {
                            match (creator, requester) {
                                (Some(c), Some(r)) => c == r,
                                (None, _) => true,
                                (Some(_), None) => false,
                            }
                        } else {
                            requester.is_some() && in_allow_list
                        };
                        assert_eq!(
                            got, expected,
                            "K58: cancel authorization disagrees at \
                             (require_self_cancel={require_self_cancel}, \
                             creator={creator:?}, requester={requester:?}, \
                             in_allow_list={in_allow_list})"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 2 * 3 * 3 * 2, "enumeration collapsed");

        // K58 stated directly: self-cancel required, different requester, reject.
        assert!(!extracted::can_cancel(
            true,
            Some("alice"),
            Some("bob"),
            true
        ));
        assert!(extracted::can_cancel(
            true,
            Some("alice"),
            Some("alice"),
            false
        ));
    }

    /// The real tracker agrees on authorization — and enforces a guard the
    /// model does not have.
    ///
    /// Production refuses to cancel a task already in a terminal state before
    /// it considers authorization at all. The model's `can_cancel` takes no
    /// state parameter, so it cannot represent that. The direction is safe —
    /// production is stricter than the model, so nothing the proof permits is
    /// under-enforced — but it means K58 is about authorization only, and the
    /// terminal guard is outside its scope. Recorded rather than assumed.
    #[tokio::test]
    async fn test_real_tracker_agrees_and_adds_a_terminal_guard() {
        use crate::task_state::TaskStateManager;

        let tracker = TaskStateManager::new(0, 0);
        tracker
            .register_task(task_in(extracted::TaskState::Running, Some("alice")))
            .await
            .expect("register");

        assert!(
            tracker
                .can_cancel("task-1", Some("alice"))
                .await
                .expect("task exists"),
            "the creator must be able to cancel their own running task"
        );
        assert!(
            !tracker
                .can_cancel("task-1", Some("bob"))
                .await
                .expect("task exists"),
            "K58: a different requester must be rejected under require_self_cancel"
        );

        // The guard the model lacks: a terminal task is never cancellable,
        // whoever asks.
        let terminal_tracker = TaskStateManager::new(0, 0);
        terminal_tracker
            .register_task(task_in(extracted::TaskState::Cancelled, Some("alice")))
            .await
            .expect("register");
        assert!(
            !terminal_tracker
                .can_cancel("task-1", Some("alice"))
                .await
                .expect("task exists"),
            "production must refuse to cancel a terminal task even for its creator"
        );
        assert!(
            extracted::can_cancel(true, Some("alice"), Some("alice"), false),
            "the model has no terminal guard, so it still authorizes here — that \
             difference is the scope note above, not a disagreement about \
             authorization"
        );
    }
}
