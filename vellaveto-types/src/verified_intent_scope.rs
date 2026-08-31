// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Intent scope as a bitmask over sink classes.
//!
//! This is the production counterpart of
//! `formal/verus/verified_intent_scope.rs`. The kernel models scope as a
//! bitmask and proves that restriction is intersection, that intersection can
//! only narrow, that a locked scope cannot expand, and that the lock is
//! irreversible. Production previously modelled scope as
//! `Vec<SinkClass>` with the convention *empty means everything is allowed* —
//! under which intersection is **not** narrowing, because filtering an empty
//! list yields an empty list and therefore still allows everything.
//!
//! `ScopeMask` exists so the proved property is the one that runs. Once a
//! scope is materialised into a mask, "allow nothing" and "allow everything"
//! are distinct values (`NONE` and `ALL`), and `restrict` is a plain bitwise
//! AND that always produces a subset.
//!
//! Width: `SinkClass` has nine variants, so the mask is `u16`. The kernel's
//! original `u8` could not represent rank 8 (`PolicyMutation`, the
//! highest-privilege sink) at all — the same root cause as `TAINT-MODEL-DRIFT`,
//! recorded in `formal/ASSUMPTION_REGISTRY.md`.

use serde::{Deserialize, Serialize};

use crate::provenance::SinkClass;

/// Number of `SinkClass` variants, and therefore of meaningful mask bits.
///
/// Kept in step with `SinkClass::rank()`, whose highest rank is 8.
pub const SCOPE_CLASS_COUNT: u8 = 9;

/// Every meaningful bit set: ranks 0 through 8.
const ALL_BITS: u16 = (1u16 << SCOPE_CLASS_COUNT) - 1;

/// A set of permitted sink classes, one bit per `SinkClass::rank()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScopeMask(u16);

impl Default for ScopeMask {
    /// Fail-closed: the default scope permits nothing.
    ///
    /// Callers that mean "unrestricted" must say so with [`ScopeMask::ALL`].
    fn default() -> Self {
        Self::NONE
    }
}

impl ScopeMask {
    /// Permits every sink class.
    pub const ALL: Self = Self(ALL_BITS);

    /// Permits no sink class.
    pub const NONE: Self = Self(0);

    /// Build a mask from an explicit set of sink classes.
    #[must_use]
    pub fn from_sink_classes(classes: &[SinkClass]) -> Self {
        let mut bits = 0u16;
        for class in classes {
            bits |= 1u16 << class.rank();
        }
        Self(bits)
    }

    /// Build a mask from the config surface, where an empty list has
    /// historically meant "no restriction expressed".
    ///
    /// This is the single point where that convention is converted into an
    /// explicit value. Everything downstream works on the mask, where
    /// "everything" and "nothing" are different values and intersection is
    /// therefore genuinely narrowing.
    #[must_use]
    pub fn from_config_sink_classes(classes: &[SinkClass]) -> Self {
        if classes.is_empty() {
            Self::ALL
        } else {
            Self::from_sink_classes(classes)
        }
    }

    /// The raw bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Reject masks carrying bits above the highest `SinkClass` rank.
    ///
    /// A bit with no sink class behind it can never be matched, so its
    /// presence means the mask was built from something other than
    /// `SinkClass::rank()` — deserialised input, most likely.
    pub fn validate(&self) -> Result<(), String> {
        if self.0 & !ALL_BITS != 0 {
            return Err(format!(
                "scope mask carries bits above sink-class rank {}: {:#06x}",
                SCOPE_CLASS_COUNT - 1,
                self.0
            ));
        }
        Ok(())
    }

    /// Whether the sink class at `rank` is permitted.
    ///
    /// Production counterpart of `spec_in_scope`. Out-of-range ranks are not
    /// in scope, which is the fail-closed direction.
    #[inline]
    #[must_use = "security decisions must not be discarded"]
    pub const fn contains_rank(self, rank: u8) -> bool {
        rank < SCOPE_CLASS_COUNT && (self.0 >> rank) & 1 == 1
    }

    /// Whether `class` is permitted.
    #[inline]
    #[must_use = "security decisions must not be discarded"]
    pub const fn contains(self, class: SinkClass) -> bool {
        self.contains_rank(class.rank())
    }

    /// Narrow this scope by intersecting it with `restriction`.
    ///
    /// Production counterpart of `spec_restrict_scope`. The result is always a
    /// subset of `self` — that is the property the kernel proves, and with a
    /// mask it holds by construction.
    #[inline]
    #[must_use = "restriction produces a new scope; the original is unchanged"]
    pub const fn restrict(self, restriction: Self) -> Self {
        Self(self.0 & restriction.0)
    }

    /// Whether every class this mask permits is also permitted by `other`.
    ///
    /// Production counterpart of `spec_is_subset_mask`.
    #[inline]
    #[must_use = "security decisions must not be discarded"]
    pub const fn is_subset_of(self, other: Self) -> bool {
        (self.0 & other.0) == self.0
    }

    /// Attempt to widen the scope to admit `rank`.
    ///
    /// Production counterpart of `attempt_scope_expansion`: when `locked`, the
    /// scope is returned unchanged, so a locked scope can never widen. An
    /// out-of-range rank is also a no-op rather than a silent bit set beyond
    /// the sink-class range.
    #[inline]
    #[must_use = "expansion produces a new scope; the original is unchanged"]
    pub const fn expand_rank(self, rank: u8, locked: bool) -> Self {
        if locked || rank >= SCOPE_CLASS_COUNT {
            self
        } else {
            Self(self.0 | (1u16 << rank))
        }
    }
}

/// Whether another distinct tool may still be used this session.
///
/// Production counterpart of `check_tool_budget`.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn tool_budget_available(distinct_tools: u32, max_distinct_tools: u32) -> bool {
    distinct_tools < max_distinct_tools
}

/// The next value of the scope lock.
///
/// Production counterpart of `spec_lock_irreversible`. Expressed as a
/// transition rather than a check so irreversibility holds by construction:
/// there is no input to this function that turns a locked scope back on.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn next_locked(locked_before: bool, lock_event: bool) -> bool {
    locked_before || lock_event
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`), kernel
    //! `formal/verus/verified_intent_scope.rs`.
    //!
    //! This kernel was one of the two recorded under `MODEL-SHAPE-1/2`: it
    //! modelled a bitmask scope that production did not have, so
    //! `check-verus-parity.sh` paired it by symbol name against a file whose
    //! structure was unrelated. The mask is now the production representation,
    //! so the specs have counterparts to compare against.
    //!
    //! Two things changed on the kernel side, both recorded in the registry:
    //! the mask widened from `u8` to `u16` because `SinkClass` has nine
    //! variants and rank 8 was unrepresentable, and the production correspondence
    //! block now names files that exist.

    use super::*;

    /// Transcription of `spec_in_scope`.
    fn spec_in_scope(allowed_mask: u16, sink_bit: u8) -> bool {
        sink_bit < SCOPE_CLASS_COUNT && (allowed_mask >> sink_bit) & 1u16 == 1u16
    }

    /// Transcription of `spec_restrict_scope`.
    fn spec_restrict_scope(current_mask: u16, restriction_mask: u16) -> u16 {
        current_mask & restriction_mask
    }

    /// Transcription of `spec_is_subset_mask`.
    fn spec_is_subset_mask(restricted: u16, original: u16) -> bool {
        (restricted & original) == restricted
    }

    /// Transcription of `attempt_scope_expansion`'s two ensures clauses.
    fn spec_attempt_scope_expansion(allowed_mask: u16, locked: bool, new_sink_bit: u8) -> u16 {
        if locked {
            allowed_mask
        } else {
            allowed_mask | (1u16 << new_sink_bit)
        }
    }

    /// Transcription of `check_tool_budget`.
    fn spec_check_tool_budget(distinct_tools: u32, max_distinct_tools: u32) -> bool {
        distinct_tools < max_distinct_tools
    }

    /// Transcription of `spec_lock_irreversible`, as a transition.
    fn spec_next_locked(locked_before: bool, lock_event: bool) -> bool {
        locked_before || lock_event
    }

    /// Every mask the nine sink classes can produce.
    fn all_valid_masks() -> Vec<u16> {
        (0u16..(1u16 << SCOPE_CLASS_COUNT)).collect()
    }

    /// TOTAL over every valid mask crossed with every rank up to and past the
    /// sink-class range, plus masks carrying bits *above* the range.
    ///
    /// The out-of-range masks are the ones that make this test bite. For a
    /// valid mask the range check in `contains_rank` is redundant — bits above
    /// rank 8 are already zero — so removing it is an equivalent mutation and
    /// the enumeration would not notice. A mask that arrived from
    /// deserialization before `validate()` ran is the case where the check is
    /// load-bearing, and where dropping it would put a rank with no sink class
    /// behind it "in scope".
    #[test]
    fn test_contains_rank_matches_verus_spec_total_domain() {
        let mut masks = all_valid_masks();
        // Every single high bit, plus the all-ones mask.
        for bit in SCOPE_CLASS_COUNT..16 {
            masks.push(1u16 << bit);
            masks.push((1u16 << bit) | 0b1_0101_0101);
        }
        masks.push(u16::MAX);

        let mut checked = 0usize;
        for bits in &masks {
            let mask = ScopeMask(*bits);
            for rank in 0u8..16 {
                assert_eq!(
                    mask.contains_rank(rank),
                    spec_in_scope(*bits, rank),
                    "PARITY-HAND-1: in-scope disagrees for mask {bits:#06x} rank {rank}"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, masks.len() * 16, "enumeration collapsed");
        assert_eq!(
            masks.len(),
            512 + 14 + 1,
            "mask set changed; recount before trusting"
        );
    }

    /// No rank at or above the sink-class count is ever in scope, whatever the
    /// mask says. Fail-closed on a mask that has not been validated.
    #[test]
    fn test_no_rank_beyond_the_sink_class_range_is_ever_in_scope() {
        for rank in SCOPE_CLASS_COUNT..=15 {
            assert!(
                !ScopeMask(u16::MAX).contains_rank(rank),
                "rank {rank} has no sink class behind it but was in scope"
            );
        }
    }

    /// TOTAL over every ordered pair of valid masks: restriction is
    /// intersection, and the result is always a subset. SCOPE-1 and SCOPE-2.
    #[test]
    fn test_restrict_matches_verus_spec_and_always_narrows() {
        let masks = all_valid_masks();
        let mut checked = 0usize;
        for &current in &masks {
            for &restriction in &masks {
                let got = ScopeMask(current).restrict(ScopeMask(restriction));
                assert_eq!(
                    got.bits(),
                    spec_restrict_scope(current, restriction),
                    "PARITY-HAND-1: restriction disagrees for {current:#06x} & {restriction:#06x}"
                );
                assert!(
                    spec_is_subset_mask(got.bits(), current),
                    "SCOPE-1: restricting {current:#06x} by {restriction:#06x} widened it"
                );
                assert!(
                    got.is_subset_of(ScopeMask(current)),
                    "PARITY-HAND-1: is_subset_of disagrees with the spec"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 512 * 512, "enumeration collapsed");
    }

    /// SCOPE-2 as the kernel states it: two restrictions in sequence stay
    /// subsets of the first result and of the original.
    #[test]
    fn test_two_restrictions_narrow_monotonically() {
        let masks: Vec<u16> = (0u16..(1u16 << SCOPE_CLASS_COUNT)).step_by(7).collect();
        for &initial in &masks {
            for &r1 in &masks {
                for &r2 in &masks {
                    let after1 = ScopeMask(initial).restrict(ScopeMask(r1));
                    let after2 = after1.restrict(ScopeMask(r2));
                    assert!(after1.is_subset_of(ScopeMask(initial)));
                    assert!(after2.is_subset_of(after1));
                }
            }
        }
    }

    /// SCOPE-3: a locked scope never widens. TOTAL over every valid mask,
    /// every in-range rank, and both lock states.
    #[test]
    fn test_expansion_matches_verus_spec_and_locking_blocks_it() {
        for bits in all_valid_masks() {
            for rank in 0u8..SCOPE_CLASS_COUNT {
                for locked in [false, true] {
                    assert_eq!(
                        ScopeMask(bits).expand_rank(rank, locked).bits(),
                        spec_attempt_scope_expansion(bits, locked, rank),
                        "PARITY-HAND-1: expansion disagrees for {bits:#06x} rank {rank} \
                         locked={locked}"
                    );
                }
                assert_eq!(
                    ScopeMask(bits).expand_rank(rank, true),
                    ScopeMask(bits),
                    "SCOPE-3: a locked scope changed"
                );
            }
        }
    }

    /// The kernel requires `new_sink_bit < SCOPE_CLASS_COUNT`. Production has
    /// no such precondition to lean on, so an out-of-range rank must be a
    /// no-op rather than setting a bit no sink class can ever match.
    #[test]
    fn test_out_of_range_expansion_is_a_noop() {
        for rank in SCOPE_CLASS_COUNT..=u8::MAX {
            assert_eq!(
                ScopeMask::NONE.expand_rank(rank, false),
                ScopeMask::NONE,
                "an out-of-range rank {rank} set a bit"
            );
        }
    }

    /// SCOPE-4.
    #[test]
    fn test_tool_budget_matches_verus_spec() {
        for distinct in 0u32..24 {
            for max in 0u32..24 {
                assert_eq!(
                    tool_budget_available(distinct, max),
                    spec_check_tool_budget(distinct, max),
                    "PARITY-HAND-1: tool budget disagrees at ({distinct}, {max})"
                );
            }
        }
    }

    /// SCOPE-5, TOTAL over 2².
    #[test]
    fn test_lock_transition_matches_verus_spec_and_is_irreversible() {
        for before in [false, true] {
            for event in [false, true] {
                assert_eq!(next_locked(before, event), spec_next_locked(before, event));
                if before {
                    assert!(
                        next_locked(before, event),
                        "SCOPE-5: a locked scope unlocked"
                    );
                }
            }
        }
    }

    /// The width fix. An 8-bit mask cannot hold rank 8, so the kernel it came
    /// from could not talk about `PolicyMutation` at all.
    #[test]
    fn test_mask_covers_every_sink_class_rank() {
        assert_eq!(SinkClass::PolicyMutation.rank(), SCOPE_CLASS_COUNT - 1);
        assert!(
            ScopeMask::ALL.contains(SinkClass::PolicyMutation),
            "the full mask must admit the highest-privilege sink"
        );
        assert!(
            !ScopeMask::NONE.contains(SinkClass::PolicyMutation),
            "the empty mask must admit nothing"
        );
        assert!(
            ScopeMask::ALL.bits() > u16::from(u8::MAX),
            "a u8 mask cannot represent rank 8"
        );
    }

    /// The config-surface convention is converted exactly once, here.
    #[test]
    fn test_empty_config_list_means_unrestricted_and_explicit_empty_means_nothing() {
        assert_eq!(ScopeMask::from_config_sink_classes(&[]), ScopeMask::ALL);
        assert_eq!(ScopeMask::from_sink_classes(&[]), ScopeMask::NONE);
        assert_eq!(
            ScopeMask::default(),
            ScopeMask::NONE,
            "default must be fail-closed"
        );
    }

    #[test]
    fn test_validate_rejects_bits_above_the_sink_class_range() {
        assert!(ScopeMask::ALL.validate().is_ok());
        assert!(ScopeMask(1u16 << SCOPE_CLASS_COUNT).validate().is_err());
        assert!(ScopeMask(u16::MAX).validate().is_err());
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Out-of-range bits are never in scope.
        assert!(!spec_in_scope(u16::MAX, SCOPE_CLASS_COUNT));
        assert!(spec_in_scope(1u16 << 8, 8));
        // Intersection is not union.
        assert_eq!(spec_restrict_scope(0b0101, 0b0011), 0b0001);
        assert_ne!(spec_restrict_scope(0b0101, 0b0011), 0b0111);
        // Subset is directional.
        assert!(spec_is_subset_mask(0b0001, 0b0011));
        assert!(!spec_is_subset_mask(0b0011, 0b0001));
    }
}
