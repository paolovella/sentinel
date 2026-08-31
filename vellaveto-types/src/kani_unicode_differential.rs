// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Differential binding for `PARITY-HAND-2` — homoglyph normalization.
//!
//! `formal/kani/src/unicode.rs` says its `normalize_confusable_char` is
//! "verbatim from `vellaveto-types/src/unicode.rs:50-188`" and proves K64
//! (idempotence) and K65 (mapped confusables collapse to ASCII) on top of it.
//! Nothing checked the "verbatim" part.
//!
//! Production inlines the mapping inside `normalize_homoglyphs`; the extraction
//! factored it into a `char -> char` function. So the comparison is made at the
//! string level, which is equivalent because production maps each character
//! independently — and it is made over **every Unicode scalar value**, so the
//! mapping is discharged totally rather than sampled.
//!
//! What rides on it: `normalize_homoglyphs` feeds `normalize_full`, which
//! decides policy matching and cache keys. A confusable production folds and
//! the model does not (or the reverse) means K64/K65 describe a different
//! normalizer than the one deciding whether `аdmin` (Cyrillic а) is `admin`.

#[cfg(test)]
// Suppressed rather than satisfied: linting the extraction would edit the copy
// the Kani proofs run against.
#[allow(clippy::manual_range_contains, dead_code, unused_imports)]
mod extracted {
    include!(concat!(env!("OUT_DIR"), "/kani_unicode_extraction.rs"));
}

#[cfg(test)]
mod kani_parity_differential_unicode {
    use super::extracted;
    use crate::unicode::normalize_homoglyphs;

    /// Every Unicode scalar value: `0..=0x10FFFF` minus the surrogate range.
    fn all_scalars() -> Vec<char> {
        (0u32..=0x10FFFF)
            .filter(|cp| !(0xD800..=0xDFFF).contains(cp))
            .filter_map(char::from_u32)
            .collect()
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/unicode.rs was not found, so this binding compared nothing"
        );
    }

    /// TOTAL over the entire Unicode scalar range.
    ///
    /// Compared in chunks for speed — production maps characters independently,
    /// so a chunk comparison is equivalent to a per-character one — and any
    /// mismatching chunk is then re-walked character by character to name the
    /// exact scalar that diverges.
    #[test]
    fn test_homoglyph_mapping_matches_production_over_every_unicode_scalar() {
        let scalars = all_scalars();
        assert_eq!(
            scalars.len(),
            0x110000 - 0x800,
            "the scalar enumeration changed; recount before trusting this result"
        );

        for chunk in scalars.chunks(2048) {
            let input: String = chunk.iter().collect();
            let production = normalize_homoglyphs(&input);
            let model = extracted::normalize_homoglyphs(&input);
            if production == model {
                continue;
            }
            // Locate the divergence rather than dumping two 2048-char strings.
            for &c in chunk {
                let one = c.to_string();
                let p = normalize_homoglyphs(&one);
                let m = extracted::normalize_homoglyphs(&one);
                assert_eq!(
                    p, m,
                    "PARITY-HAND-2: production and the Kani model normalize U+{:04X} \
                     differently (production {p:?}, model {m:?}) — K64/K65 are about \
                     a normalizer that is not the one deciding whether a confusable \
                     name matches a real one",
                    c as u32
                );
            }
            panic!(
                "PARITY-HAND-2: a chunk differed but no single character did; the two \
                 implementations are not mapping characters independently"
            );
        }
    }

    /// K64 restated against production: normalization is idempotent.
    ///
    /// If it were not, `normalize_full` would not be a fixed point and the same
    /// name could normalize to two different cache keys depending on how many
    /// times it had been through.
    #[test]
    fn test_production_normalization_is_idempotent_as_k64_claims() {
        for chunk in all_scalars().chunks(4096) {
            let input: String = chunk.iter().collect();
            let once = normalize_homoglyphs(&input);
            let twice = normalize_homoglyphs(&once);
            assert_eq!(
                once, twice,
                "K64 does not hold for production: normalizing twice differs from once"
            );
        }
    }

    /// K65 restated against production: everything the model calls a mapped
    /// confusable collapses to ASCII in production too.
    #[test]
    fn test_mapped_confusables_collapse_to_ascii_as_k65_claims() {
        let mut mapped = 0usize;
        for c in all_scalars() {
            if !extracted::is_mapped_confusable(c) {
                continue;
            }
            mapped += 1;
            let normalized = normalize_homoglyphs(&c.to_string());
            assert!(
                normalized.is_ascii(),
                "K65 violated in production: U+{:04X} is a mapped confusable but \
                 normalizes to {normalized:?}, which is not ASCII",
                c as u32
            );
        }
        assert!(
            mapped > 50,
            "only {mapped} confusables are mapped; the table has shrunk and K65 \
             covers far less than it appears to"
        );
    }

    /// The attacks this table exists to stop, stated as behaviour rather than
    /// as a character table.
    #[test]
    fn test_known_homoglyph_attacks_normalize_to_their_ascii_targets() {
        const ATTACKS: &[(&str, &str, &str)] = &[
            ("\u{0430}dmin", "admin", "Cyrillic а"),
            ("\u{0435}xecute", "execute", "Cyrillic е"),
            ("\u{03BF}wner", "owner", "Greek omicron"),
            ("\u{FF41}dmin", "admin", "fullwidth a"),
        ];
        for (attack, target, label) in ATTACKS {
            assert_eq!(
                normalize_homoglyphs(attack),
                *target,
                "{label}: {attack:?} does not normalize to {target:?}, so a \
                 confusable identity would not be caught"
            );
            assert_eq!(
                extracted::normalize_homoglyphs(attack),
                *target,
                "{label}: the Kani model disagrees, so its proofs do not cover this"
            );
        }
    }

    /// The sweep must find real mappings, or agreement is vacuous: two
    /// identity functions agree everywhere.
    #[test]
    fn test_sweep_finds_characters_that_actually_change() {
        let changed = all_scalars()
            .into_iter()
            .filter(|c| {
                let s = c.to_string();
                normalize_homoglyphs(&s) != s
            })
            .count();
        assert!(
            changed > 50,
            "only {changed} scalars change under normalization; the comparison \
             cannot distinguish this from an identity function"
        );
    }
}
