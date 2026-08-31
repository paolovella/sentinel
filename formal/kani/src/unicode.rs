// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Unicode homoglyph normalization verification extracted from
//! `vellaveto-types/src/unicode.rs`.
//!
//! The production function `normalize_homoglyphs` maps cross-script
//! confusable characters (Cyrillic, Greek, Armenian, Cherokee, Fullwidth
//! Latin, and other Unicode homoglyphs) to their ASCII equivalents. This
//! is critical for self-approval prevention and tool squatting detection.
//!
//! # Verified Properties (K64-K65)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K64 | `normalize_homoglyphs` is idempotent (applying twice == once) |
//! | K65 | All mapped confusables collapse to ASCII (output ⊆ ASCII + unmapped) |
//!
//! # Production Correspondence
//!
//! - `normalize_homoglyphs` ↔ `vellaveto-types/src/unicode.rs:50-188`
//! - `normalize_identity` ↔ `vellaveto-types/src/unicode.rs:220-222`
//!
//! That correspondence is checked behaviourally by
//! `vellaveto-types/src/kani_unicode_differential.rs`, which compares this
//! mapping against production over every Unicode scalar value. Before
//! 2026-08-30 nothing checked it — see PARITY-HAND-2 in
//! formal/ASSUMPTION_REGISTRY.md.

/// Map common Unicode confusables to their ASCII equivalents.
///
/// Verbatim from `vellaveto-types/src/unicode.rs:50-188`.
pub fn normalize_confusable_char(c: char) -> char {
    match c {
        // Cyrillic lowercase confusables
        '\u{0430}' => 'a',
        '\u{0432}' => 'b',
        '\u{0435}' => 'e',
        '\u{043A}' => 'k',
        '\u{043C}' => 'm',
        '\u{043D}' => 'h',
        '\u{043E}' => 'o',
        '\u{0440}' => 'p',
        '\u{0441}' => 'c',
        '\u{0442}' => 't',
        '\u{0443}' => 'y',
        '\u{0445}' => 'x',
        '\u{0456}' => 'i',
        '\u{0458}' => 'j',
        '\u{04BB}' => 'h',
        '\u{0455}' => 's',
        '\u{0454}' => 'e',
        '\u{044A}' => 'b',

        // Cyrillic uppercase confusables
        '\u{0410}' => 'a',
        '\u{0412}' => 'b',
        '\u{0415}' => 'e',
        '\u{041A}' => 'k',
        '\u{041C}' => 'm',
        '\u{041D}' => 'h',
        '\u{041E}' => 'o',
        '\u{0420}' => 'p',
        '\u{0421}' => 'c',
        '\u{0422}' => 't',
        '\u{0423}' => 'y',
        '\u{0425}' => 'x',
        '\u{0405}' => 's',
        '\u{0406}' => 'i',
        '\u{0408}' => 'j',

        // Greek lowercase confusables
        '\u{03B1}' => 'a',
        '\u{03B2}' => 'b',
        '\u{03B5}' => 'e',
        '\u{03B7}' => 'h',
        '\u{03B9}' => 'i',
        '\u{03BA}' => 'k',
        '\u{03BC}' => 'm',
        '\u{03BD}' => 'v',
        '\u{03BF}' => 'o',
        '\u{03C1}' => 'p',
        '\u{03C4}' => 't',
        '\u{03C5}' => 'u',
        '\u{03C7}' => 'x',
        '\u{03C9}' => 'w',
        '\u{03B6}' => 'z',

        // Greek uppercase confusables
        '\u{0391}' => 'a',
        '\u{0392}' => 'b',
        '\u{0395}' => 'e',
        '\u{0397}' => 'h',
        '\u{0399}' => 'i',
        '\u{039A}' => 'k',
        '\u{039C}' => 'm',
        '\u{039D}' => 'n',
        '\u{039F}' => 'o',
        '\u{03A1}' => 'p',
        '\u{03A4}' => 't',
        '\u{03A7}' => 'x',
        '\u{03A5}' => 'y',
        '\u{0396}' => 'z',

        // Armenian confusables
        '\u{0561}' => 'a',
        '\u{0570}' => 'h',
        '\u{0578}' => 'n',
        '\u{0585}' => 'o',
        '\u{057D}' => 's',
        '\u{0582}' => 'u',

        // Fullwidth Latin
        c @ '\u{FF21}'..='\u{FF3A}' => (c as u32 - 0xFF21 + b'a' as u32) as u8 as char,
        c @ '\u{FF41}'..='\u{FF5A}' => (c as u32 - 0xFF41 + b'a' as u32) as u8 as char,
        c @ '\u{FF10}'..='\u{FF19}' => (c as u32 - 0xFF10 + b'0' as u32) as u8 as char,
        '\u{FF3F}' => '_',

        // Cyrillic Extended-B Palochka
        '\u{04C0}' => 'i',
        '\u{04CF}' => 'l',

        // Cherokee script confusables
        '\u{13AA}' => 'g',
        '\u{13B3}' => 'w',
        '\u{13CB}' => 'h',
        '\u{13A1}' => 'e',
        '\u{13A2}' => 'r',
        '\u{13DA}' => 's',
        '\u{13E4}' => 't',
        '\u{13AC}' => 'h',
        '\u{13D9}' => 'v',
        '\u{13CF}' => 'b',
        '\u{13D2}' => 'p',
        '\u{13A0}' => 'd',

        // Other common confusables
        '\u{0131}' => 'i',
        '\u{1D00}' => 'a',
        '\u{0261}' => 'g',
        '\u{01C0}' => 'l',
        '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2015}' => '-',
        '\u{2018}' | '\u{2019}' | '\u{02BC}' => '\'',

        other => other,
    }
}

/// Proof helper: identify exactly the chars that the mapping collapses to ASCII.
pub fn maps_to_ascii_confusable(c: char) -> bool {
    matches!(
        c,
        '\u{0430}'
            | '\u{0432}'
            | '\u{0435}'
            | '\u{043A}'
            | '\u{043C}'
            | '\u{043D}'
            | '\u{043E}'
            | '\u{0440}'
            | '\u{0441}'
            | '\u{0442}'
            | '\u{0443}'
            | '\u{0445}'
            | '\u{0456}'
            | '\u{0458}'
            | '\u{04BB}'
            | '\u{0455}'
            | '\u{0454}'
            | '\u{044A}'
            | '\u{0410}'
            | '\u{0412}'
            | '\u{0415}'
            | '\u{041A}'
            | '\u{041C}'
            | '\u{041D}'
            | '\u{041E}'
            | '\u{0420}'
            | '\u{0421}'
            | '\u{0422}'
            | '\u{0423}'
            | '\u{0425}'
            | '\u{0405}'
            | '\u{0406}'
            | '\u{0408}'
            | '\u{03B1}'
            | '\u{03B2}'
            | '\u{03B5}'
            | '\u{03B7}'
            | '\u{03B9}'
            | '\u{03BA}'
            | '\u{03BC}'
            | '\u{03BD}'
            | '\u{03BF}'
            | '\u{03C1}'
            | '\u{03C4}'
            | '\u{03C5}'
            | '\u{03C7}'
            | '\u{03C9}'
            | '\u{03B6}'
            | '\u{0391}'
            | '\u{0392}'
            | '\u{0395}'
            | '\u{0397}'
            | '\u{0399}'
            | '\u{039A}'
            | '\u{039C}'
            | '\u{039D}'
            | '\u{039F}'
            | '\u{03A1}'
            | '\u{03A4}'
            | '\u{03A7}'
            | '\u{03A5}'
            | '\u{0396}'
            | '\u{0561}'
            | '\u{0570}'
            | '\u{0578}'
            | '\u{0585}'
            | '\u{057D}'
            | '\u{0582}'
            | '\u{FF10}'..='\u{FF19}'
            | '\u{FF21}'..='\u{FF3A}'
            | '\u{FF3F}'
            | '\u{FF41}'..='\u{FF5A}'
            | '\u{04C0}'
            | '\u{04CF}'
            | '\u{13AA}'
            | '\u{13B3}'
            | '\u{13CB}'
            | '\u{13A1}'
            | '\u{13A2}'
            | '\u{13DA}'
            | '\u{13E4}'
            | '\u{13AC}'
            | '\u{13D9}'
            | '\u{13CF}'
            | '\u{13D2}'
            | '\u{13A0}'
            | '\u{0131}'
            | '\u{1D00}'
            | '\u{0261}'
            | '\u{01C0}'
            | '\u{2010}'..='\u{2015}'
            | '\u{2018}'
            | '\u{2019}'
            | '\u{02BC}'
    )
}

pub fn normalize_homoglyphs(s: &str) -> String {
    s.chars().map(normalize_confusable_char).collect()
}

/// Normalize an identity string for security comparison.
///
/// Verbatim from `vellaveto-types/src/unicode.rs:220-222`.
pub fn normalize_identity(s: &str) -> String {
    normalize_homoglyphs(&s.to_lowercase())
}

/// Check if a char is in the homoglyph mapping table (maps to ASCII).
pub fn is_mapped_confusable(c: char) -> bool {
    normalize_homoglyphs(&c.to_string()) != c.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cyrillic_a_parity() {
        // Must match production: Cyrillic 'а' (U+0430) → Latin 'a'
        assert_eq!(normalize_homoglyphs("\u{0430}dmin"), "admin");
    }

    #[test]
    fn test_cyrillic_spoofed_admin_parity() {
        assert_eq!(normalize_homoglyphs("\u{0430}dmin"), "admin");
        assert_eq!(normalize_homoglyphs("adm\u{0456}n"), "admin");
        assert_eq!(normalize_homoglyphs("\u{0430}dm\u{0456}n"), "admin");
    }

    #[test]
    fn test_greek_alpha_parity() {
        assert_eq!(normalize_homoglyphs("\u{03B1}dmin"), "admin");
    }

    #[test]
    fn test_fullwidth_latin_parity() {
        // Fullwidth "ADMIN" → "admin"
        assert_eq!(
            normalize_homoglyphs("\u{FF21}\u{FF24}\u{FF2D}\u{FF29}\u{FF2E}"),
            "admin"
        );
        // Fullwidth lowercase "bash"
        assert_eq!(
            normalize_homoglyphs("\u{FF42}\u{FF41}\u{FF53}\u{FF48}"),
            "bash"
        );
        // Fullwidth digits
        assert_eq!(normalize_homoglyphs("\u{FF10}\u{FF11}\u{FF12}"), "012");
    }

    #[test]
    fn test_armenian_parity() {
        assert_eq!(normalize_homoglyphs("\u{0561}"), "a");
        assert_eq!(normalize_homoglyphs("\u{0570}"), "h");
        assert_eq!(normalize_homoglyphs("\u{0585}"), "o");
    }

    #[test]
    fn test_cherokee_parity() {
        assert_eq!(normalize_homoglyphs("\u{13AA}"), "g");
        assert_eq!(normalize_homoglyphs("\u{13E4}"), "t");
        assert_eq!(normalize_homoglyphs("\u{13A0}"), "d");
    }

    #[test]
    fn test_dashes_parity() {
        assert_eq!(normalize_homoglyphs("foo\u{2010}bar"), "foo-bar");
        assert_eq!(normalize_homoglyphs("foo\u{2013}bar"), "foo-bar");
        assert_eq!(normalize_homoglyphs("foo\u{2014}bar"), "foo-bar");
    }

    #[test]
    fn test_already_ascii_unchanged() {
        assert_eq!(normalize_homoglyphs("admin"), "admin");
        assert_eq!(normalize_homoglyphs("read_file"), "read_file");
        assert_eq!(normalize_homoglyphs(""), "");
    }

    #[test]
    fn test_normalize_identity_parity() {
        assert_eq!(normalize_identity("AgentAlpha"), "agentalpha");
        assert_eq!(normalize_identity("ADMIN"), "admin");
        assert_eq!(
            normalize_identity("\u{0430}gent"),
            normalize_identity("agent")
        );
    }

    #[test]
    fn test_idempotent_parity() {
        let input = "AgentAlph\u{0430}";
        let once = normalize_identity(input);
        let twice = normalize_identity(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn test_palochka_parity() {
        assert_eq!(normalize_homoglyphs("\u{04C0}"), "i");
        assert_eq!(normalize_homoglyphs("\u{04CF}"), "l");
    }
}
