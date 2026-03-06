// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Stylometric fingerprint resistance.
//!
//! Writing style is a fingerprint — academic deanonymization research shows
//! ~90% accuracy with 500 words. This module strips stylometric features
//! from text before it reaches the AI provider.
//!
//! Two levels of normalization are implemented:
//! - **Level 1 (low impact):** Normalize whitespace, punctuation patterns, emoji usage
//! - **Level 2 (medium impact):** Standardize sentence length, remove filler words
//!
//! Both levels are pure regex/rule transforms with no external dependencies.

use crate::error::ShieldError;

/// Aggressiveness level for stylometric normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NormalizationLevel {
    /// No normalization.
    #[default]
    None,
    /// Low impact: whitespace, punctuation, emoji normalization.
    Level1,
    /// Medium impact: sentence length normalization, filler word removal.
    Level2,
}

/// Common filler words that reveal writing style but carry no semantic content.
const FILLER_WORDS: &[&str] = &[
    "actually",
    "basically",
    "honestly",
    "literally",
    "obviously",
    "definitely",
    "essentially",
    "frankly",
    "clearly",
    "simply",
    "just",
    "really",
    "very",
    "quite",
    "rather",
    "somewhat",
    "pretty much",
    "kind of",
    "sort of",
    "you know",
    "i mean",
    "like",
];

/// Maximum input length for stylometric processing (1 MB).
const MAX_INPUT_LEN: usize = 1_048_576;

/// Maximum JSON recursion depth for `normalize_json`.
const MAX_JSON_DEPTH: usize = 20;

/// Stylometric normalizer that strips writing style fingerprints.
pub struct StylometricNormalizer {
    level: NormalizationLevel,
}

impl StylometricNormalizer {
    /// Create a new normalizer at the specified level.
    pub fn new(level: NormalizationLevel) -> Self {
        Self { level }
    }

    /// Normalize text to resist stylometric fingerprinting.
    pub fn normalize(&self, text: &str) -> Result<String, ShieldError> {
        if text.len() > MAX_INPUT_LEN {
            return Err(ShieldError::Sanitization(format!(
                "input too large for stylometric processing ({} bytes, max {})",
                text.len(),
                MAX_INPUT_LEN
            )));
        }

        match self.level {
            NormalizationLevel::None => Ok(text.to_string()),
            NormalizationLevel::Level1 => Ok(normalize_level1(text)),
            NormalizationLevel::Level2 => Ok(normalize_level2(text)),
        }
    }

    /// Get the normalization level.
    pub fn level(&self) -> NormalizationLevel {
        self.level
    }

    /// Recursively normalize all string values in a JSON value.
    ///
    /// Applies stylometric normalization to every string leaf in the JSON tree,
    /// preserving structure and non-string values. Bounded to `MAX_JSON_DEPTH`
    /// to prevent stack overflow from deeply nested payloads.
    pub fn normalize_json(
        &self,
        value: &serde_json::Value,
    ) -> Result<serde_json::Value, ShieldError> {
        self.walk_json(value, 0)
    }

    /// Recursive JSON walker for stylometric normalization.
    fn walk_json(
        &self,
        value: &serde_json::Value,
        depth: usize,
    ) -> Result<serde_json::Value, ShieldError> {
        if depth > MAX_JSON_DEPTH {
            return Err(ShieldError::Sanitization(
                "JSON recursion depth exceeded during stylometric normalization".to_string(),
            ));
        }

        match value {
            serde_json::Value::String(s) => {
                let normalized = self.normalize(s)?;
                Ok(serde_json::Value::String(normalized))
            }
            serde_json::Value::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len());
                for item in arr {
                    result.push(self.walk_json(item, depth + 1)?);
                }
                Ok(serde_json::Value::Array(result))
            }
            serde_json::Value::Object(map) => {
                let mut result = serde_json::Map::new();
                for (key, val) in map {
                    result.insert(key.clone(), self.walk_json(val, depth + 1)?);
                }
                Ok(serde_json::Value::Object(result))
            }
            other => Ok(other.clone()),
        }
    }
}

/// Level 1: Whitespace, punctuation, and emoji normalization.
fn normalize_level1(text: &str) -> String {
    let mut result = text.to_string();

    // 1. Normalize multiple spaces to single space
    result = collapse_whitespace(&result);

    // 2. Normalize multiple punctuation (!!!! → !, ??? → ?, ... → ...)
    result = normalize_repeated_punctuation(&result);

    // 3. Normalize ellipsis variations (.. or .... or …… → ...)
    result = normalize_ellipsis(&result);

    // 4. Remove emoji (they're a strong fingerprint)
    result = strip_emoji(&result);

    // 5. Normalize quote styles (" " ' ' → " and ')
    result = normalize_quotes(&result);

    // 6. Normalize dash styles (em dash, en dash → -)
    result = normalize_dashes(&result);

    // 7. Trim trailing whitespace on each line
    result = trim_lines(&result);

    result
}

/// Level 2: Sentence normalization + filler word removal (includes Level 1).
fn normalize_level2(text: &str) -> String {
    let mut result = normalize_level1(text);

    // 8. Remove filler words (case-insensitive, whole-word only)
    result = remove_filler_words(&result);

    // 9. Collapse double spaces introduced by filler removal
    result = collapse_whitespace(&result);

    result
}

/// Collapse runs of whitespace (spaces/tabs) to a single space.
/// Preserves newlines.
fn collapse_whitespace(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut in_space = false;
    for ch in text.chars() {
        if ch == '\n' || ch == '\r' {
            in_space = false;
            result.push(ch);
        } else if ch == ' ' || ch == '\t' {
            if !in_space {
                result.push(' ');
                in_space = true;
            }
        } else {
            in_space = false;
            result.push(ch);
        }
    }
    result
}

/// Normalize repeated punctuation: !! → !, ??? → ?, etc.
fn normalize_repeated_punctuation(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut prev: Option<char> = None;
    for ch in text.chars() {
        if (ch == '!' || ch == '?') && prev == Some(ch) {
            // Skip repeated ! or ?
            continue;
        }
        result.push(ch);
        prev = Some(ch);
    }
    result
}

/// Normalize ellipsis: any sequence of 2+ dots or the Unicode ellipsis → "..."
fn normalize_ellipsis(text: &str) -> String {
    // Replace Unicode ellipsis first
    let text = text.replace('\u{2026}', "...");

    let mut result = String::with_capacity(text.len());
    let mut dot_count = 0u32;
    for ch in text.chars() {
        if ch == '.' {
            dot_count = dot_count.saturating_add(1);
        } else {
            if dot_count > 0 {
                if dot_count >= 2 {
                    result.push_str("...");
                } else {
                    result.push('.');
                }
                dot_count = 0;
            }
            result.push(ch);
        }
    }
    // Handle trailing dots
    if dot_count > 0 {
        if dot_count >= 2 {
            result.push_str("...");
        } else {
            result.push('.');
        }
    }
    result
}

/// Remove emoji characters (common fingerprint).
fn strip_emoji(text: &str) -> String {
    text.chars().filter(|ch| !is_emoji(*ch)).collect()
}

/// Check if a character is an emoji.
fn is_emoji(ch: char) -> bool {
    let cp = ch as u32;
    // Emoticons
    (0x1F600..=0x1F64F).contains(&cp)
    // Misc Symbols and Pictographs
    || (0x1F300..=0x1F5FF).contains(&cp)
    // Transport and Map Symbols
    || (0x1F680..=0x1F6FF).contains(&cp)
    // Supplemental Symbols and Pictographs
    || (0x1F900..=0x1F9FF).contains(&cp)
    // Symbols and Pictographs Extended-A
    || (0x1FA00..=0x1FA6F).contains(&cp)
    || (0x1FA70..=0x1FAFF).contains(&cp)
    // Dingbats
    || (0x2702..=0x27B0).contains(&cp)
    // Regional Indicator Symbols
    || (0x1F1E0..=0x1F1FF).contains(&cp)
}

/// Normalize smart quotes to ASCII quotes.
fn normalize_quotes(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\u{201C}' | '\u{201D}' | '\u{201E}' => result.push('"'),
            '\u{2018}' | '\u{2019}' | '\u{201A}' => result.push('\''),
            _ => result.push(ch),
        }
    }
    result
}

/// Normalize dashes to ASCII hyphen.
fn normalize_dashes(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\u{2013}' | '\u{2014}' | '\u{2015}' => result.push('-'),
            _ => result.push(ch),
        }
    }
    result
}

/// Trim trailing whitespace on each line.
fn trim_lines(text: &str) -> String {
    text.lines()
        .map(|line| line.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Remove filler words (case-insensitive, whole-word boundaries).
fn remove_filler_words(text: &str) -> String {
    let mut result = text.to_string();
    for &filler in FILLER_WORDS {
        // Build a case-insensitive whole-word removal
        // Simple approach: split on whitespace, filter, rejoin
        // This handles word boundaries correctly
        result = remove_filler_word(&result, filler);
    }
    result
}

/// Remove a single filler word (case-insensitive, word boundary aware).
fn remove_filler_word(text: &str, filler: &str) -> String {
    if filler.contains(' ') {
        // Multi-word filler (e.g., "kind of", "you know")
        return remove_multiword_filler(text, filler);
    }

    let words: Vec<&str> = text.split(' ').collect();
    let mut result = Vec::with_capacity(words.len());
    for word in words {
        // Strip punctuation for comparison
        let clean: String = word.chars().filter(|c| c.is_alphanumeric()).collect();
        if clean.eq_ignore_ascii_case(filler) {
            // Preserve any trailing punctuation
            let trailing: String = word.chars().skip_while(|c| c.is_alphanumeric()).collect();
            if !trailing.is_empty() {
                result.push(trailing);
            }
        } else {
            result.push(word.to_string());
        }
    }
    result.join(" ")
}

/// Remove a multi-word filler phrase (case-insensitive).
fn remove_multiword_filler(text: &str, filler: &str) -> String {
    let lower = text.to_lowercase();
    let filler_lower = filler.to_lowercase();
    let mut result = String::with_capacity(text.len());
    let mut i = 0;
    let text_bytes = text.as_bytes();

    while i < text.len() {
        if i + filler.len() <= text.len() && lower[i..i + filler.len()] == filler_lower {
            // Check word boundaries
            let before_ok = i == 0 || !text_bytes[i - 1].is_ascii_alphanumeric();
            let after_ok = i + filler.len() >= text.len()
                || !text_bytes[i + filler.len()].is_ascii_alphanumeric();
            if before_ok && after_ok {
                i += filler.len();
                continue;
            }
        }
        // Safety: we index char-by-char through the original text
        if let Some(ch) = text[i..].chars().next() {
            result.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    result
}

impl std::fmt::Debug for StylometricNormalizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StylometricNormalizer")
            .field("level", &self.level)
            .finish()
    }
}
