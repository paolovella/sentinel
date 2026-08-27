// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Path normalization utilities.
//!
//! This module provides path normalization functions that:
//! - Resolve `..` and `.` components
//! - Reject null bytes (fail-closed)
//! - Iteratively decode percent-encoding until stable
//! - Normalize backslashes to forward slashes
//! - Ensure deterministic, absolute path output

use crate::error::EngineError;
use std::borrow::Cow;

/// Default maximum percent-decoding iterations for path normalization.
/// Paths requiring more iterations fail-closed with an error.
pub const DEFAULT_MAX_PATH_DECODE_ITERATIONS: u32 = 20;

/// Normalize a file path: resolve `..`, `.`, reject null bytes, ensure deterministic form.
///
/// Uses the default decode iteration limit ([`DEFAULT_MAX_PATH_DECODE_ITERATIONS`]).
/// For a configurable limit, use [`normalize_path_bounded`].
///
/// # Security
///
/// This function is hardened against path traversal attacks:
/// - Rejects paths containing null bytes
/// - Iteratively percent-decodes until stable (prevents double-encoding bypass)
/// - Resolves `..` and `.` components
/// - Normalizes backslashes to forward slashes
/// - Ensures output is an absolute path (prepends `/` if needed)
///
/// # Errors
///
/// Returns `EngineError::PathNormalization` if:
/// - Input contains null bytes
/// - Decoded path contains null bytes
/// - Decode iteration limit is exceeded
/// - Normalization produces an empty path
pub fn normalize_path(raw: &str) -> Result<String, EngineError> {
    normalize_path_bounded(raw, DEFAULT_MAX_PATH_DECODE_ITERATIONS)
}

/// Normalize a file path with a configurable percent-decoding iteration limit.
///
/// Iteratively decodes percent-encoding until stable. If `max_iterations` is
/// reached before stabilization, returns an error (fail-closed) and emits a
/// warning via `tracing`.
///
/// # Arguments
///
/// * `raw` - The raw path string to normalize
/// * `max_iterations` - Maximum number of decode iterations before fail-closed
///
/// # Security
///
/// See [`normalize_path`] for security details. The iteration limit prevents
/// DoS attacks via deeply-nested percent-encoding (e.g., `%25252525...`).
pub fn normalize_path_bounded(raw: &str, max_iterations: u32) -> Result<String, EngineError> {
    // Reject null bytes — return root instead of empty/raw to prevent bypass
    if raw.contains('\0') {
        return Err(EngineError::PathNormalization {
            reason: "input contains null byte".to_string(),
        });
    }

    // Phase 4.2: Percent-decode the path before normalization.
    // Decode in a loop until stable to guarantee idempotency:
    //   normalize_path(normalize_path(x)) == normalize_path(x)
    // Without loop decode, inputs like "%2570" produce "%70" on first call,
    // which decodes to "p" on the next call — breaking idempotency.
    // Safety cap prevents DoS from deeply-nested encodings.
    // If the cap is reached, return "/" (fail-closed).
    //
    // Uses Cow to avoid allocation when no percent sequences are present.
    let mut current = Cow::Borrowed(raw);
    let mut iterations = 0u32;
    loop {
        // SECURITY (R231-ENG-1): Use strict UTF-8 decode instead of lossy.
        // Lossy decode replaces invalid bytes with U+FFFD, creating a normalization
        // differential vs domain code (which uses strict decode). Invalid UTF-8 in
        // paths should be rejected fail-closed, not silently transformed.
        let decoded = match percent_encoding::percent_decode_str(&current).decode_utf8() {
            Ok(d) => d,
            Err(_) => {
                return Err(EngineError::PathNormalization {
                    reason: "decoded path contains invalid UTF-8".to_string(),
                });
            }
        };
        if decoded.contains('\0') {
            return Err(EngineError::PathNormalization {
                reason: "decoded path contains null byte".to_string(),
            });
        }
        // SECURITY (R35-ENG-1): Normalize backslashes INSIDE the decode loop
        // to prevent multi-stage encoded backslash traversals (%255C → %5C → \ → /).
        // Previously (R34-ENG-1) this was done after the loop, which meant
        // backslashes produced by intermediate decode steps were not converted
        // before the stability check, allowing %255C-based traversal.
        let decoded = if decoded.contains('\\') {
            Cow::Owned(decoded.replace('\\', "/"))
        } else {
            decoded
        };
        if decoded.as_ref() == current.as_ref() {
            break; // Stable — no more percent sequences to decode
        }
        iterations += 1;
        if iterations >= max_iterations {
            tracing::warn!(
                path = raw,
                iterations,
                max_iterations,
                "path normalization hit decode iteration limit — returning \"/\" (possible adversarial input)"
            );
            return Err(EngineError::PathNormalization {
                reason: format!("decode iteration limit ({max_iterations}) exceeded"),
            });
        }
        current = Cow::Owned(decoded.into_owned());
    }

    normalize_decoded_path(current.as_ref())
}

/// Normalize an already-decoded slash-separated path into the engine's
/// canonical absolute form.
///
/// This is the proof-friendly kernel used after percent-decoding and
/// backslash normalization. It absorbs `..` above root, drops `.` and empty
/// components, and always returns an absolute path on success.
pub(crate) fn normalize_decoded_path(decoded: &str) -> Result<String, EngineError> {
    if decoded.contains('\0') {
        return Err(EngineError::PathNormalization {
            reason: "decoded path contains null byte".to_string(),
        });
    }

    let starts_with_slash = decoded.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();

    for component in decoded.split('/') {
        match component {
            "" | "." => continue,
            ".." => {
                stack.pop();
            }
            _ => stack.push(component),
        }
    }

    if stack.is_empty() && !starts_with_slash {
        return Err(EngineError::PathNormalization {
            reason: "normalization produced empty path".to_string(),
        });
    }

    let mut normalized = String::with_capacity(decoded.len().saturating_add(1));
    normalized.push('/');

    if let Some((first, rest)) = stack.split_first() {
        normalized.push_str(first);
        for component in rest {
            normalized.push('/');
            normalized.push_str(component);
        }
    }

    Ok(normalized)
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `normalize_path_bytes == spec_normalize_path_bytes` in
    //! `formal/verus/verified_path.rs`. The transcription below restates that
    //! spec and asserts it agrees with the shipped function.
    //!
    //! **Scope.** The kernel models the *post-decode* stage only — split on
    //! `/`, skip empty and `.`, pop on `..`, render with a leading `/`. It does
    //! not model percent-decoding at all (`0x25` appears nowhere in it), so the
    //! binding targets `normalize_decoded_path`, which is that stage.
    //! `normalize_path`'s iterative decode loop is outside the proof; see
    //! `PATH-DECODE-1` in the registry.
    //!
    //! BOUNDED: exhaustive over byte strings from an alphabet holding `/`, `.`,
    //! a normal byte and a null, which is enough to reach every branch of the
    //! component classifier including the `..`-at-root pop and the null
    //! rejection.

    use super::*;

    const SLASH: u8 = b'/';
    const DOT: u8 = b'.';

    fn spec_has_no_null(path: &[u8]) -> bool {
        path.iter().all(|&b| b != 0)
    }

    /// Transcription of `spec_process_component`.
    // The kernel keeps "empty component" and "`.` component" as separate
    // branches even though both are no-ops, because they are different cases
    // in `spec_process_component`. Collapsing them, which is what clippy
    // suggests, would make this transcription structurally different from the
    // kernel and defeat the comparison it exists to make.
    #[allow(clippy::if_same_then_else)]
    fn spec_process_component(comp: &[u8], stack: &mut Vec<Vec<u8>>) {
        if comp.is_empty() {
        } else if comp.len() == 1 && comp[0] == DOT {
        } else if comp.len() == 2 && comp[0] == DOT && comp[1] == DOT {
            stack.pop();
        } else {
            stack.push(comp.to_vec());
        }
    }

    /// Transcription of `spec_process_bytes`.
    fn spec_process_bytes(path: &[u8]) -> Vec<Vec<u8>> {
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        for &byte in path {
            if byte == SLASH {
                spec_process_component(&current, &mut stack);
                current.clear();
            } else {
                current.push(byte);
            }
        }
        spec_process_component(&current, &mut stack);
        stack
    }

    /// Transcription of `spec_render_path(true, stack)`.
    fn spec_render_path(stack: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![SLASH];
        for (i, comp) in stack.iter().enumerate() {
            if i > 0 {
                out.push(SLASH);
            }
            out.extend_from_slice(comp);
        }
        out
    }

    /// Transcription of `spec_normalize_path_bytes`.
    fn spec_normalize_path_bytes(path: &[u8]) -> (bool, Vec<u8>) {
        if !spec_has_no_null(path) {
            return (false, Vec::new());
        }
        let starts_with_slash = path.first() == Some(&SLASH);
        let stack = spec_process_bytes(path);
        if starts_with_slash || !stack.is_empty() {
            (true, spec_render_path(&stack))
        } else {
            (false, Vec::new())
        }
    }

    fn corpus() -> Vec<Vec<u8>> {
        const ALPHABET: &[u8] = &[SLASH, DOT, b'a', 0];
        const MAX_LEN: usize = 5;
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
        all
    }

    #[test]
    fn test_normalize_decoded_path_matches_verus_spec_bounded_exhaustive() {
        let all = corpus();
        assert_eq!(all.len(), 1365, "enumeration size changed; recount");

        let mut checked = 0usize;
        for bytes in &all {
            let Ok(as_str) = core::str::from_utf8(bytes) else {
                continue;
            };
            let (spec_ok, spec_out) = spec_normalize_path_bytes(bytes);
            match normalize_decoded_path(as_str) {
                Ok(shipped) => {
                    assert!(
                        spec_ok,
                        "PARITY-HAND-1: shipped accepted {as_str:?} -> {shipped:?} but the spec rejects it"
                    );
                    assert_eq!(
                        shipped.as_bytes(),
                        spec_out.as_slice(),
                        "PARITY-HAND-1: normalize_decoded_path disagrees for {as_str:?}"
                    );
                }
                Err(_) => assert!(
                    !spec_ok,
                    "PARITY-HAND-1: shipped rejected {as_str:?} but the spec accepts it as {:?}",
                    String::from_utf8_lossy(&spec_out)
                ),
            }
            checked += 1;
        }
        assert!(checked > 1000, "corpus collapsed to {checked} inputs");
    }

    /// The postconditions the kernel proves of its output must hold of the
    /// shipped output too: no `..` component survives, and no null does.
    #[test]
    fn test_shipped_output_satisfies_the_proven_postconditions() {
        for bytes in &corpus() {
            let Ok(as_str) = core::str::from_utf8(bytes) else {
                continue;
            };
            let Ok(shipped) = normalize_decoded_path(as_str) else {
                continue;
            };
            assert!(
                spec_has_no_null(shipped.as_bytes()),
                "PARITY-HAND-1: null survived normalization of {as_str:?}"
            );
            assert!(
                !shipped.split('/').any(|c| c == ".."),
                "PARITY-HAND-1: a `..` component survived normalization of {as_str:?} -> {shipped:?}"
            );
            assert!(
                shipped.starts_with('/'),
                "PARITY-HAND-1: output is not rooted for {as_str:?} -> {shipped:?}"
            );
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Traversal is popped, not preserved.
        assert_eq!(spec_normalize_path_bytes(b"/a/../b").1, b"/b".to_vec());
        // `..` at the root is absorbed rather than escaping above it.
        assert_eq!(spec_normalize_path_bytes(b"/../..").1, b"/".to_vec());
        // Nulls are refused outright.
        assert!(!spec_normalize_path_bytes(b"/a b").0);
        // A relative path that normalizes to nothing is refused.
        assert!(!spec_normalize_path_bytes(b".").0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_simple() {
        assert_eq!(normalize_path("/etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(
            normalize_path("/home/user/file.txt").unwrap(),
            "/home/user/file.txt"
        );
    }

    #[test]
    fn test_normalize_path_traversal() {
        assert_eq!(normalize_path("/etc/../etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("/etc/./passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("/etc/foo/../passwd").unwrap(), "/etc/passwd");
    }

    #[test]
    fn test_normalize_path_above_root() {
        // Can't traverse above root
        assert_eq!(normalize_path("/etc/../../../passwd").unwrap(), "/passwd");
        assert_eq!(normalize_path("/../../../etc").unwrap(), "/etc");
    }

    #[test]
    fn test_normalize_path_relative() {
        // Relative paths get '/' prepended
        assert_eq!(normalize_path("etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("file.txt").unwrap(), "/file.txt");
    }

    #[test]
    fn test_normalize_path_percent_encoded() {
        // %2e = '.', %2f = '/'
        assert_eq!(normalize_path("/etc/%2e%2e/passwd").unwrap(), "/passwd");
    }

    #[test]
    fn test_normalize_path_double_encoded() {
        // %252e = '%2e' -> '.'
        assert_eq!(normalize_path("/etc/%252e%252e/passwd").unwrap(), "/passwd");
    }

    #[test]
    fn test_normalize_path_null_byte_rejected() {
        assert!(normalize_path("/etc/passwd\0").is_err());
    }

    #[test]
    fn test_normalize_path_encoded_null_rejected() {
        // %00 = null byte
        assert!(normalize_path("/etc/passwd%00").is_err());
    }

    #[test]
    fn test_normalize_path_backslash_normalized() {
        assert_eq!(normalize_path("/etc\\passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("\\etc\\passwd").unwrap(), "/etc/passwd");
    }

    #[test]
    fn test_normalize_path_iteration_limit() {
        // Deeply nested encoding should hit iteration limit
        let result = normalize_path_bounded("%25252525252525252525", 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_path_empty_result() {
        // Path that resolves to empty should error
        assert!(normalize_path("..").is_err());
    }

    #[test]
    fn test_normalize_decoded_path_kernel() {
        assert_eq!(normalize_decoded_path("/etc/../passwd").unwrap(), "/passwd");
        assert_eq!(normalize_decoded_path("etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_decoded_path("/../../etc").unwrap(), "/etc");
        assert_eq!(
            normalize_decoded_path("//server///share").unwrap(),
            "/server/share"
        );
        assert!(normalize_decoded_path("..").is_err());
    }

    // ════════════════════════════════════════════════════════
    // FIND-047: Windows UNC path and drive letter tests
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_normalize_path_windows_unc_path() {
        // UNC path \\server\share\file.txt — backslashes become forward slashes
        let result = normalize_path("\\\\server\\share\\file.txt");
        assert!(result.is_ok(), "UNC path should normalize without error");
        let normalized = result.unwrap();
        assert!(
            normalized.starts_with('/'),
            "Normalized UNC path should be absolute"
        );
        assert!(
            normalized.contains("server"),
            "Server name should be preserved"
        );
    }

    #[test]
    fn test_normalize_path_windows_drive_letter() {
        let result = normalize_path("C:\\Users\\file.txt");
        assert!(
            result.is_ok(),
            "Windows drive path should normalize without error"
        );
        let normalized = result.unwrap();
        assert!(
            normalized.starts_with('/'),
            "Normalized path should be absolute"
        );
    }

    #[test]
    fn test_normalize_path_unc_with_traversal() {
        // UNC path with traversal attempt should resolve .. safely
        let result = normalize_path("\\\\server\\..\\..\\..\\etc\\passwd");
        assert!(result.is_ok());
        let normalized = result.unwrap();
        // Traversal above root should be absorbed
        assert!(
            !normalized.contains(".."),
            "Traversal components should be resolved"
        );
    }

    #[test]
    fn test_normalize_path_percent_encoded_drive_letter() {
        // %43 = 'C', %3A = ':', %5C = '\'
        let result = normalize_path("%43%3A%5CUsers%5Cfile.txt");
        assert!(result.is_ok());
        let normalized = result.unwrap();
        assert!(
            normalized.starts_with('/'),
            "Encoded drive letter path should become absolute"
        );
    }

    #[test]
    fn test_normalize_path_mixed_separators() {
        // Mixed forward and backward slashes
        let result = normalize_path("/home\\user/docs\\file.txt");
        assert!(result.is_ok());
        let normalized = result.unwrap();
        assert_eq!(
            normalized, "/home/user/docs/file.txt",
            "Mixed separators should normalize to forward slashes"
        );
    }
}
