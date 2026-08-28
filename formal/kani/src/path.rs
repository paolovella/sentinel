// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Path normalization — verbatim extraction from `vellaveto-engine/src/path.rs`.
//!
//! The only differences from the production code:
//! - `EngineError::PathNormalization` → `PathError`
//! - `tracing::warn!()` → no-op (Kani cannot model tracing)
//!
//! The algorithm is identical. That correspondence is checked behaviourally
//! by `vellaveto-engine/src/kani_path_differential.rs`, which compiles this
//! file and compares it against production over an enumerated corpus. Before
//! 2026-08-28 the claim was made here but nothing checked it — see
//! PARITY-HAND-2 in formal/ASSUMPTION_REGISTRY.md.

use crate::PathError;
use std::borrow::Cow;
use std::path::{Component, PathBuf};

/// Default maximum percent-decoding iterations for path normalization.
pub const DEFAULT_MAX_PATH_DECODE_ITERATIONS: u32 = 20;

/// Normalize a file path: resolve `..`, `.`, reject null bytes, ensure deterministic form.
pub fn normalize_path(raw: &str) -> Result<String, PathError> {
    normalize_path_bounded(raw, DEFAULT_MAX_PATH_DECODE_ITERATIONS)
}

/// Normalize a file path with a configurable percent-decoding iteration limit.
///
/// Verbatim from `vellaveto-engine/src/path.rs:65-174` with error type substitution.
pub fn normalize_path_bounded(raw: &str, max_iterations: u32) -> Result<String, PathError> {
    // Reject null bytes
    if raw.contains('\0') {
        return Err(PathError {
            reason: "input contains null byte".to_string(),
        });
    }

    // Iterative percent-decode until stable
    let mut current = Cow::Borrowed(raw);
    let mut iterations = 0u32;
    loop {
        let decoded = match percent_encoding::percent_decode_str(&current).decode_utf8() {
            Ok(d) => d,
            Err(_) => {
                return Err(PathError {
                    reason: "decoded path contains invalid UTF-8".to_string(),
                });
            }
        };
        if decoded.contains('\0') {
            return Err(PathError {
                reason: "decoded path contains null byte".to_string(),
            });
        }
        // Normalize backslashes inside the decode loop (R35-ENG-1)
        let decoded = if decoded.contains('\\') {
            Cow::Owned(decoded.replace('\\', "/"))
        } else {
            decoded
        };
        if decoded.as_ref() == current.as_ref() {
            break; // Stable
        }
        iterations += 1;
        if iterations >= max_iterations {
            // Production code: tracing::warn!(...) — omitted for Kani
            return Err(PathError {
                reason: format!("decode iteration limit ({}) exceeded", max_iterations),
            });
        }
        current = Cow::Owned(decoded.into_owned());
    }

    let path = PathBuf::from(current.as_ref());
    let mut components = Vec::new();

    for component in path.components() {
        match component {
            Component::ParentDir => {
                match components.last() {
                    Some(Component::RootDir) | None => {
                        continue; // At root or empty — absorb
                    }
                    _ => {
                        components.pop();
                        continue;
                    }
                }
            }
            Component::CurDir => continue,
            _ => {}
        }
        components.push(component);
    }

    let result: PathBuf = components.iter().collect();
    let s = result.to_string_lossy();
    if s.is_empty() {
        return Err(PathError {
            reason: "normalization produced empty path".to_string(),
        });
    }

    let s = s.into_owned();
    if !s.starts_with('/') {
        return Ok(format!("/{}", s));
    }

    Ok(s)
}

/// Hex digit value helper for Kani byte-level percent-decode.
/// Returns 255 for invalid hex digits.
fn kani_hex_val(b: u8) -> u8 {
    if b >= b'0' && b <= b'9' {
        return b - b'0';
    }
    if b >= b'a' && b <= b'f' {
        return b - b'a' + 10;
    }
    if b >= b'A' && b <= b'F' {
        return b - b'A' + 10;
    }
    255
}

/// Maximum output buffer size for `normalize_path_kani`.
pub const KANI_PATH_BUF: usize = 16;

/// Kani-friendly ASCII path normalizer using fixed-size arrays.
///
/// Implements the same algorithm as [`normalize_path_bounded`] for ASCII input:
/// 1. Iterative percent-decode + backslash→slash normalization
/// 2. Component resolution (skip empty/`.`, absorb `..` at root, pop otherwise)
/// 3. `/` prefix normalization
///
/// Avoids String/Vec/PathBuf/percent_encoding heap operations that create SAT
/// formulas too large for CBMC bounded model checking. Production uses
/// `normalize_path_bounded`; this proves the same properties for ASCII.
/// Correspondence verified by unit tests below.
pub fn normalize_path_kani(
    input: &[u8],
    max_iter: u32,
) -> Result<([u8; KANI_PATH_BUF], usize), ()> {
    // Reject null bytes
    let mut i = 0;
    while i < input.len() {
        if input[i] == 0 {
            return Err(());
        }
        i += 1;
    }

    // Phase 1: Iterative percent-decode + backslash→slash normalization.
    // Combined in one pass per iteration to match production behavior
    // (percent_decode_str then replace('\\', "/") in same loop iteration).
    let mut buf = [0u8; KANI_PATH_BUF];
    let mut buf_len = input.len().min(KANI_PATH_BUF);
    i = 0;
    while i < buf_len {
        buf[i] = input[i];
        i += 1;
    }

    let mut iterations = 0u32;
    loop {
        let mut decoded = [0u8; KANI_PATH_BUF];
        let mut dec_len = 0usize;
        let mut changed = false;
        i = 0;
        while i < buf_len {
            if buf[i] == b'%' && i + 2 < buf_len {
                let h = kani_hex_val(buf[i + 1]);
                let l = kani_hex_val(buf[i + 2]);
                if h < 16 && l < 16 {
                    let byte = h * 16 + l;
                    if byte == 0 {
                        return Err(());
                    }
                    // Combined decode + backslash normalization
                    let out_byte = if byte == b'\\' { b'/' } else { byte };
                    if dec_len < KANI_PATH_BUF {
                        decoded[dec_len] = out_byte;
                        dec_len += 1;
                    }
                    changed = true;
                    i += 3;
                    continue;
                }
            }
            if buf[i] == b'\\' {
                if dec_len < KANI_PATH_BUF {
                    decoded[dec_len] = b'/';
                    dec_len += 1;
                }
                changed = true;
                i += 1;
                continue;
            }
            if dec_len < KANI_PATH_BUF {
                decoded[dec_len] = buf[i];
                dec_len += 1;
            }
            i += 1;
        }

        if !changed {
            break;
        }
        buf = decoded;
        buf_len = dec_len;
        iterations += 1;
        if iterations >= max_iter {
            return Err(());
        }
    }

    // Phase 2: Component resolution (mirrors PathBuf::components behavior).
    let has_root = buf_len > 0 && buf[0] == b'/';
    let mut comp_starts = [0usize; 8];
    let mut comp_lens = [0usize; 8];
    let mut n_comps = 0usize;

    let mut pos = 0;
    while pos < buf_len {
        while pos < buf_len && buf[pos] == b'/' {
            pos += 1;
        }
        if pos >= buf_len {
            break;
        }
        let start = pos;
        while pos < buf_len && buf[pos] != b'/' {
            pos += 1;
        }
        let clen = pos - start;
        let is_dot = clen == 1 && buf[start] == b'.';
        let is_dotdot = clen == 2 && buf[start] == b'.' && buf[start + 1] == b'.';

        if is_dot {
            // skip (CurDir)
        } else if is_dotdot {
            if n_comps > 0 {
                n_comps -= 1;
            }
            // At root or empty: absorb (matches Component::ParentDir at RootDir/None)
        } else if n_comps < 8 {
            comp_starts[n_comps] = start;
            comp_lens[n_comps] = clen;
            n_comps += 1;
        }
    }

    // Phase 3: Build output.
    if n_comps == 0 && !has_root {
        return Err(()); // Empty path (e.g., just ".." or ".")
    }

    let mut out = [0u8; KANI_PATH_BUF];
    let mut out_len = 0;

    // Always start with /
    out[out_len] = b'/';
    out_len += 1;

    let mut ci = 0;
    while ci < n_comps {
        if ci > 0 && out_len < KANI_PATH_BUF {
            out[out_len] = b'/';
            out_len += 1;
        }
        let mut j = 0;
        while j < comp_lens[ci] && out_len < KANI_PATH_BUF {
            out[out_len] = buf[comp_starts[ci] + j];
            out_len += 1;
            j += 1;
        }
        ci += 1;
    }

    Ok((out, out_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the extracted algorithm matches production behavior
    /// on the same test vectors from `vellaveto-engine/src/path.rs`.
    #[test]
    fn test_production_parity() {
        assert_eq!(normalize_path("/etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("/etc/../etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("/etc/./passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("/etc/../../../passwd").unwrap(), "/passwd");
        assert_eq!(normalize_path("etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(normalize_path("/etc/%2e%2e/passwd").unwrap(), "/passwd");
        assert_eq!(normalize_path("/etc/%252e%252e/passwd").unwrap(), "/passwd");
        assert!(normalize_path("/etc/passwd\0").is_err());
        assert!(normalize_path("/etc/passwd%00").is_err());
        assert_eq!(normalize_path("/etc\\passwd").unwrap(), "/etc/passwd");
        assert!(normalize_path_bounded("%25252525252525252525", 3).is_err());
        assert!(normalize_path("..").is_err());
    }

    /// Verify the Kani byte-level normalizer produces the same results as
    /// the production String-based normalizer on key test vectors.
    #[test]
    fn test_kani_normalizer_parity() {
        let cases: &[(&[u8], Option<&str>)] = &[
            (b"/", Some("/")),
            (b"/a", Some("/a")),
            (b"/a/b", Some("/a/b")),
            (b"/a/..", Some("/")),
            (b"/a/.", Some("/a")),
            (b"/..", Some("/")),
            (b"/.", Some("/")),
            (b"a", Some("/a")),
            (b"a/b", Some("/a/b")),
            (b"../a", Some("/a")),
            (b"..", None),
            (b".", None),
            (b"\x00", None),
            (b"/a\x00", None),
            (b"\\a", Some("/a")),
            (b"/a\\b", Some("/a/b")),
            (b"%2e", None),      // decodes to "." → empty → error
            (b"%2f", Some("/")), // decodes to "/"
            (b"%5c", Some("/")), // decodes to "\\" → "/"
            (b"%00", None),      // decodes to null → error
        ];
        for &(input, expected) in cases {
            let result = normalize_path_kani(input, 20);
            let input_str = std::str::from_utf8(input).ok();
            match (result, expected) {
                (Ok((buf, len)), Some(exp)) => {
                    assert_eq!(
                        &buf[..len],
                        exp.as_bytes(),
                        "kani normalizer mismatch for {:?}",
                        input_str
                    );
                    // Also verify against production
                    if let Some(s) = input_str {
                        let prod = normalize_path(s);
                        assert_eq!(
                            prod.as_ref().map(|r| r.as_str()),
                            Ok(exp),
                            "production mismatch for {:?}",
                            s
                        );
                    }
                }
                (Err(()), None) => {
                    if let Some(s) = input_str {
                        assert!(
                            normalize_path(s).is_err(),
                            "production should also error for {:?}",
                            s
                        );
                    }
                }
                (Ok((buf, len)), None) => {
                    panic!(
                        "kani normalizer should error for {:?}, got {:?}",
                        input_str,
                        std::str::from_utf8(&buf[..len])
                    );
                }
                (Err(()), Some(exp)) => {
                    panic!(
                        "kani normalizer unexpectedly errored for {:?}, expected {:?}",
                        input_str, exp
                    );
                }
            }
        }
    }
}
