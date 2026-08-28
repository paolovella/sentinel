// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Materializes the Kani path extraction so it can be compiled and compared
//! against production. See `src/kani_path_differential.rs` and `PARITY-HAND-2`
//! in `formal/ASSUMPTION_REGISTRY.md`.
//!
//! The extraction cannot be pulled in with a bare `include!` because it opens
//! with `//!` inner doc comments, and Rust rejects inner attributes that arrive
//! from a macro expansion. The only transformation applied here is turning
//! those `//!` lines into `//`. Nothing else is touched: if this script ever
//! needs to rewrite code to make the extraction compile, the extraction has
//! stopped being the thing the Kani proofs run against and that is a finding.

use std::path::Path;

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR is always set by cargo");

    let extraction = Path::new(&manifest_dir).join("../formal/kani/src/path.rs");
    println!("cargo:rerun-if-changed={}", extraction.display());
    println!("cargo:rerun-if-changed=build.rs");

    // Absent (a slim checkout, a published crate) the differential test is
    // skipped rather than failing the build; the test asserts on the marker so
    // a silent skip cannot masquerade as a pass.
    let Ok(source) = std::fs::read_to_string(&extraction) else {
        std::fs::write(
            Path::new(&out_dir).join("kani_path_extraction.rs"),
            "// Kani extraction not present in this checkout.\n\
             pub const EXTRACTION_PRESENT: bool = false;\n",
        )
        .expect("writing to OUT_DIR");
        return;
    };

    let mut rewritten = String::with_capacity(source.len() + 128);
    rewritten.push_str("pub const EXTRACTION_PRESENT: bool = true;\n");
    for line in source.lines() {
        // `//!` -> `//`. Only the doc-comment marker changes.
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("//!") {
            let indent = &line[..line.len() - trimmed.len()];
            rewritten.push_str(indent);
            rewritten.push_str("//");
            rewritten.push_str(rest);
        } else {
            rewritten.push_str(line);
        }
        rewritten.push('\n');
    }

    std::fs::write(
        Path::new(&out_dir).join("kani_path_extraction.rs"),
        rewritten,
    )
    .expect("writing to OUT_DIR");
}
