// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Materializes the Kani extractions that mirror this crate, so they can be
//! compiled and compared against production. See
//! `src/kani_unicode_differential.rs` and `PARITY-HAND-2` in
//! `formal/ASSUMPTION_REGISTRY.md`.
//!
//! An extraction cannot be pulled in with a bare `include!` because it opens
//! with `//!` inner doc comments, and Rust rejects inner attributes that arrive
//! from a macro expansion. The only transformation applied here is turning
//! those `//!` lines into `//`. Nothing else is touched: if this script ever
//! needs to rewrite code to make an extraction compile, the extraction has
//! stopped being the thing the Kani proofs run against, and that is a finding.
//!
//! No `unwrap`, `expect` or `panic!`: CI treats build scripts like runtime code.

use std::path::Path;

/// Report and exit non-zero. A build script has no error channel other than
/// stderr and its exit code.
fn fail(message: &str) -> ! {
    eprintln!("cargo:warning={message}");
    eprintln!("{message}");
    std::process::exit(1)
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // The extractions carry `#[cfg(kani)]` proof modules. Only the Kani crate
    // declares that cfg, so declare it here too or `unexpected_cfgs` rejects
    // the materialized copy. Declaring is correct; stripping the blocks would
    // mean this script rewrites code to make an extraction compile.
    println!("cargo:rustc-check-cfg=cfg(kani)");

    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        fail("CARGO_MANIFEST_DIR is not set; cannot locate the Kani extractions")
    };
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        fail("OUT_DIR is not set; cannot materialize the Kani extractions")
    };

    for (module, out_name) in [
        ("unicode", "kani_unicode_extraction.rs"),
        ("evidence_signing", "kani_evidence_signing_extraction.rs"),
        ("trust_containment", "kani_trust_containment_extraction.rs"),
        ("output_contracts", "kani_output_contracts_extraction.rs"),
    ] {
        let extraction = Path::new(&manifest_dir).join(format!("../formal/kani/src/{module}.rs"));
        println!("cargo:rerun-if-changed={}", extraction.display());
        materialize(&extraction, &Path::new(&out_dir).join(out_name));
    }
}

/// Copy one extraction into `OUT_DIR`, turning `//!` into `//`.
///
/// When the file is absent (a slim checkout, a published crate) a stub is
/// written instead of failing the build; each differential test asserts on
/// `EXTRACTION_PRESENT`, so a silent skip cannot masquerade as a pass.
fn materialize(extraction: &Path, destination: &Path) {
    let Ok(source) = std::fs::read_to_string(extraction) else {
        write_or_fail(
            destination,
            "// Kani extraction not present in this checkout.\n\
             pub const EXTRACTION_PRESENT: bool = false;\n",
        );
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

    write_or_fail(destination, &rewritten);
}

fn write_or_fail(destination: &Path, contents: &str) {
    if let Err(error) = std::fs::write(destination, contents) {
        fail(&format!(
            "could not write {}: {error}",
            destination.display()
        ));
    }
}
