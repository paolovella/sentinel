# Formal Assumption Registry

Last updated: 2026-03-07

This is the canonical local registry for trusted formal assumptions.
Every explicit trust-boundary artifact in `formal/` must be named here before
it is considered part of the reviewed proof surface.

## Canonical Rule

- if a proof introduces or depends on a trusted assumption, register it here
  before landing
- if a trusted assumption is discharged, remove or mark it discharged here and
  then clean up the subordinate artifact
- if a proof escape hatch exists in Verus, Lean, or Coq, it must also appear in
  `formal/trusted-assumptions.allowlist`

## Assumption Families

| ID | Scope | Canonical Artifact | Current Enforcement |
|----|-------|--------------------|---------------------|
| `VERUS-ESCAPE-1` | Remaining proof escape hatches (`assume`, `axiom`, external-body/spec markers, Lean `axiom`, Coq `Axiom`/`Parameter`) | `formal/trusted-assumptions.allowlist` | checked by `formal/tools/check-formal-trusted-assumptions.sh` |
| `MERKLE-HASH-1` | RFC 6962 leaf/internal hash construction is implemented as specified | `formal/MERKLE_TRUST_BOUNDARY.md` | documented local trust boundary |
| `MERKLE-HASH-2` | SHA-256 retains the standard collision and second-preimage resistance assumptions | `formal/MERKLE_TRUST_BOUNDARY.md` | documented local trust boundary |
| `MERKLE-CODEC-1` | Hex encoding/decoding preserves 32-byte Merkle hashes | `formal/MERKLE_TRUST_BOUNDARY.md` | **partially discharged** — K141 (per-byte roundtrip, all 256 byte values, Kani CBMC) + K142 (length invariant: N bytes → 2N chars) prove the per-byte correctness from which the 32-byte roundtrip follows by byte-independence |
| `AUDIT-FS-1` | Append writes target the intended audit or Merkle file | `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` | documented local trust boundary |
| `AUDIT-FS-2` | `flush()` and `sync_data()` match the intended durability model | `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` | documented local trust boundary |
| `AUDIT-FS-3` | `metadata()` and `read()` reflect the current on-disk state | `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` | documented local trust boundary |
| `AUDIT-FS-4` | `truncate`/`set_len` preserves the valid prefix during Merkle recovery | `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` | documented local trust boundary |
| `AUDIT-FS-5` | `rename` preserves cross-rotation continuity for audit segments and leaf files | `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` | documented local trust boundary |
| `FLOAT-CONV-1` | `entropy_fixed_point` output always in [0, 8000] (from the explicit three-way range check at function exit; `as u16` cast safe because 8000 < u16::MAX) | `formal/verus/float_boundary_axioms.rs` | `axiom_entropy_conv_bounded` in allowlist |
| `FLOAT-CONV-2` | Non-finite f64 inputs (NaN, ±∞) map to 0 (from the unconditional `!is_finite()` guard at function entry per IEEE 754) | `formal/verus/float_boundary_axioms.rs` | `axiom_entropy_conv_nonfinite_zero` in allowlist |
| `FLOAT-CONV-3` | `floor(y) ≤ ceil(y)` for any y ∈ [0.0, 8000.0] — threshold (floor) is at most observation (ceil) for the same input | `formal/verus/float_boundary_axioms.rs` | `axiom_entropy_conv_floor_le_ceil` in allowlist |
| `FLOAT-CONV-4` | Monotone ordering: if actual ≥ threshold (finite, float domain) then `ceil(actual×1000) ≥ floor(threshold×1000)` — no false negatives from conservative rounding | `formal/verus/float_boundary_axioms.rs` | `axiom_entropy_conv_ordering` in allowlist |

| `PARITY-HAND-1` | Each Verus kernel and its production mirror implement the same function. The two sides are **structurally different** implementations (kernels are index-based over `Vec<u8>` with an explicit `decreases`; mirrors are slice-based with `split_first()`), so this correspondence is established **by hand** and is not checked by any tool. | `formal/verus/*.rs` ↔ `vellaveto-*/src/verified_*.rs` | **undischarged** — `check-verus-parity.sh` checks symbol *existence* only; measured by `formal/tools/guard-selftest.sh` |
| `PARITY-HAND-2` | Each Kani extracted module and its production counterpart implement the same function. `formal/kani/Cargo.toml` states the extracted code "is tested to be identical to the production code via the CI diff check"; **no such diff check exists**, and the crate has no dependency on the production crates. | `formal/kani/src/*.rs` ↔ `vellaveto-*/src/*.rs` | **undischarged** — in-crate `test_*_parity` functions are hardcoded vectors asserted against Kani's own copy |

## Parity Assumptions (PARITY-HAND-*)

`PARITY-HAND-1` and `PARITY-HAND-2` are the load-bearing undischarged
assumptions in this registry. Everything a Verus or Kani proof establishes
reaches shipped behaviour only through them.

They were measured on 2026-08-24 by mutating production mirrors and observing
whether anything fired:

| Mutation to `vellaveto-mcp/src/verified_capability_glob.rs` | `check-verus-parity.sh` | crate test suite |
|---|---|---|
| body replaced with `return true` (containment disabled) | PASSED | 3 failures |
| case-fold `A..Z` → `A..<Z` (breaks folding for `Z` only) | PASSED | **1950 passed, 0 failed** |
| `?` widened to zero-or-one (fail-open) | PASSED | 2 failures |

The second row is the shape of the problem: a one-character semantic change that
no guard and no test detects, while the kernel continues to prove
case-insensitivity as a universal property.

**Discharge mechanism.** A differential test that transcribes the kernel's
`spec` function and asserts it agrees with the shipped function over an
exhaustively enumerated input space. Verus proves *exec == spec*; the
differential test binds *spec == shipped*; together they reach production.
`formal/tools/check-differential-parity.sh` runs them, and every discharge is
itself mutation-tested by `formal/tools/guard-selftest.sh` — a discharge that
cannot fail would reinstate the assumption while appearing to remove it.

**Measured trusted base (2026-08-24): 1 of 59 kernels discharged, 58 remain.**

| Kernel | Discharged by | Input space |
|---|---|---|
| `verified_capability_glob` | `vellaveto-mcp/src/verified_capability_glob.rs::verus_spec_differential` | 342,225 pairs — all strings of length 0–3 over `* ? @ A Z [ a z` |

The alphabet is chosen against the proof's dependencies rather than for
coverage: `*` and `?` drive the metacharacter branches, `A`/`a` and `Z`/`z`
drive case folding, and `@` (0x40) and `[` (0x5B) sit immediately outside
`A..=Z` so widening the fold range in either direction is caught. The three
mutations that defeated `check-verus-parity.sh` each fail this test with a
concrete counterexample; the `A..<Z` mutation, which passed all 1,950 crate
tests, fails on `parent="Z" child="z"`.

The remaining 58 kernels are listed in `PROOF_OWNER_LEDGER.md`. Until each has a
differential binding, its proof constrains the kernel and not the shipped code,
and no claim should say otherwise.

## Artifact Map

| Artifact | Role | Status |
|----------|------|--------|
| `formal/trusted-assumptions.allowlist` | machine-checked inventory of proof escape hatches | active |
| `formal/verus/assumptions.rs` | shared Verus-facing kernel-assumption map that binds standalone kernels to the named trusted boundary | active |
| `formal/verus/merkle_boundary_axioms.rs` | proof-facing trusted Merkle hash/codec axioms mirroring `MERKLE-HASH-*` and `MERKLE-CODEC-1` | active |
| `formal/verus/audit_fs_boundary_axioms.rs` | proof-facing trusted filesystem axioms mirroring `AUDIT-FS-*` | active |
| `formal/verus/float_boundary_axioms.rs` | proof-facing trusted float-to-fixed conversion axioms mirroring `FLOAT-CONV-1–4` | active |
| `formal/MERKLE_TRUST_BOUNDARY.md` | concrete Merkle hash and codec assumptions | active |
| `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` | audit append/rotation/Merkle filesystem assumptions | active |
| `formal/kani/src/merkle_codec.rs` | Kani K141-K142: partial discharge of MERKLE-CODEC-1 (per-byte roundtrip + length invariant) | active — partially discharges MERKLE-CODEC-1 |

## Current Gap

The Verus suite now shares `formal/verus/assumptions.rs`, and
`formal/tools/check-formal-trusted-assumptions.sh` enforces that each
standalone kernel binds itself to the expected named assumption contract rather
than the whole shared boundary. The Merkle and audit-filesystem trust
boundaries are now also mirrored as explicit proof-facing Verus axiom modules.
The remaining gap is no longer naming the boundary; it is eventually
discharging or further refining those trusted axioms against concrete exec/codec
semantics if we want to shrink the trusted base further.
