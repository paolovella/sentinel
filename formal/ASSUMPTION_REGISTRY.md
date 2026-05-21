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
| `MERKLE-CODEC-1` | Hex encoding/decoding preserves 32-byte Merkle hashes | `formal/MERKLE_TRUST_BOUNDARY.md` | documented local trust boundary |
| `AUDIT-FS-1` | Append writes target the intended audit or Merkle file | `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` | documented local trust boundary |
| `AUDIT-FS-2` | `flush()` and `sync_data()` match the intended durability model | `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` | documented local trust boundary |
| `AUDIT-FS-3` | `metadata()` and `read()` reflect the current on-disk state | `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` | documented local trust boundary |
| `AUDIT-FS-4` | `truncate`/`set_len` preserves the valid prefix during Merkle recovery | `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` | documented local trust boundary |
| `AUDIT-FS-5` | `rename` preserves cross-rotation continuity for audit segments and leaf files | `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` | documented local trust boundary |
| `FLOAT-CONV-1` | `entropy_fixed_point` output always in [0, 8000] (from the explicit three-way range check at function exit; `as u16` cast safe because 8000 < u16::MAX) | `formal/verus/float_boundary_axioms.rs` | `axiom_entropy_conv_bounded` in allowlist |
| `FLOAT-CONV-2` | Non-finite f64 inputs (NaN, ±∞) map to 0 (from the unconditional `!is_finite()` guard at function entry per IEEE 754) | `formal/verus/float_boundary_axioms.rs` | `axiom_entropy_conv_nonfinite_zero` in allowlist |
| `FLOAT-CONV-3` | `floor(y) ≤ ceil(y)` for any y ∈ [0.0, 8000.0] — threshold (floor) is at most observation (ceil) for the same input | `formal/verus/float_boundary_axioms.rs` | `axiom_entropy_conv_floor_le_ceil` in allowlist |
| `FLOAT-CONV-4` | Monotone ordering: if actual ≥ threshold (finite, float domain) then `ceil(actual×1000) ≥ floor(threshold×1000)` — no false negatives from conservative rounding | `formal/verus/float_boundary_axioms.rs` | `axiom_entropy_conv_ordering` in allowlist |

## Artifact Map

| Artifact | Role | Status |
|----------|------|--------|
| `formal/trusted-assumptions.allowlist` | machine-checked inventory of proof escape hatches | active |
| `formal/verus/assumptions.rs` | shared Verus-facing kernel-assumption map that binds standalone kernels to the named trusted boundary | active |
| `formal/verus/merkle_boundary_axioms.rs` | proof-facing trusted Merkle hash/codec axioms mirroring `MERKLE-HASH-*` and `MERKLE-CODEC-1` | active |
| `formal/verus/audit_fs_boundary_axioms.rs` | proof-facing trusted filesystem axioms mirroring `AUDIT-FS-*` | active |
| `formal/MERKLE_TRUST_BOUNDARY.md` | concrete Merkle hash and codec assumptions | active |
| `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` | audit append/rotation/Merkle filesystem assumptions | active |

## Current Gap

The Verus suite now shares `formal/verus/assumptions.rs`, and
`formal/tools/check-formal-trusted-assumptions.sh` enforces that each
standalone kernel binds itself to the expected named assumption contract rather
than the whole shared boundary. The Merkle and audit-filesystem trust
boundaries are now also mirrored as explicit proof-facing Verus axiom modules.
The remaining gap is no longer naming the boundary; it is eventually
discharging or further refining those trusted axioms against concrete exec/codec
semantics if we want to shrink the trusted base further.
