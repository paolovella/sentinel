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

## TAINT-MODEL-DRIFT — found, then closed

Found 2026-08-24 by the differential binding, and passing
`check-verus-parity.sh` the whole time. **Fixed the same day.**

Two kernels modelled `minimum_trust_tier_for_sink` and neither described the
shipped function. `verified_source_taint` modelled `SinkClass` as six classes
with an `else -> UNKNOWN` fail-safe; `verified_trust_lattice` used a third
mapping again, under a doc comment claiming to mirror production. Production
ships nine classes. All three agreed only at rank 0.

The concerning half was `verified_source_taint` at ranks 4..=5, where the
kernel demanded `Verified` and the shipped code accepts `High` — a guarantee
claimed that the code did not provide. Everything else was
production-stricter, so nothing was under-enforced.

**Resolution.** Both kernels were corrected to the shipped nine-variant mapping
and re-verified under Verus (`verified_source_taint` 21 verified / 0 errors,
`verified_trust_lattice` 29 / 0 — unchanged counts, with three more lemma
obligations in the first). The lemma indices in `verified_source_taint` were
wrong too: `4` and `5` were labelled `CodeExecution` and `PolicyMutation` when
those ranks are `MemoryWrite` and `ApprovalUi`; the privileged-sink and
quarantine lemmas now cover all nine classes at the right indices. The
out-of-range branch was changed from `UNKNOWN` to `VERIFIED` so an unreachable
input fails closed rather than open.

The pins that recorded the divergence are replaced by
`test_both_kernels_and_production_agree_on_every_sink_class`, which asserts
full three-way agreement so the drift cannot reopen silently, and by
`test_shipped_sink_thresholds_are_monotone`, which checks the shipped mapping
satisfies the monotonicity `lemma_sink_threshold_monotone` proves.

All nine sink classes are now bound across all seven trust tiers, so
`verified_source_taint` and `verified_trust_lattice` move from *partial* to
fully discharged.

## ENTROPY-CONFIG-1 — a kernel precondition established somewhere else

`formal/verus/verified_entropy_pipeline.rs` guards both `spec_should_alert` and
`spec_alert_severity` with `min_observations > 0`. The shipped predicates in
`vellaveto-engine/src/verified_entropy_gate.rs` carry no such guard: at
`min_entropy_observations == 0`, `high_entropy_count >= 0` is always true and
every call alerts — the flood R231-COLL-1 fixed.

Production closes it, but in `CollusionConfig::validate()`
(`vellaveto-engine/src/collusion.rs`), not in the predicate. So the kernel's
guarantee is real *only for validated configurations*, and that precondition is
carried by a different function in a different module.

This is not a defect; it is an assumption that was implicit and is now named.
The binding asserts both halves — the divergence at zero, and the validation
that makes it unreachable — so the guarantee cannot lose its foundation
silently. Removing the guard from `validate()` fails
`test_pinned_zero_observation_divergence_and_its_guard`.

For every validated configuration the kernel and the shipped predicates agree,
across 9×9 count/threshold pairs including both `u32` extremes.

**Deliberately not "fixed".** Unlike TAINT-MODEL-DRIFT, changing either side
here would make the system worse:

- Making the shipped predicate return "no alert" at zero would mean that if an
  unvalidated zero config ever reached it, entropy detection would **silently
  disable**. Missing detections is a worse failure than the alert flood
  R231-COLL-1 fixed.
- Making the kernel model the always-alert behaviour would be formalising the
  flood as correct.

The real defence is the config rejection, and it is already there. What was
missing was that the dependency was invisible — the kernel appeared to model a
guard production did not have. It is now named, asserted at both ends, and
cannot lose its foundation without failing a test. That is the fix.

## PATH-DECODE-1 — the kernel models the post-decode stage only

`formal/verus/verified_path.rs` models path normalization as: split on `/`,
skip empty and `.`, pop on `..`, render with a leading `/`. It does not model
percent-decoding — the byte `0x25` appears nowhere in it.

Production layers a decode loop on top. `normalize_path` calls
`normalize_path_bounded`, which iteratively percent-decodes until stable and
fails closed at `DEFAULT_MAX_PATH_DECODE_ITERATIONS`, and only then runs the
stage the kernel models (`normalize_decoded_path`).

So the binding targets `normalize_decoded_path`, and it holds exactly: across
1,365 byte strings over `/ . a NUL` the shipped function and the kernel's spec
agree on every input, accepted and rejected alike, including the postconditions
the kernel proves of its output — no surviving `..` component, no surviving
null, always rooted.

**The decode loop is outside the proof.** Nothing in the Verus program says the
iterative decode terminates, stabilizes, or cannot be used to smuggle a `..`
past the normalizer. That is covered by tests and by the Kani harnesses in
`formal/kani/src/path.rs`, not by this kernel, and no claim about
`normalize_path` should be sourced to it.

## AUDIT-LEGACY-1 — the composition kernel rejects what production accepts

`formal/verus/verified_audit_integrity.rs` restates chain-step validity with
`prev_seq == 0 || current_seq > prev_seq`, treating only a zero *predecessor* as
the legacy skip. Production's `sequence_monotonic` is
`current_seq == 0 || !has_prev || current_seq > prev_seq` — it also skips when
the *current* entry carries no sequence number, which is how pre-sequencing
audit entries are accepted.

So at `prev_seq = 5, current_seq = 0` production accepts and the kernel rejects.
The kernel is **stricter**, so nothing is under-enforced; the gap is that
AUDIT-INT-4 does not cover production's legacy-entry path, and no claim about
legacy entries should be sourced to it.

Asserted rather than skipped by `test_chain_step_matches_the_shipped_guards` in
`vellaveto-audit/src/verified_audit_append.rs`, in both directions: it fails if
the kernel starts accepting legacy entries (remove the carve-out) and if
production stops accepting them (the gap closed a different way).

### Why a composition kernel needs its own binding

`verified_audit_integrity` does not model a new function. It **restates**
primitives that `verified_audit_append` and `verified_audit_chain` already
model, then proves properties of composing them n times. That leaves a failure
the per-primitive bindings structurally cannot catch: the composition reasoning
about a *different* primitive than the one that ships, because it carries its
own copy of each definition.

The binding therefore checks the restated primitives against the shipped ones
first, and only then checks the n-step results against iterating the shipped
functions. AUDIT-LEGACY-1 is exactly what that first half is for.

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

**Two kinds of discharge.** Most kernels prove `exec == spec`, so the binding
transcribes the `spec` and asserts equality — a *transcription* discharge. A few
prove *properties* of a function rather than an algorithm it equals
(`verified_entropy_fixed_point` proves FP-WRAP-1..5). There is no `spec` to
restate, so the binding checks each property directly against shipped behaviour.
That is a **property** discharge and it is weaker in one specific way: it
establishes the named properties hold, not that the function is the one the
kernel reasoned about. It is recorded separately in the table for that reason.

**Equivalent mutants.** Mutation-verifying a property discharge can surface
mutants that change the text without changing behaviour. FP-WRAP-1 is enforced
jointly by a `clamp` and a range branch; removing either alone is equivalent,
and only removing both fails the test. A mutation that does not fail is not
automatically a hole — check whether it changed behaviour at all before
recording one.

**Discharge mechanism.** A differential test that transcribes the kernel's
`spec` function and asserts it agrees with the shipped function over an
exhaustively enumerated input space. Verus proves *exec == spec*; the
differential test binds *spec == shipped*; together they reach production.
`formal/tools/check-differential-parity.sh` runs them, and every discharge is
itself mutation-tested by `formal/tools/guard-selftest.sh` — a discharge that
cannot fail would reinstate the assumption while appearing to remove it.

**Measured trusted base (2026-08-24): 43 of 59 kernels bound (39 discharged + 3 partial + 1 property), 16 remain.**

An earlier revision of this count claimed every mirrored kernel was bound. That
was wrong: the survey looked only at `vellaveto-*/src/<kernel>.rs` and so missed
mirrors under a nested path (`inspection/verified_dlp_core.rs`,
`inspection/verified_cross_call_dlp.rs`) or a different filename
(`vellaveto-server/src/verified_approval_id.rs` for
`verified_server_approval_id`). All three are now bound. Enumerate mirrors with
`find vellaveto-*/src -name 'verified_*.rs'`, not a top-level glob.

A discharge is *total* where the enumeration covers the entire input domain and
*bounded* where it covers a chosen subset. The distinction matters and is not
collapsed here.

| Kernel | Discharge | Input space |
|---|---|---|
| `verified_capability_literal` | total | 2² per predicate |
| `verified_capability_identity` | total | 2¹/2²/2¹ |
| `verified_capability_coverage` | total | 2⁶ = 64 |
| `verified_capability_domain` | total | 2³/2²/2³/2⁴ |
| `verified_capability_pattern` | total + bounded | 2³ for the guard; 400 strings over `) * + > ? @ a` for metacharacter detection |
| `verified_capability_attenuation` | total + bounded | all 256 `u8` depths; 7⁴ = 2,401 expiry tuples around the overflow, clamp and ttl edges |
| `verified_capability_grant` | total + bounded | 2⁴ restriction combinations × 25 invocation pairs |
| `verified_capability_verification` | total + bounded | booleans totally; lengths exhaustive over `0..=128`; skew over a 10-value boundary set |
| `verified_capability_selection` | bounded | 32 tuples including both `usize` extremes |
| `verified_capability_glob` | bounded | 342,225 pairs — all strings of length 0–3 over `* ? @ A Z [ a z` |

| `verified_audit_chain` | total + bounded | 2⁶ for the step guards; 6×6 sequence pairs × both `has_prev` values |
| `verified_rotation_manifest` | total + bounded | 2³ and 2⁴ for the reference predicates; 5 file counts |
| `verified_audit_append` | bounded | 8-value `u64` boundary set built around zero and the saturation point |
| `verified_merkle` | bounded | 6×6 `u64` count pairs; sizes exhaustive over `0..=128` plus `usize::MAX` |
| `verified_merkle_fold` | **partial** | `next_level_len` only, exhaustive over `0..=1024` plus the top of the range; the abstract-hash fold obligations are not bound |
| `verified_merkle_path` | bounded | indices exhaustive over `0..=256` plus the top of the range; 65×65 sibling-lookup pairs |

| `verified_core` | total + bounded | all 1,536 `ResolvedMatch` inhabitants the spec distinguishes; every single-element policy list, then all lists of length 0..=4 over one representative per outcome |
| `verified_constraint_eval` | total + bounded | 2⁶ key predicates, 2⁵×3 = 96 conditional verdicts; forbidden-flag vectors of length 0..=4 |
| `verified_deputy` | total | all 256 depths and all 256×256 limit pairs; 2¹/2² allowance predicates |
| `verified_evaluation_context_projection` | total | 2³ × 256 = 2,048 |
| `verified_delegation_projection` | total | 2 × 256 = 512 |
| `verified_deputy_handoff`, `verified_bridge_principal`, `verified_transport_context` | total | 2²–2³ per predicate |
| `verified_approval_consumption`, `verified_approval_scope` | total | 2³ and 2⁶ |
| `verified_presented_approval_id` | total + bounded | 2² acceptance; lengths exhaustive over `0..=512` plus `usize::MAX` |
| `verified_capability_delegation_context` | total + bounded | 2⁷ booleans × 4⁴ depth tuples |
| `verified_context_delegation`, `verified_capability_context` | total + bounded | booleans totally; `u8` depths exhaustively; `usize` limits over a boundary set |
| `verified_nhi_delegation`, `verified_nhi_graph` | total + bounded | 2²/2⁴ link and status predicates; chain depth over a boundary set |
| `verified_entropy_gate` | bounded | boundary sets around the clamp point of `min_observations × 2` and around zero |
| `verified_capability_path` | bounded | 6 depths including both extremes × 4 flag combinations |
| `verified_audit_integrity` | **partial** | restated primitives checked against the shipped ones over a `u64` boundary set; n-step compositions over 0..=64 steps from 8 starting points; the `seen_hashed` latch over all 256 8-step hash patterns × 2 starts. The legacy zero-sequence path is asserted, not bound — see `AUDIT-LEGACY-1` |
| `verified_path` | bounded | 1,365 byte strings over `/ . a NUL`, matched against `normalize_decoded_path` on accept, reject and output; postconditions checked separately. Percent-decoding is out of scope — see `PATH-DECODE-1` |
| `verified_dlp_core` | total + bounded | all 256 `u8` boundary bytes; 341 byte strings over ASCII/lead/continuation × 6 sizes; 6⁵ field-budget tuples |
| `verified_cross_call_dlp` | bounded | 2 × 6⁵ counter tuples around the field cap, byte cap and addition overflow |
| `verified_server_approval_id` | total + bounded | 2² acceptance; lengths exhaustive over `0..=256` plus `usize::MAX` |
| `verified_entropy_fixed_point` | **property** | FP-WRAP-1..5 checked directly against the shipped conversion over a 24-value float sample reaching every branch |
| `verified_source_taint` | total | all 9 sink classes × 7 trust tiers; the trust-floor update over 7×7. Kernel corrected — see `TAINT-MODEL-DRIFT` |
| `verified_trust_lattice` | total | join, meet, `can_flow_to` and the declassification escape over 7×7×2 and 7×9×2; rank bounds for all tiers and sinks; sink mapping over all 9 classes. Kernel corrected — see `TAINT-MODEL-DRIFT` |
| `verified_entropy_pipeline` | **partial** | bound over 9×9 count/threshold pairs for every validated configuration; the `min_observations == 0` case is pinned, not bound — see `ENTROPY-CONFIG-1` |

Alphabets and boundary sets are chosen against each proof's dependencies rather
than for coverage. In the glob case `@` (0x40) and `[` (0x5B) sit immediately
outside `A..=Z` so widening the fold range either way is caught; in the pattern
case `)`/`+` and `>`/`@` bracket `*` (0x2a) and `?` (0x3f) for the same reason.

Every discharge was mutation-verified on 2026-08-24: sixty-six semantic mutations
across the thirty-seven kernels — fail-open containment, a widened invocation budget, a
wrapping delegation depth, an unclamped expiry, a wildcard child slipping past an
exact parent, last-match-wins grant selection, and a relaxed key-length check —
each fails its differential test. On the audit and Merkle side: an entry counter
that wraps instead of saturating, a rotation that restarts the count at 1, a
sequence number permitted to repeat, accepted non-UTC timestamps, a hashed entry
allowed to drop its hash, a permitted path traversal in a rotated-file
reference, a relaxed sibling-hash length, an append past capacity, an inverted
Merkle proof side, and an off-by-one parent index. Six representative cases —
one per input shape and per family — are pinned permanently in
`formal/tools/guard-selftest.sh`.

Three shapes of undischarged kernel exist and they are not equally tractable:

- **Mirrored** — the kernel pairs with an extracted `verified_*.rs` module whose
  functions are small and pure. These discharge the way the fifteen above did,
  and are the cheapest remaining work.
- **Inline** — the kernel pairs directly with a large hot-path file and the
  logic it models was never factored out. `verified_capability_chain`,
  `verified_audit_integrity`, `verified_merkle_integrity`, `verified_path`,
  `verified_dlp_core`, `verified_trust_lattice`, `verified_source_taint`,
  `verified_intent_scope` and the ACIS, refinement, entropy-pipeline and
  evidence-signing kernels are the examples:
  `check-verus-parity.sh` pairs each against a whole production file, so there
  is no function to transcribe against. Discharging these needs the production
  logic extracted into a mirror first — a code change, not only a test change.
- **Inline within a mirror** — a mirror file exists, but the predicates the
  kernel models were never given names in it. `verified_capability_glob_subset`
  is the only one: its `spec_glob_subset_fast_path` and
  `spec_glob_subset_accepting_counterexample` correspond to expressions inside
  the BFS product-automaton loop of `glob_pattern_subset`, not to functions, so
  there is nothing to call from a differential test. It needs the same
  extraction as the inline kernels.
- **Abstract** — the kernel's specs range over opaque values rather than
  concrete ones. `verified_merkle_fold` states its fold over `Seq<Seq<int>>`
  hashes, so a differential test would have to supply a *hash model*, and a
  binding against a modelled hash establishes materially less than one against
  a pure function. Its `next_level_len` is bound (marked **partial** above);
  the fold obligations stay under `PARITY-HAND-1` and are deliberately not
  counted as discharged.

The remaining 16 kernels are listed in `PROOF_OWNER_LEDGER.md`. Until each has a
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
