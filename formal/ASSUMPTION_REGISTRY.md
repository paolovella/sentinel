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
| `SORT-IDEM-1` | `sort(sort(x)) == sort(x)` for the ACIS target-path and target-domain ordering. Stated as a spec function returning `true`, so every lemma that ensures it is discharged vacuously. | `formal/verus/verified_acis_action_summary.rs` | `spec_sort_idempotent` in allowlist (kind `verus-vacuous-spec`) |
| `REVOKE-DEPTH-1` | A transitive revocation that exceeds `MAX_TRANSITIVE_REVOKE_DEPTH` is caught downstream by chain resolution (NHI-DEL-8), so the BFS may stop at the bound without leaving an active link. Stated as a spec function returning `true`. | `formal/verus/verified_transitive_revoke.rs` | `assumption_depth_exceeded_caught_by_chain_resolution` in allowlist (kind `verus-vacuous-spec`) |
| `FLOAT-CONV-1` | `entropy_fixed_point` output always in [0, 8000] (from the explicit three-way range check at function exit; `as u16` cast safe because 8000 < u16::MAX) | `formal/verus/float_boundary_axioms.rs` | `axiom_entropy_conv_bounded` in allowlist |
| `FLOAT-CONV-2` | Non-finite f64 inputs (NaN, ±∞) map to 0 (from the unconditional `!is_finite()` guard at function entry per IEEE 754) | `formal/verus/float_boundary_axioms.rs` | `axiom_entropy_conv_nonfinite_zero` in allowlist |
| `FLOAT-CONV-3` | `floor(y) ≤ ceil(y)` for any y ∈ [0.0, 8000.0] — threshold (floor) is at most observation (ceil) for the same input | `formal/verus/float_boundary_axioms.rs` | `axiom_entropy_conv_floor_le_ceil` in allowlist |
| `FLOAT-CONV-4` | Monotone ordering: if actual ≥ threshold (finite, float domain) then `ceil(actual×1000) ≥ floor(threshold×1000)` — no false negatives from conservative rounding | `formal/verus/float_boundary_axioms.rs` | `axiom_entropy_conv_ordering` in allowlist |

| `PARITY-HAND-1` | Each Verus kernel and its production mirror implement the same function. The two sides are **structurally different** implementations (kernels are index-based over `Vec<u8>` with an explicit `decreases`; mirrors are slice-based with `split_first()`), so this correspondence is established **by hand** and is not checked by any tool. | `formal/verus/*.rs` ↔ `vellaveto-*/src/verified_*.rs` | **undischarged** — `check-verus-parity.sh` checks symbol *existence* only; measured by `formal/tools/guard-selftest.sh` |
| `PARITY-HAND-2` | Each Kani extracted module and its production counterpart implement the same function. `formal/kani/Cargo.toml` states the extracted code "is tested to be identical to the production code via the CI diff check"; no such diff check existed, and the crate has no dependency on the production crates. | `formal/kani/src/*.rs` ↔ `vellaveto-*/src/*.rs` | **14 of 33 discharged** (2026-08-28/30) — `path.rs`, `ip.rs`, `cache.rs`, `domain.rs`, `rule_check.rs` (in `vellaveto-engine`), `unicode.rs` (in `vellaveto-types`), `webhook_dedup.rs` (in `vellaveto-server`) `sanitizer.rs` + `credential_vault.rs` (in `vellaveto-mcp-shield`) and `injection_pipeline.rs` + `dlp_core.rs` + `task.rs` + `transitive_revoke.rs` + `capability.rs` (in `vellaveto-mcp`) are compiled into the production crates' test builds and compared against production, mutation-verified 6/6, 6/6, 4/4, 5/5, 4/4, 4/4, 5/5, 4/4, 7/7, 4/4, 9/9, 6/6, 5/5 and 5/5; see `KANI-PATH-BOUND-1` and `KANI-CACHE-DRIFT-1`. The other 19 extractions remain undischarged: their in-crate `test_*_parity` functions are hardcoded vectors asserted against Kani's own copy |

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

## MODEL-SHAPE-1/2 — kernels modelling a design production did not implement

Found 2026-08-24 while attempting to bind them; **closed 2026-08-28 by building
the design**, which is the option chosen over reshaping the kernels to match
production. Both had passed `check-verus-parity.sh`, which pairs them by
*symbol name* against production files whose structures were unrelated to what
the kernel modelled.

Unlike TAINT-MODEL-DRIFT (a wrong value in a right-shaped model) these two
modelled a **different design**. Building it surfaced `SCOPE-NOOP-1` below,
which no test in the workspace had caught.

### MODEL-SHAPE-1 — `verified_intent_scope`

The kernel modelled scope as `ScopeState { allowed_mask, .. }`, a bitmask, with
restriction as bitwise AND. Production modelled it as
`IntentScopeConfig { allowed_sink_classes: Vec<SinkClass>, .. }` under the
convention *empty means everything is allowed*.

Both mismatches are now closed:

- **Representation.** `vellaveto-types/src/verified_intent_scope.rs` defines
  `ScopeMask`, and `restrict` is the bitwise AND the kernel proves. The config
  surface keeps `allowed_sink_classes`; the empty-means-everything convention is
  converted to an explicit value at exactly one place,
  `ScopeMask::from_config_sink_classes`. Downstream, "allow nothing"
  (`ScopeMask::NONE`) and "allow everything" (`ScopeMask::ALL`) are different
  values, which is what makes intersection genuinely narrowing.
- **Width.** The mask is `u16` and `SCOPE_CLASS_COUNT` is 9. The kernel's `u8`
  could not represent rank 8 — `PolicyMutation`, the highest-privilege sink — so
  `spec_in_scope` returned false for it unconditionally. The kernel was widened
  to match, the same correction applied to the taint kernels under
  `TAINT-MODEL-DRIFT`. Re-verified: 16 verified, 0 errors.

### MODEL-SHAPE-2 — `verified_sequence_analysis`

The kernel modelled a restriction gate built from `RESTRICTION_THRESHOLD` and
`WARMUP_CALLS`, and proved properties of it.

The original entry said neither constant existed anywhere in the workspace.
That was too strong, and is corrected here: `warmup_calls` existed as a
`SequenceConfig` field defaulting to 3, and the threshold existed as a bare
literal `70` at one relay call site. What was true is that neither was **named**
and no gate was built from them — the call site's result was discarded with
`let _ = restricted`.

The gate now exists as `vellaveto-engine/src/verified_sequence_gate.rs`
(`should_restrict`, `warmup_complete`, `update_confidence`,
`update_anomaly_detected`, `new_tool_budget_available`, `is_taint_restricted`,
`increment_new_tools`), drives `SequenceConfig::default()`, and decides at the
relay call site. Confidence is `u32` on both sides now: production's
`SequenceAnomaly.confidence` is `u32`, and the kernel's `u8` was an arbitrary
narrowing rather than a claim about the value. Re-verified: 22 verified,
0 errors.

Both are bound and mutation-verified — 6/6 and 8/8.

## SCOPE-NOOP-1 — taint-driven scope narrowing did nothing

Found 2026-08-28 while building the design for `MODEL-SHAPE-1`. Fixed in the
same change.

`IntentScopeConfig::restrict_to_trust_floor` narrowed the session's scope by
**filtering `allowed_sink_classes`**. An empty `allowed_sink_classes` means
"unrestricted", and filtering an empty list yields an empty list — so
restricting the default configuration narrowed nothing at all:

```
let scope = IntentScopeConfig::default();          // allowed_sink_classes: []
let restricted = scope.restrict_to_trust_floor(TrustTier::Quarantined);
restricted.check_in_scope("t", SinkClass::PolicyMutation)  // => InScope
```

`PolicyMutation`, the highest-privilege sink there is, stayed in scope after a
restriction to `Quarantined`, the lowest trust floor there is. The kernel proves
SCOPE-1 and SCOPE-2 — restriction is a subset, scope only narrows — and both
were false in production for the default configuration.

Two further holes were open around it, both closed in the same change:

- **The result was discarded.** Both relay call sites computed `restricted` and
  threw it away (`let _ = restricted; // full enforcement in 6.2C`). Narrowing
  never persisted, so even a correct restriction would not have survived to the
  next call. `RelayState` now carries `session_scope`, and successive narrowings
  compose from the scope in force rather than from the immutable per-relay
  config.
- **Nothing consulted the scope.** `check_in_scope` had no caller anywhere in
  the relay. It is now called on the tool-call path before forwarding, honouring
  `out_of_scope_action`. `Deny` and `RequireApproval` both refuse: the stdio
  relay has no interactive approval channel on that path, so `RequireApproval`
  is honoured in the fail-closed direction rather than degraded to an allow.
  That is stricter than an operator configuring `RequireApproval` may expect,
  and is called out here rather than left to be discovered.

Nothing in the workspace's 11,800+ tests caught this. The kernel had been
proving the property since Phase 6.2E; what was missing was any path from the
proof to the code, which is what this campaign has been closing.

## A difference that is not drift — `spec_spans_junction`

Worth recording because it looked like a finding and was not.

`verified_cross_call_split` defines `spec_spans_junction`, and production's
`scan_with_overlap` visibly declines to filter on it:

```rust
let _ = overlap_len; // used conceptually; all cross-call findings reported
```

Checking the lemmas rather than the spec names settles it. `spec_spans_junction`
appears only as a *hypothesis* of `lemma_junction_range_is_substring` — "if a
range spans the junction, it is a substring of combined" — never as an
obligation production must discharge. Every other lemma is about coverage:
combined length is the sum, the tail survives as a prefix, the current value as
a suffix.

So production reporting every finding from the combined scan is a **superset**,
which is the safe direction for a detector, and the comment explains why: a
partial match in the overlap may only become complete with the new data.

The rule: a spec function that has no production counterpart is not evidence of
drift until you check whether any lemma *requires* one. Several of these kernels
define helper predicates purely to state a hypothesis.

## VACUOUS-SPEC-1 — two axioms that escaped the escape-hatch inventory

Found 2026-08-24. **Fixed the same day**, detector included.

`check-formal-trusted-assumptions.sh` is the machine-checked inventory of proof
escape hatches. It scans for `assume`/`admit`, `axiom fn`,
`verifier::external_body` and `verifier::external_fn_specification` — all
keyword greps, all single-line.

A `pub open spec fn` whose entire body is `true` is an axiom in disguise: every
lemma that `ensures` it is discharged vacuously and establishes nothing. It
contains none of those keywords, and its body spans two lines, so a line-based
grep cannot match it. The inventory could not see this class at all.

A sweep of `formal/verus/` found eleven vacuous spec bodies. Nine are the
registration markers in `assumptions.rs`, which are vacuous by design and are
checked separately by `check_verus_kernel_assumption_bindings`. **Two were real
trusted assumptions that appeared nowhere** — not in the allowlist, not in this
registry, not routed through `assumptions.rs`:

- `spec_sort_idempotent` — "Axiomatized: sort(sort(x)) == sort(x) for any total
  ordering", now `SORT-IDEM-1`.
- `assumption_depth_exceeded_caught_by_chain_resolution` — labelled "Trusted
  assumption — see NHI-DEL-8" in its own comment, now `REVOKE-DEPTH-1`.

The second is the sharper one: it was *explicitly named as a trusted assumption
in a code comment* and still escaped the inventory whose entire job is to
enumerate trusted assumptions.

**Resolution.** Both are registered above and in the allowlist under a new kind,
`verus-vacuous-spec`. `check-formal-trusted-assumptions.sh` gained a multi-line
detector for the class, so a new one cannot be added without either registering
it or failing the check. The detector is itself mutation-tested by
`formal/tools/guard-selftest.sh`.

## ACIS-DENY-REASON-1 — a proven invariant the validator did not enforce

Found 2026-08-24 by the differential binding. **Fixed the same day.**

`formal/verus/verified_acis_envelope.rs` proves
`lemma_acis_deny_has_nonempty_reason`: a `Deny` envelope carries a non-empty
reason. It is stated as a structural invariant of the envelope, part of
`spec_envelope_valid`.

`AcisDecisionEnvelope::validate()` bounded the reason's length and rejected
dangerous characters in it, but **never related `decision` to `reason`**. A
`Deny` with an empty reason validated cleanly.

Direction: the kernel was **stricter** than the shipped code, so nothing was
under-enforced — but since R244 made envelope validation the gate before audit
persistence, the invariant that a denial explains itself was being claimed by
the proof and not enforced by the code. A denial recorded without a reason is an
audit entry nobody can act on.

**Resolution.** `validate()` now enforces it. The tightening is safe: every
`Verdict::Deny` in the workspace is constructed with a `format!` reason, and
`build_acis_envelope` copies that reason straight through, so no production path
produced an empty one. Confirmed by the full suite — 7,917 unit tests across
seven crates and all 122 integration suites pass.

One integration fixture needed updating:
`test_acis_envelope_rejects_oversized_call_chain_depth` built a `Deny` with an
empty reason in order to test the *depth* bound, and now tripped the earlier
check. It was given a reason so it isolates the property it actually names.

### The validator alone was not enough

Tracing the call path after the fix showed a second problem the fix itself
introduced. `AuditLogger::log_entry_with_acis` returns `Err` **without writing
the entry** when validation fails, and both proxy call sites swallow that error
with a `tracing::warn!` and continue. So a `Deny` with an empty reason would
have gone from *"audit entry written with an empty reason"* to *"no audit entry
at all"* — strictly worse for a security control, and the opposite of the
intent.

Exposure was zero: every `Verdict::Deny` in the workspace is built with a
`format!` carrying literal text, and `build_acis_envelope` copies it through
unchanged. But the risk was structural — `log_entry_with_acis` is public API,
and the failure mode is a warn line nobody reads.

So the invariant is now established **at construction** as well.
`build_acis_envelope_with_security_context` substitutes a placeholder for an
empty `Deny` reason, and every envelope in the system is built through it
(`build_secondary_acis_envelope*` delegates to it). `validate()` stays strict
for externally-supplied envelopes; the builder guarantees internally-generated
ones. Removing the guard fails three tests in `vellaveto-mcp/src/mediation.rs`.

The general rule: before tightening a validator, check what the *caller* does
with the rejection. A validator that gates persistence turns "malformed record"
into "no record", and for audit data that trade is usually the wrong way round.

## REPLAY-NOTCHECKED-1 — a trust cap the kernel applies and production does not

`formal/verus/verified_replay_provenance.rs` defines
`spec_effective_trust_rank`, which caps trust by replay status:

| status | kernel | production (`infer_trust_tier`) |
|---|---|---|
| `ReplayDetected` | rank 0 (`Quarantined`) | `Some(Quarantined)` — agrees |
| `NotChecked` | capped at rank 1 (`Unknown`) | `None` — no tier inferred, no cap |
| `Fresh` | base trust unchanged | `None` — agrees in effect |

Measured, not inferred: a probe over all three statuses returned
`NotChecked -> None`, `Fresh -> None`, `ReplayDetected -> Some(Quarantined)`.

The kernel is **stricter**. Its rule is a fail-closed posture — *if replay
verification did not run, do not extend trust past `Unknown`* — and production
applies no cap, so a request whose replay status was never checked keeps
whatever base trust it had. Nothing is under-enforced relative to a stated
control; the gap is that the proof describes a containment production does not
implement.

The `ReplayDetected` half is fully bound, including the lattice properties: the
merge is commutative, idempotent, and absorbing at `ReplayDetected`, so a later
clean transport observation cannot launder a detected replay.

The `NotChecked` half is pinned by
`test_pinned_notchecked_cap_is_kernel_only`, which asserts the measured
behaviour in both directions rather than skipping it.

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

**Bind the value, not just the relation.** A transcription that writes the same
named constant on both sides of a comparison binds the *relation* and not the
*value*: raising the production constant moves both sides and the test still
passes. `verified_transitive_revoke` was written that way and a mutation raising
`MAX_TRANSITIVE_REVOKE_DEPTH` from 50 to 500 escaped. Pin the kernel's literal
in the transcription and assert the production constant equals it. Mutation
testing is what found this; nothing else would have.

A sweep of every binding for the same pattern found seventeen candidate sites.
Sixteen were safe — the constant was defined inside the differential module, so
it *is* the pinned literal. One was not: `verified_merkle`'s
`spec_proof_sibling_count_valid` reused production's `MAX_PROOF_SIBLINGS`, and a
mutation raising the cap from 64 to 4096 passed cleanly. Both are pinned now and
both mutations are permanent cases in `guard-selftest.sh`.

The distinction to check when reviewing a transcription: a constant defined
*inside* the `verus_spec_differential` module is the kernel's literal restated
and is fine; one reaching production through `use super::*` is the hole.

**A tamper-coverage binding needs two kinds of mutation.** Checking that a
signed payload covers a field means mutating it and requiring the digest to
move. Two failure modes escape a careless version of that, and mutation testing
found both in `verified_evidence_signing`:

- *Count versus content.* Clearing a `Vec` changes its length, which the payload
  hashes separately. Deleting the per-element hashing loop then survives. Test
  both — clear the collection **and** rewrite an element in place.
- *Boundary ambiguity.* Every case that changes total content still moves the
  digest even with the length prefix removed. Add a pair of inputs that differ
  only in *where* a field boundary falls (`"ab"`+`"c"` versus `"a"`+`"bc"`);
  without length framing those collide and a signature verifies across the
  tamper.

**A mutation that does not compile is not a mutation.** An ad-hoc mutation
harness that only greps for `test result: FAILED` reports a non-compiling tree
as `MISSED`, which reads as a hole in the binding when nothing was actually
tested. Classify three outcomes, and check them in this order: a failing test
first (a failing test *also* prints a line starting with `error:`), then
`^error\[` or `could not compile` as invalid, then missed. Getting that order
wrong misreports caught mutations as invalid.

**Domain separation needs the forgery, not just a difference.** Checking that a
leaf hash and an internal hash merely *differ* is too weak: dropping the RFC 6962
**leaf** prefix leaves them different anyway, because the internal prefix alone
still separates plain concatenations. The test has to construct the actual
second preimage — `hash_leaf(0x01 || left || right)` against
`hash_internal(left, right)` — which collide exactly when the leaf prefix is
missing. Mutation testing found this; the weaker check passed the mutant.

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

**Measured trusted base (2026-08-28): 59 of 59 kernels bound (47 discharged + 5 partial + 7 property).** The last two, `MODEL-SHAPE-1/2`, were closed by building the design their kernels described rather than by reshaping the kernels to fit production; doing so surfaced `SCOPE-NOOP-1`. Bound is not the same as strong — the discharge kind for each kernel is in the table above, and `PARITY-HAND-2` still stands over the mirror-to-kernel correspondence itself.

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
| `verified_acis_action_summary` | bounded | 900 length/count combinations at and either side of every bound the kernel names, in both directions; dangerous-character rejection probed with null, control, bidi and BOM |
| `verified_acis_envelope` | **partial** | 720 field combinations, necessary-condition only — the kernel models a subset of `validate()`, so kernel-rejects implies production-rejects. Found `ACIS-DENY-REASON-1` |
| `verified_capability_chain` | bounded | chain lengths 0..=64 from all 256 `u8` starting depths, checked against iterating the shipped depth primitive; 8-step expiry chains over 5×5 root/ttl pairs; step identity rules cross-checked against the shipped `verified_capability_identity` predicates |
| `verified_replay_provenance` | **partial** | `merge_replay_status` totally over all 9 status pairs plus commutativity, idempotence and absorption; `ReplayDetected` quarantine bound through `infer_trust_tier`. The `NotChecked` cap is pinned — see `REPLAY-NOTCHECKED-1` |
| `verified_evidence_signing` | **property** | tamper coverage — 20 named field mutations must each move `signing_content()`, plus a field-boundary ambiguity check; hex-length and count-consistency predicates bound directly |
| `verified_merkle_integrity` | **property** | the twelve derived lemmas checked against shipped hashing: 32-byte lengths, RFC 6962 domain separation including the second-preimage forgery, order sensitivity, corpus-distinctness, leaf-to-root propagation, and hex codec round-trip and injectivity. The collision-resistance axioms it rests on stay trusted — `MERKLE-HASH-1/2` |
| `verified_refinement_safety` | **property** | SAFETY-1..3 against the shipped `compute_verdict`: empty set denies, an all-miss trace of length 0..7 denies, and a first-matching deny contribution denies across 16 lead/trail shapes |
| `verified_refinement_completeness` | **property** | COMPLETENESS-1..5 against `compute_single_verdict`/`compute_verdict`: miss advances, hit decides, both non-deny terminal verdicts apply, and evaluation stops at the first deciding entry with the decisive one placed at every position |
| `verified_refinement_sort_stutter` | **property** | postcondition binding — all 120 permutations of a 5-policy corpus forcing each comparator tier; ordering totality; deny-override checked independently of the id tiebreak |
| `verified_cross_call_split` | **property** | CC-SPLIT-1..4 checked against the shipped `format!("{tail}{current}")` join over 36 piece pairs, plus every junction-spanning range of each; end-to-end, a secret split across two calls is detected by the overlap scan and by neither half alone |
| `verified_transitive_revoke` | total + bounded | link and collateral predicates over 2³; depth bound over a `usize` set around the limit and both extremes, with the literal 50 pinned |
| `verified_warm_restart` | total + bounded | `should_restore` over every `SessionState` variant, with a test forcing a new variant to be classified deliberately; capacity and counter over a `usize` set including both extremes |
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
- **Inline within a mirror** *(cleared 2026-08-28)* — a mirror file existed, but
  the predicates the kernel models were never given names in it.
  `verified_capability_glob_subset` was the only one: its
  `spec_glob_subset_fast_path`, `spec_glob_subset_accepting_counterexample` and
  `spec_representative_other_byte_needed` corresponded to expressions inside the
  BFS product-automaton loop of `glob_pattern_subset` and inside
  `capability_token.rs`, not to functions, so there was nothing to call from a
  differential test. All three are now named
  (`accepting_counterexample`, `representative_other_byte_needed`,
  `glob_subset_fast_path`), called on the shipped path, and bound over their
  total input domains. Routing the shipped `pattern_is_subset` through
  `glob_subset_fast_path` required hoisting it out of `grant_is_subset`; the two
  pre-existing verified helpers (`pattern_subset_guard`,
  `literal_child_pattern_subset`) were deliberately kept on the path so their
  own bindings do not lapse. The expensive branches stay lazily evaluated —
  `spec_glob_subset_fast_path` proves the result reads only the selected branch,
  which is what makes `false` sound for the other.
- **Abstract** — the kernel's specs range over opaque values rather than
  concrete ones. `verified_merkle_fold` states its fold over `Seq<Seq<int>>`
  hashes, so a differential test would have to supply a *hash model*, and a
  binding against a modelled hash establishes materially less than one against
  a pure function. Its `next_level_len` is bound (marked **partial** above);
  the fold obligations stay under `PARITY-HAND-1` and are deliberately not
  counted as discharged.

No kernel now lacks a differential binding. What each binding establishes still
varies — see the discharge kinds — and a binding constrains the shipped function
it names, not the whole subsystem around it.

## DRIFT-STORE-1 — approval drift is decided by two disjuncts, not one

`verified_approval_drift` models four predicates. Three of them
(`spec_trust_downgraded`, `spec_taint_accumulated`, `spec_drift_detected`)
already had a named production home in
`vellaveto_approval::check_approval_lineage_drift` and are bound against it
directly, over every ordered pair of the seven `TrustTier` ranks crossed with a
taint boundary set (784 comparisons).

The fourth, `spec_fail_closed_drift`, did not: the store-error disjunct existed
only as a local `drift_detected = true` in the relay's `Err(e)` arm. It is now
`vellaveto_approval::approval_refused_for_drift(store_error,
drift_reason_found)`, called from the relay, and bound over its total 2³ domain.

This is the disjunct that matters most and was the least visible: R265-RELAY-3
records that a store read failure once left drift undetected and let the
approval be consumed unverified. Mutation-verified 4/4 — inverting the trust
comparison, weakening the taint comparison to `>=`, dropping the trust check,
and making the store-error branch fail open are all caught.

## GUARD-COMMENT-1 — two new guard checks that a comment could satisfy

Found 2026-08-28, immediately after writing them, by mutation-testing the guard
checks added for `MODEL-SHAPE-1/2` rather than trusting that a passing check
means anything.

`check-verus-parity.sh` matches production patterns with line-based `grep`.
Two of the seven new checks passed against a tree where the thing they claimed
to check had been removed:

- **A comment satisfied the check.** The pattern was
  `verified_sequence_gate::should_restrict`. The relay's own explanatory comment
  contains that text, so replacing the actual call left the guard green.
- **A prefix satisfied the check.** The pattern was `fn narrow_session_scope`,
  which is a substring of `fn narrow_session_scope_disabled`. Renaming the
  function away did not trip it.

Both patterns now require a call or definition — the symbol followed by `(` —
and are anchored `^[^/]*` so a line comment cannot satisfy them. Re-tested: both
mutations are caught, along with commenting the call out entirely.

The general rule this adds to the ones above: **a grep-based guard must be
written so that prose cannot satisfy it, and so that a longer identifier
containing the pattern cannot either.** Eight cases covering these checks are
now in `formal/tools/guard-selftest.sh`, so the property is re-tested on every
run rather than established once by hand.

## KANI-PATH-BOUND-1 — the first Kani extractions actually compared to production

Added 2026-08-28. `PARITY-HAND-1` is now fully discharged (59 of 59 Verus
kernels); this begins the same work on the Kani side, which had none.

**What was claimed.** `formal/kani/src/path.rs` opens by stating it is a
"verbatim extraction from `vellaveto-engine/src/path.rs`", that "the algorithm
is identical", and that "this correspondence is verified by CI".

**What CI actually did.** The Kani job's *Verify extracted code correspondence*
step runs `cargo test --lib` **inside `formal/kani`**, where the assertions are
hardcoded vectors checked against Kani's own copy — the copy cannot disagree
with itself. *Verify extraction sync* runs `check-kani-parity.sh`, which greps
for symbol names. Neither compares the two implementations, and neither could:
`formal/kani` is excluded from the workspace and does not depend on the
production crates.

**What now happens.** `vellaveto-engine/src/kani_path_differential.rs` compiles
the extraction directly — `build.rs` materializes it into `OUT_DIR`, changing
only `//!` to `//` because Rust rejects inner attributes arriving from a macro
expansion — and compares it against production over a 54-input corpus, across
the decode-iteration bound from 0 to 8, and along the default limit. It runs in
the ordinary workspace test suite, so it gates every CI job rather than only the
Kani one.

**Two things the binding had to get right, both found by mutation testing:**

- **Compare the reason, not just the outcome.** The first version compared the
  `Ok` value and whether the input errored. Deleting the null-byte check on the
  raw input survived it, because the check inside the decode loop still
  rejected and both copies still returned `Err`. The extraction declares the
  error *type* as its only difference, so the reason string is comparable — and
  comparing it catches a check moving between branches in one copy only.
- **A missing extraction must not read as agreement.** `build.rs` degrades to a
  stub when the file is absent, so the comparison would pass against nothing.
  `EXTRACTION_PRESENT` is asserted.

Lints are suppressed on the extracted module rather than satisfied. Clippy
wants `manual_range_contains` and `implicit_saturating_sub` fixed in the
extraction; doing so would edit the copy the proofs run against so it no longer
matches what was extracted, which is the drift this binding exists to detect.

Mutation-verified 6/6: iteration bound 20→30, either null-byte check removed,
backslash normalization dropped, the limit comparison weakened to `>`, and the
parent-dir-at-root absorb removed are all caught.

**`ip.rs` followed the same day**, and needed a different shape. Its header
claims "each function is a verbatim translation of the production logic — the
only difference is the type representation (`[u8; 4]` vs `Ipv4Addr`, `[u16; 8]`
vs `Ipv6Addr`)", which makes textual comparison inapplicable: the binding builds
the `std::net` value from the same octets and requires the classifications to
agree. It sweeps all 65,536 `a.b.1.1` addresses — the classification branches
almost entirely on the first two octets, so that covers the branch structure
exhaustively in the dimension that matters rather than sampling 2^32 — plus the
boundary immediately outside each RFC range, the IPv6 transition mechanisms, and
K30's embedded-IPv4 recovery. Mutation-verified 6/6: CGNAT mask widened,
RFC 1918 `172.16/12` mask dropped, loopback and link-local checks removed, the
benchmarking mask narrowed, and `192.168/16` widened to `192/8`.

What rides on it: `is_private_ip` is what `block_private` enforces, so a
disagreement means the SSRF and DNS-rebinding proofs describe a classifier that
is not the one deciding.

One thing to know before mutating that file: the classifier appears **twice**,
in `is_private_ipv4` and again in `is_embedded_ipv4_reserved` (that duplication
is what K29's "parity" is about). A mutation anchored on the shared text hits
both; anchor on the first occurrence to test the function the sweep exercises.

**Remaining: 19 extractions.** The mechanism (build.rs materialization, a
corpus, and comparison of the reason and not only the outcome) is reusable, so
the remaining work is per-module corpus design rather than new machinery.

Four shapes have been seen: **verbatim** (`path.rs` — compile and compare
directly); **representation-shifted** (`ip.rs` — `[u8; 4]` vs `Ipv4Addr`, bridge
the declared difference); **modelled** (`cache.rs` — booleans standing in for a
struct, construct real values and map them); and **abstracted dependency**
(`domain.rs` — the third-party `idna` call is a symbolic parameter, so the
binding supplies the real result and compares the wrapper around it).

`domain.rs` is worth singling out. Abstracting `idna::domain_to_ascii` is the
right boundary and is declared, but nothing had checked that the wrapper
K61-K63 explore is the wrapper that runs — and that wrapper has a history.
R25-ENG-5: a wildcard prefix was not stripped before IDNA, so `*.münchen.de`
failed normalization, the pattern never matched, and internationalized domains
bypassed wildcard blocking. R39-ENG-3: malformed ASCII slipped past a blocklist
because some IDNA implementations accept whitespace and colons without error.
Both fail open. The binding is mutation-verified against exactly those two
regressions, plus trailing-dot stripping, the wildcard character in the
ASCII-lowercase fast path, and the SRV underscore allowance from R27-ENG-2.

### `unicode.rs` — a total discharge over the whole Unicode range

Added 2026-08-30. K64 (idempotence) and K65 (mapped confusables collapse to
ASCII) rest on a `normalize_confusable_char` described as "verbatim from
`vellaveto-types/src/unicode.rs:50-188`". Production inlines that mapping inside
`normalize_homoglyphs` rather than exposing a `char -> char` function, so the
comparison is made at the string level — equivalent, because production maps
characters independently — and over **every Unicode scalar value**
(`0..=0x10FFFF` minus surrogates, 1,112,064 of them). Chunked for speed, with a
per-character re-walk on any mismatching chunk so the failure names the exact
scalar.

That makes the mapping a **total** discharge rather than a sampled one: there is
no character on which the two can differ without the test saying so.

K64 and K65 are also restated against production rather than only against the
model, and the four canonical homoglyph attacks (Cyrillic `а`, Cyrillic `е`,
Greek omicron, fullwidth `ａ`) are asserted as behaviour rather than as a
character table.

Two guards against a vacuous pass: the scalar count is pinned (a shrunken
enumeration fails rather than passing quietly), and the sweep must find more
than 50 characters that actually change — two identity functions agree
everywhere, so agreement alone proves nothing.

What rides on it: `normalize_homoglyphs` feeds `normalize_full`, which decides
policy matching and cache keys. Mutation-verified 4/4 — Cyrillic `а` no longer
folding, the fullwidth range off by one at `ｚ`, fullwidth uppercase folding to
ASCII uppercase instead of lowercase, and Cyrillic `е` folding to the wrong
letter are all caught.

This is the first binding to require a `build.rs` in `vellaveto-types`; the
mechanism is otherwise identical to `vellaveto-engine`'s.

### `rule_check.rs` — derived inputs, not a free product

Added 2026-08-30. K41-K45 are the fail-closed properties of the path, network
and IP rule checks, proved over pure boolean predicates with glob matching
abstracted to `matches: bool` (globset is third-party — the right boundary).

The binding for the path predicate does **not** enumerate the free product of
its five booleans. Most of those 32 combinations are not realisable: a path
cannot be blocked when there are no paths. Comparing production against inputs
that cannot occur would prove nothing about the ones that can, and would fail
for reasons that are artefacts of the enumeration.

Instead it constructs real policies and actions — allowlist/blocklist present or
absent, crossed with six path sets covering allowed-only, blocked-and-allowed,
neither, and mixed — compiles them through `PolicyEngine::compile_policies`, and
**derives** the model's five booleans from the same `CompiledPathRules`
production is about to use. The two are given the same world rather than the
same guess about it.

A guard against a one-sided comparison: the scenarios must produce both denials
and passes, or they cannot distinguish a predicate that always denies.

K41 and K42 are also restated against production directly. K41 is R28-ENG-1 —
an allowlist with no target paths must deny, because absent paths mean the
extractor could not identify what the tool touches, so the allowlist cannot be
checked at all.

Mutation-verified 4/4: removing the K41 no-paths denial (reinstating the
R28-ENG-1 fail-open), removing the K42 blocked-beats-allowed denial, removing
allowlist enforcement entirely, and inverting the allowlist check are all
caught.

### `webhook_dedup.rs` — replay protection, bound through the real tracker

Added 2026-08-30. K138 (a second call with the same id returns false) and K139
(empty, oversized and dangerous ids rejected) are proved over three boolean
predicates. `WebhookDedup::check_or_insert` is public, so the binding drives the
real tracker rather than a reconstruction: fresh tracker per case, first and
second calls, and every id shape production distinguishes — empty, ordinary, at
the 512-byte bound, one over, far over, embedded NUL, newline, bidi override.

What rides on it: this is billing webhook replay protection. A duplicate reading
as first-occurrence is a re-processed payment event. Production treats a
malformed id as a duplicate precisely so it is never processed — fail-closed —
and the model has to agree, or K139 describes a different rejection rule than
the one running.

The length bound is pinned on **both** sides rather than compared to itself.
`MAX_EVENT_ID_LEN` in the model and `MAX_WEBHOOK_EVENT_ID_LEN` in production are
separate constants; asserting only that they are equal would let a change move
both and escape, which is the trap recorded under "bind the value, not the
relation". The binding instead exercises 512 and 513 through the real function
and through the model independently.

Mutation-verified 5/5: the length bound drifting to 1024, the dangerous-char
rejection removed, the empty-id rejection removed, a malformed id becoming a
first occurrence (the fail-open direction), and duplicate detection weakened
from `&&` to `||` are all caught.

This is the third crate to need a `build.rs` for extraction materialization
(`vellaveto-engine`, `vellaveto-types`, `vellaveto-server`); the mechanism is
identical in each.

### The denominator was wrong — 33 extractions, not 35

Corrected 2026-08-30 while looking for the next module to bind. `formal/kani/src`
holds 35 `.rs` files, and the count of "extractions" had simply been the file
count. Two of those files carry no extracted production logic and therefore no
drift risk:

- **`merkle_codec.rs`** — contains no functions at all, only Kani harnesses that
  call `hex::encode` and `hex::decode` directly. Production
  (`vellaveto-audit/src/trusted_merkle_hash.rs`) wraps the *same* `hex` crate,
  so there is no second copy that could drift. K141/K142 constrain the shared
  dependency, which is a different (and weaker) kind of claim than the others —
  but not an undischarged correspondence.
- **`proofs.rs`** — 116 function definitions, 109 of them `#[kani::proof]`
  harnesses. It is the harness file, not an extraction.

So `PARITY-HAND-2` ranges over **33** extractions, of which 7 are discharged.

Worth recording *how* this was found, because the classification took four
attempts and each early answer was confidently wrong. A `^pub fn` grep missed
methods inside `impl` blocks (`credential_vault.rs` has a whole `Vault` state
machine and was counted as empty). Adding indentation tolerance still missed
`pub const fn`. A skip flag for `#[cfg(test)]` blocks was set once and never
reset, so every function after the first test module vanished. Only a
brace-depth-aware scan gave a stable answer, and even that needed a manual read
of the two outliers to confirm what they are.

The lesson generalises past this count: **a number derived by grep is a
hypothesis, not a measurement.** An inflated denominator here would have made
the remaining work look larger and each discharge look smaller — harmless in
that direction. The same carelessness pointed the other way is how a coverage
claim gets overstated.

## KANI-CACHE-DRIFT-1 — a proof about the function as it was before a security fix

Found 2026-08-28 by building the third Kani binding. Fixed the same day.

`formal/kani/src/cache.rs` modelled `is_cacheable_context` with a struct of
booleans and described the logic as "verbatim from production". It was not.
Production gained a `has_risk_score` short-circuit in **R237-ENG-6**:

> risk_score from continuous authorization can change ABAC verdicts between
> calls. A cached Allow for risk_score=0.1 must not be served when the next
> request has risk_score=0.9.

The model never followed. It had no such field, so **K33 was proved about the
function as it stood before that fix** — a model in which a request carrying a
risk score is cacheable whenever its context is clean.

Not a vulnerability: production has the fix and always had it after R237. What
was wrong is the claim. A reader checking whether cache poisoning via stale risk
scores was ruled out would have found a Kani proof that appears to cover it and
does not.

**Resolution.** `CacheabilityFields` gains `has_risk_score`, checked before the
context exactly as production checks it; the K33 harness quantifies over it and
asserts that a risk-carrying request is never cacheable. Re-verified with Kani
locally: 62 checks, 0 failed. The differential binding in
`vellaveto-engine/src/cache.rs` then enumerates **all 2⁸ combinations** of the
seven session-dependent fields and the risk flag, plus both risk states with no
context.

Mutation-verified 4/4, and the first mutation is the drift itself: deleting the
`has_risk_score` branch — restoring exactly the pre-fix model — is caught.

**Why this one matters more than its severity suggests.** It is the same failure
as `TAINT-MODEL-DRIFT`: production was fixed, the model was not, and every guard
stayed green because no guard compared them. That is now three findings of this
shape (`TAINT-MODEL-DRIFT`, `MODEL-SHAPE-1/2`, this), which is enough to call it
the dominant failure mode of the formal program rather than a series of
accidents. A model only tracks production if something forces it to.

The binding lives inside `cache.rs` rather than a sibling module because
`DecisionCache::is_cacheable_context` is private; a binding that required
widening its visibility would be changing shipped API surface in order to test
it.

## KANI-SANITIZER-DRIFT-1 — a proof endorsing the design a security fix removed

Found 2026-08-30 while building the eighth Kani binding. Fixed the same day.
This is the fourth finding of the model-drift shape and the most pointed one.

`formal/kani/src/sanitizer.rs` built PII placeholders as
`[PII_{CAT}_{SEQ:06}]` from a **monotonic sequence counter**, under a doc
comment reading "Mirrors the production format". K70 was titled *"Token
uniqueness from monotonic sequence counter"* and proved exactly that.

Production does not do this, and stopped doing it deliberately:

> **SECURITY (R242-SHLD-1)**: Use an unpredictable token instead of a
> sequential counter so placeholders cannot be guessed and probed as a
> desanitization oracle.

It draws a random `u64` and formats it `{:016X}` — sixteen uppercase hex digits
— redrawing until the candidate is absent from the mapping table.

So the proof did not merely describe a stale function, as `KANI-CACHE-DRIFT-1`
did. **It asserted the virtue of an arrangement that was removed because it was
a vulnerability.** A reader auditing whether placeholder guessing was ruled out
would find "token uniqueness proved" and never learn that uniqueness-from-a-
counter *was* the weakness.

**A second defect in the same proof.** The K70 harness contained

```rust
if cat1 != cat2 {
    assert_ne!(cat1, cat2, "distinct categories must produce distinct tokens");
}
```

which asserts the condition it just branched on. A tautology, constraining no
token at all. Half of K70 was vacuous — the same family as `VACUOUS-SPEC-1` and
`GUARD-COMMENT-1`, and invisible for the same reason: it passed.

**Resolution.** The model now builds production's format via
`render_sixteen_hex_digits`, and `token_is_fresh` models the redraw loop, which
is where uniqueness actually comes from. K70 was rewritten to prove the property
that matters — the *encoding* is injective, so two distinct token values can
never render to the same placeholder — and a second harness pins that a
candidate already in the mapping table is never accepted. Both verify under Kani
locally, as does K69 after its expected literals were corrected and its unwind
bound raised from 32 to 64 (the placeholder grew from 18 to 28 characters).

**What the binding can and cannot compare.** Production's token *value* is
random, so there is no generation to compare. What is comparable is the
encoding: given the same category and value, both must produce the same
placeholder text, and that is asserted against the exact `format!` production
uses. Mutation-verified 4/4 — reverting to decimal (the original drift),
lowercase hex, reversed nibble order, and a freshness check that always accepts
are all caught.

### `dlp_core.rs` — the cleanest correspondence, and two proof systems resting on it

Added 2026-08-30. This extraction states that "the algorithm is identical to the
production code. Verified by Verus (ALL inputs) and Kani (bounded inputs)
independently." **Two** proof systems rest on that identity, and nothing checked
it — which makes it the highest-leverage correspondence in the crate and, as it
turned out, the only one that was actually faithful.

Six functions, same names, same signatures, all `pub`, so the comparison is
direct: `is_utf8_char_boundary` **total** over all 256 bytes;
`extract_tail` at every truncation point of inputs mixing 1-, 2-, 3- and 4-byte
characters plus invalid UTF-8; `can_track_field` over 1,764 combinations
including the `checked_add` overflow path; the saturating arithmetic at and
around its saturation points; and `overlap_covers_secret` over 3,456
combinations.

What rides on it: these decide how much of a previous call's value is retained
and rescanned, which is what catches a secret split across two tool calls
(Phase 71, R233-DLP-1). An overlap computed too small stops detecting split
secrets and says nothing while doing so.

Mutation-verified 4/4: the UTF-8 continuation mask widened from `0xC0` to
`0x80`, the byte accounting reordered so saturation differs, the overlap size
wrapping instead of saturating, and the field capacity check weakened from `>=`
to `>` are all caught.

**Worth noting that this one was clean.** Five extractions in a row had drifted,
and it would be easy to conclude the whole crate is rotten. It is not: where the
correspondence is one-to-one and the functions are `pub`, the copies had stayed
faithful. The drift clustered in extractions that *model* rather than mirror —
`cache` (booleans for a struct), `sanitizer` (a counter for a random draw),
`injection` (a hand-maintained substitution table). That is the useful
predictor for the remaining 23: **the further an extraction is from a
one-to-one copy, the more likely it has drifted.**

### `credential_vault.rs` — enumerate the transition table, not a happy path

Added 2026-08-30. The most instructive binding of the campaign, and the lesson
is about test *shape* rather than about the extraction.

This is a hand-built state machine — a `Vec<CredState>` where production has an
encrypted, persisted, mutex-guarded entry list — carrying K108-K112: single use,
epoch monotonicity, capacity bound, fail-closed exhaustion, valid transitions.

**The predictor recorded under `dlp_core.rs` was wrong here, and that is worth
stating.** It says extractions that *model* drift while those that *mirror* do
not, and this one models heavily. It had not drifted: the transition rules match
production exactly. The predictor is a heuristic about where to look first, not
a law.

**Four mutations survived the first version of the binding**, all for the same
reason: it was a happy path plus ad-hoc cases, and each surviving mutation was a
match arm no case reached — consume from `Consumed`, from `Expired`, from
`Absent`, and re-adding an existing credential.

The `Consumed` one is the pointed one. **K108 is named "consumed credential
cannot be re-consumed", and the test re-consumed an *Active* credential**, which
takes a different arm entirely. The property the proof is named for was
precisely the one not being tested, and everything passed.

Replacing the ad-hoc cases with the **full 5 states × 3 operations table**
closed all four at once, and the binding is now 9/9. A state machine has a
small, totally enumerable transition table; testing less than all of it leaves
arms dark, and which arms are dark is not visible from a passing run.

The expected column is written out longhand rather than computed from the
model, so a behaviour change has to be reconciled with a stated intention
instead of silently redefining the expectation.

**Scope the model does not cover**, recorded rather than compared: production's
persistence — rollback on persist failure (R236-SHIELD-3 on consume,
R237-SHIELD-3 on expire) and the `activated_at` stamp used to reclaim orphaned
Active entries (R250-NHI-3). K108-K112 say nothing about those paths.

### `task.rs` — the transition-table lesson, applied first time

Added 2026-08-30. K56 (terminal states admit no transition), K57 (registration
rejected at capacity), K58 (self-cancel rejects a different requester).

Written directly as total enumerations rather than as a happy path, taking the
lesson from `credential_vault`: `is_terminal` across all six states,
`can_transition` across all **36** ordered pairs, `can_cancel` across its whole
2 × 3 × 3 × 2 domain. **6/6 on the first mutation pass**, with no follow-up
round needed — the first binding in this campaign where that was true.

`can_cancel` is then driven through the real `TaskStateManager` so the
authorization rule is checked against the running system and not only against a
restatement of it.

**A scope difference the model cannot represent, recorded rather than
compared.** Production refuses to cancel a task already in a terminal state
*before* it considers authorization at all; the model's `can_cancel` takes no
state parameter, so it has no way to express that guard. The direction is safe —
production is strictly stricter, so nothing K58 permits is under-enforced — but
it means K58 is about **authorization only**, and terminal immutability
(FIND-R60-004) is outside its scope. The binding asserts both halves: that
production refuses, and that the model still authorizes, so the difference is
visible rather than mistaken for agreement.

### `transitive_revoke.rs` — the first closed triangle

Added 2026-08-30. The first place where **all three** descriptions of one
function meet.

`vellaveto-mcp/src/verified_transitive_revoke.rs` is the production mirror. The
Verus kernel proves its specs against it (bound under `PARITY-HAND-1`), and
`formal/kani/src/transitive_revoke.rs` proves K136/K137 against its own separate
copy of the same predicates. Nothing connected the Kani copy to anything.

This binding closes the triangle over the total domain of each predicate — 2³
for link deactivation, the whole range around the depth bound, 2² for the
collateral test. With the Verus binding already in place, agreement here means
Verus, Kani and production are three descriptions of **one** function rather
than three plausible functions.

What rides on it: revoking an NHI must sever every delegation reachable from it.
Cutting on *either* endpoint is deliberate — revoking an agent severs both what
it granted and what was granted to it — and two of the mutations attack exactly
that.

**A comparison deliberately not made.** The Kani copy has
`visited_insert_new` (BFS progress); production has `no_collateral`
(reachability). Both are one-argument-ish booleans and it would be easy to
assert they agree. They model different things, so they are checked separately —
asserting an accidental agreement between two unrelated predicates is precisely
the vacuous check this campaign exists to remove, and it would have passed.

Mutation-verified 5/5 on the first pass: the depth bound drifting 50 → 500 (the
same escape that `verified_merkle`'s sibling cap made under `PARITY-HAND-1`),
requiring *both* endpoints revoked, dropping the incoming-delegation half,
an off-by-one at the boundary, and BFS revisiting nodes so K136's termination
argument fails.

## KANI-LEET-DRIFT-1 — a model that claimed a decode production does not perform

Found 2026-08-30 while building the ninth Kani binding. Fixed the same day.
Fifth finding of the model-drift shape, and the first in the **over-claiming**
direction.

`formal/kani/src/injection_pipeline.rs` models the decoders the injection
scanner runs before pattern matching; K76 is pipeline completeness and K77 is
that known attack strings are detected after decoding. Its leetspeak
substitution map had diverged from production's `LEET_MAP` five ways:

| Character | Production | Model (before) |
|---|---|---|
| `+` | `t` | *absent* |
| `2` | `z` | *absent* |
| `9` | `g` | *absent* |
| `\|` | `l` | `i` |
| `#` | *not decoded* | `h` |

The first three are production's R226-MCP-2 expansion, which the model never
picked up. The fourth is simply wrong.

**The fifth is the one that matters.** Production does not decode `#` at all.
The model did. Direction is everything here: a model that decodes *less* than
production under-claims, and the proof is merely weaker than reality — safe. A
model that decodes *more* **over-claims**: K77 would establish that a
`#`-obfuscated attack string is detected after decoding, when production never
performs that substitution and does not detect it. That is a proof asserting a
defence that is not there.

Every previous drift finding in this campaign was in the safe direction. This
one was not.

**Resolution.** The map now matches production character for character, and the
binding sweeps **every printable ASCII character** through both, so no future
divergence in either direction can hide. The specific five are also pinned
individually, including an assertion that production does *not* decode `#` — so
if production ever adds it, the binding fails and the model is updated
deliberately rather than by coincidence.

**Mutation testing found a hole in the binding, again.** ROT13 was compared
using four hand-picked encoded words, and an `a..=m` → `a..=l` off-by-one
survived: none of the four happened to contain `m`, which is exactly the
boundary between the two rotation arms. The comparison now sweeps the whole
alphabet in one word — chosen as a single word so production's stop-word density
guard (which needs ≥ 8 words) does not suppress the decode. After the fix, that
mutation and two further ROT13 boundary mutations are all caught.

That is the fourth time in this campaign a binding looked finished and was not,
and the reason every one of them is mutation-tested at the moment it is written.

**A scope difference that is not drift:** production suppresses ROT13 for text
reading as natural English (R228-INJ-1 / R238-MCP-3 stop-word density) and
requires 3+ substitutable characters before leetspeak decoding (a false-positive
guard on strings like `127.0.0.1`). The model represents neither. The binding
therefore compares on inputs the guards do not suppress, and says so.

## KANI-GLOB-ORDER-1 — two glob matchers that disagree on branch order

Found 2026-08-30 while binding `capability.rs`, the largest extraction. Fixed
the same day. Seventh drift finding.

`formal/kani/src/capability.rs::glob_match` describes itself as "the
bounded-model witness for the runtime metachar matcher now routed through
`verified_capability_glob::literal_child_matches_parent_glob`". The exhaustive
comparison — every pattern/value pair over `* ? @ A Z [ a z` up to length 2,
5,329 pairs — found them disagreeing.

The witness: pattern `"*?"`, value `"*"`. Production matches; the model did not.

**Cause: branch order.** The model's iterative matcher tested literal equality
*before* the star branch, so a literal `*` in the **value** was consumed by
`eq_ignore_ascii_case` against the pattern's `*`, leaving `?` with nothing to
match. Production's recursive matcher tests the star arm first and treats a
pattern `*` as a wildcard unconditionally. Two reasonable matchers; one
semantics.

**Direction.** The model was *stricter* than production — it refused matches
production accepts. For a coverage predicate that is the direction that
undermines a no-escalation argument: K37 is proved over a matcher that admits
**fewer** delegations than the one running, so pairs production considers
covered were never examined by the proof.

**Reachability, stated honestly.** In `pattern_is_subset`, a child carrying
metacharacters is routed to the exact subset checker rather than to this
matcher, so the divergence is not reachable there. It is reachable through
`pattern_matches(pattern, value)` for runtime action coverage — but only for a
tool or function name containing a literal `*` or `?`. Unusual, not impossible,
and the point stands regardless: K36-K41 were about a different function than
the one running.

**Resolution.** The star branch now precedes the equality branch. All 5,329
pairs agree, and all six capability harnesses re-verify under Kani locally —
`proof_grant_is_subset_reflexive`, `_no_escalation`,
`proof_pattern_is_subset_correctness`, `proof_glob_match_wildcard_universal`,
`proof_normalize_path_for_grant_no_traversal`, `proof_grant_covers_action_fail_closed`.

**This binding closes six triangles at once.** `capability.rs` duplicates
predicates that already have production mirrors bound to Verus under
`PARITY-HAND-1` — `verified_capability_pattern`, `_glob`, `_literal`, `_domain`,
`_path`, `_glob_subset`. For each, Verus proves the mirror and this shows the
Kani copy is the same function.

Mutation-verified 5/5, and two are worth naming: reverting the branch order (the
finding itself), and the `A..=Z` → `A..<Z` case-fold off-by-one — **the exact
mutation that started this campaign**, which once passed the symbol-name guard
and all 1,950 crate tests. It is now caught.

## NORMALIZE-MODEL-1 — K34's normalization is weaker than production's

Named 2026-08-28. **Deliberate, not a defect.**

K34 states "build_key is case-insensitive" and demonstrates it on the model's
`normalize_for_key`, which is `s.to_lowercase()`. Production's `build_key`
hashes through `normalize_full` — NFKC, lowercase, and homoglyph mapping — which
is strictly stronger. So the proof is about a different, weaker normalization
than the one running.

This gap is not closable in Kani and should not be: `formal/kani/Cargo.toml`
exists precisely because Kani 0.67 cannot compile the `icu_normalizer`/`zerovec`
chain, and modelling NFKC in a SAT encoding is intractable.

What *is* bindable is the property K34 claims — that the normalization
production actually uses is case-insensitive — and that is now asserted directly
against `normalize_full`, together with a pin that the model remains the weaker
of the two (a fullwidth `Ｆ` folds under production's normalization and not
under the model's). If the model ever started folding fullwidth forms, the
difference this assumption is recorded against would have changed and the pin
fails.

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
