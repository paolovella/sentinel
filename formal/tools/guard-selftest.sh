#!/usr/bin/env bash
# guard-selftest.sh — Mutation self-test for the formal/ guard scripts.
#
# Why this exists: the guards under formal/tools/ are the only thing connecting
# a Verus or Kani proof to the code that ships. If a guard cannot fail, it is
# worse than no guard, because it is believed — and `check-verus-parity.sh`
# currently prints "ALL CHECKS PASSED — Verus proof targets still align with
# production entrypoints" against a tree whose capability containment check has
# been replaced with `return true`.
#
# This script breaks the repo in one known way per guard family and asserts that
# the responsible guard notices each time. A case that reports `pass` where
# `drift` was expected is a hole in the trusted base, not a passing test.
#
# Runs against a copy of the WORKING TREE (tracked + untracked-not-ignored), not
# of HEAD. A self-test that checks the last commit instead of what you are about
# to commit is the same "believed but ineffective" failure it exists to prevent.
# It never mutates the worktree.
#
# Usage:  bash formal/tools/guard-selftest.sh
# Exit:   0 = every case behaved as expected, 1 = at least one guard has a hole.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_DIR" || exit 1

pass=0
fail=0
holes=()

# Export every tracked + untracked-not-ignored file. An earlier version listed
# only the crates the guards "obviously" read and the control case caught it:
# check-verus-parity.sh also reaches into vellaveto-approval, -server and
# -http-proxy, so the pristine export reported 38 spurious DRIFT lines and every
# mutation below it "passed" for the wrong reason.
export_tree() {
    local dest="$1"
    git ls-files -co --exclude-standard -z \
        | tar --null -T - -cf - 2>/dev/null \
        | tar -x -C "$dest" 2>/dev/null
}

# run_case <name> <guard-script> <expect: pass|drift> <mutation command...>
run_case() {
    local name="$1" guard="$2" expect="$3"
    shift 3
    local tmp
    tmp=$(mktemp -d)
    export_tree "$tmp"

    if ! ( cd "$tmp" && "$@" ) >/dev/null 2>&1; then
        printf '  FAIL  %-46s mutation itself failed to apply\n' "$name"
        fail=$((fail + 1))
        rm -rf "$tmp"
        return
    fi

    local got="pass"
    if ! ( cd "$tmp" && bash "$guard" ) >/dev/null 2>&1; then
        got="drift"
    fi

    if [ "$got" = "$expect" ]; then
        printf '  ok    %-46s (%s)\n' "$name" "$got"
        pass=$((pass + 1))
    else
        printf '  HOLE  %-46s expected %s, got %s\n' "$name" "$expect" "$got"
        fail=$((fail + 1))
        holes+=("$name")
    fi
    rm -rf "$tmp"
}

VERUS_GUARD="formal/tools/check-verus-parity.sh"
KANI_GUARD="formal/tools/check-kani-parity.sh"
ASSUM_GUARD="formal/tools/check-formal-trusted-assumptions.sh"
MARKER_GUARD="formal/tools/check-proof-completion-markers.sh"
DIFF_GUARD="formal/tools/check-differential-parity.sh"

# Differential cases compile the crate under test. Share one target directory
# across every case so only the first pays a cold build (~90s) and the rest are
# incremental.
export DIFFERENTIAL_TARGET_DIR="${DIFFERENTIAL_TARGET_DIR:-/tmp/vellaveto-guard-selftest-target}"

# Two runs sharing that directory corrupt each other's builds, and the symptom
# is fabricated results: a control case that "drifts" and a tolerated case that
# "fails", neither caused by the mutation under test. That happened once during
# development and cost a full diagnosis. For a guard self-test it is the worst
# possible failure, because it can fabricate a passing case as easily as a
# failing one. Take an exclusive lock so a second run waits instead of racing.
mkdir -p "$DIFFERENTIAL_TARGET_DIR"
exec 9>"$DIFFERENTIAL_TARGET_DIR/.guard-selftest.lock"
if ! flock -n 9; then
    echo "Another guard-selftest holds $DIFFERENTIAL_TARGET_DIR; waiting for it to finish."
    flock 9
fi

# The lock stops two runs racing. It does not stop a run being *interrupted*.
# A run killed between mutating a file and restoring it leaves the shared target
# directory holding artifacts built from mutated source, and the next run's
# control case then "drifts" against a pristine tree — a fabricated hole, which
# for a guard self-test is as dangerous as a fabricated pass. That happened on
# 2026-08-28 after a run was stopped mid-case: the differential control reported
# a hole while the same guard passed on a clean target directory.
#
# So: drop a marker while running and clear it on a clean exit. If the marker is
# still there at startup the previous run did not finish, the directory cannot
# be trusted, and this script refuses to measure rather than reporting numbers
# it has not earned.
RUNNING_MARKER="$DIFFERENTIAL_TARGET_DIR/.guard-selftest.running"
if [ -e "$RUNNING_MARKER" ]; then
    cat >&2 <<MSG
ERROR: a previous guard-selftest did not finish.

  $DIFFERENTIAL_TARGET_DIR may hold build artifacts compiled from mutated
  source. Results from it cannot be trusted in either direction.

  Clear the target directory, or point this run somewhere else:

    DIFFERENTIAL_TARGET_DIR=/tmp/vellaveto-guard-selftest-target-\$\$ \\
      bash formal/tools/guard-selftest.sh

  Refusing to run. A self-test that reports numbers it has not earned is
  worse than no self-test.
MSG
    exit 2
fi
: > "$RUNNING_MARKER"
trap 'rm -f "$RUNNING_MARKER"' EXIT

echo "=== Formal Guard Self-Test ==="
echo "Each case breaks one thing a guard claims to protect and expects it to fire."
echo ""

# ── 0. Control ────────────────────────────────────────────────────────────
# If the unmutated export does not come back clean, every result below is
# meaningless.
echo "--- control ---"
run_case "pristine export (verus guard)" "$VERUS_GUARD" pass true
run_case "pristine export (assumption guard)" "$ASSUM_GUARD" pass true
run_case "pristine export (differential guard)" "$DIFF_GUARD" pass true
# Added after the kani guard silently started failing on a pristine tree: an
# extraction moved three functions out of the file it greps, and the only case
# that noticed reported a hole for the wrong reason. Every guard needs its own
# control, not just the ones that happened to get one first.
run_case "pristine export (kani guard)" "$KANI_GUARD" pass true
run_case "pristine export (marker guard)" "$MARKER_GUARD" pass true

# ── 1. Verus ↔ production correspondence ──────────────────────────────────
# The kernel proves properties of an algorithm. These mutations change what the
# shipped algorithm computes without touching any symbol name, so
# check-verus-parity.sh cannot see them by construction — it greps for names.
# The binding that can see them is check-differential-parity.sh, which executes
# a transcription of the Verus spec alongside the shipped function.
echo ""
echo "--- verus ↔ production body correspondence (differential) ---"

GLOB_PROD="vellaveto-mcp/src/verified_capability_glob.rs"

run_case "capability containment disabled" "$DIFF_GUARD" drift \
    perl -0pi -e 's/(fn literal_child_matches_parent_glob_from\([^)]*\) -> bool \{)/$1\n    if true { return true; }/' "$GLOB_PROD"

run_case "case-fold off-by-one (A..Y, not Z)" "$DIFF_GUARD" drift \
    perl -0pi -e "s/byte >= b'A' && byte <= b'Z'/byte >= b'A' && byte < b'Z'/" "$GLOB_PROD"

run_case "'?' widened to zero-or-one (fail-open)" "$DIFF_GUARD" drift \
    perl -0pi -e "s/Some\(\(&b'\?', tail\)\) => child_literal/Some((&b'?', tail)) => literal_child_matches_parent_glob_from(tail, child_literal) || child_literal/" "$GLOB_PROD"

# The capability family is bound the same way. One case per input shape rather
# than one per kernel: each case pays a crate rebuild, and the per-kernel
# `test_spec_oracle_can_reject` tests already pin that no oracle is degenerate.

run_case "boolean kernel: coverage && -> ||" "$DIFF_GUARD" drift \
    perl -0pi -e 's/\)\)\n        && \(!grant_has_allowed_domains/))\n        || (!grant_has_allowed_domains/s' vellaveto-mcp/src/verified_capability_coverage.rs

run_case "numeric kernel: depth wraps past zero" "$DIFF_GUARD" drift \
    perl -0pi -e 's/if parent_remaining_depth == 0 \{\n        None\n    \} else \{\n        Some\(parent_remaining_depth - 1\)/if false {\n        None\n    } else {\n        Some(parent_remaining_depth.wrapping_sub(1))/s' vellaveto-mcp/src/verified_capability_attenuation.rs

run_case "delegation kernel: budget may widen" "$DIFF_GUARD" drift \
    perl -0pi -e 's/child_max_invocations <= parent_max_invocations/child_max_invocations >= parent_max_invocations/' vellaveto-mcp/src/verified_capability_grant.rs

# The audit and Merkle families are bound the same way. These three are the
# security-relevant shapes: a counter that must saturate rather than wrap, a
# sequence number that must strictly increase, and a Merkle proof step whose
# side determines the hash order.

run_case "audit counter wraps instead of saturating" "$DIFF_GUARD" drift \
    perl -0pi -e 's/current_entry_count.saturating_add\(1\)/current_entry_count.wrapping_add(1)/' vellaveto-audit/src/verified_audit_append.rs

run_case "audit sequence may repeat (replay)" "$DIFF_GUARD" drift \
    perl -0pi -e 's/current_sequence > prev_sequence/current_sequence >= prev_sequence/' vellaveto-audit/src/verified_audit_chain.rs

# Raising a bound the kernel fixes as a literal. A transcription that reuses
# production's constant symbolically binds the relation and not the value, so
# this mutation escapes until the literal is pinned. Two of them did.
run_case "merkle sibling cap raised 64x" "$DIFF_GUARD" drift \
    perl -0pi -e 's/pub\(crate\) const MAX_PROOF_SIBLINGS: usize = 64;/pub(crate) const MAX_PROOF_SIBLINGS: usize = 4096;/' vellaveto-audit/src/verified_merkle.rs

run_case "revoke depth bound raised 10x" "$DIFF_GUARD" drift \
    perl -0pi -e 's/pub\(crate\) const MAX_TRANSITIVE_REVOKE_DEPTH: usize = 50;/pub(crate) const MAX_TRANSITIVE_REVOKE_DEPTH: usize = 500;/' vellaveto-mcp/src/verified_transitive_revoke.rs

run_case "merkle proof side inverted" "$DIFF_GUARD" drift \
    perl -0pi -e 's/    node_index % 2 == 1\n\}/    node_index % 2 == 0\n}/s' vellaveto-audit/src/verified_merkle_path.rs

# The policy, delegation and approval families are bound the same way. These
# are the three highest-consequence shapes across the newly covered crates: the
# fail-closed base case of the verdict computation itself, a confused-deputy
# boundary, and an approval replay.

run_case "empty policy list allows (fail-open)" "$DIFF_GUARD" drift \
    perl -0pi -e 's/    \/\/ V2: No match produced a verdict → Deny \(fail-closed\)\n    VerdictKind::Deny\n\}/    \/\/ V2: No match produced a verdict → Deny (fail-closed)\n    VerdictKind::Allow\n}/s' vellaveto-engine/src/verified_core.rs

run_case "claim trusted without delegation" "$DIFF_GUARD" drift \
    perl -0pi -e 's/has_active_delegation && claimed_present/has_active_delegation || claimed_present/' vellaveto-mcp/src/verified_deputy_handoff.rs

run_case "session-bound approval replayable" "$DIFF_GUARD" drift \
    perl -0pi -e 's/!approval_has_session_binding \|\| \(request_has_session && request_matches_bound_session\)/!approval_has_session_binding || request_has_session/' vellaveto-approval/src/verified_approval_scope.rs

# ── 1b. Intent scope and sequence gate (MODEL-SHAPE-1/2) ──────────────────
# These kernels used to model a design production did not implement. The design
# was built on 2026-08-28; these cases test that the guards notice if it is
# taken back out. Two of them were written wrong first: one matched a comment
# rather than a call, and one matched a renamed function by prefix.
echo ""
echo "--- intent scope + sequence gate ---"

run_case "scope mask narrowed back below nine classes" "$VERUS_GUARD" drift \
    perl -0pi -e 's/pub const SCOPE_CLASS_COUNT: u8 = 9;/pub const SCOPE_CLASS_COUNT: u8 = 8;/' vellaveto-types/src/verified_intent_scope.rs

run_case "scope restriction widens instead of narrowing" "$DIFF_GUARD" drift \
    perl -0pi -e 's/Self\(self\.0 & restriction\.0\)/Self(self.0 | restriction.0)/' vellaveto-types/src/verified_intent_scope.rs

run_case "trust-floor narrowing bypasses the mask" "$VERUS_GUARD" drift \
    perl -0pi -e 's/\.restrict\(Self::trust_floor_mask\(trust_floor\)\)/.restrict(ScopeMask::ALL)/' vellaveto-config/src/channel_separation.rs

run_case "relay stops calling the verified sequence gate" "$VERUS_GUARD" drift \
    perl -0pi -e 's/vellaveto_engine::verified_sequence_gate::should_restrict\(/std::convert::identity::<bool>(/' vellaveto-mcp/src/proxy/bridge/relay.rs

run_case "relay stops persisting the narrowed scope" "$VERUS_GUARD" drift \
    perl -0pi -e 's/fn narrow_session_scope\(/fn narrow_session_scope_disabled(/' vellaveto-mcp/src/proxy/bridge/relay.rs

run_case "relay stops consulting the scope on the call path" "$VERUS_GUARD" drift \
    perl -0pi -e 's/scope\.check_in_scope\(&tool_name, sink\)/ScopeCheckResult::InScope/' vellaveto-mcp/src/proxy/bridge/relay.rs

run_case "restriction threshold drifts from the kernel" "$VERUS_GUARD" drift \
    perl -0pi -e 's/pub const RESTRICTION_THRESHOLD: u32 = 70;/pub const RESTRICTION_THRESHOLD: u32 = 71;/' vellaveto-engine/src/verified_sequence_gate.rs

run_case "sequence gate fires without an anomaly" "$DIFF_GUARD" drift \
    perl -0pi -e 's/    anomaly_detected && anomaly_confidence >= RESTRICTION_THRESHOLD\n\}/    anomaly_confidence >= RESTRICTION_THRESHOLD\n}/' vellaveto-engine/src/verified_sequence_gate.rs

# ── 2. Kani ↔ production extraction ───────────────────────────────────────
# formal/kani/Cargo.toml states the extracted code "is tested to be identical to
# the production code via the CI diff check". These test whether that holds.
echo ""
echo "--- kani ↔ production extraction ---"

run_case "kani copy of normalize_path diverges" "$KANI_GUARD" drift \
    perl -0pi -e 's/(fn normalize_path\()/fn normalize_path_unused(/' formal/kani/src/path.rs

# check-kani-parity.sh compares public fn counts between the extracted copy and
# production. An earlier case here asserted it caught a dropped kani::proof
# harness — a claim the guard never makes. Testing a guard against a promise it
# did not give is how a self-test manufactures fake holes.
run_case "kani copy drops a public fn (tolerated)" "$KANI_GUARD" pass \
    perl -0pi -e 's/pub fn normalize_path_bounded/fn normalize_path_bounded/' formal/kani/src/path.rs

# ── 3. Trusted-assumption inventory ───────────────────────────────────────
# The allowlist is a machine-checked inventory of proof escape hatches. An
# unregistered escape hatch is an undeclared hole in the trusted base.
echo ""
echo "--- trusted-assumption inventory ---"

run_case "unregistered verus assume() appears" "$ASSUM_GUARD" drift \
    bash -c "printf '\nverus!{ proof fn smuggled() { assume(false); } }\n' >> formal/verus/verified_capability_glob.rs"

run_case "allowlist entry silently deleted" "$ASSUM_GUARD" drift \
    sed -i '/axiom_merkle_codec_roundtrip/d' formal/trusted-assumptions.allowlist

# VACUOUS-SPEC-1: a spec fn whose body is `true` is an axiom in disguise and
# contains none of the keywords the other scans grep for. The detector added for
# it is only worth having if it fires.
run_case "unregistered vacuous spec fn appears" "$ASSUM_GUARD" drift \
    bash -c "printf '\nverus!{ pub open spec fn smuggled_axiom() -> bool { true } }\n' >> formal/verus/verified_capability_glob.rs"

run_case "vacuous-spec allowlist entry deleted" "$ASSUM_GUARD" drift \
    sed -i '/spec_sort_idempotent/d' formal/trusted-assumptions.allowlist

# ── 4. Proof completion markers ───────────────────────────────────────────
echo ""
echo "--- proof completion markers ---"

# The guard rejects UNFINISHED proof markers in Lean/Coq. An earlier case here
# deleted a "PROOF-COMPLETE" token that appears zero times in the repo, so the
# mutation was a no-op and the resulting "hole" was fabricated.
run_case "sorry smuggled into a Lean proof" "$MARKER_GUARD" drift \
    bash -c 'echo "theorem smuggled : True := by sorry" >> formal/lean/Vellaveto/FailClosed.lean'

# ── Report ────────────────────────────────────────────────────────────────
total=$((pass + fail))
echo ""
echo "=== RESULT: $pass/$total cases behaved as expected ==="
if [ "$fail" -gt 0 ]; then
    echo ""
    echo "Holes found — these guards report success against a broken tree:"
    for h in "${holes[@]}"; do
        echo "  - $h"
    done
    echo ""
    echo "Each hole is an undeclared trusted assumption. Either strengthen the"
    echo "guard, or name the assumption in formal/ASSUMPTION_REGISTRY.md so the"
    echo "proof stops claiming more than it establishes."
    exit 1
fi
echo "Every guard fired on every mutation it claims to protect against."
exit 0
