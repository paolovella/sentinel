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

echo "=== Formal Guard Self-Test ==="
echo "Each case breaks one thing a guard claims to protect and expects it to fire."
echo ""

# ── 0. Control ────────────────────────────────────────────────────────────
# If the unmutated export does not come back clean, every result below is
# meaningless.
echo "--- control ---"
run_case "pristine export (verus guard)" "$VERUS_GUARD" pass true
run_case "pristine export (assumption guard)" "$ASSUM_GUARD" pass true

# ── 1. Verus ↔ production correspondence ──────────────────────────────────
# The kernel proves properties of an algorithm. These mutations change what the
# shipped algorithm computes, without touching any symbol name.
echo ""
echo "--- verus ↔ production body correspondence ---"

GLOB_PROD="vellaveto-mcp/src/verified_capability_glob.rs"

run_case "capability containment disabled" "$VERUS_GUARD" drift \
    perl -0pi -e 's/(fn literal_child_matches_parent_glob_from\([^)]*\) -> bool \{)/$1\n    if true { return true; }/' "$GLOB_PROD"

run_case "case-fold off-by-one (A..Y, not Z)" "$VERUS_GUARD" drift \
    perl -0pi -e "s/byte >= b'A' && byte <= b'Z'/byte >= b'A' && byte < b'Z'/" "$GLOB_PROD"

run_case "'?' widened to zero-or-one (fail-open)" "$VERUS_GUARD" drift \
    perl -0pi -e "s/Some\(\(&b'\?', tail\)\) => child_literal/Some((&b'?', tail)) => literal_child_matches_parent_glob_from(tail, child_literal) || child_literal/" "$GLOB_PROD"

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
