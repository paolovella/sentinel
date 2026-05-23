#!/usr/bin/env bash
#
# verify-verus.sh — Canonical entrypoint for Verus proof verification
#
# Usage:
#   bash formal/tools/verify-verus.sh
#   VERUS_BIN=/path/to/verus bash formal/tools/verify-verus.sh
#   FORMAL_USE_CARGO_VERUS=1 FORMAL_REQUIRE_CARGO_VERUS=1 bash formal/tools/verify-verus.sh
#   bash formal/tools/verify-verus.sh --list
#
# Exit code: 0 = all proofs verified, non-zero = failure

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

FILES=(
    "formal/verus/verified_audit_append.rs"
    "formal/verus/verified_audit_chain.rs"
    "formal/verus/verified_merkle.rs"
    "formal/verus/verified_merkle_fold.rs"
    "formal/verus/verified_merkle_path.rs"
    "formal/verus/verified_rotation_manifest.rs"
    "formal/verus/verified_capability_attenuation.rs"
    "formal/verus/verified_capability_delegation_context.rs"
    "formal/verus/verified_bridge_principal.rs"
    "formal/verus/verified_capability_coverage.rs"
    "formal/verus/verified_capability_domain.rs"
    "formal/verus/verified_delegation_projection.rs"
    "formal/verus/verified_deputy_handoff.rs"
    "formal/verus/verified_evaluation_context_projection.rs"
    "formal/verus/verified_presented_approval_id.rs"
    "formal/verus/verified_server_approval_id.rs"
    "formal/verus/verified_approval_consumption.rs"
    "formal/verus/verified_approval_scope.rs"
    "formal/verus/verified_transport_context.rs"
    "formal/verus/verified_capability_context.rs"
    "formal/verus/verified_context_delegation.rs"
    "formal/verus/verified_capability_glob.rs"
    "formal/verus/verified_capability_glob_subset.rs"
    "formal/verus/verified_capability_grant.rs"
    "formal/verus/verified_capability_identity.rs"
    "formal/verus/verified_capability_literal.rs"
    "formal/verus/verified_capability_pattern.rs"
    "formal/verus/verified_capability_path.rs"
    "formal/verus/verified_capability_selection.rs"
    "formal/verus/verified_capability_verification.rs"
    "formal/verus/verified_constraint_eval.rs"
    "formal/verus/verified_cross_call_dlp.rs"
    "formal/verus/verified_core.rs"
    "formal/verus/verified_deputy.rs"
    "formal/verus/verified_entropy_gate.rs"
    "formal/verus/verified_nhi_delegation.rs"
    "formal/verus/verified_nhi_graph.rs"
    "formal/verus/verified_dlp_core.rs"
    "formal/verus/verified_path.rs"
    "formal/verus/verified_refinement_safety.rs"
    "formal/verus/verified_refinement_completeness.rs"
    "formal/verus/verified_acis_envelope.rs"
    "formal/verus/verified_acis_action_summary.rs"
    "formal/verus/verified_source_taint.rs"
    "formal/verus/verified_intent_scope.rs"
    "formal/verus/verified_sequence_analysis.rs"
    "formal/verus/verified_entropy_pipeline.rs"
)

MANIFEST="formal/verus/Cargo.toml"
VERUS_LIB="formal/verus/src/lib.rs"

list_cargo_verus_files() {
    local verus_lib="$PROJECT_DIR/$VERUS_LIB"

    if [ -f "$verus_lib" ]; then
        sed -n 's|^[[:space:]]*#\[path = "\.\./\(verified_[^"]*\.rs\)"\][[:space:]]*$|formal/verus/\1|p' "$verus_lib"
        return
    fi

    printf '%s\n' "${FILES[@]}"
}

verus_dir_candidates() {
    printf '%s\n' "$PROJECT_DIR/verus-bin/verus-x86-linux"
    if [ -n "${HOME:-}" ]; then
        printf '%s\n' "$HOME/verus/verus-bin/verus-x86-linux"
        printf '%s\n' "$HOME/verus/source/target-verus/release"
    fi
}

find_verus_bin() {
    if [ -n "${VERUS_BIN:-}" ]; then
        printf '%s\n' "$VERUS_BIN"
        return
    fi

    if command -v verus >/dev/null 2>&1; then
        command -v verus
        return
    fi

    while IFS= read -r verus_dir; do
        if [ -x "$verus_dir/verus" ]; then
            printf '%s\n' "$verus_dir/verus"
            return
        fi
    done < <(verus_dir_candidates)

    echo "FAIL: could not find Verus binary. Set VERUS_BIN, install verus, or keep a checkout at ~/verus." >&2
    exit 1
}

find_cargo_verus_bin() {
    if [ -n "${CARGO_VERUS_BIN:-}" ]; then
        printf '%s\n' "$CARGO_VERUS_BIN"
        return
    fi

    if command -v cargo-verus >/dev/null 2>&1; then
        command -v cargo-verus
        return
    fi

    if [ -n "${VERUS_BIN:-}" ]; then
        local verus_dir
        verus_dir="$(cd "$(dirname "$VERUS_BIN")" && pwd)"
        if [ -x "$verus_dir/cargo-verus" ]; then
            printf '%s\n' "$verus_dir/cargo-verus"
            return
        fi
    fi

    while IFS= read -r verus_dir; do
        if [ -x "$verus_dir/cargo-verus" ]; then
            printf '%s\n' "$verus_dir/cargo-verus"
            return
        fi
    done < <(verus_dir_candidates)

    return 1
}

if [ "${1:-}" = "--list" ]; then
    list_cargo_verus_files
    exit 0
fi

VERUS_FLAGS="${VERUS_FLAGS:---triggers-mode silent}"
USE_CARGO_VERUS="${FORMAL_USE_CARGO_VERUS:-}"
REQUIRE_CARGO_VERUS="${FORMAL_REQUIRE_CARGO_VERUS:-0}"
if [ "$REQUIRE_CARGO_VERUS" = "1" ]; then
    USE_CARGO_VERUS=1
fi
if [ -z "$USE_CARGO_VERUS" ] && [ "${CI:-}" = "true" ]; then
    USE_CARGO_VERUS=1
fi

if [ "$USE_CARGO_VERUS" = "1" ]; then
    if [ ! -f "$PROJECT_DIR/$MANIFEST" ]; then
        if [ "$REQUIRE_CARGO_VERUS" = "1" ]; then
            echo "FAIL: $MANIFEST not found; cannot run required cargo-Verus verification." >&2
            exit 1
        fi
        echo "INFO: $MANIFEST not found; falling back to per-file Verus verification."
    elif CARGO_VERUS="$(find_cargo_verus_bin)"; then
        CARGO_VERUS_TARGET_DIR="${CARGO_VERUS_TARGET_DIR:-${CARGO_TARGET_DIR:-/tmp/vellaveto-formal-verus-target}}"
        echo "=== Verus Verification ==="
        echo "Cargo Verus binary: $CARGO_VERUS"
        echo "Manifest: $PROJECT_DIR/$MANIFEST"
        echo "Cargo target dir: $CARGO_VERUS_TARGET_DIR"
        echo ""
        # shellcheck disable=SC2086
        CARGO_TARGET_DIR="$CARGO_VERUS_TARGET_DIR" \
            "$CARGO_VERUS" verify --manifest-path "$PROJECT_DIR/$MANIFEST" -- $VERUS_FLAGS
        exit 0
    elif [ "$REQUIRE_CARGO_VERUS" = "1" ]; then
        echo "FAIL: cargo-verus requested but not found; set CARGO_VERUS_BIN or install cargo-verus." >&2
        exit 1
    else
        echo "INFO: cargo-verus requested but not found; falling back to per-file Verus verification."
    fi
else
    echo "INFO: using per-file Verus verification; set FORMAL_USE_CARGO_VERUS=1 to use the manifest entrypoint."
fi
echo ""

VERUS="$(find_verus_bin)"
mapfile -t VERIFY_FILES < <(list_cargo_verus_files)

echo "=== Verus Verification ==="
echo "Verus binary: $VERUS"
echo ""

for file in "${VERIFY_FILES[@]}"; do
    echo "--- $file ---"
    # shellcheck disable=SC2086
    "$VERUS" $VERUS_FLAGS "$PROJECT_DIR/$file"
    echo ""
done
