#!/usr/bin/env bash
#
# check-formal-trusted-assumptions.sh — Keep non-discharged formal assumptions explicit
#
# The formal suite currently contains a small number of intentional trusted
# assumptions (Verus escape hatches, Lean `axiom`, Coq `Axiom`/`Parameter`).
# This script enforces that every such assumption is listed in the allowlist
# and that stale allowlist entries are removed when proofs are discharged.
#
# Usage: bash formal/tools/check-formal-trusted-assumptions.sh
# Exit code: 0 = inventory matches allowlist, 1 = drift detected

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ALLOWLIST="$PROJECT_DIR/formal/trusted-assumptions.allowlist"
REGISTRY="$PROJECT_DIR/formal/ASSUMPTION_REGISTRY.md"

declare -A allowed=()
declare -A actual=()
unexpected=0
stale=0

normalize_text() {
    printf '%s' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

check_verus_kernel_assumption_bindings() {
    local failed=0
    local file predicate
    declare -A expected_bindings=(
        ["formal/verus/verified_acis_envelope.rs"]="acis_envelope_kernel_assumptions_registered"
        ["formal/verus/verified_acis_action_summary.rs"]="acis_action_summary_kernel_assumptions_registered"
        ["formal/verus/verified_audit_append.rs"]="audit_append_kernel_assumptions_registered"
        ["formal/verus/verified_audit_chain.rs"]="audit_chain_kernel_assumptions_registered"
        ["formal/verus/verified_capability_attenuation.rs"]="capability_attenuation_kernel_assumptions_registered"
        ["formal/verus/verified_capability_context.rs"]="capability_context_kernel_assumptions_registered"
        ["formal/verus/verified_capability_delegation_context.rs"]="capability_delegation_context_kernel_assumptions_registered"
        ["formal/verus/verified_capability_coverage.rs"]="capability_coverage_kernel_assumptions_registered"
        ["formal/verus/verified_capability_domain.rs"]="capability_domain_kernel_assumptions_registered"
        ["formal/verus/verified_bridge_principal.rs"]="bridge_principal_kernel_assumptions_registered"
        ["formal/verus/verified_delegation_projection.rs"]="delegation_projection_kernel_assumptions_registered"
        ["formal/verus/verified_deputy_handoff.rs"]="deputy_handoff_kernel_assumptions_registered"
        ["formal/verus/verified_evaluation_context_projection.rs"]="evaluation_context_projection_kernel_assumptions_registered"
        ["formal/verus/verified_presented_approval_id.rs"]="presented_approval_id_kernel_assumptions_registered"
        ["formal/verus/verified_server_approval_id.rs"]="server_approval_id_kernel_assumptions_registered"
        ["formal/verus/verified_approval_consumption.rs"]="approval_consumption_kernel_assumptions_registered"
        ["formal/verus/verified_approval_scope.rs"]="approval_scope_kernel_assumptions_registered"
        ["formal/verus/verified_transport_context.rs"]="transport_context_kernel_assumptions_registered"
        ["formal/verus/verified_capability_glob.rs"]="capability_glob_kernel_assumptions_registered"
        ["formal/verus/verified_capability_glob_subset.rs"]="capability_glob_subset_kernel_assumptions_registered"
        ["formal/verus/verified_capability_grant.rs"]="capability_grant_kernel_assumptions_registered"
        ["formal/verus/verified_capability_identity.rs"]="capability_identity_kernel_assumptions_registered"
        ["formal/verus/verified_capability_literal.rs"]="capability_literal_kernel_assumptions_registered"
        ["formal/verus/verified_capability_pattern.rs"]="capability_pattern_kernel_assumptions_registered"
        ["formal/verus/verified_capability_path.rs"]="capability_path_kernel_assumptions_registered"
        ["formal/verus/verified_capability_selection.rs"]="capability_selection_kernel_assumptions_registered"
        ["formal/verus/verified_capability_verification.rs"]="capability_verification_kernel_assumptions_registered"
        ["formal/verus/verified_context_delegation.rs"]="context_delegation_kernel_assumptions_registered"
        ["formal/verus/verified_constraint_eval.rs"]="constraint_eval_kernel_assumptions_registered"
        ["formal/verus/verified_core.rs"]="engine_core_kernel_assumptions_registered"
        ["formal/verus/verified_cross_call_dlp.rs"]="cross_call_dlp_kernel_assumptions_registered"
        ["formal/verus/verified_dlp_core.rs"]="dlp_core_kernel_assumptions_registered"
        ["formal/verus/verified_deputy.rs"]="deputy_kernel_assumptions_registered"
        ["formal/verus/verified_entropy_gate.rs"]="entropy_gate_kernel_assumptions_registered"
        ["formal/verus/verified_entropy_pipeline.rs"]="entropy_pipeline_kernel_assumptions_registered"
        ["formal/verus/verified_merkle.rs"]="merkle_guard_kernel_assumptions_registered"
        ["formal/verus/verified_merkle_fold.rs"]="merkle_fold_kernel_assumptions_registered"
        ["formal/verus/verified_merkle_path.rs"]="merkle_path_kernel_assumptions_registered"
        ["formal/verus/verified_nhi_delegation.rs"]="nhi_delegation_kernel_assumptions_registered"
        ["formal/verus/verified_nhi_graph.rs"]="nhi_graph_kernel_assumptions_registered"
        ["formal/verus/verified_path.rs"]="path_kernel_assumptions_registered"
        ["formal/verus/verified_intent_scope.rs"]="intent_scope_kernel_assumptions_registered"
        ["formal/verus/verified_refinement_completeness.rs"]="refinement_completeness_kernel_assumptions_registered"
        ["formal/verus/verified_refinement_safety.rs"]="refinement_safety_kernel_assumptions_registered"
        ["formal/verus/verified_rotation_manifest.rs"]="rotation_manifest_kernel_assumptions_registered"
        ["formal/verus/verified_sequence_analysis.rs"]="sequence_analysis_kernel_assumptions_registered"
        ["formal/verus/verified_source_taint.rs"]="source_taint_kernel_assumptions_registered"
        ["formal/verus/verified_approval_drift.rs"]="approval_drift_kernel_assumptions_registered"
        ["formal/verus/verified_transitive_revoke.rs"]="transitive_revoke_kernel_assumptions_registered"
        ["formal/verus/verified_evidence_signing.rs"]="evidence_signing_kernel_assumptions_registered"
        ["formal/verus/verified_warm_restart.rs"]="warm_restart_kernel_assumptions_registered"
    )

    while IFS= read -r file; do
        file="${file#$PROJECT_DIR/}"
        if [ -z "${expected_bindings[$file]+set}" ]; then
            echo "UNMAPPED-KERNEL-ASSUMPTION: $file"
            failed=1
        fi
    done < <(find "$PROJECT_DIR/formal/verus" -maxdepth 1 -type f -name 'verified_*.rs' | sort)

    for file in "${!expected_bindings[@]}"; do
        predicate="${expected_bindings[$file]}"

        if [ ! -f "$PROJECT_DIR/$file" ]; then
            echo "MISSING-KERNEL-ASSUMPTION-FILE: $file"
            failed=1
            continue
        fi

        if ! grep -Fq "pub open spec fn ${predicate}()" "$PROJECT_DIR/formal/verus/assumptions.rs"; then
            echo "MISSING-KERNEL-ASSUMPTION-PREDICATE: assumptions::$predicate"
            failed=1
        fi

        if ! grep -Fq "ensures assumptions::${predicate}()," "$PROJECT_DIR/$file"; then
            echo "MISSING-KERNEL-ASSUMPTION-BINDING: $file -> assumptions::$predicate"
            failed=1
        fi

        if grep -Fq "ensures assumptions::shared_formal_assumptions_registered()," "$PROJECT_DIR/$file"; then
            echo "TOO-BROAD-KERNEL-ASSUMPTION-BINDING: $file"
            failed=1
        fi
    done

    if [ "$failed" -ne 0 ]; then
        echo ""
        echo "FAIL: Verus kernels are not bound to the expected assumption contracts"
        exit 1
    fi
}

check_registry() {
    local missing=0
    local required_entries=(
        "formal/trusted-assumptions.allowlist"
        "formal/verus/assumptions.rs"
        "formal/verus/merkle_boundary_axioms.rs"
        "formal/verus/audit_fs_boundary_axioms.rs"
        "formal/MERKLE_TRUST_BOUNDARY.md"
        "formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md"
        'VERUS-ESCAPE-1'
        'MERKLE-HASH-1'
        'AUDIT-FS-1'
    )
    local entry

    if [ ! -f "$REGISTRY" ]; then
        echo "FAIL: canonical assumption registry missing: $REGISTRY"
        exit 1
    fi
    if [ ! -f "$PROJECT_DIR/formal/verus/assumptions.rs" ]; then
        echo "FAIL: shared Verus assumptions module missing: $PROJECT_DIR/formal/verus/assumptions.rs"
        exit 1
    fi
    if [ ! -f "$PROJECT_DIR/formal/verus/merkle_boundary_axioms.rs" ]; then
        echo "FAIL: shared Verus Merkle boundary module missing: $PROJECT_DIR/formal/verus/merkle_boundary_axioms.rs"
        exit 1
    fi
    if [ ! -f "$PROJECT_DIR/formal/verus/audit_fs_boundary_axioms.rs" ]; then
        echo "FAIL: shared Verus audit filesystem boundary module missing: $PROJECT_DIR/formal/verus/audit_fs_boundary_axioms.rs"
        exit 1
    fi

    for entry in "${required_entries[@]}"; do
        if ! grep -Fq "$entry" "$REGISTRY"; then
            echo "MISSING-REGISTRY-ENTRY: $entry"
            missing=1
        fi
    done

    if [ "$missing" -ne 0 ]; then
        echo ""
        echo "FAIL: canonical assumption registry is missing required entries"
        exit 1
    fi
}

load_allowlist() {
    local kind path text key

    if [ ! -f "$ALLOWLIST" ]; then
        echo "FAIL: trusted assumption allowlist missing: $ALLOWLIST"
        exit 1
    fi

    while IFS=$'\t' read -r kind path text; do
        if [ -z "${kind:-}" ] || [[ "$kind" == \#* ]]; then
            continue
        fi
        key="$kind"$'\t'"$path"$'\t'"$text"
        allowed["$key"]=1
    done < "$ALLOWLIST"
}

scan_hits() {
    local kind="$1"
    local base_dir="$2"
    local include_glob="$3"
    local pattern="$4"
    local line file rest text key

    if [ ! -d "$base_dir" ]; then
        return
    fi

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        file="${line%%:*}"
        rest="${line#*:}"
        rest="${rest#*:}"
        text="$(normalize_text "$rest")"
        key="$kind"$'\t'"${file#$PROJECT_DIR/}"$'\t'"$text"
        actual["$key"]=1
    done < <(grep -RIn --include="$include_glob" -E "$pattern" "$base_dir" || true)
}

report_inventory() {
    local label="$1"
    local prefix="$2"
    local count=0
    local key

    for key in "${!actual[@]}"; do
        if [[ "$key" == "$prefix"$'\t'* ]]; then
            count=$((count + 1))
        fi
    done

    echo "  $label: $count"
}

report_mismatches() {
    local label="$1"
    local -n source_ref="$2"
    local key

    while IFS= read -r key; do
        [ -z "$key" ] && continue
        echo "$label: $key"
    done < <(printf '%s\n' "${!source_ref[@]}" 2>/dev/null | sort)
}

check_registry
check_verus_kernel_assumption_bindings
load_allowlist

scan_hits "verus-assume" "$PROJECT_DIR/formal/verus" "*.rs" '(^|[^[:alnum:]_])(assume|admit)[[:space:]]*\('
scan_hits "verus-axiom" "$PROJECT_DIR/formal/verus" "*.rs" '^[[:space:]]*pub([[:space:]]+broadcast)?[[:space:]]+axiom[[:space:]]+fn[[:space:]]'
scan_hits "verus-external-body" "$PROJECT_DIR/formal/verus" "*.rs" '#\[[[:space:]]*verifier::external_body[[:space:]]*\]'
scan_hits "verus-external-fn-spec" "$PROJECT_DIR/formal/verus" "*.rs" '#\[[[:space:]]*verifier::external_fn_specification([^[:alnum:]_]|$)'
scan_hits "verus-trusted-marker" "$PROJECT_DIR/formal/verus" "*.rs" '(^|[^[:alnum:]_])TRUSTED([^[:alnum:]_]|$)'
scan_hits "lean-axiom" "$PROJECT_DIR/formal/lean" "*.lean" '^[[:space:]]*axiom[[:space:]]'
scan_hits "coq-axiom" "$PROJECT_DIR/formal/coq" "*.v" '^[[:space:]]*(Axiom|Parameter)[[:space:]]'

echo "=== Formal Trusted Assumption Inventory ==="
echo "Canonical registry: $REGISTRY"
echo "Expected entries: ${#allowed[@]}"
echo "Observed entries: ${#actual[@]}"
report_inventory "Verus assume/admit" "verus-assume"
report_inventory "Verus axioms" "verus-axiom"
report_inventory "Verus external bodies" "verus-external-body"
report_inventory "Verus external fn specs" "verus-external-fn-spec"
report_inventory "Verus trusted markers" "verus-trusted-marker"
report_inventory "Lean axioms" "lean-axiom"
report_inventory "Coq axioms/parameters" "coq-axiom"
echo ""

for key in "${!actual[@]}"; do
    if [ -z "${allowed[$key]+set}" ]; then
        unexpected=1
    fi
done

for key in "${!allowed[@]}"; do
    if [ -z "${actual[$key]+set}" ]; then
        stale=1
    fi
done

if [ "$unexpected" -ne 0 ] || [ "$stale" -ne 0 ]; then
    if [ "$unexpected" -ne 0 ]; then
        declare -A unexpected_keys=()
        for key in "${!actual[@]}"; do
            if [ -z "${allowed[$key]+set}" ]; then
                unexpected_keys["$key"]=1
            fi
        done
        report_mismatches "UNEXPECTED" unexpected_keys
    fi

    if [ "$stale" -ne 0 ]; then
        declare -A stale_keys=()
        for key in "${!allowed[@]}"; do
            if [ -z "${actual[$key]+set}" ]; then
                stale_keys["$key"]=1
            fi
        done
        report_mismatches "STALE" stale_keys
    fi

    echo ""
    echo "FAIL: trusted assumption inventory drifted from formal/trusted-assumptions.allowlist"
    exit 1
fi

echo "All trusted assumptions are explicitly allowlisted."
