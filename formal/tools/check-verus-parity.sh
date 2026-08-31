#!/usr/bin/env bash
#
# check-verus-parity.sh — Verify Verus proof targets still align with production
#
# Usage: bash formal/tools/check-verus-parity.sh
# Exit code: 0 = all checks passed, 1 = drift detected

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DRIFT_FOUND=0
VERUS_MANIFEST="$PROJECT_DIR/formal/verus/Cargo.toml"
VERUS_LIB="$PROJECT_DIR/formal/verus/src/lib.rs"

fail() {
    echo "  DRIFT: $1"
    DRIFT_FOUND=1
}

pass() {
    echo "  OK: $1"
}

check_file_pair() {
    local label="$1"
    local prod_file="$2"
    local verus_file="$3"

    if [ ! -f "$prod_file" ]; then
        fail "$label — production file not found: $prod_file"
        return
    fi
    if [ ! -f "$verus_file" ]; then
        fail "$label — verus file not found: $verus_file"
        return
    fi

    pass "$label"
}

check_symbol_parity() {
    local label="$1"
    local prod_file="$2"
    local prod_pattern="$3"
    local verus_file="$4"
    local verus_pattern="$5"

    if [ ! -f "$prod_file" ]; then
        fail "$label — production file not found: $prod_file"
        return
    fi
    if [ ! -f "$verus_file" ]; then
        fail "$label — verus file not found: $verus_file"
        return
    fi

    if ! grep -Eq "$prod_pattern" "$prod_file" 2>/dev/null; then
        fail "$label — production pattern '$prod_pattern' not found in $prod_file"
        return
    fi
    if ! grep -Eq "$verus_pattern" "$verus_file" 2>/dev/null; then
        fail "$label — verus pattern '$verus_pattern' not found in $verus_file"
        return
    fi

    pass "$label"
}

check_multiline_symbol_parity() {
    local label="$1"
    local prod_file="$2"
    local prod_pattern="$3"
    local verus_file="$4"
    local verus_pattern="$5"

    if [ ! -f "$prod_file" ]; then
        fail "$label — production file not found: $prod_file"
        return
    fi
    if [ ! -f "$verus_file" ]; then
        fail "$label — verus file not found: $verus_file"
        return
    fi

    if ! PROD_PATTERN="$prod_pattern" perl -0ne '
        BEGIN { $pattern = $ENV{PROD_PATTERN}; $found = 0; }
        $found = 1 if /$pattern/s;
        END { exit($found ? 0 : 1); }
    ' "$prod_file" 2>/dev/null; then
        fail "$label — production pattern '$prod_pattern' not found in $prod_file"
        return
    fi
    if ! grep -Eq "$verus_pattern" "$verus_file" 2>/dev/null; then
        fail "$label — verus pattern '$verus_pattern' not found in $verus_file"
        return
    fi

    pass "$label"
}

list_verus_kernels() {
    find "$PROJECT_DIR/formal/verus" -maxdepth 1 -name 'verified_*.rs' -printf '%f\n' | sort
}

list_cargo_verus_shim_kernels() {
    sed -n 's|^[[:space:]]*#\[path = "\.\./\(verified_[^"]*\.rs\)"\][[:space:]]*$|\1|p' "$VERUS_LIB" | sort
}

echo "=== Verus Proof Target Parity Check ==="
echo ""

PROD_CORE="$PROJECT_DIR/vellaveto-engine/src/verified_core.rs"
VERUS_CORE="$PROJECT_DIR/formal/verus/verified_core.rs"
PROD_CAPABILITY_CONTEXT="$PROJECT_DIR/vellaveto-engine/src/verified_capability_context.rs"
PROD_CAPABILITY_DELEGATION_CONTEXT="$PROJECT_DIR/vellaveto-engine/src/verified_capability_delegation_context.rs"
PROD_CONTEXT_DELEGATION="$PROJECT_DIR/vellaveto-engine/src/verified_context_delegation.rs"
PROD_CONTEXT_WRAPPER="$PROJECT_DIR/vellaveto-engine/src/context_check.rs"
VERUS_CAPABILITY_CONTEXT="$PROJECT_DIR/formal/verus/verified_capability_context.rs"
VERUS_CAPABILITY_DELEGATION_CONTEXT="$PROJECT_DIR/formal/verus/verified_capability_delegation_context.rs"
VERUS_CONTEXT_DELEGATION="$PROJECT_DIR/formal/verus/verified_context_delegation.rs"
PROD_BRIDGE_PRINCIPAL="$PROJECT_DIR/vellaveto-mcp/src/verified_bridge_principal.rs"
PROD_DELEGATION_PROJECTION="$PROJECT_DIR/vellaveto-mcp/src/verified_delegation_projection.rs"
PROD_DEPUTY_HANDOFF="$PROJECT_DIR/vellaveto-mcp/src/verified_deputy_handoff.rs"
PROD_EVAL_CONTEXT_PROJECTION="$PROJECT_DIR/vellaveto-mcp/src/verified_evaluation_context_projection.rs"
PROD_TRANSPORT_CONTEXT="$PROJECT_DIR/vellaveto-types/src/verified_transport_context.rs"
PROD_PRESENTED_APPROVAL_ID="$PROJECT_DIR/vellaveto-approval/src/verified_presented_approval_id.rs"
PROD_SERVER_APPROVAL_ID="$PROJECT_DIR/vellaveto-server/src/verified_approval_id.rs"
PROD_APPROVAL_CONSUMPTION="$PROJECT_DIR/vellaveto-approval/src/verified_approval_consumption.rs"
PROD_APPROVAL_SCOPE="$PROJECT_DIR/vellaveto-approval/src/verified_approval_scope.rs"
PROD_RELAY_WRAPPER="$PROJECT_DIR/vellaveto-mcp/src/proxy/bridge/relay.rs"
PROD_SERVER_CONTEXT_WRAPPER="$PROJECT_DIR/vellaveto-server/src/routes/main.rs"
PROD_SERVER_APPROVAL_ROUTE="$PROJECT_DIR/vellaveto-server/src/routes/approval.rs"
PROD_HTTP_PROXY_HANDLERS="$PROJECT_DIR/vellaveto-http-proxy/src/proxy/handlers.rs"
PROD_HTTP_PROXY_GRPC_SERVICE="$PROJECT_DIR/vellaveto-http-proxy/src/proxy/grpc/service.rs"
PROD_HTTP_PROXY_WEBSOCKET="$PROJECT_DIR/vellaveto-http-proxy/src/proxy/websocket/mod.rs"
PROD_HTTP_PROXY_HELPERS="$PROJECT_DIR/vellaveto-http-proxy/src/proxy/helpers.rs"
PROD_MCP_HELPERS="$PROJECT_DIR/vellaveto-mcp/src/proxy/bridge/helpers.rs"
PROD_APPROVAL_WRAPPER="$PROJECT_DIR/vellaveto-approval/src/lib.rs"
PROD_REDIS_BACKEND="$PROJECT_DIR/vellaveto-cluster/src/redis_backend.rs"
VERUS_BRIDGE_PRINCIPAL="$PROJECT_DIR/formal/verus/verified_bridge_principal.rs"
VERUS_DELEGATION_PROJECTION="$PROJECT_DIR/formal/verus/verified_delegation_projection.rs"
VERUS_DEPUTY_HANDOFF="$PROJECT_DIR/formal/verus/verified_deputy_handoff.rs"
VERUS_EVAL_CONTEXT_PROJECTION="$PROJECT_DIR/formal/verus/verified_evaluation_context_projection.rs"
VERUS_TRANSPORT_CONTEXT="$PROJECT_DIR/formal/verus/verified_transport_context.rs"
VERUS_PRESENTED_APPROVAL_ID="$PROJECT_DIR/formal/verus/verified_presented_approval_id.rs"
VERUS_SERVER_APPROVAL_ID="$PROJECT_DIR/formal/verus/verified_server_approval_id.rs"
VERUS_APPROVAL_CONSUMPTION="$PROJECT_DIR/formal/verus/verified_approval_consumption.rs"
VERUS_APPROVAL_SCOPE="$PROJECT_DIR/formal/verus/verified_approval_scope.rs"
PROD_CONSTRAINT="$PROJECT_DIR/vellaveto-engine/src/verified_constraint_eval.rs"
PROD_CONSTRAINT_WRAPPER="$PROJECT_DIR/vellaveto-engine/src/constraint_eval.rs"
VERUS_CONSTRAINT="$PROJECT_DIR/formal/verus/verified_constraint_eval.rs"
PROD_DEPUTY="$PROJECT_DIR/vellaveto-engine/src/verified_deputy.rs"
PROD_DEPUTY_WRAPPER="$PROJECT_DIR/vellaveto-engine/src/deputy.rs"
VERUS_DEPUTY="$PROJECT_DIR/formal/verus/verified_deputy.rs"
PROD_AUDIT_APPEND="$PROJECT_DIR/vellaveto-audit/src/verified_audit_append.rs"
PROD_AUDIT_CHAIN="$PROJECT_DIR/vellaveto-audit/src/verified_audit_chain.rs"
PROD_AUDIT_APPEND_WRAPPER="$PROJECT_DIR/vellaveto-audit/src/logger.rs"
PROD_AUDIT_WRAPPER="$PROJECT_DIR/vellaveto-audit/src/verification.rs"
PROD_AUDIT_RECOVERY_WRAPPER="$PROJECT_DIR/vellaveto-audit/src/rotation.rs"
PROD_MERKLE="$PROJECT_DIR/vellaveto-audit/src/verified_merkle.rs"
PROD_MERKLE_FOLD="$PROJECT_DIR/vellaveto-audit/src/verified_merkle_fold.rs"
PROD_MERKLE_PATH="$PROJECT_DIR/vellaveto-audit/src/verified_merkle_path.rs"
PROD_MERKLE_WRAPPER="$PROJECT_DIR/vellaveto-audit/src/merkle.rs"
PROD_ROTATION_MANIFEST="$PROJECT_DIR/vellaveto-audit/src/verified_rotation_manifest.rs"
PROD_CAPABILITY_ATTENUATION="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_attenuation.rs"
PROD_CAPABILITY_COVERAGE="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_coverage.rs"
PROD_CAPABILITY_DOMAIN="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_domain.rs"
PROD_CAPABILITY_GLOB="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_glob.rs"
PROD_CAPABILITY_GLOB_SUBSET="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_glob_subset.rs"
PROD_CAPABILITY_GRANT="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_grant.rs"
PROD_CAPABILITY_IDENTITY="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_identity.rs"
PROD_CAPABILITY_LITERAL="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_literal.rs"
PROD_CAPABILITY_PATTERN="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_pattern.rs"
PROD_CAPABILITY_PATH="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_path.rs"
PROD_CAPABILITY_SELECTION="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_selection.rs"
PROD_CAPABILITY_VERIFICATION="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_verification.rs"
PROD_CAPABILITY_WRAPPER="$PROJECT_DIR/vellaveto-mcp/src/capability_token.rs"
PROD_NHI="$PROJECT_DIR/vellaveto-mcp/src/verified_nhi_delegation.rs"
PROD_NHI_GRAPH="$PROJECT_DIR/vellaveto-mcp/src/verified_nhi_graph.rs"
PROD_NHI_WRAPPER="$PROJECT_DIR/vellaveto-mcp/src/nhi.rs"
VERUS_AUDIT_CHAIN="$PROJECT_DIR/formal/verus/verified_audit_chain.rs"
VERUS_AUDIT_APPEND="$PROJECT_DIR/formal/verus/verified_audit_append.rs"
VERUS_MERKLE="$PROJECT_DIR/formal/verus/verified_merkle.rs"
VERUS_MERKLE_FOLD="$PROJECT_DIR/formal/verus/verified_merkle_fold.rs"
VERUS_MERKLE_PATH="$PROJECT_DIR/formal/verus/verified_merkle_path.rs"
VERUS_MERKLE_INTEGRITY="$PROJECT_DIR/formal/verus/verified_merkle_integrity.rs"
VERUS_AUDIT_INTEGRITY="$PROJECT_DIR/formal/verus/verified_audit_integrity.rs"
VERUS_ROTATION_MANIFEST="$PROJECT_DIR/formal/verus/verified_rotation_manifest.rs"
VERUS_CAPABILITY_ATTENUATION="$PROJECT_DIR/formal/verus/verified_capability_attenuation.rs"
VERUS_CAPABILITY_COVERAGE="$PROJECT_DIR/formal/verus/verified_capability_coverage.rs"
VERUS_CAPABILITY_DOMAIN="$PROJECT_DIR/formal/verus/verified_capability_domain.rs"
VERUS_CAPABILITY_GLOB="$PROJECT_DIR/formal/verus/verified_capability_glob.rs"
VERUS_CAPABILITY_GLOB_SUBSET="$PROJECT_DIR/formal/verus/verified_capability_glob_subset.rs"
VERUS_CAPABILITY_GRANT="$PROJECT_DIR/formal/verus/verified_capability_grant.rs"
VERUS_CAPABILITY_IDENTITY="$PROJECT_DIR/formal/verus/verified_capability_identity.rs"
VERUS_CAPABILITY_LITERAL="$PROJECT_DIR/formal/verus/verified_capability_literal.rs"
VERUS_CAPABILITY_PATTERN="$PROJECT_DIR/formal/verus/verified_capability_pattern.rs"
VERUS_CAPABILITY_PATH="$PROJECT_DIR/formal/verus/verified_capability_path.rs"
VERUS_CAPABILITY_SELECTION="$PROJECT_DIR/formal/verus/verified_capability_selection.rs"
VERUS_CAPABILITY_VERIFICATION="$PROJECT_DIR/formal/verus/verified_capability_verification.rs"
VERUS_NHI="$PROJECT_DIR/formal/verus/verified_nhi_delegation.rs"
VERUS_NHI_GRAPH="$PROJECT_DIR/formal/verus/verified_nhi_graph.rs"
PROD_ENTROPY="$PROJECT_DIR/vellaveto-engine/src/verified_entropy_gate.rs"
PROD_ENTROPY_WRAPPER="$PROJECT_DIR/vellaveto-engine/src/entropy_gate.rs"
VERUS_ENTROPY="$PROJECT_DIR/formal/verus/verified_entropy_gate.rs"
PROD_CROSS_DLP="$PROJECT_DIR/vellaveto-mcp/src/inspection/verified_cross_call_dlp.rs"
PROD_CROSS_DLP_WRAPPER="$PROJECT_DIR/vellaveto-mcp/src/inspection/cross_call_dlp.rs"
VERUS_CROSS_DLP="$PROJECT_DIR/formal/verus/verified_cross_call_dlp.rs"
PROD_DLP="$PROJECT_DIR/vellaveto-mcp/src/inspection/verified_dlp_core.rs"
VERUS_DLP="$PROJECT_DIR/formal/verus/verified_dlp_core.rs"
PROD_PATH="$PROJECT_DIR/vellaveto-engine/src/path.rs"
VERUS_PATH="$PROJECT_DIR/formal/verus/verified_path.rs"
PROD_ACIS_TYPES="$PROJECT_DIR/vellaveto-types/src/acis.rs"
PROD_ACIS_ENGINE="$PROJECT_DIR/vellaveto-engine/src/acis.rs"
VERUS_ACIS_ACTION_SUMMARY="$PROJECT_DIR/formal/verus/verified_acis_action_summary.rs"
PROD_PROVENANCE="$PROJECT_DIR/vellaveto-types/src/provenance.rs"
VERUS_SOURCE_TAINT="$PROJECT_DIR/formal/verus/verified_source_taint.rs"
PROD_CHANNEL_SEPARATION="$PROJECT_DIR/vellaveto-config/src/channel_separation.rs"
VERUS_INTENT_SCOPE="$PROJECT_DIR/formal/verus/verified_intent_scope.rs"
PROD_SEQUENCE="$PROJECT_DIR/vellaveto-engine/src/sequence.rs"
PROD_SEQUENCE_GATE="$PROJECT_DIR/vellaveto-engine/src/verified_sequence_gate.rs"
PROD_SCOPE_MASK="$PROJECT_DIR/vellaveto-types/src/verified_intent_scope.rs"
PROD_SEQUENCE_RELAY="$PROJECT_DIR/vellaveto-mcp/src/proxy/bridge/relay.rs"
VERUS_SEQUENCE_ANALYSIS="$PROJECT_DIR/formal/verus/verified_sequence_analysis.rs"
PROD_TRACED="$PROJECT_DIR/vellaveto-engine/src/traced.rs"
PROD_REFINEMENT_WITNESS="$PROJECT_DIR/vellaveto-engine/tests/refinement_trace.rs"
VERUS_REFINEMENT_COMPLETENESS="$PROJECT_DIR/formal/verus/verified_refinement_completeness.rs"
VERUS_ENTROPY_PIPELINE="$PROJECT_DIR/formal/verus/verified_entropy_pipeline.rs"
VERUS_ENTROPY_FIXED_POINT="$PROJECT_DIR/formal/verus/verified_entropy_fixed_point.rs"
VERUS_FLOAT_AXIOMS="$PROJECT_DIR/formal/verus/float_boundary_axioms.rs"
VERUS_CROSS_CALL_SPLIT="$PROJECT_DIR/formal/verus/verified_cross_call_split.rs"
PROD_CAP_TOKEN="$PROJECT_DIR/vellaveto-mcp/src/capability_token.rs"
VERUS_CAP_CHAIN="$PROJECT_DIR/formal/verus/verified_capability_chain.rs"

echo "--- Cargo Verus Entrypoint ---"
check_file_pair \
    "formal/verus/Cargo.toml ↔ formal/verus/src/lib.rs" \
    "$VERUS_MANIFEST" \
    "$VERUS_LIB"
check_symbol_parity \
    "Verus manifest pins the expected vstd crate version" \
    "$VERUS_MANIFEST" \
    'vstd[[:space:]]*=[[:space:]]*"=0\.0\.0-2026-03-01-0109"' \
    "$VERUS_LIB" \
    'verified_core\.rs'
while IFS= read -r verus_file; do
    module="${verus_file%.rs}"
    check_symbol_parity \
        "$module is wired into the cargo-verus shim" \
        "$VERUS_LIB" \
        "${module}\\.rs" \
        "$PROJECT_DIR/formal/verus/$verus_file" \
        'verus!'
done < <(list_verus_kernels)
while IFS= read -r verus_file; do
    if [ ! -f "$PROJECT_DIR/formal/verus/$verus_file" ]; then
        fail "cargo-verus shim references missing kernel: formal/verus/$verus_file"
    fi
done < <(list_cargo_verus_shim_kernels)
echo ""

echo "--- Core Verdict ---"
check_file_pair "verified_core.rs ↔ vellaveto-engine/src/verified_core.rs" "$PROD_CORE" "$VERUS_CORE"
check_symbol_parity \
    "compute_single_verdict exists in production and Verus" \
    "$PROD_CORE" \
    'pub[[:space:]]+fn[[:space:]]+compute_single_verdict' \
    "$VERUS_CORE" \
    'pub[[:space:]]+fn[[:space:]]+compute_single_verdict'
check_symbol_parity \
    "compute_verdict exists in production and Verus" \
    "$PROD_CORE" \
    'pub[[:space:]]+fn[[:space:]]+compute_verdict' \
    "$VERUS_CORE" \
    'pub[[:space:]]+fn[[:space:]]+compute_verdict'
echo ""

echo "--- Capability Context Kernel ---"
check_file_pair \
    "verified_capability_context.rs ↔ vellaveto-engine/src/verified_capability_context.rs" \
    "$PROD_CAPABILITY_CONTEXT" \
    "$VERUS_CAPABILITY_CONTEXT"
for fn in capability_holder_binding_valid capability_issuer_allowed capability_remaining_depth_sufficient; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_CONTEXT" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_CONTEXT" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "require_capability_token uses verified holder-binding guard" \
    "$PROD_CONTEXT_WRAPPER" \
    'verified_capability_context::capability_holder_binding_valid' \
    "$VERUS_CAPABILITY_CONTEXT" \
    'pub[[:space:]]+fn[[:space:]]+capability_holder_binding_valid'
check_symbol_parity \
    "require_capability_token uses verified issuer-allowlist guard" \
    "$PROD_CONTEXT_WRAPPER" \
    'verified_capability_context::capability_issuer_allowed' \
    "$VERUS_CAPABILITY_CONTEXT" \
    'pub[[:space:]]+fn[[:space:]]+capability_issuer_allowed'
check_symbol_parity \
    "require_capability_token uses verified depth-threshold guard" \
    "$PROD_CONTEXT_WRAPPER" \
    'verified_capability_context::capability_remaining_depth_sufficient' \
    "$VERUS_CAPABILITY_CONTEXT" \
    'pub[[:space:]]+fn[[:space:]]+capability_remaining_depth_sufficient'
echo ""

echo "--- Capability Delegation Context Kernel ---"
check_file_pair \
    "verified_capability_delegation_context.rs ↔ vellaveto-engine/src/verified_capability_delegation_context.rs" \
    "$PROD_CAPABILITY_DELEGATION_CONTEXT" \
    "$VERUS_CAPABILITY_DELEGATION_CONTEXT"
for fn in delegated_capability_principal_and_holder_valid delegated_capability_depths_valid delegated_capability_issuer_valid delegated_capability_context_valid; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_DELEGATION_CONTEXT" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_DELEGATION_CONTEXT" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "context checker uses verified combined delegated capability context guard" \
    "$PROD_CONTEXT_WRAPPER" \
    'verified_capability_delegation_context::delegated_capability_context_valid' \
    "$VERUS_CAPABILITY_DELEGATION_CONTEXT" \
    'pub[[:space:]]+fn[[:space:]]+delegated_capability_context_valid'
echo ""

echo "--- Context Delegation Kernel ---"
check_file_pair \
    "verified_context_delegation.rs ↔ vellaveto-engine/src/verified_context_delegation.rs" \
    "$PROD_CONTEXT_DELEGATION" \
    "$VERUS_CONTEXT_DELEGATION"
for fn in identified_principal_present principal_requirement_satisfied chain_depth_within_limit delegation_depth_within_limit; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CONTEXT_DELEGATION" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CONTEXT_DELEGATION" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "context checker uses verified call-chain depth guard" \
    "$PROD_CONTEXT_WRAPPER" \
    'verified_context_delegation::chain_depth_within_limit' \
    "$VERUS_CONTEXT_DELEGATION" \
    'pub[[:space:]]+fn[[:space:]]+chain_depth_within_limit'
check_symbol_parity \
    "context checker uses verified principal-presence guard" \
    "$PROD_CONTEXT_WRAPPER" \
    'verified_context_delegation::identified_principal_present' \
    "$VERUS_CONTEXT_DELEGATION" \
    'pub[[:space:]]+fn[[:space:]]+identified_principal_present'
check_symbol_parity \
    "context checker uses verified principal-requirement guard" \
    "$PROD_CONTEXT_WRAPPER" \
    'verified_context_delegation::principal_requirement_satisfied' \
    "$VERUS_CONTEXT_DELEGATION" \
    'pub[[:space:]]+fn[[:space:]]+principal_requirement_satisfied'
check_symbol_parity \
    "context checker uses verified delegation-depth guard" \
    "$PROD_CONTEXT_WRAPPER" \
    'verified_context_delegation::delegation_depth_within_limit' \
    "$VERUS_CONTEXT_DELEGATION" \
    'pub[[:space:]]+fn[[:space:]]+delegation_depth_within_limit'
echo ""

echo "--- Bridge Principal Kernel ---"
check_file_pair \
    "verified_bridge_principal.rs ↔ vellaveto-mcp/src/verified_bridge_principal.rs" \
    "$PROD_BRIDGE_PRINCIPAL" \
    "$VERUS_BRIDGE_PRINCIPAL"
for fn in configured_claim_consistent deputy_principal_source evaluation_principal_source; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_BRIDGE_PRINCIPAL" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_BRIDGE_PRINCIPAL" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "relay uses verified configured-vs-claimed consistency guard" \
    "$PROD_RELAY_WRAPPER" \
    'verified_bridge_principal::configured_claim_consistent' \
    "$VERUS_BRIDGE_PRINCIPAL" \
    'pub[[:space:]]+fn[[:space:]]+configured_claim_consistent'
check_symbol_parity \
    "relay uses verified deputy principal-source selector" \
    "$PROD_RELAY_WRAPPER" \
    'verified_bridge_principal::deputy_principal_source' \
    "$VERUS_BRIDGE_PRINCIPAL" \
    'pub[[:space:]]+fn[[:space:]]+deputy_principal_source'
check_symbol_parity \
    "relay uses verified evaluation principal-source selector" \
    "$PROD_RELAY_WRAPPER" \
    'verified_bridge_principal::evaluation_principal_source' \
    "$VERUS_BRIDGE_PRINCIPAL" \
    'pub[[:space:]]+fn[[:space:]]+evaluation_principal_source'
echo ""

echo "--- Delegation Projection Kernel ---"
check_file_pair \
    "verified_delegation_projection.rs ↔ vellaveto-mcp/src/verified_delegation_projection.rs" \
    "$PROD_DELEGATION_PROJECTION" \
    "$VERUS_DELEGATION_PROJECTION"
check_symbol_parity \
    "projected_call_chain_len exists in production and Verus" \
    "$PROD_DELEGATION_PROJECTION" \
    'pub\(crate\)[[:space:]]+const[[:space:]]+fn[[:space:]]+projected_call_chain_len|pub\(crate\)[[:space:]]+fn[[:space:]]+projected_call_chain_len' \
    "$VERUS_DELEGATION_PROJECTION" \
    'pub[[:space:]]+fn[[:space:]]+projected_call_chain_len'
check_symbol_parity \
    "evaluation-context projection uses verified delegation-depth projection" \
    "$PROD_EVAL_CONTEXT_PROJECTION" \
    'verified_delegation_projection::projected_call_chain_len' \
    "$VERUS_DELEGATION_PROJECTION" \
    'pub[[:space:]]+fn[[:space:]]+projected_call_chain_len'
echo ""

echo "--- Deputy Handoff Kernel ---"
check_file_pair \
    "verified_deputy_handoff.rs ↔ vellaveto-mcp/src/verified_deputy_handoff.rs" \
    "$PROD_DEPUTY_HANDOFF" \
    "$VERUS_DEPUTY_HANDOFF"
for fn in deputy_validated_claim_trusted evaluation_principal_source_after_deputy; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_DEPUTY_HANDOFF" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_DEPUTY_HANDOFF" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "evaluation-context projection uses verified deputy-validated claim guard" \
    "$PROD_EVAL_CONTEXT_PROJECTION" \
    'verified_deputy_handoff::deputy_validated_claim_trusted' \
    "$VERUS_DEPUTY_HANDOFF" \
    'pub[[:space:]]+fn[[:space:]]+deputy_validated_claim_trusted'
check_symbol_parity \
    "evaluation-context projection uses verified post-deputy evaluation principal selector" \
    "$PROD_EVAL_CONTEXT_PROJECTION" \
    'verified_deputy_handoff::evaluation_principal_source_after_deputy' \
    "$VERUS_DEPUTY_HANDOFF" \
    'pub[[:space:]]+fn[[:space:]]+evaluation_principal_source_after_deputy'
echo ""

echo "--- Evaluation Context Projection Kernel ---"
check_file_pair \
    "verified_evaluation_context_projection.rs ↔ vellaveto-mcp/src/verified_evaluation_context_projection.rs" \
    "$PROD_EVAL_CONTEXT_PROJECTION" \
    "$VERUS_EVAL_CONTEXT_PROJECTION"
check_symbol_parity \
    "project_evaluation_context exists in production and Verus" \
    "$PROD_EVAL_CONTEXT_PROJECTION" \
    'pub\(crate\)[[:space:]]+const[[:space:]]+fn[[:space:]]+project_evaluation_context|pub\(crate\)[[:space:]]+fn[[:space:]]+project_evaluation_context' \
    "$VERUS_EVAL_CONTEXT_PROJECTION" \
    'pub[[:space:]]+fn[[:space:]]+project_evaluation_context'
check_symbol_parity \
    "relay uses verified evaluation-context projection" \
    "$PROD_RELAY_WRAPPER" \
    'verified_evaluation_context_projection::project_evaluation_context' \
    "$VERUS_EVAL_CONTEXT_PROJECTION" \
    'pub[[:space:]]+fn[[:space:]]+project_evaluation_context'
echo ""

echo "--- Presented Approval ID Kernel ---"
check_file_pair \
    "verified_presented_approval_id.rs ↔ vellaveto-approval/src/verified_presented_approval_id.rs" \
    "$PROD_PRESENTED_APPROVAL_ID" \
    "$VERUS_PRESENTED_APPROVAL_ID"
for fn in \
    presented_approval_id_length_valid \
    presented_approval_id_value_accepted
do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_PRESENTED_APPROVAL_ID" \
        "pub[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_PRESENTED_APPROVAL_ID" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "shared RPC meta approval extractor uses the verified presented-approval-id kernel" \
    "$PROD_APPROVAL_WRAPPER" \
    'verified_presented_approval_id::presented_approval_id_value_accepted' \
    "$VERUS_PRESENTED_APPROVAL_ID" \
    'pub[[:space:]]+fn[[:space:]]+presented_approval_id_value_accepted'
check_symbol_parity \
    "MCP relay helper uses the shared RPC meta approval extractor" \
    "$PROD_MCP_HELPERS" \
    'extract_presented_approval_id_from_rpc_meta' \
    "$VERUS_PRESENTED_APPROVAL_ID" \
    'pub[[:space:]]+fn[[:space:]]+presented_approval_id_value_accepted'
check_symbol_parity \
    "HTTP proxy helper uses the shared RPC meta approval extractor" \
    "$PROD_HTTP_PROXY_HELPERS" \
    'extract_presented_approval_id_from_rpc_meta' \
    "$VERUS_PRESENTED_APPROVAL_ID" \
    'pub[[:space:]]+fn[[:space:]]+presented_approval_id_value_accepted'
echo ""

echo "--- Server Approval ID Kernel ---"
check_file_pair \
    "verified_server_approval_id.rs ↔ vellaveto-server/src/verified_approval_id.rs" \
    "$PROD_SERVER_APPROVAL_ID" \
    "$VERUS_SERVER_APPROVAL_ID"
for fn in \
    server_approval_id_length_valid \
    server_approval_id_value_accepted
do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_SERVER_APPROVAL_ID" \
        "pub[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_SERVER_APPROVAL_ID" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "server approval route validator uses the verified server approval-id kernel" \
    "$PROD_SERVER_APPROVAL_ROUTE" \
    'verified_approval_id::server_approval_id_value_accepted' \
    "$VERUS_SERVER_APPROVAL_ID" \
    'pub[[:space:]]+fn[[:space:]]+server_approval_id_value_accepted'
check_symbol_parity \
    "server evaluate route validates the presented approval header through validate_approval_id" \
    "$PROD_SERVER_CONTEXT_WRAPPER" \
    'super::approval::validate_approval_id\(approval_id\)' \
    "$VERUS_SERVER_APPROVAL_ID" \
    'pub[[:space:]]+fn[[:space:]]+server_approval_id_value_accepted'
echo ""

echo "--- Approval Consumption Kernel ---"
check_file_pair \
    "verified_approval_consumption.rs ↔ vellaveto-approval/src/verified_approval_consumption.rs" \
    "$PROD_APPROVAL_CONSUMPTION" \
    "$VERUS_APPROVAL_CONSUMPTION"
for fn in \
    approval_status_allows_consumption \
    approval_binding_allows_consumption \
    approval_consumption_permitted
do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_APPROVAL_CONSUMPTION" \
        "pub[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_APPROVAL_CONSUMPTION" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "ApprovalStore::consume_approved uses the verified approval-consumption kernel" \
    "$PROD_APPROVAL_WRAPPER" \
    'verified_approval_consumption::approval_consumption_permitted' \
    "$VERUS_APPROVAL_CONSUMPTION" \
    'pub[[:space:]]+fn[[:space:]]+approval_consumption_permitted'
check_symbol_parity \
    "ApprovalStore::consume_approved transitions permitted approvals to Consumed" \
    "$PROD_APPROVAL_WRAPPER" \
    'approval\.status[[:space:]]*=[[:space:]]*ApprovalStatus::Consumed' \
    "$VERUS_APPROVAL_CONSUMPTION" \
    'pub[[:space:]]+fn[[:space:]]+approval_consumption_permitted'
check_symbol_parity \
    "server evaluate route consumes presented approvals on allow" \
    "$PROD_SERVER_CONTEXT_WRAPPER" \
    'consume_approved_approval\(' \
    "$VERUS_APPROVAL_CONSUMPTION" \
    'pub[[:space:]]+fn[[:space:]]+approval_consumption_permitted'
check_multiline_symbol_parity \
    "relay final-allow path consumes presented approvals" \
    "$PROD_RELAY_WRAPPER" \
    '\.consume_presented_approval\([[:space:]]*Some\(approval_id\.as_str\(\)\),[[:space:]]*&action' \
    "$VERUS_APPROVAL_CONSUMPTION" \
    'pub[[:space:]]+fn[[:space:]]+approval_consumption_permitted'
check_symbol_parity \
    "http proxy JSON-RPC path consumes presented approvals" \
    "$PROD_HTTP_PROXY_HANDLERS" \
    'consume_presented_approval\(' \
    "$VERUS_APPROVAL_CONSUMPTION" \
    'pub[[:space:]]+fn[[:space:]]+approval_consumption_permitted'
check_symbol_parity \
    "http proxy WebSocket path consumes presented approvals" \
    "$PROD_HTTP_PROXY_WEBSOCKET" \
    'consume_presented_approval\(' \
    "$VERUS_APPROVAL_CONSUMPTION" \
    'pub[[:space:]]+fn[[:space:]]+approval_consumption_permitted'
check_symbol_parity \
    "http proxy gRPC path consumes presented approvals" \
    "$PROD_HTTP_PROXY_GRPC_SERVICE" \
    'consume_presented_approval\(' \
    "$VERUS_APPROVAL_CONSUMPTION" \
    'pub[[:space:]]+fn[[:space:]]+approval_consumption_permitted'
check_symbol_parity \
    "Redis consume script rejects non-Approved approvals" \
    "$PROD_REDIS_BACKEND" \
    "approval\\['status'\\][[:space:]]*~=[[:space:]]*'Approved'" \
    "$VERUS_APPROVAL_CONSUMPTION" \
    'pub[[:space:]]+fn[[:space:]]+approval_status_allows_consumption'
check_symbol_parity \
    "Redis consume script rejects approvals without action fingerprints" \
    "$PROD_REDIS_BACKEND" \
    "if[[:space:]]+not[[:space:]]+bound_fingerprint[[:space:]]+or[[:space:]]+bound_fingerprint[[:space:]]*==[[:space:]]*cjson\\.null" \
    "$VERUS_APPROVAL_CONSUMPTION" \
    'pub[[:space:]]+fn[[:space:]]+approval_binding_allows_consumption'
check_symbol_parity \
    "Redis consume script transitions successful consumes to Consumed" \
    "$PROD_REDIS_BACKEND" \
    "approval\\['status'\\][[:space:]]*=[[:space:]]*'Consumed'" \
    "$VERUS_APPROVAL_CONSUMPTION" \
    'pub[[:space:]]+fn[[:space:]]+approval_consumption_permitted'
echo ""

echo "--- Approval Scope Kernel ---"
check_file_pair \
    "verified_approval_scope.rs ↔ vellaveto-approval/src/verified_approval_scope.rs" \
    "$PROD_APPROVAL_SCOPE" \
    "$VERUS_APPROVAL_SCOPE"
for fn in \
    approval_session_binding_satisfied \
    approval_fingerprint_binding_satisfied \
    approval_scope_binding_satisfied
do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_APPROVAL_SCOPE" \
        "pub[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_APPROVAL_SCOPE" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "PendingApproval::scope_matches uses the verified approval-scope kernel" \
    "$PROD_APPROVAL_WRAPPER" \
    'verified_approval_scope::approval_scope_binding_satisfied' \
    "$VERUS_APPROVAL_SCOPE" \
    'pub[[:space:]]+fn[[:space:]]+approval_scope_binding_satisfied'
check_symbol_parity \
    "server evaluate route uses approval scope matching for presented approvals" \
    "$PROD_SERVER_CONTEXT_WRAPPER" \
    'scope_matches\(None,[[:space:]]*Some\(action_fingerprint\.as_str\(\)\)\)' \
    "$VERUS_APPROVAL_SCOPE" \
    'pub[[:space:]]+fn[[:space:]]+approval_scope_binding_satisfied'
check_symbol_parity \
    "relay presented approval matcher uses session-bound approval scope matching" \
    "$PROD_RELAY_WRAPPER" \
    'scope_matches\(session_scope_binding,[[:space:]]*Some\(action_fingerprint\.as_str\(\)\)\)' \
    "$VERUS_APPROVAL_SCOPE" \
    'pub[[:space:]]+fn[[:space:]]+approval_scope_binding_satisfied'
check_symbol_parity \
    "http proxy presented approval matcher uses session-bound approval scope matching" \
    "$PROD_HTTP_PROXY_HELPERS" \
    'Some\(session_scope_binding\.as_str\(\)\)' \
    "$VERUS_APPROVAL_SCOPE" \
    'pub[[:space:]]+fn[[:space:]]+approval_scope_binding_satisfied'
echo ""

echo "--- Transport Context Projection Kernel ---"
check_file_pair \
    "verified_transport_context.rs ↔ vellaveto-types/src/verified_transport_context.rs" \
    "$PROD_TRANSPORT_CONTEXT" \
    "$VERUS_TRANSPORT_CONTEXT"
for fn in \
    trusted_transport_preserves_agent_identity \
    trusted_transport_preserves_capability_token \
    project_agent_identity_from_transport \
    project_capability_token_from_transport
do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_TRANSPORT_CONTEXT" \
        "pub[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_TRANSPORT_CONTEXT" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "server sanitize_context uses verified agent-identity transport projection" \
    "$PROD_SERVER_CONTEXT_WRAPPER" \
    'project_agent_identity_from_transport' \
    "$VERUS_TRANSPORT_CONTEXT" \
    'pub[[:space:]]+fn[[:space:]]+project_agent_identity_from_transport'
check_symbol_parity \
    "server sanitize_context uses verified capability-token transport projection" \
    "$PROD_SERVER_CONTEXT_WRAPPER" \
    'project_capability_token_from_transport' \
    "$VERUS_TRANSPORT_CONTEXT" \
    'pub[[:space:]]+fn[[:space:]]+project_capability_token_from_transport'
check_symbol_parity \
    "relay uses verified agent-identity transport projection" \
    "$PROD_RELAY_WRAPPER" \
    'project_agent_identity_from_transport' \
    "$VERUS_TRANSPORT_CONTEXT" \
    'pub[[:space:]]+fn[[:space:]]+project_agent_identity_from_transport'
check_symbol_parity \
    "relay uses verified capability-token transport projection" \
    "$PROD_RELAY_WRAPPER" \
    'project_capability_token_from_transport' \
    "$VERUS_TRANSPORT_CONTEXT" \
    'pub[[:space:]]+fn[[:space:]]+project_capability_token_from_transport'
echo ""

echo "--- Constraint Evaluation Kernel ---"
check_file_pair \
    "verified_constraint_eval.rs ↔ vellaveto-engine/src/verified_constraint_eval.rs" \
    "$PROD_CONSTRAINT" \
    "$VERUS_CONSTRAINT"
for fn in all_constraints_skipped has_known_condition_key unrecognized_condition_payload has_forbidden_parameter conditional_verdict; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CONSTRAINT" \
        "pub[[:space:]]+(const[[:space:]]+)?fn[[:space:]]+$fn" \
        "$VERUS_CONSTRAINT" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "constraint wrapper uses verified all-skipped kernel" \
    "$PROD_CONSTRAINT_WRAPPER" \
    'verified_constraint_eval::all_constraints_skipped' \
    "$VERUS_CONSTRAINT" \
    'pub[[:space:]]+fn[[:space:]]+all_constraints_skipped'
check_symbol_parity \
    "constraint wrapper uses verified no-match kernel" \
    "$PROD_CONSTRAINT_WRAPPER" \
    'verified_constraint_eval::no_match_verdict' \
    "$VERUS_CONSTRAINT" \
    'pub[[:space:]]+fn[[:space:]]+no_match_verdict'
check_symbol_parity \
    "policy compiler uses verified unknown-only condition kernel" \
    "$PROJECT_DIR/vellaveto-engine/src/policy_compile.rs" \
    'verified_constraint_eval::unrecognized_condition_payload' \
    "$VERUS_CONSTRAINT" \
    'pub[[:space:]]+fn[[:space:]]+unrecognized_condition_payload'
echo ""

echo "--- Deputy Delegation Kernel ---"
check_file_pair \
    "verified_deputy.rs ↔ vellaveto-engine/src/verified_deputy.rs" \
    "$PROD_DEPUTY" \
    "$VERUS_DEPUTY"
for fn in next_delegation_depth delegation_depth_within_limit redelegation_chain_principal_valid redelegation_tool_allowed delegated_principal_matches delegated_tool_allowed; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_DEPUTY" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_DEPUTY" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "deputy register_delegation uses verified depth increment" \
    "$PROD_DEPUTY_WRAPPER" \
    'verified_deputy::next_delegation_depth' \
    "$VERUS_DEPUTY" \
    'pub[[:space:]]+fn[[:space:]]+next_delegation_depth'
check_symbol_parity \
    "deputy register_delegation uses verified depth-limit guard" \
    "$PROD_DEPUTY_WRAPPER" \
    'verified_deputy::delegation_depth_within_limit' \
    "$VERUS_DEPUTY" \
    'pub[[:space:]]+fn[[:space:]]+delegation_depth_within_limit'
check_symbol_parity \
    "deputy register_delegation uses verified chain-principal guard" \
    "$PROD_DEPUTY_WRAPPER" \
    'verified_deputy::redelegation_chain_principal_valid' \
    "$VERUS_DEPUTY" \
    'pub[[:space:]]+fn[[:space:]]+redelegation_chain_principal_valid'
check_symbol_parity \
    "deputy register_delegation uses verified child-tool scope guard" \
    "$PROD_DEPUTY_WRAPPER" \
    'verified_deputy::redelegation_tool_allowed' \
    "$VERUS_DEPUTY" \
    'pub[[:space:]]+fn[[:space:]]+redelegation_tool_allowed'
check_symbol_parity \
    "deputy validate_action uses verified delegate-match guard" \
    "$PROD_DEPUTY_WRAPPER" \
    'verified_deputy::delegated_principal_matches' \
    "$VERUS_DEPUTY" \
    'pub[[:space:]]+fn[[:space:]]+delegated_principal_matches'
check_symbol_parity \
    "deputy validate_action uses verified tool-allowance guard" \
    "$PROD_DEPUTY_WRAPPER" \
    'verified_deputy::delegated_tool_allowed' \
    "$VERUS_DEPUTY" \
    'pub[[:space:]]+fn[[:space:]]+delegated_tool_allowed'
echo ""

echo "--- Audit Append Kernel ---"
check_file_pair \
    "verified_audit_append.rs ↔ vellaveto-audit/src/verified_audit_append.rs" \
    "$PROD_AUDIT_APPEND" \
    "$VERUS_AUDIT_APPEND"
for fn in entry_count_after_rotation assigned_sequence next_entry_count next_global_sequence next_sequence_after_recovery; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_AUDIT_APPEND" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_AUDIT_APPEND" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "audit logger uses verified rotation reset" \
    "$PROD_AUDIT_APPEND_WRAPPER" \
    'verified_audit_append::entry_count_after_rotation' \
    "$VERUS_AUDIT_APPEND" \
    'pub[[:space:]]+fn[[:space:]]+entry_count_after_rotation'
check_symbol_parity \
    "audit logger uses verified assigned sequence snapshot" \
    "$PROD_AUDIT_APPEND_WRAPPER" \
    'verified_audit_append::assigned_sequence' \
    "$VERUS_AUDIT_APPEND" \
    'pub[[:space:]]+fn[[:space:]]+assigned_sequence'
check_symbol_parity \
    "audit logger uses verified per-file counter increment" \
    "$PROD_AUDIT_APPEND_WRAPPER" \
    'verified_audit_append::next_entry_count' \
    "$VERUS_AUDIT_APPEND" \
    'pub[[:space:]]+fn[[:space:]]+next_entry_count'
check_symbol_parity \
    "audit logger uses verified global sequence increment" \
    "$PROD_AUDIT_APPEND_WRAPPER" \
    'verified_audit_append::next_global_sequence' \
    "$VERUS_AUDIT_APPEND" \
    'pub[[:space:]]+fn[[:space:]]+next_global_sequence'
check_symbol_parity \
    "audit recovery uses verified next sequence after restart" \
    "$PROD_AUDIT_RECOVERY_WRAPPER" \
    'verified_audit_append::next_sequence_after_recovery' \
    "$VERUS_AUDIT_APPEND" \
    'pub[[:space:]]+fn[[:space:]]+next_sequence_after_recovery'
echo ""

echo "--- Audit Chain Kernel ---"
check_file_pair \
    "verified_audit_chain.rs ↔ vellaveto-audit/src/verified_audit_chain.rs" \
    "$PROD_AUDIT_CHAIN" \
    "$VERUS_AUDIT_CHAIN"
for fn in timestamp_guard sequence_monotonic hash_presence_valid audit_chain_step_valid next_seen_hashed_entry next_prev_sequence; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_AUDIT_CHAIN" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_AUDIT_CHAIN" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "audit verification uses verified timestamp guard" \
    "$PROD_AUDIT_WRAPPER" \
    'verified_audit_chain::timestamp_guard' \
    "$VERUS_AUDIT_CHAIN" \
    'pub[[:space:]]+fn[[:space:]]+timestamp_guard'
check_symbol_parity \
    "audit verification uses verified sequence gate" \
    "$PROD_AUDIT_WRAPPER" \
    'verified_audit_chain::sequence_monotonic' \
    "$VERUS_AUDIT_CHAIN" \
    'pub[[:space:]]+fn[[:space:]]+sequence_monotonic'
check_symbol_parity \
    "audit verification uses verified hash-presence gate" \
    "$PROD_AUDIT_WRAPPER" \
    'verified_audit_chain::hash_presence_valid' \
    "$VERUS_AUDIT_CHAIN" \
    'pub[[:space:]]+fn[[:space:]]+hash_presence_valid'
check_symbol_parity \
    "audit verification uses verified step gate" \
    "$PROD_AUDIT_WRAPPER" \
    'verified_audit_chain::audit_chain_step_valid' \
    "$VERUS_AUDIT_CHAIN" \
    'pub[[:space:]]+fn[[:space:]]+audit_chain_step_valid'
echo ""

echo "--- Merkle Kernel ---"
check_file_pair \
    "verified_merkle.rs ↔ vellaveto-audit/src/verified_merkle.rs" \
    "$PROD_MERKLE" \
    "$VERUS_MERKLE"
for fn in append_allowed stored_leaf_count_valid proof_tree_size_valid proof_leaf_index_valid proof_sibling_count_valid sibling_hash_len_valid; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_MERKLE" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_MERKLE" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "merkle append uses verified capacity gate" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle::append_allowed' \
    "$VERUS_MERKLE" \
    'pub[[:space:]]+fn[[:space:]]+append_allowed'
check_symbol_parity \
    "merkle initialize uses verified stored-count gate" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle::stored_leaf_count_valid' \
    "$VERUS_MERKLE" \
    'pub[[:space:]]+fn[[:space:]]+stored_leaf_count_valid'
check_symbol_parity \
    "merkle proof verification uses verified sibling-count gate" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle::proof_sibling_count_valid' \
    "$VERUS_MERKLE" \
    'pub[[:space:]]+fn[[:space:]]+proof_sibling_count_valid'
check_symbol_parity \
    "merkle proof verification uses verified tree-size gate" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle::proof_tree_size_valid' \
    "$VERUS_MERKLE" \
    'pub[[:space:]]+fn[[:space:]]+proof_tree_size_valid'
check_symbol_parity \
    "merkle proof verification uses verified leaf-index gate" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle::proof_leaf_index_valid' \
    "$VERUS_MERKLE" \
    'pub[[:space:]]+fn[[:space:]]+proof_leaf_index_valid'
check_symbol_parity \
    "merkle proof verification uses verified sibling hash-length gate" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle::sibling_hash_len_valid' \
    "$VERUS_MERKLE" \
    'pub[[:space:]]+fn[[:space:]]+sibling_hash_len_valid'
echo ""

echo "--- Merkle Fold Kernel ---"
check_file_pair \
    "verified_merkle_fold.rs ↔ vellaveto-audit/src/verified_merkle_fold.rs" \
    "$PROD_MERKLE_FOLD" \
    "$VERUS_MERKLE_FOLD"
for fn in next_level_len next_level_hashes fold_proof_step fold_peak_into_root; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_MERKLE_FOLD" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_MERKLE_FOLD" \
        "pub([[:space:]]+open[[:space:]]+spec)?[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "merkle root uses verified peak-fold helper" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_fold::fold_peak_into_root' \
    "$VERUS_MERKLE_FOLD" \
    'pub([[:space:]]+open[[:space:]]+spec)?[[:space:]]+fn[[:space:]]+fold_peak_into_root'
check_symbol_parity \
    "merkle level builder uses verified next-level helper" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_fold::next_level_hashes' \
    "$VERUS_MERKLE_FOLD" \
    'pub([[:space:]]+open[[:space:]]+spec)?[[:space:]]+fn[[:space:]]+next_level_hashes'
check_symbol_parity \
    "merkle proof verification uses verified fold-step helper" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_fold::fold_proof_step' \
    "$VERUS_MERKLE_FOLD" \
    'pub([[:space:]]+open[[:space:]]+spec)?[[:space:]]+fn[[:space:]]+fold_proof_step'
echo ""

echo "--- Merkle Proof-Path Kernel ---"
check_file_pair \
    "verified_merkle_path.rs ↔ vellaveto-audit/src/verified_merkle_path.rs" \
    "$PROD_MERKLE_PATH" \
    "$VERUS_MERKLE_PATH"
for fn in proof_sibling_index proof_step_is_left proof_level_has_sibling proof_parent_index proof_step_places_sibling_left; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_MERKLE_PATH" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_MERKLE_PATH" \
        "pub([[:space:]]+open[[:space:]]+spec)?[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "merkle proof generation uses verified sibling-presence gate" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_path::proof_level_has_sibling' \
    "$VERUS_MERKLE_PATH" \
    'pub[[:space:]]+fn[[:space:]]+proof_level_has_sibling'
check_symbol_parity \
    "merkle proof generation uses verified sibling-index helper" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_path::proof_sibling_index' \
    "$VERUS_MERKLE_PATH" \
    'pub[[:space:]]+fn[[:space:]]+proof_sibling_index'
check_symbol_parity \
    "merkle proof generation uses verified direction helper" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_path::proof_step_is_left' \
    "$VERUS_MERKLE_PATH" \
    'pub[[:space:]]+fn[[:space:]]+proof_step_is_left'
check_symbol_parity \
    "merkle proof generation uses verified parent-index helper" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_path::proof_parent_index' \
    "$VERUS_MERKLE_PATH" \
    'pub[[:space:]]+fn[[:space:]]+proof_parent_index'
check_symbol_parity \
    "merkle proof verification uses verified concatenation-direction helper" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_path::proof_step_places_sibling_left' \
    "$VERUS_MERKLE_PATH" \
    'pub[[:space:]]+fn[[:space:]]+proof_step_places_sibling_left'
echo ""

echo "--- Rotation Manifest Kernel ---"
check_file_pair \
    "verified_rotation_manifest.rs ↔ vellaveto-audit/src/verified_rotation_manifest.rs" \
    "$PROD_ROTATION_MANIFEST" \
    "$VERUS_ROTATION_MANIFEST"
for fn in rotation_start_hash_link_valid rotated_file_reference_valid missing_rotated_file_allowed; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_ROTATION_MANIFEST" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_ROTATION_MANIFEST" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "rotation verifier uses verified start-hash linkage guard" \
    "$PROD_AUDIT_RECOVERY_WRAPPER" \
    'verified_rotation_manifest::rotation_start_hash_link_valid' \
    "$VERUS_ROTATION_MANIFEST" \
    'pub[[:space:]]+fn[[:space:]]+rotation_start_hash_link_valid'
check_symbol_parity \
    "rotation verifier uses verified rotated-file path guard" \
    "$PROD_AUDIT_RECOVERY_WRAPPER" \
    'verified_rotation_manifest::rotated_file_reference_valid' \
    "$VERUS_ROTATION_MANIFEST" \
    'pub[[:space:]]+fn[[:space:]]+rotated_file_reference_valid'
check_symbol_parity \
    "rotation verifier uses verified prune-boundary guard" \
    "$PROD_AUDIT_RECOVERY_WRAPPER" \
    'verified_rotation_manifest::missing_rotated_file_allowed' \
    "$VERUS_ROTATION_MANIFEST" \
    'pub[[:space:]]+fn[[:space:]]+missing_rotated_file_allowed'
echo ""

echo "--- Capability Attenuation Kernel ---"
check_file_pair \
    "verified_capability_attenuation.rs ↔ vellaveto-mcp/src/verified_capability_attenuation.rs" \
    "$PROD_CAPABILITY_ATTENUATION" \
    "$VERUS_CAPABILITY_ATTENUATION"
for fn in attenuated_remaining_depth attenuated_expiry_epoch; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_ATTENUATION" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_ATTENUATION" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "capability attenuation uses verified depth gate" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_attenuation::attenuated_remaining_depth' \
    "$VERUS_CAPABILITY_ATTENUATION" \
    'pub[[:space:]]+fn[[:space:]]+attenuated_remaining_depth'
check_symbol_parity \
    "capability attenuation uses verified expiry gate" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_attenuation::attenuated_expiry_epoch' \
    "$VERUS_CAPABILITY_ATTENUATION" \
    'pub[[:space:]]+fn[[:space:]]+attenuated_expiry_epoch'
echo ""

echo "--- Capability Coverage Kernel ---"
check_file_pair \
    "verified_capability_coverage.rs ↔ vellaveto-mcp/src/verified_capability_coverage.rs" \
    "$PROD_CAPABILITY_COVERAGE" \
    "$VERUS_CAPABILITY_COVERAGE"
check_symbol_parity \
    "grant_restrictions_cover_action exists in production and Verus" \
    "$PROD_CAPABILITY_COVERAGE" \
    'pub\(crate\)[[:space:]]+const[[:space:]]+fn[[:space:]]+grant_restrictions_cover_action' \
    "$VERUS_CAPABILITY_COVERAGE" \
    'pub[[:space:]]+fn[[:space:]]+grant_restrictions_cover_action'
check_symbol_parity \
    "capability grant coverage uses verified restriction gate" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_coverage::grant_restrictions_cover_action' \
    "$VERUS_CAPABILITY_COVERAGE" \
    'pub[[:space:]]+fn[[:space:]]+grant_restrictions_cover_action'
echo ""

echo "--- Capability Domain Kernel ---"
check_file_pair \
    "verified_capability_domain.rs ↔ vellaveto-mcp/src/verified_capability_domain.rs" \
    "$PROD_CAPABILITY_DOMAIN" \
    "$VERUS_CAPABILITY_DOMAIN"
for fn in domain_pattern_shape_valid normalized_domain_suffix_matches normalized_domain_pattern_matches normalized_domain_pattern_subset; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_DOMAIN" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_DOMAIN" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "capability domain coverage uses verified matcher" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_domain::domain_matches_pattern' \
    "$PROD_CAPABILITY_DOMAIN" \
    'pub\(crate\)[[:space:]]+fn[[:space:]]+domain_matches_pattern'
check_symbol_parity \
    "capability domain subset uses verified containment kernel" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_domain::domain_pattern_is_subset' \
    "$PROD_CAPABILITY_DOMAIN" \
    'pub\(crate\)[[:space:]]+fn[[:space:]]+domain_pattern_is_subset'
echo ""

echo "--- Capability Parent-Glob Kernel ---"
check_file_pair \
    "verified_capability_glob.rs ↔ vellaveto-mcp/src/verified_capability_glob.rs" \
    "$PROD_CAPABILITY_GLOB" \
    "$VERUS_CAPABILITY_GLOB"
for fn in ascii_fold_byte byte_eq_ignore_ascii_case literal_child_matches_parent_glob; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_GLOB" \
        "pub\\(crate\\)[[:space:]]+(const[[:space:]]+)?fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_GLOB" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "capability subset uses verified literal child glob matcher" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_glob::literal_child_matches_parent_glob' \
    "$VERUS_CAPABILITY_GLOB" \
    'pub[[:space:]]+fn[[:space:]]+literal_child_matches_parent_glob'
check_symbol_parity \
    "capability runtime matcher uses verified literal child glob matcher" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_glob::literal_child_matches_parent_glob\(pattern, value\)' \
    "$VERUS_CAPABILITY_GLOB" \
    'pub[[:space:]]+fn[[:space:]]+literal_child_matches_parent_glob'
echo ""

echo "--- Capability Glob-Subset Kernel ---"
check_file_pair \
    "verified_capability_glob_subset.rs ↔ vellaveto-mcp/src/verified_capability_glob_subset.rs" \
    "$PROD_CAPABILITY_GLOB_SUBSET" \
    "$VERUS_CAPABILITY_GLOB_SUBSET"
for fn in glob_subset_accepting_counterexample glob_subset_fast_path representative_other_byte_needed; do
    check_symbol_parity \
        "$fn exists in the Verus subset-kernel model" \
        "$VERUS_CAPABILITY_GLOB_SUBSET" \
        "pub[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_GLOB_SUBSET" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "capability subset uses verified child-glob subset kernel" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_glob_subset::glob_pattern_subset' \
    "$VERUS_CAPABILITY_GLOB_SUBSET" \
    'pub[[:space:]]+fn[[:space:]]+glob_subset_fast_path'
echo ""

echo "--- Capability Grant Kernel ---"
check_file_pair \
    "verified_capability_grant.rs ↔ vellaveto-mcp/src/verified_capability_grant.rs" \
    "$PROD_CAPABILITY_GRANT" \
    "$VERUS_CAPABILITY_GRANT"
check_symbol_parity \
    "grant_restrictions_attenuated exists in production and Verus" \
    "$PROD_CAPABILITY_GRANT" \
    'pub\(crate\)[[:space:]]+const[[:space:]]+fn[[:space:]]+grant_restrictions_attenuated' \
    "$VERUS_CAPABILITY_GRANT" \
    'pub[[:space:]]+fn[[:space:]]+grant_restrictions_attenuated'
check_symbol_parity \
    "capability grant subset uses verified restriction gate" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_grant::grant_restrictions_attenuated' \
    "$VERUS_CAPABILITY_GRANT" \
    'pub[[:space:]]+fn[[:space:]]+grant_restrictions_attenuated'
echo ""

echo "--- Capability Identity Kernel ---"
check_file_pair \
    "verified_capability_identity.rs ↔ vellaveto-mcp/src/verified_capability_identity.rs" \
    "$PROD_CAPABILITY_IDENTITY" \
    "$VERUS_CAPABILITY_IDENTITY"
for fn in delegation_holder_distinct delegated_child_issuer_valid holder_expectation_satisfied; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_IDENTITY" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_IDENTITY" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "capability attenuation uses verified holder-distinct guard" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_identity::delegation_holder_distinct' \
    "$VERUS_CAPABILITY_IDENTITY" \
    'pub[[:space:]]+fn[[:space:]]+delegation_holder_distinct'
check_symbol_parity \
    "capability attenuation uses verified issuer-link guard" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_identity::delegated_child_issuer_valid' \
    "$VERUS_CAPABILITY_IDENTITY" \
    'pub[[:space:]]+fn[[:space:]]+delegated_child_issuer_valid'
check_symbol_parity \
    "capability verification uses verified holder-expectation guard" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_identity::holder_expectation_satisfied' \
    "$VERUS_CAPABILITY_IDENTITY" \
    'pub[[:space:]]+fn[[:space:]]+holder_expectation_satisfied'
echo ""

echo "--- Capability Literal Kernel ---"
check_file_pair \
    "verified_capability_literal.rs ↔ vellaveto-mcp/src/verified_capability_literal.rs" \
    "$PROD_CAPABILITY_LITERAL" \
    "$VERUS_CAPABILITY_LITERAL"
for fn in literal_pattern_matches literal_child_pattern_subset; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_LITERAL" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_LITERAL" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "capability literal matcher uses verified literal fast path" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_literal::literal_pattern_matches' \
    "$VERUS_CAPABILITY_LITERAL" \
    'pub[[:space:]]+fn[[:space:]]+literal_pattern_matches'
check_symbol_parity \
    "capability subset uses verified literal child branch" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_literal::literal_child_pattern_subset' \
    "$VERUS_CAPABILITY_LITERAL" \
    'pub[[:space:]]+fn[[:space:]]+literal_child_pattern_subset'
echo ""

echo "--- Capability Pattern Kernel ---"
check_file_pair \
    "verified_capability_pattern.rs ↔ vellaveto-mcp/src/verified_capability_pattern.rs" \
    "$PROD_CAPABILITY_PATTERN" \
    "$VERUS_CAPABILITY_PATTERN"
for fn in has_glob_metacharacters pattern_subset_guard; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_PATTERN" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_PATTERN" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "capability pattern subset uses verified guard" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_pattern::pattern_subset_guard' \
    "$VERUS_CAPABILITY_PATTERN" \
    'pub[[:space:]]+fn[[:space:]]+pattern_subset_guard'
check_symbol_parity \
    "capability pattern subset uses verified metacharacter detector" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_pattern::has_glob_metacharacters' \
    "$VERUS_CAPABILITY_PATTERN" \
    'pub[[:space:]]+fn[[:space:]]+has_glob_metacharacters'
echo ""

echo "--- Capability Path Kernel ---"
check_file_pair \
    "verified_capability_path.rs ↔ vellaveto-mcp/src/verified_capability_path.rs" \
    "$PROD_CAPABILITY_PATH" \
    "$VERUS_CAPABILITY_PATH"
check_symbol_parity \
    "path_component_next_depth exists in production and Verus" \
    "$PROD_CAPABILITY_PATH" \
    'pub\(crate\)[[:space:]]+const[[:space:]]+fn[[:space:]]+path_component_next_depth' \
    "$VERUS_CAPABILITY_PATH" \
    'pub[[:space:]]+fn[[:space:]]+path_component_next_depth'
check_symbol_parity \
    "capability coverage uses verified path normalizer" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_path::normalize_path_for_grant' \
    "$PROD_CAPABILITY_PATH" \
    'pub\(crate\)[[:space:]]+fn[[:space:]]+normalize_path_for_grant'
echo ""

echo "--- Capability Selection Kernel ---"
check_file_pair \
    "verified_capability_selection.rs ↔ vellaveto-mcp/src/verified_capability_selection.rs" \
    "$PROD_CAPABILITY_SELECTION" \
    "$VERUS_CAPABILITY_SELECTION"
check_symbol_parity \
    "next_covering_grant_index exists in production and Verus" \
    "$PROD_CAPABILITY_SELECTION" \
    'pub\(crate\)[[:space:]]+const[[:space:]]+fn[[:space:]]+next_covering_grant_index' \
    "$VERUS_CAPABILITY_SELECTION" \
    'pub[[:space:]]+fn[[:space:]]+next_covering_grant_index'
check_symbol_parity \
    "capability grant selection uses verified first-match kernel" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_selection::next_covering_grant_index' \
    "$VERUS_CAPABILITY_SELECTION" \
    'pub[[:space:]]+fn[[:space:]]+next_covering_grant_index'
echo ""

echo "--- Capability Verification Kernel ---"
check_file_pair \
    "verified_capability_verification.rs ↔ vellaveto-mcp/src/verified_capability_verification.rs" \
    "$PROD_CAPABILITY_VERIFICATION" \
    "$VERUS_CAPABILITY_VERIFICATION"
for fn in \
    capability_not_expired \
    capability_issued_at_within_skew \
    capability_expected_public_key_matches \
    capability_public_key_length_valid \
    capability_signature_length_valid
do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_VERIFICATION" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_VERIFICATION" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "capability verification uses verified expiry gate" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_verification::capability_not_expired' \
    "$VERUS_CAPABILITY_VERIFICATION" \
    'pub[[:space:]]+fn[[:space:]]+capability_not_expired'
check_symbol_parity \
    "capability verification uses verified issued-at skew gate" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_verification::capability_issued_at_within_skew' \
    "$VERUS_CAPABILITY_VERIFICATION" \
    'pub[[:space:]]+fn[[:space:]]+capability_issued_at_within_skew'
check_symbol_parity \
    "capability verification uses verified expected-key gate" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_verification::capability_expected_public_key_matches' \
    "$VERUS_CAPABILITY_VERIFICATION" \
    'pub[[:space:]]+fn[[:space:]]+capability_expected_public_key_matches'
check_symbol_parity \
    "capability verification uses verified public-key length gate" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_verification::capability_public_key_length_valid' \
    "$VERUS_CAPABILITY_VERIFICATION" \
    'pub[[:space:]]+fn[[:space:]]+capability_public_key_length_valid'
check_symbol_parity \
    "capability verification uses verified signature length gate" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_verification::capability_signature_length_valid' \
    "$VERUS_CAPABILITY_VERIFICATION" \
    'pub[[:space:]]+fn[[:space:]]+capability_signature_length_valid'
echo ""

echo "--- Entropy Alert Gate ---"
check_file_pair \
    "verified_entropy_gate.rs ↔ vellaveto-engine/src/verified_entropy_gate.rs" \
    "$PROD_ENTROPY" \
    "$VERUS_ENTROPY"
for fn in is_high_entropy_millibits should_alert_on_high_entropy_count high_severity_entropy_threshold entropy_alert_level entropy_alert_severity; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_ENTROPY" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_ENTROPY" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "entropy wrapper uses verified fixed-point comparator" \
    "$PROD_ENTROPY_WRAPPER" \
    'pub\(crate\)[[:space:]]+use[[:space:]]+crate::verified_entropy_gate::' \
    "$VERUS_ENTROPY" \
    'pub[[:space:]]+fn[[:space:]]+is_high_entropy_millibits'
echo ""

echo "--- NHI Delegation Kernel ---"
check_file_pair \
    "verified_nhi_delegation.rs ↔ vellaveto-mcp/src/verified_nhi_delegation.rs" \
    "$PROD_NHI" \
    "$VERUS_NHI"
for fn in identity_is_terminal delegation_participant_allowed delegation_link_effective_for_chain delegation_chain_depth_exceeded; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_NHI" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_NHI" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "NHI is_terminal uses verified terminal-state guard" \
    "$PROD_NHI_WRAPPER" \
    'verified_nhi_delegation::identity_is_terminal' \
    "$VERUS_NHI" \
    'pub[[:space:]]+fn[[:space:]]+identity_is_terminal'
check_symbol_parity \
    "NHI create_delegation uses verified participant guard" \
    "$PROD_NHI_WRAPPER" \
    'verified_nhi_delegation::delegation_participant_allowed' \
    "$VERUS_NHI" \
    'pub[[:space:]]+fn[[:space:]]+delegation_participant_allowed'
check_symbol_parity \
    "NHI resolve_delegation_chain uses verified link-effective guard" \
    "$PROD_NHI_WRAPPER" \
    'verified_nhi_delegation::delegation_link_effective_for_chain' \
    "$VERUS_NHI" \
    'pub[[:space:]]+fn[[:space:]]+delegation_link_effective_for_chain'
check_symbol_parity \
    "NHI resolve_delegation_chain uses verified depth-exceeded guard" \
    "$PROD_NHI_WRAPPER" \
    'verified_nhi_delegation::delegation_chain_depth_exceeded' \
    "$VERUS_NHI" \
    'pub[[:space:]]+fn[[:space:]]+delegation_chain_depth_exceeded'
echo ""

echo "--- NHI Delegation Graph Kernel ---"
check_file_pair \
    "verified_nhi_graph.rs ↔ vellaveto-mcp/src/verified_nhi_graph.rs" \
    "$PROD_NHI_GRAPH" \
    "$VERUS_NHI_GRAPH"
for fn in delegation_link_effective_for_successor delegation_edge_preserves_acyclicity; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_NHI_GRAPH" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_NHI_GRAPH" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "NHI create_delegation uses verified successor-link guard" \
    "$PROD_NHI_WRAPPER" \
    'verified_nhi_graph::delegation_link_effective_for_successor' \
    "$VERUS_NHI_GRAPH" \
    'pub[[:space:]]+fn[[:space:]]+delegation_link_effective_for_successor'
check_symbol_parity \
    "NHI create_delegation uses verified cycle-preservation guard" \
    "$PROD_NHI_WRAPPER" \
    'verified_nhi_graph::delegation_edge_preserves_acyclicity' \
    "$VERUS_NHI_GRAPH" \
    'pub[[:space:]]+fn[[:space:]]+delegation_edge_preserves_acyclicity'
echo ""

echo "--- Cross-Call DLP Tracker Gate ---"
check_file_pair \
    "verified_cross_call_dlp.rs ↔ vellaveto-mcp/src/inspection/verified_cross_call_dlp.rs" \
    "$PROD_CROSS_DLP" \
    "$VERUS_CROSS_DLP"
for fn in should_emit_capacity_exhausted_finding should_update_buffer; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CROSS_DLP" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CROSS_DLP" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "cross-call tracker uses verified capacity finding gate" \
    "$PROD_CROSS_DLP_WRAPPER" \
    'verified_cross_call_dlp::should_emit_capacity_exhausted_finding' \
    "$VERUS_CROSS_DLP" \
    'pub[[:space:]]+fn[[:space:]]+should_emit_capacity_exhausted_finding'
check_symbol_parity \
    "cross-call tracker uses verified update gate" \
    "$PROD_CROSS_DLP_WRAPPER" \
    'verified_cross_call_dlp::should_update_buffer' \
    "$VERUS_CROSS_DLP" \
    'pub[[:space:]]+fn[[:space:]]+should_update_buffer'
echo ""

echo "--- DLP Buffer Core ---"
check_file_pair "verified_dlp_core.rs ↔ vellaveto-mcp/src/inspection/verified_dlp_core.rs" "$PROD_DLP" "$VERUS_DLP"
for fn in is_utf8_char_boundary extract_tail can_track_field update_total_bytes; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_DLP" \
        "pub[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_DLP" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
echo ""

echo "--- Path Normalization Kernel ---"
check_file_pair "verified_path.rs ↔ vellaveto-engine/src/path.rs" "$PROD_PATH" "$VERUS_PATH"
check_symbol_parity \
    "production engine path normalization kernel exists" \
    "$PROD_PATH" \
    'pub(\(crate\))?[[:space:]]+fn[[:space:]]+normalize_decoded_path' \
    "$VERUS_PATH" \
    'pub[[:space:]]+fn[[:space:]]+normalize_path_bytes'
check_symbol_parity \
    "engine path wrapper calls the verified kernel boundary" \
    "$PROD_PATH" \
    'normalize_decoded_path\(current\.as_ref\(\)\)' \
    "$VERUS_PATH" \
    'pub[[:space:]]+fn[[:space:]]+normalize_path_bytes'
echo ""

echo "--- Refinement Completeness Kernel ---"
check_file_pair \
    "verified_refinement_completeness.rs ↔ vellaveto-engine/tests/refinement_trace.rs" \
    "$PROD_REFINEMENT_WITNESS" \
    "$VERUS_REFINEMENT_COMPLETENESS"
check_symbol_parity \
    "traced evaluator exists and Verus models non-empty start" \
    "$PROD_TRACED" \
    'pub[[:space:]]+fn[[:space:]]+evaluate_action_traced' \
    "$VERUS_REFINEMENT_COMPLETENESS" \
    'pub[[:space:]]+fn[[:space:]]+evaluate_start_nonempty'
check_symbol_parity \
    "refinement witness covers MatchMiss and Verus models miss advancement" \
    "$PROD_REFINEMENT_WITNESS" \
    'MatchMiss' \
    "$VERUS_REFINEMENT_COMPLETENESS" \
    'pub[[:space:]]+fn[[:space:]]+evaluate_match_miss'
check_symbol_parity \
    "refinement witness covers MatchHit and Verus models hit transition" \
    "$PROD_REFINEMENT_WITNESS" \
    'MatchHit' \
    "$VERUS_REFINEMENT_COMPLETENESS" \
    'pub[[:space:]]+fn[[:space:]]+evaluate_match_hit'
check_symbol_parity \
    "refinement witness covers ApplyAllow and Verus models allow completion" \
    "$PROD_REFINEMENT_WITNESS" \
    'ApplyAllow' \
    "$VERUS_REFINEMENT_COMPLETENESS" \
    'spec_apply_allow_verdict'
check_symbol_parity \
    "refinement witness covers ApplyRequireApproval and Verus models approval completion" \
    "$PROD_REFINEMENT_WITNESS" \
    'ApplyRequireApproval' \
    "$VERUS_REFINEMENT_COMPLETENESS" \
    'spec_apply_require_approval_verdict'
check_symbol_parity \
    "refinement witness covers ApplyContinue and Verus models continue transition" \
    "$PROD_REFINEMENT_WITNESS" \
    'ApplyContinue' \
    "$VERUS_REFINEMENT_COMPLETENESS" \
    'spec_continue_to_next'
echo ""

echo "--- Refinement Sort + Stutter Kernel (P5b) ---"
VERUS_REFINEMENT_SORT_STUTTER="$PROJECT_DIR/formal/verus/verified_refinement_sort_stutter.rs"
check_file_pair \
    "verified_refinement_sort_stutter.rs exists (R-MCP-INIT-SORT + R-MCP-INDEX-STUTTER)" \
    "$PROD_REFINEMENT_WITNESS" \
    "$VERUS_REFINEMENT_SORT_STUTTER"
check_symbol_parity \
    "sort_policies exists and Verus models priority ordering predicate (R-MCP-INIT-SORT)" \
    "$PROJECT_DIR/vellaveto-engine/src/lib.rs" \
    'sort_policies' \
    "$VERUS_REFINEMENT_SORT_STUTTER" \
    'spec_sorted_by_priority'
check_symbol_parity \
    "tool_index optimization exists and Verus proves stutter soundness (R-MCP-INDEX-STUTTER)" \
    "$PROJECT_DIR/vellaveto-engine/src/lib.rs" \
    'build_tool_index' \
    "$VERUS_REFINEMENT_SORT_STUTTER" \
    'lemma_stutter_is_miss'
check_symbol_parity \
    "P5b closing theorem is present (lemma_p5b_full_simulation_is_complete)" \
    "$PROJECT_DIR/vellaveto-engine/src/lib.rs" \
    'sort_policies' \
    "$VERUS_REFINEMENT_SORT_STUTTER" \
    'lemma_p5b_full_simulation_is_complete'
echo ""

echo "--- ACIS Action Summary Kernel ---"
check_file_pair \
    "verified_acis_action_summary.rs ↔ vellaveto-types/src/acis.rs" \
    "$PROD_ACIS_TYPES" \
    "$VERUS_ACIS_ACTION_SUMMARY"
check_file_pair \
    "verified_acis_action_summary.rs ↔ vellaveto-engine/src/acis.rs" \
    "$PROD_ACIS_ENGINE" \
    "$VERUS_ACIS_ACTION_SUMMARY"
check_symbol_parity \
    "AcisActionSummary exists in production and Verus model" \
    "$PROD_ACIS_TYPES" \
    'pub[[:space:]]+struct[[:space:]]+AcisActionSummary' \
    "$VERUS_ACIS_ACTION_SUMMARY" \
    'pub[[:space:]]+struct[[:space:]]+SpecActionSummary'
check_symbol_parity \
    "production ACIS fingerprint helper exists and Verus models fingerprinting" \
    "$PROD_ACIS_ENGINE" \
    'pub[[:space:]]+fn[[:space:]]+compute_action_fingerprint' \
    "$VERUS_ACIS_ACTION_SUMMARY" \
    'pub[[:space:]]+uninterp[[:space:]]+spec[[:space:]]+fn[[:space:]]+spec_action_fingerprint'
check_symbol_parity \
    "ACIS target-count bound exists in production and Verus model" \
    "$PROD_ACIS_TYPES" \
    'const[[:space:]]+MAX_TARGET_COUNT:[[:space:]]+u32[[:space:]]*=' \
    "$VERUS_ACIS_ACTION_SUMMARY" \
    'pub[[:space:]]+const[[:space:]]+MAX_TARGET_COUNT:[[:space:]]+u32[[:space:]]*='
check_symbol_parity \
    "DecisionKind default deny exists in production and Verus model" \
    "$PROD_ACIS_TYPES" \
    'impl[[:space:]]+Default[[:space:]]+for[[:space:]]+DecisionKind' \
    "$VERUS_ACIS_ACTION_SUMMARY" \
    'lemma_decision_kind_default_is_deny|SpecDecisionKind::Deny'
echo ""

echo "--- Source Taint Kernel ---"
check_file_pair \
    "verified_source_taint.rs ↔ vellaveto-types/src/provenance.rs" \
    "$PROD_PROVENANCE" \
    "$VERUS_SOURCE_TAINT"
check_symbol_parity \
    "minimum_trust_tier_for_sink exists in production and Verus taint model" \
    "$PROD_PROVENANCE" \
    'pub[[:space:]]+const[[:space:]]+fn[[:space:]]+minimum_trust_tier_for_sink' \
    "$VERUS_SOURCE_TAINT" \
    'pub[[:space:]]+fn[[:space:]]+min_trust_for_sink'
check_symbol_parity \
    "TrustTier rank exists in production and Verus taint constants" \
    "$PROD_PROVENANCE" \
    'pub[[:space:]]+const[[:space:]]+fn[[:space:]]+rank\(self\)[[:space:]]*->[[:space:]]+u8' \
    "$VERUS_SOURCE_TAINT" \
    'pub[[:space:]]+const[[:space:]]+VERIFIED:[[:space:]]+u8[[:space:]]*=[[:space:]]*6;'
check_symbol_parity \
    "provenance flow gate exists in production and Verus taint model" \
    "$PROD_PROVENANCE" \
    'pub[[:space:]]+const[[:space:]]+fn[[:space:]]+can_flow_to' \
    "$VERUS_SOURCE_TAINT" \
    'spec_sink_accessible'
echo ""

echo "--- Intent Scope Kernel ---"
check_file_pair \
    "verified_intent_scope.rs ↔ vellaveto-config/src/channel_separation.rs" \
    "$PROD_CHANNEL_SEPARATION" \
    "$VERUS_INTENT_SCOPE"
check_symbol_parity \
    "IntentScopeConfig exists in production and Verus scope model" \
    "$PROD_CHANNEL_SEPARATION" \
    'pub[[:space:]]+struct[[:space:]]+IntentScopeConfig' \
    "$VERUS_INTENT_SCOPE" \
    'pub[[:space:]]+struct[[:space:]]+ScopeState'
check_symbol_parity \
    "scope is a bitmask in production and Verus" \
    "$PROD_SCOPE_MASK" \
    'pub[[:space:]]+struct[[:space:]]+ScopeMask\(u16\)' \
    "$VERUS_INTENT_SCOPE" \
    'pub[[:space:]]+allowed_mask:[[:space:]]+u16'
check_symbol_parity \
    "scope width covers every sink class in production and Verus" \
    "$PROD_SCOPE_MASK" \
    'pub[[:space:]]+const[[:space:]]+SCOPE_CLASS_COUNT:[[:space:]]+u8[[:space:]]*=[[:space:]]*9;' \
    "$VERUS_INTENT_SCOPE" \
    'pub[[:space:]]+const[[:space:]]+SCOPE_CLASS_COUNT:[[:space:]]+u8[[:space:]]*=[[:space:]]*9;'
check_symbol_parity \
    "restriction is intersection in production and Verus" \
    "$PROD_SCOPE_MASK" \
    'Self\(self\.0[[:space:]]*&[[:space:]]*restriction\.0\)' \
    "$VERUS_INTENT_SCOPE" \
    'pub[[:space:]]+open[[:space:]]+spec[[:space:]]+fn[[:space:]]+spec_restrict_scope'
check_symbol_parity \
    "trust-floor narrowing runs through the mask, not a filter over the config list" \
    "$PROD_CHANNEL_SEPARATION" \
    '\.restrict\(Self::trust_floor_mask\(trust_floor\)\)' \
    "$VERUS_INTENT_SCOPE" \
    'pub[[:space:]]+fn[[:space:]]+restrict_scope'
check_symbol_parity \
    "the scope check is actually called on the relay tool-call path" \
    "$PROD_SEQUENCE_RELAY" \
    '^[^/]*scope\.check_in_scope\(&tool_name,[[:space:]]*sink\)' \
    "$VERUS_INTENT_SCOPE" \
    'pub[[:space:]]+open[[:space:]]+spec[[:space:]]+fn[[:space:]]+spec_in_scope'
check_symbol_parity \
    "intent scope trust-floor restriction exists in production and Verus model" \
    "$PROD_CHANNEL_SEPARATION" \
    'pub[[:space:]]+fn[[:space:]]+restrict_to_trust_floor' \
    "$VERUS_INTENT_SCOPE" \
    'pub[[:space:]]+open[[:space:]]+spec[[:space:]]+fn[[:space:]]+spec_restrict_scope'
check_symbol_parity \
    "intent scope tool-budget narrowing exists in production and Verus model" \
    "$PROD_CHANNEL_SEPARATION" \
    'max_distinct_tools:[[:space:]]+self\.max_distinct_tools\.map\(\|n\|[[:space:]]*n\.min\(3\)\)' \
    "$VERUS_INTENT_SCOPE" \
    'pub[[:space:]]+fn[[:space:]]+check_tool_budget'
check_symbol_parity \
    "intent scope expansion lock exists in production and Verus model" \
    "$PROD_CHANNEL_SEPARATION" \
    'allow_scope_expansion:[[:space:]]+false' \
    "$VERUS_INTENT_SCOPE" \
    'pub[[:space:]]+fn[[:space:]]+attempt_scope_expansion'
echo ""

echo "--- Sequence Analysis Kernel ---"
check_file_pair \
    "verified_sequence_analysis.rs ↔ vellaveto-engine/src/sequence.rs" \
    "$PROD_SEQUENCE" \
    "$VERUS_SEQUENCE_ANALYSIS"
check_symbol_parity \
    "sequence warmup configuration exists in production and Verus model" \
    "$PROD_SEQUENCE" \
    'warmup_calls:[[:space:]]+crate::verified_sequence_gate::WARMUP_CALLS' \
    "$VERUS_SEQUENCE_ANALYSIS" \
    'pub[[:space:]]+const[[:space:]]+WARMUP_CALLS:[[:space:]]+u32[[:space:]]*=[[:space:]]*3;'
check_symbol_parity \
    "sequence new-tool budget exists in production and Verus model" \
    "$PROD_SEQUENCE" \
    'max_new_tools_after_taint:[[:space:]]+crate::verified_sequence_gate::MAX_NEW_TOOLS' \
    "$VERUS_SEQUENCE_ANALYSIS" \
    'pub[[:space:]]+const[[:space:]]+MAX_NEW_TOOLS:[[:space:]]+u32[[:space:]]*=[[:space:]]*2;'
check_symbol_parity \
    "sequence tracker record path exists in production and Verus models a state step" \
    "$PROD_SEQUENCE" \
    'pub[[:space:]]+fn[[:space:]]+record_and_analyze' \
    "$VERUS_SEQUENCE_ANALYSIS" \
    'pub[[:space:]]+fn[[:space:]]+sequence_step'
check_symbol_parity \
    "production sequence warmup gate exists and Verus models warmup completion" \
    "$PROD_SEQUENCE" \
    'if[[:space:]]*\([[:space:]]*self\.call_log\.len\(\)[[:space:]]+as[[:space:]]+u32[[:space:]]*\)[[:space:]]*<[[:space:]]*self\.config\.warmup_calls' \
    "$VERUS_SEQUENCE_ANALYSIS" \
    'pub[[:space:]]+open[[:space:]]+spec[[:space:]]+fn[[:space:]]+spec_warmup_complete'
check_symbol_parity \
    "restriction threshold is a named constant in production and Verus" \
    "$PROD_SEQUENCE_GATE" \
    'pub[[:space:]]+const[[:space:]]+RESTRICTION_THRESHOLD:[[:space:]]+u32[[:space:]]*=[[:space:]]*70;' \
    "$VERUS_SEQUENCE_ANALYSIS" \
    'pub[[:space:]]+const[[:space:]]+RESTRICTION_THRESHOLD:[[:space:]]+u32[[:space:]]*=[[:space:]]*70;'
check_symbol_parity \
    "production restriction gate exists and Verus models the restriction decision" \
    "$PROD_SEQUENCE_GATE" \
    'pub[[:space:]]+const[[:space:]]+fn[[:space:]]+should_restrict' \
    "$VERUS_SEQUENCE_ANALYSIS" \
    'pub[[:space:]]+open[[:space:]]+spec[[:space:]]+fn[[:space:]]+spec_should_restrict'
check_symbol_parity \
    "relay high-confidence sequence gate calls the verified gate, not a bare literal" \
    "$PROD_SEQUENCE_RELAY" \
    '^[^/]*vellaveto_engine::verified_sequence_gate::should_restrict\(' \
    "$VERUS_SEQUENCE_ANALYSIS" \
    'pub[[:space:]]+open[[:space:]]+spec[[:space:]]+fn[[:space:]]+spec_should_restrict'
check_symbol_parity \
    "relay persists the narrowed scope instead of discarding it" \
    "$PROD_SEQUENCE_RELAY" \
    '^[^/]*fn[[:space:]]+narrow_session_scope\(' \
    "$VERUS_INTENT_SCOPE" \
    'pub[[:space:]]+open[[:space:]]+spec[[:space:]]+fn[[:space:]]+spec_restrict_scope'
echo ""

echo "--- Replay Non-Admission + Unknown-Provenance Kernel ---"
VERUS_REPLAY_PROV="$PROJECT_DIR/formal/verus/verified_replay_provenance.rs"
PROD_REPLAY_HELPERS="$PROJECT_DIR/vellaveto-http-proxy/src/proxy/helpers.rs"
check_file_pair \
    "verified_replay_provenance.rs exists (REPLAY-MERGE-1–5, REPLAY-ADMIT-1–5)" \
    "$PROD_REPLAY_HELPERS" \
    "$VERUS_REPLAY_PROV"
check_symbol_parity \
    "merge_replay_status production exists, Verus proves stickiness (REPLAY-MERGE-2)" \
    "$PROD_REPLAY_HELPERS" \
    'fn merge_replay_status' \
    "$VERUS_REPLAY_PROV" \
    'lemma_replay_detected_absorbs'
check_symbol_parity \
    "replay -> Quarantined clamp in production, Verus proves end-to-end denial (REPLAY-ADMIT-4)" \
    "$PROD_REPLAY_HELPERS" \
    'replay_status == ReplayStatus::ReplayDetected' \
    "$VERUS_REPLAY_PROV" \
    'lemma_replay_admit_end_to_end_denied'
check_symbol_parity \
    "NotChecked != Fresh in Verus (REPLAY-ADMIT-2 fail-closed unknown-provenance)" \
    "$PROJECT_DIR/vellaveto-types/src/provenance.rs" \
    'NotChecked' \
    "$VERUS_REPLAY_PROV" \
    'lemma_unknown_provenance_fail_closed_end_to_end'
echo ""

echo "--- Trust Lattice Kernel (WP 3A) ---"
VERUS_TRUST_LATTICE="$PROJECT_DIR/formal/verus/verified_trust_lattice.rs"
check_file_pair \
    "verified_trust_lattice.rs exists (TRUST-LAT-1–6, FLOW-ADM-1–5, FLOW-PROD-1–4)" \
    "$PROD_PROVENANCE" \
    "$VERUS_TRUST_LATTICE"
check_symbol_parity \
    "TrustTier::join exists and Verus models join commutativity (TRUST-LAT-1)" \
    "$PROD_PROVENANCE" \
    'pub const fn join' \
    "$VERUS_TRUST_LATTICE" \
    'lemma_trust_join_commutative'
check_symbol_parity \
    "can_flow_to exists and Verus models fail-closed flow admissibility (FLOW-ADM-1)" \
    "$PROD_PROVENANCE" \
    'pub const fn can_flow_to' \
    "$VERUS_TRUST_LATTICE" \
    'lemma_flow_adm_fail_closed'
check_symbol_parity \
    "FlowPoint::compose exists and Verus models composition lowers trust (FLOW-PROD-1)" \
    "$PROD_PROVENANCE" \
    'pub const fn compose' \
    "$VERUS_TRUST_LATTICE" \
    'lemma_flow_prod_compose_lowers_trust'
check_symbol_parity \
    "WP 3A end-to-end: tainted privileged flow denied without declassification" \
    "$PROD_PROVENANCE" \
    'pub fn check_flow_admissibility' \
    "$VERUS_TRUST_LATTICE" \
    'lemma_tainted_privileged_flow_denied'
echo ""

echo "--- Entropy Pipeline Kernel ---"
check_file_pair \
    "verified_entropy_pipeline.rs ↔ vellaveto-engine/src/verified_entropy_gate.rs" \
    "$PROD_ENTROPY" \
    "$VERUS_ENTROPY_PIPELINE"
check_symbol_parity \
    "production entropy severity helper exists and Verus models pipeline severity" \
    "$PROD_ENTROPY" \
    'entropy_alert_severity' \
    "$VERUS_ENTROPY_PIPELINE" \
    'pub[[:space:]]+fn[[:space:]]+alert_severity'
check_symbol_parity \
    "production entropy alert gate exists and Verus models pipeline alerting" \
    "$PROD_ENTROPY" \
    'should_alert_on_high_entropy_count' \
    "$VERUS_ENTROPY_PIPELINE" \
    'pub[[:space:]]+fn[[:space:]]+should_alert'
echo ""

echo "--- Merkle Integrity Composition Kernel (P4) ---"
check_file_pair \
    "verified_merkle_integrity.rs exists (MERKL-INT-1 through MERKL-INT-5)" \
    "$PROD_MERKLE_WRAPPER" \
    "$VERUS_MERKLE_INTEGRITY"
check_symbol_parity \
    "merkle leaf second-preimage axiom used in integrity kernel (MERKL-INT-1)" \
    "$VERUS_MERKLE_INTEGRITY" \
    'axiom_merkle_leaf_second_preimage_resistance' \
    "$VERUS_MERKLE_INTEGRITY" \
    'lemma_leaf_hash_unique'
check_symbol_parity \
    "domain separation axiom used in integrity kernel (MERKL-INT-3)" \
    "$VERUS_MERKLE_INTEGRITY" \
    'axiom_merkle_rfc6962_domain_separation' \
    "$VERUS_MERKLE_INTEGRITY" \
    'lemma_leaf_and_internal_hash_never_equal'
check_symbol_parity \
    "depth-2 tamper evidence lemma present (MERKL-INT-5 extension)" \
    "$PROD_MERKLE_WRAPPER" \
    'pub fn append' \
    "$VERUS_MERKLE_INTEGRITY" \
    'lemma_different_leaf_means_different_grandparent'
echo ""

echo "--- Audit Chain Integrity Composition Kernel (P4) ---"
check_file_pair \
    "verified_audit_integrity.rs exists (AUDIT-INT-1 through AUDIT-INT-4)" \
    "$PROD_AUDIT_WRAPPER" \
    "$VERUS_AUDIT_INTEGRITY"
check_symbol_parity \
    "global sequence monotone growth proven (AUDIT-INT-1)" \
    "$PROD_AUDIT_APPEND_WRAPPER" \
    'global_sequence' \
    "$VERUS_AUDIT_INTEGRITY" \
    'lemma_global_seq_increases_by_n'
check_symbol_parity \
    "rotation resets entry count (AUDIT-INT-2)" \
    "$PROD_AUDIT_APPEND_WRAPPER" \
    'rotation' \
    "$VERUS_AUDIT_INTEGRITY" \
    'lemma_rotation_resets_entry_count'
check_symbol_parity \
    "hash-latch monotonicity proven (AUDIT-INT-3)" \
    "$PROD_AUDIT_CHAIN" \
    'next_seen_hashed_entry' \
    "$VERUS_AUDIT_INTEGRITY" \
    'lemma_seen_hashed_latches_true'
echo ""

echo "--- Capability Chain Composition Kernel ---"
check_file_pair \
    "verified_capability_chain.rs exists (CAP-CHAIN-1 through CAP-CHAIN-5)" \
    "$PROD_CAP_TOKEN" \
    "$VERUS_CAP_CHAIN"
check_symbol_parity \
    "production depth decrement exists and chain proof covers monotonicity" \
    "$PROD_CAP_TOKEN" \
    'attenuate_capability_token' \
    "$VERUS_CAP_CHAIN" \
    'lemma_chain_depth_exact'
check_symbol_parity \
    "chain proof covers fail-closed depth exhaustion (CAP-CHAIN-2)" \
    "$PROD_CAP_TOKEN" \
    'remaining_depth' \
    "$VERUS_CAP_CHAIN" \
    'lemma_depth_exhausted_at_n_steps'
check_symbol_parity \
    "chain proof covers end-to-end fail-closed composition (CAP-CHAIN-5)" \
    "$PROD_CAP_TOKEN" \
    'attenuate_capability_token' \
    "$VERUS_CAP_CHAIN" \
    'lemma_delegated_context_fail_closed'
echo ""

echo "--- Float-to-Fixed Wrapper Kernel ---"
check_file_pair \
    "verified_entropy_fixed_point.rs exists (FP-WRAP-1 through FP-WRAP-6)" \
    "$PROD_ENTROPY_WRAPPER" \
    "$VERUS_ENTROPY_FIXED_POINT"
check_symbol_parity \
    "float_boundary_axioms.rs contains FLOAT-CONV-1 (output bounded)" \
    "$VERUS_FLOAT_AXIOMS" \
    'axiom_entropy_conv_bounded' \
    "$VERUS_ENTROPY_FIXED_POINT" \
    'lemma_entropy_conv_bounded'
check_symbol_parity \
    "float-to-fixed wrapper proves no false negative (FP-WRAP-4)" \
    "$PROD_ENTROPY_WRAPPER" \
    'entropy_threshold_millibits' \
    "$VERUS_ENTROPY_FIXED_POINT" \
    'lemma_no_false_negative'
check_file_pair \
    "float_boundary_axioms.rs exists and is in allowlist" \
    "$PROD_ENTROPY_WRAPPER" \
    "$VERUS_FLOAT_AXIOMS"
echo ""

echo "--- Cross-Call Split-Detection Completeness ---"
check_file_pair \
    "verified_cross_call_split.rs exists (CC-SPLIT-1 through CC-SPLIT-4)" \
    "$PROD_CROSS_DLP_WRAPPER" \
    "$VERUS_CROSS_CALL_SPLIT"
check_symbol_parity \
    "cross_call_dlp.rs uses format! concatenation and split proof covers it" \
    "$PROD_CROSS_DLP_WRAPPER" \
    'format!' \
    "$VERUS_CROSS_CALL_SPLIT" \
    'lemma_split_secret_in_combined'
check_symbol_parity \
    "bounded-secret completeness lemma present (secrets ≤ 2×overlap)" \
    "$PROD_CROSS_DLP_WRAPPER" \
    'DEFAULT_OVERLAP_BUFFER_SIZE' \
    "$VERUS_CROSS_CALL_SPLIT" \
    'lemma_bounded_secret_always_covered'
echo ""

if [ "$DRIFT_FOUND" -ne 0 ]; then
    echo "=== DRIFT DETECTED ==="
    echo "Verus proof targets have drifted from their documented production counterparts."
    exit 1
fi

echo "=== SYMBOL PARITY PASSED ==="
echo "Every documented Verus kernel has its production counterpart, and every"
echo "expected symbol is present on both sides."
echo ""
echo "This does NOT establish that the two implementations compute the same"
echo "function. The kernels and their mirrors are structurally different"
echo "implementations and the correspondence between them is hand-established:"
echo "see PARITY-HAND-1 in formal/ASSUMPTION_REGISTRY.md. Behavioural drift is"
echo "caught only where a differential test exists."
