#!/usr/bin/env bash
#
# check-formal-e2e-coverage.sh — storage-light end-to-end formal coverage guard
#
# Usage: bash formal/tools/check-formal-e2e-coverage.sh
# Exit code: 0 = all expected stages are anchored, 1 = drift detected

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DRIFT_FOUND=0

fail() {
    echo "  DRIFT: $1"
    DRIFT_FOUND=1
}

pass() {
    echo "  OK: $1"
}

check_file() {
    local label="$1"
    local file="$2"

    if [ ! -f "$file" ]; then
        fail "$label — file not found: $file"
        return
    fi

    pass "$label"
}

check_pattern() {
    local label="$1"
    local file="$2"
    local pattern="$3"

    if [ ! -f "$file" ]; then
        fail "$label — file not found: $file"
        return
    fi

    if ! grep -Eq "$pattern" "$file" 2>/dev/null; then
        fail "$label — pattern '$pattern' not found in $file"
        return
    fi

    pass "$label"
}

echo "=== Formal End-to-End Coverage Check ==="
echo ""

echo "--- Transport Context ---"
check_file \
    "production transport kernel present" \
    "$PROJECT_DIR/vellaveto-types/src/verified_transport_context.rs"
check_file \
    "Verus transport kernel present" \
    "$PROJECT_DIR/formal/verus/verified_transport_context.rs"
check_pattern \
    "transport identity projection is anchored in production" \
    "$PROJECT_DIR/vellaveto-types/src/verified_transport_context.rs" \
    'project_agent_identity_from_transport'
check_pattern \
    "transport identity projection is modeled in Verus" \
    "$PROJECT_DIR/formal/verus/verified_transport_context.rs" \
    'project_agent_identity_from_transport'
echo ""

echo "--- Source Taint ---"
check_file \
    "production source-taint logic present" \
    "$PROJECT_DIR/vellaveto-types/src/provenance.rs"
check_file \
    "Verus source-taint kernel present" \
    "$PROJECT_DIR/formal/verus/verified_source_taint.rs"
check_file \
    "TLA source-taint model present" \
    "$PROJECT_DIR/formal/tla/SourceTaintContainment.tla"
check_file \
    "TLA source-taint config present" \
    "$PROJECT_DIR/formal/tla/SourceTaintContainment.cfg"
check_pattern \
    "production trust-floor gate exists" \
    "$PROJECT_DIR/vellaveto-types/src/provenance.rs" \
    'minimum_trust_tier_for_sink'
check_pattern \
    "Verus source-taint gate exists" \
    "$PROJECT_DIR/formal/verus/verified_source_taint.rs" \
    'min_trust_for_sink'
echo ""

echo "--- Intent Scope ---"
check_file \
    "production intent-scope config present" \
    "$PROJECT_DIR/vellaveto-config/src/channel_separation.rs"
check_file \
    "Verus intent-scope kernel present" \
    "$PROJECT_DIR/formal/verus/verified_intent_scope.rs"
check_file \
    "TLA intent-scope model present" \
    "$PROJECT_DIR/formal/tla/IntentScopeContainment.tla"
check_file \
    "TLA intent-scope config present" \
    "$PROJECT_DIR/formal/tla/IntentScopeContainment.cfg"
check_pattern \
    "production trust-floor restriction exists" \
    "$PROJECT_DIR/vellaveto-config/src/channel_separation.rs" \
    'restrict_to_trust_floor'
check_pattern \
    "Verus intent-scope restriction exists" \
    "$PROJECT_DIR/formal/verus/verified_intent_scope.rs" \
    'spec_restrict_scope'
echo ""

echo "--- Sequence Analysis ---"
check_file \
    "production sequence tracker present" \
    "$PROJECT_DIR/vellaveto-engine/src/sequence.rs"
check_file \
    "runtime sequence integration present" \
    "$PROJECT_DIR/vellaveto-mcp/src/proxy/bridge/relay.rs"
check_file \
    "Verus sequence-analysis kernel present" \
    "$PROJECT_DIR/formal/verus/verified_sequence_analysis.rs"
check_file \
    "TLA sequence model present" \
    "$PROJECT_DIR/formal/tla/SequenceContainment.tla"
check_file \
    "TLA sequence config present" \
    "$PROJECT_DIR/formal/tla/SequenceContainment.cfg"
check_pattern \
    "production sequence tracker records calls" \
    "$PROJECT_DIR/vellaveto-engine/src/sequence.rs" \
    'record_and_analyze'
check_pattern \
    "runtime sequence gate uses max confidence" \
    "$PROJECT_DIR/vellaveto-mcp/src/proxy/bridge/relay.rs" \
    'state\.sequence\.max_confidence\(\)[[:space:]]*>?=[[:space:]]*70'
check_pattern \
    "Verus sequence-analysis step exists" \
    "$PROJECT_DIR/formal/verus/verified_sequence_analysis.rs" \
    'sequence_step'
echo ""

echo "--- Inspection And DLP ---"
check_file \
    "production DLP kernel present" \
    "$PROJECT_DIR/vellaveto-mcp/src/inspection/verified_dlp_core.rs"
check_file \
    "Verus DLP kernel present" \
    "$PROJECT_DIR/formal/verus/verified_dlp_core.rs"
check_file \
    "Kani DLP extraction present" \
    "$PROJECT_DIR/formal/kani/src/dlp_core.rs"
check_pattern \
    "production DLP tail extraction exists" \
    "$PROJECT_DIR/vellaveto-mcp/src/inspection/verified_dlp_core.rs" \
    'extract_tail'
check_pattern \
    "Verus DLP tail extraction exists" \
    "$PROJECT_DIR/formal/verus/verified_dlp_core.rs" \
    'extract_tail'
check_pattern \
    "Kani DLP tail extraction exists" \
    "$PROJECT_DIR/formal/kani/src/dlp_core.rs" \
    'extract_tail'
echo ""

echo "--- Refinement ---"
check_file \
    "traced evaluator present" \
    "$PROJECT_DIR/vellaveto-engine/src/traced.rs"
check_file \
    "refinement witness tests present" \
    "$PROJECT_DIR/vellaveto-engine/tests/refinement_trace.rs"
check_file \
    "Verus refinement safety kernel present" \
    "$PROJECT_DIR/formal/verus/verified_refinement_safety.rs"
check_file \
    "Verus refinement completeness kernel present" \
    "$PROJECT_DIR/formal/verus/verified_refinement_completeness.rs"
check_file \
    "TLA MCP policy engine model present" \
    "$PROJECT_DIR/formal/tla/MCPPolicyEngine.tla"
check_file \
    "TLA MCP policy engine config present" \
    "$PROJECT_DIR/formal/tla/MCPPolicyEngine.cfg"
check_pattern \
    "traced evaluator entrypoint exists" \
    "$PROJECT_DIR/vellaveto-engine/src/traced.rs" \
    'pub[[:space:]]+fn[[:space:]]+evaluate_action_traced'
check_pattern \
    "refinement witness covers MatchHit transitions" \
    "$PROJECT_DIR/vellaveto-engine/tests/refinement_trace.rs" \
    'MatchHit'
check_pattern \
    "refinement witness covers ApplyAllow transitions" \
    "$PROJECT_DIR/vellaveto-engine/tests/refinement_trace.rs" \
    'ApplyAllow'
check_pattern \
    "refinement witness covers ApplyRequireApproval transitions" \
    "$PROJECT_DIR/vellaveto-engine/tests/refinement_trace.rs" \
    'ApplyRequireApproval'
check_pattern \
    "refinement witness covers ApplyContinue transitions" \
    "$PROJECT_DIR/vellaveto-engine/tests/refinement_trace.rs" \
    'ApplyContinue'
echo ""

echo "--- Approval ---"
check_file \
    "production approval-scope kernel present" \
    "$PROJECT_DIR/vellaveto-approval/src/verified_approval_scope.rs"
check_file \
    "Verus approval-scope kernel present" \
    "$PROJECT_DIR/formal/verus/verified_approval_scope.rs"
check_file \
    "production approval-consumption kernel present" \
    "$PROJECT_DIR/vellaveto-approval/src/verified_approval_consumption.rs"
check_file \
    "Verus approval-consumption kernel present" \
    "$PROJECT_DIR/formal/verus/verified_approval_consumption.rs"
check_pattern \
    "production approval-scope binding exists" \
    "$PROJECT_DIR/vellaveto-approval/src/verified_approval_scope.rs" \
    'approval_scope_binding_satisfied'
check_pattern \
    "production approval-consumption gate exists" \
    "$PROJECT_DIR/vellaveto-approval/src/verified_approval_consumption.rs" \
    'approval_consumption_permitted'
echo ""

echo "--- Audit And Merkle ---"
check_file \
    "production audit-chain kernel present" \
    "$PROJECT_DIR/vellaveto-audit/src/verified_audit_chain.rs"
check_file \
    "Verus audit-chain kernel present" \
    "$PROJECT_DIR/formal/verus/verified_audit_chain.rs"
check_file \
    "production merkle kernel present" \
    "$PROJECT_DIR/vellaveto-audit/src/verified_merkle.rs"
check_file \
    "Verus merkle kernel present" \
    "$PROJECT_DIR/formal/verus/verified_merkle.rs"
check_file \
    "Kani merkle sanity checks present" \
    "$PROJECT_DIR/formal/kani/src/merkle_sanity.rs"
check_file \
    "TLA audit-chain model present" \
    "$PROJECT_DIR/formal/tla/AuditChain.tla"
check_file \
    "TLA audit-chain config present" \
    "$PROJECT_DIR/formal/tla/AuditChain.cfg"
check_pattern \
    "production audit sequence gate exists" \
    "$PROJECT_DIR/vellaveto-audit/src/verified_audit_chain.rs" \
    'sequence_monotonic'
check_pattern \
    "production merkle append gate exists" \
    "$PROJECT_DIR/vellaveto-audit/src/verified_merkle.rs" \
    'append_allowed'
check_pattern \
    "Kani merkle hash sanity exists" \
    "$PROJECT_DIR/formal/kani/src/merkle_sanity.rs" \
    'sha256'
echo ""

echo "--- Credential Vault ---"
check_file \
    "production credential-vault implementation present" \
    "$PROJECT_DIR/vellaveto-mcp-shield/src/credential_vault.rs"
check_file \
    "Kani credential-vault extraction present" \
    "$PROJECT_DIR/formal/kani/src/credential_vault.rs"
check_file \
    "TLA credential-vault model present" \
    "$PROJECT_DIR/formal/tla/CredentialVault.tla"
check_file \
    "TLA credential-vault config present" \
    "$PROJECT_DIR/formal/tla/CredentialVault.cfg"
check_pattern \
    "production credential consumption exists" \
    "$PROJECT_DIR/vellaveto-mcp-shield/src/credential_vault.rs" \
    'pub[[:space:]]+fn[[:space:]]+consume_credential'
check_pattern \
    "Kani credential consumption exists" \
    "$PROJECT_DIR/formal/kani/src/credential_vault.rs" \
    'pub[[:space:]]+fn[[:space:]]+consume_credential'
echo ""

if [ "$DRIFT_FOUND" -ne 0 ]; then
    echo "=== DRIFT DETECTED ==="
    echo "End-to-end formal coverage anchors have drifted."
    exit 1
fi

echo "=== ALL CHECKS PASSED ==="
echo "End-to-end formal coverage anchors are present."
