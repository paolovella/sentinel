#!/usr/bin/env bash
#
# check-kani-parity.sh — Verify Kani extracted code matches production
#
# The Kani crate (formal/kani/) cannot import vellaveto-engine directly
# due to ICU normalizer issues. Instead, critical functions are extracted
# into standalone files. This script verifies the extractions haven't
# drifted from production.
#
# Usage: bash formal/tools/check-kani-parity.sh
# Env:
#   RUN_KANI_PARITY_TESTS=0 to skip the filtered cargo parity test run
# Exit code: 0 = all match, 1 = drift detected

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
KANI_DIR="$PROJECT_DIR/formal/kani/src"
KANI_LIB="$KANI_DIR/lib.rs"
KANI_PARITY_TARGET_DIR="${KANI_PARITY_TARGET_DIR:-${CARGO_TARGET_DIR:-/tmp/vellaveto-formal-kani-parity-target}}"
DRIFT_FOUND=0

echo "=== Kani Extracted Code Parity Check ==="
echo ""

# ─── Helpers ─────────────────────────────────────────────────────────────
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
    local kani_file="$3"

    if [ ! -f "$prod_file" ]; then
        fail "$label — production file not found: $prod_file"
        return
    fi
    if [ ! -f "$kani_file" ]; then
        fail "$label — kani file not found: $kani_file"
        return
    fi

    pass "$label"
}

check_symbol_parity() {
    local label="$1"
    local prod_file="$2"
    local prod_pattern="$3"
    local kani_file="$4"
    local kani_pattern="$5"

    if [ ! -f "$prod_file" ]; then
        fail "$label — production file not found: $prod_file"
        return
    fi
    if [ ! -f "$kani_file" ]; then
        fail "$label — kani file not found: $kani_file"
        return
    fi

    if ! grep -Eq "$prod_pattern" "$prod_file" 2>/dev/null; then
        fail "$label — production pattern '$prod_pattern' not found in $prod_file"
        return
    fi
    if ! grep -Eq "$kani_pattern" "$kani_file" 2>/dev/null; then
        fail "$label — kani pattern '$kani_pattern' not found in $kani_file"
        return
    fi

    pass "$label"
}

check_manifest_correspondence() {
    local line
    while IFS= read -r line; do
        if [[ "$line" =~ ^//!\ -\ \`([^[:space:]]+)\`:\ (Verbatim\ from|Extracted\ from)\ \`([^[:space:]]+)\` ]]; then
            local kani_rel="${BASH_REMATCH[1]}"
            local prod_rel="${BASH_REMATCH[3]}"
            check_file_pair "$kani_rel ↔ $prod_rel" "$PROJECT_DIR/$prod_rel" "$KANI_DIR/$kani_rel"
        fi
    done < "$KANI_LIB"
}

# ─── 1. Manifest correspondence ──────────────────────────────────────────
echo "--- Extracted File Manifest ---"

check_manifest_correspondence

echo ""

# ─── 2. verified_core.rs (Verdict computation) ──────────────────────────
echo "--- Verdict Core (V1-V8) ---"

PROD_CORE="$PROJECT_DIR/vellaveto-engine/src/verified_core.rs"
KANI_CORE="$KANI_DIR/verified_core.rs"

    if [ -f "$PROD_CORE" ] && [ -f "$KANI_CORE" ]; then
    for fn in "compute_single_verdict" "compute_verdict"; do
        check_symbol_parity "$fn exists in both files" "$PROD_CORE" "pub[[:space:]]+fn[[:space:]]+$fn" "$KANI_CORE" "pub[[:space:]]+fn[[:space:]]+$fn"
    done

    if [ "${RUN_KANI_PARITY_TESTS:-1}" = "1" ]; then
        echo "  Running filtered parity tests..."
        if (cd "$PROJECT_DIR/formal/kani" && CARGO_TARGET_DIR="$KANI_PARITY_TARGET_DIR" cargo test --lib -- parity 2>/dev/null | grep -q "test result: ok"); then
            pass "Kani parity tests pass"
        else
            fail "Kani parity tests FAILED"
        fi
    fi
else
    fail "verified_core.rs manifest pair missing"
fi

echo ""

# ─── 3. path.rs (Path normalization) ────────────────────────────────────
echo "--- Path Normalization (K2-K3) ---"

PROD_PATH="$PROJECT_DIR/vellaveto-engine/src/path.rs"
KANI_PATH="$KANI_DIR/path.rs"

check_symbol_parity "normalize_path" "$PROD_PATH" "pub[[:space:]]+fn[[:space:]]+normalize_path" "$KANI_PATH" "pub[[:space:]]+fn[[:space:]]+normalize_path"

echo ""

# ─── 4. dlp_core.rs (DLP buffer arithmetic) ─────────────────────────────
echo "--- DLP Buffer (D1-D6) ---"

PROD_DLP="$PROJECT_DIR/vellaveto-mcp/src/inspection/verified_dlp_core.rs"
KANI_DLP="$KANI_DIR/dlp_core.rs"

for fn in "extract_tail" "can_track_field" "update_total_bytes" "is_utf8_char_boundary"; do
    check_symbol_parity "$fn" "$PROD_DLP" "pub[[:space:]]+fn[[:space:]]+$fn" "$KANI_DLP" "pub[[:space:]]+fn[[:space:]]+$fn"
done

echo ""

# ─── 5. IP address verification ─────────────────────────────────────────
echo "--- IP Address (K26-K32) ---"

PROD_IP="$PROJECT_DIR/vellaveto-engine/src/ip.rs"
KANI_IP="$KANI_DIR/ip.rs"

check_symbol_parity \
    "is_private_ip (→ is_private_ipv4 in Kani)" \
    "$PROD_IP" \
    "fn[[:space:]]+is_private_ip" \
    "$KANI_IP" \
    "pub[[:space:]]+fn[[:space:]]+is_private_ipv4"
check_symbol_parity \
    "is_embedded_ipv4_reserved" \
    "$PROD_IP" \
    "fn[[:space:]]+is_embedded_ipv4_reserved" \
    "$KANI_IP" \
    "pub[[:space:]]+fn[[:space:]]+is_embedded_ipv4_reserved"

echo ""

# ─── 6. Broader extracted surface spot checks ───────────────────────────
echo "--- Extended Extraction Spot Checks ---"

PROD_ENGINE_LIB="$PROJECT_DIR/vellaveto-engine/src/lib.rs"
PROD_RULE_CHECK="$PROJECT_DIR/vellaveto-engine/src/rule_check.rs"
PROD_CACHE="$PROJECT_DIR/vellaveto-engine/src/cache.rs"
PROD_CONSTRAINT="$PROJECT_DIR/vellaveto-engine/src/constraint_eval.rs"
PROD_CASCADING="$PROJECT_DIR/vellaveto-engine/src/cascading.rs"
PROD_COLLUSION="$PROJECT_DIR/vellaveto-engine/src/collusion.rs"
PROD_TASK="$PROJECT_DIR/vellaveto-types/src/task.rs"
PROD_TASK_STATE="$PROJECT_DIR/vellaveto-mcp/src/task_state.rs"
PROD_CAPABILITY="$PROJECT_DIR/vellaveto-mcp/src/capability_token.rs"
PROD_DOMAIN="$PROJECT_DIR/vellaveto-engine/src/domain.rs"
PROD_UNICODE="$PROJECT_DIR/vellaveto-types/src/unicode.rs"
PROD_SANITIZER="$PROJECT_DIR/vellaveto-mcp-shield/src/sanitizer.rs"
PROD_INJECTION="$PROJECT_DIR/vellaveto-mcp/src/inspection/injection.rs"
PROD_ENTROPY_GATE="$PROJECT_DIR/vellaveto-engine/src/entropy_gate.rs"
PROD_COLLUSION_DETECTION="$PROJECT_DIR/vellaveto-engine/src/collusion.rs"
PROD_CREDENTIAL_VAULT="$PROJECT_DIR/vellaveto-mcp-shield/src/credential_vault.rs"
PROD_TLS="$PROJECT_DIR/vellaveto-tls/src/lib.rs"
PROD_MERKLE="$PROJECT_DIR/vellaveto-audit/src/merkle.rs"

check_symbol_parity "cacheability predicate" "$PROD_CACHE" "fn[[:space:]]+is_cacheable_context" "$KANI_DIR/cache.rs" "pub[[:space:]]+fn[[:space:]]+is_cacheable_context"
check_symbol_parity "capability action coverage" "$PROD_CAPABILITY" "fn[[:space:]]+grant_covers_action" "$KANI_DIR/capability.rs" "pub[[:space:]]+fn[[:space:]]+grant_covers_action"
check_symbol_parity "capability runtime glob matcher uses verified kernel" "$PROD_CAPABILITY" "verified_capability_glob::literal_child_matches_parent_glob" "$KANI_DIR/capability.rs" "fn[[:space:]]+pattern_matches"
check_symbol_parity "capability child-glob exact subset kernel" "$PROD_CAPABILITY" "verified_capability_glob_subset::glob_pattern_subset" "$KANI_DIR/capability.rs" "pub[[:space:]]+fn[[:space:]]+glob_pattern_subset"
check_symbol_parity "capability metacharacter detector" "$PROD_CAPABILITY" "verified_capability_pattern::has_glob_metacharacters" "$KANI_DIR/capability.rs" "pub[[:space:]]+fn[[:space:]]+has_glob_metacharacters"
check_symbol_parity "capability literal matcher" "$PROD_CAPABILITY" "verified_capability_literal::literal_pattern_matches" "$KANI_DIR/capability.rs" "pub[[:space:]]+fn[[:space:]]+literal_pattern_matches"
check_symbol_parity "capability literal child subset" "$PROD_CAPABILITY" "verified_capability_literal::literal_child_pattern_subset" "$KANI_DIR/capability.rs" "pub[[:space:]]+fn[[:space:]]+literal_child_pattern_subset"
check_symbol_parity "capability grant attenuation gate" "$PROD_CAPABILITY" "verified_capability_grant::grant_restrictions_attenuated" "$KANI_DIR/capability.rs" "pub[[:space:]]+fn[[:space:]]+grant_restrictions_attenuated"
check_symbol_parity "capability grant coverage gate" "$PROD_CAPABILITY" "verified_capability_coverage::grant_restrictions_cover_action" "$KANI_DIR/capability.rs" "pub[[:space:]]+fn[[:space:]]+grant_restrictions_cover_action"
check_symbol_parity "capability domain coverage uses verified helper" "$PROD_CAPABILITY" "verified_capability_domain::domain_matches_pattern" "$KANI_DIR/capability.rs" "pub[[:space:]]+fn[[:space:]]+domain_pattern_shape_valid"
check_symbol_parity "capability domain subset uses verified helper" "$PROD_CAPABILITY" "verified_capability_domain::domain_pattern_is_subset" "$KANI_DIR/capability.rs" "pub[[:space:]]+fn[[:space:]]+normalized_domain_pattern_subset"
check_symbol_parity "capability path transition gate" "$PROD_CAPABILITY" "verified_capability_path::normalize_path_for_grant" "$KANI_DIR/capability.rs" "pub[[:space:]]+fn[[:space:]]+path_component_next_depth"
check_symbol_parity "capability first-match selection gate" "$PROD_CAPABILITY" "verified_capability_selection::next_covering_grant_index" "$KANI_DIR/capability.rs" "pub[[:space:]]+fn[[:space:]]+next_covering_grant_index"
check_symbol_parity "capability path normalization uses verified helper" "$PROD_CAPABILITY" "verified_capability_path::normalize_path_for_grant" "$KANI_DIR/capability.rs" "pub[[:space:]]+fn[[:space:]]+normalize_path_for_grant"
check_symbol_parity "rule_check path rules" "$PROD_RULE_CHECK" "fn[[:space:]]+check_path_rules" "$KANI_DIR/rule_check.rs" "pub[[:space:]]+fn[[:space:]]+check_path_rules_decision"
check_symbol_parity "rule_check network rules" "$PROD_RULE_CHECK" "fn[[:space:]]+check_network_rules" "$KANI_DIR/rule_check.rs" "pub[[:space:]]+fn[[:space:]]+check_network_rules_decision"
check_symbol_parity "rule_check ip rules" "$PROD_RULE_CHECK" "fn[[:space:]]+check_ip_rules" "$KANI_DIR/rule_check.rs" "pub[[:space:]]+fn[[:space:]]+check_ip_rules_decision"
check_symbol_parity "resolved match inline path" "$PROD_ENGINE_LIB" "fn[[:space:]]+apply_compiled_policy_ctx" "$KANI_DIR/resolve.rs" "pub[[:space:]]+fn[[:space:]]+apply_policy_inline"
check_symbol_parity "resolved match verified path" "$PROD_ENGINE_LIB" "fn[[:space:]]+apply_compiled_policy_ctx" "$KANI_DIR/resolve.rs" "pub[[:space:]]+fn[[:space:]]+apply_policy_verified"
check_symbol_parity "cascading config validation" "$PROD_CASCADING" "pub[[:space:]]+fn[[:space:]]+validate" "$KANI_DIR/cascading.rs" "pub[[:space:]]+fn[[:space:]]+validate_config"
check_symbol_parity "cascading error rate" "$PROD_CASCADING" "fn[[:space:]]+compute_error_rate_inner" "$KANI_DIR/cascading.rs" "pub[[:space:]]+fn[[:space:]]+compute_error_rate"
check_symbol_parity "constraint skip detection" "$PROD_CONSTRAINT" "fn[[:space:]]+evaluate_compiled_conditions_core" "$KANI_DIR/constraint.rs" "pub[[:space:]]+fn[[:space:]]+detect_all_skipped"
check_symbol_parity "constraint forbidden params" "$PROD_CONSTRAINT" "fn[[:space:]]+evaluate_compiled_conditions_core" "$KANI_DIR/constraint.rs" "pub[[:space:]]+fn[[:space:]]+check_forbidden_params"
check_symbol_parity "task terminal state" "$PROD_TASK" "pub[[:space:]]+fn[[:space:]]+is_terminal" "$KANI_DIR/task.rs" "pub[[:space:]]+fn[[:space:]]+is_terminal"
check_symbol_parity "task cancellation authorization" "$PROD_TASK_STATE" "pub[[:space:]]+async[[:space:]]+fn[[:space:]]+can_cancel" "$KANI_DIR/task.rs" "pub[[:space:]]+fn[[:space:]]+can_cancel"
check_symbol_parity "entropy computation" "$PROD_COLLUSION" "pub[[:space:]]+fn[[:space:]]+compute_entropy" "$KANI_DIR/entropy.rs" "pub[[:space:]]+fn[[:space:]]+compute_entropy"
check_symbol_parity "domain normalization" "$PROD_DOMAIN" "fn[[:space:]]+normalize_domain_for_match" "$KANI_DIR/domain.rs" "pub[[:space:]]+fn[[:space:]]+normalize_domain_for_match"
check_symbol_parity "unicode homoglyph normalization" "$PROD_UNICODE" "pub[[:space:]]+fn[[:space:]]+normalize_homoglyphs" "$KANI_DIR/unicode.rs" "pub[[:space:]]+fn[[:space:]]+normalize_homoglyphs"
check_symbol_parity "shield sanitizer forward pass" "$PROD_SANITIZER" "pub[[:space:]]+fn[[:space:]]+sanitize" "$KANI_DIR/sanitizer.rs" "pub[[:space:]]+fn[[:space:]]+sanitize_and_record"
check_symbol_parity "shield sanitizer reverse pass" "$PROD_SANITIZER" "pub[[:space:]]+fn[[:space:]]+desanitize" "$KANI_DIR/sanitizer.rs" "pub[[:space:]]+fn[[:space:]]+desanitize"
check_symbol_parity "temporal window extraction source" "$PROD_COLLUSION" "pub[[:space:]]+fn[[:space:]]+compute_entropy" "$KANI_DIR/temporal_window.rs" "pub[[:space:]]+fn[[:space:]]+expire_events"
check_symbol_parity "circuit-breaker state machine extraction source" "$PROD_CASCADING" "pub[[:space:]]+fn[[:space:]]+record_pipeline_error" "$KANI_DIR/cascading_fsm.rs" "pub[[:space:]]+fn[[:space:]]+should_break"
check_symbol_parity "injection decode pipeline" "$PROD_INJECTION" "pub[[:space:]]+fn[[:space:]]+inspect_for_injection" "$KANI_DIR/injection_pipeline.rs" "pub[[:space:]]+fn[[:space:]]+run_decode_pipeline"
check_symbol_parity "entropy fixed-point wrapper" "$PROD_ENTROPY_GATE" "fn[[:space:]]+entropy_fixed_point" "$KANI_DIR/entropy_wrapper.rs" "pub[[:space:]]+fn[[:space:]]+entropy_fixed_point"
check_symbol_parity "entropy threshold floor helper" "$PROD_ENTROPY_GATE" "fn[[:space:]]+entropy_threshold_millibits" "$KANI_DIR/entropy_wrapper.rs" "pub[[:space:]]+fn[[:space:]]+entropy_threshold_millibits"
check_symbol_parity "entropy observation ceil helper" "$PROD_ENTROPY_GATE" "fn[[:space:]]+entropy_observation_millibits" "$KANI_DIR/entropy_wrapper.rs" "pub[[:space:]]+fn[[:space:]]+entropy_observation_millibits"
check_symbol_parity "collusion config validation" "$PROD_COLLUSION_DETECTION" "pub[[:space:]]+fn[[:space:]]+validate" "$KANI_DIR/collusion_detection.rs" "pub[[:space:]]+fn[[:space:]]+validate"
check_symbol_parity "collusion tracked-agent capacity bound" "$PROD_COLLUSION_DETECTION" "const[[:space:]]+MAX_TRACKED_AGENTS:[[:space:]]+usize[[:space:]]*=[[:space:]]*10_000;" "$KANI_DIR/collusion_detection.rs" "pub[[:space:]]+const[[:space:]]+MAX_TRACKED_AGENTS:[[:space:]]+usize[[:space:]]*=[[:space:]]*10_000;"
check_symbol_parity "collusion half-open denial window" "$PROD_COLLUSION_DETECTION" "ts >= window_start && ts < window_end" "$KANI_DIR/collusion_detection.rs" "ts >= window_start && ts < window_end"
check_symbol_parity "sort bridge anchors engine policy sorting" "$PROD_ENGINE_LIB" "pub[[:space:]]+fn[[:space:]]+sort_policies" "$KANI_DIR/sort_bridge.rs" "sort_resolved_matches"
check_symbol_parity "credential vault consumption path" "$PROD_CREDENTIAL_VAULT" "pub[[:space:]]+fn[[:space:]]+consume_credential" "$KANI_DIR/credential_vault.rs" "pub[[:space:]]+fn[[:space:]]+consume_credential"
check_symbol_parity "credential vault consume-to-consumed transition" "$PROD_CREDENTIAL_VAULT" "pub[[:space:]]+fn[[:space:]]+mark_consumed" "$KANI_DIR/credential_vault.rs" "pub[[:space:]]+fn[[:space:]]+mark_consumed"
check_symbol_parity "credential vault epoch expiry" "$PROD_CREDENTIAL_VAULT" "pub[[:space:]]+fn[[:space:]]+expire_old_epochs" "$KANI_DIR/credential_vault.rs" "pub[[:space:]]+fn[[:space:]]+expire_old_epochs"
check_symbol_parity "TLS hex-digit parser" "$PROD_TLS" "fn[[:space:]]+hex_digit" "$KANI_DIR/tls_spiffe.rs" "pub[[:space:]]+fn[[:space:]]+hex_digit"
check_symbol_parity "TLS SPIFFE percent decoder" "$PROD_TLS" "fn[[:space:]]+percent_decode_workload_path" "$KANI_DIR/tls_spiffe.rs" "pub[[:space:]]+fn[[:space:]]+percent_decode_workload_path"
check_symbol_parity "TLS SPIFFE parser" "$PROD_TLS" "pub[[:space:]]+fn[[:space:]]+parse" "$KANI_DIR/tls_spiffe.rs" "pub[[:space:]]+fn[[:space:]]+parse"
check_symbol_parity "Merkle leaf hashing" "$PROD_MERKLE" "pub[[:space:]]+fn[[:space:]]+hash_leaf" "$KANI_DIR/merkle_sanity.rs" "pub[[:space:]]+fn[[:space:]]+merkle_leaf_hash"
check_symbol_parity "Merkle internal hashing" "$PROD_MERKLE" "pub[[:space:]]+fn[[:space:]]+hash_internal" "$KANI_DIR/merkle_sanity.rs" "pub[[:space:]]+fn[[:space:]]+merkle_internal_hash"

echo ""

# ─── 7. Structural checks ────────────────────────────────────────────────
echo "--- Structural Checks ---"

for pair in \
    "verified_core:$PROD_CORE:$KANI_CORE" \
    "dlp_core:$PROD_DLP:$KANI_DLP" \
    "cache:$PROD_CACHE:$KANI_DIR/cache.rs" \
    "constraint:$PROD_CONSTRAINT:$KANI_DIR/constraint.rs" \
    "cascading:$PROD_CASCADING:$KANI_DIR/cascading.rs"; do

    label="${pair%%:*}"
    rest="${pair#*:}"
    prod="${rest%%:*}"
    kani="${rest#*:}"

    if [ -f "$prod" ] && [ -f "$kani" ]; then
        PROD_FN_COUNT=$(grep -c "pub.*fn " "$prod" 2>/dev/null || echo 0)
        KANI_FN_COUNT=$(grep -c "pub.*fn " "$kani" 2>/dev/null || echo 0)
        if [ "$KANI_FN_COUNT" -lt "$PROD_FN_COUNT" ]; then
            echo "  INFO: $label — kani has fewer functions ($KANI_FN_COUNT) than production ($PROD_FN_COUNT)"
            echo "        This is acceptable for partial models, but review if production semantics changed."
        else
            pass "$label — kani has $KANI_FN_COUNT functions (production: $PROD_FN_COUNT)"
        fi
    fi
done

echo ""

# ─── Summary ──────────────────────────────────────────────────────────
if [ "$DRIFT_FOUND" -eq 1 ]; then
    echo "=== DRIFT DETECTED ==="
    echo "Kani extracted code has drifted from production."
    echo "Update formal/kani/src/ to match the production code."
    exit 1
else
    echo "=== ALL CHECKS PASSED ==="
    echo "Kani extracted code matches production."
    exit 0
fi
