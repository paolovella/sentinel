#!/usr/bin/env bash
# check-differential-parity.sh — behavioural binding between Verus kernels and
# the code that ships.
#
# check-verus-parity.sh establishes symbol parity only: it greps for names and
# cannot see what a function computes. This guard runs the differential tests
# that execute a transcription of the Verus *spec* function alongside the
# shipped function and assert they agree over an exhaustively enumerated input
# space. Each such test discharges PARITY-HAND-1 for one kernel.
#
# Kernels without a differential test remain under the assumption. The registry
# is the source of truth for which those are.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_DIR" || exit 1

# Shared across invocations so the guard self-test's repeated runs stay
# incremental instead of paying a cold build per mutation case.
export CARGO_TARGET_DIR="${DIFFERENTIAL_TARGET_DIR:-/tmp/vellaveto-differential-target}"

FAILED=0

run_differential() {
    local label="$1" crate="$2" filter="$3"
    if cargo test -p "$crate" --lib "$filter" >/dev/null 2>&1; then
        echo "  OK: $label"
    else
        echo "  DRIFT: $label — shipped behaviour disagrees with the Verus spec"
        FAILED=1
    fi
}

echo "=== Differential Parity (PARITY-HAND-1 discharge) ==="

# One filter covers every `verus_spec_differential` module in the crate, so a
# newly added discharge is picked up without editing this script.
run_differential "vellaveto-mcp capability kernels ↔ their Verus specs" \
    vellaveto-mcp verus_spec_differential

run_differential "vellaveto-audit chain/merkle kernels ↔ their Verus specs" \
    vellaveto-audit verus_spec_differential

run_differential "vellaveto-engine policy/delegation kernels ↔ their Verus specs" \
    vellaveto-engine verus_spec_differential

run_differential "vellaveto-approval consumption/scope kernels ↔ their Verus specs" \
    vellaveto-approval verus_spec_differential

run_differential "vellaveto-types transport-context kernel ↔ its Verus spec" \
    vellaveto-types verus_spec_differential

echo ""
if [ "$FAILED" -ne 0 ]; then
    echo "=== DRIFT DETECTED ==="
    exit 1
fi
echo "=== DIFFERENTIAL PARITY PASSED ==="
exit 0
