#!/usr/bin/env bash
#
# run-alloy-model.sh - Run one Alloy model with the pinned Analyzer CLI entrypoint.
#
# Usage:
#   ALLOY_JAR=formal/alloy/alloy.jar bash formal/tools/run-alloy-model.sh formal/alloy/CapabilityDelegation.als

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <model.als>" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
MODEL_PATH="$1"
ALLOY_JAR_PATH="${ALLOY_JAR:-$PROJECT_DIR/formal/alloy/alloy.jar}"
ALLOY_COMMAND_PATTERN="${ALLOY_COMMAND_PATTERN:-S*}"

case "$MODEL_PATH" in
    /*) ;;
    *) MODEL_PATH="$PROJECT_DIR/$MODEL_PATH" ;;
esac

case "$ALLOY_JAR_PATH" in
    /*) ;;
    *) ALLOY_JAR_PATH="$PROJECT_DIR/$ALLOY_JAR_PATH" ;;
esac

if ! command -v java >/dev/null 2>&1; then
    echo "FAIL: java is required to run Alloy" >&2
    exit 1
fi

if [ ! -f "$ALLOY_JAR_PATH" ]; then
    echo "FAIL: Alloy jar not found: $ALLOY_JAR_PATH" >&2
    echo "Set ALLOY_JAR or place the Analyzer jar at formal/alloy/alloy.jar" >&2
    exit 1
fi

if [ ! -f "$MODEL_PATH" ]; then
    echo "FAIL: Alloy model not found: $MODEL_PATH" >&2
    exit 1
fi

LOG_FILE="$(mktemp "${TMPDIR:-/tmp}/vellaveto-alloy.XXXXXX.log")"
cleanup() {
    rm -f "$LOG_FILE"
}
trap cleanup EXIT

echo "=== Alloy $(basename "$MODEL_PATH") ==="
echo "Command pattern: $ALLOY_COMMAND_PATTERN"

set +e
java -jar "$ALLOY_JAR_PATH" exec \
    --force \
    --output - \
    --type text \
    --command "$ALLOY_COMMAND_PATTERN" \
    "$MODEL_PATH" 2>&1 | tee "$LOG_FILE"
exit_code=${PIPESTATUS[0]}
set -e

if [ "$exit_code" -ne 0 ]; then
    echo "FAIL: Alloy exited with code $exit_code" >&2
    exit "$exit_code"
fi

if grep -Eq "Counterexample|---Trace---" "$LOG_FILE"; then
    echo "FAIL: Alloy found a counterexample in $MODEL_PATH" >&2
    exit 1
fi

echo "Alloy checks passed: $(basename "$MODEL_PATH")"
