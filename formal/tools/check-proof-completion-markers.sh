#!/usr/bin/env bash
#
# check-proof-completion-markers.sh - reject unfinished Lean/Coq proof holes
#
# This complements the trusted-assumption inventory. Axioms and parameters are
# tracked there; proof holes such as Lean `sorry` and Coq `Admitted` should not
# appear in committed proof sources at all.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

LEAN_DIR="$PROJECT_DIR/formal/lean/Vellaveto"
COQ_DIR="$PROJECT_DIR/formal/coq/Vellaveto"
failed=0

require_dir() {
    local dir="$1"
    local label="$2"

    if [ ! -d "$dir" ]; then
        echo "FAIL: $label proof directory missing: ${dir#$PROJECT_DIR/}"
        exit 1
    fi
}

scan_markers() {
    local label="$1"
    local dir="$2"
    local include_glob="$3"
    local pattern="$4"
    local hits

    hits="$(grep -RInE --include="$include_glob" "$pattern" "$dir" || true)"
    if [ -n "$hits" ]; then
        echo "FAIL: $label proof completion markers found"
        printf '%s\n' "$hits" | sed "s#$PROJECT_DIR/##"
        failed=1
    else
        echo "$label proof completion markers: none"
    fi
}

require_dir "$LEAN_DIR" "Lean"
require_dir "$COQ_DIR" "Coq"

scan_markers \
    "Lean" \
    "$LEAN_DIR" \
    "*.lean" \
    '(^|[^[:alnum:]_])(sorry|admit)([^[:alnum:]_]|$)'

scan_markers \
    "Coq" \
    "$COQ_DIR" \
    "*.v" \
    '(^|[^[:alnum:]_])(Admitted|admit|Abort)[[:space:]]*\.'

if [ "$failed" -ne 0 ]; then
    echo ""
    echo "FAIL: unfinished proof markers are present in Lean/Coq sources"
    exit 1
fi

echo "All Lean/Coq proof sources are free of unfinished proof markers."
