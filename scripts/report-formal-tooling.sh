#!/usr/bin/env bash
#
# report-formal-tooling.sh — print local formal tool availability.
#
# This script is informational by design. Strict proof enforcement belongs in
# `make verify` through the individual formal targets.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

report_available() {
    printf 'AVAILABLE: %s\n' "$1"
}

report_skip() {
    printf 'SKIP: %s\n' "$1"
}

if command -v java >/dev/null 2>&1 && [ -f formal/tla/tla2tools.jar ]; then
    report_available "TLA+ model checking"
else
    report_skip "TLA+ model checking (requires Java 11+ and formal/tla/tla2tools.jar)"
fi

if command -v java >/dev/null 2>&1 && [ -f formal/alloy/alloy.jar ]; then
    report_available "Alloy bounded model checking"
else
    report_skip "Alloy bounded model checking (requires Java 11+ and formal/alloy/alloy.jar)"
fi

if command -v lake >/dev/null 2>&1; then
    report_available "Lean 4 type checking"
else
    report_skip "Lean 4 type checking (requires lake)"
fi

if command -v coqc >/dev/null 2>&1; then
    report_available "Coq type checking"
else
    report_skip "Coq type checking (requires coqc)"
fi

if command -v cargo-kani >/dev/null 2>&1; then
    report_available "Kani bounded model checking"
else
    report_skip "Kani bounded model checking (requires cargo-kani)"
fi

if [ -n "${CARGO_VERUS_BIN:-}" ] \
    || command -v cargo-verus >/dev/null 2>&1 \
    || [ -x verus-bin/verus-x86-linux/cargo-verus ] \
    || [ -x "$HOME/verus/verus-bin/verus-x86-linux/cargo-verus" ] \
    || [ -x "$HOME/verus/source/target-verus/release/cargo-verus" ]; then
    report_available "Verus deductive verification"
else
    report_skip "Verus deductive verification (requires CARGO_VERUS_BIN, cargo-verus, verus-bin/, or ~/verus)"
fi
