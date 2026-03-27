#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <shard-index> <shard-count>" >&2
    exit 2
fi

SHARD_INDEX="$1"
SHARD_COUNT="$2"

case "$SHARD_INDEX" in
    ''|*[!0-9]*)
        echo "Invalid shard index: $SHARD_INDEX" >&2
        exit 2
        ;;
esac

case "$SHARD_COUNT" in
    ''|*[!0-9]*)
        echo "Invalid shard count: $SHARD_COUNT" >&2
        exit 2
        ;;
esac

if [ "$SHARD_COUNT" -eq 0 ] || [ "$SHARD_INDEX" -ge "$SHARD_COUNT" ]; then
    echo "Shard index $SHARD_INDEX out of range for shard count $SHARD_COUNT" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
KANI_DIR="$PROJECT_DIR/formal/kani"
KANI_MANIFEST="$KANI_DIR/Cargo.toml"
KANI_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/vellaveto-formal-kani-target}"
LIST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vellaveto-kani-list.XXXXXX")"
LIST_FILE="$LIST_DIR/kani-list.json"
GENERATED_LIST_FILE="$KANI_DIR/kani-list.json"
LIST_BACKUP_FILE="$LIST_DIR/kani-list.original"
RESTORE_LIST_FILE=0

cleanup() {
    if [ "$RESTORE_LIST_FILE" -eq 1 ] && [ -f "$LIST_BACKUP_FILE" ]; then
        mv "$LIST_BACKUP_FILE" "$GENERATED_LIST_FILE"
    else
        rm -f "$GENERATED_LIST_FILE"
    fi
    rm -rf "$LIST_DIR"
}

trap cleanup EXIT

export CARGO_TARGET_DIR="$KANI_TARGET_DIR"

if [ -f "$GENERATED_LIST_FILE" ]; then
    cp "$GENERATED_LIST_FILE" "$LIST_BACKUP_FILE"
    RESTORE_LIST_FILE=1
fi

cd "$KANI_DIR"

cargo kani list --format json >/dev/null

if [ ! -f "$GENERATED_LIST_FILE" ]; then
    echo "No Kani list file generated at $GENERATED_LIST_FILE" >&2
    exit 1
fi

cp "$GENERATED_LIST_FILE" "$LIST_FILE"

mapfile -t ALL_HARNESSES < <(
    if command -v rg >/dev/null 2>&1; then
        rg -o '"proofs::[^"]+"' "$LIST_FILE"
    else
        grep -oE '"proofs::[^"]+"' "$LIST_FILE"
    fi | tr -d '"'
)

if [ "${#ALL_HARNESSES[@]}" -eq 0 ]; then
    echo "No Kani harnesses found in $LIST_FILE" >&2
    exit 1
fi

SELECTED_HARNESSES=()
for idx in "${!ALL_HARNESSES[@]}"; do
    if [ $((idx % SHARD_COUNT)) -eq "$SHARD_INDEX" ]; then
        SELECTED_HARNESSES+=("${ALL_HARNESSES[$idx]}")
    fi
done

if [ "${#SELECTED_HARNESSES[@]}" -eq 0 ]; then
    echo "Shard $SHARD_INDEX/$SHARD_COUNT selected no Kani harnesses" >&2
    exit 1
fi

echo "Running Kani shard $((SHARD_INDEX + 1))/$SHARD_COUNT with ${#SELECTED_HARNESSES[@]} harnesses"
printf '  %s\n' "${SELECTED_HARNESSES[@]}"

if [ "${KANI_SHARD_DRY_RUN:-0}" = "1" ]; then
    exit 0
fi

KANI_ARGS=()
if [ -n "${KANI_SOLVER:-}" ]; then
    KANI_ARGS+=(--solver "$KANI_SOLVER")
fi

# Per-harness timeout (default 10 minutes). Override with KANI_HARNESS_TIMEOUT.
HARNESS_TIMEOUT="${KANI_HARNESS_TIMEOUT:-600}"

FAILED_HARNESSES=()
for harness in "${SELECTED_HARNESSES[@]}"; do
    echo "Verifying harness: $harness (timeout: ${HARNESS_TIMEOUT}s)"
    if ! timeout "${HARNESS_TIMEOUT}" \
        cargo kani --manifest-path "$KANI_MANIFEST" "${KANI_ARGS[@]}" --harness "$harness"; then
        exit_code=$?
        if [ "$exit_code" -eq 124 ]; then
            echo "TIMEOUT: harness $harness exceeded ${HARNESS_TIMEOUT}s limit" >&2
        else
            echo "FAIL: harness $harness exited with code $exit_code" >&2
        fi
        FAILED_HARNESSES+=("$harness")
    fi
done

if [ "${#FAILED_HARNESSES[@]}" -gt 0 ]; then
    echo ""
    echo "=== FAILED HARNESSES (${#FAILED_HARNESSES[@]}) ==="
    printf '  %s\n' "${FAILED_HARNESSES[@]}"
    exit 1
fi
