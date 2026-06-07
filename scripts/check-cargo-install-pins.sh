#!/usr/bin/env bash
set -euo pipefail

workflow_dir="${1:-.github/workflows}"

if [ ! -d "$workflow_dir" ]; then
  echo "workflow directory not found: $workflow_dir" >&2
  exit 1
fi

python3 - "$workflow_dir" <<'PY'
import pathlib
import sys

workflow_dir = pathlib.Path(sys.argv[1])
errors = []

for path in sorted(workflow_dir.glob("*.yml")):
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if "cargo install" not in stripped or stripped.startswith("#") or stripped.startswith("- name:"):
            continue
        if "--version" in stripped or "--git" in stripped or "--path" in stripped:
            continue
        errors.append(f"{path}:{line_number}: cargo install must pin --version, --git, or --path: {stripped}")

if errors:
    for error in errors:
        print(f"::error::{error}")
    sys.exit(1)

print("Cargo install pins OK")
PY
