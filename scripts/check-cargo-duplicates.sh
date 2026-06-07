#!/usr/bin/env bash
set -euo pipefail

metadata_file="$(mktemp)"

cleanup() {
  rm -f "$metadata_file"
}
trap cleanup EXIT

cargo metadata --locked --format-version=1 > "$metadata_file"

python3 - "$metadata_file" <<'PY'
import json
import sys
from collections import defaultdict

BASELINE = {
    "block-buffer": ["0.10.4", "0.12.0"],
    "chacha20": ["0.10.0", "0.9.1"],
    "const-oid": ["0.10.2", "0.9.6"],
    "cpufeatures": ["0.2.17", "0.3.0"],
    "crypto-common": ["0.1.7", "0.2.1"],
    "digest": ["0.10.7", "0.11.3"],
    "foldhash": ["0.1.5", "0.2.0"],
    "getrandom": ["0.2.17", "0.3.4", "0.4.2"],
    "hashbrown": ["0.14.5", "0.15.5", "0.16.1", "0.17.1"],
    "itertools": ["0.13.0", "0.14.0"],
    "password-hash": ["0.5.0", "0.6.1"],
    "r-efi": ["5.3.0", "6.0.0"],
    "rand": ["0.10.1", "0.9.4"],
    "rand_core": ["0.10.1", "0.6.4", "0.9.5"],
    "reqwest": ["0.12.28", "0.13.4"],
    "sha2": ["0.10.9", "0.11.0"],
    "untrusted": ["0.7.1", "0.9.0"],
    "windows-sys": ["0.52.0", "0.59.0", "0.60.2", "0.61.2"],
    "windows-targets": ["0.52.6", "0.53.5"],
    "windows_aarch64_gnullvm": ["0.52.6", "0.53.1"],
    "windows_aarch64_msvc": ["0.52.6", "0.53.1"],
    "windows_i686_gnu": ["0.52.6", "0.53.1"],
    "windows_i686_gnullvm": ["0.52.6", "0.53.1"],
    "windows_i686_msvc": ["0.52.6", "0.53.1"],
    "windows_x86_64_gnu": ["0.52.6", "0.53.1"],
    "windows_x86_64_gnullvm": ["0.52.6", "0.53.1"],
    "windows_x86_64_msvc": ["0.52.6", "0.53.1"],
    "wit-bindgen": ["0.51.0", "0.57.1"],
}

with open(sys.argv[1], encoding="utf-8") as f:
    metadata = json.load(f)

versions_by_name = defaultdict(set)
for package in metadata["packages"]:
    source = package.get("source")
    if source is None or not source.startswith("registry+"):
        continue
    versions_by_name[package["name"]].add(package["version"])

duplicates = {
    name: sorted(versions)
    for name, versions in versions_by_name.items()
    if len(versions) > 1
}

errors = []
for name, versions in sorted(duplicates.items()):
    allowed = BASELINE.get(name)
    if allowed is None:
        errors.append(f"new duplicate crate '{name}' has versions: {', '.join(versions)}")
        continue
    new_versions = [version for version in versions if version not in allowed]
    if new_versions:
        errors.append(
            f"duplicate crate '{name}' added version(s): {', '.join(new_versions)} "
            f"(current: {', '.join(versions)})"
        )

if errors:
    for error in errors:
        print(f"::error::{error}")
    print("")
    print("Current duplicate baseline:")
    for name, versions in sorted(duplicates.items()):
        print(f"  {name}: {', '.join(versions)}")
    sys.exit(1)

print(f"Cargo duplicate baseline OK ({len(duplicates)} duplicate crate names)")
PY
