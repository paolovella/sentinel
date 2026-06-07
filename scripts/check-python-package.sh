#!/usr/bin/env bash
set -euo pipefail

package_dir="${1:-sdk/python}"
tmpdir="$(mktemp -d)"

cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

if [ ! -f "$package_dir/pyproject.toml" ]; then
  echo "pyproject.toml not found in: $package_dir" >&2
  exit 1
fi

python3 -m build --no-isolation --outdir "$tmpdir/dist" "$package_dir"

python3 - "$package_dir" "$tmpdir/dist" <<'PY'
import email.parser
import pathlib
import re
import sys
import tarfile
import zipfile

package_dir = pathlib.Path(sys.argv[1])
dist_dir = pathlib.Path(sys.argv[2])


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(1)


pyproject = (package_dir / "pyproject.toml").read_text(encoding="utf-8")
name_match = re.search(r'^name = "([^"]+)"$', pyproject, re.MULTILINE)
version_match = re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE)
if not name_match or not version_match:
    fail("pyproject.toml must define project name and version")

expected_name = name_match.group(1)
expected_version = version_match.group(1)
wheels = sorted(dist_dir.glob("*.whl"))
sdists = sorted(dist_dir.glob("*.tar.gz"))
if len(wheels) != 1:
    fail(f"expected exactly one wheel, found {len(wheels)}")
if len(sdists) != 1:
    fail(f"expected exactly one sdist, found {len(sdists)}")

with zipfile.ZipFile(wheels[0]) as wheel:
    wheel_names = set(wheel.namelist())
    for name in wheel_names:
        if name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts:
            fail(f"wheel contains unsafe path: {name}")
        if "__pycache__" in pathlib.PurePosixPath(name).parts or name.endswith(".pyc"):
            fail(f"wheel contains Python cache artifact: {name}")
    for required in ("vellaveto/__init__.py", "vellaveto/py.typed"):
        if required not in wheel_names:
            fail(f"wheel missing required file: {required}")
    metadata_names = [name for name in wheel_names if name.endswith(".dist-info/METADATA")]
    if len(metadata_names) != 1:
        fail(f"expected exactly one wheel METADATA file, found {len(metadata_names)}")
    metadata = email.parser.Parser().parsestr(wheel.read(metadata_names[0]).decode("utf-8"))
    if metadata.get("Name") != expected_name:
        fail(f"wheel metadata name mismatch: {metadata.get('Name')} != {expected_name}")
    if metadata.get("Version") != expected_version:
        fail(f"wheel metadata version mismatch: {metadata.get('Version')} != {expected_version}")

with tarfile.open(sdists[0]) as sdist:
    sdist_names = set(sdist.getnames())
    top_level = {name.split("/", 1)[0] for name in sdist_names if "/" in name}
    if len(top_level) != 1:
        fail("sdist must contain exactly one top-level directory")
    prefix = next(iter(top_level))
    for member in sdist.getmembers():
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            fail(f"sdist contains unsafe path: {member.name}")
        if "__pycache__" in path.parts or member.name.endswith(".pyc"):
            fail(f"sdist contains Python cache artifact: {member.name}")
    for required in (
        "pyproject.toml",
        "README.md",
        "LICENSE",
        "vellaveto/__init__.py",
        "vellaveto/py.typed",
    ):
        member_name = f"{prefix}/{required}"
        if member_name not in sdist_names:
            fail(f"sdist missing required file: {required}")

print(f"Python package contract OK: {expected_name} {expected_version}")
PY
