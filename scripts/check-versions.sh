#!/usr/bin/env bash
# check-versions.sh — Pre-flight version alignment validator
#
# Scans ALL version-bearing files in the repository and verifies they match
# the expected version. Exits 0 if all match, 1 if any mismatch.
#
# Usage:
#   scripts/check-versions.sh 6.0.10
#   scripts/check-versions.sh              # reads version from root Cargo.toml

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Determine expected version
if [ $# -ge 1 ]; then
  EXPECTED="$1"
else
  EXPECTED="$(grep '^version = ' vellaveto-types/Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')"
fi

if [ -z "$EXPECTED" ]; then
  echo "ERROR: Could not determine expected version"
  exit 1
fi

echo "Checking all version files for: $EXPECTED"
echo "---"

ERRORS=0

check_toml() {
  local file="$1"
  local pattern="${2:-^version = }"
  if [ ! -f "$file" ]; then
    echo "MISS  $file (file not found)"
    ERRORS=$((ERRORS + 1))
    return
  fi
  local actual
  actual="$(grep "$pattern" "$file" | head -1 | sed 's/.*"\(.*\)".*/\1/')"
  if [ "$actual" = "$EXPECTED" ]; then
    echo "  OK  $file ($actual)"
  else
    echo "FAIL  $file (found: $actual, expected: $EXPECTED)"
    ERRORS=$((ERRORS + 1))
  fi
}

check_json() {
  local file="$1"
  local key="${2:-version}"
  if [ ! -f "$file" ]; then
    echo "MISS  $file (file not found)"
    ERRORS=$((ERRORS + 1))
    return
  fi
  local actual
  actual="$(grep "\"$key\"" "$file" | head -1 | sed 's/.*: *"\(.*\)".*/\1/')"
  if [ "$actual" = "$EXPECTED" ]; then
    echo "  OK  $file ($actual)"
  else
    echo "FAIL  $file (found: $actual, expected: $EXPECTED)"
    ERRORS=$((ERRORS + 1))
  fi
}

check_yaml() {
  local file="$1"
  local key="$2"
  if [ ! -f "$file" ]; then
    echo "MISS  $file (file not found)"
    ERRORS=$((ERRORS + 1))
    return
  fi
  local actual
  actual="$(grep "^${key}:" "$file" | head -1 | sed 's/.*: *"\{0,1\}\([^"]*\)"\{0,1\}/\1/')"
  if [ "$actual" = "$EXPECTED" ]; then
    echo "  OK  $file ($key: $actual)"
  else
    echo "FAIL  $file ($key: found '$actual', expected '$EXPECTED')"
    ERRORS=$((ERRORS + 1))
  fi
}

check_xml() {
  local file="$1"
  if [ ! -f "$file" ]; then
    echo "MISS  $file (file not found)"
    ERRORS=$((ERRORS + 1))
    return
  fi
  # Get the first <version> tag (project version, not dependency versions)
  local actual
  actual="$(grep '<version>' "$file" | head -1 | sed 's/.*<version>\(.*\)<\/version>.*/\1/')"
  if [ "$actual" = "$EXPECTED" ]; then
    echo "  OK  $file ($actual)"
  else
    echo "FAIL  $file (found: $actual, expected: $EXPECTED)"
    ERRORS=$((ERRORS + 1))
  fi
}

check_pyproject() {
  local file="$1"
  if [ ! -f "$file" ]; then
    echo "MISS  $file (file not found)"
    ERRORS=$((ERRORS + 1))
    return
  fi
  local actual
  actual="$(grep '^version = ' "$file" | head -1 | sed 's/version = "\(.*\)"/\1/')"
  if [ "$actual" = "$EXPECTED" ]; then
    echo "  OK  $file ($actual)"
  else
    echo "FAIL  $file (found: $actual, expected: $EXPECTED)"
    ERRORS=$((ERRORS + 1))
  fi
}

echo ""
echo "=== Rust crates (Cargo.toml) ==="
for crate_dir in \
  vellaveto-types vellaveto-canonical vellaveto-canary vellaveto-config \
  vellaveto-discovery vellaveto-engine vellaveto-audit vellaveto-approval \
  vellaveto-mcp vellaveto-mcp-shield vellaveto-tls vellaveto-cluster \
  vellaveto-http-proxy vellaveto-http-proxy-shield vellaveto-server \
  vellaveto-proxy vellaveto-shield vellaveto-operator vellaveto-integration; do
  check_toml "$crate_dir/Cargo.toml"
done

echo ""
echo "=== JavaScript/TypeScript packages (package.json) ==="
check_json "sdk/typescript/package.json"
check_json "packages/create-vellaveto/package.json"
check_json "admin-console/package.json"
check_json "packages/vellaveto-desktop/package.json"
check_json "site/package.json"
check_json "vscode-vellaveto/package.json"

echo ""
echo "=== Desktop app (Tauri) ==="
check_json "packages/vellaveto-desktop/src-tauri/tauri.conf.json"
check_toml "packages/vellaveto-desktop/src-tauri/Cargo.toml"

echo ""
echo "=== Python SDK ==="
check_pyproject "sdk/python/pyproject.toml"

echo ""
echo "=== Java SDK ==="
check_xml "sdk/java/pom.xml"

echo ""
echo "=== Helm chart ==="
check_yaml "helm/vellaveto/Chart.yaml" "version"
check_yaml "helm/vellaveto/Chart.yaml" "appVersion"

echo ""
echo "=== OpenAPI spec ==="
# OpenAPI version is indented
if [ -f "docs/openapi.yaml" ]; then
  actual="$(grep '  version:' docs/openapi.yaml | head -1 | sed 's/.*version: *//')"
  if [ "$actual" = "$EXPECTED" ]; then
    echo "  OK  docs/openapi.yaml ($actual)"
  else
    echo "FAIL  docs/openapi.yaml (found: $actual, expected: $EXPECTED)"
    ERRORS=$((ERRORS + 1))
  fi
fi

echo ""
echo "=== CHANGELOG ==="
if grep -q "^\## \[$EXPECTED\]" CHANGELOG.md; then
  echo "  OK  CHANGELOG.md (has [$EXPECTED] section)"
else
  echo "FAIL  CHANGELOG.md (missing [$EXPECTED] section)"
  ERRORS=$((ERRORS + 1))
fi

echo ""
echo "---"
if [ "$ERRORS" -eq 0 ]; then
  echo "ALL VERSION FILES MATCH: $EXPECTED"
  exit 0
else
  echo "FAILED: $ERRORS version file(s) do not match $EXPECTED"
  exit 1
fi
