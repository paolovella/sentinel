#!/usr/bin/env bash
# release.sh — Bump all versions, validate, and optionally trigger release workflow
#
# Usage:
#   scripts/release.sh 6.0.10                    # bump + validate + commit
#   scripts/release.sh 6.0.10 --trigger           # bump + validate + commit + push + trigger workflow
#   scripts/release.sh 6.0.10 --dry-run            # bump + validate (no commit)
#
# This script:
#   1. Bumps ALL 33 version files to the given version
#   2. Runs cargo check to regenerate Cargo.lock
#   3. Runs check-versions.sh to validate alignment
#   4. Optionally commits, pushes, and triggers the release workflow

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [ $# -lt 1 ]; then
  echo "Usage: scripts/release.sh <version> [--trigger] [--dry-run]"
  echo ""
  echo "Examples:"
  echo "  scripts/release.sh 6.0.10              # bump + commit"
  echo "  scripts/release.sh 6.0.10 --trigger    # bump + commit + push + trigger workflow"
  echo "  scripts/release.sh 6.0.10 --dry-run    # bump only, no commit"
  exit 1
fi

VERSION="$1"
TRIGGER=false
DRY_RUN=false

shift
while [ $# -gt 0 ]; do
  case "$1" in
    --trigger) TRIGGER=true ;;
    --dry-run) DRY_RUN=true ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
  shift
done

# Validate version format
if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "ERROR: Version must be semver (e.g., 6.0.10), got: $VERSION"
  exit 1
fi

# Check for clean working tree (unless dry-run)
if [ "$DRY_RUN" = false ]; then
  if ! git diff --quiet HEAD 2>/dev/null; then
    echo "ERROR: Working tree has uncommitted changes. Commit or stash first."
    exit 1
  fi
fi

# Check tag doesn't already exist
if git rev-parse "v$VERSION" >/dev/null 2>&1; then
  echo "ERROR: Tag v$VERSION already exists locally. Use a different version."
  exit 1
fi

echo "=== Bumping all versions to $VERSION ==="
echo ""

# --- Rust crates (Cargo.toml) ---
# Get current version from root Cargo.toml
OLD_VERSION="$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')"
echo "Current version: $OLD_VERSION"
echo "Target version:  $VERSION"
echo ""

if [ "$OLD_VERSION" = "$VERSION" ]; then
  echo "Version is already $VERSION — skipping bump, running validation only."
else
  # Bump workspace version in root Cargo.toml
  sed -i "s/^version = \"$OLD_VERSION\"/version = \"$VERSION\"/" Cargo.toml

  # Bump all crate Cargo.toml files
  for crate_dir in \
    vellaveto-types vellaveto-canonical vellaveto-canary vellaveto-config \
    vellaveto-discovery vellaveto-engine vellaveto-audit vellaveto-approval \
    vellaveto-mcp vellaveto-mcp-shield vellaveto-tls vellaveto-cluster \
    vellaveto-http-proxy vellaveto-http-proxy-shield vellaveto-server \
    vellaveto-proxy vellaveto-shield vellaveto-operator vellaveto-integration; do
    if [ -f "$crate_dir/Cargo.toml" ]; then
      # Replace the crate version
      sed -i "0,/^version = \"$OLD_VERSION\"/{s/^version = \"$OLD_VERSION\"/version = \"$VERSION\"/}" "$crate_dir/Cargo.toml"
      # Replace internal dependency versions
      sed -i "s/version = \"$OLD_VERSION\", path/version = \"$VERSION\", path/g" "$crate_dir/Cargo.toml"
    fi
  done

  # Bump Tauri desktop crate
  if [ -f "packages/vellaveto-desktop/src-tauri/Cargo.toml" ]; then
    sed -i "0,/^version = \"$OLD_VERSION\"/{s/^version = \"$OLD_VERSION\"/version = \"$VERSION\"/}" \
      "packages/vellaveto-desktop/src-tauri/Cargo.toml"
  fi

  # --- JavaScript/TypeScript packages ---
  for pkg in \
    sdk/typescript/package.json \
    packages/create-vellaveto/package.json \
    admin-console/package.json \
    packages/vellaveto-desktop/package.json \
    site/package.json \
    vscode-vellaveto/package.json; do
    if [ -f "$pkg" ]; then
      sed -i "s/\"version\": \"$OLD_VERSION\"/\"version\": \"$VERSION\"/" "$pkg"
    fi
  done

  # Tauri config
  if [ -f "packages/vellaveto-desktop/src-tauri/tauri.conf.json" ]; then
    sed -i "s/\"version\": \"$OLD_VERSION\"/\"version\": \"$VERSION\"/" \
      "packages/vellaveto-desktop/src-tauri/tauri.conf.json"
  fi

  # --- Python SDK ---
  if [ -f "sdk/python/pyproject.toml" ]; then
    sed -i "s/^version = \"$OLD_VERSION\"/version = \"$VERSION\"/" sdk/python/pyproject.toml
  fi

  # --- Java SDK ---
  if [ -f "sdk/java/pom.xml" ]; then
    # Replace only the first <version> (project version, not dependencies)
    sed -i "0,/<version>$OLD_VERSION<\/version>/{s/<version>$OLD_VERSION<\/version>/<version>$VERSION<\/version>/}" \
      sdk/java/pom.xml
  fi

  # --- Helm chart ---
  if [ -f "helm/vellaveto/Chart.yaml" ]; then
    sed -i "s/^version: $OLD_VERSION/version: $VERSION/" helm/vellaveto/Chart.yaml
    sed -i "s/^appVersion: \"$OLD_VERSION\"/appVersion: \"$VERSION\"/" helm/vellaveto/Chart.yaml
  fi

  # --- OpenAPI spec ---
  if [ -f "docs/openapi.yaml" ]; then
    sed -i "s/  version: $OLD_VERSION/  version: $VERSION/" docs/openapi.yaml
  fi

  echo "All version files bumped."
  echo ""
fi

# --- Regenerate Cargo.lock ---
echo "=== Regenerating Cargo.lock ==="
cargo check --workspace 2>&1 | tail -3
echo ""

# --- Validate ---
echo "=== Running version validation ==="
scripts/check-versions.sh "$VERSION"
echo ""

# --- CHANGELOG check ---
if ! grep -q "^\## \[$VERSION\]" CHANGELOG.md; then
  echo ""
  echo "WARNING: CHANGELOG.md does not have a [$VERSION] section yet."
  echo "Add it before releasing. Example:"
  echo ""
  echo "  ## [$VERSION] - $(date +%Y-%m-%d)"
  echo ""
fi

if [ "$DRY_RUN" = true ]; then
  echo ""
  echo "=== DRY RUN — no commit made ==="
  echo "Review changes with: git diff"
  exit 0
fi

# --- Commit ---
echo "=== Committing version bump ==="
git add -A
git commit -m "chore: release v$VERSION — version alignment across all packages"
echo ""

echo "=== Release commit created ==="
echo ""

if [ "$TRIGGER" = true ]; then
  echo "=== Pushing to origin ==="
  git push origin main
  echo ""
  echo "=== Triggering release workflow ==="
  gh workflow run release.yml -f version="$VERSION" -f dry_run=false
  echo ""
  echo "Monitor at: gh run list --workflow=release.yml"
else
  echo "Next steps:"
  echo "  1. Review:  git log --oneline -1 && git diff HEAD~1"
  echo "  2. Push:    git push origin main"
  echo "  3. Release: gh workflow run release.yml -f version=$VERSION"
  echo "  4. Monitor: gh run list --workflow=release.yml"
fi
