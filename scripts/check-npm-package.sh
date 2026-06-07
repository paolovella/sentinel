#!/usr/bin/env bash
set -euo pipefail

package_dir="${1:-.}"

if [ ! -d "$package_dir" ]; then
  echo "package directory not found: $package_dir" >&2
  exit 1
fi

if [ ! -f "$package_dir/package.json" ]; then
  echo "package.json not found in: $package_dir" >&2
  exit 1
fi

cache_dir="${NPM_CONFIG_CACHE:-}"
cleanup_cache=0
if [ -z "$cache_dir" ]; then
  cache_dir="$(mktemp -d)"
  cleanup_cache=1
fi

cleanup() {
  if [ "$cleanup_cache" -eq 1 ]; then
    rm -rf "$cache_dir"
  fi
}
trap cleanup EXIT

(
  cd "$package_dir"
  export NPM_CONFIG_CACHE="$cache_dir"
  pack_json="$(npm pack --dry-run --json --ignore-scripts)"
  PACK_JSON="$pack_json" node <<'NODE'
const fs = require("fs");
const path = require("path");

const packageJson = JSON.parse(fs.readFileSync("package.json", "utf8"));
const packEntries = JSON.parse(process.env.PACK_JSON || "[]");
const files = new Set((packEntries[0]?.files || []).map((entry) => entry.path));

function fail(message) {
  console.error(message);
  process.exit(1);
}

function checkPackagePath(field, value, options = {}) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${field} must be a non-empty string`);
  }
  const packagePath = value.replace(/\\/g, "/").replace(/^\.\//, "");
  if (path.isAbsolute(value) || packagePath.split("/").includes("..")) {
    fail(`${field} must stay inside the package: ${value}`);
  }
  if (!fs.existsSync(value)) {
    fail(`${field} points to a missing file: ${value}`);
  }
  if (!files.has(packagePath)) {
    fail(`${field} is missing from npm package contents: ${value}`);
  }
  if (options.shebang) {
    const firstLine = fs.readFileSync(value, "utf8").split(/\r?\n/, 1)[0];
    if (!firstLine.startsWith("#!")) {
      fail(`${field} must start with a shebang: ${value}`);
    }
  }
}

if (packageJson.main) {
  checkPackagePath("main", packageJson.main);
}

if (packageJson.types) {
  checkPackagePath("types", packageJson.types);
}

if (typeof packageJson.bin === "string") {
  checkPackagePath("bin", packageJson.bin, { shebang: true });
} else if (packageJson.bin && typeof packageJson.bin === "object") {
  for (const [name, target] of Object.entries(packageJson.bin)) {
    checkPackagePath(`bin.${name}`, target, { shebang: true });
  }
}

console.log(`npm package contract OK: ${packageJson.name}`);
NODE
)
