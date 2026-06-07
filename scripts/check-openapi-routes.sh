#!/usr/bin/env bash
set -euo pipefail

routes_file="${1:-vellaveto-server/src/routes/main.rs}"
spec_file="${2:-docs/openapi.yaml}"
tmp_dir="$(mktemp -d)"

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

awk '
  /let authenticated = Router::new\(\)/ { in_routes=1 }
  in_routes && /\.route\(/ { looking=1 }
  looking {
    if (match($0, /"\/[^"]+"/)) {
      path=substr($0, RSTART + 1, RLENGTH - 2)
      if (path ~ /^\/api\// || path ~ /^\/iam\// || path == "/metrics" || path == "/health") {
        print path
      }
      looking=0
    }
  }
' "$routes_file" | sort -u > "$tmp_dir/routes.txt"

awk '/^  \// { line=$1; sub(/:$/, "", line); print line }' "$spec_file" \
  | sort -u > "$tmp_dir/openapi-paths.txt"

comm -23 "$tmp_dir/routes.txt" "$tmp_dir/openapi-paths.txt" > "$tmp_dir/missing.txt"

if [ -s "$tmp_dir/missing.txt" ]; then
  echo "::error::OpenAPI spec is missing implemented API routes:"
  cat "$tmp_dir/missing.txt"
  exit 1
fi

echo "OpenAPI route coverage OK"
