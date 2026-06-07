#!/usr/bin/env bash
set -euo pipefail

dockerfile="${1:-Dockerfile}"

if [ ! -f "$dockerfile" ]; then
  echo "Dockerfile not found: $dockerfile" >&2
  exit 1
fi

if grep -Fq -- "--allow-anonymous" "$dockerfile"; then
  echo "::error::Docker image must not enable anonymous API access by default"
  exit 1
fi

if ! grep -Fq "VELLAVETO_API_KEY" "$dockerfile"; then
  echo "::error::Dockerfile must document authenticated startup with VELLAVETO_API_KEY"
  exit 1
fi

if ! grep -Fq 'CMD ["serve", "--config", "/etc/vellaveto/config.toml", "--bind", "0.0.0.0"]' "$dockerfile"; then
  echo "::error::Docker default CMD changed; review authentication and bind defaults"
  exit 1
fi

echo "Docker secure defaults OK"
