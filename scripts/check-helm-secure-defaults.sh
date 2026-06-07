#!/usr/bin/env bash
set -euo pipefail

chart_dir="${1:-helm/vellaveto}"
release_name="${HELM_RELEASE_NAME:-vellaveto}"
tmpdir="$(mktemp -d)"

cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

render() {
  local name="$1"
  shift
  helm template "$release_name" "$chart_dir" "$@" > "$tmpdir/$name.yaml"
}

require_present() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  if ! grep -Fq -- "$pattern" "$file"; then
    echo "::error::$message"
    exit 1
  fi
}

require_absent() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  if grep -Fq -- "$pattern" "$file"; then
    echo "::error::$message"
    exit 1
  fi
}

render default
default_render="$tmpdir/default.yaml"
require_absent "$default_render" "- {}" "Default NetworkPolicy must not allow ingress from all namespaces"
require_present "$default_render" "podSelector: {}" "Default NetworkPolicy must limit ingress to same-namespace pods"
require_absent "$default_render" "--allow-anonymous" "Chart must not enable anonymous API access by default"

render allow-all --set networkPolicy.allowAllNamespaces=true
require_present "$tmpdir/allow-all.yaml" "- {}" "allowAllNamespaces=true must explicitly render all-namespace ingress"

render namespace --set 'networkPolicy.allowedNamespaces[0]=ingress-nginx'
namespace_render="$tmpdir/namespace.yaml"
require_present "$namespace_render" 'kubernetes.io/metadata.name: "ingress-nginx"' "allowedNamespaces must render namespace selector labels"
require_absent "$namespace_render" "- {}" "allowedNamespaces must not also render all-namespace ingress"

render stateful --set statefulSet.enabled=true
stateful_render="$tmpdir/stateful.yaml"
require_present "$stateful_render" "kind: StatefulSet" "statefulSet.enabled=true must render a StatefulSet"
require_absent "$stateful_render" "--allow-anonymous" "StatefulSet render must not enable anonymous API access"

echo "Helm secure defaults OK"
