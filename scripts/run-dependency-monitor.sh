#!/usr/bin/env bash
# run-dependency-monitor.sh — composite dependency/telemetry scan for Batch 3
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR_INPUT="${1:-${WORKSPACE_ROOT}/target/security}"
mkdir -p "${OUTPUT_DIR_INPUT}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR_INPUT}" && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
AUDIT_JSON="${OUTPUT_DIR}/cargo-audit-${TIMESTAMP}.json"
DENY_JSON="${OUTPUT_DIR}/cargo-deny-${TIMESTAMP}.txt"
VET_TXT="${OUTPUT_DIR}/cargo-vet-${TIMESTAMP}.txt"
DUPLICATES_TXT="${OUTPUT_DIR}/cargo-duplicates-${TIMESTAMP}.txt"
METADATA_JSON="${OUTPUT_DIR}/cargo-metadata-${TIMESTAMP}.json"
CARGO_HOME_DIR="${OUTPUT_DIR}/cargo-home"
VET_CACHE_DIR="${OUTPUT_DIR}/cargo-vet-cache"
AUDIT_FETCH_ARGS=()
DENY_FETCH_ARGS=()

require_cargo_subcommand() {
  local subcommand="$1"
  if ! cargo "${subcommand}" --version >/dev/null 2>&1; then
    echo "Missing cargo subcommand: cargo ${subcommand}. Install it with: cargo install cargo-${subcommand} --locked" >&2
    exit 2
  fi
}

require_cargo_subcommand audit
require_cargo_subcommand deny
require_cargo_subcommand vet

mkdir -p "${CARGO_HOME_DIR}"
mkdir -p "${VET_CACHE_DIR}"
if [[ -d "${HOME}/.cargo" ]]; then
  cp -a "${HOME}/.cargo/registry" "${CARGO_HOME_DIR}/" 2>/dev/null || true
  cp -a "${HOME}/.cargo/advisory-db" "${CARGO_HOME_DIR}/" 2>/dev/null || true
  cp -a "${HOME}/.cargo/advisory-dbs" "${CARGO_HOME_DIR}/" 2>/dev/null || true
fi

if [[ "${DEPENDENCY_MONITOR_NO_FETCH:-}" == "1" ]]; then
  AUDIT_FETCH_ARGS=(--no-fetch --stale)
  DENY_FETCH_ARGS=(--disable-fetch)
  echo "Dependency monitor running without advisory DB fetches; using cached advisory data only."
fi

echo "Running dependency monitoring scan..."
echo "  Audit output:      ${AUDIT_JSON}"
echo "  Deny output:       ${DENY_JSON}"
echo "  Vet output:        ${VET_TXT}"
echo "  Duplicates output: ${DUPLICATES_TXT}"
echo "  Metadata:          ${METADATA_JSON}"

echo "1/5: cargo audit"
audit_status=0
if CARGO_HOME="${CARGO_HOME_DIR}" cargo audit "${AUDIT_FETCH_ARGS[@]}" --json >"${AUDIT_JSON}"; then
  echo "cargo audit: no advisories"
else
  audit_status=$?
  echo "cargo audit detected advisories (exit ${audit_status}). Review ${AUDIT_JSON}."
fi

echo "2/5: cargo deny --locked check -A duplicate advisories bans sources licenses"
deny_status=0
if CARGO_HOME="${CARGO_HOME_DIR}" cargo deny --locked check "${DENY_FETCH_ARGS[@]}" -A duplicate advisories bans sources licenses | tee "${DENY_JSON}"; then
  echo "cargo deny: clean"
else
  deny_status=$?
  echo "cargo deny reported issues (exit ${deny_status}). See ${DENY_JSON}."
fi

echo "3/5: cargo vet --locked"
vet_status=0
if cargo vet --locked --cache-dir "${VET_CACHE_DIR}" --output-file "${VET_TXT}"; then
  cat "${VET_TXT}"
  echo "cargo vet: baseline satisfied"
else
  vet_status=$?
  cat "${VET_TXT}" 2>/dev/null || true
  echo "cargo vet reported issues (exit ${vet_status}). See ${VET_TXT}."
fi

echo "4/5: duplicate dependency baseline"
duplicates_status=0
if bash "${WORKSPACE_ROOT}/scripts/check-cargo-duplicates.sh" | tee "${DUPLICATES_TXT}"; then
  echo "duplicate dependency baseline: clean"
else
  duplicates_status=$?
  echo "duplicate dependency baseline reported issues (exit ${duplicates_status}). See ${DUPLICATES_TXT}."
fi

metadata_status=0
echo "5/5: cargo metadata --locked"
if cargo metadata --locked --format-version 1 >"${METADATA_JSON}"; then
  echo "cargo metadata: complete"
else
  metadata_status=$?
  echo "cargo metadata failed (exit ${metadata_status}). Inspect ${CARGO_HOME_DIR} for cached registry data."
fi

echo "Optional CISA Known Exploited Vulnerabilities matching"
CISA_FILE="${CISA_KEV_JSON:-}"
OSINT_DIR="${OSINT_SECURITY_DIR:-}"

if [[ -n "${CISA_FILE}" && -f "${CISA_FILE}" ]]; then
  python3 <<PY
import json, os
metadata_path = '${METADATA_JSON}'
cisa_path = '${CISA_FILE}'
output_dir = '${OUTPUT_DIR}'
with open(metadata_path) as f:
    metadata = json.load(f)
packages = {pkg['name'].lower() for pkg in metadata.get('packages', [])}
with open(cisa_path) as f:
    data = json.load(f)
kev_entries = data.get('vulnerabilities') or data.get('known_exploited_vulnerabilities', [])
matches = []
for entry in kev_entries:
    cve = entry.get('cveID') or entry.get('cveId') or entry.get('cve')
    vendor = entry.get('vendorProject', '')
    product = entry.get('product', '')
    candidates = []
    for value in (vendor, product):
        if isinstance(value, (list, tuple)):
            candidates.extend(value)
        elif value:
            candidates.append(value)
    for candidate in candidates:
        normalized = candidate.lower()
        for dep in packages:
            if dep and dep in normalized and not any(m['dep'] == dep and m['cve'] == cve for m in matches):
                matches.append({'dep': dep, 'cve': cve, 'vendor': vendor, 'product': product, 'entry': candidate})
if matches:
    out_path = os.path.join(output_dir, 'cisa-kev-matches.json')
    with open(out_path, 'w') as out_file:
        json.dump(matches, out_file, indent=2)
    print('CISA KEV matches found:')
    for match in matches:
        print('  -', match['dep'], match['cve'], match['product'])
    print('  Details saved to', out_path)
else:
    print('No CISA KEV matches detected with current CISA file')
PY
else
  echo "  Skipped (set CISA_KEV_JSON to a local Known Exploited Vulnerabilities JSON file)"
fi

if [[ -n "${OSINT_DIR}" && -d "${OSINT_DIR}" ]]; then
  echo "OSINT directory provided: ${OSINT_DIR}"
  echo "  You can drop supply-chain intel notes here (e.g., vendor warnings, malicious packages) and this script will remind you to review them."
  echo "  Latest files:"
  find "${OSINT_DIR}" -mindepth 1 -maxdepth 1 -printf '  %f\n' | sort | head -n 5 || true
else
  echo "Set OSINT_SECURITY_DIR to an OSINT note directory to link in supply-chain reporting."
fi

echo "Dependency monitoring summary written under ${OUTPUT_DIR}."
final_status=0
if [[ ${audit_status} -ne 0 || ${deny_status} -ne 0 || ${vet_status} -ne 0 || ${duplicates_status} -ne 0 || ${metadata_status} -ne 0 ]]; then
  final_status=1
fi
exit ${final_status}
