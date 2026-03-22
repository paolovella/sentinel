# Incident Statement: GitHub Account Suspension — March 18, 2026

## Summary

On March 18, 2026, the GitHub account `vellaveto` was suspended following a burst of approximately 18 GitHub Actions workflow runs triggered within a 10-minute window during the v6.0.9 release of the Vellaveto project. The burst was caused by a release process bug — not by automated abuse, bot activity, or interaction with third-party services for non-CI/CD purposes.

## Timeline of Events (UTC)

**22:42** — Release commit `1521bc65` pushed to `main` with tag `v6.0.9`. This triggered 6 independent publish workflows (npm, PyPI, Maven Central, Docker, Provenance, Release binaries). All workflows are legitimate CI/CD publishing to package registries.

**~22:44** — Discovered that 5 of 33 version files had not been updated in the release commit:
- `packages/create-vellaveto/package.json`
- `vscode-vellaveto/package.json`
- `site/package.json`
- `docs/openapi.yaml`
- `helm/vellaveto/Chart.yaml`

**22:51** — Pushed a fix commit `0638e221` and force-updated the `v6.0.9` tag to point to the corrected commit. This re-triggered all 6 publish workflows. The npm and Maven Central workflows failed with HTTP 403 because `@vellaveto-sdk/typescript@6.0.9` and `io.github.vellaveto:vellaveto-java-sdk:6.0.9` had already been published by the first run. PyPI also rejected the duplicate.

**~22:55** — Attempted to fix by deleting the remote tag and recreating it, which triggered a third wave of 6 workflows. These also failed on duplicate version errors.

**Total:** ~18 workflow runs in ~13 minutes, most of which attempted to publish to npm, PyPI, and Maven Central (third-party registries) and received 403/duplicate rejection errors.

## Root Cause

The release process relied on tag pushes (`push: tags: ["v*"]`) to trigger independent publish workflows. This design had three critical flaws:

1. **No pre-flight version validation.** There was no automated check that all 33 version-bearing files (Cargo.toml, package.json, pyproject.toml, pom.xml, Chart.yaml, openapi.yaml, tauri.conf.json) were aligned before tagging.

2. **No idempotent publishing.** The publish workflows did not check whether a version already existed on the registry before attempting to publish. A duplicate publish attempt crashed with a 403 error instead of succeeding gracefully.

3. **No orchestration.** Six independent workflows raced on each tag push. There was no single coordinator to sequence validation → build → publish → tag creation.

The combination of these flaws meant that a single human error (missing 5 version files) escalated into three tag push attempts, 18 workflow runs, and multiple failed publish attempts to external registries — a pattern that triggered GitHub's automated abuse detection.

## Actions Taken (Completed)

The following changes have been implemented to prevent recurrence:

### 1. Release orchestrator (`release.yml` — complete rewrite)
- Trigger changed from `push: tags: ["v*"]` to `workflow_dispatch` with a `version` input
- Single orchestrator controls the entire pipeline: preflight → build → publish → tag
- The git tag is created **only after** all publishing succeeds (tag is output, not input)
- Dry-run mode available for pre-release validation

### 2. Pre-flight version validator (`scripts/check-versions.sh`)
- Scans all 33 version-bearing files before any release
- Fails if any file does not match the expected version
- Runs in CI preflight job and locally

### 3. Idempotent publishing
- npm: checks `npm view <package>@<version>` before publishing; skips if exists
- Maven Central: checks Maven Central repository URL before deploying; skips if exists
- PyPI: checks PyPI JSON API before uploading; skips if exists
- Behavior: version already exists → SUCCESS, not failure

### 4. Tag push triggers removed
- All 6 publish workflows (`publish-npm.yml`, `publish-pypi.yml`, `publish-maven.yml`, `docker-publish.yml`, `provenance-sbom.yml`, `publish-go.yml`) had their `push: tags: ["v*"]` triggers removed
- Only the orchestrator creates tags, and only after all publishing succeeds

### 5. Release automation script (`scripts/release.sh`)
- Bumps all 33 version files in one command
- Runs validation, compiles, and commits
- Optional `--trigger` flag pushes and starts the release workflow

### 6. Documented policy
- CONTRIBUTING.md updated with new release checklist
- Rule: never force-push tags, never re-tag — bump to next patch version instead

## Nature of the Project

Vellaveto is an open-source MCP (Model Context Protocol) agent interaction firewall. It is a legitimate software security project with:

- 19 Rust crates, 4 SDK languages (Python, TypeScript, Go, Java)
- 11,000+ automated tests across the workspace
- 646 formally verified proof items (Verus deductive verification)
- 240 bounded model checking harnesses (Kani/CBMC)
- 14 TLA+ model-checked specifications (67+ million states explored)
- 254 documented security audit rounds
- VS Code extension, Helm chart, Terraform provider, admin console
- Documented in CHANGELOG.md, ROADMAP.md, and extensive technical documentation

All GitHub Actions usage was exclusively for CI/CD: compiling, testing, building release binaries, and publishing to package registries (npm, PyPI, Maven Central, crates.io, GHCR). There was no interaction with third-party websites for incentivized activities, general computing, or any purpose outside of standard software release automation.

## Responsibility

The incident was caused by a combination of:
1. An incomplete manual release process (no automated version scanning)
2. A poor recovery strategy (force-pushing and re-creating tags instead of bumping the version)
3. The absence of rate limiting or orchestration in the CI/CD pipeline

The burst of Actions runs was not intentional abuse. It was a human operator making repeated attempts to fix a botched release, each attempt triggering a new wave of workflows. The architectural fixes described above eliminate the possibility of this pattern recurring.

---

*Document prepared: March 19, 2026*
*Project: Vellaveto — https://github.com/paolovella/vellaveto*
