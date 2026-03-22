# Contributing to Vellaveto

Thank you for your interest in contributing to Vellaveto.

## Contributor License Agreement (CLA)

All contributors must sign the [Individual Contributor License Agreement](CLA.md) before their first contribution can be merged. This is a one-time process.

**Why a CLA?** Vellaveto uses a three-tier license model (MPL-2.0 / Apache-2.0 / BUSL-1.1). The CLA grants the maintainer the right to distribute your contributions under all license tiers, enabling the project's sustainability model.

**How to sign:**
1. **Automatic:** When you open your first pull request, the CLA Assistant bot will prompt you to sign electronically.
2. **Manual:** Email **hello@vellaveto.online** with subject "CLA Signature — Vellaveto" containing your full name, GitHub username, and the statement: "I have read and agree to the Vellaveto Individual Contributor License Agreement."

## License

Vellaveto uses a three-tier license model (MPL-2.0 / Apache-2.0 / BUSL-1.1).
See [LICENSING.md](LICENSING.md) for details. By submitting a contribution,
you agree to the terms in [LICENSING.md](LICENSING.md) and [CLA.md](CLA.md).

## Where to Start

New to the project? Here are some ways to get involved:

- **Good first issues** — Look for the [`good first issue`](https://github.com/paolovella/vellaveto/labels/good%20first%20issue) label. These are self-contained tasks that don't require deep knowledge of the codebase.
- **Documentation** — Improve examples, fix typos, clarify explanations. Every docs PR is welcome.
- **SDK examples** — Add usage examples for Python, TypeScript, Go, or Java SDKs with popular frameworks.
- **Policy presets** — Create new policy preset templates for specific use cases (see `examples/presets/`).
- **Security research** — Run adversarial tests against the engine and report findings. See [SECURITY.md](SECURITY.md) for responsible disclosure.
- **Formal verification** — Extend TLA+, Lean 4, or Coq proofs for additional properties (see `formal/`).

If you're unsure where to start, open a [Discussion](https://github.com/paolovella/vellaveto/discussions) and ask.

## Getting Started

```bash
git clone https://github.com/paolovella/vellaveto.git
cd vellaveto
cargo check --workspace
cargo test --workspace
cargo clippy --workspace
```

All three must pass before submitting changes.

## Development Rules

1. **No `unwrap()` or `expect()` in library code** — use `?` and `ok_or_else()`
2. **Fail-closed** — errors produce `Deny`, not `Allow`
3. **Every change gets tests** — unit tests at minimum, integration tests for new features
4. **Zero clippy warnings** — `cargo clippy --workspace` must be clean
5. **No new dependencies without justification** — every dep is attack surface

## Commit Format

```
<type>(<scope>): <subject>

<body>
```

**Types:** `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`
**Scopes:** `types`, `engine`, `audit`, `config`, `mcp`, `server`, `proxy`, `integration`

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes with tests
4. Ensure all checks pass:
   ```bash
   cargo test --workspace
   cargo clippy --workspace
   cargo fmt --check
   ```
5. Submit a pull request with a clear description

## Release Checklist

For maintainers cutting a new release:

1. **Update CHANGELOG** — Add `[X.Y.Z] - YYYY-MM-DD` section
2. **Run release script** — `scripts/release.sh X.Y.Z` (bumps all 33 version files, validates, commits)
3. **Review** — `git log --oneline -1 && git diff HEAD~1`
4. **Push** — `git push origin main`
5. **Trigger** — `gh workflow run release.yml -f version=X.Y.Z`
   - Optional dry run first: `gh workflow run release.yml -f version=X.Y.Z -f dry_run=true`
6. **Monitor** — `gh run list --workflow=release.yml`

The release workflow handles everything: preflight validation, 4-platform builds,
publishing to npm/PyPI/Maven Central/Docker, provenance/SBOM, and only creates
the git tag + GitHub Release after all publishing succeeds.

**Rules:**
- Never `git tag` manually — tags are created by the release workflow
- Never force-push tags — if a release is broken, bump to the next patch version
- Never re-run a failed publish by deleting/recreating tags — use `workflow_dispatch`

Shortcut: `scripts/release.sh X.Y.Z --trigger` does steps 2-5 in one command.

## Code Review Standards

All pull requests must pass the following before merge:

### CI Gates (Automated)
- `cargo fmt --all -- --check` (formatting)
- `cargo clippy --workspace --all-targets --locked -- -D warnings` (linting)
- `cargo test --workspace --no-fail-fast --locked` (9,900+ tests)
- unwrap/expect/panic scanner (no panics in library code)
- SPDX license header check (all `.rs` files)
- Feature matrix (5 feature combinations)
- Coq formal proofs (zero `Admitted`)

### Reviewer Checklist
- [ ] Changes match the stated purpose (no scope creep)
- [ ] New code has tests (unit at minimum, integration for features)
- [ ] Error paths produce Deny, not Allow (fail-closed)
- [ ] No secrets in code, logs, or error messages
- [ ] Input validation on all external data (bounds, control chars, format)
- [ ] Transport parity: if HTTP has the check, WebSocket/gRPC/stdio must too
- [ ] SDK parity: changes to server format reflected in all 4 SDKs

### Acceptance Criteria
- All CI jobs green
- At least 1 approval from a maintainer or trusted reviewer
- No unresolved review comments

## Security

If you discover a security vulnerability, please report it privately.
See [SECURITY.md](SECURITY.md) for details.
