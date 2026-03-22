# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 6.x     | Yes       |
| 5.x     | Security fixes only |
| < 5.0   | No        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities via one of the following channels:

- **Email:** [security@vellaveto.online](mailto:security@vellaveto.online) with subject line `[SECURITY] <brief description>`
- **GitHub Security Advisory:** [Report a vulnerability](https://github.com/paolovella/vellaveto/security/advisories/new) (preferred)

### What to Include

- Description of the vulnerability
- Steps to reproduce or a proof of concept
- Affected version(s)
- Impact assessment (if known)

### Disclosure Timeline

1. **Acknowledgment:** within 3 business days of receipt
2. **Triage and severity assessment:** within 7 days
3. **Fix development and testing:** target 30 days for critical/high, 90 days for medium/low
4. **Coordinated disclosure:** we will coordinate with you on a disclosure date after a fix is available
5. **Advisory publication:** GitHub Security Advisory published at disclosure time

We follow [coordinated vulnerability disclosure](https://vuls.cert.org/confluence/display/Wiki/Vulnerability+Disclosure+Policy). We will not pursue legal action against researchers who act in good faith.

## Scope

The following are in scope:

- All code in the [vellaveto/vellaveto](https://github.com/paolovella/vellaveto) repository
- Published Docker images (`ghcr.io/paolovella/vellaveto`)
- Published SDKs (Python, TypeScript, Go)

The following are **out of scope:**

- Third-party MCP servers or tools behind Vellaveto
- Denial-of-service attacks against hosted instances
- Social engineering of maintainers

## Security Advisories

Published advisories will be listed at [github.com/paolovella/vellaveto/security/advisories](https://github.com/paolovella/vellaveto/security/advisories).

## Security Hardening

For production deployment hardening guidance, see [docs/SECURITY.md](docs/SECURITY.md).

## Security Documentation

| Document | Description |
|----------|-------------|
| [Security Guarantees](docs/SECURITY_GUARANTEES.md) | Normative contract: what Vellaveto guarantees, assumes, and excludes |
| [Assurance Case](docs/ASSURANCE_CASE.md) | Claim → Evidence map with reproduction commands |
| [Security Model](docs/SECURITY_MODEL.md) | Trust boundaries, data flows, threat coverage |
| [Security Defaults](docs/DEFAULTS.md) | Every security-relevant default value and rationale |
| [Formal Verification Scope](docs/FORMAL_SCOPE.md) | What is proven vs. tested vs. assumed |
| [Hardening Guide](docs/SECURITY.md) | Production deployment security configuration |
| [Audit History](docs/SECURITY_REVIEW.md) | Internal adversarial testing methodology and results |

## Patch Policy

- **Critical/High (CVSS ≥ 7.0):** Patch released within 30 days of confirmed triage.
- **Medium (CVSS 4.0–6.9):** Patch released within 90 days.
- **Low (CVSS < 4.0):** Addressed in next scheduled release.
- Security patches are backported to the latest minor release of each supported major version.
