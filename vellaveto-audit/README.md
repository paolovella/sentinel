# vellaveto-audit

Tamper-evident audit logging for the [Vellaveto](https://vellaveto.online) MCP security gateway.

## Overview

- **Hash-chained entries** — SHA-256 linked list with Merkle proofs
- **Ed25519 + ML-DSA-65 checkpoints** — cryptographic signing with post-quantum hybrid option
- **Export formats** — CEF, JSONL, syslog, OCSF, webhook
- **PostgreSQL dual-write** — file + database for high availability
- **Compliance registries** — EU AI Act, SOC 2, CoSAI, OWASP MCP Top 10, ISO 42001, DORA, NIS2, and more
- **Evidence packs** — bundled audit trails for compliance reporting
- **ZK proofs** — Pedersen commitments and Groth16 for privacy-preserving audit

## Usage

```toml
[dependencies]
vellaveto-audit = "6"
```

## License

MPL-2.0 — see [LICENSE-MPL-2.0](../LICENSE-MPL-2.0) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
