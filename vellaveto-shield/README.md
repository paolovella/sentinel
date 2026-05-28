# vellaveto-shield

Consumer AI shield — privacy-preserving protection for end-user MCP interactions.

## Overview

Protects individual users when interacting with AI agents and MCP tools:

- **Bidirectional PII sanitization** — strips personal data before it reaches tools, restores on return
- **Encrypted local audit** — XChaCha20-Poly1305 encrypted audit trail with Merkle proofs
- **Session isolation** — per-session PII and context isolation
- **Credential vault** — encrypted credential storage with epoch-based rotation
- **Warrant canary** — cryptographic proof that no covert access has occurred

## Quick start

```bash
# Pre-built binary, SHA-256 verified (no Rust toolchain needed):
curl -fsSL https://raw.githubusercontent.com/paolovella/vellaveto/main/scripts/install.sh \
  | VELLAVETO_BINARY=vellaveto-shield sh

# From source:
cargo install vellaveto-shield

vellaveto-shield --passphrase-env SHIELD_KEY -- ./your-mcp-server
```

## License

MPL-2.0 (crate source). The compiled binary links `vellaveto-mcp` (BUSL-1.1), but the BSL Additional Use Grant permits Consumer Shield deployments on end-user devices without a commercial license.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
