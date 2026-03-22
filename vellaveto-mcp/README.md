# vellaveto-mcp

MCP protocol security layer for the [Vellaveto](https://vellaveto.online) gateway.

## Overview

Handles MCP-specific security concerns between agents and their tools:

- **DLP inspection** — 5-layer decode pipeline with Aho-Corasick pattern matching
- **Injection detection** — NFKC normalization, ROT13/base64/leetspeak decode, Policy Puppetry defense
- **Tool registry** — topology-aware tool verification with Levenshtein suggestions
- **Semantic guardrails** — output schema validation and behavioral constraints
- **Multimodal inspection** — image and document content scanning
- **A2A hardening** — Agent Card signature enforcement, DPoP token binding
- **MCP 2025-11-25 compliant** — Tasks, CIMD, XAA, M2M auth, step-up authorization

## Usage

```toml
[dependencies]
vellaveto-mcp = "6"
```

## License

BUSL-1.1 — see [LICENSE-BSL-1.1](../LICENSE-BSL-1.1) and [LICENSING.md](../LICENSING.md) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
