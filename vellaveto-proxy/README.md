# vellaveto-proxy

MCP stdio proxy with built-in security presets for [Vellaveto](https://vellaveto.online).

## Overview

Zero-config MCP security — wraps any stdio-based MCP server with policy enforcement:

```bash
# Pre-built binary, SHA-256 verified (no Rust toolchain needed):
curl -fsSL https://raw.githubusercontent.com/paolovella/vellaveto/main/scripts/install.sh \
  | VELLAVETO_BINARY=vellaveto-proxy sh

# From source:
cargo install vellaveto-proxy

vellaveto-proxy --protect shield -- ./your-mcp-server
```

- **Stdio transport** — intercepts JSON-RPC messages between agent and MCP server
- **Built-in presets** — `shield`, `strict`, `permissive`, or custom TOML policies
- **Environment forwarding** — passes through PATH, NODE_PATH, PYTHONPATH, etc.
- **Fail-closed** — denies tool calls that don't match any policy

## License

MPL-2.0 — see [LICENSE-MPL-2.0](../LICENSE-MPL-2.0) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
