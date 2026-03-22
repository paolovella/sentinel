# vellaveto-proxy

MCP stdio proxy with built-in security presets for [Vellaveto](https://vellaveto.online).

## Overview

Zero-config MCP security — wraps any stdio-based MCP server with policy enforcement:

```bash
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
