# vellaveto-discovery

MCP tool topology crawling and verification for [Vellaveto](https://vellaveto.online).

## Overview

Builds a live graph of MCP servers, tools, and data-flow edges:

- **Topology graph** — petgraph DiGraph mapping servers to tools to resources
- **TopologyGuard** — pre-policy filter, fail-closed on unknown tools with Levenshtein suggestions
- **MCP server crawler** — automatic discovery and re-crawl scheduling
- **Data-flow inference** — detects tool-to-resource data dependencies
- **Topology diff** — tracks added/removed/changed tools across crawl cycles
- **Serialization** — JSON and bincode for persistence and transport

## Usage

```toml
[dependencies]
vellaveto-discovery = "6"
```

## License

MPL-2.0 — see [LICENSE-MPL-2.0](../LICENSE-MPL-2.0) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
