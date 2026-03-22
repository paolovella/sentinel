# vellaveto-http-proxy

Streamable HTTP reverse proxy for the [Vellaveto](https://vellaveto.online) MCP security gateway.

## Overview

Inline policy enforcement across multiple transport protocols:

- **HTTP reverse proxy** — intercepts MCP tool calls over Streamable HTTP
- **WebSocket proxy** — bidirectional MCP message inspection
- **gRPC proxy** — protocol-aware tool call interception
- **Transport health** — automatic health checking with smart fallback
- **OAuth 2.1** — JWT/JWKS validation with DPoP binding

## Usage

```toml
[dependencies]
vellaveto-http-proxy = "6"
```

## License

BUSL-1.1 — see [LICENSE-BSL-1.1](../LICENSE-BSL-1.1) and [LICENSING.md](../LICENSING.md) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
