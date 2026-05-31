# vellaveto-http-proxy

Streamable HTTP reverse proxy for the [Vellaveto](https://vellaveto.online) MCP security gateway.

## Overview

Inline policy enforcement across multiple transport protocols:

- **HTTP reverse proxy** - intercepts MCP tool calls over Streamable HTTP
- **WebSocket proxy** - bidirectional MCP message inspection
- **gRPC proxy** - protocol-aware tool call interception
- **Transport health** - automatic health checking with smart fallback
- **OAuth 2.1** - JWT/JWKS validation with DPoP binding
- **MCP 2026 guardrails** - version-gated routing headers, `requestState`
  sealing, and unsolicited server-request blocking

## Usage

```toml
[dependencies]
vellaveto-http-proxy = "6"
```

## MCP Protocol Guardrails

The proxy accepts MCP protocol versions through a configurable floor. By
default, inbound HTTP requests must include `MCP-Protocol-Version`, and the
default floor is `2025-11-25`. The proxy advertises and forwards
`2026-07-28` to upstream servers.

```toml
[streamable_http]
protocol_version_floor = "2025-11-25"
require_protocol_version_header = true
resumability_enabled = true
allowed_mcp_param_headers = ["Region", "TenantId"]
```

For `2026-07-28` requests, `Mcp-Method` and `Mcp-Name` routing headers must
agree with the JSON-RPC body. Custom `Mcp-Param-*` headers are only forwarded
when both policy allowlists the suffix and the observed `tools/list` schema
declares the matching `x-mcp-header` binding. Reserved headers such as
`Authorization`, `Host`, and `Cookie` are never sourced from tool parameters.

Multi-round-trip `requestState` values from upstream responses are replaced
with Vellaveto-sealed tokens before they reach the client. A later client echo
must present the sealed token in the same session; tampered, expired, replayed,
or untracked tokens are denied.

Detached server-initiated JSON-RPC requests are fail-closed. `GET /mcp` SSE
streams cannot carry server requests, and WebSocket upstream requests are only
forwarded while a client request is live in the same connection.

## License

BUSL-1.1 - see [LICENSE-BSL-1.1](../LICENSE-BSL-1.1) and [LICENSING.md](../LICENSING.md) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
