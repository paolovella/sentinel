# vellaveto-config

Configuration parsing and validation for [Vellaveto](https://vellaveto.online) policies.

## Overview

Parses TOML policy files into validated `PolicyConfig` structs with:

- Path rules, network rules, ABAC constraints
- Discovery, topology, and shield configuration
- Cedar policy import/export for AWS AgentCore interoperability
- MCP Streamable HTTP protocol-version floors and routing header allowlists
- Bounded validation on all fields (max lengths, collection sizes, numeric ranges)
- `deny_unknown_fields` on all deserialized structs

## Usage

```toml
[dependencies]
vellaveto-config = "6"
```

## Streamable HTTP Settings

The `streamable_http` section controls MCP Streamable HTTP compatibility and
fail-closed protocol checks:

```toml
[streamable_http]
protocol_version_floor = "2025-11-25"
require_protocol_version_header = true
resumability_enabled = true
max_event_id_length = 128
allowed_mcp_param_headers = ["Region", "TenantId"]
```

`protocol_version_floor` rejects inbound versions below the configured floor.
`allowed_mcp_param_headers` lists permitted `Mcp-Param-*` suffixes; every entry
must be a valid HTTP field-name token, cannot be duplicated
case-insensitively, and is capped by the config validator.

## License

MPL-2.0 - see [LICENSE-MPL-2.0](../LICENSE-MPL-2.0) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
