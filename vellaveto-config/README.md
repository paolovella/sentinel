# vellaveto-config

Configuration parsing and validation for [Vellaveto](https://vellaveto.online) policies.

## Overview

Parses TOML policy files into validated `PolicyConfig` structs with:

- Path rules, network rules, ABAC constraints
- Discovery, topology, and shield configuration
- Cedar policy import/export for AWS AgentCore interoperability
- Bounded validation on all fields (max lengths, collection sizes, numeric ranges)
- `deny_unknown_fields` on all deserialized structs

## Usage

```toml
[dependencies]
vellaveto-config = "6"
```

## License

MPL-2.0 — see [LICENSE-MPL-2.0](../LICENSE-MPL-2.0) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
