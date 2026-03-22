# vellaveto-types

Core type definitions for the [Vellaveto](https://vellaveto.online) MCP security engine.

## Overview

This crate provides the foundational types used across the Vellaveto workspace:

- **`Action`** — represents an MCP tool invocation with tool name, parameters, target paths, and domains
- **`Policy`** — security policy with path rules, network rules, and ABAC constraints
- **`Verdict`** — evaluation result: `Allow`, `Deny { reason }`, or `RequireApproval`
- **`AgentIdentity`** / **`EvaluationContext`** — identity-aware policy evaluation context
- **`NetworkRules`** / **`IpRules`** — domain allowlists, blocklists, and CIDR rules
- ETDI, ABAC, capability delegation, compliance, NHI, and discovery types

## Usage

```toml
[dependencies]
vellaveto-types = "6"
```

```rust
use vellaveto_types::{Action, Policy, Verdict};
```

## License

MPL-2.0 — see [LICENSE-MPL-2.0](../LICENSE-MPL-2.0) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
