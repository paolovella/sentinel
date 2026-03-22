# vellaveto-engine

Policy evaluation engine for the [Vellaveto](https://vellaveto.online) MCP security gateway.

## Overview

Evaluates security policies against MCP tool invocations with:

- **Glob and regex path matching** with traversal protection
- **Domain matching** with IDNA normalization and DNS rebinding defense
- **ABAC engine** with Cedar-style `forbid` overrides
- **Decision cache** with LRU eviction and TTL expiry
- **Wasm policy plugins** via Wasmtime with fuel metering
- **Collusion detection** and cascading failure circuit breakers
- **Fail-closed by default** — errors and missing policies produce `Deny`

P99 evaluation latency: <5ms.

## Usage

```toml
[dependencies]
vellaveto-engine = "6"
```

```rust
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy};

let engine = PolicyEngine::with_policies(true, &policies);
let verdict = engine.evaluate(&action)?;
```

## License

MPL-2.0 — see [LICENSE-MPL-2.0](../LICENSE-MPL-2.0) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
