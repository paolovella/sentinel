# vellaveto-cluster

Distributed state backend for [Vellaveto](https://vellaveto.online) clustering.

## Overview

Provides leader election, service discovery, and distributed state for multi-node deployments:

- Redis backend with optional feature flag
- Local in-memory backend for single-node deployments
- Approval workflow deduplication across nodes

## Usage

```toml
[dependencies]
vellaveto-cluster = { version = "6", features = ["redis-backend"] }
```

## License

BUSL-1.1 — see [LICENSE-BSL-1.1](../LICENSE-BSL-1.1) and [LICENSING.md](../LICENSING.md) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
