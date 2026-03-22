# vellaveto-operator

Kubernetes operator for [Vellaveto](https://vellaveto.online).

## Overview

Manages Vellaveto resources in Kubernetes via Custom Resource Definitions:

- **VellavetoPolicy** — declarative security policies as K8s resources
- **VellavetoCluster** — multi-node gateway cluster management
- **VellavetoTenant** — multi-tenant isolation and quota enforcement

Communicates with `vellaveto-server` via REST API. Deploy with the accompanying Helm chart.

## Installation

```bash
helm install vellaveto ./helm/vellaveto
```

## License

BUSL-1.1 — see [LICENSE-BSL-1.1](../LICENSE-BSL-1.1) and [LICENSING.md](../LICENSING.md) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
