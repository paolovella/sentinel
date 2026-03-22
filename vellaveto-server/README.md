# vellaveto-server

Vellaveto policy engine HTTP server and CLI.

## Overview

The main server binary for the [Vellaveto](https://vellaveto.online) MCP security gateway:

- **HTTP API** — RESTful endpoints for policy evaluation, management, and audit
- **Admin dashboard** — built-in setup wizard and status page
- **Enterprise IAM** — OIDC (Okta/AzureAD/Keycloak), SAML 2.0, RBAC, SCIM 2.0
- **Multi-tenancy** — per-tenant isolation, metering, and quota enforcement
- **Topology API** — live MCP server/tool discovery endpoints
- **DPoP token binding** — RFC 9449 proof-of-possession

## Quick start

```bash
cargo install vellaveto-server
vellaveto --config policy.toml
```

## License

BUSL-1.1 — free for non-production use and production deployments with <=3 nodes and <=25 endpoints. See [LICENSING.md](../LICENSING.md).

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
