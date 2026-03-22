# vellaveto-approval

Human-in-the-loop approval workflow for the [Vellaveto](https://vellaveto.online) MCP security gateway.

## Overview

When the policy engine returns `RequireApproval`, this crate manages the approval lifecycle:

- Create, approve, or deny pending requests
- Deduplication with cross-principal isolation
- Expiration and automatic cleanup

## Usage

```toml
[dependencies]
vellaveto-approval = "6"
```

## License

MPL-2.0 — see [LICENSE-MPL-2.0](../LICENSE-MPL-2.0) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
