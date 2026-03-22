# vellaveto-canary

Warrant canary creation and cryptographic verification.

## Overview

Provides Ed25519-signed warrant canaries for transparency guarantees:

- `create_canary()` — generate a signed canary with expiration
- `verify_canary()` — verify signature, check expiration, detect tampering

Used by `vellaveto-shield` to prove that no covert access or data requests have been made.

## Usage

```toml
[dependencies]
vellaveto-canary = "6"
```

```rust
use vellaveto_canary::{create_canary, verify_canary};
```

## License

Apache-2.0 — see [LICENSE-APACHE-2.0](../LICENSE-APACHE-2.0) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
