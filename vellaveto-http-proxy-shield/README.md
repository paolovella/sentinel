# vellaveto-http-proxy-shield

Consumer shield HTTP proxy layer for [Vellaveto](https://vellaveto.online).

## Overview

Privacy-enhancing transport layer for the consumer shield:

- **Traffic padding** — fixed-size response buckets to prevent content-length fingerprinting
- **Header stripping** — removes privacy-sensitive HTTP headers

## Usage

```toml
[dependencies]
vellaveto-http-proxy-shield = "6"
```

## License

MPL-2.0 — see [LICENSE-MPL-2.0](../LICENSE-MPL-2.0) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
