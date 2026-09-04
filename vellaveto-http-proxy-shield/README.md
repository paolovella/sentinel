# vellaveto-http-proxy-shield

Consumer shield HTTP proxy layer for [Vellaveto](https://vellaveto.online).

## Overview

Privacy-enhancing transport layer for the consumer shield:

- **Header stripping** — withholds correlation and tracing headers from upstream
  requests. **Integrated** into `vellaveto-http-proxy` behind
  `shield.strip_privacy_headers`. `PRIVACY_STRIP_HEADERS` is the authoritative
  list; the proxy consults it rather than restating header names.
- **Traffic padding** — fixed-size buckets to blunt content-length
  fingerprinting. **Not yet integrated** — see below.

## Why padding is not wired up

`pad_content` produces a framed message: a 4-byte little-endian length prefix,
the content, then zero padding to the bucket size. The receiver strips it with
`unpad_content`. That means a padded body is **not valid JSON**, so sending one
to a standard MCP client breaks it.

Padding can therefore only be applied where both ends have agreed to it. Wiring
it requires negotiation — a client advertising support (for example via a
request header), the proxy padding only for those clients, and unpadded
responses for everyone else — plus a decision about what padding is worth
against a given observer. Under TLS an observer sees ciphertext lengths, which
padding does help with; HTTP/2 framing and compression already obscure some of
the same signal.

Until that negotiation exists, the functions here are correct and tested but
unused, and `shield.traffic_padding` does not pad anything.

## Usage

```toml
[dependencies]
vellaveto-http-proxy-shield = "7"
```

## License

MPL-2.0 — see [LICENSE-MPL-2.0](../LICENSE-MPL-2.0) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
