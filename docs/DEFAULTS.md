# Security Defaults Reference

Every security-relevant default value in Vellaveto, with rationale.

**Design principle:** Secure by default. Dangerous configurations require
explicit opt-in. Silent insecurity is a bug.

---

## Policy Engine

| Setting | Default | Rationale |
|---------|---------|-----------|
| No matching policy | **Deny** | Fail-closed. An `Allow` verdict requires an explicit `Allow` policy. |
| Policy evaluation error | **Deny** | Fail-closed. Errors must not open access. |
| Missing evaluation context | **Deny** | Fail-closed. Context-dependent policies cannot evaluate without context. |
| Missing verification tier | **Deny** | When `min_verification_tier` is configured, unverified tools are denied. |
| Circuit breaker `Open` state | **Deny** | A tripped circuit breaker blocks all requests to the affected tool. |

## Network Rules

| Setting | Default | Rationale |
|---------|---------|-----------|
| `block_private` | **`true`** | Blocks RFC 1918/4193 private IP ranges by default. Prevents SSRF and DNS rebinding to internal services. |
| `allowed_domains` | **Empty** (all blocked) | When network rules are present, only explicitly allowed domains are reachable. |

## Authentication

| Setting | Default | Rationale |
|---------|---------|-----------|
| `api_key` | **`None`** (no auth) | Auth is disabled by default for local development. **Must be set in production.** |
| `metrics_require_auth` | **`true`** | Prometheus `/metrics` endpoint requires API key. Prevents information leakage. |
| `audit_strict_mode` | **`false`** | Audit write failures do not block requests by default. Set to `true` in production for non-repudiation guarantees. |
| OAuth 2.1 | **Disabled** | Requires explicit configuration of JWKS endpoint, issuer, and audience. |
| CSRF protection | **Enabled** | Origin/Referer validation on state-changing requests. |

## Rate Limiting

| Setting | Default | Rationale |
|---------|---------|-----------|
| Evaluate endpoint | **No limit** | Operator must configure based on expected throughput. |
| Readonly endpoints | **No limit** | Operator must configure. |
| `/health` | **Exempt** | Health checks must always succeed for load balancer probes. |

## Audit

| Setting | Default | Rationale |
|---------|---------|-----------|
| Redaction level | **`KeysAndPatterns`** | Redacts sensitive key names AND value patterns (API keys, PII). |
| Hash chain | **Enabled** | SHA-256 linking of every audit entry. Cannot be disabled. |
| Ed25519 checkpoints | **Disabled** | Requires signing key configuration. Enable in production. |
| Log rotation threshold | **100 MB** | Rotates at 100 MB. Configurable via `audit.max_size_bytes`. |
| Approval TTL | **1 hour** (3,600s) | Pending approvals expire. Prevents stale approval accumulation. |
| Max pending approvals | **10,000** | Caps memory usage for approval queue. |

## DLP / Inspection

| Setting | Default | Rationale |
|---------|---------|-----------|
| DLP scanning | **Enabled** (when `dlp` patterns configured) | Scans all parameters for credentials, PII. |
| Injection detection | **Enabled** (when `injection` patterns configured) | Scans for prompt injection patterns. |
| `max_validation_depth` | **20** | JSON nesting depth limit. Prevents stack exhaustion. |
| `max_path_decode_iterations` | **3** | Limits percent-decode/base64-decode passes. Prevents DoS via deeply nested encoding. |

## MCP Streamable HTTP

| Setting | Default | Rationale |
|---------|---------|-----------|
| `streamable_http.protocol_version_floor` | **`2025-11-25`** | Keeps the current migration window while refusing older protocol behavior unless policy explicitly lowers the floor. |
| `streamable_http.require_protocol_version_header` | **`true`** | Firewalls must not guess MCP wire semantics from a missing header. |
| `streamable_http.allowed_mcp_param_headers` | **Empty** | Custom `Mcp-Param-*` headers are denied until the operator allowlists each suffix. |
| `streamable_http.resumability_enabled` | **`false`** | Detached GET SSE resumability is opt-in. |
| `streamable_http.max_event_id_length` | **128 bytes** | Caps `Last-Event-ID` and SSE event identifier memory exposure. |

## Config Loading

| Setting | Default | Rationale |
|---------|---------|-----------|
| Accepted config extensions | **`.toml`, `.json` only** | Rejects unknown formats instead of silently falling back to a parser that may misinterpret content. |
| Empty/whitespace-only config file | **Rejected at load time** | Prevents accidental startup from empty mounts/files that would otherwise mask operator error. |
| Max config file size | **10 MB** | Caps memory exposure from malicious or accidental oversized config files. |

## CORS

| Setting | Default | Rationale |
|---------|---------|-----------|
| `allowed_origins` | **Empty** (localhost only) | Strict CORS by default. Must be explicitly opened for cross-origin access. |

## Deployment

| Setting | Default | Rationale |
|---------|---------|-----------|
| Deployment mode | **`standalone`** | Single instance, no coordination. |
| Leader election | **Disabled** | Requires explicit enablement for clustered deployments. |
| Governance `require_agent_registration` | **`false`** | Does not block unregistered agents by default. Set to `true` for strict governance. |

---

## Dangerous Modes (Require Explicit Opt-In)

The following configurations weaken security posture. They are never enabled
by default and produce warnings in logs when activated:

| Mode | Config | Risk |
|------|--------|------|
| Auth disabled | `api_key = None` | All endpoints unprotected. Acceptable for local dev only. |
| Audit strict off | `audit_strict_mode = false` | Requests proceed even when audit fails. Breaks non-repudiation. |
| Metrics public | `metrics_require_auth = false` | Exposes operational metrics without auth. Information leakage risk. |
| Private IPs allowed | `block_private = false` | Allows connections to RFC 1918 addresses. SSRF risk. |
| Redaction off | `redaction = "Off"` | Secrets written to audit log in plaintext. |
| CORS wildcard | `allowed_origins = ["*"]` | Any origin can make cross-origin requests. |
| Governance permissive | `require_agent_registration = false` | Unregistered agents are not blocked. |

---

## Verifying Defaults

The test suite includes tests verifying that unsafe configurations require
explicit opt-in:

```bash
# Default engine behavior
cargo test -p vellaveto-engine -- default

# Default config values
cargo test -p vellaveto-config -- default

# Fail-closed integration tests
cargo test -p vellaveto-integration -- regression
```
