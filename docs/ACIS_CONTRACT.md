# ACIS Decision Envelope Contract

## Overview

Every security decision in Vellaveto produces an `AcisDecisionEnvelope` -- the
normalized runtime contract shared by every enforcement path (stdio, HTTP,
WebSocket, gRPC, shield). Envelopes are attached to audit entries via
`AuditLogger::log_entry_with_acis()` and consumed by audit logging, metrics,
external webhooks, and the admin console.

Each envelope captures five dimensions of a decision:

- **Who** -- `agent_id`, `agent_identity`, `session_id`, `tenant_id`
- **What** -- `action_summary` (tool, function, target counts), `action_fingerprint` (SHA-256)
- **Why** -- `decision`, `origin`, `reason`, `matched_policy_id`, `findings`
- **Where** -- `transport`
- **When** -- `timestamp`, `evaluation_us`

Design constraints: fail-closed defaults (`DecisionKind::Deny`), no secrets in
fingerprints (parameters are never hashed), transport-agnostic serialization,
bounded fields on all strings and collections.

Source: `vellaveto-types/src/acis.rs`

## Envelope Structure

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `decision_id` | `String` | yes | UUID v4 hex, max 64 chars |
| `timestamp` | `String` | yes | RFC 3339, must end with `Z` or `+00:00` |
| `session_id` | `Option<String>` | no | Transport-scoped isolation identifier: stdio relay UUID, WebSocket connection UUID, HTTP proxy session state, or legacy `Mcp-Session-Id` when present; max 512 |
| `tenant_id` | `Option<String>` | no | Multi-tenant identifier, max 256 |
| `agent_identity` | `Option<AgentIdentity>` | no | Cryptographically attested identity from JWT |
| `agent_id` | `Option<String>` | no | Legacy agent identifier, max 512 |
| `action_summary` | `AcisActionSummary` | yes | Tool, function, target path/domain counts |
| `action_fingerprint` | `String` | yes | SHA-256 hex (64 chars), max 128 |
| `decision` | `DecisionKind` | yes | `allow`, `deny`, or `require_approval` |
| `origin` | `DecisionOrigin` | yes | Which enforcement layer produced the decision |
| `reason` | `String` | conditional | Human-readable reason; empty for Allow, max 4096 |
| `matched_policy_id` | `Option<String>` | no | Policy ID when origin is PolicyEngine, max 256 |
| `transport` | `String` | yes | `"http"`, `"websocket"`, `"grpc"`, `"stdio"`, `"sse"` |
| `findings` | `Vec<String>` | no | DLP/injection finding summaries, max 64 entries, max 512 chars each |
| `evaluation_us` | `Option<u64>` | no | Wall-clock evaluation latency in microseconds, capped at 3,600,000,000 |
| `call_chain_depth` | `u32` | yes | Multi-agent call chain depth, capped at 256 |

`AcisActionSummary` contains `tool` (max 256), `function` (max 256),
`target_path_count` (max 100,000), and `target_domain_count` (max 100,000).
Parameters are deliberately excluded because they may contain secrets.

All structs use `#[serde(deny_unknown_fields)]`.

## When to Use Which Builder

### Primary decisions: `mediate()`

The canonical mediation pipeline in `vellaveto-mcp/src/mediation.rs`. Every
transport surface calls this single function to evaluate an action through the
full enforcement sequence:

1. ACIS binding enforcement (session/identity requirements)
2. DLP parameter scanning
3. Injection scanning
4. Policy engine evaluation
5. ACIS envelope construction

Produces a `MediationResult` containing the verdict, origin, envelope, trace,
and any DLP/injection findings.

```
mediate(decision_id, action, engine, context, transport, config, session_id, tenant_id)
    -> MediationResult { verdict, origin, envelope, trace, dlp_findings, injection_findings }
```

### Standalone envelope: `build_acis_envelope()`

Used when a transport has already executed its own evaluation pipeline and
needs to attach an ACIS envelope to an audit entry without re-running
`mediate()`. Same function that `mediate()` calls internally.

```
build_acis_envelope(decision_id, action, verdict, origin, transport, findings,
                    evaluation_us, session_id, tenant_id, context)
    -> AcisDecisionEnvelope
```

### Secondary decisions: `build_secondary_acis_envelope()`

Convenience builder for decisions made outside the primary mediation pipeline.
Generates a fresh UUID, passes no findings list and no evaluation context.

Use cases: DLP parameter scanning, injection blocking, memory poisoning
detection, circuit breaker trips, capability enforcement failures, topology
guard denials, session guard violations.

```
build_secondary_acis_envelope(action, verdict, origin, transport, session_id)
    -> AcisDecisionEnvelope
```

## DecisionOrigin Assignment Rules

| Origin | When Used |
|--------|-----------|
| `PolicyEngine` | Only from `mediate()` -- policy evaluation verdict |
| `Dlp` | DLP parameter or response scanning blocked the action |
| `InjectionScanner` | Prompt injection, tool squatting, or rug-pull detected |
| `MemoryPoisoning` | MINJA-style memory poisoning detected in tool responses |
| `ApprovalGate` | `RequireApproval` verdict, approval timeout, or consumption failure |
| `CapabilityEnforcement` | Capability token validation failure |
| `RateLimiter` | Rate limit exhaustion |
| `CircuitBreaker` | Tool failure threshold exceeded (circuit breaker open) |
| `TopologyGuard` | Unknown tool denial by topology guard |
| `SessionGuard` | Session isolation or identity requirement violation |

The default `DecisionKind` is `Deny` (fail-closed). `RequireApproval` verdicts
from the policy engine map to `DecisionOrigin::ApprovalGate`.

## Transport Parity Requirements

All transports (HTTP, WebSocket, gRPC, stdio) must:

1. Construct ACIS envelopes for every security decision
2. Pass the correct transport label (`"http"`, `"websocket"`, `"grpc"`, `"stdio"`)
3. Include `session_id` when available
4. Pass `EvaluationContext` to the envelope builder when available
5. Validate envelopes before audit persistence via `log_entry_with_acis()`

The `mediate()` function is transport-agnostic. The caller passes the transport
label; the pipeline does not know which transport invoked it. This guarantees
that the same action produces the same verdict and fingerprint regardless of
transport.

## Validation

All envelopes are validated via `AcisDecisionEnvelope::validate()` before
persistence. `AuditLogger::log_entry_with_acis()` rejects invalid envelopes
with `AuditError::Validation` (fail-closed).

Validation checks:

- `decision_id`: non-empty, max 64, no dangerous characters
- `timestamp`: non-empty, must end with `Z` or `+00:00` (UTC)
- `session_id`: max 512, no dangerous characters
- `tenant_id`: max 256, no dangerous characters
- `agent_id`: non-empty when present, max 512, no dangerous characters
- `agent_identity`: delegates to `AgentIdentity::validate()`
- `action_fingerprint`: non-empty, max 128
- `action_summary`: tool/function non-empty, max 256, no dangerous characters; target counts max 100,000
- `reason`: max 4096, no dangerous characters
- `matched_policy_id`: max 256, no dangerous characters
- `transport`: non-empty, max 32, no dangerous characters
- `findings`: max 64 entries, each max 512, no dangerous characters
- `evaluation_us`: max 3,600,000,000 (1 hour)
- `call_chain_depth`: max 256

"Dangerous characters" includes ASCII control characters and Unicode format
characters (zero-width joiners, bidi overrides, BOM, tag characters).

## Action Fingerprinting

Source: `vellaveto-engine/src/acis.rs`

The fingerprint is a SHA-256 hash of:

```
tool \0 function \0 sorted_path_1 \0 sorted_path_2 ... \0 sorted_domain_1 \0 sorted_domain_2 ...
```

Properties:

- **Deterministic:** target paths and domains are sorted before hashing
- **Transport-agnostic:** same action produces same fingerprint regardless of transport
- **Secret-safe:** parameters are never included in the hash input
- **Cross-session coherent:** enables audit correlation without leaking session boundaries

The fingerprint is computed by `compute_action_fingerprint()` in `vellaveto-engine`
(not `vellaveto-types`) to avoid pulling `sha2` into the leaf types crate.

## Event Logging Wrappers

The convenience wrappers in `vellaveto-audit/src/events.rs` (heartbeat,
circuit-breaker events, etc.) use bare `log_entry()` without ACIS envelopes.
ACIS envelope construction is the **caller's** responsibility. The enforcement
path that invokes these wrappers must build and persist the envelope separately
via `log_entry_with_acis()`.
