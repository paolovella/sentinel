# Security Audit Log

> **Living document** tracking all adversarial security audit rounds, findings, and fixes.
> Updated after every audit-fix-commit cycle.
>
> **Last updated:** 2026-03-30 (Round 267)
> **Total audit rounds:** 267
> **Total security fix commits:** 375+
> **Total findings resolved:** 1,750+

---

## How to Read This Document

Each audit round follows this lifecycle:
1. **Audit** — 4 parallel agents scan: types+engine, MCP+audit, server+proxy, config+SDKs
2. **Triage** — Findings prioritized: P0 (critical exploit) > P1 (bypass) > P2 (security gap) > P3 (defense-in-depth) > P4 (code quality)
3. **Fix** — P1+P2 fixed first, then P3, then P4
4. **Verify** — `cargo test --workspace`, `cargo clippy --workspace`, SDK tests
5. **Commit** — All fixes committed with finding IDs in message

Finding IDs follow the pattern `FIND-R{round}-{number}` (e.g., `FIND-R116-001`).

---

## ACIS Decision Envelopes (E1/E2, Mar 2026)

Every security decision now carries a structured `AcisDecisionEnvelope` in the audit trail, providing:

- **Decision identity** — unique decision ID and SHA-256 action fingerprint
- **Decision kind** — `Allow`, `Deny`, or `RequireApproval` with structured metadata
- **Decision origin** — `PolicyEngine` or `ApprovalGate`
- **Transport label** — `"http"`, `"stdio"`, `"websocket"`, `"grpc"` identifying the interception point
- **Session and tenant binding** — optional session/tenant context for multi-tenant traceability
- **Timestamp** — ISO 8601 decision timestamp

ACIS envelopes are wired into:
- **Server evaluate API** — 7 audit sites (`/api/evaluate`)
- **Stdio relay** — 4 primary sites (tool call allow/block, resource read allow/block)
- **HTTP proxy** — 6 primary sites (tool call, resource read, task request verdicts)
- **ProxyBridge** — via canonical `mediate()` pipeline

The `AuditEntry.acis_envelope` field is `Option<AcisDecisionEnvelope>` for backward compatibility — existing entries without envelopes remain valid.

---

## Round 116 (2026-02-21)

**Commit:** `df5a96e`
**Findings:** 2 P1 + 9 P2 + 20 P3 = 31 total (P1+P2 fixed, P3 noted)
**Auditors:** 4 parallel agents (types+engine, MCP+audit, server+proxy, config+SDKs)

### P1 Findings (Fixed)

| ID | Crate | Description |
|----|-------|-------------|
| FIND-R116-MCP-001 | vellaveto-mcp | Capability token `expires_at` NOT included in Ed25519 signature — attacker can extend token lifetime indefinitely |
| FIND-R116-MCP-002 | vellaveto-mcp | DPoP verification deadlocks on nonce validation failure (read lock held while acquiring write lock) |

### P2 Findings (Fixed)

| ID | Crate | Description |
|----|-------|-------------|
| FIND-R116-TE-001 | vellaveto-types | `validate_url_no_ssrf()` missing IPv6 transition mechanism checks (6to4, Teredo, NAT64) |
| FIND-R116-TE-002 | vellaveto-types | `Action::validate()` missing control char validation on `resolved_ips` |
| FIND-R116-TE-003 | vellaveto-engine | `BehavioralTracker::record_session()` missing tool key validation (asymmetry with `from_snapshot()`) |
| FIND-R116-MCP-003 | vellaveto-mcp | Delegation chain includes expired-but-uncleaned links (TOCTOU) |
| FIND-R116-MCP-004 | vellaveto-mcp | A2A response scanning misses `status.message` and `history` fields |
| FIND-R116-MCP-005 | vellaveto-mcp | Self-delegation check bypassed via Unicode confusables (Cyrillic lookalikes) |
| FIND-R116-CA-001 | vellaveto-approval | Local ApprovalStore::create() missing reason control/format char validation (parity gap vs Redis) |
| FIND-R116-CA-002 | vellaveto-approval | `with_max_pending()` uses `assert!` (panic in library code) |
| FIND-R116-CA-003 | sdk/python | Missing timeout range validation (parity gap vs Go/TS) |

### P3 Findings (Defense-in-Depth)

| ID | Crate | Description | Status |
|----|-------|-------------|--------|
| FIND-R116-TE-004 | vellaveto-engine | `LeastAgencyTracker` missing control char validation on agent_id/session_id | Noted |
| FIND-R116-TE-005 | vellaveto-types | `EvaluationContext.timestamp` not validated for length/control chars | Noted |
| FIND-R116-TE-006 | vellaveto-types | EvaluationTrace/ActionSummary/PolicyMatch missing `deny_unknown_fields` | Noted |
| FIND-R116-TE-007 | vellaveto-engine | Mixed `to_lowercase()` vs `to_ascii_lowercase()` across context conditions | Noted |
| FIND-R116-MCP-008 | vellaveto-mcp | `AuthScheme` missing `deny_unknown_fields` (by design with `#[serde(flatten)]`) | Noted |
| FIND-R116-MCP-009 | vellaveto-mcp | Delegation chain resolution O(n*d) quadratic performance | Noted |
| FIND-R116-CA-004 | vellaveto-cluster | Redis approval keys stored without TTL; never-resolved approvals accumulate | Noted |
| FIND-R116-CA-005 | vellaveto-cluster | Rate limit with rps=0/burst=0 silently blocks all requests | Noted |
| FIND-R116-CA-006 | vellaveto-config | ClusterConfig key_prefix missing Redis hash tag character validation | Noted |
| FIND-R116-CA-007 | sdk/python | discovery_tools() server_id missing Unicode format char validation | Noted |
| FIND-R116-CA-008 | sdk/go | DiscoveryTools() serverID missing Unicode format char validation | Noted |
| FIND-R116-CA-009 | sdk/typescript | discoveryTools() serverId missing Unicode format char validation | Noted |
| FIND-R116-SP-001–008 | vellaveto-server | 8 P3s: WS counter ordering, registry tool echo, auth level length, trim mismatch, access review filter, federation unbounded, deployment info exposure, handler error echo | Noted |

---

## Round 115 (2026-02-21)

**Commit:** `d0a954d`
**Findings:** 0 P1 + 17 P2 + 0 P3 = 17 total (all fixed)

### P2 Findings (All Fixed)

| ID | Crate | Description |
|----|-------|-------------|
| FIND-R115-001 | vellaveto-types | `CapabilityToken::validate_structure()` missing control/format char validation on identity fields |
| FIND-R115-002 | vellaveto-types | `AccessReviewEntry::validate()` missing control/format char validation |
| FIND-R115-003 | vellaveto-types | `ZkBatchProof::validate()` missing control/format char validation on `batch_id`/`created_at` |
| FIND-R115-004 | vellaveto-types | `CanonicalToolSchema/CanonicalToolCall::validate()` missing control/format char validation |
| FIND-R115-005 | vellaveto-types | `DeploymentInfo::validate()` missing control/format char validation |
| FIND-R115-006 | vellaveto-types | `AbacPolicy/AbacEntity/LeastAgencyReport::validate()` missing control/format char validation |
| FIND-R115-007 | vellaveto-types | 9 types missing `deny_unknown_fields` (ToolSignature, ToolAttestation, etc.) |
| FIND-R115-020 | vellaveto-mcp | Capability token canonical content length-prefix collision |
| FIND-R115-021 | vellaveto-mcp | NHI self-delegation rejection missing |
| FIND-R115-022 | vellaveto-mcp | NHI delegation from/to terminal-state agents allowed |
| FIND-R115-023 | vellaveto-mcp | WorkflowTracker `record_step` bypasses max_sessions/max_workflows limits |
| FIND-R115-024 | vellaveto-mcp | NHI `check_behavior` NaN bypass in request interval anomaly detection |
| FIND-R115-025 | vellaveto-mcp | NHI `register_identity` missing input validation |
| FIND-R115-040 | vellaveto-http-proxy | gRPC tools/list missing rug-pull annotation + output schema extraction |
| FIND-R115-041 | vellaveto-http-proxy | gRPC+WS resource_read missing rug-pull URI check |
| FIND-R115-042 | vellaveto-http-proxy | gRPC+WS resource_read missing circuit breaker check |
| FIND-R115-043 | vellaveto-http-proxy | gRPC handle_tool_call missing `tool_registry.record_call()` |

---

## Round 114 (2026-02-20)

**Commit:** `7277c2a`
**Findings:** NHI delegation bypass, IPv4-mapped IPv6 SSRF, SDK parity

### Key Fixes
- NHI delegation chain bypass via expired links
- `validate_url_no_ssrf()` added IPv4-mapped IPv6 check
- Go/TS SDK parity fixes for discovery and projector methods
- MCP DLP scan `result` field in PassThrough for sampling/elicitation responses

---

## Round 113 (2026-02-20)

**Commit:** `96f75d0`
**Findings:** gRPC injection scanning, deny reason redaction, extension parity

### Key Fixes
- gRPC forward_and_scan injection scanning parity with HTTP
- Deny reason redacted from client responses (internal details leaked)
- Extension method ABAC+DNS+tracking parity across all transports

---

## Round 112 (2026-02-19)

**Commits:** `71cc152`, `ee1f843`, `9cbd609`
**Findings:** Unicode format char validation, config hardening, WebSocket parity

### Key Fixes
- Unicode format character validation across 20+ types
- WebSocket ResourceRead parity with HTTP handler
- Projector compression bounds
- StatelessContextBlob char validation
- SDK+approval hardening

---

## Round 111 (2026-02-19)

**Commit:** `536850a`
**Findings:** 1 P1 + multiple P2

### P1 Fix
- **Capability token holder bypass** — attacker could issue token to holder with trailing whitespace, bypassing holder verification

### P2 Fixes
- DLP pattern leakage in error messages
- Audit sequence number continuity across rotation
- Route handler Content-Type validation
- Path parameter bounds

---

## Round 110 (2026-02-19)

**Commit:** `4d41640`
**Findings:** Enterprise/ETDI validation, schema depth limits, A2A bounds

### Key Fixes
- `EnterpriseConfig` and `EtdiConfig` validate() methods added
- JSON schema depth limits to prevent stack overflow
- A2A response body bounds
- Relay message sanitization

---

## Rounds 100–109 (2026-02-18–19)

**Key commits:** Multiple
**Focus:** Deep structural hardening

### Highlights
- Round 108: `#[must_use]` on Verdict types, `call_counts` saturating_add
- Round 104: Simulator validate() bypass, manifest bounds, budget tracker OOM, Debug redaction
- Round 103: Python SDK context validation, discovery deny_unknown_fields
- Round 101: Setup wizard TOCTOU race, Unicode format chars, Go SDK validation

---

## Rounds 80–99 (2026-02-17–18)

**Focus:** Transport parity, ABAC hardening, NHI management

### Major Findings
- Round 96–99: DLP result scanning in PassThrough across all transports
- Round 84–85: Levenshtein distance validation, Redis parity
- Round 82–83: UTF-8 truncation panics, audit deny_unknown_fields, config validation
- Round 81: WebSocket+NHI hardening, config validation gaps
- Round 80: Go+TS SDK P2s, MCP ABAC+DNS findings

---

## Rounds 58–79 (2026-02-15–17)

**Focus:** SDK parity, compliance, deep adversarial testing

### Major Findings (Round 58 — 78 findings)
- **3 P1:** Redis self-approval homoglyph bypass, Redis self-denial missing, TS SDK missing `resolved_ips`
- **24 P2:** Engine snapshot OOM, regex safety bypass, session baselines unbounded, config deny_unknown_fields (28 structs)
- Round 67: Server unbounded responses, SDK config validation
- Rounds 60–66: Incremental hardening across all crates

---

## Rounds 40–57 (2026-02-13–15)

**Focus:** Code quality, deduplication, formal verification alignment

### Round 57 (100 P4 findings, 84 fixed)
- Code deduplication: `glob_match`, `html_escape`, `FORWARDED_HEADERS`, `validate_path_param_core`, `parse_iso8601_secs`
- `thiserror` migration for error types
- `deny_unknown_fields` on 25 config structs
- New `validate()` methods on 9 types
- Named constants extracted from magic numbers

### Round 56 (91 P3 findings, ~72 fixed)
- Custom Debug impls redacting secrets on 6 types
- `MAX_DLP_FINDINGS=1000` cap
- `MultimodalConfig` validate+deny_unknown_fields
- Safe u128→u64 conversions
- `#[must_use]` on evaluate_action methods

### Round 55 (72 P2 findings)
- Setup wizard CSRF+session+TOML generation
- gRPC transport parity for injection/DLP/behavioral
- RAG defense config bounds
- Route handler hardening

---

## Rounds 1–39 (2026-02-01–13)

**Focus:** Foundation hardening, critical bypass fixes

### Landmark Findings
- **Round 53 (2 P0):** Constant-time HMAC verification compiler optimization bypass via `black_box`, tier_override silent license bypass
- **Round 52 (8 P1):** EvaluationContext previous_actions control char bypass, call_chain Unicode format chars, WebSocket DLP parity, SessionState pub→pub(crate), A2A response body limit, audit sequence counters SeqCst
- **Round 51:** Float scores [0.0,1.0] range validation across 6 types, ToolSignature.is_expired() ISO 8601 validation
- **Round 50 (6 P1):** Policy::validate() fail-closed, NhiDelegationChain.max_depth hard cap, TS SDK evaluate() target fields, federation JWT validation
- **Round 49 (6 P1):** EvaluationContext/StatelessContextBlob collection bounds OOM, AccessReviewEntry NaN bypass, ZK audit mutex poison redaction
- **Round 48 (2 P1):** WebSocket canonicalization TOCTOU across 6 message types, ABAC NaN risk.score bypass
- **Round 47 (3 P0 + 12 P1):** Unbounded intent_chains OOM, SDK payload format mismatch (Python/Go/TS), async response body limit, ZK witness restore-on-failure
- **Round 46:** Fail-closed defaults for ToolSensitivity/NhiIdentityStatus/ABAC, deny_unknown_fields on security structs, SDK input validation
- **Round 45:** GET /mcp full security parity with POST (session binding, identity validation, call chain, audit logging)
- **Round 44:** Various hardening fixes
- **Round 43 (35 findings):** Stdio pipe deadlock, subprocess environment clearing, stale circuit breaker, Merkle leaf pruning, NHI terminal-state enforcement, trust graph caps
- **Round 42:** Transport preference dedup, URL userinfo SSRF, circuit breaker capacity, exec graph metadata ordering
- **Round 41:** Header allowlist, shell injection prevention, circuit breaker OOM bound, response body limit, stdio zombie kill

---

## Vulnerability Categories Tracked

| Category | Description | Rounds with Findings |
|----------|-------------|---------------------|
| **SSRF** | Server-side request forgery via URL parsing | 41, 42, 50, 114, 116 |
| **Injection** | Command/log/template injection | 41, 43, 52, 55, 112 |
| **Auth Bypass** | Token/capability/delegation bypasses | 50, 51, 53, 58, 111, 116 |
| **DoS/OOM** | Unbounded collections, memory exhaustion | 43, 46, 47, 49, 52, 58 |
| **Transport Parity** | Missing checks in WS/gRPC/stdio/SSE | 45, 48, 52, 55, 80, 96, 113, 115 |
| **SDK Parity** | Missing validation/features across Python/Go/TS | 47, 50, 51, 58, 82, 104, 116 |
| **Unicode/Encoding** | Homoglyph, bidi, format char bypasses | 52, 58, 101, 112, 115, 116 |
| **Numeric** | NaN/Infinity/overflow bypasses | 48, 49, 51, 56, 115 |
| **Concurrency** | RwLock poisoning, TOCTOU, deadlocks | 43, 48, 52, 116 |
| **Cryptographic** | Signature, HMAC, timing attacks | 50, 53, 111, 116 |
| **Config** | Missing validation, fail-open defaults | 46, 55, 56, 57, 58, 110, 112 |

---

## Security Metrics

| Metric | Value |
|--------|-------|
| Total audit rounds | 116+ |
| Total findings found | ~1,400+ |
| P0 findings (all-time) | 5 |
| P1 findings (all-time) | ~82 |
| P2 findings (all-time) | ~509 |
| P3 findings (all-time) | ~500 |
| P4 findings (all-time) | ~300 |
| Rust tests | 6,593+ |
| Python SDK tests | 343 |
| Go SDK tests | 106 |
| TypeScript SDK tests | 103 |
| Fuzz targets | 24 |
| `unwrap()` in library code | 0 |

---

## Update Protocol

After every audit-fix-commit cycle:
1. Add a new round section at the top (below the header)
2. List all P1/P2 findings with status (Fixing/Fixed/Noted)
3. Update the "Last updated" date and round number
4. Update security metrics if counts changed significantly
5. Move findings from "Fixing" to "Fixed" once committed
