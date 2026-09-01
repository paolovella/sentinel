# Vellaveto Security Model

This document defines Vellaveto's trust boundaries, data flows, storage guarantees, and residual risks. It is intended for security teams evaluating Vellaveto for production deployment.

---

## Trust Boundaries

```
                 +------------------+
  Agent/LLM ---->|  Vellaveto Proxy  |----> MCP Tool Server
                 |  (trust boundary)|
                 +------------------+
                    |            |
              Policy Engine   Audit Log
              (in-memory)     (on-disk)
```

**Vellaveto sits between the AI agent and the tool server.** Every tool call crosses the trust boundary twice: once on the request path (where policy is evaluated) and once on the response path (where output is inspected).

---

## Data That Enters Vellaveto

| Data | Source | Purpose |
|------|--------|---------|
| `tool` + `function` names | Agent request | Policy matching, squatting detection |
| `parameters` (JSON) | Agent request | Path/domain extraction, DLP scanning, injection detection |
| `target_paths` / `target_domains` | Extracted from parameters | Policy evaluation against path/network rules |
| `resolved_ips` | DNS resolution by proxy | DNS rebinding protection |
| `Authorization` header | Agent/client | OAuth 2.1 / JWT validation, scope enforcement |
| `X-Agent-Identity` header | Upstream proxy | Call chain tracking, identity attestation |
| HTTP response bodies | Tool server | Output validation, DLP scanning, injection detection |
| MCP elicitation/sampling | MCP server | Capability validation, rate limiting |

**All external input is validated:** tool/function names are length-bounded (256 bytes), control characters (U+0000-U+009F) are rejected, and parameters are depth-limited to prevent stack exhaustion.

---

## Data That Is Stored

### Audit Log (disk, append-only)

Each policy decision is written as a JSON Lines entry containing:
- Timestamp, tool name, function name, verdict, matched policy ID, reason
- **Redacted** parameters (secrets, PII, credentials replaced with `[REDACTED]`)
- SHA-256 hash chain linking each entry to the previous
- Optional Ed25519 checkpoint signatures every N entries
- Optional ACIS decision envelope — structured metadata containing decision ID, SHA-256 action fingerprint, verdict kind, decision origin (PolicyEngine or ApprovalGate), transport label, and session/tenant binding (backward-compatible: `acis_envelope` is `null` for pre-ACIS entries)

**Integrity:** The hash chain provides tamper *detection* (not prevention). An attacker with file-system write access could truncate the log, but this is detected on the next verification pass. Ed25519 checkpoints prevent silent key rotation.

**Rotation:** Logs rotate at 100 MB by default. Each rotated file gets a timestamped name and a manifest entry for chain continuity verification.

### Approval Queue (in-memory, optional file export)

Pending human approvals store the full `Action` (including unredacted parameters) so reviewers can make informed decisions. Approvals expire after 1 hour (configurable TTL) and are capped at 10,000 pending entries. When an approval is reused on `/api/evaluate`, Vellaveto fails closed unless the presented approval is already approved, its stored scope bindings (`session_id` and/or `action_fingerprint`) match the current request, and the approval has not already been consumed by a prior successful allow. Successful reuse transitions the approval to `Consumed`, so replay attempts fail closed.

**Self-approval prevention:** The `requested_by` identity must differ from the `resolved_by` identity.

### Policy Configuration (disk, operator-managed)

Vellaveto reads policies from TOML files. It does not write or modify policy files. Hot-reload is supported via filesystem watcher or API endpoint.

---

## Data That Is Redacted

Vellaveto applies multi-layer redaction before writing audit logs:

**Sensitive key names** (always redacted): `password`, `secret`, `token`, `api_key`, `authorization`, `credentials`, `private_key`, `client_secret`, `session_token`, `refresh_token`

**Sensitive value prefixes** (always redacted): `sk-` (OpenAI/Anthropic), `AKIA` (AWS), `ghp_`/`gho_`/`ghs_` (GitHub), `xoxb-`/`xoxp-` (Slack), `Bearer`/`Basic` (auth headers), `sk_live_` (Stripe), `AIza` (Google), `SG.` (SendGrid), `npm_`, `pypi-`

**PII patterns** (extensible): the built-in set is exactly seven — email
addresses, US SSNs, US phone numbers, credit card numbers (Luhn-validated),
IPv4 addresses, JWTs, and AWS key IDs.

These defaults are **US-centric and deliberately narrow**. Not covered: IBANs,
NHS numbers, EU/UK national IDs, passport numbers, non-US phone formats, IPv6
addresses, **filesystem paths**, and **personal names**. Add site-specific
patterns as `CustomPiiPattern` entries; each is checked by
`validate_regex_safety()` for ReDoS-prone constructs before being compiled.

The same pattern set backs the Consumer Shield's `QuerySanitizer`, so the
Shield's sanitization coverage is identical to the list above.

Redaction level is configurable: `Off`, `KeysOnly`, `KeysAndPatterns` (default), `High`.

---

## Data That Never Leaves the Process

| Data | Lifetime | Why |
|------|----------|-----|
| `EvaluationContext` (call counts, previous actions, call chain) | Per-request | Ephemeral session state, reconstructed each request |
| Behavioral anomaly baselines (EMA) | Per-session | Frequency tracking for tool usage patterns |
| Schema poisoning cache | Process lifetime | In-memory comparison of tool schema versions |
| Memory poisoning tracker | Per-session | Cross-request data laundering detection |
| Semantic injection n-grams | Process lifetime | TF-IDF similarity cache |
| DLP scan intermediate results | Per-request | Only the verdict is logged, not matched content |
| Raw JWT payload | Per-request | Only extracted claims (issuer, subject, audience) are logged |
| Circuit breaker state | Process lifetime | Open/HalfOpen/Closed per policy |

---

## Threats Covered

| Threat | Detection | Response |
|--------|-----------|----------|
| **Unauthorized tool access** | Policy engine (glob/regex matching) | Deny + audit |
| **Path traversal** | Normalization + blocked globs | Deny |
| **DNS rebinding** | IP resolution + private range blocking | Deny |
| **Prompt injection in parameters** | Aho-Corasick + semantic similarity | Deny or flag |
| **Tool squatting / rug-pull** | Levenshtein distance + homoglyph detection + schema pinning | Flag + persistent block |
| **Credential exfiltration** | DLP scanning (5-layer decode: raw/base64/percent/combos) | Deny |
| **Privilege escalation (multi-agent)** | Call chain depth limits + identity verification | Deny |
| **Schema poisoning** | Annotation change detection + persistent flagging | Block tool |
| **Behavioral anomaly** | EMA-based frequency tracking per agent | Alert |
| **Cross-request data laundering** | Session-level exfiltration chain detection | Alert |
| **Elicitation abuse** | Capability/schema/rate-limit validation | Deny |

---

## Threats NOT Covered

These are explicitly out of scope or represent residual risks:

### Out of Scope

1. **LLM-internal threats** — Model weight manipulation, training data poisoning, and in-model jailbreaks operate below Vellaveto's interception layer. Vellaveto evaluates the *output* of the LLM's decision, not the decision process itself.

2. **Credential provisioning** — How agents obtain credentials is outside Vellaveto's scope. Vellaveto blocks suspicious *use* of credentials but does not manage credential lifecycle.

3. **Physical/side-channel attacks** — Memory dumps, timing attacks, and electromagnetic emanations require OS-level and hardware-level mitigations.

### Residual Risks (Mitigated But Not Eliminated)

1. **Deep JSON parameter smuggling** — DLP scans flattened JSON leaves, but structures beyond `MAX_VALIDATION_DEPTH` are abandoned to prevent stack DoS. Secrets in very deep structures could evade scanning.

2. **Novel injection patterns** — Detection relies on known patterns (Aho-Corasick corpus) and semantic similarity. Entirely novel attack patterns not in the corpus may not be detected.

3. **Behavioral baseline manipulation** — An adversary could slowly ramp up tool usage over multiple sessions to shift the EMA baseline, then exploit the elevated threshold.

4. **Multi-agent collusion** — Call chain HMAC signatures prevent single-agent tampering, but two colluding agents in a chain could present a fabricated history.

5. **Audit log truncation** — Hash chains detect tampering but cannot prevent deletion. An attacker with filesystem write access could truncate the log. The deletion window persists until the next verification pass.

6. **DNS TOCTOU** — A domain may resolve to a public IP during the rebinding check but to a private IP during actual use. Mitigated by `block_private = true` default, but not eliminable at the application layer.

---

## Default Security Posture

Vellaveto is **fail-closed by design**:

- Missing policies produce `Deny`
- Policy evaluation errors produce `Deny`
- Unresolved evaluation context produces `Deny`
- Missing verification tier produces `Deny` (when `min_verification_tier` is set)
- Circuit breaker in `Open` state produces `Deny`
- Private IP ranges blocked by default (`block_private = true`)

No `unwrap()` or `expect()` calls exist in library code. All error paths are observable via structured logging.

---

## Deployment Recommendations

See [HARDENING.md](HARDENING.md) for detailed deployment guidance. Key points:

- Set `VELLAVETO_API_KEY` for all mutating endpoints
- Enable Ed25519 audit checkpoints in production
- Use OAuth 2.1 / JWT for agent authentication
- Run behind TLS termination (nginx, Caddy, cloud LB)
- Mount config files read-only (`:ro` in Docker)
- Set `read_only: true` and `no-new-privileges: true` in container runtime
- Forward audit logs to external SIEM for tamper-resistant archival
