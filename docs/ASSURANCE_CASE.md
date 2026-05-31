# Assurance Case

Structured Claim → Evidence map for Vellaveto's public security claims.
Each claim includes scope, assumptions, evidence pointers, and a single
reproduction command.

For the normative definition of each guarantee, see
[SECURITY_GUARANTEES.md](SECURITY_GUARANTEES.md).

---

## Claims

### C1. "Fail-closed: errors and missing policies produce Deny"

| Field | Value |
|-------|-------|
| **Scope** | `PolicyEngine::evaluate` and `AbacEngine::evaluate` code paths |
| **Assumptions** | Engine is called for every tool call (complete mediation) |
| **Formal evidence** | TLA+ invariants S1, S5, S6 (`formal/tla/MCPPolicyEngine.tla`); Lean 4 proof (`formal/lean/Vellaveto/FailClosed.lean`) |
| **Test evidence** | `vellaveto-engine/src/lib.rs` — `test_no_matching_policy_denies`, `test_empty_engine_denies`, `test_error_in_context_denies`; `vellaveto-integration/tests/` — negative integration tests |
| **Negative tests** | Tests that verify `Allow` is never produced without an explicit `Allow` policy match |
| **Reproduce** | `cargo test -p vellaveto-engine -- fail_closed && cd formal/tla && java -jar tla2tools.jar -config MCPPolicyEngine.cfg MC_MCPPolicyEngine.tla` |

### C2. "<5ms P99 policy evaluation latency"

| Field | Value |
|-------|-------|
| **Scope** | `PolicyEngine::evaluate_with_compiled` hot path. Excludes upstream tool latency, TLS termination, network I/O, DLP scanning, and injection detection. |
| **Assumptions** | Payload ≤ 64 KB; policies ≤ 1,000; pre-compiled policy index; warm cache; reference hardware (see below) |
| **Benchmark evidence** | `vellaveto-engine/benches/evaluation.rs` — 7 Criterion benchmarks; measured 7–31 ns (1 policy), ~1.2 µs (100 policies), ~12 µs (1,000 policies) |
| **Reference hardware** | AMD EPYC 7R13 (c6a.2xlarge), 3.6 GHz boost, Amazon Linux 2023, Rust 1.93.0, release profile with `lto = "thin"` |
| **Reproducibility kit** | `repro/` directory with `bench.sh`, `Dockerfile`, `pinned-results.json`, `verify.sh` |
| **CI gate** | Benchmark regression check on every push to `main`; >10% regression flagged |
| **Reproduce** | `./repro/bench.sh` or `docker build -t vellaveto-bench -f repro/Dockerfile . && docker run --rm vellaveto-bench` |

**Note:** The "<5ms P99" claim is conservative. Measured P99 for the full evaluation path
(including path normalization, domain extraction, and context evaluation) is under 15 µs
for 1,000 policies — two orders of magnitude below the 5ms target. The claim refers to the
`/api/evaluate` hot path excluding network I/O.

For load testing under concurrency, see [perf/LOADTEST.md](../perf/LOADTEST.md).

### C3. "Tamper-evident audit trail with cryptographic integrity"

| Field | Value |
|-------|-------|
| **Scope** | Append-only audit log with SHA-256 hash chain, Ed25519 checkpoint signatures, Merkle inclusion proofs |
| **Assumptions** | Filesystem not actively compromised during writes; Ed25519/SHA-256 primitives are correct; signing key not compromised |
| **What "tamper-evident" means** | Tampering is *detected* on verification, not *prevented*. Truncation is detectable. Silent modification of individual entries breaks the hash chain. |
| **What it does NOT mean** | An attacker with write access cannot be prevented from deleting the log entirely. Forward to external SIEM for tamper-resistant archival. |
| **Test evidence** | `vellaveto-audit/src/tests.rs` — hash chain verification, corruption detection, checkpoint validation, Merkle proof verification; `vellaveto-integration/tests/` — audit integrity tests |
| **Reproduce** | `cargo test -p vellaveto-audit -- chain && cargo test -p vellaveto-audit -- checkpoint && cargo test -p vellaveto-audit -- merkle` |

### C4. "MCP 2025-11-25 and 2026-07-28 compliance with version-gated compatibility"

| Field | Value |
|-------|-------|
| **Scope** | JSON-RPC 2.0 message handling, MCP method routing, protocol-version dispatch, capability negotiation, elicitation/sampling interception |
| **Assumptions** | Upstream MCP server is spec-compliant |
| **Test evidence** | `vellaveto-mcp/src/wire.rs` adapter and `_meta` normalization tests; `vellaveto-http-proxy/tests/proxy_integration.rs` HTTP routing, `requestState`, SSE, and WebSocket guardrails; `vellaveto-integration/tests/` transport/version compatibility |
| **Backwards compat** | Default advertised floor is `2025-11-25`, with `2026-07-28` preferred. Older known versions remain parseable only when policy explicitly lowers the floor. |
| **Reproduce** | `cargo test -p vellaveto-mcp wire && cargo test -p vellaveto-http-proxy request_state && cargo test -p vellaveto-http-proxy server_request && cargo test -p vellaveto-integration` |

### C5. "EU AI Act compliance (Art 50(2) + Art 10)"

| Field | Value |
|-------|-------|
| **Scope** | Art 50(2): automated decision explanations injected into `_meta.vellaveto_decision_explanation`. Art 10: data governance registry with classification, purpose, provenance, retention. Art 50(1): transparency marking via `_meta.vellaveto_ai_mediated`. |
| **Assumptions** | Operator configures appropriate explanation verbosity and data governance mappings |
| **Test evidence** | `vellaveto-mcp/src/transparency.rs` — Art 50(1) tests; `vellaveto-server/src/routes/compliance.rs` — API tests; `vellaveto-audit/src/eu_ai_act.rs` — registry tests; `vellaveto-audit/src/data_governance.rs` — Art 10 tests |
| **Reproduce** | `cargo test -p vellaveto-audit -- eu_ai_act && cargo test -p vellaveto-audit -- data_governance && cargo test -p vellaveto-mcp -- transparency` |

### C6. "254 audit rounds, 1,720+ findings"

| Field | Value |
|-------|-------|
| **Scope** | Internal adversarial testing using automated multi-agent protocol (Swarm). Not external third-party audits. |
| **Methodology** | Automated adversarial agent generates attack payloads against running instance; findings triaged by severity (P0–P3); fixes verified by re-running attack corpus. 6-agent parallel swarm with threat intelligence integration (100+ attack vectors, 30+ CVEs per sweep from R226+). |
| **Evidence** | `CHANGELOG.md` — per-round finding counts and fix PRs; `docs/SECURITY_REVIEW.md` — methodology and severity breakdown; `vellaveto-integration/tests/` — regression tests |
| **Clarification** | These are *internal automated audit iterations*, not external penetration tests by a third-party firm. The badge text reflects this. |
| **Reproduce** | Finding verification: `cargo test -p vellaveto-integration -- regression` |

### C7. "882+ formally verified properties"

| Field | Value |
|-------|-------|
| **Scope** | 668 Verus verified items (deductive, ALL inputs via Z3 SMT on actual Rust), 108 Kani CBMC proof harnesses (on actual Rust), 14 TLA+ specs, 45 Coq theorems, 37 Lean 4 theorems, 10 Alloy assertions — across 6 tools. |
| **Verus coverage** | 47 verified kernels covering verdict fail-closed (V1-V8), path normalization (V9-V10), rule override (V11-V12), DLP buffer safety (D1-D6), constraint evaluation, audit chain integrity, Merkle proofs, rotation manifests, capability delegation, NHI delegation, approval scope binding, deputy chain, entropy gates, cross-call DLP, refinement safety obligations, and ACIS envelope invariants. |
| **Assumptions** | Verus: Z3 SMT-checked for ALL inputs. Kani: bounded model checking (finite state spaces). TLA+: exhaustive within declared bounds. Properties are structural. |
| **What is NOT verified** | Pattern compilation, cryptographic primitives, timing, concurrency, network properties, serialization. See [FORMAL_SCOPE.md](FORMAL_SCOPE.md). |
| **Test evidence** | `formal/README.md` — property catalog with source traceability; `formal/verus/` — 47 Verus kernels; `formal/kani/` — 108 harnesses |
| **Reproduce** | `cd formal/tla && java -jar tla2tools.jar -config MCPPolicyEngine.cfg MC_MCPPolicyEngine.tla` and `cd formal/verus && cargo verus --crate-type=lib src/lib.rs` |

---

## Evidence Summary

| Verification Layer | Method | Count |
|--------------------|--------|-------|
| Unit + integration tests | Rust `#[test]` | 10,990+ |
| SDK tests | Python / Go / TypeScript / Java | 855 |
| Fuzz targets | `cargo fuzz` | 24 |
| Property-based tests | `proptest` | ~50 |
| Formal — Verus (deductive) | Z3 SMT on actual Rust (ALL inputs) | 534 verified items |
| Formal — Kani (BMC) | Bounded model checking on actual Rust | 82 harnesses |
| Formal — TLA+ | Exhaustive model checking | 64 properties |
| Formal — Coq | Interactive theorem proving | 45 theorems |
| Formal — Lean 4 | Dependent type checking | 32 theorems |
| Formal — Alloy | Relational model checking | 10 assertions |
| Criterion benchmarks | Statistical microbenchmark | 51 benchmarks |
| Reproducibility kit | Docker + pinned results | `repro/` |
| CI gates | GitHub Actions | 16 workflows |

---

## Reproducing the Full Evidence Bundle

```bash
make verify
```

This runs all verification steps and produces a JSON evidence bundle.
See the root [Makefile](../Makefile) for details.
