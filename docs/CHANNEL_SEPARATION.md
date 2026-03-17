# Control/Data Channel Separation

VellaVeto addresses MCP's control/data channel conflation through three structural layers that compose into detection-independent defense.

## The Problem

MCP's design shares a single channel for both control (tool invocations) and data (tool responses). A tool response can contain content that, when processed by the LLM, causes it to invoke other tools — including privileged ones the attacker controls through the injected content. Traditional detection-based defenses (regex, ML classifiers) cannot reliably distinguish between legitimate tool output and injected control instructions.

## Three-Layer Defense

### Layer 1: Source-Class Tainting

**Principle**: Classify tools by trust tier *before* their output is seen. Auto-taint sessions based on source classification, not detection results.

```toml
[source_trust]
default_tool_trust = "unknown"
untrusted_tools = ["fetch_url", "browse_*", "search_*"]
verified_tools = ["internal_api_*"]
```

When any tool classified as `untrusted` returns a response, the session is automatically tainted — regardless of whether any injection detector fires. This inverts the detection model: instead of "detect bad → taint", it's "classify source → taint by default".

Taint types: `SourceClassUntrusted` (trust floor: Untrusted), `SourceClassUnknown` (trust floor: Low). These compose with existing detection-based taints (injection, DLP, schema poisoning) via the strictest-wins rule.

### Layer 2: Intent Scope Declaration

**Principle**: Constrain what tools and sink classes the agent can use. Scope narrows automatically when taint is present.

```toml
[intent_scope]
allowed_sink_classes = ["ReadOnly", "LowRiskWrite", "FilesystemWrite"]
allowed_tools = ["read_*", "write_*", "list_*"]
denied_tools = ["execute_*"]
out_of_scope_action = "RequireApproval"
max_distinct_tools = 10
```

When source-class taint fires, `restrict_to_trust_floor()` automatically narrows the scope: sink classes requiring higher trust than the taint floor are removed. This creates the core composition: untrusted data enters → session taints → scope narrows → privileged actions blocked.

### Layer 3: Behavioral Sequence Analysis

**Principle**: Track tool call sequences and flag behavioral anomalies that may indicate injection-provoked actions — even within the allowed scope.

Five deterministic heuristic detectors (no ML, fully auditable):

1. **ReadThenExfil** — tainted read followed by network egress within time window
2. **PrivilegeEscalationAfterTaint** — sink class jump after source taint
3. **ToolDiversitySpike** — new tools cluster after taint event
4. **NovelToolAfterUntrustedContent** — never-seen tool targets privileged sink
5. **PrivilegedActionCluster** — burst of high-privilege calls in tainted session

## How They Compose

```
Untrusted tool response arrives
  → Source-class auto-taint fires (Layer 1)
  → Session trust floor drops to Untrusted
  → Intent scope narrows: high-privilege sinks removed (Layer 2)
  → Next tool call enters evaluation pipeline
    → Intent scope check: out-of-scope → blocked
    → Contagion + flow lattice: trust < sink requirement → blocked
    → Sequence analysis: anomalous pattern → blocked (Layer 3)
```

Each layer independently blocks the attack. An attacker must bypass all three:
- Avoid source-class tainting (requires using only verified tools)
- Stay within the narrowed intent scope (requires only low-privilege sinks)
- Avoid triggering any behavioral detector (requires human-like tool patterns)

## Configuration Examples

### Shield Preset (audit-only source tainting)

```toml
[source_trust]
untrusted_tools = ["fetch_url", "browse_*", "search_*", "read_file"]
default_tool_trust = "unknown"

[intent_scope]
out_of_scope_action = "AuditOnly"
max_distinct_tools = 20
```

### Fortress Preset (enforced)

```toml
[source_trust]
untrusted_tools = ["fetch_url", "browse_*", "search_*"]
default_tool_trust = "unknown"

[intent_scope]
allowed_sink_classes = ["ReadOnly", "LowRiskWrite", "FilesystemWrite"]
out_of_scope_action = "RequireApproval"
max_distinct_tools = 10
```

### Vault Preset (strict)

```toml
[source_trust]
untrusted_tools = ["fetch_url", "browse_*", "search_*", "read_file"]
default_tool_trust = "untrusted"

[intent_scope]
allowed_sink_classes = ["ReadOnly"]
allowed_tools = ["read_file", "list_directory", "search_*"]
out_of_scope_action = "Deny"
max_distinct_tools = 5
allow_scope_expansion = false
```

## Performance

Total added latency per evaluation: <15μs
- Source trust lookup: HashMap + glob match (<1μs)
- Intent scope check: set membership test (<1μs)
- Sequence analysis: O(window_size) with window ≤ 20 (<10μs)

Well within the <5ms P99 evaluation budget.

## Formal Verification

- **TLA+**: `SourceTaintContainment.tla` — completeness, monotonic composition, privileged sink unreachability, auto-taint inversion property
- **TLA+**: `IntentScopeContainment.tla` — enforcement completeness, monotonic narrowing, atomic taint-to-restriction
- **TLA+**: `SequenceContainment.tla` — anomaly persistence, restriction monotonicity, warmup safety
- **Verus**: `verified_source_taint.rs` — panic-freedom, trust floor correctness
- **Kani**: proof harnesses for each detector pattern
