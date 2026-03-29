# Vellaveto Go SDK

Go client for the [Vellaveto](https://github.com/paolovella/vellaveto) agent interaction firewall API.

**Zero dependencies** — uses only the Go standard library.

## Installation

```bash
go get github.com/paolovella/vellaveto/sdk/go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    vellaveto "github.com/paolovella/vellaveto/sdk/go"
)

func main() {
    client, err := vellaveto.NewClient("http://localhost:3000",
        vellaveto.WithAPIKey("your-api-key"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Check health
    health, err := client.Health(context.Background())
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Server status: %s\n", health.Status)

    // Evaluate an action
    result, err := client.Evaluate(context.Background(), vellaveto.Action{
        Tool:          "read_file",
        TargetPaths:   []string{"/data/report.csv"},
    }, nil, false)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Verdict: %s\n", result.Verdict)

    // Or use EvaluateOrError for typed errors
    err = client.EvaluateOrError(context.Background(), vellaveto.Action{
        Tool:          "exec_command",
        Function:      "shell",
        Parameters:    map[string]interface{}{"cmd": "ls"},
    }, nil)
    if err != nil {
        switch e := err.(type) {
        case *vellaveto.PolicyDeniedError:
            fmt.Printf("Denied: %s (policy: %s)\n", e.Reason, e.PolicyID)
        case *vellaveto.ApprovalRequiredError:
            fmt.Printf("Needs approval: %s (id: %s)\n", e.Reason, e.ApprovalID)
        default:
            log.Fatal(err)
        }
    }
}
```

## API Reference

| Method | Description |
|--------|-------------|
| `Health(ctx)` | Check server health |
| `Evaluate(ctx, action, context, trace)` | Evaluate a single action |
| `EvaluateOrError(ctx, action, context)` | Evaluate; returns typed error on deny/approval |
| `ListPolicies(ctx)` | List loaded policies |
| `ReloadPolicies(ctx)` | Trigger policy reload |
| `Simulate(ctx, action, context)` | Simulate with full trace |
| `BatchEvaluate(ctx, actions, policyConfig)` | Batch evaluate up to 100 actions |
| `ValidateConfig(ctx, config, strict)` | Validate policy configuration |
| `DiffConfigs(ctx, before, after)` | Diff two policy configs |
| `ListPendingApprovals(ctx)` | List pending approvals |
| `ApproveApproval(ctx, id)` | Approve by ID |
| `DenyApproval(ctx, id)` | Deny by ID |
| `Discover(ctx, query, maxResults, tokenBudget)` | Search the tool discovery index |
| `DiscoveryStats(ctx)` | Get discovery index statistics |
| `DiscoveryReindex(ctx)` | Rebuild discovery IDF weights |
| `DiscoveryTools(ctx, serverID, sensitivity)` | List indexed tools with optional filters |
| `ProjectorModels(ctx)` | List supported projector model families |
| `ProjectSchema(ctx, schema, modelFamily)` | Project canonical schema for a model family |
| **ZK Audit** | |
| `ZkStatus(ctx)` | Get ZK audit scheduler status |
| `ZkProofs(ctx, limit, offset)` | List stored ZK batch proofs with pagination |
| `ZkVerify(ctx, batchID)` | Verify a stored ZK batch proof by batch ID |
| `ZkCommitments(ctx, from, to)` | List Pedersen commitments for an audit sequence range |
| **Compliance** | |
| `Soc2AccessReview(ctx, period, format, agentID)` | Generate a SOC 2 Type II access review report |
| `OwaspAsiCoverage(ctx)` | Retrieve OWASP Agentic Security Index coverage report |
| `EvidencePack(ctx, framework, format)` | Generate a compliance evidence pack for a framework |
| `EvidencePackStatus(ctx)` | List which evidence pack frameworks are available |
| **Federation** | |
| `FederationStatus(ctx)` | Get federation resolver status |
| `FederationTrustAnchors(ctx, orgID)` | List configured federation trust anchors |
| **Billing & Usage** | |
| `Usage(ctx, tenantID)` | Get current-period usage metrics for a tenant |
| `QuotaStatus(ctx, tenantID)` | Get quota status (usage vs limits) for a tenant |
| `UsageHistory(ctx, tenantID, periods)` | Retrieve usage history across billing periods |

## Response Attestation

```go
valid := vellaveto.VerifyAttestation(response, []byte(os.Getenv("VELLAVETO_ATTESTATION_SECRET")))
```

## Client Options

```go
client, err := vellaveto.NewClient("http://localhost:3000",
    vellaveto.WithAPIKey("key"),              // Bearer token auth
    vellaveto.WithTimeout(10 * time.Second),  // Request timeout (default 5s)
    vellaveto.WithHTTPClient(customClient),   // Custom http.Client
    vellaveto.WithHeaders(map[string]string{  // Extra headers
        "X-Tenant-ID": "acme",
    }),
)
```

## Examples

The [`examples/`](examples/) directory contains runnable programs demonstrating
common integration patterns:

| Example | Description |
|---------|-------------|
| [`basic`](examples/basic/) | Create a client, evaluate tool calls, handle Allow/Deny/RequireApproval verdicts |
| [`middleware`](examples/middleware/) | HTTP middleware that enforces Vellaveto policies before forwarding requests |

Run any example with:

```bash
export VELLAVETO_URL=http://localhost:3000
export VELLAVETO_API_KEY=your-api-key
cd examples/basic && go run .
```

See [`examples/README.md`](examples/README.md) for full details.

## License

See [LICENSE](LICENSE) and [LICENSING.md](../../LICENSING.md)
