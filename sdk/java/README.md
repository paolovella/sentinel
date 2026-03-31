# Vellaveto Java SDK

Java client for the [Vellaveto](https://github.com/paolovella/vellaveto) agent interaction firewall API.

**Requires Java 11+.**

## Installation

### Maven

```xml
<dependency>
  <groupId>com.vellaveto</groupId>
  <artifactId>vellaveto-java-sdk</artifactId>
  <version>6.0.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'com.vellaveto:vellaveto-java-sdk:6.0.0'
```

## Quick Start

```java
import com.vellaveto.VellavetoClient;
import com.vellaveto.Action;
import com.vellaveto.EvaluationResult;
import com.vellaveto.Verdict;

import java.util.Map;

public class Example {
    public static void main(String[] args) throws Exception {
        VellavetoClient client = new VellavetoClient.Builder()
            .baseUrl("http://localhost:3000")
            .apiKey("your-api-key")
            .build();

        // Check health
        var health = client.health();
        System.out.println("Status: " + health.getStatus());

        // Evaluate a tool call
        Action action = new Action.Builder()
            .tool("filesystem")
            .function("read_file")
            .parameters(Map.of("path", "/etc/passwd"))
            .build();

        EvaluationResult result = client.evaluate(action);

        switch (result.getVerdict()) {
            case ALLOW:
                System.out.println("Allowed");
                break;
            case DENY:
                System.out.println("Denied: " + result.getReason());
                break;
            case REQUIRE_APPROVAL:
                System.out.println("Needs approval: " + result.getApprovalId());
                break;
        }
    }
}
```

### Exception Handling

```java
import com.vellaveto.PolicyDeniedException;
import com.vellaveto.ApprovalRequiredException;
import com.vellaveto.EvaluationContext;

EvaluationContext context = EvaluationContext.builder()
        .agentId("my-agent")
        .build();

try {
    client.evaluateOrRaise(action, context);
    // Allowed — proceed
} catch (PolicyDeniedException e) {
    System.out.println("Blocked: " + e.getReason());
} catch (ApprovalRequiredException e) {
    System.out.println("Needs approval: " + e.getApprovalId());
}
```

## API Reference

### Core Evaluation

| Method | Description |
|--------|-------------|
| `health()` | Check server health |
| `evaluate(action, context, trace)` | Evaluate a single action |
| `evaluateOrRaise(action, context)` | Evaluate; throws on deny/approval |
| `simulate(action, context)` | Evaluate with full trace via the simulator endpoint |
| `batchEvaluate(actions, policyConfig)` | Evaluate multiple actions in a single request |

### Policy Management

| Method | Description |
|--------|-------------|
| `listPolicies()` | List loaded policies |
| `reloadPolicies()` | Trigger policy reload |
| `validateConfig(config, strict)` | Validate a policy configuration without loading it |
| `diffConfigs(before, after)` | Compare two policy configurations |

### Approval Management

| Method | Description |
|--------|-------------|
| `listPendingApprovals()` | List pending approvals |
| `approveApproval(id, reason)` | Approve a pending approval by ID |
| `denyApproval(id, reason)` | Deny a pending approval by ID |

### Discovery

| Method | Description |
|--------|-------------|
| `discover(query, maxResults, tokenBudget)` | Search the tool discovery index |
| `discoveryStats()` | Get discovery index statistics |
| `discoveryReindex()` | Rebuild discovery IDF weights |
| `discoveryTools(serverId, sensitivity)` | List indexed tools with optional filters |

### Projector

| Method | Description |
|--------|-------------|
| `projectorModels()` | List supported projector model families |
| `projectSchema(schema, modelFamily)` | Project canonical schema for a model family |

### Zero-Knowledge Audit

| Method | Description |
|--------|-------------|
| `zkStatus()` | Get the current ZK audit scheduler status |
| `zkProofs(limit, offset)` | List stored ZK batch proofs with pagination |
| `zkVerify(batchId)` | Verify a stored ZK batch proof by batch ID |
| `zkCommitments(from, to)` | List Pedersen commitments for a sequence range |

### Compliance & Evidence

| Method | Description |
|--------|-------------|
| `soc2AccessReview(period, format, agentId)` | Generate a SOC 2 Type II access review report |
| `owaspAsiCoverage()` | Retrieve the OWASP Agentic Security Index coverage report |
| `evidencePack(framework, format)` | Generate a compliance evidence pack for a framework |
| `evidencePackStatus()` | Retrieve available evidence pack frameworks |

### Federation

| Method | Description |
|--------|-------------|
| `federationStatus()` | Get the federation resolver status |
| `federationTrustAnchors(orgId)` | Get configured federation trust anchors |

### Usage & Billing

| Method | Description |
|--------|-------------|
| `usage(tenantId)` | Retrieve current-period usage metrics for a tenant |
| `quotaStatus(tenantId)` | Retrieve quota status (usage vs limits) for a tenant |
| `usageHistory(tenantId, periods)` | Retrieve usage history across billing periods |

## Response Attestation

```java
byte[] key = System.getenv("VELLAVETO_ATTESTATION_SECRET").getBytes();
boolean valid = VellavetoClient.verifyAttestation(response, key);
```

**Security guarantees** (R260): `verifyAttestation()` validates signature is exactly
64 hex characters, checks `instanceof` before casting `version`, `timestamp`,
`trust_tier`, and `scan_passes` fields (prevents `String.valueOf(null)` → `"null"`
string poisoning of the HMAC signing content).

## Client Options

```java
VellavetoClient client = new VellavetoClient.Builder()
    .baseUrl("http://localhost:3000")   // Vellaveto server URL
    .apiKey("your-api-key")             // API key for authentication
    .timeout(Duration.ofSeconds(5))      // Request timeout (default 5s)
    .build();
```

## Development

```bash
# Run tests (120 tests)
mvn test

# Build
mvn package
```

## License

See [LICENSE](LICENSE) and [LICENSING.md](../../LICENSING.md) for package and repository licensing details.
