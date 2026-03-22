# Vellaveto TypeScript SDK

TypeScript/JavaScript client for the [Vellaveto](https://github.com/paolovella/vellaveto) agent interaction firewall API.

## Installation

```bash
npm install @vellaveto-sdk/typescript
```

## Quick Start

```typescript
import { VellavetoClient, Verdict } from '@vellaveto-sdk/typescript';

const client = new VellavetoClient({
  baseUrl: 'http://localhost:3000',
  apiKey: 'your-api-key',
});

// Evaluate a tool call
const result = await client.evaluate({
  tool: 'filesystem',
  function: 'read_file',
  parameters: { path: '/etc/passwd' },
});

if (result.verdict === Verdict.Allow) {
  // Proceed with tool call
} else if (result.verdict === Verdict.Deny) {
  console.log(`Blocked: ${result.reason}`);
} else if (result.verdict === Verdict.RequireApproval) {
  console.log(`Needs approval: ${result.approvalId}`);
}
```

### With Exception Handling

```typescript
import { VellavetoClient, PolicyDenied, ApprovalRequired } from '@vellaveto-sdk/typescript';

const client = new VellavetoClient({ baseUrl: 'http://localhost:3000' });

try {
  await client.evaluateOrRaise({
    tool: 'http',
    function: 'fetch',
    parameters: { url: 'https://evil.com/exfil' },
  });
} catch (e) {
  if (e instanceof PolicyDenied) {
    console.log(`Denied: ${e.reason}`);
  } else if (e instanceof ApprovalRequired) {
    console.log(`Needs approval: ${e.approvalId}`);
  }
}
```

### With Evaluation Context

```typescript
const result = await client.evaluate(
  {
    tool: 'filesystem',
    function: 'write_file',
    parameters: { path: '/tmp/out.txt', content: 'data' },
  },
  {
    sessionId: 'user-session-123',
    agentId: 'my-agent',
    tenantId: 'tenant-abc',
    callChain: ['tool1', 'tool2'],
  },
);
```

## Claude Agent SDK Integration

The SDK includes a `VellavetoToolPermission` class that integrates with the Anthropic Claude Agent SDK's `toolPermissionCallback`:

```typescript
import { VellavetoClient } from '@vellaveto-sdk/typescript';
import { VellavetoToolPermission } from '@vellaveto-sdk/typescript/claude-agent';
import { Agent } from '@anthropic-ai/agent';

const client = new VellavetoClient({ baseUrl: 'http://localhost:3000' });
const permission = new VellavetoToolPermission(client, {
  sessionId: 'session-001',
  agentId: 'my-agent',
  denyOnError: true, // fail-closed (default)
});

const agent = new Agent({
  tools: [readFile, webSearch, executeCommand],
  toolPermissionCallback: (name, args) => permission.check(name, args),
});

// Every tool call is evaluated against Vellaveto policies before execution.
// Dangerous calls (credential access, exfiltration, destructive commands)
// are blocked automatically.
const result = await agent.run('Analyze the project structure');
```

### Filter Available Tools

Pre-filter tools to only those currently allowed by policy:

```typescript
const allTools = ['read_file', 'write_file', 'execute', 'web_search'];
const allowed = await permission.filterAllowedTools(allTools);
// allowed: ['read_file', 'web_search'] (if write/execute are denied)
```

### Wrap Individual Tools

Add policy enforcement to any function:

```typescript
const safeReadFile = permission.wrapTool(readFile, 'filesystem.read_file');

try {
  const content = await safeReadFile({ path: '/tmp/notes.txt' }); // allowed
  const secrets = await safeReadFile({ path: '/home/user/.aws/credentials' }); // throws PolicyDenied
} catch (e) {
  if (e instanceof PolicyDenied) {
    console.log(`Blocked: ${e.message}`);
  }
}
```

## Vercel AI SDK Integration

Guard tool calls in a Vercel AI SDK application:

```typescript
import { VellavetoClient, PolicyDenied } from '@vellaveto-sdk/typescript';
import { generateText, tool } from 'ai';
import { openai } from '@ai-sdk/openai';
import { z } from 'zod';

const vellaveto = new VellavetoClient({ baseUrl: 'http://localhost:3000' });

const readFile = tool({
  description: 'Read a file from the filesystem',
  parameters: z.object({ path: z.string() }),
  execute: async ({ path }) => {
    // Evaluate before execution
    await vellaveto.evaluateOrRaise({
      tool: 'filesystem',
      function: 'read_file',
      parameters: { path },
      targetPaths: [path],
    });
    return fs.readFileSync(path, 'utf-8');
  },
});

const result = await generateText({
  model: openai('gpt-4o'),
  tools: { readFile },
  prompt: 'Read the project README',
});
```

## Express/Koa Middleware Pattern

Enforce policies on HTTP endpoints that proxy tool calls:

```typescript
import express from 'express';
import { VellavetoClient, Verdict } from '@vellaveto-sdk/typescript';

const app = express();
const vellaveto = new VellavetoClient({ baseUrl: 'http://localhost:3000' });

// Middleware: evaluate tool calls before forwarding
app.use('/api/tools/:tool', async (req, res, next) => {
  const result = await vellaveto.evaluate({
    tool: req.params.tool,
    function: req.body.function ?? '*',
    parameters: req.body.parameters ?? {},
  });

  if (result.verdict !== Verdict.Allow) {
    return res.status(403).json({
      error: 'Policy denied',
      reason: result.reason,
    });
  }
  next();
});
```

## API Reference

| Method | Description |
|--------|-------------|
| `evaluate()` | Evaluate a tool call against policies |
| `evaluateOrRaise()` | Evaluate and throw on denial |
| `health()` | Check server health |
| `listPolicies()` | List configured policies |
| `reloadPolicies()` | Reload policies from config |
| `listPendingApprovals()` | Get pending approval requests |
| `approveApproval()` | Approve a pending request |
| `denyApproval()` | Deny a pending request |
| `discover()` | Search the tool discovery index |
| `discoveryStats()` | Get discovery index statistics |
| `discoveryReindex()` | Rebuild discovery IDF weights |
| `discoveryTools()` | List indexed tools with optional filters |
| `projectorModels()` | List supported projector model families |
| `projectSchema()` | Project canonical schema for a model family |
| **Simulator** | |
| `simulate()` | Simulate a single action evaluation with full trace |
| `batchEvaluate()` | Batch-evaluate multiple actions |
| `validateConfig()` | Validate a policy configuration string |
| `diffConfigs()` | Diff two policy configurations |
| **ZK Audit** | |
| `zkStatus()` | Get the ZK audit scheduler status |
| `zkProofs()` | List stored ZK batch proofs with optional pagination |
| `zkVerify()` | Verify a stored ZK batch proof by batch ID |
| `zkCommitments()` | List Pedersen commitments for audit entries in a sequence range |
| **Compliance** | |
| `soc2AccessReview()` | Generate a SOC 2 Type II access review report |
| `owaspAsiCoverage()` | Get OWASP Agentic Security Index (ASI) coverage report |
| `evidencePack()` | Generate a compliance evidence pack for a specified framework |
| `evidencePackStatus()` | Get evidence pack status — which frameworks are available |
| **Federation** | |
| `federationStatus()` | Get federation status including per-anchor cache info |
| `federationTrustAnchors()` | List federation trust anchors, optionally filtered by org ID |
| **Billing & Usage** | |
| `usage()` | Get current-period usage metrics for a tenant |
| `quotaStatus()` | Get quota status (usage vs limits) for a tenant |
| `usageHistory()` | Get usage history across billing periods for a tenant |

## Client Options

```typescript
const client = new VellavetoClient({
  baseUrl: 'http://localhost:3000', // Vellaveto server URL
  apiKey: 'your-api-key',           // API key for authentication
  timeout: 5000,                     // Request timeout in ms (default 5000)
  headers: {                         // Extra headers
    'X-Tenant-ID': 'acme',
  },
});
```

## Development

```bash
npm install
npm test       # 119 tests
npm run build
```

## License

See [LICENSE](LICENSE) and [LICENSING.md](../../LICENSING.md) for package and repository licensing details.
