# Vellaveto Python SDK

Python SDK for the [Vellaveto agent interaction firewall](https://github.com/paolovella/vellaveto).

## Installation

```bash
# Basic installation
pip install vellaveto-sdk

# With LangChain support
pip install vellaveto-sdk[langchain]

# With LangGraph support
pip install vellaveto-sdk[langgraph]

# With CrewAI support
pip install vellaveto-sdk[crewai]

# With Google ADK support
pip install vellaveto-sdk[google-adk]

# With OpenAI Agents SDK support
pip install vellaveto-sdk[openai-agents]

# With Composio support
pip install vellaveto-sdk[composio]

# Full installation (all integrations)
pip install vellaveto-sdk[all]
```

## Quick Start

### Direct API Usage

```python
from vellaveto import VellavetoClient, Verdict

client = VellavetoClient(url="http://localhost:3000", api_key="your-key")

# Evaluate a tool call
result = client.evaluate(
    tool="filesystem",
    function="read_file",
    parameters={"path": "/etc/passwd"}
)

if result.verdict == Verdict.ALLOW:
    # Proceed with tool call
    content = read_file("/etc/passwd")
elif result.verdict == Verdict.DENY:
    print(f"Blocked: {result.reason}")
elif result.verdict == Verdict.REQUIRE_APPROVAL:
    print(f"Needs approval: {result.approval_id}")
```

### With Exception Handling

```python
from vellaveto import VellavetoClient, PolicyDenied, ApprovalRequired

client = VellavetoClient(url="http://localhost:3000")

try:
    client.evaluate_or_raise(
        tool="http",
        function="fetch",
        parameters={"url": "https://evil.com/exfil"}
    )
    # Allowed - proceed
except PolicyDenied as e:
    print(f"Blocked by policy: {e.reason}")
except ApprovalRequired as e:
    print(f"Needs approval: {e.approval_id}")
```

### Async Usage

```python
from vellaveto import AsyncVellavetoClient

async with AsyncVellavetoClient(url="http://localhost:3000") as client:
    result = await client.evaluate(
        tool="bash",
        function="execute",
        parameters={"command": "rm -rf /"}
    )
```

## LangChain Integration

### Callback Handler

The `VellavetoCallbackHandler` automatically intercepts and evaluates all tool calls:

```python
from langchain.agents import create_react_agent
from langchain_openai import ChatOpenAI
from vellaveto import VellavetoClient
from vellaveto.langchain import VellavetoCallbackHandler

client = VellavetoClient(url="http://localhost:3000")
handler = VellavetoCallbackHandler(
    client=client,
    session_id="my-session",
    raise_on_deny=True,
)

llm = ChatOpenAI()
agent = create_react_agent(llm, tools, callbacks=[handler])

# All tool calls will be evaluated by Vellaveto
result = agent.invoke({"input": "Read the file /etc/passwd"})
```

### Tool Decorator

Guard individual tools with the `@guard` decorator:

```python
from langchain.tools import tool
from vellaveto import VellavetoClient
from vellaveto.langchain import VellavetoToolGuard

client = VellavetoClient(url="http://localhost:3000")
guard = VellavetoToolGuard(client)

@tool
@guard("filesystem", "read_file")
def read_file(path: str) -> str:
    """Read a file from the filesystem."""
    with open(path) as f:
        return f.read()
```

### Wrap Existing Toolkits

```python
from langchain_community.agent_toolkits import FileManagementToolkit
from vellaveto import VellavetoClient
from vellaveto.langchain import create_guarded_toolkit

client = VellavetoClient(url="http://localhost:3000")
toolkit = FileManagementToolkit()
guarded_tools = create_guarded_toolkit(client, toolkit)
```

## LangGraph Integration

### Vellaveto Node

Add a vellaveto evaluation node to your graph:

```python
from langgraph.graph import StateGraph, END
from vellaveto import VellavetoClient
from vellaveto.langgraph import create_vellaveto_node, VellavetoState

client = VellavetoClient(url="http://localhost:3000")
vellaveto_node = create_vellaveto_node(client, on_deny="block")

class MyState(VellavetoState):
    messages: list
    # ... your fields

graph = StateGraph(MyState)
graph.add_node("plan", plan_node)
graph.add_node("vellaveto", vellaveto_node)
graph.add_node("tools", tool_node)

graph.add_edge("plan", "vellaveto")
graph.add_conditional_edges(
    "vellaveto",
    lambda s: "blocked" if s.get("tool_blocked") else "allowed",
    {"blocked": END, "allowed": "tools"},
)
```

### Guarded Tool Node

Combine tool execution with policy evaluation:

```python
from langgraph.graph import StateGraph
from vellaveto import VellavetoClient
from vellaveto.langgraph import create_vellaveto_tool_node

client = VellavetoClient(url="http://localhost:3000")
tool_node = create_vellaveto_tool_node(client, [read_file, write_file])

graph = StateGraph(MyState)
graph.add_node("tools", tool_node)  # Policy evaluation + execution
```

## CrewAI Integration

Guard tool calls in CrewAI crews with `VellavetoCrewGuard`:

```python
from crewai import Agent, Crew, Task
from vellaveto import VellavetoClient
from vellaveto.crewai import VellavetoCrewGuard

client = VellavetoClient(url="http://localhost:3000")
guard = VellavetoCrewGuard(client)

agent = Agent(role="researcher", tools=[web_search])
task = Task(description="Research topic", agent=agent)
crew = Crew(agents=[agent], tasks=[task])

# Option 1: Wrap entire crew execution
result = guard.kickoff(crew)

# Option 2: Wrap individual tools
guarded_tool = guard.wrap_tool(web_search)
```

## Google ADK Integration

Guard tools in Google Agent Development Kit applications with `VellavetoADKGuard`:

```python
from google.adk import Agent
from vellaveto import VellavetoClient
from vellaveto.google_adk import VellavetoADKGuard

client = VellavetoClient(url="http://localhost:3000")
guard = VellavetoADKGuard(client)

# Option 1: Decorator
@guard.protect
def search_web(query: str) -> str:
    return do_search(query)

# Option 2: Before-tool callback
agent = Agent(
    tools=[search_web],
    before_tool_call=guard.before_tool_callback(),
)
```

## OpenAI Agents SDK Integration

Enforce policies on OpenAI Agents SDK function calls with `VellavetoAgentGuard`:

```python
from agents import Agent, Runner
from vellaveto import VellavetoClient
from vellaveto.openai_agents import VellavetoAgentGuard

client = VellavetoClient(url="http://localhost:3000")
guard = VellavetoAgentGuard(client)

# Wrap tools with policy enforcement
agent = Agent(
    name="assistant",
    tools=[guard.wrap_function(read_file), guard.wrap_function(web_search)],
)
result = Runner.run_sync(agent, "Read the config file")
```

## Composio Integration

Guard Composio tool calls across any provider (OpenAI, LangChain, CrewAI, AutoGen) with `ComposioGuard`:

```python
from composio import Composio
from vellaveto import VellavetoClient
from vellaveto.composio import ComposioGuard

client = VellavetoClient(url="http://localhost:3000", api_key="key")
guard = ComposioGuard(client, session_id="sess-1")

composio = Composio(api_key="...")
tools = composio.tools.get(
    user_id="default",
    toolkits=["GITHUB"],
    modifiers=[guard.before_execute_modifier(), guard.after_execute_modifier()],
)
```

## Claude Agent SDK Integration

Enforce tool permissions in Anthropic Claude Agent SDK applications with `VellavetoToolPermission`:

```python
from claude_agent_sdk import Agent, tool
from vellaveto import VellavetoClient
from vellaveto.claude_agent import VellavetoToolPermission

client = VellavetoClient(url="http://localhost:3000")
permission = VellavetoToolPermission(client)

@tool
def read_file(path: str) -> str:
    return open(path).read()

agent = Agent(
    tools=[read_file],
    tool_permission_callback=permission.check,
)
```

## AWS Strands Agents Integration

Guard tool calls in AWS Strands Agents applications with `VellavetoStrandsGuard`:

```python
from strands import Agent
from strands.tools import tool
from vellaveto import VellavetoClient
from vellaveto.strands import VellavetoStrandsGuard

client = VellavetoClient(url="http://localhost:3000")
guard = VellavetoStrandsGuard(client)

@tool
def read_file(path: str) -> str:
    return open(path).read()

agent = Agent(
    tools=[guard.wrap_tool(read_file)],
)
```

## Microsoft Agent Framework Integration

Intercept tool calls in Microsoft Agent Framework (AutoGen + Semantic Kernel) with `VellavetoAgentMiddleware`:

```python
from vellaveto import VellavetoClient
from vellaveto.microsoft_agents import VellavetoAgentMiddleware

client = VellavetoClient(url="http://localhost:3000")
middleware = VellavetoAgentMiddleware(client)

# Use as middleware in Microsoft Agent Framework
agent = Agent(
    middleware=[middleware],
    tools=[read_file, web_search],
)
```

## Parameter Redaction

Strip sensitive parameter values before they transit the network to Vellaveto:

```python
from vellaveto import VellavetoClient, ParameterRedactor

# Keys-only (default): redacts values for known sensitive parameter names
redactor = ParameterRedactor()

# Values: also scans string values for secret patterns (sk-..., ghp_..., JWTs)
redactor = ParameterRedactor(mode="values")

# All: redacts every parameter value (sends only keys to Vellaveto)
redactor = ParameterRedactor(mode="all")

# Custom sensitive keys (added to defaults)
redactor = ParameterRedactor(extra_keys={"internal_token", "vault_path"})

client = VellavetoClient(url="http://localhost:3000", redactor=redactor)

# api_key value is replaced with "[REDACTED]" before sending
client.evaluate(
    tool="http",
    function="fetch",
    parameters={"url": "https://api.example.com", "api_key": "sk-secret123"},
)
```

## Configuration

### Client Options

```python
client = VellavetoClient(
    url="http://localhost:3000",  # Vellaveto server URL
    api_key="your-api-key",       # API key for authentication
    timeout=30.0,                  # Request timeout in seconds
    verify_ssl=True,               # Verify SSL certificates
    redactor=ParameterRedactor(),  # Client-side parameter redaction (optional)
)
```

### Evaluation Context

Provide context for stateful policy evaluation:

```python
from vellaveto.types import EvaluationContext

context = EvaluationContext(
    session_id="user-session-123",
    agent_id="my-agent",
    tenant_id="tenant-abc",
    call_chain=["tool1", "tool2"],
    metadata={"user": "alice"},
)

result = client.evaluate(
    tool="filesystem",
    function="write_file",
    parameters={"path": "/tmp/output.txt", "content": "data"},
    context=context,
)
```

## API Reference

### VellavetoClient

| Method | Description |
|--------|-------------|
| `evaluate()` | Evaluate a tool call against policies |
| `evaluate_or_raise()` | Evaluate and raise on denial |
| `health()` | Check server health |
| `list_policies()` | List configured policies |
| `reload_policies()` | Reload policies from config |
| `get_pending_approvals()` | Get pending approval requests |
| `resolve_approval()` | Approve or deny a request |
| `discover()` | Search the tool discovery index |
| `discovery_stats()` | Get discovery index statistics |
| `discovery_reindex()` | Rebuild discovery IDF weights |
| `discovery_tools()` | List indexed tools with optional filters |
| `projector_models()` | List supported projector model families |
| `project_schema()` | Project canonical schema for a model family |
| **ZK Audit** | |
| `zk_status()` | Get ZK audit scheduler status |
| `zk_proofs(limit, offset)` | List stored ZK batch proofs with pagination |
| `zk_verify(batch_id)` | Verify a stored ZK batch proof |
| **Compliance** | |
| `owasp_asi_coverage()` | Get OWASP Agentic Security Index coverage report |
| `evidence_pack_status()` | Get evidence pack status and available frameworks |
| **Federation** | |
| `federation_status()` | Get federation status including per-anchor cache info |
| **Billing** | |
| `usage(tenant_id)` | Get current-period usage metrics for a tenant |
| `quota_status(tenant_id)` | Get quota status (usage vs limits) for a tenant |
| `usage_history(tenant_id, periods)` | Get usage history across billing periods for a tenant |

### Types

| Type | Description |
|------|-------------|
| `Verdict` | Policy decision (ALLOW, DENY, REQUIRE_APPROVAL) |
| `Action` | Tool call representation |
| `EvaluationResult` | Policy evaluation result |
| `EvaluationContext` | Context for stateful evaluation |

### Exceptions

| Exception | Description |
|-----------|-------------|
| `VellavetoError` | Base exception |
| `PolicyDenied` | Action denied by policy |
| `ApprovalRequired` | Action requires human approval |
| `ConnectionError` | Failed to connect to server |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy vellaveto

# Linting
ruff check vellaveto
```

## License

See [LICENSE](LICENSE) and [LICENSING.md](../../LICENSING.md) for package and repository licensing details.
