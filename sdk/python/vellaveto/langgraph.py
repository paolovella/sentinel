"""
LangGraph integration for Vellaveto.

Provides nodes and state management for integrating Vellaveto policy
enforcement into LangGraph agent workflows.

Example:
    from langgraph.graph import StateGraph
    from vellaveto import VellavetoClient
    from vellaveto.langgraph import create_vellaveto_node, VellavetoState

    client = VellavetoClient(url="http://localhost:3000")
    vellaveto_node = create_vellaveto_node(client)

    # Add to your graph
    graph = StateGraph(VellavetoState)
    graph.add_node("vellaveto", vellaveto_node)
"""

import logging
from typing import Any, Callable, Dict, List, Optional, TypedDict, cast
from urllib.parse import urlparse

from vellaveto.client import VellavetoClient, PolicyDenied, ApprovalRequired
from vellaveto.types import EvaluationContext, Verdict

logger = logging.getLogger(__name__)

# Check for LangGraph availability
try:
    from langgraph.prebuilt import ToolNode
    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False


class VellavetoState(TypedDict, total=False):
    """
    State schema for Vellaveto integration in LangGraph.

    Add these fields to your graph state to enable Vellaveto integration.

    Example:
        from typing import TypedDict, List
        from vellaveto.langgraph import VellavetoState

        class MyAgentState(VellavetoState):
            messages: List[BaseMessage]
            # ... your other state fields
    """

    # Vellaveto evaluation results
    vellaveto_verdict: Optional[str]
    vellaveto_reason: Optional[str]
    vellaveto_policy_id: Optional[str]
    vellaveto_approval_id: Optional[str]

    # Context tracking
    vellaveto_session_id: Optional[str]
    vellaveto_agent_id: Optional[str]
    vellaveto_call_chain: List[str]

    # Pending tool call (set before vellaveto node, cleared after)
    pending_tool_name: Optional[str]
    pending_tool_input: Optional[Dict[str, Any]]

    # Block flag (set by vellaveto node if tool is denied)
    tool_blocked: bool


def create_vellaveto_node(
    client: VellavetoClient,
    on_deny: str = "block",
    on_approval_required: str = "block",
) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """
    Create a LangGraph node for Vellaveto policy evaluation.

    This node should be placed before the tool execution node in your graph.
    It evaluates the pending tool call and either allows it to proceed or
    blocks execution.

    Example:
        from langgraph.graph import StateGraph, END
        from vellaveto import VellavetoClient
        from vellaveto.langgraph import create_vellaveto_node

        client = VellavetoClient(url="http://localhost:3000")
        vellaveto_node = create_vellaveto_node(client, on_deny="block")

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

    Args:
        client: VellavetoClient instance
        on_deny: Action on denial - "block" (default) or "continue"
        on_approval_required: Action on approval required - "block" or "continue"

    Returns:
        A LangGraph node function
    """

    def vellaveto_node(state: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate pending tool call against Vellaveto policies."""
        tool_name = state.get("pending_tool_name")
        tool_input = state.get("pending_tool_input", {})

        if not tool_name:
            # No pending tool call - pass through
            return {"tool_blocked": False}

        # Build context from state
        context = EvaluationContext(
            session_id=state.get("vellaveto_session_id"),
            agent_id=state.get("vellaveto_agent_id"),
            call_chain=state.get("vellaveto_call_chain", []),
        )

        # Extract paths and domains from tool input
        target_paths = []
        target_domains = []

        if isinstance(tool_input, dict):
            for key, value in tool_input.items():
                if isinstance(value, str):
                    if key in ("path", "file", "filepath", "directory"):
                        target_paths.append(value)
                    elif key in ("url", "uri", "endpoint", "domain"):
                        target_domains.append(value)
                    else:
                        parsed = urlparse(value)
                        if parsed.scheme in ("http", "https", "ftp") and parsed.netloc:
                            target_domains.append(value)

        try:
            result = client.evaluate(
                tool=tool_name,
                function=tool_name,
                parameters=tool_input if isinstance(tool_input, dict) else {"input": tool_input},
                target_paths=target_paths,
                target_domains=target_domains,
                context=context,
            )

            # Update call chain
            # SECURITY (FIND-SDK-010): Bound call chain at 20 entries using slice
            call_chain = state.get("vellaveto_call_chain", []).copy()
            call_chain.append(tool_name)
            call_chain = call_chain[-20:]

            # Determine if blocked
            blocked = False
            if result.verdict == Verdict.DENY:
                if on_deny == "block":
                    blocked = True
                    logger.warning(f"Tool {tool_name} blocked by policy: {result.reason}")
                else:
                    # SECURITY (FIND-SDK-009): Warn when denied tool proceeds
                    logger.warning(
                        f"Tool {tool_name} denied but proceeding (on_deny='continue'): "
                        f"{result.reason}"
                    )
            elif result.verdict == Verdict.REQUIRE_APPROVAL:
                if on_approval_required == "block":
                    blocked = True
                    logger.warning(f"Tool {tool_name} requires approval: {result.reason}")
                else:
                    logger.warning(
                        f"Tool {tool_name} requires approval but proceeding "
                        f"(on_approval_required='continue'): {result.reason}"
                    )

            return {
                "vellaveto_verdict": result.verdict.value,
                "vellaveto_reason": result.reason,
                "vellaveto_policy_id": result.policy_id,
                "vellaveto_approval_id": result.approval_id,
                "vellaveto_call_chain": call_chain,
                "tool_blocked": blocked,
            }

        except Exception as e:
            logger.error(f"Vellaveto evaluation failed: {e}")
            # Fail-closed
            return {
                "vellaveto_verdict": "deny",
                "vellaveto_reason": f"Evaluation error: {e}",
                "tool_blocked": on_deny == "block",
            }

    return vellaveto_node


def create_vellaveto_tool_node(
    client: VellavetoClient,
    tools: List[Any],
    session_id: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """
    Create a LangGraph tool node with built-in Vellaveto evaluation.

    This combines tool execution with policy evaluation in a single node,
    eliminating the need for a separate vellaveto node.

    Example:
        from langgraph.graph import StateGraph
        from langchain_core.tools import tool
        from vellaveto import VellavetoClient
        from vellaveto.langgraph import create_vellaveto_tool_node

        @tool
        def read_file(path: str) -> str:
            '''Read a file.'''
            return open(path).read()

        client = VellavetoClient(url="http://localhost:3000")
        tool_node = create_vellaveto_tool_node(client, [read_file])

        graph = StateGraph(MyState)
        graph.add_node("tools", tool_node)

    Args:
        client: VellavetoClient instance
        tools: List of LangChain tools
        session_id: Session ID for stateful evaluation
        agent_id: Agent ID for agent-specific policies

    Returns:
        A LangGraph tool node function with Vellaveto guards
    """
    if not HAS_LANGGRAPH:
        raise ImportError(
            "LangGraph is required. Install with: pip install langgraph"
        )

    # Create base tool node
    base_node = ToolNode(tools)

    def guarded_tool_node(state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tools with Vellaveto policy evaluation."""
        # Get messages from state
        messages = state.get("messages", [])

        if not messages:
            return state

        last_message = messages[-1]

        # Check if it's a tool call message
        if not hasattr(last_message, "tool_calls") or not last_message.tool_calls:
            return state

        # Evaluate each tool call
        for tool_call in last_message.tool_calls:
            tool_name = str(tool_call.get("name", "unknown"))
            tool_input = tool_call.get("args", {})

            context = EvaluationContext(
                session_id=session_id or state.get("vellaveto_session_id"),
                agent_id=agent_id or state.get("vellaveto_agent_id"),
                call_chain=state.get("vellaveto_call_chain", []),
            )

            # Extract paths/domains
            target_paths = []
            target_domains = []
            if isinstance(tool_input, dict):
                for key, value in tool_input.items():
                    if isinstance(value, str):
                        if key in ("path", "file", "filepath"):
                            target_paths.append(value)
                        elif key in ("url", "uri", "domain"):
                            target_domains.append(value)

            try:
                client.evaluate_or_raise(
                    tool=tool_name,
                    function=tool_name,
                    parameters=tool_input,
                    target_paths=target_paths,
                    target_domains=target_domains,
                    context=context,
                )
            except PolicyDenied as e:
                # Return denial as tool message
                from langchain_core.messages import ToolMessage

                return {
                    "messages": [
                        ToolMessage(
                            content=f"Tool call blocked by security policy: {e.reason}",
                            tool_call_id=tool_call.get("id", ""),
                            name=tool_name,
                        )
                    ]
                }
            except ApprovalRequired as e:
                from langchain_core.messages import ToolMessage

                return {
                    "messages": [
                        ToolMessage(
                            content=f"Tool call requires approval (id: {e.approval_id}): {e.reason}",
                            tool_call_id=tool_call.get("id", ""),
                            name=tool_name,
                        )
                    ]
                }

        # All tools allowed - execute with base node
        return cast(Dict[str, Any], base_node(state))

    return guarded_tool_node


class VellavetoCheckpoint:
    """
    LangGraph checkpoint wrapper with Vellaveto session tracking.

    Automatically manages session state across graph checkpoints.

    Example:
        from langgraph.checkpoint import MemorySaver
        from vellaveto import VellavetoClient
        from vellaveto.langgraph import VellavetoCheckpoint

        client = VellavetoClient(url="http://localhost:3000")
        checkpoint = VellavetoCheckpoint(client, MemorySaver())

        graph = graph.compile(checkpointer=checkpoint)
    """

    # SECURITY (FIND-SDK-017): Maximum thread_id length to prevent abuse
    _MAX_THREAD_ID_LEN = 256

    def __init__(
        self,
        client: VellavetoClient,
        base_checkpoint: Any,
    ):
        self.client = client
        self.base = base_checkpoint
        # SECURITY (FIND-SDK-016): Removed unused _sessions dict (dead code)

    def get(self, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get checkpoint state."""
        state = self.base.get(config)
        if state:
            # Inject session ID if not present
            thread_id = config.get("configurable", {}).get("thread_id", "default")
            # SECURITY (FIND-SDK-017): Validate thread_id to prevent injection
            if not isinstance(thread_id, str):
                thread_id = str(thread_id)
            # Sanitize: only allow alphanumeric, dash, underscore, dot
            import re
            if not re.match(r"^[a-zA-Z0-9_.\-]{1,256}$", thread_id):
                thread_id = "invalid"
            if "vellaveto_session_id" not in state:
                state["vellaveto_session_id"] = f"langgraph-{thread_id}"
        return cast(Optional[Dict[str, Any]], state)

    def put(self, config: Dict[str, Any], state: Dict[str, Any]) -> None:
        """Save checkpoint state."""
        self.base.put(config, state)
