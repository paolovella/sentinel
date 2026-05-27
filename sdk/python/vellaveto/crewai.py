"""
CrewAI integration for Vellaveto.

Provides crew-level and agent-level policy enforcement for CrewAI applications.
Intercepts tool calls before execution and blocks denied actions.

Example:
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
"""

import logging
import threading
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from vellaveto.client import ApprovalRequired, PolicyDenied, VellavetoClient
from vellaveto.types import EvaluationContext, Verdict

logger = logging.getLogger(__name__)

# Path/domain heuristic keys (shared with Composio extractor)
_PATH_KEYS = frozenset({
    "path", "file", "filepath", "file_path", "filename", "directory",
    "dir", "folder", "src", "dst", "source", "destination", "output",
    "input", "location", "target",
})
_DOMAIN_KEYS = frozenset({
    "url", "uri", "endpoint", "host", "domain", "api_url", "base_url",
    "webhook_url", "server", "address",
})

MAX_CALL_CHAIN = 20
MAX_FIELD_LENGTH = 256


class VellavetoCrewGuard:
    """
    Policy enforcement guard for CrewAI crews.

    Intercepts tool calls made by CrewAI agents, evaluates them against
    Vellaveto policies, and blocks denied actions. Supports both crew-level
    wrapping and individual tool wrapping.

    Args:
        client: VellavetoClient instance for policy evaluation.
        session_id: Optional session identifier for audit correlation.
        agent_id: Optional agent identifier.
        tenant_id: Optional tenant identifier for multi-tenant deployments.
        raise_on_deny: If True (default), raises PolicyDenied on deny verdict.
        metadata: Additional metadata to include in evaluation context.
    """

    def __init__(
        self,
        client: VellavetoClient,
        *,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        raise_on_deny: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._client = client
        self._session_id = session_id
        self._agent_id = agent_id
        self._tenant_id = tenant_id
        self._raise_on_deny = raise_on_deny
        self._metadata = metadata or {}
        self._call_chain: List[str] = []
        self._lock = threading.Lock()

    def _append_chain(self, entry: str) -> None:
        """Thread-safe call chain append with FIFO eviction."""
        with self._lock:
            self._call_chain.append(entry[:MAX_FIELD_LENGTH])
            if len(self._call_chain) > MAX_CALL_CHAIN:
                self._call_chain = self._call_chain[-MAX_CALL_CHAIN:]

    def _get_chain(self) -> List[str]:
        """Thread-safe call chain snapshot."""
        with self._lock:
            return list(self._call_chain)

    def _build_context(self, agent_role: Optional[str] = None) -> EvaluationContext:
        """Build evaluation context with current state."""
        meta = dict(self._metadata)
        if agent_role:
            meta["crewai_role"] = agent_role[:MAX_FIELD_LENGTH]
        return EvaluationContext(
            session_id=self._session_id,
            agent_id=self._agent_id,
            tenant_id=self._tenant_id,
            call_chain=self._get_chain(),
            metadata=meta,
        )

    def _extract_targets(
        self, params: Dict[str, Any]
    ) -> tuple:
        """Extract target paths and domains from tool parameters."""
        paths: List[str] = []
        domains: List[str] = []
        for key, value in params.items():
            if not isinstance(value, str):
                continue
            k = key.lower()
            if k in _PATH_KEYS:
                paths.append(value)
            elif k in _DOMAIN_KEYS:
                domains.append(value)
            else:
                parsed = urlparse(value)
                if parsed.scheme in ("http", "https", "ftp") and parsed.netloc:
                    domains.append(value)
                elif parsed.scheme == "file":
                    paths.append(value)
        return paths[:100], domains[:100]

    def evaluate_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        *,
        agent_role: Optional[str] = None,
    ) -> None:
        """
        Evaluate a tool call against Vellaveto policies.

        Raises PolicyDenied or ApprovalRequired on non-allow verdicts
        when raise_on_deny is True.

        Args:
            tool_name: Name of the tool being called.
            arguments: Tool call arguments.
            agent_role: Optional CrewAI agent role for context.
        """
        paths, domains = self._extract_targets(arguments)
        ctx = self._build_context(agent_role=agent_role)

        result = self._client.evaluate(
            tool=tool_name,
            function="execute",
            parameters=arguments,
            target_paths=paths,
            target_domains=domains,
            context=ctx,
        )

        # Append to call chain AFTER evaluation (not before)
        self._append_chain(tool_name)

        if result.verdict == Verdict.DENY:
            logger.warning(
                "CrewAI tool call denied: tool=%s reason=%s",
                tool_name,
                result.reason,
            )
            if self._raise_on_deny:
                raise PolicyDenied(result.reason or "Policy denied")
        elif result.verdict == Verdict.REQUIRE_APPROVAL:
            logger.info(
                "CrewAI tool call requires approval: tool=%s approval_id=%s",
                tool_name,
                result.approval_id,
            )
            if self._raise_on_deny:
                raise ApprovalRequired(
                    result.reason or "Approval required",
                    result.approval_id or "unknown",
                )

    def wrap_tool(self, tool_func: Callable[..., Any]) -> Callable[..., Any]:
        """
        Wrap a CrewAI tool function with policy enforcement.

        The wrapper evaluates the tool call before execution. If the policy
        denies the action, PolicyDenied is raised and the tool is not called.

        Args:
            tool_func: The original tool function to wrap.

        Returns:
            A wrapped function with policy enforcement.
        """
        guard = self
        tool_name: str = str(
            getattr(tool_func, "name", None)
            or getattr(tool_func, "__name__", "unknown_tool")
        )

        def guarded(*args: Any, **kwargs: Any) -> Any:
            guard.evaluate_tool_call(tool_name, kwargs)
            return tool_func(*args, **kwargs)

        # Preserve tool metadata for CrewAI
        guarded.__name__ = getattr(tool_func, "__name__", "guarded_tool")
        guarded.__doc__ = getattr(tool_func, "__doc__", None)
        for attr in ("name", "description", "args_schema"):
            if hasattr(tool_func, attr):
                setattr(guarded, attr, getattr(tool_func, attr))

        return guarded

    def guard_agent_tools(self, tools: List[Any]) -> List[Any]:
        """
        Wrap all tools in a list with policy enforcement.

        Args:
            tools: List of CrewAI tool objects or functions.

        Returns:
            New list with all tools wrapped.
        """
        return [self.wrap_tool(t) for t in tools]
