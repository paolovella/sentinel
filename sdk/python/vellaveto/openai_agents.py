"""
OpenAI Agents SDK integration for Vellaveto.

Provides function calling interception for OpenAI Agents SDK applications.
Evaluates tool/function calls against Vellaveto policies before execution.

Example:
    from openai import OpenAI
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
"""

import logging
import threading
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from vellaveto.client import ApprovalRequired, PolicyDenied, VellavetoClient
from vellaveto.types import EvaluationContext, Verdict

logger = logging.getLogger(__name__)

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


class VellavetoAgentGuard:
    """
    Policy enforcement guard for OpenAI Agents SDK.

    Wraps function tools with Vellaveto policy evaluation. Each function
    call is evaluated before execution, and denied actions raise
    PolicyDenied to prevent the tool from running.

    Args:
        client: VellavetoClient instance for policy evaluation.
        session_id: Optional session identifier for audit correlation.
        agent_id: Optional agent identifier.
        tenant_id: Optional tenant identifier.
        raise_on_deny: If True (default), raises PolicyDenied on deny.
        metadata: Additional metadata for evaluation context.
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
        with self._lock:
            self._call_chain.append(entry[:MAX_FIELD_LENGTH])
            if len(self._call_chain) > MAX_CALL_CHAIN:
                self._call_chain = self._call_chain[-MAX_CALL_CHAIN:]

    def _get_chain(self) -> List[str]:
        with self._lock:
            return list(self._call_chain)

    def _build_context(
        self, agent_name: Optional[str] = None
    ) -> EvaluationContext:
        meta = dict(self._metadata)
        if agent_name:
            meta["openai_agent"] = agent_name[:MAX_FIELD_LENGTH]
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

    def evaluate_call(
        self,
        tool_name: str,
        function_name: str,
        arguments: Dict[str, Any],
        *,
        agent_name: Optional[str] = None,
    ) -> None:
        """
        Evaluate a function call against Vellaveto policies.

        Args:
            tool_name: Tool name (typically the function's qualified name).
            function_name: Function name being called.
            arguments: Function call arguments.
            agent_name: Optional agent name for context.

        Raises:
            PolicyDenied: If the policy denies the action.
            ApprovalRequired: If the action requires human approval.
        """
        paths, domains = self._extract_targets(arguments)
        ctx = self._build_context(agent_name=agent_name)

        result = self._client.evaluate(
            tool=tool_name,
            function=function_name,
            parameters=arguments,
            target_paths=paths,
            target_domains=domains,
            context=ctx,
        )

        self._append_chain(function_name)

        if result.verdict == Verdict.DENY:
            logger.warning(
                "OpenAI agent tool call denied: fn=%s reason=%s",
                function_name,
                result.reason,
            )
            if self._raise_on_deny:
                raise PolicyDenied(result.reason or "Policy denied")
        elif result.verdict == Verdict.REQUIRE_APPROVAL:
            logger.info(
                "OpenAI agent tool call requires approval: fn=%s",
                function_name,
            )
            if self._raise_on_deny:
                raise ApprovalRequired(
                    result.reason or "Approval required",
                    result.approval_id or "unknown",
                )

    def wrap_function(
        self,
        func: Callable[..., Any],
        *,
        tool_name: Optional[str] = None,
        agent_name: Optional[str] = None,
    ) -> Callable[..., Any]:
        """
        Wrap a function tool with Vellaveto policy enforcement.

        Works with OpenAI Agents SDK function tools. The wrapper evaluates
        the function call before execution. If the policy denies the action,
        the function is not called.

        Args:
            func: The function to wrap.
            tool_name: Override for the tool name (defaults to module.function).
            agent_name: Optional agent name for context.

        Returns:
            Wrapped function with policy enforcement.
        """
        guard = self
        _tool_name: str = tool_name or str(
            getattr(func, "__qualname__", func.__name__)
        )
        fn_name = func.__name__
        _agent_name = agent_name

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            guard.evaluate_call(
                _tool_name,
                fn_name,
                kwargs,
                agent_name=_agent_name,
            )
            return func(*args, **kwargs)

        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        wrapper.__qualname__ = getattr(func, "__qualname__", func.__name__)
        # Preserve OpenAI function tool metadata
        for attr in ("__annotations__", "name", "description", "parameters"):
            if hasattr(func, attr):
                setattr(wrapper, attr, getattr(func, attr))
        return wrapper

    def wrap_tools(
        self,
        tools: List[Callable[..., Any]],
        *,
        agent_name: Optional[str] = None,
    ) -> List[Callable[..., Any]]:
        """
        Wrap multiple function tools with policy enforcement.

        Args:
            tools: List of function tools.
            agent_name: Optional agent name for context.

        Returns:
            New list with all tools wrapped.
        """
        return [self.wrap_function(t, agent_name=agent_name) for t in tools]
