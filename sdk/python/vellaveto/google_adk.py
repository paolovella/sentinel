"""
Google ADK (Agent Development Kit) integration for Vellaveto.

Provides tool validation callbacks and decorators for Google ADK agents.
Intercepts function calls before execution and blocks denied actions.

Example:
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


class VellavetoADKGuard:
    """
    Policy enforcement guard for Google ADK agents.

    Evaluates tool calls against Vellaveto policies before execution.
    Supports decorator-based and callback-based integration patterns.

    Args:
        client: VellavetoClient instance for policy evaluation.
        session_id: Optional session identifier for audit correlation.
        agent_id: Optional agent identifier.
        tenant_id: Optional tenant identifier.
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
        with self._lock:
            self._call_chain.append(entry[:MAX_FIELD_LENGTH])
            if len(self._call_chain) > MAX_CALL_CHAIN:
                self._call_chain = self._call_chain[-MAX_CALL_CHAIN:]

    def _get_chain(self) -> List[str]:
        with self._lock:
            return list(self._call_chain)

    def _build_context(self) -> EvaluationContext:
        return EvaluationContext(
            session_id=self._session_id,
            agent_id=self._agent_id,
            tenant_id=self._tenant_id,
            call_chain=self._get_chain(),
            metadata=dict(self._metadata),
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

    def evaluate(
        self,
        tool_name: str,
        function_name: str,
        arguments: Dict[str, Any],
    ) -> None:
        """
        Evaluate a tool call against Vellaveto policies.

        Args:
            tool_name: Name of the tool.
            function_name: Name of the function being called.
            arguments: Function arguments.

        Raises:
            PolicyDenied: If the policy denies the action.
            ApprovalRequired: If the action requires human approval.
        """
        paths, domains = self._extract_targets(arguments)
        ctx = self._build_context()

        result = self._client.evaluate(
            tool=tool_name,
            function=function_name,
            parameters=arguments,
            target_paths=paths,
            target_domains=domains,
            context=ctx,
        )

        self._append_chain(f"{tool_name}.{function_name}")

        if result.verdict == Verdict.DENY:
            logger.warning(
                "ADK tool call denied: tool=%s fn=%s reason=%s",
                tool_name,
                function_name,
                result.reason,
            )
            if self._raise_on_deny:
                raise PolicyDenied(result.reason or "Policy denied")
        elif result.verdict == Verdict.REQUIRE_APPROVAL:
            logger.info(
                "ADK tool call requires approval: tool=%s fn=%s",
                tool_name,
                function_name,
            )
            if self._raise_on_deny:
                raise ApprovalRequired(
                    result.reason or "Approval required",
                    result.approval_id or "unknown",
                )

    def protect(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """
        Decorator to protect a Google ADK tool function.

        Example:
            @guard.protect
            def read_file(path: str) -> str:
                return open(path).read()

        Args:
            func: The tool function to protect.

        Returns:
            Wrapped function with policy enforcement.
        """
        guard = self
        tool_name: str = str(getattr(func, "__qualname__", func.__name__))
        fn_name = func.__name__

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            guard.evaluate(tool_name, fn_name, kwargs)
            return func(*args, **kwargs)

        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        wrapper.__qualname__ = getattr(func, "__qualname__", func.__name__)
        # Preserve Google ADK metadata
        for attr in ("name", "description", "parameters", "__annotations__"):
            if hasattr(func, attr):
                setattr(wrapper, attr, getattr(func, attr))
        return wrapper

    def before_tool_callback(
        self,
    ) -> Callable[[str, str, Dict[str, Any]], None]:
        """
        Create a before-tool callback for Google ADK agent configuration.

        Returns a callable that ADK agents invoke before each tool execution.
        If the policy denies the action, PolicyDenied is raised and the
        tool call is blocked.

        Returns:
            A callback function with signature (tool_name, fn_name, args) -> None.
        """
        guard = self

        def callback(
            tool_name: str, function_name: str, arguments: Dict[str, Any]
        ) -> None:
            guard.evaluate(tool_name, function_name, arguments)

        return callback
