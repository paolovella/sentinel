"""
Microsoft Agent Framework integration for Vellaveto.

Provides tool call interception middleware for Microsoft Agent Framework
(AutoGen + Semantic Kernel merger) applications. Compatible with
Microsoft Entra ID security hooks and OpenTelemetry audit export.

Example:
    from vellaveto import VellavetoClient
    from vellaveto.microsoft_agents import VellavetoAgentMiddleware

    client = VellavetoClient(url="http://localhost:3000")
    middleware = VellavetoAgentMiddleware(client)

    # Use as middleware in Microsoft Agent Framework
    agent = Agent(
        middleware=[middleware],
        tools=[read_file, web_search],
    )
"""

import asyncio
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


class VellavetoAgentMiddleware:
    """
    Tool call interception middleware for Microsoft Agent Framework.

    Integrates with the Microsoft Agent Framework's middleware pipeline
    to evaluate tool calls against Vellaveto policies. Supports Entra ID
    security hooks for identity-aware policy evaluation and exports
    OpenTelemetry-compatible audit spans.

    Args:
        client: VellavetoClient instance for policy evaluation.
        session_id: Optional session identifier for audit correlation.
        agent_id: Optional agent identifier.
        tenant_id: Optional tenant identifier.
        entra_token: Optional Microsoft Entra ID access token for identity.
        raise_on_deny: If True (default), raise PolicyDenied on denial.
        deny_on_error: If True (default), deny on evaluation errors.
        otel_enabled: If True, emit OpenTelemetry spans for evaluations.
        metadata: Additional metadata for evaluation context.
    """

    def __init__(
        self,
        client: VellavetoClient,
        *,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        entra_token: Optional[str] = None,
        raise_on_deny: bool = True,
        deny_on_error: bool = True,
        otel_enabled: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._client = client
        self._session_id = session_id
        self._agent_id = agent_id
        self._tenant_id = tenant_id
        self._entra_token = entra_token
        self._raise_on_deny = raise_on_deny
        self._deny_on_error = deny_on_error
        self._otel_enabled = otel_enabled
        self._metadata = metadata or {}
        self._call_chain: List[str] = []
        self._lock = threading.Lock()
        self._tracer = None
        if otel_enabled:
            self._init_otel()

    def _init_otel(self) -> None:
        """Initialize OpenTelemetry tracer if available."""
        try:
            from opentelemetry import trace
            self._tracer = trace.get_tracer(
                "vellaveto.microsoft_agents",
                schema_url="https://opentelemetry.io/schemas/1.28.0",
            )
        except ImportError:
            logger.debug(
                "opentelemetry not installed; OTel spans disabled"
            )
            self._otel_enabled = False

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
        meta["sdk"] = "microsoft_agent_framework"
        if agent_name:
            meta["ms_agent_name"] = agent_name[:MAX_FIELD_LENGTH]
        if self._entra_token:
            meta["has_entra_token"] = "true"
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

    def _record_otel_span(
        self,
        tool_name: str,
        function_name: str,
        verdict: str,
        reason: Optional[str] = None,
    ) -> None:
        """Record an OpenTelemetry span for a policy evaluation."""
        if not self._otel_enabled or not self._tracer:
            return
        try:
            from opentelemetry import trace
            with self._tracer.start_as_current_span(
                "vellaveto.evaluate",
                kind=trace.SpanKind.INTERNAL,
            ) as span:
                span.set_attribute("vellaveto.tool", tool_name)
                span.set_attribute("vellaveto.function", function_name)
                span.set_attribute("vellaveto.verdict", verdict)
                if reason:
                    span.set_attribute("vellaveto.reason", reason[:512])
                if self._session_id:
                    span.set_attribute("vellaveto.session_id", self._session_id)
                if self._agent_id:
                    span.set_attribute("vellaveto.agent_id", self._agent_id)
        except Exception:
            logger.debug("Failed to record OTel span", exc_info=True)

    def evaluate_call(
        self,
        tool_name: str,
        function_name: str,
        arguments: Dict[str, Any],
        *,
        agent_name: Optional[str] = None,
    ) -> None:
        """
        Evaluate a tool call against Vellaveto policies.

        Args:
            tool_name: Tool name.
            function_name: Function name being called.
            arguments: Function call arguments.
            agent_name: Optional agent name for context.

        Raises:
            PolicyDenied: If the policy denies the action.
            ApprovalRequired: If the action requires human approval.
        """
        try:
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
            self._record_otel_span(
                tool_name, function_name,
                result.verdict.value, result.reason,
            )

            if result.verdict == Verdict.DENY:
                logger.warning(
                    "MS Agent tool call denied: tool=%s fn=%s reason=%s",
                    tool_name,
                    function_name,
                    result.reason,
                )
                if self._raise_on_deny:
                    raise PolicyDenied(result.reason or "Policy denied")
            elif result.verdict == Verdict.REQUIRE_APPROVAL:
                logger.info(
                    "MS Agent tool call requires approval: tool=%s fn=%s",
                    tool_name,
                    function_name,
                )
                if self._raise_on_deny:
                    raise ApprovalRequired(
                        result.reason or "Approval required",
                        result.approval_id or "unknown",
                    )
        except (PolicyDenied, ApprovalRequired):
            raise
        except Exception:
            logger.exception(
                "Error evaluating tool permission: tool=%s", tool_name
            )
            self._record_otel_span(tool_name, function_name, "error")
            if self._deny_on_error and self._raise_on_deny:
                raise PolicyDenied(
                    f"Evaluation error for tool '{tool_name}' (fail-closed)"
                )

    def wrap_tool(
        self,
        func: Callable[..., Any],
        *,
        tool_name: Optional[str] = None,
        agent_name: Optional[str] = None,
    ) -> Callable[..., Any]:
        """
        Wrap a tool function with Vellaveto policy enforcement.

        Args:
            func: The tool function to wrap.
            tool_name: Override tool name (defaults to function name).
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
        Wrap multiple tools with policy enforcement.

        Args:
            tools: List of tool functions.
            agent_name: Optional agent name for context.

        Returns:
            New list with all tools wrapped.
        """
        return [self.wrap_tool(t, agent_name=agent_name) for t in tools]

    def set_entra_token(self, token: str) -> None:
        """
        Update the Entra ID token for identity-aware evaluation.

        Call this when the token is refreshed to ensure evaluations
        include the latest identity context.

        Args:
            token: New Entra ID access token.
        """
        self._entra_token = token

    async def evaluate_call_async(
        self,
        tool_name: str,
        function_name: str,
        arguments: Dict[str, Any],
        *,
        agent_name: Optional[str] = None,
    ) -> None:
        """
        Async version of evaluate_call for use with async agent pipelines.

        Args:
            tool_name: Tool name.
            function_name: Function name being called.
            arguments: Function call arguments.
            agent_name: Optional agent name for context.

        Raises:
            PolicyDenied: If the policy denies the action.
            ApprovalRequired: If the action requires human approval.
        """
        try:
            paths, domains = self._extract_targets(arguments)
            ctx = self._build_context(agent_name=agent_name)

            result = await asyncio.to_thread(
                self._client.evaluate,
                tool=tool_name,
                function=function_name,
                parameters=arguments,
                target_paths=paths,
                target_domains=domains,
                context=ctx,
            )

            self._append_chain(function_name)
            self._record_otel_span(
                tool_name, function_name,
                result.verdict.value, result.reason,
            )

            if result.verdict == Verdict.DENY:
                logger.warning(
                    "MS Agent tool call denied (async): tool=%s fn=%s reason=%s",
                    tool_name,
                    function_name,
                    result.reason,
                )
                if self._raise_on_deny:
                    raise PolicyDenied(result.reason or "Policy denied")
            elif result.verdict == Verdict.REQUIRE_APPROVAL:
                logger.info(
                    "MS Agent tool call requires approval (async): tool=%s fn=%s",
                    tool_name,
                    function_name,
                )
                if self._raise_on_deny:
                    raise ApprovalRequired(
                        result.reason or "Approval required",
                        result.approval_id or "unknown",
                    )
        except (PolicyDenied, ApprovalRequired):
            raise
        except Exception:
            logger.exception(
                "Error evaluating tool permission (async): tool=%s", tool_name
            )
            self._record_otel_span(tool_name, function_name, "error")
            if self._deny_on_error and self._raise_on_deny:
                raise PolicyDenied(
                    f"Evaluation error for tool '{tool_name}' (fail-closed)"
                )

    def wrap_tool_async(
        self,
        func: Callable[..., Any],
        *,
        tool_name: Optional[str] = None,
        agent_name: Optional[str] = None,
    ) -> Callable[..., Any]:
        """
        Wrap an async tool function with Vellaveto policy enforcement.

        Args:
            func: The async tool function to wrap.
            tool_name: Override tool name (defaults to function name).
            agent_name: Optional agent name for context.

        Returns:
            Wrapped async function with policy enforcement.
        """
        guard = self
        _tool_name: str = tool_name or str(
            getattr(func, "__qualname__", func.__name__)
        )
        fn_name = func.__name__
        _agent_name = agent_name

        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            await guard.evaluate_call_async(
                _tool_name,
                fn_name,
                kwargs,
                agent_name=_agent_name,
            )
            return await func(*args, **kwargs)

        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        wrapper.__qualname__ = getattr(func, "__qualname__", func.__name__)
        for attr in ("__annotations__", "name", "description", "parameters"):
            if hasattr(func, attr):
                setattr(wrapper, attr, getattr(func, attr))
        return wrapper
