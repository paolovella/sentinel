"""
Anthropic Claude Agent SDK integration for Vellaveto.

Provides tool permission enforcement hooks for Claude Agent SDK applications.
Evaluates tool calls against Vellaveto policies before execution, bridging
the Agent SDK's sandbox-runtime allowlists with Vellaveto's path_rules and
network_rules.

Example:
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


class VellavetoToolPermission:
    """
    Tool permission callback for Claude Agent SDK.

    Integrates with the Claude Agent SDK's ``tool_permission_callback``
    parameter. Each tool invocation is evaluated against Vellaveto policies.
    If the policy denies the action, the SDK receives a denial response
    preventing the tool from executing.

    The permission callback bridges Claude Agent SDK's sandbox-runtime
    domain/path allowlists with Vellaveto's ``path_rules`` and
    ``network_rules`` for unified policy enforcement.

    Args:
        client: VellavetoClient instance for policy evaluation.
        session_id: Optional session identifier for audit correlation.
        agent_id: Optional agent identifier.
        tenant_id: Optional tenant identifier.
        deny_on_error: If True (default), deny on evaluation errors.
        metadata: Additional metadata for evaluation context.
    """

    def __init__(
        self,
        client: VellavetoClient,
        *,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        deny_on_error: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._client = client
        self._session_id = session_id
        self._agent_id = agent_id
        self._tenant_id = tenant_id
        self._deny_on_error = deny_on_error
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
        meta["sdk"] = "claude_agent_sdk"
        if agent_name:
            meta["claude_agent_name"] = agent_name[:MAX_FIELD_LENGTH]
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

    def check(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        *,
        agent_name: Optional[str] = None,
    ) -> bool:
        """
        Check tool permission against Vellaveto policies.

        This method is designed to be used as the ``tool_permission_callback``
        parameter of the Claude Agent SDK. Returns True to allow the tool
        call, False to deny it.

        Args:
            tool_name: Name of the tool being called.
            arguments: Tool call arguments dictionary.
            agent_name: Optional agent name for context.

        Returns:
            True if the tool call is allowed, False if denied.

        Raises:
            PolicyDenied: If deny_on_error is False but policy explicitly denies.
            ApprovalRequired: If the action requires human approval.
        """
        try:
            paths, domains = self._extract_targets(arguments)
            ctx = self._build_context(agent_name=agent_name)

            result = self._client.evaluate(
                tool=tool_name,
                function="*",
                parameters=arguments,
                target_paths=paths,
                target_domains=domains,
                context=ctx,
            )

            self._append_chain(tool_name)

            if result.verdict == Verdict.ALLOW:
                return True
            elif result.verdict == Verdict.REQUIRE_APPROVAL:
                logger.info(
                    "Claude agent tool requires approval: tool=%s",
                    tool_name,
                )
                raise ApprovalRequired(
                    result.reason or "Approval required",
                    result.approval_id or "unknown",
                )
            else:
                logger.warning(
                    "Claude agent tool denied: tool=%s reason=%s",
                    tool_name,
                    result.reason,
                )
                return False
        except (PolicyDenied, ApprovalRequired):
            raise
        except Exception:
            logger.exception(
                "Error evaluating tool permission: tool=%s", tool_name
            )
            if self._deny_on_error:
                return False
            return True

    def wrap_tool(
        self,
        func: Callable[..., Any],
        *,
        tool_name: Optional[str] = None,
        agent_name: Optional[str] = None,
    ) -> Callable[..., Any]:
        """
        Wrap a tool function with Vellaveto policy enforcement.

        Use this when the Claude Agent SDK does not support
        ``tool_permission_callback`` or for pre-SDK-integration use cases.

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
        _agent_name = agent_name

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not guard.check(_tool_name, kwargs, agent_name=_agent_name):
                raise PolicyDenied(
                    f"Tool '{_tool_name}' denied by Vellaveto policy"
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

    def create_allowed_tools_filter(
        self,
        available_tools: List[str],
        *,
        agent_name: Optional[str] = None,
    ) -> List[str]:
        """
        Filter a list of tool names to only those allowed by Vellaveto policies.

        Useful for populating the Claude Agent SDK's ``allowedTools``
        configuration based on the current policy state.

        Args:
            available_tools: List of tool names to filter.
            agent_name: Optional agent name for context.

        Returns:
            Filtered list of allowed tool names.
        """
        allowed = []
        empty_args: Dict[str, Any] = {}
        for tool_name in available_tools:
            try:
                if self.check(tool_name, empty_args, agent_name=agent_name):
                    allowed.append(tool_name)
            except (PolicyDenied, ApprovalRequired):
                continue
            except Exception:
                logger.debug("Skipping tool %s in filter due to error", tool_name)
                continue
        return allowed
