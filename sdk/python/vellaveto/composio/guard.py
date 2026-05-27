"""
High-level Composio integration guard for Vellaveto.

``ComposioGuard`` wraps the low-level modifier factories into a
user-friendly API that can be used in two ways:

1. **Modifier-based** (recommended) — pass ``guard.before_execute_modifier()``
   and ``guard.after_execute_modifier()`` to Composio's ``tools.get(modifiers=...)``.
   This works with every Composio provider (OpenAI, LangChain, CrewAI, etc.).

2. **Standalone execute** — call ``guard.execute()`` to wrap a single
   ``composio.tools.execute()`` call with policy checks.
"""

import copy
import logging
from typing import Any, Callable, Dict, List, Optional, cast

from vellaveto.client import VellavetoClient, PolicyDenied, ApprovalRequired
from vellaveto.composio.modifiers import (
    CallChainTracker,
    create_before_execute_modifier,
    create_after_execute_modifier,
)
from vellaveto.composio.scanner import ResponseScanner
from vellaveto.composio.extractor import normalize_slug_to_tool_function, extract_targets
from vellaveto.types import EvaluationContext, Verdict

logger = logging.getLogger(__name__)

class ComposioGuard:
    """Vellaveto policy guard for Composio tool calls.

    Example — modifier-based (recommended)::

        from composio import Composio
        from vellaveto import VellavetoClient
        from vellaveto.composio import ComposioGuard

        client = VellavetoClient(url="http://localhost:3000", api_key="key")
        guard = ComposioGuard(client, session_id="sess-1", agent_id="my-agent")

        composio = Composio(api_key="...")
        tools = composio.tools.get(
            user_id="default",
            toolkits=["GITHUB"],
            modifiers=[
                guard.before_execute_modifier(),
                guard.after_execute_modifier(),
            ],
        )

    Example — standalone execute::

        result = guard.execute(
            composio=composio, user_id="default",
            slug="SLACK_SEND_MESSAGE",
            arguments={"channel": "#general", "text": "Hello"},
        )

    Args:
        client: Vellaveto API client.
        session_id: Session ID for stateful evaluation.
        agent_id: Agent ID for agent-specific policies.
        tenant_id: Tenant ID for multi-tenant deployments.
        fail_closed: Treat API/network errors as denials (default *True*).
        scan_responses: Enable response scanning (default *True*).
        redactor: Optional ``ParameterRedactor`` for response scanning.
            When provided, its ``is_sensitive_value()`` method is used
            for secret detection in responses.
    """

    def __init__(
        self,
        client: VellavetoClient,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        fail_closed: bool = True,
        scan_responses: bool = True,
        redactor: Optional[Any] = None,
    ):
        self._client = client
        self._session_id = session_id
        self._agent_id = agent_id
        self._tenant_id = tenant_id
        self._fail_closed = fail_closed
        self._scan_responses = scan_responses
        self._tracker = CallChainTracker()

        self._scanner: Optional[ResponseScanner] = None
        if scan_responses:
            self._scanner = ResponseScanner(redactor=redactor)
        else:
            logger.info("ComposioGuard: response scanning disabled (scan_responses=False)")

    def before_execute_modifier(
        self,
        tools: Optional[List[str]] = None,
    ) -> Callable:
        """Return a ``before_execute`` modifier for Composio.

        Args:
            tools: Optional allowlist of tool slugs.  When provided,
                only matching calls are policy-checked.

        Returns:
            Callable with signature ``(tool, toolkit, params) -> params``.
        """
        return create_before_execute_modifier(
            client=self._client,
            session_id=self._session_id,
            agent_id=self._agent_id,
            tenant_id=self._tenant_id,
            call_chain_tracker=self._tracker,
            fail_closed=self._fail_closed,
            tools=tools,
        )

    def after_execute_modifier(
        self,
        tools: Optional[List[str]] = None,
    ) -> Callable:
        """Return an ``after_execute`` modifier for Composio.

        When ``scan_responses=False`` was set on the guard, this returns
        a no-op modifier that passes responses through unchanged.

        Args:
            tools: Optional allowlist of tool slugs to scan.

        Returns:
            Callable with signature ``(tool, toolkit, response) -> response``.
        """
        if not self._scan_responses:
            # When scan_responses=False, return a no-op modifier that passes through
            def _noop_modifier(tool: str, toolkit: str, response: Any) -> Any:
                return response
            return _noop_modifier
        return create_after_execute_modifier(
            scanner=self._scanner,
            fail_closed=self._fail_closed,
            tools=tools,
        )

    def execute(
        self,
        composio: Any,
        user_id: str,
        slug: str,
        arguments: Dict[str, Any],
        toolkit: str = "",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Execute a Composio tool call with Vellaveto policy enforcement.

        This is the standalone path — wraps ``composio.tools.execute()``
        with before/after checks.

        Args:
            composio: A ``Composio`` client instance.
            user_id: Composio user ID.
            slug: Tool action slug (e.g. ``"GITHUB_CREATE_ISSUE"``).
            arguments: Tool call arguments.
            toolkit: Optional toolkit hint for slug normalization.
            **kwargs: Extra keyword arguments forwarded to
                ``composio.tools.execute()``.

        Returns:
            The Composio execution response (possibly sanitized).

        Raises:
            PolicyDenied: If the policy denies the action or if the
                evaluation fails and ``fail_closed`` is *True*.
            ApprovalRequired: If the action requires human approval.
        """
        # Deep-copy arguments to prevent TOCTOU mutation between check and use
        frozen_arguments = copy.deepcopy(arguments)

        tool_name, function_name = normalize_slug_to_tool_function(slug, toolkit)

        # SECURITY (FIND-COMPOSIO-006): Validate derived names are non-empty
        if not tool_name or not function_name:
            raise PolicyDenied("Invalid tool slug: empty tool_name or function_name after normalization")

        target_paths, target_domains = extract_targets(slug, frozen_arguments)

        context = EvaluationContext(
            session_id=self._session_id,
            agent_id=self._agent_id,
            tenant_id=self._tenant_id,
            call_chain=self._tracker.copy(),
        )

        eval_params = frozen_arguments
        if self._client.redactor is not None:
            eval_params = self._client.redactor.redact(frozen_arguments)

        evaluated = True
        try:
            result = self._client.evaluate(
                tool=tool_name,
                function=function_name,
                parameters=eval_params,
                target_paths=target_paths,
                target_domains=target_domains,
                context=context,
            )
        except (PolicyDenied, ApprovalRequired):
            raise
        except Exception as exc:
            logger.error("Vellaveto evaluation failed for %s: %s", slug, type(exc).__name__)
            if self._fail_closed:
                raise PolicyDenied(f"Evaluation failed: {type(exc).__name__}")
            # fail-open: skip policy check and proceed
            logger.warning("Proceeding without policy evaluation (fail_closed=False) for %s", slug)
            result = None
            evaluated = False

        if result is not None:
            if result.verdict == Verdict.DENY:
                raise PolicyDenied(
                    result.reason or "Policy denied",
                    result.policy_id,
                )
            if result.verdict == Verdict.REQUIRE_APPROVAL:
                raise ApprovalRequired(
                    result.reason or "Approval required",
                    result.approval_id or "unknown",
                )

        # Only append to call chain if policy was actually evaluated
        if evaluated:
            self._tracker.append(slug)

        # Execute via Composio with frozen arguments
        try:
            response = composio.tools.execute(
                user_id=user_id,
                slug=slug,
                arguments=frozen_arguments,
                **kwargs,
            )
        except Exception as exc:
            logger.error("Composio execute raised for %s: %s", slug, type(exc).__name__)
            if self._fail_closed:
                raise PolicyDenied(f"Tool execution failed (unscanned): {type(exc).__name__}")
            raise

        # Post-execution scan
        if self._scanner is not None:
            scan_data = None
            if isinstance(response, dict):
                scan_data = response.get("data", response)
            elif isinstance(response, str):
                scan_data = {"_raw": response}
            else:
                logger.warning(
                    "Non-scannable response type %s from %s",
                    type(response).__name__, slug,
                )
                if self._fail_closed:
                    return {
                        "data": {"error": "Response blocked: non-scannable response type"},
                        "successful": False,
                    }

            if scan_data is not None:
                try:
                    scan_result = self._scanner.scan(scan_data)
                except Exception as exc:
                    logger.error("Response scan failed for %s: %s", slug, type(exc).__name__)
                    if self._fail_closed:
                        return {
                            "data": {"error": "Response blocked: scan failure"},
                            "successful": False,
                        }
                else:
                    if scan_result.findings:
                        logger.warning(
                            "Vellaveto response scan found %d finding(s) in %s",
                            len(scan_result.findings),
                            slug,
                        )
                        if self._fail_closed:
                            return {
                                "data": {"error": "Response blocked by Vellaveto security scan"},
                                "successful": False,
                                "error": f"Security scan detected {len(scan_result.findings)} finding(s)",
                            }

        return cast(Dict[str, Any], response)

    def reset_session(self) -> None:
        """Reset the call chain tracker (e.g. on new session)."""
        self._tracker.reset()
