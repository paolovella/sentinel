"""
LangChain integration for Vellaveto.

Provides callback handlers and guards for integrating Vellaveto policy
enforcement into LangChain applications.

Example:
    from langchain.llms import OpenAI
    from langchain.chains import LLMChain
    from vellaveto import VellavetoClient
    from vellaveto.langchain import VellavetoCallbackHandler

    client = VellavetoClient(url="http://localhost:3000")
    handler = VellavetoCallbackHandler(client)

    llm = OpenAI()
    chain = LLMChain(llm=llm, callbacks=[handler])
"""

import logging
import threading
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING, Union
from urllib.parse import urlparse
from uuid import UUID

from vellaveto.client import VellavetoClient, PolicyDenied, ApprovalRequired
from vellaveto.types import EvaluationContext, Verdict

logger = logging.getLogger(__name__)

# Check for LangChain availability
HAS_LANGCHAIN = False
if TYPE_CHECKING:
    from langchain_core.agents import AgentAction, AgentFinish
    from langchain_core.callbacks import (
        BaseCallbackHandler as LangChainBaseCallbackHandler,
    )
    from langchain_core.outputs import LLMResult
else:
    try:
        from langchain_core.agents import AgentAction, AgentFinish
        from langchain_core.callbacks import (
            BaseCallbackHandler as LangChainBaseCallbackHandler,
        )
        from langchain_core.outputs import LLMResult
        HAS_LANGCHAIN = True
    except ImportError:
        HAS_LANGCHAIN = False

        # Define stub for runtime inheritance when LangChain is not installed.
        class LangChainBaseCallbackHandler:
            pass


class VellavetoCallbackHandler(LangChainBaseCallbackHandler):
    """
    LangChain callback handler for Vellaveto policy enforcement.

    This handler intercepts tool calls and evaluates them against Vellaveto
    policies before execution. If a policy denies the action, the handler
    raises PolicyDenied to stop execution.

    Example:
        from vellaveto import VellavetoClient
        from vellaveto.langchain import VellavetoCallbackHandler

        client = VellavetoClient(url="http://localhost:3000")
        handler = VellavetoCallbackHandler(
            client=client,
            session_id="my-session",
            raise_on_deny=True,
        )

        # Use with any LangChain component
        agent = create_react_agent(..., callbacks=[handler])

    Attributes:
        client: VellavetoClient instance
        session_id: Session ID for stateful evaluation
        agent_id: Agent ID for agent-specific policies
        raise_on_deny: Whether to raise exceptions on policy denial
        log_evaluations: Whether to log all evaluations
    """

    def __init__(
        self,
        client: VellavetoClient,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        raise_on_deny: bool = True,
        log_evaluations: bool = True,
        scan_responses: bool = True,
        scan_prompts: bool = True,
    ):
        """
        Args:
            client: VellavetoClient instance.
            session_id: Session ID for stateful evaluation.
            agent_id: Agent ID for agent-specific policies.
            raise_on_deny: Raise PolicyDenied on denial (fail-closed).
            log_evaluations: Log all evaluation attempts.
            scan_responses: Enable DLP scanning of tool and LLM outputs.
                Set to False to reduce HTTP calls per step from 3-4 to 1.
            scan_prompts: Enable injection scanning of LLM prompts.
                Set to False to skip the pre-LLM injection check.
        """
        if not HAS_LANGCHAIN:
            raise ImportError(
                "LangChain is required for VellavetoCallbackHandler. "
                "Install with: pip install langchain-core"
            )

        self.client = client
        self.session_id = session_id
        self.agent_id = agent_id
        self.raise_on_deny = raise_on_deny
        self.log_evaluations = log_evaluations
        self.scan_responses = scan_responses
        self.scan_prompts = scan_prompts
        self._call_chain: List[str] = []
        # SECURITY (FIND-SDK-015): Thread safety for _call_chain
        self._chain_lock = threading.Lock()

    def _get_context(self) -> EvaluationContext:
        """Build evaluation context from handler state."""
        with self._chain_lock:
            chain_copy = self._call_chain.copy()
        return EvaluationContext(
            session_id=self.session_id,
            agent_id=self.agent_id,
            call_chain=chain_copy,
        )

    def _extract_tool_info(
        self,
        tool_name: str,
        tool_input: Union[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Extract tool, function, and parameters from LangChain tool call."""
        # Handle string inputs (some tools accept raw strings)
        if isinstance(tool_input, str):
            parameters = {"input": tool_input}
        else:
            parameters = tool_input

        # Extract paths and domains from common parameter patterns
        target_paths = []
        target_domains = []

        for key, value in parameters.items():
            if isinstance(value, str):
                # Common path parameter names
                if key in ("path", "file", "filename", "filepath", "directory", "dir"):
                    target_paths.append(value)
                # Common URL/domain parameter names
                elif key in ("url", "uri", "endpoint", "host", "domain"):
                    target_domains.append(value)
                # Check for URL patterns in any string value
                else:
                    parsed = urlparse(value)
                    if parsed.scheme in ("http", "https", "ftp") and parsed.netloc:
                        target_domains.append(value)

        return {
            "tool": tool_name,
            "function": tool_name,  # LangChain tools are typically single-function
            "parameters": parameters,
            "target_paths": target_paths,
            "target_domains": target_domains,
        }

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        inputs: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """
        Called when a tool starts running.

        Evaluates the tool call against Vellaveto policies and raises
        PolicyDenied if the action is not allowed.
        """
        tool_name = serialized.get("name", "unknown")

        # Parse input - could be string or dict
        try:
            import json
            tool_input = json.loads(input_str) if isinstance(input_str, str) else input_str
        except (json.JSONDecodeError, TypeError):
            tool_input = input_str

        # Use inputs if provided (newer LangChain versions)
        if inputs:
            tool_input = inputs

        tool_info = self._extract_tool_info(tool_name, tool_input)

        if self.log_evaluations:
            logger.info(f"Evaluating tool call: {tool_name}")

        try:
            result = self.client.evaluate(
                tool=tool_info["tool"],
                function=tool_info["function"],
                parameters=tool_info["parameters"],
                target_paths=tool_info["target_paths"],
                target_domains=tool_info["target_domains"],
                context=self._get_context(),
            )

            if self.log_evaluations:
                logger.info(f"Tool {tool_name} verdict: {result.verdict.value}")

            if result.verdict == Verdict.DENY:
                if self.raise_on_deny:
                    raise PolicyDenied(result.reason or "Policy denied", result.policy_id)
                else:
                    # SECURITY (FIND-SDK-008): Warn when denied action proceeds
                    logger.warning(
                        f"Tool {tool_name} denied but proceeding (raise_on_deny=False): "
                        f"{result.reason}"
                    )

            elif result.verdict == Verdict.REQUIRE_APPROVAL:
                if self.raise_on_deny:
                    raise ApprovalRequired(
                        result.reason or "Approval required",
                        result.approval_id or "unknown",
                    )
                else:
                    # SECURITY (FIND-SDK-008): Warn when approval-required action proceeds
                    logger.warning(
                        f"Tool {tool_name} requires approval but proceeding "
                        f"(raise_on_deny=False): {result.reason}"
                    )

            # SECURITY (FIND-SDK-018): Append to call chain AFTER verdict check,
            # not before — denied/approval-required calls that raise never reach here.
            with self._chain_lock:
                self._call_chain.append(tool_name)
                if len(self._call_chain) > 20:  # Limit chain length
                    self._call_chain.pop(0)

        except (PolicyDenied, ApprovalRequired):
            raise
        except Exception as e:
            logger.error(f"Vellaveto evaluation failed for {tool_name}: {e}")
            if self.raise_on_deny:
                # Fail-closed: treat errors as denials
                raise PolicyDenied(f"Evaluation failed: {e}")

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """
        Called when a tool finishes running.

        Evaluates the tool output against Vellaveto policies for DLP scanning
        (secret detection in tool responses). If a tool leaks a credential in
        its output, the handler logs a warning and optionally raises PolicyDenied.

        Skipped when scan_responses=False.
        """
        if not self.scan_responses:
            return
        if output is None:
            return

        # Convert output to string for scanning
        output_str = str(output) if not isinstance(output, str) else output

        # Skip trivially short outputs (no secrets in < 8 chars)
        if len(output_str) < 8:
            return

        if self.log_evaluations:
            logger.debug(
                "Scanning tool output (%d chars) for DLP findings",
                len(output_str),
            )

        try:
            result = self.client.evaluate(
                tool="__vellaveto_response_scan",
                function="dlp_check",
                parameters={"output": output_str[:4096]},  # Cap scan size
                context=self._get_context(),
            )

            if result.verdict == Verdict.DENY:
                logger.warning(
                    "Tool output blocked by DLP policy: %s",
                    result.reason or "secret detected in output",
                )
                if self.raise_on_deny:
                    raise PolicyDenied(
                        result.reason or "DLP: secret detected in tool output",
                        result.policy_id,
                    )

        except PolicyDenied:
            raise
        except Exception as e:
            # Fail-open for output scanning: log but don't block.
            # Tool already executed; blocking the output would lose data
            # without preventing the action.
            logger.debug("DLP output scan failed (non-blocking): %s", e)

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool errors."""
        logger.error(f"Tool error: {error}")

    def on_agent_action(
        self,
        action: "AgentAction",
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """
        Called when an agent takes an action.

        This is called before on_tool_start for ReAct-style agents.
        """
        if self.log_evaluations:
            logger.debug(f"Agent action: {action.tool} with input: {action.tool_input}")

    def on_agent_finish(
        self,
        finish: "AgentFinish",
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when an agent finishes."""
        if self.log_evaluations:
            logger.debug("Agent finished")

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """
        Called when LLM starts running.

        Evaluates prompts for injection patterns that may have been injected
        by a compromised tool output (cross-prompt injection defense).

        Skipped when scan_prompts=False.
        """
        if not self.scan_prompts:
            return
        if not prompts:
            return

        if self.log_evaluations:
            model_name = serialized.get("name", serialized.get("id", ["unknown"])[-1] if isinstance(serialized.get("id"), list) else "unknown")
            logger.info(
                "LLM starting: model=%s, prompt_count=%d",
                model_name,
                len(prompts),
            )

        # Scan the combined prompt text for injection patterns
        combined = "\n".join(prompts)[:8192]  # Cap scan size
        if len(combined) < 8:
            return

        try:
            result = self.client.evaluate(
                tool="__vellaveto_prompt_scan",
                function="injection_check",
                parameters={"prompt": combined},
                context=self._get_context(),
            )

            if result.verdict == Verdict.DENY:
                logger.warning(
                    "Prompt blocked by injection policy: %s",
                    result.reason or "injection pattern detected in prompt",
                )
                if self.raise_on_deny:
                    raise PolicyDenied(
                        result.reason or "Injection pattern detected in prompt",
                        result.policy_id,
                    )

        except PolicyDenied:
            raise
        except Exception as e:
            # Fail-open for prompt scanning: log but don't block.
            logger.debug("Prompt injection scan failed (non-blocking): %s", e)

    def on_llm_end(
        self,
        response: "LLMResult",
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """
        Called when LLM ends running.

        Scans LLM response text for DLP findings (secrets that may have been
        generated or echoed by the model from tool output).

        Skipped when scan_responses=False.
        """
        if not self.scan_responses:
            return
        if response is None:
            return

        # Extract text from LLMResult generations
        texts = []
        if HAS_LANGCHAIN and hasattr(response, "generations"):
            for gen_list in response.generations:
                for gen in gen_list:
                    if hasattr(gen, "text") and gen.text:
                        texts.append(gen.text)

        if not texts:
            return

        combined = "\n".join(texts)[:8192]  # Cap scan size
        if len(combined) < 8:
            return

        if self.log_evaluations:
            logger.debug(
                "Scanning LLM response (%d chars) for DLP findings",
                len(combined),
            )

        try:
            result = self.client.evaluate(
                tool="__vellaveto_response_scan",
                function="dlp_check",
                parameters={"response": combined},
                context=self._get_context(),
            )

            if result.verdict == Verdict.DENY:
                logger.warning(
                    "LLM response blocked by DLP policy: %s",
                    result.reason or "secret detected in LLM response",
                )
                if self.raise_on_deny:
                    raise PolicyDenied(
                        result.reason or "DLP: secret detected in LLM response",
                        result.policy_id,
                    )

        except PolicyDenied:
            raise
        except Exception as e:
            # Fail-open for response scanning: log but don't block.
            logger.debug("LLM response DLP scan failed (non-blocking): %s", e)


class VellavetoToolGuard:
    """
    Decorator for guarding individual tools with Vellaveto policies.

    Example:
        from langchain.tools import tool
        from vellaveto import VellavetoClient
        from vellaveto.langchain import VellavetoToolGuard

        client = VellavetoClient(url="http://localhost:3000")
        guard = VellavetoToolGuard(client)

        @tool
        @guard("filesystem", "read_file")
        def read_file(path: str) -> str:
            '''Read a file from the filesystem.'''
            with open(path) as f:
                return f.read()

    Attributes:
        client: VellavetoClient instance
        session_id: Session ID for stateful evaluation
    """

    def __init__(
        self,
        client: VellavetoClient,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> None:
        self.client = client
        self.session_id = session_id
        self.agent_id = agent_id

    def __call__(
        self,
        tool: str,
        function: Optional[str] = None,
        extract_paths: Optional[List[str]] = None,
        extract_domains: Optional[List[str]] = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Create a guard decorator for a specific tool.

        Args:
            tool: Tool name for policy evaluation
            function: Function name (defaults to decorated function name)
            extract_paths: Parameter names to extract as target_paths
            extract_domains: Parameter names to extract as target_domains
        """
        extract_paths = extract_paths or ["path", "file", "filepath"]
        extract_domains = extract_domains or ["url", "uri", "domain"]

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            import functools

            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                func_name = function or func.__name__

                # Extract paths and domains from kwargs
                target_paths: List[str] = []
                target_domains: List[str] = []

                for key, value in kwargs.items():
                    if key in extract_paths and isinstance(value, str):
                        target_paths.append(value)
                    if key in extract_domains and isinstance(value, str):
                        target_domains.append(value)

                # Evaluate with Vellaveto
                context = EvaluationContext(
                    session_id=self.session_id,
                    agent_id=self.agent_id,
                )

                self.client.evaluate_or_raise(
                    tool=tool,
                    function=func_name,
                    parameters=kwargs,
                    target_paths=target_paths,
                    target_domains=target_domains,
                    context=context,
                )

                # Policy allowed - execute the function
                return func(*args, **kwargs)

            return wrapper

        return decorator


def create_guarded_toolkit(
    client: VellavetoClient,
    toolkit: Any,
    session_id: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> List[Any]:
    """
    Wrap all tools in a LangChain toolkit with Vellaveto guards.

    Example:
        from langchain_community.agent_toolkits import FileManagementToolkit
        from vellaveto import VellavetoClient
        from vellaveto.langchain import create_guarded_toolkit

        client = VellavetoClient(url="http://localhost:3000")
        toolkit = FileManagementToolkit()
        guarded_tools = create_guarded_toolkit(client, toolkit)

    Args:
        client: VellavetoClient instance
        toolkit: LangChain toolkit instance
        session_id: Session ID for stateful evaluation
        agent_id: Agent ID for agent-specific policies

    Returns:
        List of tools with Vellaveto guards applied
    """
    if not HAS_LANGCHAIN:
        raise ImportError("LangChain is required. Install with: pip install langchain")

    guard = VellavetoToolGuard(client, session_id=session_id, agent_id=agent_id)
    guarded_tools = []

    for tool in toolkit.get_tools():
        # Create a guarded version of the tool
        guarded_func = guard(
            tool=tool.name,
            function=tool.name,
        )(tool.func)

        # Create new tool with guarded function
        from langchain_core.tools import StructuredTool

        guarded_tool = StructuredTool(
            name=tool.name,
            description=tool.description,
            func=guarded_func,
            args_schema=getattr(tool, "args_schema", None),
        )
        guarded_tools.append(guarded_tool)

    return guarded_tools
