"""
Vellaveto API client for Python.

Provides synchronous and asynchronous HTTP client for the Vellaveto API.
"""

import asyncio
import json
import logging
import random
import time
import warnings
from typing import Optional, Dict, Any, List
from urllib.parse import quote, urljoin, urlparse

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from vellaveto.types import Action, EvaluationResult, EvaluationContext, Verdict

logger = logging.getLogger(__name__)

# Maximum response body size (10 MB) — prevents OOM on malicious/runaway responses
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024

# Maximum length for approval IDs — aligned with Go/TypeScript SDKs
_MAX_APPROVAL_ID_LENGTH = 256


class VellavetoError(Exception):
    """Base exception for Vellaveto SDK errors."""
    pass


class PolicyDenied(VellavetoError):
    """Raised when a policy denies an action."""

    def __init__(self, reason: str, policy_id: Optional[str] = None):
        self.reason = reason
        self.policy_id = policy_id
        super().__init__(f"Policy denied: {reason}")


class ApprovalRequired(VellavetoError):
    """Raised when an action requires human approval."""

    def __init__(self, reason: str, approval_id: str):
        self.reason = reason
        self.approval_id = approval_id
        super().__init__(f"Approval required: {reason} (approval_id: {approval_id})")


class VellavetoConnectionError(VellavetoError):
    """Raised when unable to connect to Vellaveto server."""
    pass


# SECURITY (FIND-SDK-019): Backward-compatible alias.
# The old name shadowed Python's builtin ConnectionError.
ConnectionError = VellavetoConnectionError  # noqa: A001


# HTTP status codes considered transient (safe to retry)
_TRANSIENT_STATUS_CODES = frozenset({429, 502, 503, 504})

# Maximum length for tool name, function name, and similar string inputs
_MAX_INPUT_STRING_LEN = 1024

# SECURITY (FIND-R114-002): Maximum serialized size of parameters (512KB).
# Parity with Go SDK maxParametersJSONSize. Prevents sending oversized payloads
# that approach the server's MAX_REQUEST_BODY_SIZE (1MB).
_MAX_PARAMETERS_JSON_SIZE = 524288

# IMP-R210-005: Module-level constant instead of per-call allocation.
_VALID_SENSITIVITIES = frozenset({"low", "medium", "high"})


def _validate_approval_id(approval_id: str) -> None:
    """Validate approval_id format — shared by sync and async clients.

    SECURITY (FIND-R56-SDK-001): Aligned with Go/TypeScript SDKs.
    Rejects empty, oversized (>256), and control-character-containing IDs.

    Raises:
        VellavetoError: If approval_id is invalid.
    """
    if not isinstance(approval_id, str) or not approval_id.strip():
        raise VellavetoError("Invalid approval_id: must be a non-empty string")
    if len(approval_id) > _MAX_APPROVAL_ID_LENGTH:
        raise VellavetoError(
            f"Invalid approval_id: exceeds max length ({_MAX_APPROVAL_ID_LENGTH})"
        )
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in approval_id):
        raise VellavetoError("Invalid approval_id: contains control characters")
    # SECURITY (FIND-R104-SDK-002): Reject Unicode format characters — parity with Go SDK.
    if _UNICODE_FORMAT_RE.search(approval_id):
        raise VellavetoError("Invalid approval_id: contains Unicode format characters")


def _validate_evaluate_inputs(
    tool: str,
    function: Optional[str],
    parameters: Optional[Dict[str, Any]],
    target_paths: Optional[List[str]],
    target_domains: Optional[List[str]],
    resolved_ips: Optional[List[str]] = None,
) -> None:
    """Validate inputs for evaluate() — shared by sync and async clients.

    Raises:
        VellavetoError: If any input is invalid.
    """
    # SECURITY (FIND-SDK-020): Validate inputs to prevent abuse
    if not isinstance(tool, str) or not tool.strip():
        raise VellavetoError("tool must be a non-empty string")
    if len(tool) > _MAX_INPUT_STRING_LEN:
        raise VellavetoError(
            f"tool name too long: {len(tool)} > {_MAX_INPUT_STRING_LEN}"
        )
    # SECURITY (FIND-R211-002): Reject control and Unicode format characters in
    # tool and function names to prevent invisible-text manipulation attacks.
    # Parity with context field validation (session_id, agent_id, tenant_id).
    if _CONTROL_CHAR_RE.search(tool):
        raise VellavetoError("tool contains control characters")
    if _UNICODE_FORMAT_RE.search(tool):
        raise VellavetoError("tool contains Unicode format characters")
    if function is not None:
        if not isinstance(function, str):
            raise VellavetoError("function must be a string or None")
        if len(function) > _MAX_INPUT_STRING_LEN:
            raise VellavetoError(
                f"function name too long: {len(function)} > {_MAX_INPUT_STRING_LEN}"
            )
        if _CONTROL_CHAR_RE.search(function):
            raise VellavetoError("function contains control characters")
        if _UNICODE_FORMAT_RE.search(function):
            raise VellavetoError("function contains Unicode format characters")
    if parameters is not None and not isinstance(parameters, dict):
        raise VellavetoError("parameters must be a dict or None")
    # SECURITY (FIND-R114-002): Validate parameters serialized size (512KB).
    # Parity with Go SDK validateParameters(). Prevents oversized payloads
    # approaching the server's 1MB body limit.
    if parameters is not None and len(parameters) > 0:
        try:
            param_json = json.dumps(parameters, separators=(",", ":"))
            if len(param_json.encode("utf-8")) > _MAX_PARAMETERS_JSON_SIZE:
                raise VellavetoError(
                    f"parameters exceeds max serialized size ({_MAX_PARAMETERS_JSON_SIZE} bytes)"
                )
        except (TypeError, ValueError) as e:
            raise VellavetoError(f"parameters serialization failed: {e}")
    if target_paths is not None and not isinstance(target_paths, list):
        raise VellavetoError("target_paths must be a list or None")
    # SECURITY (FIND-R55-SDK-006): Bound target_paths count. Parity with Go SDK (100).
    if target_paths is not None and len(target_paths) > 100:
        raise VellavetoError(
            f"target_paths has {len(target_paths)} entries, max 100"
        )
    if target_domains is not None and not isinstance(target_domains, list):
        raise VellavetoError("target_domains must be a list or None")
    # SECURITY (FIND-R55-SDK-006): Bound target_domains count. Parity with Go SDK (100).
    if target_domains is not None and len(target_domains) > 100:
        raise VellavetoError(
            f"target_domains has {len(target_domains)} entries, max 100"
        )
    # SECURITY (FIND-R67-SDK-001): Bound resolved_ips count. Parity with Go SDK (100).
    if resolved_ips is not None and not isinstance(resolved_ips, list):
        raise VellavetoError("resolved_ips must be a list or None")
    if resolved_ips is not None and len(resolved_ips) > 100:
        raise VellavetoError("resolved_ips exceeds max entries (100)")


# ── Constants for EvaluationContext validation ──
_MAX_CONTEXT_FIELD_LEN = 256
_MAX_CALL_CHAIN_LEN = 100
_MAX_CALL_CHAIN_ENTRY_LEN = 256
_MAX_METADATA_KEYS = 100

# SECURITY (FIND-R103-P1): Unicode format character ranges — zero-width,
# bidi overrides, BOM, interlinear annotation anchors.
import re as _re

_MAX_TENANT_LENGTH = 64
_TENANT_RE = _re.compile(r"^[a-zA-Z0-9_-]+$")

_CONTROL_CHAR_RE = _re.compile(r"[\x00-\x1f\x7f-\x9f]")
_UNICODE_FORMAT_RE = _re.compile(
    # SECURITY (FIND-R110-SDK-003): Added U+2028-202F (line/paragraph separators
    # and bidi embedding controls). The broader 2028-202F range supersedes the
    # old 202A-202E range and also covers U+2028 LINE SEPARATOR and U+2029
    # PARAGRAPH SEPARATOR which can be used for injection.
    # SECURITY (FIND-R157-003): Added U+00AD (soft hyphen) and U+E0001-E007F
    # (TAG characters). Parity with Rust canonical is_unicode_format_char().
    r"[\u00ad\u200b-\u200f\u2028-\u202f\u2060-\u2069\ufeff\ufff9-\ufffb\U000e0001-\U000e007f]"
)


def _validate_evaluation_context(context: Optional["EvaluationContext"]) -> None:
    """Validate EvaluationContext fields match Go/TS SDK parity.

    SECURITY (FIND-R103-P1): The Go SDK validates context fields for length,
    control characters, and Unicode format characters in Validate(). The TS SDK
    has validateContext(). The Python SDK was missing this — a parity gap that
    allows oversized or manipulated context fields to reach the server.

    Raises:
        VellavetoError: If any context field is invalid.
    """
    if context is None:
        return

    # Validate string identity fields.
    for name, value in [
        ("session_id", context.session_id),
        ("agent_id", context.agent_id),
        ("tenant_id", context.tenant_id),
    ]:
        if value is None:
            continue
        if not isinstance(value, str):
            raise VellavetoError(f"context.{name} must be a string")
        if len(value) > _MAX_CONTEXT_FIELD_LEN:
            raise VellavetoError(
                f"context.{name} exceeds max length {_MAX_CONTEXT_FIELD_LEN}"
            )
        if _CONTROL_CHAR_RE.search(value):
            raise VellavetoError(
                f"context.{name} contains control characters"
            )
        if _UNICODE_FORMAT_RE.search(value):
            raise VellavetoError(
                f"context.{name} contains Unicode format characters"
            )

    # Validate call_chain bounds.
    if hasattr(context, "call_chain") and context.call_chain is not None:
        if len(context.call_chain) > _MAX_CALL_CHAIN_LEN:
            raise VellavetoError(
                f"context.call_chain has {len(context.call_chain)} entries, "
                f"max {_MAX_CALL_CHAIN_LEN}"
            )
        for i, entry in enumerate(context.call_chain):
            if isinstance(entry, str) and len(entry) > _MAX_CALL_CHAIN_ENTRY_LEN:
                raise VellavetoError(
                    f"context.call_chain[{i}] exceeds max length "
                    f"{_MAX_CALL_CHAIN_ENTRY_LEN}"
                )
            # SECURITY (FIND-R114-003): Validate call_chain entries for control
            # and Unicode format characters. Parity with identity field validation
            # (session_id, agent_id, tenant_id) which already checks these.
            if isinstance(entry, str):
                if _CONTROL_CHAR_RE.search(entry):
                    raise VellavetoError(
                        f"context.call_chain[{i}] contains control characters"
                    )
                if _UNICODE_FORMAT_RE.search(entry):
                    raise VellavetoError(
                        f"context.call_chain[{i}] contains Unicode format characters"
                    )

    # Validate metadata key count.
    if hasattr(context, "metadata") and context.metadata is not None:
        if len(context.metadata) > _MAX_METADATA_KEYS:
            raise VellavetoError(
                f"context.metadata has {len(context.metadata)} keys, "
                f"max {_MAX_METADATA_KEYS}"
            )


def _validate_base_url(url: str) -> str:
    """Validate and normalize the base URL for the Vellaveto server.

    SECURITY (FIND-R73-SDK-002): Validates URL before use, matching Go and
    TypeScript SDK parity. Rejects empty URLs, non-http(s) schemes, and
    URLs containing credentials (userinfo).

    Args:
        url: The base URL to validate.

    Returns:
        The normalized URL (trailing slashes stripped).

    Raises:
        VellavetoError: If the URL is invalid.
    """
    if not isinstance(url, str) or not url.strip():
        raise VellavetoError("base_url must not be empty")

    trimmed = url.strip().rstrip("/")

    parsed = urlparse(trimmed)

    if parsed.scheme not in ("http", "https"):
        raise VellavetoError(
            f"base_url must use http:// or https:// scheme, got {parsed.scheme!r}"
        )

    if not parsed.hostname:
        raise VellavetoError("base_url must have a host")

    # SECURITY: Reject credentials in URL (userinfo) — they leak into logs,
    # HTTP headers, and error messages. Parity with Go/TS SDKs.
    if parsed.username or parsed.password:
        raise VellavetoError(
            "base_url must not contain credentials (userinfo)"
        )

    return trimmed


def _build_evaluate_payload(
    action: Action,
    context: Optional[EvaluationContext],
) -> Dict[str, Any]:
    """Build a flattened evaluate payload — shared by sync and async clients.

    The server expects fields at the root level (``#[serde(flatten)]``), not
    nested under an ``"action"`` key.
    """
    payload: Dict[str, Any] = {
        "tool": action.tool,
        "function": action.function or "",
        "parameters": action.parameters,
        "target_paths": action.target_paths,
        "target_domains": action.target_domains,
        # SECURITY (FIND-R63-SDK-001): Include resolved_ips for parity with Go SDK.
        "resolved_ips": action.resolved_ips,
    }
    if context:
        payload["context"] = context.to_dict()
    return payload


class VellavetoClient:
    """
    Synchronous client for the Vellaveto API.

    Example:
        client = VellavetoClient(url="http://localhost:3000", api_key="your-key")

        # Evaluate a tool call
        result = client.evaluate(
            tool="filesystem",
            function="read_file",
            parameters={"path": "/etc/passwd"}
        )

        if result.verdict == Verdict.ALLOW:
            # Proceed with tool call
            pass
        elif result.verdict == Verdict.DENY:
            print(f"Denied: {result.reason}")

    Attributes:
        url: Base URL of the Vellaveto server
        api_key: API key for authentication (optional)
        timeout: Request timeout in seconds
        redactor: Optional ParameterRedactor for client-side secret stripping
    """

    def __init__(
        self,
        url: str = "http://localhost:3000",
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        redactor: Optional["ParameterRedactor"] = None,
        max_retries: int = 3,
        tenant: Optional[str] = None,
        fail_closed: bool = False,
    ):
        """
        Initialize the Vellaveto client.

        Args:
            url: Base URL of the Vellaveto server
            api_key: API key for authentication
            timeout: Request timeout in seconds (default: 10.0, aligned with Go/TS SDKs)
            verify_ssl: Whether to verify SSL certificates
            redactor: Optional ParameterRedactor for client-side secret stripping
            max_retries: Maximum number of retries for transient failures
                (connection errors, 502/503/504). Default 3 (aligned with Go/TS SDKs).
            tenant: Optional tenant ID for multi-tenant deployments. Must be
                alphanumeric with hyphens/underscores, max 64 characters.
            fail_closed: When True, evaluate() returns a Deny verdict instead of
                raising on connection errors. This makes the client fail-closed
                without requiring try/except in application code. Default: False
                (raises VellavetoConnectionError for backward compatibility).
        """
        # SECURITY (FIND-R73-SDK-002): Validate base URL — parity with Go/TS SDKs.
        self.url = _validate_base_url(url)
        self.api_key = api_key
        # SECURITY (FIND-R116-CA-003): Validate timeout range — parity with TS SDK
        # ([100ms, 300s]) and Go SDK ([100ms, 300s] with clamping). Python uses
        # seconds, so valid range is [0.1, 300.0].
        if timeout is not None:
            if not isinstance(timeout, (int, float)) or timeout != timeout:
                # timeout != timeout catches NaN
                raise VellavetoError("timeout must be a finite number between 0.1 and 300.0 seconds")
            if timeout < 0.1 or timeout > 300.0:
                raise VellavetoError("timeout must be between 0.1 and 300.0 seconds")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.redactor = redactor
        self.max_retries = max(0, max_retries)

        # Validate tenant ID if provided.
        if tenant is not None:
            if not isinstance(tenant, str):
                raise VellavetoError("tenant must be a string")
            if len(tenant) == 0 or len(tenant) > _MAX_TENANT_LENGTH:
                raise VellavetoError(
                    f"tenant must be between 1 and {_MAX_TENANT_LENGTH} characters"
                )
            if not _TENANT_RE.match(tenant):
                raise VellavetoError(
                    "tenant must match pattern ^[a-zA-Z0-9_-]+$ "
                    "(alphanumeric, hyphens, underscores only)"
                )
        self.tenant = tenant
        self.fail_closed = fail_closed

        if not verify_ssl:
            warnings.warn(
                "SSL verification disabled - connections are vulnerable to MITM attacks",
                SecurityWarning,
                stacklevel=2,
            )

        if HAS_HTTPX:
            # SECURITY (FIND-R155-001): Disable automatic redirects to prevent
            # Authorization header leakage to different domains on 3xx responses.
            self._client = httpx.Client(
                timeout=timeout,
                verify=verify_ssl,
                follow_redirects=False,
            )
            self._use_httpx = True
        elif HAS_REQUESTS:
            self._session = requests.Session()
            # SECURITY (FIND-R155-001): Disable automatic redirects to prevent
            # Authorization header leakage to different domains on 3xx responses.
            self._session.max_redirects = 0
            self._use_httpx = False
        else:
            raise ImportError(
                "Either 'httpx' or 'requests' package is required. "
                "Install with: pip install httpx"
            )

    def __repr__(self) -> str:
        """SECURITY (FIND-SDK-013): Redact api_key in repr to prevent log leakage."""
        return (
            f"VellavetoClient(base_url={self.url!r}, api_key=***, "
            f"timeout={self.timeout}, max_retries={self.max_retries}, "
            f"tenant={self.tenant!r})"
        )

    def __enter__(self) -> "VellavetoClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _headers(self) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self.tenant:
            headers["X-Tenant-ID"] = self.tenant
        return headers

    def _request(
        self,
        method: str,
        path: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Make an HTTP request to the Vellaveto API.

        SECURITY (FIND-SDK-014): Retries transient failures (connection errors,
        502/503/504) up to ``max_retries`` times with exponential backoff
        (0.5s, 1s, 2s, ...).  Non-transient errors are raised immediately.
        """
        url = urljoin(self.url + "/", path.lstrip("/"))

        last_exc: Optional[Exception] = None
        for attempt in range(1 + self.max_retries):
            try:
                if self._use_httpx:
                    response = self._client.request(
                        method=method,
                        url=url,
                        json=json_data,
                        params=params,
                        headers=self._headers(),
                    )
                    # SECURITY (FIND-SDK-014): Retry on transient HTTP status
                    if response.status_code in _TRANSIENT_STATUS_CODES:
                        last_exc = VellavetoError(
                            f"Transient HTTP {response.status_code}"
                        )
                        if attempt < self.max_retries:
                            # SECURITY (FIND-R213-002): Full jitter prevents thundering herd.
                            time.sleep(random.uniform(0, 0.5 * (2 ** attempt)))
                            continue
                        # Last attempt — fall through to "all retries exhausted"
                        break
                    response.raise_for_status()
                    # SECURITY (FIND-SDK-003): Enforce response size limit to prevent OOM
                    # SECURITY (FIND-R51-005): Safe Content-Length parsing
                    content_length = response.headers.get("content-length")
                    if content_length is not None:
                        try:
                            cl = int(content_length)
                        except (ValueError, TypeError):
                            cl = None
                        if cl is not None and cl > _MAX_RESPONSE_BYTES:
                            raise VellavetoError(
                                f"Response too large: {content_length} bytes exceeds "
                                f"{_MAX_RESPONSE_BYTES} byte limit"
                            )
                    if len(response.content) > _MAX_RESPONSE_BYTES:
                        raise VellavetoError(
                            f"Response body too large: {len(response.content)} bytes exceeds "
                            f"{_MAX_RESPONSE_BYTES} byte limit"
                        )
                    return response.json()
                else:
                    response = self._session.request(
                        method=method,
                        url=url,
                        json=json_data,
                        params=params,
                        headers=self._headers(),
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                    )
                    # SECURITY (FIND-SDK-014): Retry on transient HTTP status
                    if response.status_code in _TRANSIENT_STATUS_CODES:
                        last_exc = VellavetoError(
                            f"Transient HTTP {response.status_code}"
                        )
                        if attempt < self.max_retries:
                            # SECURITY (FIND-R213-002): Full jitter prevents thundering herd.
                            time.sleep(random.uniform(0, 0.5 * (2 ** attempt)))
                            continue
                        # Last attempt — fall through to "all retries exhausted"
                        break
                    response.raise_for_status()
                    # SECURITY (FIND-SDK-003): Enforce response size limit to prevent OOM
                    # SECURITY (FIND-R51-005): Safe Content-Length parsing
                    content_length = response.headers.get("content-length")
                    if content_length is not None:
                        try:
                            cl = int(content_length)
                        except (ValueError, TypeError):
                            cl = None
                        if cl is not None and cl > _MAX_RESPONSE_BYTES:
                            raise VellavetoError(
                                f"Response too large: {content_length} bytes exceeds "
                                f"{_MAX_RESPONSE_BYTES} byte limit"
                            )
                    if len(response.content) > _MAX_RESPONSE_BYTES:
                        raise VellavetoError(
                            f"Response body too large: {len(response.content)} bytes exceeds "
                            f"{_MAX_RESPONSE_BYTES} byte limit"
                        )
                    return response.json()

            except (VellavetoError, PolicyDenied, ApprovalRequired):
                raise
            except Exception as e:
                # SECURITY (FIND-SDK-001): Sanitize error messages to prevent API key
                # leakage. The requests/httpx libraries may include the Authorization
                # header in exception messages on connection failures.
                last_exc = e
                # SECURITY (FIND-R110-SDK-001): Match both "ConnectionError" and
                # "ConnectError" (httpx raises ConnectError, requests raises
                # ConnectionError). Check for "Connect" covers both.
                is_connection = "Connect" in str(type(e).__name__)
                # SECURITY (FIND-SDK-014): Retry connection errors
                if is_connection and attempt < self.max_retries:
                    # SECURITY (FIND-R213-002): Full jitter prevents thundering herd.
                    time.sleep(random.uniform(0, 0.5 * (2 ** attempt)))
                    continue
                error_msg = str(e)
                if self.api_key and self.api_key in error_msg:
                    error_msg = error_msg.replace(self.api_key, "[REDACTED]")
                if is_connection:
                    raise ConnectionError(f"Failed to connect to Vellaveto at {url}: {error_msg}")
                raise VellavetoError(f"Request failed: {error_msg}")

        # All retries exhausted
        error_msg = str(last_exc) if last_exc else "Unknown error"
        if self.api_key and self.api_key in error_msg:
            error_msg = error_msg.replace(self.api_key, "[REDACTED]")
        raise VellavetoError(f"Request failed after {self.max_retries + 1} attempts: {error_msg}")

    def evaluate(
        self,
        tool: str,
        function: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        target_paths: Optional[List[str]] = None,
        target_domains: Optional[List[str]] = None,
        context: Optional[EvaluationContext] = None,
        trace: bool = False,
        resolved_ips: Optional[List[str]] = None,
    ) -> EvaluationResult:
        """
        Evaluate a tool call against Vellaveto policies.

        Args:
            tool: Tool name (e.g., "filesystem", "http", "bash")
            function: Function name (e.g., "read_file", "fetch")
            parameters: Tool call parameters
            target_paths: File paths the tool will access
            target_domains: Network domains the tool will access
            context: Evaluation context for stateful policies
            trace: Whether to include evaluation trace
            resolved_ips: Pre-resolved IP addresses for DNS rebinding defense

        Returns:
            EvaluationResult with verdict and details

        Raises:
            PolicyDenied: If policy denies the action (when raise_on_deny=True)
            ApprovalRequired: If action requires approval (when raise_on_deny=True)
            VellavetoError: On API errors
        """
        _validate_evaluate_inputs(tool, function, parameters, target_paths, target_domains, resolved_ips)
        _validate_evaluation_context(context)

        effective_params = parameters or {}
        if self.redactor is not None:
            effective_params = self.redactor.redact(effective_params)

        action = Action(
            tool=tool,
            function=function,
            parameters=effective_params,
            target_paths=target_paths or [],
            target_domains=target_domains or [],
            resolved_ips=resolved_ips or [],
        )

        payload = _build_evaluate_payload(action, context)

        params = {}
        if trace:
            params["trace"] = "true"

        try:
            response = self._request(
                method="POST",
                path="/api/evaluate",
                json_data=payload,
                params=params if params else None,
            )
        except (VellavetoConnectionError, VellavetoError) as e:
            if self.fail_closed and isinstance(e, VellavetoConnectionError):
                logger.warning(
                    "Vellaveto server unreachable (fail_closed=True), denying: %s", e,
                )
                return EvaluationResult(
                    verdict=Verdict.DENY,
                    reason=f"Server unreachable (fail-closed): {e}",
                )
            raise

        return EvaluationResult.from_dict(response)

    def evaluate_or_raise(
        self,
        tool: str,
        function: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        target_paths: Optional[List[str]] = None,
        target_domains: Optional[List[str]] = None,
        context: Optional[EvaluationContext] = None,
        resolved_ips: Optional[List[str]] = None,
    ) -> EvaluationResult:
        """
        Evaluate a tool call, raising an exception if not allowed.

        Same as evaluate(), but raises PolicyDenied or ApprovalRequired
        instead of returning a deny/require_approval verdict.

        Returns:
            EvaluationResult (only if verdict is ALLOW)

        Raises:
            PolicyDenied: If policy denies the action
            ApprovalRequired: If action requires human approval
        """
        result = self.evaluate(
            tool=tool,
            function=function,
            parameters=parameters,
            target_paths=target_paths,
            target_domains=target_domains,
            context=context,
            resolved_ips=resolved_ips,
        )

        if result.verdict == Verdict.DENY:
            raise PolicyDenied(result.reason or "Policy denied", result.policy_id)

        if result.verdict == Verdict.REQUIRE_APPROVAL:
            raise ApprovalRequired(
                result.reason or "Approval required",
                result.approval_id or "unknown",
            )

        return result

    def health(self) -> Dict[str, Any]:
        """Check Vellaveto server health."""
        return self._request("GET", "/health")

    def list_policies(self) -> List[Dict[str, Any]]:
        """List all configured policies."""
        return self._request("GET", "/api/policies")

    def reload_policies(self) -> Dict[str, Any]:
        """Reload policies from configuration."""
        return self._request("POST", "/api/policies/reload")

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get list of pending approval requests."""
        return self._request("GET", "/api/approvals/pending")

    def resolve_approval(
        self,
        approval_id: str,
        approved: bool,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Resolve a pending approval request.

        Args:
            approval_id: ID of the approval request
            approved: Whether to approve or deny
            reason: Optional reason for the decision (max 4096 bytes)
        """
        # SECURITY (FIND-R56-SDK-001): Validate approval_id — aligned with Go/TS SDKs.
        _validate_approval_id(approval_id)
        # SECURITY (FIND-R111-006): Validate reason length and control characters.
        # Parity with server-side MAX_REASON_LEN (4096 bytes in vellaveto-approval).
        # Without this check, an attacker can pass an unbounded reason string that
        # the server must allocate and store in Redis/disk, enabling OOM attacks.
        # SECURITY (FIND-R218-003): Use byte length (UTF-8) to match server's
        # Rust `str::len()` which counts bytes, not characters.
        if reason is not None:
            if not isinstance(reason, str):
                raise VellavetoError("reason must be a string or None")
            byte_len = len(reason.encode("utf-8"))
            if byte_len > 4096:
                raise VellavetoError(
                    f"reason exceeds maximum length (4096 bytes, got {byte_len})"
                )
            if _CONTROL_CHAR_RE.search(reason):
                raise VellavetoError("reason contains control characters")
            # SECURITY (FIND-R112-004): Reject Unicode format characters (zero-width,
            # bidi overrides, BOM, etc.) in reason. These can be used for invisible
            # text manipulation or log injection attacks.
            if _UNICODE_FORMAT_RE.search(reason):
                raise VellavetoError("reason contains Unicode format characters")
        action = "approve" if approved else "deny"
        json_data: Optional[Dict[str, Any]] = None
        if reason is not None:
            json_data = {"reason": reason}
        # SECURITY: URL-encode approval_id to prevent path injection (parity with Go/TS).
        encoded_id = quote(approval_id, safe="")
        return self._request(
            method="POST",
            path=f"/api/approvals/{encoded_id}/{action}",
            json_data=json_data,
        )

    def discover(
        self,
        query: str,
        max_results: int = 5,
        token_budget: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Search the tool discovery index for matching tools.

        Args:
            query: Natural language description of the desired tool
            max_results: Maximum number of results (default: 5, max: 20)
            token_budget: Optional token budget for returned schemas

        Returns:
            Discovery result with ranked tools, total candidates, and policy-filtered count
        """
        # SECURITY (FIND-R55-SDK-001): Validate query non-empty. Parity with TS/Go.
        if not isinstance(query, str) or not query.strip():
            raise VellavetoError("discovery query must not be empty")
        # SECURITY (FIND-R104-SDK-003): Cap query length. Parity with TS SDK (1024).
        if len(query) > 1024:
            raise VellavetoError("discovery query exceeds max length (1024)")
        # SECURITY (FIND-R110-SDK-002): Validate max_results [1, 20]. The docstring
        # documents max 20; enforce it to prevent unbounded result sets.
        if not isinstance(max_results, int) or max_results < 1 or max_results > 20:
            raise VellavetoError("max_results must be an integer in [1, 20]")
        # SECURITY (FIND-R110-SDK-002): Validate token_budget non-negative.
        if token_budget is not None:
            if not isinstance(token_budget, int) or token_budget < 0:
                raise VellavetoError("token_budget must be a non-negative integer")
        payload: Dict[str, Any] = {
            "query": query,
            "max_results": max_results,
        }
        if token_budget is not None:
            payload["token_budget"] = token_budget

        return self._request("POST", "/api/discovery/search", json_data=payload)

    def discovery_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the tool discovery index.

        Returns:
            Index statistics including total tools, max capacity, and enabled status
        """
        return self._request("GET", "/api/discovery/index/stats")

    def discovery_reindex(self) -> Dict[str, Any]:
        """
        Trigger a full rebuild of the IDF weights in the discovery index.

        Returns:
            Status and total tool count after reindex
        """
        return self._request("POST", "/api/discovery/reindex")

    def discovery_tools(
        self,
        server_id: Optional[str] = None,
        sensitivity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List all indexed tools, optionally filtered.

        Args:
            server_id: Filter by originating MCP server ID (max 256 chars)
            sensitivity: Filter by sensitivity level (low, medium, high)

        Returns:
            List of tool metadata objects and total count
        """
        # SECURITY (FIND-R111-009): Validate filter parameters. Without validation,
        # an attacker can inject unbounded or control-character-containing strings
        # into query parameters, potentially causing log injection or server OOM.

        if server_id is not None:
            if not isinstance(server_id, str):
                raise VellavetoError("server_id must be a string or None")
            if len(server_id) > 256:
                raise VellavetoError(
                    f"server_id exceeds maximum length (256 chars, got {len(server_id)})"
                )
            if _CONTROL_CHAR_RE.search(server_id):
                raise VellavetoError("server_id contains control characters")
            # SECURITY (FIND-R157-003): Reject Unicode format characters (zero-width,
            # bidi overrides, soft hyphen, TAG chars). Parity with Go SDK and
            # approval ID validation.
            if _UNICODE_FORMAT_RE.search(server_id):
                raise VellavetoError("server_id contains Unicode format characters")
        if sensitivity is not None:
            if sensitivity not in _VALID_SENSITIVITIES:
                raise VellavetoError(
                    f"sensitivity must be one of {sorted(_VALID_SENSITIVITIES)}, "
                    f"got {sensitivity!r}"
                )
        params: Dict[str, str] = {}
        if server_id is not None:
            params["server_id"] = server_id
        if sensitivity is not None:
            params["sensitivity"] = sensitivity

        return self._request(
            "GET", "/api/discovery/tools", params=params if params else None
        )

    # ── Projector (Phase 35.3) ───────────────────────────────────

    def projector_models(self) -> Dict[str, Any]:
        """
        List supported model families in the projector registry.

        Returns:
            Dictionary with ``model_families`` list of strings
        """
        return self._request("GET", "/api/projector/models")

    def project_schema(
        self,
        schema: Dict[str, Any],
        model_family: str,
    ) -> Dict[str, Any]:
        """
        Project a canonical tool schema for a given model family.

        Args:
            schema: Canonical tool schema dict with name, description,
                input_schema, and optional output_schema
            model_family: Target model family (e.g., "claude", "openai",
                "deepseek", "qwen", "generic")

        Returns:
            Dictionary with projected_schema, token_estimate, and model_family
        """
        # SECURITY (FIND-R55-SDK-007): Validate model_family non-empty.
        if not isinstance(model_family, str) or not model_family.strip():
            raise VellavetoError("model_family must be a non-empty string")
        payload = {
            "schema": schema,
            "model_family": model_family,
        }
        return self._request("POST", "/api/projector/transform", json_data=payload)

    # ── ZK Audit (Phase 37) ────────────────────────────────────────

    def zk_status(self) -> Dict[str, Any]:
        """
        Get the ZK audit scheduler status.

        Returns:
            Dictionary with active, pending_witnesses, completed_proofs,
            last_proved_sequence, and last_proof_at
        """
        return self._request("GET", "/api/zk-audit/status")

    def zk_proofs(
        self,
        limit: int = 20,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        List stored ZK batch proofs with pagination.

        Args:
            limit: Maximum number of proofs to return (default: 20, range: [1, 1000])
            offset: Offset for pagination (default: 0, must be >= 0)

        Returns:
            Dictionary with proofs list, total count, offset, and limit
        """
        # SECURITY (FIND-R111-007): Validate limit and offset bounds. Without
        # validation, an attacker can request limit=2^63 to cause OOM on the
        # server, or offset=-1 to trigger undefined server behavior.
        if not isinstance(limit, int) or limit < 1 or limit > 1000:
            raise VellavetoError("limit must be an integer in [1, 1000]")
        if not isinstance(offset, int) or offset < 0:
            raise VellavetoError("offset must be a non-negative integer")
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        return self._request("GET", "/api/zk-audit/proofs", params=params)

    def zk_verify(self, batch_id: str) -> Dict[str, Any]:
        """
        Verify a stored ZK batch proof.

        Args:
            batch_id: The batch identifier to verify

        Returns:
            Dictionary with valid, batch_id, entry_range, verified_at, and error
        """
        # SECURITY (FIND-R55-SDK-002): Validate batch_id non-empty. Parity with TS/Go.
        if not isinstance(batch_id, str) or not batch_id.strip():
            raise VellavetoError("batch_id must not be empty")
        return self._request(
            "POST", "/api/zk-audit/verify", json_data={"batch_id": batch_id}
        )

    def zk_commitments(
        self,
        from_seq: int,
        to_seq: int,
    ) -> Dict[str, Any]:
        """
        List Pedersen commitments for audit entries in a sequence range.

        Args:
            from_seq: Start of the entry range (sequence number)
            to_seq: End of the entry range (sequence number, inclusive)

        Returns:
            Dictionary with commitments list, total count, and range
        """
        # SECURITY (FIND-R104-SDK-004): Validate sequence range. Parity with TS SDK.
        if not isinstance(from_seq, int) or from_seq < 0:
            raise VellavetoError("from_seq must be a non-negative integer")
        if not isinstance(to_seq, int) or to_seq < 0:
            raise VellavetoError("to_seq must be a non-negative integer")
        if from_seq > to_seq:
            raise VellavetoError("from_seq must be <= to_seq")
        params = {"from": from_seq, "to": to_seq}
        return self._request("GET", "/api/zk-audit/commitments", params=params)

    def soc2_access_review(
        self,
        period: str = "30d",
        export_format: str = "json",
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a SOC 2 Type II access review report.

        Args:
            period: Review period duration (e.g. "30d", "7d", "90d")
            export_format: Export format ("json" or "html")
            agent_id: Optional agent ID filter (max 128 chars)

        Returns:
            Access review report as dictionary (JSON) or raw HTML string
        """
        # SECURITY (FIND-R82-004): Validate period parameter. Parity with TS SDK.
        if not isinstance(period, str) or len(period) == 0:
            raise VellavetoError("period must be a non-empty string")
        if len(period) > 32:
            raise VellavetoError("period exceeds max length (32)")
        if not _re.match(r'^[a-zA-Z0-9\-:]+$', period):
            raise VellavetoError(
                "period contains invalid characters: only alphanumeric, dashes, and colons are allowed"
            )
        # SECURITY (FIND-R72-SDK-007): Validate format parameter. Parity with Go/TS SDKs.
        if export_format not in ("json", "html"):
            raise VellavetoError(
                f'export_format must be "json" or "html", got {export_format!r}'
            )
        if agent_id is not None:
            if not isinstance(agent_id, str):
                raise VellavetoError("agent_id must be a string")
            if len(agent_id) > 128:
                raise VellavetoError("agent_id exceeds max length (128)")
            # SECURITY (FIND-R55-SDK-003): Reject control chars. Parity with federation_trust_anchors.
            if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in agent_id):
                raise VellavetoError("agent_id contains control characters")
            # SECURITY (FIND-R112-005): Reject Unicode format characters (zero-width,
            # bidi overrides, BOM, etc.). Parity with resolve_approval reason check.
            if _UNICODE_FORMAT_RE.search(agent_id):
                raise VellavetoError("agent_id contains Unicode format characters")
        params: Dict[str, Any] = {"period": period, "format": export_format}
        if agent_id is not None:
            params["agent_id"] = agent_id
        return self._request("GET", "/api/compliance/soc2/access-review", params=params)

    # ── Federation (Phase 39) ─────────────────────────────────────

    def federation_status(self) -> Dict[str, Any]:
        """
        Get federation status including per-anchor cache info.

        Returns:
            Dictionary with enabled, trust_anchor_count, and anchors list
        """
        return self._request("GET", "/api/federation/status")

    def federation_trust_anchors(
        self,
        org_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List federation trust anchors.

        Args:
            org_id: Optional filter by organization ID (max 128 chars)

        Returns:
            Dictionary with anchors list and total count
        """
        params: Dict[str, str] = {}
        if org_id is not None:
            if len(org_id) > 128:
                raise VellavetoError("org_id exceeds max length (128)")
            # SECURITY (FIND-R50-037): Catch DEL (0x7F) and C1 control chars (0x80-0x9F)
            if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in org_id):
                raise VellavetoError("org_id contains control characters")
            # SECURITY (FIND-R112-006): Reject Unicode format characters (zero-width,
            # bidi overrides, BOM, etc.). Parity with Go SDK and evaluation context checks.
            if _UNICODE_FORMAT_RE.search(org_id):
                raise VellavetoError("org_id contains Unicode format characters")
            params["org_id"] = org_id
        return self._request(
            "GET", "/api/federation/trust-anchors", params=params if params else None
        )

    def owasp_asi_coverage(self) -> Dict[str, Any]:
        """
        Get OWASP Agentic Security Index (ASI) coverage report.

        Returns:
            Dictionary with ASI coverage metrics (total_controls,
            covered_controls, coverage_percent, category_coverage,
            control_matrix).
        """
        return self._request("GET", "/api/compliance/owasp-agentic")

    # ── Evidence Packs (Phase 48) ─────────────────────────────────

    # Allowed evidence pack frameworks
    _EVIDENCE_PACK_FRAMEWORKS = ("dora", "nis2", "iso42001", "eu-ai-act")

    def evidence_pack(
        self,
        framework: str,
        export_format: str = "json",
    ) -> Dict[str, Any]:
        """
        Generate a compliance evidence pack for the specified framework.

        Args:
            framework: Framework identifier ("dora", "nis2", "iso42001", "eu-ai-act")
            export_format: Export format ("json" or "html")

        Returns:
            Evidence pack as dictionary (JSON) or raw HTML string
        """
        if not isinstance(framework, str) or len(framework) == 0:
            raise VellavetoError("framework must be a non-empty string")
        if framework not in self._EVIDENCE_PACK_FRAMEWORKS:
            raise VellavetoError(
                f'framework must be one of {self._EVIDENCE_PACK_FRAMEWORKS}, got {framework!r}'
            )
        if export_format not in ("json", "html"):
            raise VellavetoError(
                f'export_format must be "json" or "html", got {export_format!r}'
            )
        params: Dict[str, Any] = {}
        if export_format != "json":
            params["format"] = export_format
        path = f"/api/compliance/evidence-pack/{quote(framework, safe='')}"
        return self._request("GET", path, params=params if params else None)

    def evidence_pack_status(self) -> Dict[str, Any]:
        """
        Get evidence pack status — which frameworks are available.

        Returns:
            Dictionary with available_frameworks list, dora_enabled, nis2_enabled.
        """
        return self._request("GET", "/api/compliance/evidence-pack/status")

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 50: Usage Metering & Billing
    # ═══════════════════════════════════════════════════════════════════════

    def usage(self, tenant_id: str) -> Dict[str, Any]:
        """
        Get current-period usage metrics for a tenant.

        Args:
            tenant_id: Tenant identifier (1-64 chars, alphanumeric/hyphens/underscores).

        Returns:
            Dictionary with evaluations, policies_created, approvals_processed,
            audit_entries, period_start, period_end.
        """
        if not tenant_id or len(tenant_id) > _MAX_TENANT_LENGTH:
            raise ValueError("tenant_id must be 1-64 characters")
        if not _TENANT_RE.match(tenant_id):
            raise ValueError("tenant_id must be alphanumeric, hyphens, or underscores")
        return self._request("GET", f"/api/billing/usage/{quote(tenant_id, safe='')}")

    def quota_status(self, tenant_id: str) -> Dict[str, Any]:
        """
        Get quota status (usage vs limits) for a tenant.

        Args:
            tenant_id: Tenant identifier (1-64 chars, alphanumeric/hyphens/underscores).

        Returns:
            Dictionary with evaluations_used, evaluations_limit, evaluations_remaining,
            policies_used, policies_limit, quota_exceeded, period_start, period_end.
        """
        if not tenant_id or len(tenant_id) > _MAX_TENANT_LENGTH:
            raise ValueError("tenant_id must be 1-64 characters")
        if not _TENANT_RE.match(tenant_id):
            raise ValueError("tenant_id must be alphanumeric, hyphens, or underscores")
        return self._request("GET", f"/api/billing/quotas/{quote(tenant_id, safe='')}")

    def usage_history(self, tenant_id: str, periods: int = 12) -> Dict[str, Any]:
        """
        Get usage history across billing periods for a tenant.

        Args:
            tenant_id: Tenant identifier (1-64 chars, alphanumeric/hyphens/underscores).
            periods: Number of periods to return (max 120, default 12).

        Returns:
            Dictionary with tenant_id, periods list, total_evaluations.
        """
        if not tenant_id or len(tenant_id) > _MAX_TENANT_LENGTH:
            raise ValueError("tenant_id must be 1-64 characters")
        if not _TENANT_RE.match(tenant_id):
            raise ValueError("tenant_id must be alphanumeric, hyphens, or underscores")
        if periods < 1 or periods > 120:
            raise ValueError("periods must be between 1 and 120")
        params: Dict[str, Any] = {"periods": periods}
        return self._request(
            "GET",
            f"/api/billing/usage/{quote(tenant_id, safe='')}/history",
            params=params,
        )

    def close(self):
        """Close the client and release resources."""
        if self._use_httpx and hasattr(self, "_client"):
            self._client.close()

    # ═══════════════════════════════════════════════════════════════════════
    # Content-Bound Attestation Verification
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def verify_attestation(response: Dict[str, Any], hmac_key: bytes) -> bool:
        """Verify the proxy's content attestation on a response.

        Returns True if the attestation HMAC is valid and the content hash
        matches the response body. Returns False if verification fails or
        no attestation is present.

        Args:
            response: The JSON-RPC response dict from the proxy.
            hmac_key: The shared HMAC secret (same as VELLAVETO_ATTESTATION_SECRET).

        Returns:
            True if attestation is present and valid, False otherwise.
        """
        import hashlib
        import hmac as hmac_mod

        meta = response.get("_meta", {})
        attestation = meta.get("vellaveto_attestation")
        if not attestation:
            return False

        # Verify content hash matches
        content = response.get("result") or response.get("error")
        canonical = json.dumps(content, sort_keys=False, separators=(",", ":"))
        expected_hash = hashlib.sha256(canonical.encode()).hexdigest()
        if attestation.get("content_hash") != expected_hash:
            return False

        # Verify HMAC signature
        signing_content = (
            f"v{attestation['version']}:{attestation['timestamp']}"
            f":{attestation['content_hash']}"
            f":{str(attestation['injection_clean']).lower()}"
            f":{str(attestation['dlp_clean']).lower()}"
            f":{str(attestation['schema_valid']).lower()}"
            f":{attestation['trust_tier']}:{attestation['scan_passes']}"
        )
        expected_sig = hmac_mod.new(
            hmac_key, signing_content.encode(), hashlib.sha256
        ).hexdigest()
        return hmac_mod.compare_digest(attestation.get("signature", ""), expected_sig)


class AsyncVellavetoClient:
    """
    Asynchronous client for the Vellaveto API.

    Example:
        async with AsyncVellavetoClient(url="http://localhost:3000") as client:
            result = await client.evaluate(
                tool="filesystem",
                function="read_file",
                parameters={"path": "/etc/passwd"}
            )

    Requires httpx to be installed: pip install httpx
    """

    def __init__(
        self,
        url: str = "http://localhost:3000",
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        redactor: Optional["ParameterRedactor"] = None,
        max_retries: int = 3,
        tenant: Optional[str] = None,
    ):
        """
        Initialize the async Vellaveto client.

        Args:
            url: Base URL of the Vellaveto server
            api_key: API key for authentication
            timeout: Request timeout in seconds (default: 10.0, aligned with Go/TS SDKs)
            verify_ssl: Whether to verify SSL certificates
            redactor: Optional ParameterRedactor for client-side secret stripping
            max_retries: Maximum number of retries for transient failures
                (connection errors, 502/503/504). Default 3 (aligned with Go/TS SDKs).
            tenant: Optional tenant ID for multi-tenant deployments. Must be
                alphanumeric with hyphens/underscores, max 64 characters.
        """
        if not HAS_HTTPX:
            raise ImportError(
                "AsyncVellavetoClient requires 'httpx' package. "
                "Install with: pip install httpx"
            )

        # SECURITY (FIND-R73-SDK-002): Validate base URL — parity with Go/TS SDKs.
        self.url = _validate_base_url(url)
        self.api_key = api_key
        # SECURITY (FIND-R116-CA-003): Validate timeout range — parity with TS SDK
        # ([100ms, 300s]) and Go SDK ([100ms, 300s] with clamping). Python uses
        # seconds, so valid range is [0.1, 300.0].
        if timeout is not None:
            if not isinstance(timeout, (int, float)) or timeout != timeout:
                # timeout != timeout catches NaN
                raise VellavetoError("timeout must be a finite number between 0.1 and 300.0 seconds")
            if timeout < 0.1 or timeout > 300.0:
                raise VellavetoError("timeout must be between 0.1 and 300.0 seconds")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.redactor = redactor
        self.max_retries = max(0, max_retries)

        # Validate tenant ID if provided.
        if tenant is not None:
            if not isinstance(tenant, str):
                raise VellavetoError("tenant must be a string")
            if len(tenant) == 0 or len(tenant) > _MAX_TENANT_LENGTH:
                raise VellavetoError(
                    f"tenant must be between 1 and {_MAX_TENANT_LENGTH} characters"
                )
            if not _TENANT_RE.match(tenant):
                raise VellavetoError(
                    "tenant must match pattern ^[a-zA-Z0-9_-]+$ "
                    "(alphanumeric, hyphens, underscores only)"
                )
        self.tenant = tenant

        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "AsyncVellavetoClient":
        # SECURITY (FIND-R155-001): Disable automatic redirects to prevent
        # Authorization header leakage to different domains on 3xx responses.
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            follow_redirects=False,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()

    def __repr__(self) -> str:
        """SECURITY (FIND-R56-SDK-002): Redact api_key in repr, matching sync client."""
        return (
            f"AsyncVellavetoClient(base_url={self.url!r}, api_key=***, "
            f"timeout={self.timeout}, max_retries={self.max_retries}, "
            f"tenant={self.tenant!r})"
        )

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self.tenant:
            headers["X-Tenant-ID"] = self.tenant
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Make an HTTP request to the Vellaveto API (async).

        SECURITY (FIND-R51-003): Retries transient failures (connection errors,
        502/503/504) up to ``max_retries`` times with exponential backoff
        (0.5s, 1s, 2s, ...).  Non-transient errors are raised immediately.
        """
        if not self._client:
            raise VellavetoError("Client not initialized. Use 'async with' context.")

        url = urljoin(self.url + "/", path.lstrip("/"))

        last_exc: Optional[Exception] = None
        for attempt in range(1 + self.max_retries):
            try:
                response = await self._client.request(
                    method=method,
                    url=url,
                    json=json_data,
                    params=params,
                    headers=self._headers(),
                )
                # SECURITY (FIND-R51-003): Retry on transient HTTP status
                if response.status_code in _TRANSIENT_STATUS_CODES:
                    last_exc = VellavetoError(
                        f"Transient HTTP {response.status_code}"
                    )
                    if attempt < self.max_retries:
                        # SECURITY (FIND-R213-002): Full jitter prevents thundering herd.
                        await asyncio.sleep(random.uniform(0, 0.5 * (2 ** attempt)))
                        continue
                    # Last attempt — fall through to "all retries exhausted"
                    break
                response.raise_for_status()
                # SECURITY (FIND-SDK-003): Enforce response size limit to prevent OOM
                # SECURITY (FIND-R51-005): Safe Content-Length parsing
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        cl = int(content_length)
                    except (ValueError, TypeError):
                        cl = None
                    if cl is not None and cl > _MAX_RESPONSE_BYTES:
                        raise VellavetoError(
                            f"Response too large: {content_length} bytes exceeds "
                            f"{_MAX_RESPONSE_BYTES} byte limit"
                        )
                if len(response.content) > _MAX_RESPONSE_BYTES:
                    raise VellavetoError(
                        f"Response body too large: {len(response.content)} bytes exceeds "
                        f"{_MAX_RESPONSE_BYTES} byte limit"
                    )
                return response.json()

            except (VellavetoError, PolicyDenied, ApprovalRequired):
                raise
            except Exception as e:
                # SECURITY (FIND-SDK-001): Sanitize error messages in async client too.
                last_exc = e
                # SECURITY (FIND-R110-SDK-001): Match both "ConnectionError" and
                # "ConnectError" (httpx raises ConnectError). Check for "Connect"
                # covers both names.
                is_connection = "Connect" in str(type(e).__name__)
                # SECURITY (FIND-R51-003): Retry connection errors
                if is_connection and attempt < self.max_retries:
                    # SECURITY (FIND-R213-002): Full jitter prevents thundering herd.
                    await asyncio.sleep(random.uniform(0, 0.5 * (2 ** attempt)))
                    continue
                error_msg = str(e)
                if self.api_key and self.api_key in error_msg:
                    error_msg = error_msg.replace(self.api_key, "[REDACTED]")
                if is_connection:
                    raise ConnectionError(f"Failed to connect to Vellaveto at {url}: {error_msg}")
                raise VellavetoError(f"Request failed: {error_msg}")

        # All retries exhausted
        error_msg = str(last_exc) if last_exc else "Unknown error"
        if self.api_key and self.api_key in error_msg:
            error_msg = error_msg.replace(self.api_key, "[REDACTED]")
        raise VellavetoError(f"Request failed after {self.max_retries + 1} attempts: {error_msg}")

    async def evaluate(
        self,
        tool: str,
        function: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        target_paths: Optional[List[str]] = None,
        target_domains: Optional[List[str]] = None,
        context: Optional[EvaluationContext] = None,
        trace: bool = False,
        resolved_ips: Optional[List[str]] = None,
    ) -> EvaluationResult:
        """Evaluate a tool call against Vellaveto policies (async)."""
        _validate_evaluate_inputs(tool, function, parameters, target_paths, target_domains, resolved_ips)
        _validate_evaluation_context(context)

        effective_params = parameters or {}
        if self.redactor is not None:
            effective_params = self.redactor.redact(effective_params)

        action = Action(
            tool=tool,
            function=function,
            parameters=effective_params,
            target_paths=target_paths or [],
            target_domains=target_domains or [],
            resolved_ips=resolved_ips or [],
        )

        payload = _build_evaluate_payload(action, context)

        params = {}
        if trace:
            params["trace"] = "true"

        response = await self._request(
            method="POST",
            path="/api/evaluate",
            json_data=payload,
            params=params if params else None,
        )

        return EvaluationResult.from_dict(response)

    async def evaluate_or_raise(
        self,
        tool: str,
        function: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        target_paths: Optional[List[str]] = None,
        target_domains: Optional[List[str]] = None,
        context: Optional[EvaluationContext] = None,
        resolved_ips: Optional[List[str]] = None,
    ) -> EvaluationResult:
        """Evaluate and raise exception if not allowed (async)."""
        result = await self.evaluate(
            tool=tool,
            function=function,
            parameters=parameters,
            target_paths=target_paths,
            target_domains=target_domains,
            context=context,
            resolved_ips=resolved_ips,
        )

        if result.verdict == Verdict.DENY:
            raise PolicyDenied(result.reason or "Policy denied", result.policy_id)

        if result.verdict == Verdict.REQUIRE_APPROVAL:
            raise ApprovalRequired(
                result.reason or "Approval required",
                result.approval_id or "unknown",
            )

        return result

    async def health(self) -> Dict[str, Any]:
        """Check Vellaveto server health (async)."""
        return await self._request("GET", "/health")

    async def list_policies(self) -> List[Dict[str, Any]]:
        """List all configured policies (async)."""
        return await self._request("GET", "/api/policies")

    async def reload_policies(self) -> Dict[str, Any]:
        """Reload policies from configuration (async)."""
        return await self._request("POST", "/api/policies/reload")

    async def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get list of pending approval requests (async)."""
        return await self._request("GET", "/api/approvals/pending")

    async def resolve_approval(
        self,
        approval_id: str,
        approved: bool,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Resolve a pending approval request (async).

        Args:
            approval_id: ID of the approval request
            approved: Whether to approve or deny
            reason: Optional reason for the decision (max 4096 bytes)
        """
        # SECURITY (FIND-R56-SDK-001): Validate approval_id — aligned with Go/TS SDKs.
        _validate_approval_id(approval_id)
        # SECURITY (FIND-R111-006): Validate reason length and control characters.
        # Parity with server-side MAX_REASON_LEN (4096 bytes in vellaveto-approval).
        # SECURITY (FIND-R218-003): Use byte length (UTF-8) to match server.
        if reason is not None:
            if not isinstance(reason, str):
                raise VellavetoError("reason must be a string or None")
            byte_len = len(reason.encode("utf-8"))
            if byte_len > 4096:
                raise VellavetoError(
                    f"reason exceeds maximum length (4096 bytes, got {byte_len})"
                )
            if _CONTROL_CHAR_RE.search(reason):
                raise VellavetoError("reason contains control characters")
            # SECURITY (FIND-R112-004): Reject Unicode format characters (async parity).
            if _UNICODE_FORMAT_RE.search(reason):
                raise VellavetoError("reason contains Unicode format characters")
        action = "approve" if approved else "deny"
        json_data: Optional[Dict[str, Any]] = None
        if reason is not None:
            json_data = {"reason": reason}
        # SECURITY: URL-encode approval_id to prevent path injection (parity with Go/TS).
        encoded_id = quote(approval_id, safe="")
        return await self._request(
            method="POST",
            path=f"/api/approvals/{encoded_id}/{action}",
            json_data=json_data,
        )

    async def discover(
        self,
        query: str,
        max_results: int = 5,
        token_budget: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Search the tool discovery index for matching tools (async)."""
        # SECURITY (FIND-R55-SDK-001): Validate query non-empty.
        if not isinstance(query, str) or not query.strip():
            raise VellavetoError("discovery query must not be empty")
        # SECURITY (FIND-R104-SDK-003): Cap query length. Parity with TS SDK (1024).
        if len(query) > 1024:
            raise VellavetoError("discovery query exceeds max length (1024)")
        # SECURITY (FIND-R110-SDK-002): Validate max_results [1, 20]. Parity with sync.
        if not isinstance(max_results, int) or max_results < 1 or max_results > 20:
            raise VellavetoError("max_results must be an integer in [1, 20]")
        # SECURITY (FIND-R110-SDK-002): Validate token_budget non-negative.
        if token_budget is not None:
            if not isinstance(token_budget, int) or token_budget < 0:
                raise VellavetoError("token_budget must be a non-negative integer")
        payload: Dict[str, Any] = {
            "query": query,
            "max_results": max_results,
        }
        if token_budget is not None:
            payload["token_budget"] = token_budget

        return await self._request(
            "POST", "/api/discovery/search", json_data=payload
        )

    async def discovery_stats(self) -> Dict[str, Any]:
        """Get statistics about the tool discovery index (async)."""
        return await self._request("GET", "/api/discovery/index/stats")

    async def discovery_reindex(self) -> Dict[str, Any]:
        """Trigger a full rebuild of the IDF weights (async)."""
        return await self._request("POST", "/api/discovery/reindex")

    async def discovery_tools(
        self,
        server_id: Optional[str] = None,
        sensitivity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List all indexed tools, optionally filtered (async).

        Args:
            server_id: Filter by originating MCP server ID (max 256 chars)
            sensitivity: Filter by sensitivity level (low, medium, high)
        """
        # SECURITY (FIND-R111-009): Validate filter parameters (async parity).

        if server_id is not None:
            if not isinstance(server_id, str):
                raise VellavetoError("server_id must be a string or None")
            if len(server_id) > 256:
                raise VellavetoError(
                    f"server_id exceeds maximum length (256 chars, got {len(server_id)})"
                )
            if _CONTROL_CHAR_RE.search(server_id):
                raise VellavetoError("server_id contains control characters")
            # SECURITY (FIND-R157-003): Reject Unicode format characters (async parity).
            if _UNICODE_FORMAT_RE.search(server_id):
                raise VellavetoError("server_id contains Unicode format characters")
        if sensitivity is not None:
            if sensitivity not in _VALID_SENSITIVITIES:
                raise VellavetoError(
                    f"sensitivity must be one of {sorted(_VALID_SENSITIVITIES)}, "
                    f"got {sensitivity!r}"
                )
        params: Dict[str, str] = {}
        if server_id is not None:
            params["server_id"] = server_id
        if sensitivity is not None:
            params["sensitivity"] = sensitivity

        return await self._request(
            "GET", "/api/discovery/tools", params=params if params else None
        )

    # ── Projector (Phase 35.3) ───────────────────────────────────

    async def projector_models(self) -> Dict[str, Any]:
        """List supported model families in the projector registry (async)."""
        return await self._request("GET", "/api/projector/models")

    async def project_schema(
        self,
        schema: Dict[str, Any],
        model_family: str,
    ) -> Dict[str, Any]:
        """Project a canonical tool schema for a given model family (async)."""
        # SECURITY (FIND-R55-SDK-007): Validate model_family non-empty.
        if not isinstance(model_family, str) or not model_family.strip():
            raise VellavetoError("model_family must be a non-empty string")
        payload = {
            "schema": schema,
            "model_family": model_family,
        }
        return await self._request(
            "POST", "/api/projector/transform", json_data=payload
        )

    # ── ZK Audit (Phase 37) ────────────────────────────────────────

    async def zk_status(self) -> Dict[str, Any]:
        """Get the ZK audit scheduler status (async)."""
        return await self._request("GET", "/api/zk-audit/status")

    async def zk_proofs(
        self,
        limit: int = 20,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List stored ZK batch proofs with pagination (async).

        Args:
            limit: Maximum number of proofs to return (default: 20, range: [1, 1000])
            offset: Offset for pagination (default: 0, must be >= 0)
        """
        # SECURITY (FIND-R111-007): Validate limit and offset bounds (async parity).
        if not isinstance(limit, int) or limit < 1 or limit > 1000:
            raise VellavetoError("limit must be an integer in [1, 1000]")
        if not isinstance(offset, int) or offset < 0:
            raise VellavetoError("offset must be a non-negative integer")
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        return await self._request("GET", "/api/zk-audit/proofs", params=params)

    async def zk_verify(self, batch_id: str) -> Dict[str, Any]:
        """Verify a stored ZK batch proof (async)."""
        # SECURITY (FIND-R55-SDK-002): Validate batch_id non-empty.
        if not isinstance(batch_id, str) or not batch_id.strip():
            raise VellavetoError("batch_id must not be empty")
        return await self._request(
            "POST", "/api/zk-audit/verify", json_data={"batch_id": batch_id}
        )

    async def zk_commitments(
        self,
        from_seq: int,
        to_seq: int,
    ) -> Dict[str, Any]:
        """List Pedersen commitments for entries in a sequence range (async)."""
        # SECURITY (FIND-R104-SDK-004): Validate sequence range. Parity with TS SDK.
        if not isinstance(from_seq, int) or from_seq < 0:
            raise VellavetoError("from_seq must be a non-negative integer")
        if not isinstance(to_seq, int) or to_seq < 0:
            raise VellavetoError("to_seq must be a non-negative integer")
        if from_seq > to_seq:
            raise VellavetoError("from_seq must be <= to_seq")
        params = {"from": from_seq, "to": to_seq}
        return await self._request(
            "GET", "/api/zk-audit/commitments", params=params
        )

    async def soc2_access_review(
        self,
        period: str = "30d",
        export_format: str = "json",
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate a SOC 2 Type II access review report (async).

        Args:
            period: Review period duration (e.g. "30d", "7d", "90d")
            export_format: Export format ("json" or "html")
            agent_id: Optional agent ID filter (max 128 chars)

        Returns:
            Access review report as dictionary (JSON) or raw HTML string
        """
        # SECURITY (FIND-R82-004): Validate period parameter. Parity with TS SDK.
        if not isinstance(period, str) or len(period) == 0:
            raise VellavetoError("period must be a non-empty string")
        if len(period) > 32:
            raise VellavetoError("period exceeds max length (32)")
        if not _re.match(r'^[a-zA-Z0-9\-:]+$', period):
            raise VellavetoError(
                "period contains invalid characters: only alphanumeric, dashes, and colons are allowed"
            )
        # SECURITY (FIND-R72-SDK-007): Validate format parameter. Parity with Go/TS SDKs.
        if export_format not in ("json", "html"):
            raise VellavetoError(
                f'export_format must be "json" or "html", got {export_format!r}'
            )
        if agent_id is not None:
            if not isinstance(agent_id, str):
                raise VellavetoError("agent_id must be a string")
            if len(agent_id) > 128:
                raise VellavetoError("agent_id exceeds max length (128)")
            # SECURITY (FIND-R55-SDK-003): Reject control chars.
            if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in agent_id):
                raise VellavetoError("agent_id contains control characters")
            # SECURITY (FIND-R112-005): Reject Unicode format characters (async parity).
            if _UNICODE_FORMAT_RE.search(agent_id):
                raise VellavetoError("agent_id contains Unicode format characters")
        params: Dict[str, Any] = {"period": period, "format": export_format}
        if agent_id is not None:
            params["agent_id"] = agent_id
        return await self._request(
            "GET", "/api/compliance/soc2/access-review", params=params
        )

    # ── Federation (Phase 39) ─────────────────────────────────────

    async def federation_status(self) -> Dict[str, Any]:
        """Get federation status including per-anchor cache info (async)."""
        return await self._request("GET", "/api/federation/status")

    async def federation_trust_anchors(
        self,
        org_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List federation trust anchors (async)."""
        params: Dict[str, str] = {}
        if org_id is not None:
            if len(org_id) > 128:
                raise VellavetoError("org_id exceeds max length (128)")
            # SECURITY (FIND-R50-037): Catch DEL (0x7F) and C1 control chars (0x80-0x9F)
            if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in org_id):
                raise VellavetoError("org_id contains control characters")
            # SECURITY (FIND-R112-006): Reject Unicode format characters (async parity).
            if _UNICODE_FORMAT_RE.search(org_id):
                raise VellavetoError("org_id contains Unicode format characters")
            params["org_id"] = org_id
        return await self._request(
            "GET", "/api/federation/trust-anchors", params=params if params else None
        )

    async def owasp_asi_coverage(self) -> Dict[str, Any]:
        """Get OWASP Agentic Security Index (ASI) coverage report (async)."""
        return await self._request("GET", "/api/compliance/owasp-agentic")

    # ── Evidence Packs (Phase 48) ─────────────────────────────────

    _EVIDENCE_PACK_FRAMEWORKS = ("dora", "nis2", "iso42001", "eu-ai-act")

    async def evidence_pack(
        self,
        framework: str,
        export_format: str = "json",
    ) -> Dict[str, Any]:
        """Generate a compliance evidence pack (async)."""
        if not isinstance(framework, str) or len(framework) == 0:
            raise VellavetoError("framework must be a non-empty string")
        if framework not in self._EVIDENCE_PACK_FRAMEWORKS:
            raise VellavetoError(
                f'framework must be one of {self._EVIDENCE_PACK_FRAMEWORKS}, got {framework!r}'
            )
        if export_format not in ("json", "html"):
            raise VellavetoError(
                f'export_format must be "json" or "html", got {export_format!r}'
            )
        params: Dict[str, Any] = {}
        if export_format != "json":
            params["format"] = export_format
        path = f"/api/compliance/evidence-pack/{quote(framework, safe='')}"
        return await self._request("GET", path, params=params if params else None)

    async def evidence_pack_status(self) -> Dict[str, Any]:
        """Get evidence pack status (async)."""
        return await self._request("GET", "/api/compliance/evidence-pack/status")

    # ═══════════════════════════════════════════════════════════════════════
    # Phase 50: Usage Metering & Billing
    # ═══════════════════════════════════════════════════════════════════════

    async def usage(self, tenant_id: str) -> Dict[str, Any]:
        """Get current-period usage metrics for a tenant (async)."""
        if not tenant_id or len(tenant_id) > _MAX_TENANT_LENGTH:
            raise ValueError("tenant_id must be 1-64 characters")
        if not _TENANT_RE.match(tenant_id):
            raise ValueError("tenant_id must be alphanumeric, hyphens, or underscores")
        return await self._request("GET", f"/api/billing/usage/{quote(tenant_id, safe='')}")

    async def quota_status(self, tenant_id: str) -> Dict[str, Any]:
        """Get quota status (usage vs limits) for a tenant (async)."""
        if not tenant_id or len(tenant_id) > _MAX_TENANT_LENGTH:
            raise ValueError("tenant_id must be 1-64 characters")
        if not _TENANT_RE.match(tenant_id):
            raise ValueError("tenant_id must be alphanumeric, hyphens, or underscores")
        return await self._request("GET", f"/api/billing/quotas/{quote(tenant_id, safe='')}")

    async def usage_history(self, tenant_id: str, periods: int = 12) -> Dict[str, Any]:
        """Get usage history across billing periods for a tenant (async)."""
        if not tenant_id or len(tenant_id) > _MAX_TENANT_LENGTH:
            raise ValueError("tenant_id must be 1-64 characters")
        if not _TENANT_RE.match(tenant_id):
            raise ValueError("tenant_id must be alphanumeric, hyphens, or underscores")
        if periods < 1 or periods > 120:
            raise ValueError("periods must be between 1 and 120")
        params: Dict[str, Any] = {"periods": periods}
        return await self._request(
            "GET",
            f"/api/billing/usage/{quote(tenant_id, safe='')}/history",
            params=params,
        )

    # ═══════════════════════════════════════════════════════════════════════
    # Content-Bound Attestation Verification
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def verify_attestation(response: Dict[str, Any], hmac_key: bytes) -> bool:
        """Verify the proxy's content attestation on a response.

        Delegates to VellavetoClient.verify_attestation (same logic).
        """
        return VellavetoClient.verify_attestation(response, hmac_key)
