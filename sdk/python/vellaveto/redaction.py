"""
Client-side parameter redaction for Vellaveto SDK.

Strips or masks sensitive parameter values before they are sent to the
Vellaveto server for policy evaluation. This prevents secrets from
transiting the network even when the Vellaveto server is trusted.

Example:
    from vellaveto import VellavetoClient
    from vellaveto.redaction import ParameterRedactor

    redactor = ParameterRedactor()
    client = VellavetoClient(url="http://localhost:3000", redactor=redactor)

    # The api_key value will be replaced with "[REDACTED]" before sending
    client.evaluate(
        tool="http",
        function="fetch",
        parameters={"url": "https://api.example.com", "api_key": "sk-1234567890"}
    )
"""

import re
from typing import Any, Dict, FrozenSet, List, Optional, Pattern, Set


# Default parameter names considered sensitive (case-insensitive matching)
DEFAULT_SENSITIVE_KEYS: FrozenSet[str] = frozenset({
    # Authentication
    "password",
    "passwd",
    "pass",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api_secret",
    "access_token",
    "refresh_token",
    "auth_token",
    "bearer",
    "authorization",
    # Credentials
    "credential",
    "credentials",
    "private_key",
    "private_key_pem",
    "signing_key",
    "encryption_key",
    "master_key",
    "session_token",
    "session_key",
    "client_secret",
    # Database
    "connection_string",
    "database_url",
    "db_password",
    "db_pass",
    # Cloud/service keys
    "aws_secret_access_key",
    "aws_session_token",
    "gcp_credentials",
    "azure_key",
    "stripe_key",
    "sendgrid_key",
    "twilio_token",
    "slack_token",
    "github_token",
    "gitlab_token",
    # SSH
    "ssh_key",
    "ssh_passphrase",
    # Certificates
    "cert_key",
    "ssl_key",
    "tls_key",
})

# Patterns that match secret-like values (e.g., "sk-...", "ghp_...", "xoxb-...")
# SECURITY (FIND-SDK-007): Use non-anchored patterns so embedded secrets are detected
# via re.search(). Patterns use word-boundary or prefix matching instead of ^/$.
_SECRET_VALUE_PATTERNS: List[str] = [
    r"sk-[a-zA-Z0-9]{20,}",             # OpenAI-style keys
    r"ghp_[a-zA-Z0-9]{36,}",            # GitHub personal access tokens
    r"gho_[a-zA-Z0-9]{36,}",            # GitHub OAuth tokens
    r"github_pat_[a-zA-Z0-9_]{20,}",    # GitHub fine-grained PATs
    r"xoxb-[0-9]+-[a-zA-Z0-9]+",        # Slack bot tokens
    r"xoxp-[0-9]+-[a-zA-Z0-9]+",        # Slack user tokens
    r"glpat-[a-zA-Z0-9_-]{20,}",        # GitLab PATs
    r"AKIA[0-9A-Z]{16}",                # AWS access key IDs
    r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",  # JWTs
    # SECURITY (FIND-SDK-012): Additional secret patterns
    r"sk_live_[a-zA-Z0-9]{20,}",         # Stripe live keys
    r"sk-ant-[a-zA-Z0-9_-]{20,}",        # Anthropic API keys
    r"npm_[a-zA-Z0-9]{20,}",             # npm tokens
    r"pypi-[a-zA-Z0-9_-]{20,}",          # PyPI tokens
]

REDACTED_PLACEHOLDER = "[REDACTED]"


class ParameterRedactor:
    """
    Redacts sensitive parameter values before they are sent to Vellaveto.

    Supports three modes of redaction:
    - ``keys_only``: Redact values whose parameter name matches a sensitive key
    - ``values``: Also scan string values for secret-like patterns
    - ``all``: Redact all parameter values (send only keys)

    Example:
        redactor = ParameterRedactor()  # defaults to "keys_only"

        # Only sensitive key names are redacted
        redactor.redact({"path": "/tmp/x", "api_key": "sk-123"})
        # => {"path": "/tmp/x", "api_key": "[REDACTED]"}

        redactor = ParameterRedactor(mode="values")

        # Also scans values for secret patterns
        redactor.redact({"path": "/tmp/x", "config": "sk-abcdefghijklmnopqrstuvwxyz"})
        # => {"path": "/tmp/x", "config": "[REDACTED]"}

    Attributes:
        mode: Redaction mode ("keys_only", "values", or "all")
        sensitive_keys: Set of parameter names considered sensitive
        placeholder: Replacement string for redacted values
    """

    def __init__(
        self,
        mode: str = "keys_only",
        sensitive_keys: Optional[Set[str]] = None,
        extra_keys: Optional[Set[str]] = None,
        placeholder: str = REDACTED_PLACEHOLDER,
        scan_values: Optional[bool] = None,
    ):
        """
        Initialize the parameter redactor.

        Args:
            mode: Redaction mode - "keys_only" (default), "values", or "all"
            sensitive_keys: Override the default sensitive key set entirely
            extra_keys: Additional keys to add to the default set
            placeholder: Replacement string for redacted values
            scan_values: Deprecated, use mode="values" instead
        """
        if mode not in ("keys_only", "values", "all"):
            raise ValueError(f"Invalid redaction mode: {mode!r}. Must be 'keys_only', 'values', or 'all'.")

        # Handle deprecated scan_values parameter
        if scan_values is not None:
            mode = "values" if scan_values else "keys_only"

        self.mode = mode
        self.placeholder = placeholder

        if sensitive_keys is not None:
            self._sensitive_keys = {k.lower() for k in sensitive_keys}
        else:
            self._sensitive_keys = set(DEFAULT_SENSITIVE_KEYS)

        if extra_keys:
            self._sensitive_keys.update(k.lower() for k in extra_keys)

        # Compile value patterns once
        self._value_patterns: List[Pattern] = [
            re.compile(p) for p in _SECRET_VALUE_PATTERNS
        ]

    @property
    def sensitive_keys(self) -> Set[str]:
        """Return the current set of sensitive keys."""
        return self._sensitive_keys.copy()

    def is_sensitive_key(self, key: str) -> bool:
        """Check if a parameter key is considered sensitive."""
        normalized = key.lower().replace("-", "_")
        # Direct match
        if normalized in self._sensitive_keys:
            return True
        # Suffix match: "x_api_key" matches "api_key"
        for sensitive in self._sensitive_keys:
            if normalized.endswith(f"_{sensitive}") or normalized.endswith(f".{sensitive}"):
                return True
        return False

    def is_sensitive_value(self, value: Any) -> bool:
        """Check if a string value looks like a secret.

        Also accepts bytes, which are decoded as UTF-8 before scanning
        (FIND-SDK-006).
        """
        # SECURITY (FIND-SDK-006): Convert bytes to str before scanning
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if not isinstance(value, str) or len(value) < 8:
            return False
        # SECURITY (FIND-SDK-007): Use re.search() so embedded secrets are detected
        return any(p.search(value) for p in self._value_patterns)

    def redact(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact sensitive values from a parameters dictionary.

        Args:
            parameters: Tool call parameters to redact

        Returns:
            New dictionary with sensitive values replaced by placeholder
        """
        if not parameters:
            return parameters

        if self.mode == "all":
            return {k: self.placeholder for k in parameters}

        return self._redact_dict(parameters)

    def _redact_dict(self, d: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
        """Recursively redact sensitive values in a dictionary."""
        if depth > 10:
            # Prevent stack overflow on deeply nested structures
            return {k: self.placeholder for k in d}

        result: Dict[str, Any] = {}
        for key, value in d.items():
            if self.is_sensitive_key(key):
                result[key] = self.placeholder
            elif isinstance(value, dict):
                result[key] = self._redact_dict(value, depth + 1)
            elif isinstance(value, list):
                result[key] = self._redact_list(value, depth + 1)
            elif self.mode == "values" and isinstance(value, (str, bytes)) and self.is_sensitive_value(value):
                result[key] = self.placeholder
            else:
                result[key] = value
        return result

    def _redact_list(self, lst: List[Any], depth: int = 0) -> List[Any]:
        """Recursively redact sensitive values in a list."""
        if depth > 10:
            return [self.placeholder for _ in lst]

        result: List[Any] = []
        for item in lst:
            if isinstance(item, dict):
                result.append(self._redact_dict(item, depth + 1))
            elif isinstance(item, list):
                result.append(self._redact_list(item, depth + 1))
            elif self.mode == "values" and isinstance(item, (str, bytes)) and self.is_sensitive_value(item):
                result.append(self.placeholder)
            else:
                result.append(item)
        return result
