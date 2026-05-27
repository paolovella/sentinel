"""
Client-side response scanning for Composio integration.

Provides lightweight DLP (Data Loss Prevention) and prompt injection
detection on tool call responses.  This is defense-in-depth — the full
Aho-Corasick + NFKC + 5-layer decode scanning runs server-side via the
Vellaveto HTTP proxy.  The client-side scanner catches obvious leaks and
injections using regex patterns.

Reuses ``ParameterRedactor.is_sensitive_value()`` for secret-pattern
detection when a redactor is provided.
"""

import re
import logging
import unicodedata
from dataclasses import dataclass, field
from typing import Any, List, Optional, Pattern

logger = logging.getLogger(__name__)

# Injection patterns — lightweight regex for common prompt injection
# indicators in tool responses.  Not a substitute for server-side scanning.
_DEFAULT_INJECTION_PATTERNS: List[str] = [
    r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)",
    r"(?i)you\s+are\s+now\s+(a|an|in)\s+",
    r"(?i)system\s*:\s*",
    r"(?i)new\s+instructions?\s*:",
    r"(?i)\bdo\s+not\s+follow\s+(the\s+)?(original|previous|prior)\b",
    r"(?i)\b(admin|root|sudo)\s+override\b",
    r"(?i)\bact\s+as\s+(a|an|if)\b",
    r"(?i)\bforget\s+(everything|all|your)\b",
    r"(?i)\brole\s*:\s*system\b",
    r"(?i)<\s*\/?system\s*>",
]

# Zero-width and invisible characters to strip before pattern matching
_INVISIBLE_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u00ad\ufeff\u200e\u200f\u2060\u2061\u2062\u2063\u2064]"
)

# SECURITY (FIND-COMPOSIO-006): Maximum string length to apply regex scanning
# (1 MB).  Strings exceeding this are truncated for injection scanning only.
_MAX_SCAN_STRING_LEN = 1_048_576

# Maximum findings before stopping scan (prevents resource exhaustion)
# SECURITY (FIND-COMPOSIO-005): Capped at 100.
_MAX_FINDINGS = 100

# SECURITY (FIND-COMPOSIO-010): Maximum total nodes walked to prevent CPU exhaustion
_MAX_TOTAL_NODES = 100_000

# ReDoS detection: reject patterns with nested quantifiers like (a+)+ or (a*)*
_NESTED_QUANTIFIER_RE = re.compile(r"[+*]\)?[+*{]")


@dataclass
class ScanFinding:
    """A single finding from response scanning.

    Attributes:
        category: ``"secret"`` or ``"injection"``.
        field_path: Dot-delimited JSON path to the finding.
        pattern: The pattern name or regex that matched.
        snippet: A safe excerpt.  For secrets, this is ``"[REDACTED]"``
            to prevent leaking the detected value.
    """
    category: str
    field_path: str
    pattern: str
    snippet: str = ""


@dataclass
class ResponseScanResult:
    """Result of scanning a Composio tool response.

    Attributes:
        findings: List of individual findings.
        blocked: ``True`` if the response should be blocked.
        truncated: ``True`` if scanning stopped early due to finding cap.
    """
    findings: List[ScanFinding] = field(default_factory=list)
    blocked: bool = False
    truncated: bool = False


class ResponseScanner:
    """Scans Composio tool responses for secrets and injection indicators.

    Args:
        redactor: Optional ``ParameterRedactor`` whose
            ``is_sensitive_value()`` method is used for secret detection.
            When *None*, secret scanning is skipped.
        injection_patterns: Override the default injection regex list.
        scan_depth: Maximum recursion depth for nested structures
            (default 10, range 1–50).
    """

    def __init__(
        self,
        redactor: Optional[Any] = None,
        injection_patterns: Optional[List[str]] = None,
        scan_depth: int = 10,
    ):
        self._redactor = redactor
        if scan_depth < 1:
            raise ValueError(f"scan_depth must be >= 1, got {scan_depth}")
        self._scan_depth = min(scan_depth, 50)

        raw_patterns = injection_patterns if injection_patterns is not None else _DEFAULT_INJECTION_PATTERNS
        # SECURITY (FIND-COMPOSIO-002): Validate user patterns to prevent ReDoS
        self._injection_patterns: List[Pattern[str]] = []
        for p in raw_patterns:
            # Reject patterns with nested quantifiers that can cause catastrophic backtracking
            if _NESTED_QUANTIFIER_RE.search(p):
                logger.warning("Skipping potentially dangerous regex pattern: %s", p[:80])
                continue
            try:
                self._injection_patterns.append(re.compile(p))
            except re.error as exc:
                logger.warning("Skipping invalid regex pattern %r: %s", p[:80], exc)

    def scan(self, response_data: Any) -> ResponseScanResult:
        """Scan *response_data* for secrets and injection indicators.

        Recursively walks dicts and lists up to ``scan_depth`` levels.

        Args:
            response_data: The Composio response payload (typically a dict).

        Returns:
            ``ResponseScanResult`` with any findings.
        """
        result = ResponseScanResult()
        # SECURITY (FIND-COMPOSIO-008): Track visited object ids to prevent
        # infinite loops from circular references.
        visited: set = set()
        # SECURITY (FIND-COMPOSIO-010): Count total nodes to bound CPU work.
        node_count = [0]
        self._walk(response_data, "", 0, result, visited, node_count)
        if result.findings:
            result.blocked = True
        return result

    # ── internal helpers ─────────────────────────────────────────

    def _walk(
        self,
        value: Any,
        path: str,
        depth: int,
        result: ResponseScanResult,
        visited: set,
        node_count: list,
    ) -> None:
        # SECURITY (FIND-COMPOSIO-010): Bail if total work limit exceeded
        node_count[0] += 1
        if node_count[0] > _MAX_TOTAL_NODES:
            result.truncated = True
            return
        if depth >= self._scan_depth:
            return
        if len(result.findings) >= _MAX_FINDINGS:
            result.truncated = True
            return

        if isinstance(value, str):
            self._scan_string(value, path, result)
        elif isinstance(value, bytes):
            # SECURITY (FIND-COMPOSIO-009): Decode bytes to string for scanning
            try:
                self._scan_string(value.decode("utf-8", errors="replace"), path, result)
            except Exception:
                pass  # Skip non-decodable bytes
        elif isinstance(value, dict):
            # SECURITY (FIND-COMPOSIO-008): Circular reference protection
            obj_id = id(value)
            if obj_id in visited:
                return
            visited.add(obj_id)
            try:
                for k, v in value.items():
                    if len(result.findings) >= _MAX_FINDINGS:
                        result.truncated = True
                        return
                    if node_count[0] > _MAX_TOTAL_NODES:
                        result.truncated = True
                        return
                    # SECURITY (FIND-COMPOSIO-011): Guard against non-string dict keys
                    if not isinstance(k, str):
                        k_safe = str(k)
                    elif "." in k:
                        # SECURITY (FIND-COMPOSIO-012): Escape dots in field path keys
                        k_safe = k.replace(".", "\\.")
                    else:
                        k_safe = k
                    child_path = f"{path}.{k_safe}" if path else k_safe
                    self._walk(v, child_path, depth + 1, result, visited, node_count)
            finally:
                visited.discard(obj_id)
        elif isinstance(value, (list, tuple)):
            # SECURITY (FIND-COMPOSIO-008): Circular reference protection
            obj_id = id(value)
            if obj_id in visited:
                return
            visited.add(obj_id)
            try:
                for i, item in enumerate(value):
                    if len(result.findings) >= _MAX_FINDINGS:
                        result.truncated = True
                        return
                    if node_count[0] > _MAX_TOTAL_NODES:
                        result.truncated = True
                        return
                    child_path = f"{path}[{i}]"
                    self._walk(item, child_path, depth + 1, result, visited, node_count)
            finally:
                visited.discard(obj_id)

    def _scan_string(
        self,
        value: str,
        path: str,
        result: ResponseScanResult,
    ) -> None:
        if len(result.findings) >= _MAX_FINDINGS:
            result.truncated = True
            return

        # Secret detection via redactor patterns (check stripped value)
        if self._redactor is not None:
            stripped = value.strip()
            if self._redactor.is_sensitive_value(stripped):
                result.findings.append(ScanFinding(
                    category="secret",
                    field_path=path,
                    pattern="secret_value_pattern",
                    snippet="[REDACTED]",
                ))

        # Truncate for injection scanning to bound CPU
        scan_value = value[:_MAX_SCAN_STRING_LEN] if len(value) > _MAX_SCAN_STRING_LEN else value

        # NFKC normalize and strip invisible characters before pattern matching
        scan_value = unicodedata.normalize("NFKC", scan_value)
        scan_value = _INVISIBLE_CHARS.sub("", scan_value)

        # Injection pattern matching
        for pattern in self._injection_patterns:
            if pattern.search(scan_value):
                result.findings.append(ScanFinding(
                    category="injection",
                    field_path=path,
                    pattern=pattern.pattern,
                    snippet=self._truncate(scan_value),
                ))
                # One injection finding per field is enough
                break

    @staticmethod
    def _truncate(value: str, max_len: int = 60) -> str:
        """Truncate value for snippet display.

        SECURITY (FIND-COMPOSIO-010): Snippets may appear in logs or error
        responses.  To prevent secret leakage, we only show the first
        ``max_len`` characters and replace common secret prefixes with
        a generic marker.
        """
        if len(value) <= max_len:
            excerpt = value
        else:
            excerpt = value[:max_len - 3] + "..."
        # Extra safety: mask anything that looks like a secret prefix
        # (e.g., "sk-...", "ghp_...", "AKIA...") in the snippet
        import re
        excerpt = re.sub(
            r"(sk-|ghp_|gho_|ghs_|ghr_|AKIA|AIza|xox[bpras]-|eyJ)\S{4,}",
            r"\1[MASKED]",
            excerpt,
        )
        return excerpt
