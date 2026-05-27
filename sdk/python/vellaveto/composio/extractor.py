"""
Target extraction and tool slug normalization for Composio integration.

Composio uses uppercase slugs like ``GITHUB_CREATE_ISSUE`` that need to be
split into a tool name and function name for Vellaveto policy evaluation.

This module provides pure functions with no external dependencies.
"""

from typing import Any, Dict, List, Tuple

# Maximum targets extracted on client side (matches server MAX_TARGETS = 256)
_MAX_CLIENT_TARGETS = 256

# Maximum recursion depth for nested argument extraction
_MAX_EXTRACT_DEPTH = 5

# SECURITY (FIND-COMPOSIO-007): Maximum number of top-level keys in arguments
# to prevent CPU exhaustion from pathologically large dicts.
_MAX_ARGUMENT_KEYS = 1024

# Parameter names that indicate file-system paths
# SECURITY (FIND-COMPOSIO-005): Added common variants (src, dst, target, etc.)
_PATH_KEYS = frozenset({
    "path", "file", "filename", "filepath", "file_path",
    "directory", "dir", "folder", "dest", "destination", "source",
    "src", "dst", "target", "target_path", "output", "output_path",
    "input_path", "input_file", "local_path", "remote_path",
})

# Parameter names that indicate network targets
# SECURITY (FIND-COMPOSIO-005): Added common variants (server_url, target_url, etc.)
_DOMAIN_KEYS = frozenset({
    "url", "uri", "endpoint", "host", "domain", "repo_url",
    "base_url", "api_url", "webhook_url", "callback_url",
    "server_url", "target_url", "redirect_url", "proxy_url",
    "origin", "hostname", "server", "upstream_url",
})

# URL schemes to detect (checked case-insensitively)
_URL_SCHEMES = ("http://", "https://", "ftp://", "ws://", "wss://")
_FILE_SCHEME = "file://"


def normalize_slug_to_tool_function(
    slug: str,
    toolkit: str = "",
) -> Tuple[str, str]:
    """Convert a Composio tool slug to a ``(tool, function)`` pair.

    Composio slugs follow the pattern ``TOOLKIT_ACTION_NAME`` (uppercase,
    underscore-delimited).  When a *toolkit* hint is provided, the toolkit
    prefix is stripped from the slug to produce the function name.  Otherwise
    the first underscore-delimited segment is assumed to be the toolkit.

    Examples::

        normalize_slug_to_tool_function("GITHUB_CREATE_ISSUE", "GITHUB")
        # => ("github", "create_issue")

        normalize_slug_to_tool_function("SLACK_SEND_MESSAGE")
        # => ("slack", "send_message")

        normalize_slug_to_tool_function("MYTOOL")
        # => ("mytool", "mytool")

    Args:
        slug: The Composio action slug (e.g. ``"GITHUB_CREATE_ISSUE"``).
            Must be a non-empty ASCII string.
        toolkit: Optional toolkit name hint.  When supplied, the toolkit
            prefix is stripped from *slug* to derive the function name.

    Returns:
        A ``(tool, function)`` tuple of lower-cased strings.

    Raises:
        ValueError: If *slug* is not a non-empty ASCII string.
    """
    if not isinstance(slug, str) or not slug.strip():
        raise ValueError(f"Invalid slug: {slug!r}")

    if not slug.isascii():
        raise ValueError(
            f"Slug contains non-ASCII characters: {slug!r}"
        )

    slug_lower = slug.casefold()
    toolkit_lower = toolkit.casefold() if isinstance(toolkit, str) and toolkit else ""

    if toolkit_lower and slug_lower.startswith(toolkit_lower + "_"):
        function = slug_lower[len(toolkit_lower) + 1:]
        # SECURITY (FIND-COMPOSIO-008): Reject empty function after prefix strip
        if function:
            return (toolkit_lower, function)

    # Fall back to first-underscore split
    parts = slug_lower.split("_", 1)
    # SECURITY (FIND-COMPOSIO-008): Both components must be non-empty
    if len(parts) == 2 and parts[0] and parts[1]:
        return (parts[0], parts[1])

    # Single-segment slug — use as both tool and function
    return (slug_lower, slug_lower)


def extract_targets(
    slug: str,
    arguments: Dict[str, Any],
) -> Tuple[List[str], List[str]]:
    """Extract ``target_paths`` and ``target_domains`` from Composio arguments.

    Mirrors the heuristic from ``vellaveto.langchain._extract_tool_info``:

    * Keys matching ``_PATH_KEYS`` are treated as file-system paths.
    * Keys matching ``_DOMAIN_KEYS`` are treated as network targets.
    * Any string value starting with a URL scheme (case-insensitive) is also
      captured as a domain target.
    * ``file://`` URIs are extracted as paths.
    * Nested dicts and lists are walked up to 5 levels deep.

    Args:
        slug: The Composio action slug (unused in extraction but reserved
            for future per-tool rules).
        arguments: The tool call arguments dictionary.

    Returns:
        A ``(target_paths, target_domains)`` tuple of string lists.
    """
    target_paths: List[str] = []
    target_domains: List[str] = []

    if not isinstance(arguments, dict):
        return (target_paths, target_domains)

    # SECURITY (FIND-COMPOSIO-007): Bound arguments dict size to prevent CPU exhaustion
    if len(arguments) > _MAX_ARGUMENT_KEYS:
        import logging
        logging.getLogger(__name__).warning(
            "Arguments dict too large (%d keys > %d), truncating extraction",
            len(arguments), _MAX_ARGUMENT_KEYS,
        )

    _extract_recursive(arguments, target_paths, target_domains, 0)

    # SECURITY (FIND-COMPOSIO-004): Flag paths with traversal sequences for server-side
    # enforcement.  The server already blocks ".." in PathRules, but we log a warning
    # client-side so operators can detect probing attempts.
    for p in target_paths:
        if ".." in p:
            import logging
            logging.getLogger(__name__).warning(
                "Path traversal sequence detected in extracted target: %s", p[:200]
            )

    return (target_paths, target_domains)


def _extract_recursive(
    data: Any,
    target_paths: List[str],
    target_domains: List[str],
    depth: int,
) -> None:
    """Recursively extract targets from nested structures."""
    if depth > _MAX_EXTRACT_DEPTH:
        return
    if len(target_paths) + len(target_domains) >= _MAX_CLIENT_TARGETS:
        return

    if isinstance(data, dict):
        for key, value in data.items():
            if len(target_paths) + len(target_domains) >= _MAX_CLIENT_TARGETS:
                return
            if not isinstance(key, str):
                continue

            if isinstance(value, str):
                _classify_string_value(key, value, target_paths, target_domains)
            elif isinstance(value, (dict, list)):
                _extract_recursive(value, target_paths, target_domains, depth + 1)

    elif isinstance(data, list):
        for item in data:
            if len(target_paths) + len(target_domains) >= _MAX_CLIENT_TARGETS:
                return
            if isinstance(item, str):
                # List items have no key context — check URL patterns only
                _classify_url_value(item, target_paths, target_domains)
            elif isinstance(item, (dict, list)):
                _extract_recursive(item, target_paths, target_domains, depth + 1)


def _classify_string_value(
    key: str,
    value: str,
    target_paths: List[str],
    target_domains: List[str],
) -> None:
    """Classify a string value as path, domain, or both based on key name and value."""
    if not value:
        return

    # SECURITY (FIND-COMPOSIO-006): casefold() handles locale-sensitive casing
    # (e.g. German eszett, Turkish dotted I) more robustly than lower().
    key_lower = key.casefold()
    value_stripped = value.strip()
    value_lower = value_stripped.lower()

    # Check key-based classification (independent checks, not elif)
    if key_lower in _PATH_KEYS:
        target_paths.append(value)

    if key_lower in _DOMAIN_KEYS:
        target_domains.append(value)

    # Auto-detect URL schemes (case-insensitive) regardless of key name
    if value_lower.startswith(_URL_SCHEMES):
        if value not in target_domains:
            target_domains.append(value)
    elif value_lower.startswith(_FILE_SCHEME):
        # file:// URI — extract path portion
        file_path = value[len(_FILE_SCHEME):]
        if file_path and file_path not in target_paths:
            target_paths.append(file_path)


def _classify_url_value(
    value: str,
    target_paths: List[str],
    target_domains: List[str],
) -> None:
    """Classify a string value by URL pattern only (no key context)."""
    if not value:
        return

    value_lower = value.strip().lower()
    if value_lower.startswith(_URL_SCHEMES):
        if value not in target_domains:
            target_domains.append(value)
    elif value_lower.startswith(_FILE_SCHEME):
        file_path = value[len(_FILE_SCHEME):]
        if file_path and file_path not in target_paths:
            target_paths.append(file_path)
