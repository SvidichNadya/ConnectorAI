"""Secret redaction for logs, errors and anything that could reach a model prompt."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*)(bearer\s+|basic\s+)?[^\s,;\"']+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret|password|passwd|token)(\s*[:=]\s*)[^\s,;&\"']+"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/\-]{16,}=*"), r"\1 [REDACTED]"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"), "[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"), "[REDACTED]"),
    (re.compile(r"://[^/\s:@]+:[^/\s@]+@"), "://[REDACTED]@"),
]

_SENSITIVE_QUERY = re.compile(r"(?i)(token|key|secret|password|passwd|sig|signature|auth|session|credential)")


def redact(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


def redact_url(url: str) -> str:
    """Mask userinfo and sensitive query values; safe for logs."""
    try:
        parts = urlsplit(url)
        netloc = parts.netloc.rsplit("@", 1)[-1]
        q = [(k, "[REDACTED]" if _SENSITIVE_QUERY.search(k) else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
        return urlunsplit((parts.scheme, netloc, parts.path, urlencode(q, safe="[]"), ""))
    except ValueError:
        return "[INVALID_URL]"
