"""Everything that originates from a source is untrusted data (ТЗ §6.8).

Before any source-derived value reaches a model it is sanitised, truncated and wrapped in a
clearly delimited block whose delimiter cannot be forged from inside the data.
"""
from __future__ import annotations

import json
import re
from typing import Any

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
_WS = re.compile(r"\s+")


def sanitize_text(value: str, max_len: int = 200) -> str:
    value = _WS.sub(" ", _CTRL.sub(" ", value)).strip()
    return value if len(value) <= max_len else value[: max_len - 1] + "…"


def sanitize(obj: Any, *, max_len: int = 200, max_items: int = 20, depth: int = 5) -> Any:
    if depth <= 0:
        return None
    if isinstance(obj, str):
        return sanitize_text(obj, max_len)
    if isinstance(obj, bool) or obj is None or isinstance(obj, (int, float)):
        return obj
    if isinstance(obj, dict):
        return {sanitize_text(str(k), 64): sanitize(v, max_len=max_len, max_items=max_items, depth=depth - 1)
                for k, v in list(obj.items())[:max_items]}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [sanitize(v, max_len=max_len, max_items=max_items, depth=depth - 1) for v in list(obj)[:max_items]]
    return sanitize_text(str(obj), max_len)


def untrusted_block(label: str, obj: Any, *, max_len: int = 200) -> str:
    """max_len bounds each individual string field. The default (200) suits small structured metadata
    (a title, a capability name). Callers embedding a real text blob a model must reason over (a full
    document, a classification sample) MUST pass a max_len matching their own actual size budget -
    otherwise this silently re-truncates to 200 chars regardless of what the caller intended, which
    also breaks evidence verification done against the caller's own (longer) reference string."""
    safe_label = re.sub(r"[^a-z0-9_]", "", label.lower())[:32] or "data"
    payload = json.dumps(sanitize(obj, max_len=max_len), ensure_ascii=True, sort_keys=True)
    # '<' / '>' only occur inside JSON strings; escaping them makes the closing tag unforgeable.
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e")
    return f'<untrusted_data label="{safe_label}">\n{payload}\n</untrusted_data>'
