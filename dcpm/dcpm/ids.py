from __future__ import annotations

import re
import secrets
import time
from datetime import datetime, timezone

_ID_RE = re.compile(r"^[a-z]{2,5}_[0-9a-f]{16,40}$")
_TENANT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def new_id(prefix: str) -> str:
    return f"{prefix}_{time.time_ns():x}{secrets.token_hex(6)}"


def is_valid_id(value: object, prefix: str | None = None) -> bool:
    if not isinstance(value, str) or not _ID_RE.match(value):
        return False
    return prefix is None or value.startswith(prefix + "_")


def is_valid_tenant(value: object) -> bool:
    return isinstance(value, str) and bool(_TENANT_RE.match(value))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
