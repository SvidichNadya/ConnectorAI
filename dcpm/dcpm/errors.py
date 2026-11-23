"""Error catalogue (ТЗ §7.5). Every failure inside DCPM is a DCPMError with a stable code."""
from __future__ import annotations

from typing import Any

from .security.redact import redact

ERROR_CATALOG: dict[str, dict[str, bool]] = {
    "AUTH_REQUIRED": {"retryable": False, "requires_reauthentication": True, "requires_operator_action": True},
    "PERMISSION_DENIED": {"retryable": False, "requires_operator_action": True},
    "SOURCE_UNAVAILABLE": {"retryable": True},
    "RATE_LIMITED": {"retryable": True},
    "NETWORK_ERROR": {"retryable": True},
    "TIMEOUT": {"retryable": True},
    "TLS_ERROR": {"retryable": False},
    "SOURCE_NOT_FOUND": {"retryable": False},
    "HTTP_ERROR": {"retryable": False},
    "INVALID_URL": {"retryable": False},
    "UNSUPPORTED_PROTOCOL": {"retryable": False},
    "UNSUPPORTED_FORMAT": {"retryable": False},
    "UNSUPPORTED_ENCODING": {"retryable": False},
    "POLICY_BLOCKED": {"retryable": False, "requires_operator_action": True},
    "SSRF_BLOCKED": {"retryable": False},
    "ROBOTS_DISALLOWED": {"retryable": False},
    "OUT_OF_SCOPE": {"retryable": False},
    "PARSE_FAILED": {"retryable": False},
    "SCHEMA_DRIFT": {"retryable": False, "requires_rediscovery": True},
    "PLAN_INVALID": {"retryable": False, "requires_recompilation": True},
    "BUDGET_EXCEEDED": {"retryable": False},
    "RESPONSE_TOO_LARGE": {"retryable": False},
    "QUOTA_EXCEEDED": {"retryable": False},
    "CHECKPOINT_INVALID": {"retryable": False},
    "STORAGE_FAILURE": {"retryable": True},
    "MODEL_UNAVAILABLE": {"retryable": True},
    "CANCELLED": {"retryable": False},
    "INTERNAL_ERROR": {"retryable": False},
    # API-level
    "UNAUTHENTICATED": {"retryable": False},
    "VALIDATION_ERROR": {"retryable": False},
    "NOT_FOUND": {"retryable": False},
    "CONFLICT": {"retryable": False},
    "IDEMPOTENCY_KEY_REUSED": {"retryable": False},
    "PAYLOAD_TOO_LARGE": {"retryable": False},
}

# Failures that mean "cannot continue without a change in access/policy" (run status BLOCKED).
BLOCKING_CODES = frozenset({"AUTH_REQUIRED", "PERMISSION_DENIED", "POLICY_BLOCKED", "SSRF_BLOCKED"})

HTTP_STATUS = {
    "UNAUTHENTICATED": 401, "VALIDATION_ERROR": 422, "NOT_FOUND": 404, "CONFLICT": 409,
    "IDEMPOTENCY_KEY_REUSED": 422, "PAYLOAD_TOO_LARGE": 413, "RATE_LIMITED": 429,
    "SSRF_BLOCKED": 422, "OUT_OF_SCOPE": 422, "INVALID_URL": 422, "POLICY_BLOCKED": 403,
    "PLAN_INVALID": 422,
}


class DCPMError(Exception):
    def __init__(self, code: str, message: str, *, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})

    @property
    def meta(self) -> dict[str, bool]:
        return ERROR_CATALOG.get(self.code, {})

    @property
    def retryable(self) -> bool:
        return bool(self.meta.get("retryable", False))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": redact(self.message),
            "retryable": self.retryable,
            "requires_reauthentication": bool(self.meta.get("requires_reauthentication", False)),
            "requires_rediscovery": bool(self.meta.get("requires_rediscovery", False)),
            "requires_recompilation": bool(self.meta.get("requires_recompilation", False)),
            "requires_operator_action": bool(self.meta.get("requires_operator_action", False)),
            "details": self.details,
        }

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.code}: {self.message}"
