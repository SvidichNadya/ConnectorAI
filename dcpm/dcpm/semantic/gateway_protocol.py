"""Shared model-gateway protocol. compiler.ModelGateway is kept as an alias for backward compatibility."""
from __future__ import annotations

from typing import Protocol


class ChatGateway(Protocol):
    def complete_json(self, *, system: str, user: str, max_tokens: int) -> str: ...
