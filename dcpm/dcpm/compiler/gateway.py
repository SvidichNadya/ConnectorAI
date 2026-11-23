"""Model Gateway contract. The compiler never talks to a model directly and never passes secrets to it.

Kept as a thin alias of the shared ChatGateway protocol so the Compiler and the Semantic Engine can
both be pointed at the same LocalLLMClient instance without a hard dependency between the two.
"""
from __future__ import annotations

from ..semantic.gateway_protocol import ChatGateway as ModelGateway  # noqa: F401
