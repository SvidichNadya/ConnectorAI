"""Shared helper: pull a single JSON object out of a model's raw text answer.

Models often wrap JSON in prose or code fences despite instructions. This never trusts the
result; callers still run it through their own deterministic validator.
"""
from __future__ import annotations

import json
import re
from typing import Any

_FENCE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.S)
_FIRST_OBJ = re.compile(r"\{.*\}", re.S)


def extract_json(text: str, limit: int) -> Any:
    if not isinstance(text, str):
        raise ValueError("model answer must be text")
    if len(text) > limit:
        raise ValueError("model answer too large")
    t = text.strip()
    m = _FENCE.match(t)
    if m:
        t = m.group(1)
    try:
        return json.loads(t)
    except ValueError:
        pass
    m = _FIRST_OBJ.search(t)  # last resort: largest {...} span, for models that add a trailing remark
    if not m:
        raise ValueError("no JSON object found in model answer")
    return json.loads(m.group(0))
