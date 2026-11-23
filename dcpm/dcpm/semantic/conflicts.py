"""Conflict resolution over assertions (ТЗ §10.9): different sources disagreeing about one fact.

No assertion is ever deleted or silently overwritten; "the canonical value" is a *computed, reversible
view* over the full assertion ledger, recomputed from scratch every time (see Store.assertions_for /
set_canonical_value). The policy below is deliberately simple and fully deterministic - duplicate
reporting of one underlying fact (e.g. twenty sites re-publishing one press release) must not be
allowed to out-vote a single better-corroborated, independent source, which is why corroboration is
counted by DISTINCT source_id, not by assertion count.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

POLICY_VERSION = "1.0"


def _value_key(value: Any) -> str:
    import json
    return json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)


@dataclass(frozen=True)
class CanonicalResult:
    value: Any
    confidence: float
    based_on: list[str]       # assertion ids that support the winning value
    corroboration: int        # distinct sources agreeing with the winning value
    contested: bool           # True if at least one other value has its own independent corroboration


def compute_canonical(assertions: list[dict[str, Any]]) -> CanonicalResult | None:
    """assertions: ACTIVE rows for one (entity, attribute) from Store.assertions_for(). FACT-type only
    contributes to the vote; PLAN/FORECAST/OPINION are informational and never decide the canonical
    value on their own (ТЗ §10.1: a prediction is not a fact)."""
    facts = [a for a in assertions if a.get("assertion_type", "FACT") == "FACT"]
    pool = facts or assertions  # if literally nothing is marked FACT, fall back rather than returning nothing
    if not pool:
        return None
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in pool:
        groups[_value_key(a["value"])].append(a)

    def score(rows: list[dict[str, Any]]) -> tuple[int, float, str]:
        sources = {r["source_id"] for r in rows}
        total_conf = sum(r["confidence"] for r in rows)
        latest = max(r["observed_at"] for r in rows)
        return (len(sources), total_conf, latest)

    ranked = sorted(groups.values(), key=score, reverse=True)
    winner = ranked[0]
    win_sources = {r["source_id"] for r in winner}
    # "contested": at least one other distinct value has independent corroboration of its own (not
    # just a lone, unsourced outlier) - a single stray assertion does not make the winner "contested".
    contested = len(ranked) > 1
    total_sources = len({r["source_id"] for a_list in groups.values() for r in a_list})
    confidence = len(win_sources) / total_sources if total_sources else 0.0
    return CanonicalResult(winner[0]["value"], round(confidence, 4), [r["id"] for r in winner], len(win_sources), contested)


def recompute_and_store(store, tenant_id: str, entity_id: str, attribute: str) -> CanonicalResult | None:
    assertions = store.assertions_for(tenant_id, entity_id, attribute)
    result = compute_canonical(assertions)
    if result is not None:
        store.set_canonical_value(tenant_id, entity_id, attribute, result.value, result.confidence, result.based_on, POLICY_VERSION)
    return result
