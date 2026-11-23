"""Semantic Understanding Engine orchestrator (ТЗ §10): the pipeline that turns extracted
content into domain-scoped entities, relationships and reversible, auditable assertions.

Per extraction: candidates -> judge_facts (domain relevance + entity type + relationships, each
claim verified against the source text) -> Fact rows (every judged candidate is recorded, even a
REJECTED one, so nothing is silently discarded) -> entity resolution for "nameable" candidates ->
relationships between resolved entities, or assertions when one side is a plain value (a date, an
amount). Canonical values for every (entity, attribute) touched in the run are recomputed at the end.

GENERIC facts (real, but not material to the identified subject domain) still get an entity record
(domain_id=None, a cross-domain bucket) - they are stored, just not merged into the domain's graph.
REJECTED facts get a Fact row only, as a record of what was screened out and why.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..ids import now_iso
from ..security.untrusted import sanitize_text
from .candidates import spot_candidates
from .conflicts import recompute_and_store
from .domains import resolve_domain
from .entities import normalize_key, recompute_entity_confidence, resolve_mention
from .facts import judge_facts
from .gateway_protocol import ChatGateway

NAMEABLE_TYPES = frozenset({"PERSON", "ORGANIZATION", "PRODUCT", "LOCATION", "EVENT", "DOCUMENT", "CONTACT", "OTHER"})
VALUE_TYPES = frozenset({"DATE", "MONEY", "PERCENTAGE"})
STRONG_KINDS = frozenset({"EMAIL", "URL"})
SAMPLE_EXTRACTIONS_FOR_DOMAIN = 3
SAMPLE_CHARS_PER_EXTRACTION = 1500
MAX_TEXT_CHARS_PER_EXTRACTION = 20_000


@dataclass
class SemanticStats:
    domain_key: str = ""
    domain_method: str = ""
    extractions_processed: int = 0
    extractions_skipped_no_text: int = 0
    facts_created: int = 0
    facts_domain_relevant: int = 0
    facts_generic: int = 0
    facts_rejected: int = 0
    candidates_dropped_by_model_validation: int = 0
    entities_created: int = 0
    entities_auto_merged: int = 0
    entities_review_required: int = 0
    relationships_created: int = 0
    assertions_created: int = 0
    canonical_values_recomputed: int = 0
    method: str = "rules"

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _attribute_key(predicate: str) -> str:
    from .domains import slugify
    return slugify(predicate)[:64]


def extract_plain_text(extraction: dict[str, Any]) -> str:
    """Pull analysable prose out of a stored extraction. Kinds with no free text (json, csv, binary
    summaries) are intentionally skipped here - structured-data semantics is a distinct, future task.

    Canonicalises (control-char strip, whitespace collapse, length cap) exactly ONCE, here, at the
    single entry point before candidate spotting ever sees the text. Every later step - spot_candidates
    offsets, judge_facts' document embedding, evidence verification - operates on this same string, so
    "evidence copied verbatim from the document" means verbatim against what was actually shown."""
    if extraction.get("status") != "OK":
        return ""
    content = extraction.get("content") or {}
    kind = extraction.get("kind")
    if kind == "html":
        # The title is deliberately NOT glued onto the body text: once whitespace is collapsed (below),
        # a title like "Acme-Beta Deal" immediately followed by body prose starting with another
        # capitalised name ("Acme Corp...") reads as one unbroken capitalised run to the candidate
        # spotter, merging two distinct things into a single bogus candidate.
        raw = content.get("text", "")
    elif kind in ("text", "xml"):
        raw = str(content.get("text", ""))
    elif kind == "pdf":
        raw = "\n".join(str(p.get("text", "")) for p in (content.get("pages") or []))
    else:
        return ""
    return sanitize_text(raw, max_len=MAX_TEXT_CHARS_PER_EXTRACTION)


def _build_domain_sample(extractions: list[dict[str, Any]]) -> str:
    parts = []
    for ext in extractions[:SAMPLE_EXTRACTIONS_FOR_DOMAIN]:
        t = extract_plain_text(ext)
        if t:
            parts.append(t[:SAMPLE_CHARS_PER_EXTRACTION])
    return "\n".join(parts)


def process_extractions(store, tenant_id: str, source_id: str, run_id: str, extractions: list[dict[str, Any]], *,
                        llm: ChatGateway | None, ai_allowed: bool) -> SemanticStats:
    stats = SemanticStats()
    sample = _build_domain_sample(extractions)
    if not sample.strip():
        return stats  # nothing textual came out of this run; nothing to classify or extract facts from
    domain_row, domain_result = resolve_domain(store, tenant_id, source_id, llm=llm, ai_allowed=ai_allowed,
                                               sample_text=sample, run_id=run_id)
    stats.domain_key, stats.domain_method = domain_row["key"], domain_result.method
    touched: set[tuple[str, str]] = set()   # (entity_id, attribute) pairs needing canonical recompute

    for ext in extractions:
        text = extract_plain_text(ext)
        if not text.strip():
            stats.extractions_skipped_no_text += 1
            continue
        stats.extractions_processed += 1
        cands = spot_candidates(text)
        judged = judge_facts(llm, ai_allowed=ai_allowed, source_text=text, domain_title=domain_row["title"],
                             domain_description=domain_row["description"], candidates=cands)
        stats.method = judged.method if judged.method == "llm" else stats.method
        stats.candidates_dropped_by_model_validation += judged.dropped
        resolved: dict[str, dict[str, Any]] = {}   # local candidate.id -> {"entity_id","entity_type","relevance"}

        for jc in judged.candidates:
            fact = store.create_fact(
                tenant_id, source_id=source_id, resource_id=ext["resource_id"], artifact_id=ext["artifact_id"],
                extraction_id=ext["id"], run_id=run_id, fact_type="ENTITY_MENTION",
                payload={"text": jc.candidate.text, "kind": jc.candidate.kind, "entity_type": jc.entity_type},
                evidence_text=jc.candidate.context, evidence_verified=True, method=judged.method,
                domain_id=domain_row["id"] if jc.relevance == "DOMAIN_RELEVANT" else None,
                relevance_status=jc.relevance, relevance_confidence=jc.confidence)
            stats.facts_created += 1
            if jc.relevance == "DOMAIN_RELEVANT":
                stats.facts_domain_relevant += 1
            elif jc.relevance == "GENERIC":
                stats.facts_generic += 1
            else:
                stats.facts_rejected += 1
                continue  # screened out as noise: recorded above, nothing further happens with it

            if jc.entity_type not in NAMEABLE_TYPES:
                continue
            domain_for_resolution = domain_row["id"] if jc.relevance == "DOMAIN_RELEVANT" else None
            strong = {jc.candidate.text} if jc.candidate.kind in STRONG_KINDS else set()
            pool = store.candidate_entities(tenant_id, domain_for_resolution, jc.entity_type)
            decision = resolve_mention(llm, ai_allowed=ai_allowed, entity_type=jc.entity_type, mention_text=jc.candidate.text,
                                       mention_context=jc.candidate.context, mention_strong_values=strong, candidates=pool)
            if decision.verdict == "AUTO_MERGE" and decision.target_entity_id:
                entity_id = decision.target_entity_id
                stats.entities_auto_merged += 1
            else:
                attrs: dict[str, Any] = {}
                if strong:
                    attrs["strong_identifiers"] = list(strong)
                if decision.verdict == "REVIEW_REQUIRED" and decision.target_entity_id:
                    attrs["review_suggestion"] = {"candidate_entity_id": decision.target_entity_id,
                                                 "confidence": decision.confidence, "reasoning": decision.reasoning}
                    stats.entities_review_required += 1
                entity = store.create_entity(tenant_id, domain_for_resolution, jc.entity_type, jc.candidate.text,
                                             normalize_key(jc.candidate.text), jc.confidence, attrs)
                entity_id = entity["id"]
                stats.entities_created += 1
            store.add_mention(tenant_id, fact["id"], entity_id, jc.candidate.text, normalize_key(jc.candidate.text),
                              jc.entity_type, jc.confidence, source_id=source_id)
            recompute_entity_confidence(store, tenant_id, entity_id)
            resolved[jc.candidate.id] = {"entity_id": entity_id, "entity_type": jc.entity_type}

        for rel in judged.relationships:
            subj, obj = resolved.get(rel.subject_id), resolved.get(rel.object_id)
            if subj is None:
                continue  # relationship referenced a candidate the model never classified: not actioned
            if obj is not None:
                store.create_relationship(tenant_id, subj["entity_id"], rel.predicate, obj["entity_id"],
                                          confidence=rel.confidence, evidence=[rel.evidence], source_id=source_id,
                                          fact_id=None)
                stats.relationships_created += 1
                continue
            cand = next((c for c in cands if c.id == rel.object_id), None)
            if cand is None:
                continue
            attribute = _attribute_key(rel.predicate)
            store.add_assertion(tenant_id, subj["entity_id"], attribute, cand.text, source_id=source_id,
                                resource_id=ext["resource_id"], fact_id=None, confidence=rel.confidence,
                                evidence=[rel.evidence], observed_at=now_iso(), assertion_type=rel.assertion_type)
            stats.assertions_created += 1
            touched.add((subj["entity_id"], attribute))

    for entity_id, attribute in touched:
        if recompute_and_store(store, tenant_id, entity_id, attribute) is not None:
            stats.canonical_values_recomputed += 1
    return stats
