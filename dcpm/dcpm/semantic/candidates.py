"""Deterministic candidate spotting (no model involved).

Why this exists: asking a model to extract entities from raw free text makes every claim it
returns unverifiable. Instead we first find concrete, mechanically-located spans of text (regex
and capitalisation patterns), and ONLY ask the model to classify / relate / judge domain-relevance
of THOSE spans. Because every candidate carries its own exact offset into the source text, any
later claim the model makes about it is checked by substring containment (facts.py), which is a
real, mechanical hallucination guard: a model cannot "find" a fact that wasn't already here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

MAX_CANDIDATES = 400
CONTEXT_RADIUS = 80

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_URL = re.compile(r"https?://[^\s<>\"']{4,300}")
_MONEY = re.compile(r"(?:[$€£¥]\s?\d[\d .,]{0,18}\d|\d[\d .,]{0,18}\d\s?(?:USD|EUR|GBP|RUB|руб\.?|грн\.?))", re.I)
_PERCENT = re.compile(r"\d{1,3}(?:[.,]\d{1,2})?\s?%")
_DATE_NUM = re.compile(r"\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b|\b\d{4}-\d{2}-\d{2}\b")
_DATE_MONTH = re.compile(
    r"\b(?:\d{1,2}\s+)?(?:January|February|March|April|May|June|July|August|September|October|November|December"
    r"|января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s*,?\s*\d{0,4}\b", re.I)
_QUOTED = re.compile(r"[\u00ab\"\u201c]([^\u00ab\u00bb\"\u201c\u201d]{3,120})[\u00bb\"\u201d]")
# Title-case run (Latin or Cyrillic), 1..5 words, each word capitalised: candidate PERSON/ORG names.
_NAME = re.compile(
    r"\b(?:[A-ZÀ-Þ][\w'’\-]*(?:\.\s?|\s+)){1,4}[A-ZÀ-Þ][\w'’\-]*\b"
    r"|\b(?:[А-ЯЁ][\wа-яё'’\-]*\s+){1,4}[А-ЯЁ][\wа-яё'’\-]*\b")
_ACRONYM = re.compile(r"\b[A-ZА-Я]{2,10}\b")
_STOPWORDS_START = frozenset({"The", "This", "That", "These", "Those", "It", "He", "She", "They", "We", "I",
                              "А", "И", "Но", "Это", "Его", "Её", "Их"})


@dataclass(frozen=True)
class Candidate:
    id: str              # stable within one call: "c0", "c1", ...
    text: str
    kind: str            # EMAIL, URL, MONEY, PERCENT, DATE, QUOTE, NAME, ACRONYM
    start: int
    end: int
    context: str

    def to_dict(self) -> dict:
        return {"id": self.id, "text": self.text, "kind": self.kind, "context": self.context}


def _context(text: str, start: int, end: int) -> str:
    a, b = max(0, start - CONTEXT_RADIUS), min(len(text), end + CONTEXT_RADIUS)
    return text[a:b].replace("\n", " ").strip()


def spot_candidates(text: str, max_candidates: int = MAX_CANDIDATES) -> list[Candidate]:
    if not text:
        return []
    spans: list[tuple[int, int, str]] = []
    for pattern, kind in ((_EMAIL, "EMAIL"), (_URL, "URL"), (_MONEY, "MONEY"), (_PERCENT, "PERCENT"),
                          (_DATE_NUM, "DATE"), (_DATE_MONTH, "DATE"), (_QUOTED, "QUOTE"),
                          (_NAME, "NAME"), (_ACRONYM, "ACRONYM")):
        for m in pattern.finditer(text):
            s, e = (m.start(1), m.end(1)) if kind == "QUOTE" else (m.start(), m.end())
            if kind == "URL":
                while e > s and text[e - 1] in ").,;:!?\'\"]>":
                    e -= 1
            if kind == "NAME" and text[s:e].split()[0].strip(".") in _STOPWORDS_START:
                continue
            if e > s:
                spans.append((s, e, kind))
    spans.sort(key=lambda t: (t[0], -(t[1] - t[0])))
    out: list[Candidate] = []
    occupied: list[tuple[int, int]] = []
    seen_exact: set[tuple[int, int]] = set()
    priority = {"EMAIL": 0, "URL": 0, "MONEY": 1, "PERCENT": 1, "DATE": 1, "QUOTE": 2, "NAME": 3, "ACRONYM": 4}
    for s, e, kind in sorted(spans, key=lambda t: priority[t[2]]):
        if (s, e) in seen_exact or any(s < oe and os < e for os, oe in occupied):
            continue
        seen_exact.add((s, e))
        occupied.append((s, e))
    occupied.sort()
    ordered = [(s, e, k) for s, e, k in spans if (s, e) in seen_exact]
    ordered.sort(key=lambda t: t[0])
    for i, (s, e, kind) in enumerate(ordered[:max_candidates]):
        out.append(Candidate(f"c{i}", text[s:e], kind, s, e, _context(text, s, e)))
    return out
