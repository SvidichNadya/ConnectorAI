"""Operation handlers. Each is a deterministic, read-only, budget-aware implementation of a registry entry."""
from __future__ import annotations

import json
from collections import Counter
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..errors import DCPMError
from ..processing.html import in_scope_links, page_links, parse_html
from ..processing.sniff import sniff
from ..processing.structured import (get_path, maybe_gunzip, parse_feed, parse_json_bytes, parse_sitemap)
from ..security.urls import normalize_url
from .context import RunContext
from ..semantic.engine import process_extractions
from .extract import extract_one

SOFT_CODES = frozenset({"ROBOTS_DISALLOWED", "OUT_OF_SCOPE", "SOURCE_NOT_FOUND"})
MAX_SITEMAPS = 50


@dataclass
class OpResult:
    outputs: dict[str, Any]
    partial: bool = False
    warnings: list[str] = field(default_factory=list)


def _failure_summary(fails: Counter, warnings: list[str]) -> bool:
    """Add one warning per failure class; return True if any failure means data is missing."""
    partial = False
    for code, n in sorted(fails.items()):
        warnings.append(f"{n} request(s) failed with {code}")
        if code not in SOFT_CODES:
            partial = True
    return partial


def op_http_fetch(ctx: RunContext, p: dict) -> OpResult:
    return OpResult({"response": ctx.fetcher.fetch(p["url"])})


def op_http_fetch_many(ctx: RunContext, p: dict) -> OpResult:
    urls = p["urls"][: p["max_items"]]
    truncated = len(p["urls"]) > p["max_items"]
    responses, fails, first, warnings = [], Counter(), None, []
    for u in urls:
        try:
            responses.append(ctx.fetcher.fetch(u))
        except DCPMError as e:
            if e.code == "CANCELLED":
                raise
            if e.code == "BUDGET_EXCEEDED":
                warnings.append(e.message)
                truncated = True
                break
            fails[e.code] += 1
            first = first or e
    if not responses and first:
        raise first
    if truncated:
        warnings.append("not all URLs were fetched (limit reached)")
    partial = _failure_summary(fails, warnings) or truncated
    return OpResult({"responses": responses}, partial, warnings)


def op_html_parse(ctx: RunContext, p: dict) -> OpResult:
    resp = p["response"]
    body = ctx.read_body(resp)
    if sniff(body, resp.get("content_type")) != "html":
        raise DCPMError("UNSUPPORTED_FORMAT", "response is not HTML")
    return OpResult({"document": parse_html(body, resp["final_url"])})


def op_html_extract_links(ctx: RunContext, p: dict) -> OpResult:
    links, outside = in_scope_links(p["document"], ctx.scope, ctx.policy.max_links_per_page)
    warnings = [f"{outside} link(s) outside the source scope were ignored"] if outside else []
    return OpResult({"urls": [u for u, _ in links]}, False, warnings)


def _in_scope_urls(ctx: RunContext, locs: list[str], base: str, limit: int, seen: set[str], out: list[str]) -> tuple[int, bool]:
    outside, full = 0, False
    for loc in locs:
        try:
            nu = normalize_url(loc, base=base)
        except DCPMError:
            continue
        if not ctx.scope.allows(nu.host):
            outside += 1
            continue
        if nu.key in seen:
            continue
        if len(out) >= limit:
            full = True
            break
        seen.add(nu.key)
        out.append(nu.url)
    return outside, full


def op_sitemap_collect(ctx: RunContext, p: dict) -> OpResult:
    limit = min(p["max_urls"], ctx.policy.max_sitemap_urls)
    urls: list[str] = []
    seen: set[str] = set()
    queue = deque([(p["url"], 0)])
    fetched, warnings, partial, outside_total = 0, [], False, 0
    while queue:
        u, depth = queue.popleft()
        if fetched >= MAX_SITEMAPS:
            warnings.append(f"stopped after {MAX_SITEMAPS} sitemap files")
            partial = True
            break
        try:
            resp = ctx.fetcher.fetch(u, accept="application/xml,text/xml;q=0.9,*/*;q=0.5")
        except DCPMError as e:
            if fetched == 0 or e.code in ("CANCELLED",):
                raise
            warnings.append(f"nested sitemap failed: {e.code}")
            partial = partial or e.code not in SOFT_CODES
            continue
        fetched += 1
        try:
            kind, locs = parse_sitemap(maybe_gunzip(ctx.read_body(resp), ctx.policy.max_response_bytes))
        except DCPMError as e:
            if fetched == 1:
                raise
            warnings.append(f"nested sitemap unparsable: {e.code}")
            partial = True
            continue
        if kind == "sitemapindex":
            if depth >= 2:
                warnings.append("sitemap index nesting limit reached")
                partial = True
                continue
            outside, _ = _in_scope_urls(ctx, locs, resp["final_url"], 10**9, set(), nested := [])
            outside_total += outside
            queue.extend((n, depth + 1) for n in nested[:MAX_SITEMAPS])
        else:
            outside, full = _in_scope_urls(ctx, locs, resp["final_url"], limit, seen, urls)
            outside_total += outside
            if full:
                warnings.append("max_urls reached; sitemap truncated")
                partial = True
                break
    if outside_total:
        warnings.append(f"{outside_total} sitemap URL(s) outside the source scope were ignored")
    return OpResult({"urls": urls}, partial, warnings)


def op_feed_collect(ctx: RunContext, p: dict) -> OpResult:
    resp = ctx.fetcher.fetch(p["url"], accept="application/rss+xml,application/atom+xml,application/xml;q=0.9,*/*;q=0.5")
    locs = parse_feed(ctx.read_body(resp))
    urls: list[str] = []
    outside, full = _in_scope_urls(ctx, locs, resp["final_url"], p["max_urls"], set(), urls)
    warnings = [f"{outside} feed item(s) outside the source scope were ignored"] if outside else []
    if full:
        warnings.append("max_urls reached; feed truncated")
    return OpResult({"urls": urls}, full, warnings)


# ------------------------------------------------------------------ crawler
def op_crawl_recursive(ctx: RunContext, p: dict) -> OpResult:
    pol = ctx.policy
    max_depth, max_res, follow_att = p["max_depth"], p["max_resources"], p["follow_attachments"]
    frontier: deque = deque()
    queued: set[str] = set()
    responses: list[dict] = []
    fails: Counter = Counter()
    warnings: list[str] = []
    state = {"truncated": False, "oos_recorded": 0, "oos_total": 0}

    def enqueue(url: str, depth: int, parent_id: str | None, rel: str) -> None:
        try:
            nu = normalize_url(url)
        except DCPMError:
            ctx.stats.inc("invalid_urls")
            return
        if not ctx.scope.allows(nu.host):
            state["oos_total"] += 1
            ctx.stats.inc("blocked_out_of_scope")
            if state["oos_recorded"] < pol.max_out_of_scope_records:
                state["oos_recorded"] += 1
                rid = ctx.store.upsert_resource(ctx.tenant_id, ctx.source_id, nu, ctx.run_id, depth, status="BLOCKED", reason="OUT_OF_SCOPE")
                if parent_id:
                    ctx.store.add_relation(ctx.tenant_id, ctx.source_id, ctx.run_id, parent_id, rid, rel)
            return
        rid = ctx.store.upsert_resource(ctx.tenant_id, ctx.source_id, nu, ctx.run_id, depth)
        if parent_id:  # keep every discovery path for audit, even for duplicates
            ctx.store.add_relation(ctx.tenant_id, ctx.source_id, ctx.run_id, parent_id, rid, rel)
        if nu.key in queued:
            ctx.stats.inc("skipped_duplicate")
            return
        if len(queued) >= pol.max_frontier:
            state["truncated"] = True
            return
        if rel == "ATTACHMENT_OF" and not follow_att:
            return
        queued.add(nu.key)
        ctx.stats.inc("resources_discovered")
        frontier.append((nu.url, depth, parent_id, rel))

    for s in p["seeds"]:
        enqueue(s, 0, None, "LINKS_TO")

    attempts, budget_stop = 0, False
    while frontier:
        ctx.check_cancel()
        try:
            ctx.check_deadline()
        except DCPMError:
            budget_stop = True
            warnings.append("run time budget exhausted during crawl")
            break
        if attempts >= max_res:
            budget_stop = True
            warnings.append(f"max_resources ({max_res}) reached; {len(frontier)} discovered URL(s) not fetched")
            break
        url, depth, parent_id, rel = frontier.popleft()
        attempts += 1
        try:
            resp = ctx.fetcher.fetch(url, parent_resource_id=parent_id, depth=depth, relation=rel)
        except DCPMError as e:
            if e.code == "CANCELLED":
                raise
            if e.code == "BUDGET_EXCEEDED":
                budget_stop = True
                warnings.append(e.message)
                break
            fails[e.code] += 1
            continue
        responses.append(resp)
        if depth < max_depth and sniff_is_html(ctx, resp):
            doc = parse_html(ctx.read_body(resp), resp["final_url"])
            ctx.store.set_resource_title(ctx.tenant_id, resp["resource_id"], doc.get("title"))
            links = page_links(doc, pol.max_links_per_page)
            ctx.stats.inc("links_found", len(links))
            for nu, lrel in links:   # out-of-scope links are recorded (BLOCKED) by enqueue, not silently dropped
                enqueue(nu.url, depth + 1, resp["resource_id"], lrel)
    if state["oos_total"]:
        warnings.append(f"{state['oos_total']} link(s) outside the source scope were not followed")
    if state["truncated"]:
        warnings.append("frontier limit reached; some links were not queued")
    partial = _failure_summary(fails, warnings) or budget_stop or state["truncated"]
    if not responses and fails:
        raise DCPMError("SOURCE_UNAVAILABLE", "no resource could be fetched: " + ", ".join(f"{k}x{v}" for k, v in fails.items()))
    return OpResult({"responses": responses}, partial, warnings)


def sniff_is_html(ctx: RunContext, resp: dict) -> bool:
    ct = resp.get("content_type") or ""
    if ct not in ("text/html", "application/xhtml+xml", "", "application/octet-stream", "text/plain"):
        return False
    if resp["size"] > 5 * 1024 * 1024:
        return False
    return sniff(ctx.read_body(resp)[:4096], ct) == "html"


# ------------------------------------------------------------------ REST
_AUTO_NEXT_PATHS = ("next", "next_url", "next_page_url", "links.next", "_links.next.href", "paging.next", "pagination.next", "meta.next")


def _link_header_next(header: str | None) -> str | None:
    if not header:
        return None
    for part in header.split(","):
        seg = part.strip().split(";")
        if len(seg) < 2 or not (seg[0].startswith("<") and seg[0].endswith(">")):
            continue
        if any(s.strip().replace(" ", "").lower() in ('rel="next"', "rel=next") for s in seg[1:]):
            return seg[0][1:-1]
    return None


def _as_url(v: Any) -> str | None:
    if isinstance(v, str) and v.strip():
        return v.strip()
    if isinstance(v, dict) and isinstance(v.get("href"), str):
        return v["href"]
    return None


def _set_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    q = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
    q.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))


def op_rest_paginate(ctx: RunContext, p: dict) -> OpResult:
    mode, items_path, max_pages = p["pagination"], p["items_path"], p["max_pages"]
    responses: list[dict] = []
    warnings: list[str] = []
    partial = False
    seen_req: set[str] = set()
    seen_cursors: set[str] = set()
    next_url: str | None = p["url"]
    page_no, items_total, last_items = 1, 0, 0
    more_available = False
    while next_url is not None:
        key = normalize_url(next_url).key
        if key in seen_req:
            warnings.append("pagination loop detected; stopped")
            break
        if len(responses) >= max_pages:
            more_available = True
            break
        seen_req.add(key)
        try:
            resp = ctx.fetcher.fetch(next_url, accept="application/json")
            data = parse_json_bytes(ctx.read_body(resp))
        except DCPMError as e:
            if not responses or e.code == "CANCELLED":
                raise
            warnings.append(f"page {len(responses) + 1} failed: {e.code}")
            partial = True
            break
        responses.append(resp)
        items = get_path(data, items_path) if items_path else data
        last_items = len(items) if isinstance(items, list) else (0 if items is None else 1)
        items_total += last_items
        nxt: str | None = None
        if mode in ("link_header", "auto"):
            nxt = _link_header_next(resp.get("link_header"))
        if nxt is None and mode == "next_link":
            nxt = _as_url(get_path(data, p["next_path"])) if p["next_path"] else None
        if nxt is None and mode == "auto":
            for path in _AUTO_NEXT_PATHS:
                nxt = _as_url(get_path(data, path))
                if nxt:
                    break
        if nxt is not None:
            try:
                nxt = normalize_url(nxt, base=resp["final_url"]).url
            except DCPMError:
                warnings.append("invalid next-page URL; stopped")
                partial = True
                nxt = None
        elif mode == "cursor":
            cur = get_path(data, p["next_path"]) if p["next_path"] else None
            if cur not in (None, "", False):
                if str(cur) in seen_cursors:
                    warnings.append("cursor did not advance; stopped")
                else:
                    seen_cursors.add(str(cur))
                    nxt = _set_param(resp["final_url"], p["cursor_param"], str(cur))
        elif mode == "page":
            if last_items > 0:
                page_no += 1
                nxt = _set_param(resp["final_url"], p["page_param"], str(page_no))
        next_url = nxt
    if more_available:
        partial = True
        warnings.append(f"max_pages ({max_pages}) reached; more pages are available")
    warnings.append(f"{items_total} item(s) seen across {len(responses)} page(s)")
    return OpResult({"responses": responses}, partial, warnings)


def op_content_extract(ctx: RunContext, p: dict) -> OpResult:
    summaries, warnings, failed, unsupported = [], [], 0, 0
    for resp in p["responses"][: ctx.policy.max_resources]:
        ctx.check_cancel()
        s = extract_one(ctx, resp)
        summaries.append(s)
        failed += s["status"] == "FAILED"
        unsupported += s["status"] == "UNSUPPORTED"
    if failed:
        warnings.append(f"{failed} document(s) could not be parsed (raw content preserved)")
    if unsupported:
        warnings.append(f"{unsupported} document(s) in unsupported formats (raw content preserved)")
    return OpResult({"extractions": summaries}, partial=bool(failed), warnings=warnings)


def op_semantic_process(ctx: RunContext, p: dict) -> OpResult:
    rows = []
    for e in p["extractions"][: ctx.policy.max_resources]:
        row = ctx.store.get_extraction(ctx.tenant_id, e["extraction_id"])
        if row is not None:
            rows.append(row)
    stats = process_extractions(ctx.store, ctx.tenant_id, ctx.source_id, ctx.run_id, rows, llm=ctx.llm, ai_allowed=ctx.ai_allowed)
    warnings = []
    if not ctx.ai_allowed or ctx.llm is None:
        warnings.append("semantic processing ran without a local model (ai_allowed is off or no model is configured); "
                        "domain identification and entity resolution used deterministic rules only")
    if stats.candidates_dropped_by_model_validation:
        warnings.append(f"{stats.candidates_dropped_by_model_validation} model-proposed item(s) failed evidence verification and were dropped")
    if stats.entities_review_required:
        warnings.append(f"{stats.entities_review_required} entity match(es) need manual review")
    if stats.extractions_skipped_no_text:
        warnings.append(f"{stats.extractions_skipped_no_text} extraction(s) had no analysable text and were skipped")
    return OpResult({"summary": stats.to_dict()}, partial=bool(stats.entities_review_required), warnings=warnings)


HANDLERS: dict[str, Callable[[RunContext, dict], OpResult]] = {
    "http.fetch": op_http_fetch, "http.fetch_many": op_http_fetch_many, "html.parse": op_html_parse,
    "html.extract_links": op_html_extract_links, "sitemap.collect": op_sitemap_collect, "feed.collect": op_feed_collect,
    "crawl.recursive": op_crawl_recursive, "rest.paginate": op_rest_paginate, "content.extract": op_content_extract,
    "semantic.process": op_semantic_process,
}
