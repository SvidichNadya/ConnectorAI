"""Deterministic rule-based planner: turns a Discovery Report into a plan from allowed operations only."""
from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

from ..config import Policy
from ..errors import DCPMError
from ..security.urls import normalize_url

PLAN_VERSION = "1.0"


def _caps(report: dict) -> dict[str, dict]:
    return {c["name"]: c for c in report.get("capabilities", []) if c.get("status") == "VERIFIED"}


def propose_plan(report: dict[str, Any], source_id: str, policy: Policy) -> dict[str, Any]:
    if report.get("status") != "COMPLETED":
        raise DCPMError("PLAN_INVALID", f"discovery status is {report.get('status')}; a plan cannot be compiled")
    strategy = report.get("recommended_strategy", "none")
    obs = report.get("observations", {})
    root_url = report.get("normalized_locator") or report["locator"]
    max_res = min(100, policy.max_resources)
    ops: list[dict[str, Any]] = []

    def extract(after: str, out: str, idx: str = "") -> None:
        ops.append({"id": f"extract{idx}", "type": "content.extract", "depends_on": [after], "inputs": {"responses": f"${after}.{out}"}})

    if strategy == "sitemap_then_crawl":
        ops.append({"id": "sitemap", "type": "sitemap.collect", "inputs": {"url": obs["sitemap_urls"][0], "max_urls": min(max_res * 5, policy.max_sitemap_urls)}})
        ops.append({"id": "crawl", "type": "crawl.recursive", "depends_on": ["sitemap"],
                    "inputs": {"seeds": "$sitemap.urls", "max_depth": min(1, policy.max_depth), "max_resources": max_res}})
        extract("crawl", "responses")
    elif strategy == "openapi_collections":
        api = obs.get("openapi", {})
        base = root_url
        for s in api.get("servers", []):
            try:
                base = normalize_url(s, base=api.get("url", root_url)).url
                break
            except DCPMError:
                continue
        paths = api.get("get_paths", [])[:3]
        if not paths:
            raise DCPMError("PLAN_INVALID", "OpenAPI document exposes no parameter-free GET endpoints")
        for i, path in enumerate(paths):
            url = urljoin(base if base.endswith("/") else base + "/", path.lstrip("/"))
            ops.append({"id": f"api{i}", "type": "rest.paginate", "inputs": {"url": url, "pagination": "auto", "max_pages": min(10, policy.max_rest_pages)}})
            extract(f"api{i}", "responses", str(i))
    elif strategy == "rest_json":
        rc = obs.get("rest_collection", {})
        inputs: dict[str, Any] = {"url": rc.get("url", root_url), "pagination": "auto", "items_path": rc.get("items_path", ""),
                                  "max_pages": min(10, policy.max_rest_pages)}
        if rc.get("pagination") == "next_link" and rc.get("next_path"):
            inputs.update(pagination="next_link", next_path=rc["next_path"])
        elif rc.get("pagination") == "link_header":
            inputs["pagination"] = "link_header"
        ops.append({"id": "api", "type": "rest.paginate", "inputs": inputs})
        extract("api", "responses")
    elif strategy == "feed_then_fetch":
        ops.append({"id": "feed", "type": "feed.collect", "inputs": {"url": obs["feed_urls"][0]}})
        ops.append({"id": "crawl", "type": "crawl.recursive", "depends_on": ["feed"],
                    "inputs": {"seeds": "$feed.urls", "max_depth": 0, "max_resources": max_res}})
        extract("crawl", "responses")
    elif strategy in ("recursive_http", "single_fetch"):
        depth = 0 if strategy == "single_fetch" else min(2, policy.max_depth)
        ops.append({"id": "crawl", "type": "crawl.recursive", "inputs": {"seeds": [root_url], "max_depth": depth, "max_resources": max_res}})
        extract("crawl", "responses")
    else:
        raise DCPMError("PLAN_INVALID", "discovery found no usable access method")
    return {"plan_version": PLAN_VERSION, "source_id": source_id, "strategy": strategy,
            "description": f"Rule-based plan for strategy {strategy}", "operations": ops,
            "limits": {"max_runtime_seconds": min(1800, policy.max_runtime_seconds)}}
