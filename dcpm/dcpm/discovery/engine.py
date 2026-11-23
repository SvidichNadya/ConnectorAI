"""Source Discovery Engine (ТЗ §5, research §2).

Every capability carries evidence and a verification status:
  DISCOVERED = a hint exists; VERIFIED = confirmed by a real request; NOT_FOUND = probed and absent.
Confidence belongs to a single fact, never to the source as a whole. Nothing here executes source content.
"""
from __future__ import annotations

import threading
import time
import urllib.robotparser
from typing import Any, Callable

from ..config import Policy
from ..errors import DCPMError
from ..ids import now_iso
from ..plan.validator import canonical_json
from ..processing.html import parse_html
from ..processing.sniff import declared_mime, sniff
from ..processing.structured import (get_path, maybe_gunzip, parse_feed, parse_json_bytes, parse_sitemap)
from ..runtime.ops import _AUTO_NEXT_PATHS, _as_url, _link_header_next
from ..security.netguard import RawResponse, SafeFetcher
from ..security.untrusted import sanitize_text
from ..security.urls import NormalizedUrl, Scope, normalize_url, origin_of

DISCOVERY_VERSION = "1.0"
OPENAPI_PATHS = ("/openapi.json", "/swagger.json", "/api/openapi.json", "/v3/api-docs", "/api/v1/openapi.json")
MAX_PROBE_BYTES = 2 * 1024 * 1024


class _ProbeBudgetExceeded(Exception):
    pass


class DiscoveryEngine:
    def __init__(self, policy: Policy, safe: SafeFetcher, sleep: Callable[[float], None] = time.sleep):
        self.policy, self.safe, self._sleep = policy, safe, sleep

    # ------------------------------------------------------------------ probing helpers
    def _get(self, st: dict, url: str, scope: Scope, *, max_bytes: int = MAX_PROBE_BYTES, headers: dict | None = None) -> RawResponse:
        if st["cancel"].is_set():
            raise DCPMError("CANCELLED", "discovery cancelled")
        if st["probes"] >= self.policy.max_probes:
            raise _ProbeBudgetExceeded()
        st["probes"] += 1
        wait = st["next"] - time.monotonic()
        if wait > 0:
            self._sleep(wait)
        st["next"] = time.monotonic() + self.policy.min_request_interval_s
        return self.safe.fetch(url, scope=scope, max_bytes=max_bytes, headers=headers)

    @staticmethod
    def _cap(name: str, status: str, confidence: float, evidence: list[str], **details: Any) -> dict[str, Any]:
        return {"name": name, "status": status, "available": status in ("VERIFIED", "DISCOVERED"),
                "confidence": confidence, "evidence": evidence, "details": details, "verified_at": now_iso() if status == "VERIFIED" else None}

    # ------------------------------------------------------------------ main
    def discover(self, locator: str, scope: Scope, cancel: threading.Event | None = None) -> dict[str, Any]:
        st = {"probes": 0, "next": 0.0, "cancel": cancel or threading.Event()}
        report: dict[str, Any] = {"discovery_version": DISCOVERY_VERSION, "locator": locator, "started_at": now_iso(),
                                  "capabilities": [], "limitations": [], "observations": {}, "authentication": {"required": False, "methods": []},
                                  "pagination": {"detected": False}, "robots": {"found": False}}
        caps: list[dict[str, Any]] = report["capabilities"]
        lim: list[str] = report["limitations"]
        try:
            root_nu = normalize_url(locator)
            report["normalized_locator"] = root_nu.url
            try:
                root = self._get(st, root_nu.url, scope)
            except DCPMError as e:
                if e.code == "CANCELLED":
                    raise
                report["status"] = "BLOCKED" if e.code in ("SSRF_BLOCKED", "OUT_OF_SCOPE", "POLICY_BLOCKED", "UNSUPPORTED_PROTOCOL") else "FAILED"
                report["error"] = e.to_dict()
                caps.append(self._cap("transport", "NOT_FOUND", 0.95, [f"request failed: {e.code}"]))
                return self._finish(report, st)
            self._analyse_root(st, report, root, root_nu, scope)
        except _ProbeBudgetExceeded:
            lim.append(f"probe budget ({self.policy.max_probes}) exhausted; discovery may be incomplete")
            report.setdefault("status", "COMPLETED")
        except DCPMError as e:
            if e.code == "CANCELLED":
                raise
            report["status"] = "FAILED"
            report["error"] = e.to_dict()
        return self._finish(report, st)

    def _finish(self, report: dict[str, Any], st: dict) -> dict[str, Any]:
        report.setdefault("status", "COMPLETED")
        report["probe_count"] = st["probes"]
        report["finished_at"] = now_iso()
        report["recommended_strategy"] = self._strategy(report)
        if len(canonical_json(report)) > 512 * 1024:  # hard cap on stored report size
            report["observations"] = {"truncated": True}
        return report

    # ------------------------------------------------------------------ analysis
    def _analyse_root(self, st: dict, report: dict, root: RawResponse, root_nu: NormalizedUrl, scope: Scope) -> None:
        caps, lim = report["capabilities"], report["limitations"]
        ctype = declared_mime(root.header("content-type"))
        obs = {"final_url": root.final_url, "http_status": root.status, "content_type": ctype,
               "redirects": len(root.redirect_chain) - 1, "server": sanitize_text(root.header("server") or "", 100) or None,
               "etag": bool(root.header("etag")), "last_modified": bool(root.header("last-modified"))}
        report["observations"]["root"] = obs
        caps.append(self._cap("transport", "VERIFIED", 0.99, [f"GET {root.final_url} -> {root.status}"]))
        if root.status in (401, 403):
            report["status"] = "NEEDS_AUTH"
            report["authentication"] = {"required": True, "methods": [m.split()[0] for m in (root.header("www-authenticate") or "").split(",") if m.strip()][:5]}
            lim.append(f"the root resource answered HTTP {root.status}; credentials are required")
            return
        if not 200 <= root.status < 300:
            report["status"] = "FAILED"
            report["error"] = DCPMError("HTTP_ERROR", f"root request returned HTTP {root.status}").to_dict()
            return
        kind = sniff(root.body, ctype)
        obs["detected_format"] = kind
        final_nu = normalize_url(root.final_url)
        doc: dict[str, Any] | None = None
        if kind == "html":
            doc = parse_html(root.body, root.final_url)
            obs.update({"title": sanitize_text(doc["title"]), "lang": doc["lang"], "canonical": doc["canonical"],
                        "link_count": len(doc["links"]), "has_json_ld": bool(doc["json_ld"])})
            caps.append(self._cap("http_html", "VERIFIED", 0.99, [f"content-type {ctype or 'unknown'}; HTML signature"]))
            if doc["js_rendered_suspected"]:
                caps.append(self._cap("js_rendered", "DISCOVERED", 0.6, ["little visible text and script-heavy markup"]))
                lim.append("the page may be JavaScript-rendered; a browser adapter is not available in this build")
        elif kind == "json":
            self._analyse_json_root(report, root)
        elif kind == "xml":
            self._analyse_xml_root(report, root)
        elif kind in ("pdf", "zip", "image", "binary"):
            caps.append(self._cap("file_document", "VERIFIED", 0.9, [f"detected format {kind}"]))
        else:
            caps.append(self._cap("http_text", "VERIFIED", 0.8, [f"detected format {kind}"]))

        self._probe_robots(st, report, final_nu, scope)
        self._probe_sitemaps(st, report, final_nu, scope)
        feeds = [a["href"] for a in (doc["alternates"] if doc else [])][:3]
        self._probe_feeds(st, report, feeds, scope)
        if kind == "html" or kind == "json":
            self._probe_openapi(st, report, final_nu, scope)
        self._probe_conditional(st, report, root, scope)
        report.setdefault("status", "COMPLETED")

    def _analyse_json_root(self, report: dict, root: RawResponse) -> None:
        caps = report["capabilities"]
        try:
            data = parse_json_bytes(root.body)
        except DCPMError:
            report["limitations"].append("root declared JSON but could not be parsed")
            return
        items_path = ""
        if isinstance(data, dict):
            items_path = next((k for k, v in data.items() if isinstance(v, list) and v and isinstance(v[0], dict)), "")
        nxt_type, nxt_path = None, ""
        if _link_header_next(root.header("link")):
            nxt_type = "link_header"
        else:
            for p in _AUTO_NEXT_PATHS:
                if _as_url(get_path(data, p)):
                    nxt_type, nxt_path = "next_link", p
                    break
        caps.append(self._cap("http_json", "VERIFIED", 0.97, ["response parsed as JSON"], items_path=items_path))
        report["pagination"] = {"detected": nxt_type is not None, "type": nxt_type, "next_path": nxt_path}
        report["observations"]["rest_collection"] = {"url": root.final_url, "items_path": items_path,
                                                     "pagination": nxt_type or "none", "next_path": nxt_path}
        caps.append(self._cap("rest_api", "VERIFIED", 0.7, ["root endpoint returns JSON; this does not prove a documented API"]))

    def _analyse_xml_root(self, report: dict, root: RawResponse) -> None:
        caps = report["capabilities"]
        try:
            parse_sitemap(maybe_gunzip(root.body, MAX_PROBE_BYTES))
            caps.append(self._cap("sitemap", "VERIFIED", 0.98, ["root resource is a sitemap"], url=root.final_url))
            report["observations"].setdefault("sitemap_urls", []).append(root.final_url)
            return
        except DCPMError:
            pass
        try:
            n = len(parse_feed(root.body))
            caps.append(self._cap("rss_feed", "VERIFIED", 0.98, ["root resource is a feed"], url=root.final_url, items=n))
            report["observations"].setdefault("feed_urls", []).append(root.final_url)
        except DCPMError:
            caps.append(self._cap("http_xml", "VERIFIED", 0.8, ["root resource is XML"]))

    def _probe_robots(self, st, report, nu: NormalizedUrl, scope: Scope) -> None:
        caps = report["capabilities"]
        try:
            r = self._get(st, origin_of(nu) + "/robots.txt", scope, max_bytes=512 * 1024)
        except (DCPMError,) as e:
            if e.code == "CANCELLED":
                raise
            report["limitations"].append(f"robots.txt could not be retrieved ({e.code}); crawling will be treated as disallowed")
            report["robots"] = {"found": False, "unreachable": True}
            return
        if 200 <= r.status < 300:
            rp = urllib.robotparser.RobotFileParser()
            rp.parse(r.body.decode("utf-8", "replace").splitlines())
            rp.modified()
            tok = self.policy.robots_token
            allowed = rp.can_fetch(tok, nu.url)
            report["robots"] = {"found": True, "root_allowed": allowed, "crawl_delay": rp.crawl_delay(tok),
                                "sitemaps": [s for s in (rp.site_maps() or [])][:10]}
            caps.append(self._cap("robots_txt", "VERIFIED", 0.99, ["robots.txt retrieved"]))
            if not allowed:
                report["limitations"].append("robots.txt disallows the root URL for this crawler")
        elif 400 <= r.status < 500:
            report["robots"] = {"found": False, "root_allowed": True}
            caps.append(self._cap("robots_txt", "NOT_FOUND", 0.95, [f"HTTP {r.status}"]))
        else:
            report["robots"] = {"found": False, "unreachable": True}
            report["limitations"].append(f"robots.txt returned HTTP {r.status}; crawling will be treated as disallowed")

    def _probe_sitemaps(self, st, report, nu: NormalizedUrl, scope: Scope) -> None:
        cands: list[str] = []
        for u in report["robots"].get("sitemaps", []):
            try:
                n = normalize_url(u)
            except DCPMError:
                continue
            if scope.allows(n.host):
                cands.append(n.url)
        default = origin_of(nu) + "/sitemap.xml"
        if default not in cands:
            cands.append(default)
        if report["observations"].get("sitemap_urls"):
            return
        found = False
        for u in cands[:3]:
            try:
                r = self._get(st, u, scope)
            except DCPMError as e:
                if e.code == "CANCELLED":
                    raise
                continue
            if not 200 <= r.status < 300:
                continue
            try:
                kind, locs = parse_sitemap(maybe_gunzip(r.body, MAX_PROBE_BYTES))
            except DCPMError:
                continue
            report["capabilities"].append(self._cap("sitemap", "VERIFIED", 0.98, [f"GET {r.final_url} parsed as {kind}"],
                                                    url=r.final_url, kind=kind, entries=len(locs)))
            report["observations"].setdefault("sitemap_urls", []).append(r.final_url)
            found = True
            break
        if not found:
            report["capabilities"].append(self._cap("sitemap", "NOT_FOUND", 0.8, ["no valid sitemap at the probed locations"]))

    def _probe_feeds(self, st, report, urls: list[str], scope: Scope) -> None:
        for u in urls:
            try:
                n = normalize_url(u)
                if not scope.allows(n.host):
                    continue
                r = self._get(st, n.url, scope)
                if 200 <= r.status < 300:
                    items = len(parse_feed(r.body))
                    report["capabilities"].append(self._cap("rss_feed", "VERIFIED", 0.97, [f"GET {r.final_url} parsed as feed"], url=r.final_url, items=items))
                    report["observations"].setdefault("feed_urls", []).append(r.final_url)
                    return
            except DCPMError as e:
                if e.code == "CANCELLED":
                    raise

    def _probe_openapi(self, st, report, nu: NormalizedUrl, scope: Scope) -> None:
        for path in OPENAPI_PATHS:
            try:
                r = self._get(st, origin_of(nu) + path, scope)
                if not 200 <= r.status < 300:
                    continue
                spec = parse_json_bytes(r.body)
            except DCPMError as e:
                if e.code == "CANCELLED":
                    raise
                continue
            if not isinstance(spec, dict) or not ("openapi" in spec or "swagger" in spec):
                continue
            paths = spec.get("paths") if isinstance(spec.get("paths"), dict) else {}
            get_paths = [p for p, v in paths.items() if isinstance(v, dict) and "get" in v and "{" not in p and isinstance(p, str) and p.startswith("/")][:20]
            servers = [s.get("url") for s in spec.get("servers", []) if isinstance(s, dict) and isinstance(s.get("url"), str)][:3]
            has_sec = bool(spec.get("security")) or bool(get_path(spec, "components.securitySchemes"))
            info = spec.get("info") if isinstance(spec.get("info"), dict) else {}
            report["capabilities"].append(self._cap("openapi", "VERIFIED", 0.97, [f"GET {r.final_url} is an OpenAPI/Swagger document"],
                                                    url=r.final_url, title=sanitize_text(str(info.get("title", "")), 100), paths=len(paths), requires_auth_hint=has_sec))
            report["observations"]["openapi"] = {"url": r.final_url, "get_paths": [sanitize_text(p, 150) for p in get_paths],
                                                 "servers": [sanitize_text(s, 200) for s in servers]}
            if has_sec:
                report["limitations"].append("the OpenAPI document declares security schemes; some endpoints may need credentials")
            return
        report["capabilities"].append(self._cap("openapi", "NOT_FOUND", 0.8, ["no OpenAPI/Swagger document at well-known locations"]))

    def _probe_conditional(self, st, report, root: RawResponse, scope: Scope) -> None:
        hdr = {}
        if root.header("etag"):
            hdr["If-None-Match"] = root.header("etag")
        elif root.header("last-modified"):
            hdr["If-Modified-Since"] = root.header("last-modified")
        if not hdr:
            report["capabilities"].append(self._cap("conditional_requests", "NOT_FOUND", 0.7, ["no ETag/Last-Modified on the root resource"]))
            return
        try:
            r = self._get(st, root.final_url, scope, headers=hdr)
        except DCPMError as e:
            if e.code == "CANCELLED":
                raise
            return
        ok = r.status == 304
        report["capabilities"].append(self._cap("conditional_requests", "VERIFIED" if ok else "NOT_FOUND", 0.9,
                                                [f"conditional GET -> {r.status}"], validator=next(iter(hdr))))

    @staticmethod
    def _strategy(report: dict) -> str:
        have = {c["name"] for c in report["capabilities"] if c["status"] == "VERIFIED"}
        if report.get("status") not in ("COMPLETED",):
            return "none"
        if "http_json" in have:   # the user pointed at a JSON endpoint: that endpoint is the collection
            return "rest_json"
        if "sitemap" in have and "http_html" in have:
            return "sitemap_then_crawl"
        if "openapi" in have:
            return "openapi_collections"
        if "rss_feed" in have and "http_html" not in have:
            return "feed_then_fetch"
        if "sitemap" in have:
            return "sitemap_then_crawl"
        if "http_html" in have:
            return "recursive_http"
        if "file_document" in have or "http_text" in have:
            return "single_fetch"
        return "none"
