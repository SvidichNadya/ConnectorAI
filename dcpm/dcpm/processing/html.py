"""HTML -> document model. Source markup is data: nothing in it is ever executed or obeyed."""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from ..security.urls import normalize_url
from ..errors import DCPMError

ATTACHMENT_EXTENSIONS = frozenset({"pdf", "docx", "doc", "xlsx", "xls", "pptx", "csv", "json", "xml", "txt", "rtf", "odt", "ods"})
_SKIP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "sms:", "ftp:", "file:", "blob:")
_WS = re.compile(r"\s+")


def _text(node: Any, limit: int = 2000) -> str:
    return _WS.sub(" ", node.get_text(" ", strip=True))[:limit]


def link_extension(url: str) -> str:
    path = url.split("?", 1)[0].rsplit("/", 1)[-1]
    return path.rsplit(".", 1)[-1].lower() if "." in path else ""


def parse_html(body: bytes, base_url: str, *, max_links: int = 2000) -> dict[str, Any]:
    soup = BeautifulSoup(body, "lxml")
    base = base_url
    bt = soup.find("base", href=True)
    if bt:
        try:
            base = urljoin(base_url, bt["href"])
        except ValueError:
            pass

    json_ld: list[Any] = []
    for s in soup.find_all("script", attrs={"type": re.compile(r"ld\+json", re.I)})[:20]:
        try:
            json_ld.append(json.loads(s.string or ""))
        except (ValueError, RecursionError):
            continue

    meta: dict[str, str] = {}
    for m in soup.find_all("meta")[:200]:
        key = (m.get("name") or m.get("property") or "").lower()
        if key in ("description", "og:title", "og:description", "og:type", "og:url", "author", "keywords", "robots") and m.get("content"):
            meta[key] = m["content"][:500]
    canonical = None
    alternates: list[dict[str, str]] = []
    for l in soup.find_all("link", href=True)[:100]:
        rel = " ".join(l.get("rel") or []).lower()
        if "canonical" in rel and canonical is None:
            canonical = urljoin(base, l["href"])
        elif "alternate" in rel and (l.get("type") or "").lower() in ("application/rss+xml", "application/atom+xml", "application/feed+json"):
            alternates.append({"href": urljoin(base, l["href"]), "type": l["type"].lower()})

    links: list[dict[str, str]] = []
    for a in soup.find_all("a", href=True):
        if len(links) >= max_links:
            break
        href = a["href"].strip()
        if not href or href.startswith("#") or href.lower().startswith(_SKIP_SCHEMES):
            continue
        rel = " ".join(a.get("rel") or []).lower()
        try:
            absolute = urljoin(base, href)
        except ValueError:
            continue
        links.append({"href": absolute, "text": _text(a, 200), "rel": rel})

    scripts = len(soup.find_all("script"))
    for t in soup(["script", "style", "noscript", "template", "svg", "iframe", "object", "embed"]):
        t.decompose()

    headings = [{"level": int(h.name[1]), "text": _text(h, 300)} for h in soup.find_all(re.compile(r"^h[1-6]$"))[:200]]
    paragraphs = [t for t in (_text(p, 2000) for p in soup.find_all(["p", "li", "blockquote", "pre"])[:2000]) if t]
    tables: list[list[list[str]]] = []
    for tb in soup.find_all("table")[:50]:
        rows = []
        for tr in tb.find_all("tr")[:1000]:
            cells = [_text(c, 500) for c in tr.find_all(["th", "td"])[:50]]
            if cells:
                rows.append(cells)
        if rows:
            tables.append(rows)
    body_text = _text(soup.body or soup, 200_000)
    title = _text(soup.title, 300) if soup.title else ""
    html_tag = soup.find("html")
    lang = (html_tag.get("lang") if html_tag else None) or None
    root_div = bool(soup.find(id=re.compile(r"^(root|app|__next|__nuxt)$")))
    return {
        "url": base_url, "title": title, "lang": lang, "canonical": canonical, "meta": meta,
        "headings": headings, "paragraphs": paragraphs, "tables": tables, "links": links,
        "alternates": alternates, "json_ld": json_ld[:10], "text": body_text,
        "js_rendered_suspected": len(body_text) < 200 and (scripts >= 3 or root_div),
    }


def page_links(doc: dict[str, Any], max_links: int) -> list[tuple[Any, str]]:
    """All distinct http(s) links of a page as (NormalizedUrl, relation), regardless of scope."""
    out: list[tuple[Any, str]] = []
    seen: set[str] = set()
    for l in doc.get("links", []):
        try:
            nu = normalize_url(l["href"])
        except DCPMError:
            continue
        if nu.key in seen:
            continue
        seen.add(nu.key)
        rel = "ATTACHMENT_OF" if link_extension(nu.url) in ATTACHMENT_EXTENSIONS else "LINKS_TO"
        out.append((nu, rel))
        if len(out) >= max_links:
            break
    return out


def in_scope_links(doc: dict[str, Any], scope, max_links: int) -> tuple[list[tuple[str, str]], int]:
    """Return ([(normalized_url, relation)], out_of_scope_count) with duplicates removed."""
    inside, outside = [], 0
    for nu, rel in page_links(doc, max_links):
        if scope.allows(nu.host):
            inside.append((nu.url, rel))
        else:
            outside += 1
    return inside, outside
