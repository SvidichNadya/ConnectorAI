"""content.extract: real-format detection + parsing; persists an extraction per (artifact, parser, version)."""
from __future__ import annotations

import json
from typing import Any

from ..errors import DCPMError
from ..processing.html import link_extension, parse_html
from ..processing.pdf_sandbox import extract_pdf
from ..processing.sniff import sniff
from ..processing.structured import decode_text, parse_csv, parse_json_bytes, parse_xml_root, summarize_json
from .context import RunContext

PARSER_VERSION = "1.0"
_SHRINK_KEYS = ("records", "rows", "pages", "paragraphs", "tables", "links", "headings", "text")


def _size(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=True))


def _shrink(content: dict[str, Any], limit: int) -> tuple[dict[str, Any], bool]:
    shrunk = False
    for _ in range(40):
        if _size(content) <= limit:
            return content, shrunk
        sizes = {k: _size(content[k]) for k in _SHRINK_KEYS if k in content and content[k]}
        if not sizes:
            break
        k = max(sizes, key=sizes.get)
        v = content[k]
        content[k] = v[: len(v) // 2] if isinstance(v, (list, str)) else v
        shrunk = True
    return {"truncated": True, "note": "content exceeded the extraction size limit"}, True


def extract_one(ctx: RunContext, resp: dict[str, Any]) -> dict[str, Any]:
    body = ctx.read_body(resp)
    declared = resp.get("content_type")
    kind = sniff(body, declared)
    warnings: list[str] = []
    status, parser, content = "OK", kind, {}
    ext = link_extension(resp["final_url"])
    try:
        if kind == "html":
            d = parse_html(body, resp["final_url"])
            content = {k: d[k] for k in ("title", "lang", "canonical", "meta", "headings", "paragraphs", "tables",
                                           "alternates", "json_ld", "js_rendered_suspected")}
            content["links"] = d["links"][:500]
            content["text"] = d["text"][:100_000]
            if d["js_rendered_suspected"]:
                warnings.append("page looks JavaScript-rendered; content may be incomplete (browser adapter not available)")
            ctx.store.set_resource_title(ctx.tenant_id, resp["resource_id"], d["title"])
        elif kind == "json":
            content = summarize_json(parse_json_bytes(body))
        elif kind == "pdf":
            content = extract_pdf(body, ctx.policy)
            if content.get("needs_ocr"):
                warnings.append("PDF has no text layer; OCR is not available in this build")
        elif kind == "xml":
            root = parse_xml_root(body)
            content = {"root_tag": root.tag.rsplit("}", 1)[-1], "text": " ".join(t.strip() for t in root.itertext() if t.strip())[:100_000]}
        elif kind in ("csv", "text") and (kind == "csv" or ext in ("csv", "tsv") or declared == "text/csv"):
            parser = "csv"
            content = parse_csv(decode_text(body, declared))
        elif kind == "text":
            content = {"text": decode_text(body, declared)[:200_000]}
        else:
            status, content = "UNSUPPORTED", {"detected_format": kind}
        if declared and kind not in ("empty",) and status == "OK":
            mism = {"html": ("text/html", "application/xhtml+xml"), "json": ("application/json",), "pdf": ("application/pdf",)}.get(kind)
            if mism and declared not in mism and not declared.endswith("+json") and declared not in ("application/octet-stream", "text/plain"):
                warnings.append(f"declared type {declared!r} differs from detected format {kind!r}")
    except DCPMError as e:
        if e.code == "UNSUPPORTED_FORMAT":
            status, content = "UNSUPPORTED", {"detected_format": kind}
        else:
            status, content = "FAILED", {}
            warnings.append(f"{e.code}: {e.message}")
    if status == "OK":
        content, shrunk = _shrink(content, ctx.policy.max_extraction_bytes)
        if shrunk:
            warnings.append("extraction truncated to the size limit")
    eid = ctx.store.upsert_extraction(ctx.tenant_id, resp["artifact_id"], resp["resource_id"], ctx.run_id, kind=kind,
                                      parser_name=parser, parser_version=PARSER_VERSION, status=status, content=content, warnings=warnings)
    return {"extraction_id": eid, "artifact_id": resp["artifact_id"], "resource_id": resp["resource_id"], "kind": kind, "status": status}
