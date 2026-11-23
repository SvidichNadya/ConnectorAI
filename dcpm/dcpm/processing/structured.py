"""JSON / CSV / XML (sitemap, feeds) parsing with hard limits."""
from __future__ import annotations

import csv
import io
import json
import zlib
from typing import Any

import defusedxml.ElementTree as DET
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import ParseError

from ..errors import DCPMError


def decode_text(body: bytes, content_type: str | None = None) -> str:
    charset = None
    if content_type and "charset=" in content_type.lower():
        charset = content_type.lower().split("charset=", 1)[1].split(";")[0].strip().strip('"\'')
    for enc in ([charset] if charset else []) + ["utf-8-sig"]:
        try:
            return body.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return body.decode("latin-1", errors="replace")


def parse_json_bytes(body: bytes) -> Any:
    try:
        return json.loads(decode_text(body))
    except (ValueError, RecursionError):
        raise DCPMError("PARSE_FAILED", "invalid or too deeply nested JSON") from None


def get_path(data: Any, path: str) -> Any:
    """Dotted path lookup; numeric segments index lists. Missing => None."""
    if not path:
        return data
    cur = data
    for seg in path.split("."):
        if isinstance(cur, dict):
            if seg not in cur:
                return None
            cur = cur[seg]
        elif isinstance(cur, list) and seg.isdigit() and int(seg) < len(cur):
            cur = cur[int(seg)]
        else:
            return None
    return cur


def _limit(obj: Any, depth: int = 4, items: int = 50, strlen: int = 500) -> Any:
    if depth <= 0:
        return "…"
    if isinstance(obj, dict):
        return {str(k)[:100]: _limit(v, depth - 1, items, strlen) for k, v in list(obj.items())[:items]}
    if isinstance(obj, list):
        return [_limit(v, depth - 1, items, strlen) for v in obj[:items]]
    if isinstance(obj, str):
        return obj if len(obj) <= strlen else obj[:strlen] + "…"
    return obj


def summarize_json(data: Any, max_records: int = 1000) -> dict[str, Any]:
    out: dict[str, Any] = {"top_level_type": type(data).__name__}
    records = None
    if isinstance(data, list):
        out["count"] = len(data)
        records = data
    elif isinstance(data, dict):
        out["keys"] = [str(k)[:100] for k in list(data.keys())[:100]]
        for k, v in data.items():
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v[:5]):
                records = v
                out["records_path"] = str(k)
                out["count"] = len(v)
                break
        if records is None:
            records = [data]
    if records is not None:
        out["records"] = [_limit(r) for r in records[:max_records]]
        out["records_truncated"] = len(records) > max_records
    return out


def parse_csv(text: str, max_rows: int = 1000) -> dict[str, Any]:
    csv.field_size_limit(1_000_000)
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    rows: list[list[str]] = []
    truncated = False
    try:
        for i, row in enumerate(csv.reader(io.StringIO(text), dialect)):
            if i >= max_rows + 1:
                truncated = True
                break
            rows.append([c[:1000] for c in row[:200]])
    except csv.Error as e:
        raise DCPMError("PARSE_FAILED", f"invalid CSV: {e}") from None
    header = rows[0] if rows else []
    return {"header": header, "rows": rows[1:], "rows_truncated": truncated, "delimiter": getattr(dialect, "delimiter", ",")}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def parse_xml_root(body: bytes):
    try:
        return DET.fromstring(body, forbid_dtd=True)
    except (DefusedXmlException, ParseError, ValueError):
        raise DCPMError("PARSE_FAILED", "invalid or unsafe XML") from None


def maybe_gunzip(body: bytes, limit: int) -> bytes:
    if not body.startswith(b"\x1f\x8b"):
        return body
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(body, limit + 1)
    except zlib.error:
        raise DCPMError("PARSE_FAILED", "invalid gzip data") from None
    if len(out) > limit:
        raise DCPMError("RESPONSE_TOO_LARGE", "decompressed content exceeds size limit")
    return out


def parse_sitemap(body: bytes) -> tuple[str, list[str]]:
    root = parse_xml_root(body)
    kind = _local(root.tag)
    if kind not in ("urlset", "sitemapindex"):
        raise DCPMError("PARSE_FAILED", "not a sitemap")
    locs = []
    for child in root:
        for el in child:
            if _local(el.tag) == "loc" and el.text and el.text.strip():
                locs.append(el.text.strip())
    return kind, locs


def parse_feed(body: bytes) -> list[str]:
    root = parse_xml_root(body)
    kind = _local(root.tag)
    urls: list[str] = []
    if kind in ("rss", "RDF"):
        for el in root.iter():
            if _local(el.tag) == "item":
                for c in el:
                    if _local(c.tag) == "link" and c.text and c.text.strip():
                        urls.append(c.text.strip())
                        break
    elif kind == "feed":
        for el in root:
            if _local(el.tag) == "entry":
                chosen = None
                for c in el:
                    if _local(c.tag) == "link" and c.get("href"):
                        if c.get("rel") in (None, "alternate"):
                            chosen = c.get("href")
                            break
                        chosen = chosen or c.get("href")
                if chosen:
                    urls.append(chosen)
    else:
        raise DCPMError("PARSE_FAILED", "not an RSS/Atom feed")
    return urls


def xml_kind(body: bytes) -> str | None:
    try:
        return _local(parse_xml_root(body).tag)
    except DCPMError:
        return None
