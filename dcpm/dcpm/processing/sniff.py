"""Real-format detection. Never trust the extension or Content-Type alone (ТЗ §9.9)."""
from __future__ import annotations


def declared_mime(content_type: str | None) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


def sniff(body: bytes, declared: str | None = None) -> str:
    """Return one of: pdf, html, xml, json, gzip, zip, image, csv, text, binary, empty."""
    if not body:
        return "empty"
    head = body[:2048]
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"II*\x00", b"MM\x00*")) or (head[:4] == b"RIFF" and head[8:12] == b"WEBP"):
        return "image"
    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    low = stripped[:512].lower()
    if low.startswith(b"<?xml") or low.startswith(b"<rss") or low.startswith(b"<feed") or low.startswith(b"<urlset") or low.startswith(b"<sitemapindex"):
        # an XML prolog may precede XHTML
        if b"<html" in low or b"<!doctype html" in low:
            return "html"
        return "xml"
    if low.startswith(b"<!doctype html") or low.startswith(b"<html") or b"<html" in low or b"<head" in low or b"<body" in low:
        return "html"
    if stripped[:1] in (b"{", b"[") and (declared in ("application/json", "text/json") or (declared or "").endswith("+json")):
        return "json"
    if stripped[:1] in (b"{", b"["):
        return "json"
    if b"\x00" in head:
        return "binary"
    if declared in ("text/csv", "application/csv"):
        return "csv"
    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        try:
            body[:65536].decode("latin-1")
        except UnicodeDecodeError:  # pragma: no cover
            return "binary"
    return "text"
