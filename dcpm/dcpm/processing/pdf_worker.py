"""PDF text extraction worker. Runs in a SEPARATE, resource-limited process (never in the API/worker process).

Standalone on purpose: it is launched with `python -I <this file>` and imports nothing from DCPM.
Protocol: PDF bytes on stdin, JSON on stdout. Network sockets are disabled before pypdf is imported.
"""
import json
import resource
import sys


def _limit(max_as: int, cpu: int) -> None:
    for res, val in ((resource.RLIMIT_AS, max_as), (resource.RLIMIT_CPU, cpu), (resource.RLIMIT_NOFILE, 32),
                     (resource.RLIMIT_FSIZE, 1024 * 1024), (resource.RLIMIT_CORE, 0)):
        try:
            resource.setrlimit(res, (val, val))
        except (ValueError, OSError):
            pass


def main() -> int:
    max_pages, max_as, cpu = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    max_chars = 1_000_000
    _limit(max_as, cpu)
    import socket

    def _no_net(*a, **k):
        raise OSError("network disabled in sandbox")
    socket.socket = _no_net  # type: ignore[assignment,misc]
    socket.create_connection = _no_net  # type: ignore[assignment]

    data = sys.stdin.buffer.read()
    import io
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(data), strict=False)
    if reader.is_encrypted:
        print(json.dumps({"status": "ENCRYPTED"}))
        return 0
    total = len(reader.pages)
    pages, used, any_text = [], 0, False
    for i in range(min(total, max_pages)):
        try:
            t = reader.pages[i].extract_text() or ""
        except Exception:
            t = ""
            pages.append({"page_number": i + 1, "text": "", "error": "page extraction failed"})
            continue
        t = t[: max(0, max_chars - used)]
        used += len(t)
        any_text = any_text or bool(t.strip())
        pages.append({"page_number": i + 1, "text": t})
    md = {}
    try:
        info = reader.metadata
        if info:
            for k in ("title", "author", "subject", "creator", "producer"):
                v = getattr(info, k, None)
                if v:
                    md[k] = str(v)[:500]
    except Exception:
        pass
    print(json.dumps({"status": "OK", "page_count": total, "pages": pages, "metadata": md,
                      "pages_truncated": total > max_pages, "text_layer": any_text, "needs_ocr": not any_text}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
