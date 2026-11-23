"""Launches pdf_worker.py in an isolated subprocess: rlimits, wall-clock timeout, scrubbed environment,
throw-away working directory, bounded output. (Network namespace isolation is a deployment concern: ТЗ §14.6.)"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from ..config import Policy
from ..errors import DCPMError
from ..security.redact import redact

_WORKER = str(Path(__file__).with_name("pdf_worker.py"))
MAX_OUTPUT = 8 * 1024 * 1024


def extract_pdf(body: bytes, policy: Policy) -> dict:
    if not body.startswith(b"%PDF-"):
        raise DCPMError("UNSUPPORTED_FORMAT", "not a PDF (bad signature)")
    cpu = int(policy.pdf_timeout_s) + 5
    with tempfile.TemporaryDirectory(prefix="dcpm-pdf-") as cwd:
        try:
            proc = subprocess.run(
                [sys.executable, "-I", _WORKER, str(policy.pdf_max_pages), str(policy.pdf_memory_bytes), str(cpu)],
                input=body, capture_output=True, timeout=policy.pdf_timeout_s, cwd=cwd,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, start_new_session=True, check=False)
        except subprocess.TimeoutExpired:
            raise DCPMError("PARSE_FAILED", "PDF parsing timed out") from None
        except OSError:
            raise DCPMError("INTERNAL_ERROR", "could not start the PDF sandbox") from None
    if proc.returncode != 0:
        tail = redact(proc.stderr.decode("utf-8", "replace")[-300:])
        raise DCPMError("PARSE_FAILED", f"PDF parser failed (exit {proc.returncode}): {tail}")
    if len(proc.stdout) > MAX_OUTPUT:
        raise DCPMError("PARSE_FAILED", "PDF parser output too large")
    try:
        result = json.loads(proc.stdout)
    except ValueError:
        raise DCPMError("PARSE_FAILED", "PDF parser returned invalid output") from None
    if result.get("status") == "ENCRYPTED":
        raise DCPMError("UNSUPPORTED_FORMAT", "PDF is encrypted")
    return result
