"""Immutable, content-addressed raw artifact store (ТЗ §11.13 Raw Layer).

Layout: <root>/<tenant>/<sha[:2]>/<sha256>. Writes are atomic (tmp + fsync + rename).
Deduplication is per tenant only, so one tenant can never learn what another stores.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
from pathlib import Path

from ..errors import DCPMError
from ..ids import is_valid_tenant

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class BlobStore:
    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _path(self, tenant_id: str, sha256: str) -> Path:
        if not is_valid_tenant(tenant_id) or not _SHA_RE.match(sha256):
            raise DCPMError("STORAGE_FAILURE", "invalid blob address")
        p = (self.root / tenant_id / sha256[:2] / sha256).resolve()
        if self.root not in p.parents:  # defence in depth against path traversal
            raise DCPMError("STORAGE_FAILURE", "invalid blob address")
        return p

    def put(self, tenant_id: str, data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        path = self._path(tenant_id, sha)
        if path.exists() and path.stat().st_size == len(data):
            return sha
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.parent / f".tmp-{secrets.token_hex(8)}"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
            except BaseException:
                raise
            os.replace(tmp, path)
        except OSError:
            raise DCPMError("STORAGE_FAILURE", "could not write artifact") from None
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            except OSError:  # pragma: no cover
                pass
        return sha

    def get(self, tenant_id: str, sha256: str, *, verify: bool = True) -> bytes:
        path = self._path(tenant_id, sha256)
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            raise DCPMError("STORAGE_FAILURE", "artifact content missing") from None
        except OSError:
            raise DCPMError("STORAGE_FAILURE", "could not read artifact") from None
        if verify and hashlib.sha256(data).hexdigest() != sha256:
            raise DCPMError("STORAGE_FAILURE", "artifact integrity check failed")
        return data

    def exists(self, tenant_id: str, sha256: str) -> bool:
        return self._path(tenant_id, sha256).exists()
