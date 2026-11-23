"""RunFetcher: the single path through which an operation obtains a resource.

policy -> robots -> throttle -> SafeFetcher (SSRF/scope/limits) -> retry/backoff -> raw blob
-> resource/artifact/relation records (provenance). Returns a small JSON-able response reference;
bodies live in the blob store and are read lazily, so memory stays bounded.
"""
from __future__ import annotations

from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from ..errors import DCPMError
from ..processing.sniff import declared_mime
from ..security.urls import normalize_url

if TYPE_CHECKING:  # pragma: no cover
    from .context import RunContext

_BLOCKED_CODES = {"ROBOTS_DISALLOWED", "OUT_OF_SCOPE", "SSRF_BLOCKED", "POLICY_BLOCKED", "AUTH_REQUIRED", "PERMISSION_DENIED",
                  "UNSUPPORTED_PROTOCOL", "INVALID_URL"}
_NO_STATUS_CHANGE = {"CANCELLED", "BUDGET_EXCEEDED"}


class RunFetcher:
    def __init__(self, ctx: "RunContext"):
        self.ctx = ctx

    # ------------------------------------------------------------------ helpers
    def _backoff(self, attempt: int) -> float:
        p = self.ctx.policy
        base = min(p.retry_max_delay_s, p.retry_base_delay_s * (2 ** (attempt - 1)))
        return base * (0.5 + self.ctx.rng.random() / 2)  # exponential backoff with jitter

    def _retry_after(self, raw) -> float | None:
        v = raw.header("retry-after")
        if not v:
            return None
        try:
            secs = float(int(v.strip()))
        except ValueError:
            try:
                secs = (parsedate_to_datetime(v) - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError):
                return None
        return max(0.0, min(secs, self.ctx.policy.retry_max_delay_s))

    @staticmethod
    def _status_error(raw) -> DCPMError | None:
        s = raw.status
        if 200 <= s < 300:
            return None
        d = {"status": s}
        if s == 401:
            return DCPMError("AUTH_REQUIRED", "the source requires authorization", details=d)
        if s == 403:
            return DCPMError("PERMISSION_DENIED", "access to the resource is forbidden", details=d)
        if s in (404, 410):
            return DCPMError("SOURCE_NOT_FOUND", f"resource not found (HTTP {s})", details=d)
        if s in (408, 429):
            return DCPMError("RATE_LIMITED", f"source asked us to slow down (HTTP {s})", details=d)
        if s in (500, 502, 503, 504):
            return DCPMError("SOURCE_UNAVAILABLE", f"source error (HTTP {s})", details=d)
        return DCPMError("HTTP_ERROR", f"unexpected HTTP status {s}", details=d)

    def _mark_failure(self, rid: str, err: DCPMError) -> None:
        ctx = self.ctx
        ctx.stats.inc(f"failed.{err.code}")
        if err.code in _NO_STATUS_CHANGE:
            return
        res = ctx.store.get_resource(ctx.tenant_id, rid)
        had_content = bool(res and res.get("current_artifact_id"))
        if err.code in _BLOCKED_CODES:
            status = "BLOCKED"
        elif err.code == "SOURCE_NOT_FOUND":
            status = "UNAVAILABLE"
        else:
            status = "FAILED"
        # A resource we already hold content for is never silently flipped to "gone": it becomes STALE.
        if had_content and status in ("FAILED", "UNAVAILABLE"):
            status = "STALE"
        ctx.store.set_resource_status(ctx.tenant_id, rid, status, err.code)

    # ------------------------------------------------------------------ main entry
    def fetch(self, url: str, *, parent_resource_id: str | None = None, depth: int = 0, relation: str = "LINKS_TO",
              accept: str | None = None, check_robots: bool = True, max_bytes: int | None = None) -> dict[str, Any]:
        ctx = self.ctx
        p = ctx.policy
        ctx.check_cancel()
        ctx.check_deadline()
        nu = normalize_url(url)
        ctx.budget.consume_request()
        rid = ctx.store.upsert_resource(ctx.tenant_id, ctx.source_id, nu, ctx.run_id, depth)
        if parent_resource_id:
            ctx.store.add_relation(ctx.tenant_id, ctx.source_id, ctx.run_id, parent_resource_id, rid, relation)
        try:
            if not ctx.scope.allows(nu.host):
                raise DCPMError("OUT_OF_SCOPE", "host is outside the source scope")
            delay = 0.0
            if check_robots and ctx.respect_robots:
                allowed, delay = ctx.robots.check(nu)
                if not allowed:
                    raise DCPMError("ROBOTS_DISALLOWED", "disallowed by robots.txt")
            raw = self._request_with_retry(nu, accept, max_bytes, delay)
            body = raw.body
            ctx.budget.consume_bytes(len(body))
        except DCPMError as e:
            self._mark_failure(rid, e)
            raise

        sha = ctx.blobs.put(ctx.tenant_id, body)
        final = normalize_url(raw.final_url)
        frid = rid
        if final.key != nu.key:
            frid = ctx.store.upsert_resource(ctx.tenant_id, ctx.source_id, final, ctx.run_id, depth)
            ctx.store.add_relation(ctx.tenant_id, ctx.source_id, ctx.run_id, rid, frid, "REDIRECTS_TO")
            ctx.store.set_resource_status(ctx.tenant_id, rid, "FETCHED", "REDIRECT")
        mime = declared_mime(raw.header("content-type"))
        art, created = ctx.store.record_artifact(
            ctx.tenant_id, frid, ctx.run_id, sha256=sha, size=len(body), mime=mime, http_status=raw.status,
            etag=raw.header("etag"), last_modified=raw.header("last-modified"))
        ctx.stats.inc("fetched")
        ctx.stats.inc("bytes", len(body))
        if not created:
            ctx.stats.inc("unchanged")
        return {"resource_id": frid, "requested_resource_id": rid, "artifact_id": art["id"], "artifact_version": art["version"],
                "url": nu.url, "final_url": final.url, "status": raw.status, "content_type": mime, "size": len(body),
                "sha256": sha, "etag": raw.header("etag"), "last_modified": raw.header("last-modified"),
                "link_header": raw.header("link"), "new_version": created}

    def _request_with_retry(self, nu, accept, max_bytes, robots_delay):
        ctx, p = self.ctx, self.ctx.policy
        attempt = 0
        while True:
            ctx.check_cancel()
            ctx.throttle.wait(nu.host, max(p.min_request_interval_s, robots_delay))
            try:
                raw = ctx.safe.fetch(nu.url, scope=ctx.scope, headers={"Accept": accept} if accept else None, max_bytes=max_bytes)
                ctx.stats.inc("requests")
            except DCPMError as e:
                if e.retryable and attempt < p.max_retries:
                    attempt += 1
                    ctx.stats.inc("retries")
                    ctx.sleep(self._backoff(attempt))
                    continue
                raise
            err = self._status_error(raw)
            if err is None:
                return raw
            if err.retryable and attempt < p.max_retries:
                attempt += 1
                ctx.stats.inc("retries")
                ctx.sleep(self._retry_after(raw) or self._backoff(attempt))
                continue
            raise err
