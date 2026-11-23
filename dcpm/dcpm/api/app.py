"""DCPM HTTP API v1 (ТЗ §4.3). Thin: validation, authz, orchestration calls. No business logic lives here."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

from flask import Flask, Response, g, jsonify, request
from werkzeug.exceptions import HTTPException

from ..compiler.compiler import Compiler
from ..compiler.gateway import ModelGateway
from ..config import Policy
from ..semantic.llm import LocalLLMClient, LocalLLMConfig
from ..discovery.engine import DiscoveryEngine
from ..errors import HTTP_STATUS, DCPMError
from ..ids import is_valid_id, is_valid_tenant
from ..plan.validator import plan_hash, validate_plan
from ..runtime.manager import RunManager
from ..security.netguard import Resolver, SafeFetcher
from ..security.redact import redact
from ..security.urls import Scope, normalize_url
from ..storage.blobs import BlobStore
from ..storage.db import Store

log = logging.getLogger("dcpm.api")
_IDEM_RE = re.compile(r"^[A-Za-z0-9_\-:.]{1,128}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_ALLOWED_CONFIG = {"ai_allowed": bool, "respect_robots": bool}


def hash_key(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class AppConfig:
    data_dir: str
    api_keys: dict[str, str]                 # sha256(token) -> tenant_id
    policy: Policy = field(default_factory=Policy)
    worker_threads: int = 4
    rate_limit_per_minute: int = 600
    max_body_bytes: int = 1_000_000
    db_path: str | None = None
    local_llm: LocalLLMConfig | None = None   # set to point the whole deployment at a local model server

    def __post_init__(self) -> None:
        for h, t in self.api_keys.items():
            if not re.fullmatch(r"[0-9a-f]{64}", h) or not is_valid_tenant(t):
                raise ValueError("api_keys must map sha256 hex digests to valid tenant ids")


class RateLimiter:
    def __init__(self, per_minute: int):
        self.capacity, self.rate = float(per_minute), per_minute / 60.0
        self._b: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> float | None:
        """None if allowed, else seconds to wait."""
        now = time.monotonic()
        with self._lock:
            tokens, last = self._b.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens < 1:
                self._b[key] = (tokens, now)
                return (1 - tokens) / self.rate
            self._b[key] = (tokens - 1, now)
            return None


class Services:
    def __init__(self, cfg: AppConfig, gateway: ModelGateway | None, resolver: Resolver | None, store: Store | None):
        import os
        os.makedirs(cfg.data_dir, mode=0o700, exist_ok=True)
        self.cfg, self.policy = cfg, cfg.policy
        self.store = store or Store(cfg.db_path or os.path.join(cfg.data_dir, "dcpm.sqlite3"))
        self.blobs = BlobStore(os.path.join(cfg.data_dir, "raw"))
        self.safe = SafeFetcher(self.policy, resolver=resolver)
        # One local-model client, process-wide: used by both the connector compiler and the semantic
        # engine, so a single running Ollama/llama.cpp/LM Studio server backs the whole deployment.
        self.llm = gateway or (LocalLLMClient(cfg.local_llm) if cfg.local_llm else None)
        self.runs = RunManager(self.store, self.blobs, self.policy, resolver=resolver, max_workers=cfg.worker_threads, llm=self.llm)
        self.engine = DiscoveryEngine(self.policy, self.safe)
        self.compiler = Compiler(self.policy, self.llm)
        self.pool = ThreadPoolExecutor(max_workers=max(2, cfg.worker_threads), thread_name_prefix="dcpm-disc")
        self.limiter = RateLimiter(cfg.rate_limit_per_minute)
        self.cancels: dict[str, threading.Event] = {}
        self.store.recover_discoveries()
        self.runs.recover()

    def shutdown(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)
        self.runs.shutdown(wait=False)


def _err(code: str, msg: str, **details: Any) -> DCPMError:
    return DCPMError(code, msg, details=details)


def create_app(cfg: AppConfig, *, gateway: ModelGateway | None = None, resolver: Resolver | None = None,
               store: Store | None = None) -> Flask:
    app = Flask("dcpm")
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_body_bytes
    app.json.sort_keys = False  # type: ignore[attr-defined]
    svc = Services(cfg, gateway, resolver, store)
    app.dcpm = svc  # type: ignore[attr-defined]
    st = svc.store

    # ------------------------------------------------------------------ plumbing
    @app.before_request
    def _begin() -> None:
        g.cid = "corr_" + uuid.uuid4().hex[:20]
        g.tenant = None
        if request.path == "/api/v1/health":
            return
        if not request.path.startswith("/api/v1/"):
            raise _err("NOT_FOUND", "not found")
        auth = request.headers.get("Authorization", "")
        token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        tenant = None
        if token:
            digest = hash_key(token)
            for known, t in cfg.api_keys.items():       # constant-time comparison against every key
                if hmac.compare_digest(known, digest):
                    tenant = t
        if tenant is None:
            raise _err("UNAUTHENTICATED", "missing or invalid API key")
        g.tenant, g.actor = tenant, "key:" + hash_key(token)[:8]
        wait = svc.limiter.allow(tenant)
        if wait is not None:
            e = _err("RATE_LIMITED", "rate limit exceeded")
            g.retry_after = max(1, int(wait + 0.999))
            raise e

    @app.after_request
    def _headers(resp: Response) -> Response:
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        resp.headers["X-Request-ID"] = getattr(g, "cid", "")
        if getattr(g, "retry_after", None):
            resp.headers["Retry-After"] = str(g.retry_after)
        return resp

    def error_response(e: DCPMError, status: int | None = None) -> Response:
        body = {"error": {"code": e.code, "message": redact(e.message), "retryable": e.retryable,
                          "details": e.details, "correlation_id": getattr(g, "cid", "")}}
        return jsonify(body), status or HTTP_STATUS.get(e.code, 500 if e.code == "INTERNAL_ERROR" else 400)  # type: ignore[return-value]

    @app.errorhandler(DCPMError)
    def _dcpm_error(e: DCPMError):
        return error_response(e)

    @app.errorhandler(HTTPException)
    def _http_error(e: HTTPException):
        code = {404: "NOT_FOUND", 405: "VALIDATION_ERROR", 413: "PAYLOAD_TOO_LARGE", 415: "VALIDATION_ERROR"}.get(e.code or 0, "VALIDATION_ERROR")
        return error_response(DCPMError(code, e.name or "error"), e.code)

    @app.errorhandler(Exception)
    def _unhandled(e: Exception):
        log.exception("unhandled error [%s]", getattr(g, "cid", "-"))
        return error_response(DCPMError("INTERNAL_ERROR", "internal error"), 500)

    def body() -> dict[str, Any]:
        if not request.get_data(cache=True):
            return {}
        if not request.is_json:
            raise _err("VALIDATION_ERROR", "Content-Type must be application/json")
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise _err("VALIDATION_ERROR", "request body must be a JSON object")
        return data

    def page() -> tuple[int, int]:
        try:
            cursor = int(request.args.get("cursor", "0"))
            limit = int(request.args.get("limit", "50"))
        except ValueError:
            raise _err("VALIDATION_ERROR", "cursor and limit must be integers") from None
        if cursor < 0 or not 1 <= limit <= 200:
            raise _err("VALIDATION_ERROR", "cursor must be >= 0 and limit within 1..200")
        return cursor, limit

    def paged(rows_next: tuple[list, int | None]):
        rows, nxt = rows_next
        return jsonify({"items": rows, "next_cursor": str(nxt) if nxt else None})

    def need(kind: str, obj_id: str, getter: Callable[[str, str], Any]) -> dict[str, Any]:
        if not is_valid_id(obj_id, kind):
            raise _err("NOT_FOUND", f"{kind} not found")
        row = getter(g.tenant, obj_id)
        if row is None:                      # also the answer for other tenants' objects: existence is not leaked
            raise _err("NOT_FOUND", f"{kind} not found")
        return row

    def need_source(sid: str) -> dict[str, Any]:
        return need("src", sid, st.get_source)

    def idempotent(fn: Callable[[], tuple[dict[str, Any], int]]):
        key = request.headers.get("Idempotency-Key")
        if key is None:
            b, s = fn()
            return jsonify(b), s
        if not _IDEM_RE.match(key):
            raise _err("VALIDATION_ERROR", "invalid Idempotency-Key")
        rh = hashlib.sha256((request.method + request.path + (request.get_data(as_text=True) or "")).encode()).hexdigest()
        cached = st.idempotency_begin(g.tenant, key, rh)
        if cached is not None:
            return jsonify(cached["body"]), cached["status"]
        try:
            b, s = fn()
        except BaseException:
            st.idempotency_finish(g.tenant, key, None)
            raise
        st.idempotency_finish(g.tenant, key, {"body": b, "status": s})
        return jsonify(b), s

    def op_response(source_id: str, operation_id: str, status_url: str, status: str = "accepted"):
        return {"operation_id": operation_id, "source_id": source_id, "status": status, "status_url": status_url}, 202

    # ------------------------------------------------------------------ health
    @app.get("/api/v1/health")
    def health():
        return jsonify({"status": "ok"})

    # ------------------------------------------------------------------ sources
    def parse_source_input(data: dict[str, Any], *, creating: bool) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if creating or "name" in data:
            name = data.get("name")
            if not isinstance(name, str) or not 1 <= len(name.strip()) <= 200 or _CTRL.search(name):
                raise _err("VALIDATION_ERROR", "name must be 1..200 characters without control characters")
            out["name"] = name.strip()
        if "config" in data or creating:
            cfgv = data.get("config", {})
            if not isinstance(cfgv, dict):
                raise _err("VALIDATION_ERROR", "config must be an object")
            for k, v in cfgv.items():
                if k not in _ALLOWED_CONFIG or not isinstance(v, _ALLOWED_CONFIG[k]):
                    raise _err("VALIDATION_ERROR", f"unsupported config key or type: {k!r}")
            if cfgv.get("respect_robots", True) is not True:
                raise _err("POLICY_BLOCKED", "robots.txt handling cannot be disabled through the API")
            out["config"] = cfgv
        return out

    @app.post("/api/v1/sources")
    def create_source():
        data = body()

        def go():
            for k in data:
                if k not in ("name", "locator", "scope", "config", "source_type_hint"):
                    raise _err("VALIDATION_ERROR", f"unknown field {k!r}")
            parsed = parse_source_input(data, creating=True)
            locator = data.get("locator")
            if not isinstance(locator, str):
                raise _err("VALIDATION_ERROR", "locator must be a string")
            nu = normalize_url(locator)
            try:
                svc.safe.check_destination(nu.url, Scope((nu.host,)))   # SSRF verdict first, whatever the scope says
            except DCPMError as e:
                if e.code != "NETWORK_ERROR":
                    raise
            sc = data.get("scope") or {}
            if not isinstance(sc, dict) or set(sc) - {"allowed_domains"}:
                raise _err("VALIDATION_ERROR", "scope may only contain allowed_domains")
            scope = Scope.parse(sc.get("allowed_domains") or [nu.host])
            if not scope.allows(nu.host):
                raise _err("OUT_OF_SCOPE", "the locator host must be inside scope.allowed_domains")
            src = st.create_source(g.tenant, parsed["name"], nu.url, {"allowed_domains": list(scope.allowed_domains)}, parsed["config"])
            st.audit(g.tenant, g.actor, "source.registered", "source", src["id"], {"locator": nu.url})
            return src, 201
        return idempotent(go)

    @app.get("/api/v1/sources")
    def list_sources():
        c, l = page()
        return paged(st.list_sources(g.tenant, c, l))

    @app.get("/api/v1/sources/<sid>")
    def get_source(sid):
        src = need_source(sid)
        src["resource_counts"] = st.resource_status_counts(g.tenant, sid)
        return jsonify(src)

    @app.patch("/api/v1/sources/<sid>")
    def patch_source(sid):
        need_source(sid)
        data = body()
        if set(data) - {"name", "config"}:
            raise _err("VALIDATION_ERROR", "only name and config can be changed")
        parsed = parse_source_input(data, creating=False)
        st.update_source(g.tenant, sid, name=parsed.get("name"), config=parsed.get("config"))
        st.audit(g.tenant, g.actor, "source.updated", "source", sid, {"fields": sorted(parsed)})
        return jsonify(st.get_source(g.tenant, sid))

    @app.delete("/api/v1/sources/<sid>")
    def delete_source(sid):
        need_source(sid)
        rid = st.active_run_id(g.tenant, sid)
        if rid:
            svc.runs.cancel(g.tenant, rid)
        st.disable_source(g.tenant, sid)
        st.audit(g.tenant, g.actor, "source.disabled", "source", sid)
        return "", 204

    @app.post("/api/v1/sources/<sid>/test-connection")
    def test_connection(sid):
        src = need_source(sid)
        scope = Scope(tuple(src["scope"]["allowed_domains"]))
        try:
            raw = svc.safe.fetch(src["locator"], scope=scope, method="HEAD", max_bytes=1024)
            return jsonify({"reachable": True, "http_status": raw.status, "final_url": raw.final_url})
        except DCPMError as e:
            return jsonify({"reachable": False, "error": e.to_dict()})

    # ------------------------------------------------------------------ discovery
    @app.post("/api/v1/sources/<sid>/discover")
    def discover(sid):
        src = need_source(sid)
        if src["status"] == "DISABLED":
            raise _err("CONFLICT", "source is disabled")

        def go():
            if st.discovery_running(g.tenant, sid):
                raise _err("CONFLICT", "a discovery is already running for this source")
            did = st.create_discovery(g.tenant, sid)
            st.set_source_status(g.tenant, sid, "DISCOVERING", ("REGISTERED", "DISCOVERED", "NEEDS_AUTH", "FAILED", "BLOCKED"))
            st.audit(g.tenant, g.actor, "discovery.started", "discovery", did)
            tenant = g.tenant
            svc.pool.submit(_run_discovery, tenant, sid, did)
            return op_response(sid, did, f"/api/v1/discovery-reports/{did}")
        return idempotent(go)

    def _run_discovery(tenant: str, sid: str, did: str) -> None:
        try:
            src = st.get_source(tenant, sid)
            scope = Scope(tuple(src["scope"]["allowed_domains"]))  # type: ignore[index]
            report = svc.engine.discover(src["locator"], scope)    # type: ignore[index]
            status = report["status"]
            with st._tx():   # report and source state change together: a poller never sees one without the other
                st.finish_discovery(tenant, did, status, report, report.get("error"))
                st.set_source_status(tenant, sid, {"COMPLETED": "DISCOVERED", "NEEDS_AUTH": "NEEDS_AUTH", "BLOCKED": "BLOCKED"}.get(status, "FAILED"), ("DISCOVERING",))
            st.audit(tenant, "system", "discovery." + ("completed" if status == "COMPLETED" else "failed"), "discovery", did, {"status": status})
        except Exception:  # noqa: BLE001
            log.exception("discovery %s crashed", did)
            with st._tx():
                st.finish_discovery(tenant, did, "FAILED", None, DCPMError("INTERNAL_ERROR", "discovery crashed unexpectedly").to_dict())
                st.set_source_status(tenant, sid, "FAILED", ("DISCOVERING",))

    @app.get("/api/v1/discovery-reports/<did>")
    def get_discovery(did):
        return jsonify(need("dsc", did, st.get_discovery))

    @app.get("/api/v1/sources/<sid>/discovery-reports")
    def list_discoveries(sid):
        need_source(sid)
        c, l = page()
        return paged(st.list_discoveries(g.tenant, sid, c, l))

    # ------------------------------------------------------------------ plans
    @app.post("/api/v1/sources/<sid>/plans/compile")
    def compile_plan(sid):
        src = need_source(sid)
        data = body()
        if set(data) - {"use_ai", "discovery_id"}:
            raise _err("VALIDATION_ERROR", "unknown field")
        use_ai = data.get("use_ai", False)
        if not isinstance(use_ai, bool):
            raise _err("VALIDATION_ERROR", "use_ai must be a boolean")
        if src["status"] == "DISABLED":
            raise _err("CONFLICT", "source is disabled")
        if "discovery_id" in data:
            disc = need("dsc", str(data["discovery_id"]), st.get_discovery)
            if disc["source_id"] != sid or disc["status"] != "COMPLETED":
                raise _err("VALIDATION_ERROR", "discovery_id must be a completed discovery of this source")
        else:
            disc = st.latest_discovery(g.tenant, sid)
            if disc is None:
                raise _err("CONFLICT", "run discovery first")
        res = svc.compiler.compile(src, disc["report"], use_ai=use_ai)
        row = st.create_plan(g.tenant, sid, res.plan, res.plan_hash, res.generated_by, res.diagnostics, disc["id"], "VALIDATED")
        st.audit(g.tenant, g.actor, "plan.generated", "plan", row["id"], {"generated_by": res.generated_by})
        return jsonify(row), 201

    @app.get("/api/v1/sources/<sid>/plans")
    def list_plans(sid):
        need_source(sid)
        c, l = page()
        return paged(st.list_plans(g.tenant, sid, c, l))

    @app.get("/api/v1/plans/<pid>")
    def get_plan(pid):
        return jsonify(need("pln", pid, st.get_plan))

    def _revalidate(plan_row: dict[str, Any]):
        src = st.get_source(g.tenant, plan_row["source_id"])
        scope = Scope(tuple(src["scope"]["allowed_domains"]))  # type: ignore[index]
        return validate_plan(plan_row["plan"], policy=svc.policy, scope=scope, expected_source_id=plan_row["source_id"])

    @app.post("/api/v1/plans/<pid>/validate")
    def validate(pid):
        row = need("pln", pid, st.get_plan)
        vr = _revalidate(row)
        diags = [d.to_dict() for d in vr.diagnostics]
        if row["status"] in ("PROPOSED", "VALIDATED", "REJECTED"):
            st.set_plan_status(g.tenant, pid, "VALIDATED" if vr.ok else "REJECTED", diags, ("PROPOSED", "VALIDATED", "REJECTED"))
        return jsonify({"ok": vr.ok, "diagnostics": diags, "plan_hash": plan_hash(row["plan"])})

    @app.post("/api/v1/plans/<pid>/activate")
    def activate(pid):
        row = need("pln", pid, st.get_plan)
        src = need_source(row["source_id"])
        if src["status"] in ("DISABLED", "DISCOVERING"):
            raise _err("CONFLICT", f"source in state {src['status']} cannot activate a plan")
        vr = _revalidate(row)
        if not vr.ok or plan_hash(row["plan"]) != row["plan_hash"]:
            st.set_plan_status(g.tenant, pid, "REJECTED", [d.to_dict() for d in vr.diagnostics])
            raise DCPMError("PLAN_INVALID", "plan failed validation", details={"diagnostics": [d.to_dict() for d in vr.errors()][:20]})
        st.activate_plan(g.tenant, src["id"], pid)
        st.set_source_status(g.tenant, src["id"], "READY", ("REGISTERED", "DISCOVERED", "READY"))
        st.audit(g.tenant, g.actor, "plan.activated", "plan", pid)
        return jsonify(st.get_plan(g.tenant, pid))

    @app.post("/api/v1/plans/<pid>/deactivate")
    def deactivate(pid):
        row = need("pln", pid, st.get_plan)
        if not st.deactivate_plan(g.tenant, row["source_id"], pid):
            raise _err("CONFLICT", "plan is not active")
        st.audit(g.tenant, g.actor, "plan.deactivated", "plan", pid)
        return jsonify(st.get_plan(g.tenant, pid))

    # ------------------------------------------------------------------ runs
    @app.post("/api/v1/sources/<sid>/runs")
    def start_run(sid):
        src = need_source(sid)
        body()

        def go():
            if not src["active_plan_id"]:
                raise _err("CONFLICT", "source has no active plan")
            plan = st.get_plan(g.tenant, src["active_plan_id"])
            run = svc.runs.start(g.tenant, src, plan)  # type: ignore[arg-type]
            st.audit(g.tenant, g.actor, "run.started", "run", run["id"], {"plan_id": plan["id"]})  # type: ignore[index]
            return op_response(sid, run["id"], f"/api/v1/runs/{run['id']}")
        return idempotent(go)

    @app.get("/api/v1/sources/<sid>/runs")
    def list_runs(sid):
        need_source(sid)
        c, l = page()
        return paged(st.list_runs(g.tenant, sid, c, l))

    @app.get("/api/v1/runs/<rid>")
    def get_run(rid):
        return jsonify(need("run", rid, st.get_run))

    @app.post("/api/v1/runs/<rid>/cancel")
    def cancel_run(rid):
        need("run", rid, st.get_run)
        st.audit(g.tenant, g.actor, "run.cancel_requested", "run", rid)
        return jsonify(svc.runs.cancel(g.tenant, rid)), 202

    @app.post("/api/v1/runs/<rid>/resume")
    def resume_run(rid):
        need("run", rid, st.get_run)
        run = svc.runs.resume(g.tenant, rid)
        st.audit(g.tenant, g.actor, "run.resumed", "run", rid)
        return jsonify(run), 202

    @app.get("/api/v1/runs/<rid>/tasks")
    def run_tasks(rid):
        need("run", rid, st.get_run)
        return jsonify({"items": st.get_tasks(g.tenant, rid)})

    @app.get("/api/v1/runs/<rid>/errors")
    def run_errors(rid):
        need("run", rid, st.get_run)
        items = [{"operation_id": t["op_id"], "operation": t["op_type"], "error": t["error"]} for t in st.get_tasks(g.tenant, rid) if t["error"]]
        return jsonify({"items": items})

    # ------------------------------------------------------------------ resources / artifacts
    @app.get("/api/v1/sources/<sid>/resources")
    def list_resources(sid):
        need_source(sid)
        c, l = page()
        status = request.args.get("status")
        if status is not None and not re.fullmatch(r"[A-Z_]{3,20}", status):
            raise _err("VALIDATION_ERROR", "invalid status filter")
        return paged(st.list_resources(g.tenant, sid, status, c, l))

    @app.get("/api/v1/resources/<rid>")
    def get_resource(rid):
        return jsonify(need("res", rid, st.get_resource))

    @app.get("/api/v1/resources/<rid>/children")
    def resource_children(rid):
        need("res", rid, st.get_resource)
        return jsonify({"items": st.resource_children(g.tenant, rid)})

    @app.get("/api/v1/resources/<rid>/artifacts")
    def resource_artifacts(rid):
        need("res", rid, st.get_resource)
        return jsonify({"items": st.list_artifacts(g.tenant, rid)})

    @app.get("/api/v1/artifacts/<aid>")
    def get_artifact(aid):
        return jsonify(need("art", aid, st.get_artifact))

    @app.get("/api/v1/artifacts/<aid>/extractions")
    def artifact_extractions(aid):
        need("art", aid, st.get_artifact)
        return jsonify({"items": st.list_extractions(g.tenant, aid)})

    @app.get("/api/v1/artifacts/<aid>/content")
    def artifact_content(aid):
        art = need("art", aid, st.get_artifact)
        data = svc.blobs.get(g.tenant, art["sha256"])
        mime = re.sub(r"[^A-Za-z0-9/+.\-]", "", art.get("mime_type") or "")[:100]
        # Source content is hostile: never rendered by a browser, always a download, in a CSP sandbox.
        return Response(data, mimetype="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="{aid}.bin"', "X-Original-Content-Type": mime,
            "Content-Security-Policy": "default-src 'none'; sandbox", "X-DCPM-SHA256": art["sha256"]})

    return app
