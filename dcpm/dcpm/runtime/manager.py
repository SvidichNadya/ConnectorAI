"""RunManager: starts, cancels, resumes runs on a bounded worker pool and keeps the source state machine in sync."""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from ..config import Policy
from ..errors import DCPMError
from ..ids import now_iso
from ..plan.validator import validate_plan
from ..security.netguard import Resolver, SafeFetcher
from ..security.urls import Scope
from ..storage.blobs import BlobStore
from ..storage.db import Store
from .executor import Executor, effective_budget

log = logging.getLogger("dcpm.manager")

START_ALLOWED = ("READY", "ACTIVE", "PARTIAL", "DEGRADED", "BLOCKED", "FAILED", "DISCOVERED")
AFTER_RUN = {"COMPLETED": "ACTIVE", "COMPLETED_WITH_WARNINGS": "ACTIVE", "PARTIAL": "PARTIAL", "BLOCKED": "BLOCKED",
             "FAILED": "FAILED", "CANCELLED": "PARTIAL", "INTERRUPTED": "DEGRADED"}


class RunManager:
    def __init__(self, store: Store, blobs: BlobStore, policy: Policy, *, resolver: Resolver | None = None,
                 max_workers: int = 4, sleep_clock: Callable[[], float] | None = None, llm=None):
        self.store, self.blobs, self.policy, self.llm = store, blobs, policy, llm
        self.safe = SafeFetcher(policy, resolver=resolver)
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="dcpm-run")
        self._cancels: dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        self._futures: dict[str, Any] = {}

    def shutdown(self, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait, cancel_futures=True)

    def recover(self) -> int:
        return len(self.store.recover_interrupted_runs())

    # ------------------------------------------------------------------ commands
    def start(self, tenant_id: str, source: dict[str, Any], plan_row: dict[str, Any], run_type: str | None = None) -> dict[str, Any]:
        if source["status"] not in START_ALLOWED:
            raise DCPMError("CONFLICT", f"source in state {source['status']} cannot start a run")
        scope = Scope(tuple(source["scope"]["allowed_domains"]))
        vr = validate_plan(plan_row["plan"], policy=self.policy, scope=scope, expected_source_id=source["id"])
        if not vr.ok or vr.plan is None:
            raise DCPMError("PLAN_INVALID", "plan failed validation", details={"diagnostics": [d.to_dict() for d in vr.errors()][:20]})
        initial = source["status"] in ("READY", "DISCOVERED")
        run = self.store.create_run(tenant_id, source["id"], plan_row, run_type or ("INITIAL" if initial else "FULL_RESCAN"),
                                    effective_budget(vr.plan.limits, self.policy))
        self.store.set_source_status(tenant_id, source["id"], "INITIAL_ACQUISITION" if initial else "SYNCING", START_ALLOWED)
        self._submit(tenant_id, run["id"], ("PENDING",))
        return run

    def resume(self, tenant_id: str, run_id: str) -> dict[str, Any]:
        run = self.store.get_run(tenant_id, run_id)
        if run is None:
            raise DCPMError("NOT_FOUND", "run not found")
        if run["status"] not in ("INTERRUPTED", "FAILED", "PARTIAL"):
            raise DCPMError("CONFLICT", f"run in state {run['status']} cannot be resumed")
        if self.store.active_run_exists(tenant_id, run["source_id"]):
            raise DCPMError("CONFLICT", "another run is already active for this source")
        self.store.set_source_status(tenant_id, run["source_id"], "SYNCING", START_ALLOWED)
        self._submit(tenant_id, run_id, ("INTERRUPTED", "FAILED", "PARTIAL"))
        return self.store.get_run(tenant_id, run_id)  # type: ignore[return-value]

    def cancel(self, tenant_id: str, run_id: str) -> dict[str, Any]:
        run = self.store.get_run(tenant_id, run_id)
        if run is None:
            raise DCPMError("NOT_FOUND", "run not found")
        if run["status"] in ("PENDING", "RUNNING"):
            with self._lock:
                ev = self._cancels.get(run_id)
            if ev is not None:
                ev.set()
        elif run["status"] == "INTERRUPTED":
            self.store.update_run(tenant_id, run_id, status="CANCELLED", completed_at=now_iso())
        return self.store.get_run(tenant_id, run_id)  # type: ignore[return-value]

    def wait(self, run_id: str, timeout: float = 60.0) -> None:
        with self._lock:
            fut = self._futures.get(run_id)
        if fut is not None:
            fut.result(timeout=timeout)

    # ------------------------------------------------------------------ internals
    def _submit(self, tenant_id: str, run_id: str, from_states: tuple[str, ...]) -> None:
        ev = threading.Event()
        with self._lock:
            self._cancels[run_id] = ev
            self._futures[run_id] = self._pool.submit(self._work, tenant_id, run_id, from_states, ev)

    def _work(self, tenant_id: str, run_id: str, from_states: tuple[str, ...], ev: threading.Event) -> None:
        status = "FAILED"
        try:
            if ev.is_set():  # cancelled before it ever started
                self.store.update_run(tenant_id, run_id, status="CANCELLED", completed_at=now_iso())
                status = "CANCELLED"
                return
            if not self.store.claim_run(tenant_id, run_id, from_states):
                return
            status = Executor(store=self.store, blobs=self.blobs, policy=self.policy, safe=self.safe,
                              tenant_id=tenant_id, run_id=run_id, cancel=ev, llm=self.llm).run()
        except Exception:  # noqa: BLE001
            log.exception("run %s crashed", run_id)
            status = "FAILED"
            try:
                self.store.update_run(tenant_id, run_id, status="FAILED", completed_at=now_iso(),
                                      error_summary={"code": "INTERNAL_ERROR", "message": "run crashed unexpectedly"})
            except Exception:  # pragma: no cover
                log.exception("could not record crash of run %s", run_id)
        finally:
            with self._lock:
                self._cancels.pop(run_id, None)
            try:
                run = self.store.get_run(tenant_id, run_id)
                if run:
                    self.store.set_source_status(tenant_id, run["source_id"], AFTER_RUN.get(status, "FAILED"),
                                                 ("INITIAL_ACQUISITION", "SYNCING"))
            except Exception:  # pragma: no cover
                log.exception("could not update source after run %s", run_id)
