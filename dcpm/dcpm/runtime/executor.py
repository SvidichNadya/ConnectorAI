"""Plan runtime: executes a validated DAG of registry operations (ТЗ §4.6, §7).

* the plan is re-validated and its hash re-checked at run start (activation-time validation is not trusted);
* task state is persisted per operation, so an interrupted run can resume without redoing finished work;
* failures are classified; dependants of a failed op are SKIPPED, never run on missing data;
* the final status distinguishes completeness (COMPLETED / WITH_WARNINGS / PARTIAL / BLOCKED / FAILED / CANCELLED).
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

from ..config import Policy
from ..errors import BLOCKING_CODES, DCPMError
from ..ids import now_iso
from ..plan.registry import REGISTRY
from ..plan.validator import parse_ref, plan_hash, validate_plan
from ..security.netguard import SafeFetcher
from ..security.urls import Scope
from ..storage.blobs import BlobStore
from ..storage.db import Store
from .context import Budget, RunContext
from .ops import HANDLERS

log = logging.getLogger("dcpm.executor")
MAX_OUTPUT_BYTES = 5 * 1024 * 1024
MAX_LIMITATIONS = 100


def effective_budget(plan_limits: dict[str, int], policy: Policy) -> dict[str, int]:
    return {
        "max_runtime_seconds": min(plan_limits.get("max_runtime_seconds", policy.max_runtime_seconds), policy.max_runtime_seconds),
        "max_total_bytes": min(plan_limits.get("max_total_bytes", policy.max_total_bytes), policy.max_total_bytes),
        "max_resources": min(plan_limits.get("max_resources", policy.max_resources), policy.max_resources),
    }


class Executor:
    def __init__(self, *, store: Store, blobs: BlobStore, policy: Policy, safe: SafeFetcher, tenant_id: str, run_id: str,
                 cancel: threading.Event, clock=time.monotonic, llm=None):
        self.store, self.blobs, self.policy, self.safe = store, blobs, policy, safe
        self.tenant_id, self.run_id, self.cancel, self.clock = tenant_id, run_id, cancel, clock
        self.llm = llm

    def _finish(self, status: str, stats: dict[str, Any], error: dict[str, Any] | None = None) -> str:
        self.store.update_run(self.tenant_id, self.run_id, status=status, statistics=stats, error_summary=error, completed_at=now_iso())
        return status

    def run(self) -> str:
        st, t = self.store, self.tenant_id
        run = st.get_run(t, self.run_id)
        if run is None:
            return "FAILED"
        source = st.get_source(t, run["source_id"])
        plan_row = st.get_plan(t, run["plan_id"])
        if source is None or plan_row is None:
            return self._finish("FAILED", {}, DCPMError("PLAN_INVALID", "source or plan no longer exists").to_dict())
        scope = Scope(tuple(source["scope"]["allowed_domains"]))
        vr = validate_plan(plan_row["plan"], policy=self.policy, scope=scope, expected_source_id=source["id"])
        if not vr.ok or plan_hash(plan_row["plan"]) != run["plan_hash"] or vr.plan is None:
            msg = "plan failed re-validation" if not vr.ok else "plan content changed after activation"
            return self._finish("FAILED", {}, DCPMError("PLAN_INVALID", msg, details={"diagnostics": [d.to_dict() for d in vr.errors()][:20]}).to_dict())

        plan = vr.plan
        eff = effective_budget(plan.limits, self.policy)
        ai_allowed = bool(source["config"].get("ai_allowed", False))
        ctx = RunContext(tenant_id=t, source_id=source["id"], run_id=self.run_id, store=st, blobs=self.blobs, policy=self.policy,
                         scope=scope, safe=self.safe, cancel=self.cancel, deadline=self.clock() + eff["max_runtime_seconds"],
                         budget=Budget(eff["max_total_bytes"], eff["max_resources"]), clock=self.clock,
                         respect_robots=bool(source["config"].get("respect_robots", True)),
                         llm=self.llm, ai_allowed=ai_allowed)
        by_id = {o.id: o for o in plan.operations}
        done = {x["op_id"]: x for x in st.get_tasks(t, self.run_id) if x["status"] == "COMPLETED"}
        outputs: dict[str, dict[str, Any]] = {}
        partial_ops: set[str] = set()
        failed: dict[str, dict[str, Any]] = {}
        skipped: set[str] = set()
        warnings: list[str] = []
        cancelled = False

        for op_id in vr.order:
            op = by_id[op_id]
            if self.cancel.is_set():
                cancelled = True
                break
            if op_id in done:  # resume: reuse persisted result
                saved = done[op_id]["output"] or {}
                outputs[op_id] = saved.get("outputs", {})
                if saved.get("partial"):
                    partial_ops.add(op_id)
                warnings += done[op_id].get("warnings") or []
                continue
            if any(d in failed or d in skipped for d in op.depends_on):
                st.upsert_task(t, self.run_id, op_id, op.type, "SKIPPED", finished=True)
                skipped.add(op_id)
                continue
            st.upsert_task(t, self.run_id, op_id, op.type, "RUNNING", started=True)
            try:
                spec = REGISTRY[op.type]
                params = {}
                for p in spec.inputs:
                    if p.name in op.inputs:
                        ref = parse_ref(op.inputs[p.name])
                        params[p.name] = outputs[ref[0]][ref[1]] if ref else op.inputs[p.name]
                    else:
                        params[p.name] = p.default
                res = HANDLERS[op.type](ctx, params)
                blob = {"outputs": res.outputs, "partial": res.partial}
                if len(json.dumps(blob)) > MAX_OUTPUT_BYTES:
                    raise DCPMError("BUDGET_EXCEEDED", "operation output too large")
                outputs[op_id] = res.outputs
                if res.partial:
                    partial_ops.add(op_id)
                warnings += res.warnings
                st.upsert_task(t, self.run_id, op_id, op.type, "COMPLETED", output=blob, warnings=res.warnings, finished=True)
            except DCPMError as e:
                if e.code == "CANCELLED":
                    st.upsert_task(t, self.run_id, op_id, op.type, "CANCELLED", finished=True)
                    cancelled = True
                    break
                failed[op_id] = e.to_dict()
                st.upsert_task(t, self.run_id, op_id, op.type, "FAILED", error=e.to_dict(), finished=True)
            except Exception:  # noqa: BLE001 - never leak internals; full detail goes to the log
                log.exception("operation %s crashed (run %s)", op.type, self.run_id)
                err = DCPMError("INTERNAL_ERROR", "operation crashed unexpectedly").to_dict()
                failed[op_id] = err
                st.upsert_task(t, self.run_id, op_id, op.type, "FAILED", error=err, finished=True)

        completed_any = any(o in outputs for o in by_id)
        if cancelled:
            status = "CANCELLED"
        elif failed:
            blocking = any(e["code"] in BLOCKING_CODES for e in failed.values())
            status = "BLOCKED" if blocking and not completed_any else ("PARTIAL" if completed_any else "FAILED")
        elif partial_ops:
            status = "PARTIAL"
        elif warnings:
            status = "COMPLETED_WITH_WARNINGS"
        else:
            status = "COMPLETED"
        stats = {
            "operations": {"total": len(by_id), "completed": len(outputs), "failed": len(failed), "skipped": len(skipped)},
            "counters": ctx.stats.snapshot(), "budget": ctx.budget.snapshot(),
            "resources_by_status": st.resource_status_counts(t, source["id"]),
            "limitations": (warnings + [f"{k}: {v['code']}" for k, v in failed.items()])[:MAX_LIMITATIONS],
        }
        err_summary = {"failed_operations": failed} if failed else None
        return self._finish(status, stats, err_summary)
