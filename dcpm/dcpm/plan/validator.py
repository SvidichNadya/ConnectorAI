"""Static plan validation (ТЗ §6.6). Pure, deterministic and independent of any model.

A plan is data. It is parsed strictly (unknown keys rejected), type-checked against the Operation
Registry, checked for cycles, scope, SSRF-obvious targets and policy caps. The AI cannot override a
rejection: activation requires a VALIDATED plan and the runtime re-validates before every run.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..config import Policy
from ..errors import DCPMError
from ..security.netguard import ip_block_reason
from ..security.urls import Scope, normalize_url
from .registry import REGISTRY, OperationSpec, Param

PLAN_VERSION = "1.0"
VALIDATOR_VERSION = "1"
_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_REF_RE = re.compile(r"^\$([a-z][a-z0-9_]{0,63})\.([a-z][a-z0-9_]{0,63})$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_TOP_KEYS = {"plan_version", "source_id", "strategy", "description", "operations", "limits"}
_OP_KEYS = {"id", "type", "inputs", "depends_on", "outputs"}
_LIMIT_KEYS = {"max_runtime_seconds": "max_runtime_seconds", "max_total_bytes": "max_total_bytes", "max_resources": "max_resources"}
_FORBIDDEN_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain", ".lan", ".home.arpa")


@dataclass(frozen=True)
class Diagnostic:
    level: str   # "error" | "warning"
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"level": self.level, "code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class PlanOp:
    id: str
    type: str
    inputs: dict[str, Any]
    depends_on: tuple[str, ...]


@dataclass(frozen=True)
class Plan:
    plan_version: str
    source_id: str
    strategy: str
    operations: tuple[PlanOp, ...]
    limits: dict[str, int]
    description: str = ""


@dataclass
class ValidationResult:
    ok: bool
    diagnostics: list[Diagnostic] = field(default_factory=list)
    plan: Plan | None = None
    order: list[str] = field(default_factory=list)

    def errors(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.level == "error"]


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def plan_hash(plan: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(plan).encode()).hexdigest()


def parse_ref(value: Any) -> tuple[str, str] | None:
    if isinstance(value, str) and value.startswith("$"):
        m = _REF_RE.match(value)
        return (m.group(1), m.group(2)) if m else None
    return None


def validate_plan(raw: Any, *, policy: Policy, scope: Scope, expected_source_id: str) -> ValidationResult:
    diags: list[Diagnostic] = []

    def err(code: str, path: str, msg: str) -> None:
        diags.append(Diagnostic("error", code, path, msg))

    def done() -> ValidationResult:
        return ValidationResult(False, diags)

    # ---- size & shape -------------------------------------------------------
    if isinstance(raw, (str, bytes, bytearray)):
        if len(raw) > policy.max_plan_bytes:
            err("PLAN_TOO_LARGE", "$", "plan exceeds size limit")
            return done()
        try:
            raw = json.loads(raw)
        except (ValueError, RecursionError):
            err("SYNTAX", "$", "plan is not valid JSON")
            return done()
    try:
        if len(canonical_json(raw)) > policy.max_plan_bytes:
            err("PLAN_TOO_LARGE", "$", "plan exceeds size limit")
            return done()
    except (TypeError, ValueError, RecursionError):
        err("SYNTAX", "$", "plan is not JSON-serialisable")
        return done()
    if not isinstance(raw, dict):
        err("SCHEMA", "$", "plan must be an object")
        return done()
    for k in raw:
        if k not in _TOP_KEYS:
            err("SCHEMA", f"$.{k}", "unknown top-level field")
    if raw.get("plan_version") != PLAN_VERSION:
        err("SCHEMA", "$.plan_version", f"plan_version must be {PLAN_VERSION!r}")
    if raw.get("source_id") != expected_source_id:
        err("SCOPE", "$.source_id", "plan does not belong to this source")
    strategy = raw.get("strategy", "")
    if not isinstance(strategy, str) or len(strategy) > 128 or _CTRL_RE.search(strategy):
        err("SCHEMA", "$.strategy", "strategy must be a short string")
    desc = raw.get("description", "")
    if not isinstance(desc, str) or len(desc) > 1024:
        err("SCHEMA", "$.description", "description must be a string up to 1024 chars")
    ops_raw = raw.get("operations")
    if not isinstance(ops_raw, list) or not ops_raw:
        err("SCHEMA", "$.operations", "operations must be a non-empty list")
        return done()
    if len(ops_raw) > policy.max_operations:
        err("BUDGET", "$.operations", f"at most {policy.max_operations} operations allowed")
        return done()

    # ---- limits -------------------------------------------------------------
    limits: dict[str, int] = {}
    lraw = raw.get("limits", {})
    if not isinstance(lraw, dict):
        err("SCHEMA", "$.limits", "limits must be an object")
        lraw = {}
    for k, v in lraw.items():
        if k not in _LIMIT_KEYS:
            err("SCHEMA", f"$.limits.{k}", "unknown limit")
        elif isinstance(v, bool) or not isinstance(v, int) or v <= 0:
            err("SCHEMA", f"$.limits.{k}", "must be a positive integer")
        elif v > getattr(policy, _LIMIT_KEYS[k]):
            err("BUDGET", f"$.limits.{k}", f"exceeds platform maximum {getattr(policy, _LIMIT_KEYS[k])}")
        else:
            limits[k] = v

    # ---- operations ---------------------------------------------------------
    ops: list[PlanOp] = []
    specs: dict[str, OperationSpec] = {}
    seen_ids: set[str] = set()
    for i, o in enumerate(ops_raw):
        path = f"$.operations[{i}]"
        if not isinstance(o, dict):
            err("SCHEMA", path, "operation must be an object")
            continue
        for k in o:
            if k not in _OP_KEYS:
                err("SCHEMA", f"{path}.{k}", "unknown operation field")
        oid, otype = o.get("id"), o.get("type")
        if not isinstance(oid, str) or not _ID_RE.match(oid):
            err("SCHEMA", f"{path}.id", "id must match [a-z][a-z0-9_]{0,63}")
            continue
        if oid in seen_ids:
            err("SCHEMA", f"{path}.id", f"duplicate operation id {oid!r}")
            continue
        seen_ids.add(oid)
        spec = REGISTRY.get(otype) if isinstance(otype, str) else None
        if spec is None:
            err("UNKNOWN_OPERATION", f"{path}.type", "operation is not in the registry")
            continue
        if any(e != "read" for e in spec.effects):
            err("POLICY", f"{path}.type", "operations with side effects are not permitted")
            continue
        inputs = o.get("inputs", {})
        deps = o.get("depends_on", [])
        if not isinstance(inputs, dict):
            err("SCHEMA", f"{path}.inputs", "inputs must be an object")
            inputs = {}
        if not isinstance(deps, list) or not all(isinstance(d, str) for d in deps):
            err("SCHEMA", f"{path}.depends_on", "depends_on must be a list of operation ids")
            deps = []
        if "outputs" in o:
            outs = o["outputs"]
            if not isinstance(outs, list) or any(not isinstance(x, str) or spec.output(x) is None for x in outs):
                err("SCHEMA", f"{path}.outputs", "outputs must name outputs declared by the operation")
        specs[oid] = spec
        ops.append(PlanOp(oid, otype, dict(inputs), tuple(dict.fromkeys(deps))))

    by_id = {o.id: o for o in ops}
    for i, op in enumerate(ops):
        path = f"$.operations[{op.id}]"
        spec = specs[op.id]
        for d in op.depends_on:
            if d == op.id:
                err("DAG", f"{path}.depends_on", "operation cannot depend on itself")
            elif d not in by_id:
                err("REFERENCE", f"{path}.depends_on", f"unknown dependency {d!r}")
        for name in op.inputs:
            if spec.param(name) is None:
                err("SCHEMA", f"{path}.inputs.{name}", "unknown input")
        for p in spec.inputs:
            if p.name not in op.inputs:
                if p.required:
                    err("SCHEMA", f"{path}.inputs.{p.name}", "required input missing")
                continue
            _check_value(p, op.inputs[p.name], f"{path}.inputs.{p.name}", op, by_id, specs, policy, scope, err)

    # ---- DAG ----------------------------------------------------------------
    order = _toposort(ops, by_id)
    if order is None:
        err("DAG", "$.operations", "dependency cycle detected")
    if any(d.level == "error" for d in diags):
        return done()
    plan = Plan(PLAN_VERSION, expected_source_id, strategy, tuple(ops), limits, desc)
    return ValidationResult(True, diags, plan, order or [])


def _toposort(ops: list[PlanOp], by_id: dict[str, PlanOp]) -> list[str] | None:
    indeg = {o.id: len([d for d in o.depends_on if d in by_id]) for o in ops}
    children: dict[str, list[str]] = {o.id: [] for o in ops}
    for o in ops:
        for d in o.depends_on:
            if d in by_id:
                children[d].append(o.id)
    ready = [o.id for o in ops if indeg[o.id] == 0]
    out: list[str] = []
    while ready:
        n = ready.pop(0)
        out.append(n)
        for c in children[n]:
            indeg[c] -= 1
            if indeg[c] == 0:
                ready.append(c)
    return out if len(out) == len(ops) else None


def _check_value(p: Param, value: Any, path: str, op: PlanOp, by_id: dict[str, PlanOp],
                 specs: dict[str, OperationSpec], policy: Policy, scope: Scope, err) -> None:
    if isinstance(value, str) and value.startswith("$"):
        ref = parse_ref(value)
        if ref is None:
            err("REFERENCE", path, "malformed reference (expected $operation_id.output_name)")
            return
        src_id, out_name = ref
        if src_id == op.id:
            err("DAG", path, "operation cannot reference itself")
            return
        if src_id not in by_id:
            err("REFERENCE", path, f"reference to unknown operation {src_id!r}")
            return
        if src_id not in op.depends_on:
            err("REFERENCE", path, f"{src_id!r} must be listed in depends_on")
        out = specs[src_id].output(out_name)
        if out is None:
            err("REFERENCE", path, f"operation {src_id!r} has no output {out_name!r}")
        elif out.type != p.type:
            err("TYPE", path, f"type mismatch: input expects {p.type}, reference provides {out.type}")
        return
    if p.type not in ("url", "url_list", "int", "bool", "string"):
        err("TYPE", path, f"input of type {p.type} must be a reference to another operation's output")
        return
    if p.type == "url":
        _check_url(value, path, policy, scope, err)
    elif p.type == "url_list":
        if not isinstance(value, list) or not value:
            err("TYPE", path, "expected a non-empty list of URLs")
        elif len(value) > policy.max_resources:
            err("BUDGET", path, f"at most {policy.max_resources} literal URLs")
        else:
            for j, u in enumerate(value):
                _check_url(u, f"{path}[{j}]", policy, scope, err)
    elif p.type == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            err("TYPE", path, "expected an integer")
        else:
            if p.min is not None and value < p.min:
                err("TYPE", path, f"must be >= {p.min}")
            cap = getattr(policy, p.policy_max) if p.policy_max else p.max
            if cap is not None and value > cap:
                err("BUDGET", path, f"exceeds platform maximum {cap}")
    elif p.type == "bool":
        if not isinstance(value, bool):
            err("TYPE", path, "expected a boolean")
    elif p.type == "string":
        if not isinstance(value, str) or len(value) > p.max_len or _CTRL_RE.search(value):
            err("TYPE", path, "expected a short string without control characters")
        elif p.choices is not None and value not in p.choices:
            err("TYPE", path, f"must be one of {list(p.choices)}")
        elif p.pattern is not None and not re.fullmatch(p.pattern, value):
            err("TYPE", path, "value has an invalid format")


def _check_url(value: Any, path: str, policy: Policy, scope: Scope, err) -> None:
    try:
        nu = normalize_url(value)
    except DCPMError as e:
        err("URL", path, e.message)
        return
    if nu.scheme not in policy.allowed_schemes:
        err("URL", path, "scheme not allowed")
    if policy.allowed_ports is not None and nu.port not in policy.allowed_ports:
        err("URL", path, f"port {nu.port} not allowed")
    if not scope.allows(nu.host):
        err("SCOPE", path, f"host {nu.host!r} is outside the source scope")
        return
    try:
        ip = ipaddress.ip_address(nu.host)
    except ValueError:
        if not policy.allow_private_networks and (nu.host == "localhost" or nu.host.endswith(_FORBIDDEN_SUFFIXES)):
            err("SSRF", path, "internal host names are not allowed")
        return
    reason = ip_block_reason(str(ip), policy.allow_private_networks)
    if reason:
        err("SSRF", path, f"IP literal not allowed ({reason})")
