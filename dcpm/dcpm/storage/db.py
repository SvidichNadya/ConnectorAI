"""Metadata store (SQLite for the MVP; the Store interface is what the rest of DCPM depends on).

* every query is parameterised and tenant-scoped;
* writes run in explicit transactions (BEGIN IMMEDIATE) guarded by one RLock;
* audit_log is append-only (triggers) and hash-chained for tamper evidence.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from ..errors import DCPMError
from ..ids import new_id, now_iso
from ..security.redact import redact
from ..security.urls import NormalizedUrl

SOURCE_STATES = ("REGISTERED", "DISCOVERING", "DISCOVERED", "NEEDS_AUTH", "READY", "INITIAL_ACQUISITION",
                 "ACTIVE", "SYNCING", "PARTIAL", "DEGRADED", "BLOCKED", "FAILED", "DISABLED")
ACTIVE_RUN_STATES = ("PENDING", "RUNNING")

_JSON_FIELDS = frozenset({"scope", "config", "report", "plan", "diagnostics", "budget", "statistics",
                          "error_summary", "output", "error", "content", "warnings", "details", "response",
                          "payload", "attributes", "evidence", "value", "based_on"})

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL, locator TEXT NOT NULL,
  source_type TEXT NOT NULL DEFAULT 'auto', status TEXT NOT NULL, scope TEXT NOT NULL, config TEXT NOT NULL,
  active_plan_id TEXT, discovery_version INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, disabled_at TEXT);
CREATE INDEX IF NOT EXISTS ix_sources_tenant ON sources(tenant_id, status);

CREATE TABLE IF NOT EXISTS discovery_reports(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, source_id TEXT NOT NULL, version INTEGER NOT NULL,
  status TEXT NOT NULL, report TEXT, error TEXT, created_at TEXT NOT NULL, finished_at TEXT);
CREATE INDEX IF NOT EXISTS ix_disc_source ON discovery_reports(tenant_id, source_id);

CREATE TABLE IF NOT EXISTS plans(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, source_id TEXT NOT NULL, version INTEGER NOT NULL,
  status TEXT NOT NULL, plan TEXT NOT NULL, plan_hash TEXT NOT NULL, generated_by TEXT NOT NULL,
  diagnostics TEXT, discovery_id TEXT, created_at TEXT NOT NULL, activated_at TEXT,
  UNIQUE(source_id, version));
CREATE INDEX IF NOT EXISTS ix_plans_source ON plans(tenant_id, source_id);

CREATE TABLE IF NOT EXISTS runs(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, source_id TEXT NOT NULL, plan_id TEXT NOT NULL,
  plan_version INTEGER NOT NULL, plan_hash TEXT NOT NULL, run_type TEXT NOT NULL, status TEXT NOT NULL,
  budget TEXT, statistics TEXT, error_summary TEXT,
  created_at TEXT NOT NULL, started_at TEXT, completed_at TEXT);
CREATE INDEX IF NOT EXISTS ix_runs_source ON runs(tenant_id, source_id, status);

CREATE TABLE IF NOT EXISTS tasks(
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL, tenant_id TEXT NOT NULL, op_id TEXT NOT NULL, op_type TEXT NOT NULL,
  status TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 1, output TEXT, error TEXT, warnings TEXT,
  started_at TEXT, completed_at TEXT, UNIQUE(run_id, op_id));

CREATE TABLE IF NOT EXISTS resources(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, source_id TEXT NOT NULL, canonical_key TEXT NOT NULL,
  canonical_uri TEXT NOT NULL, original_uri TEXT NOT NULL, resource_type TEXT NOT NULL, mime_type TEXT, title TEXT,
  status TEXT NOT NULL, status_reason TEXT, depth INTEGER NOT NULL DEFAULT 0,
  first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, last_fetched_at TEXT,
  content_hash TEXT, current_artifact_id TEXT, discovered_run_id TEXT,
  UNIQUE(tenant_id, source_id, canonical_key));
CREATE INDEX IF NOT EXISTS ix_res_source ON resources(tenant_id, source_id, status);

CREATE TABLE IF NOT EXISTS relations(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, source_id TEXT NOT NULL, run_id TEXT,
  source_resource_id TEXT NOT NULL, target_resource_id TEXT NOT NULL, rel_type TEXT NOT NULL, created_at TEXT NOT NULL,
  UNIQUE(tenant_id, source_resource_id, target_resource_id, rel_type));
CREATE INDEX IF NOT EXISTS ix_rel_src ON relations(tenant_id, source_resource_id);

CREATE TABLE IF NOT EXISTS artifacts(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, resource_id TEXT NOT NULL, run_id TEXT, version INTEGER NOT NULL,
  sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, mime_type TEXT, http_status INTEGER, etag TEXT, last_modified TEXT,
  captured_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, UNIQUE(resource_id, sha256));
CREATE INDEX IF NOT EXISTS ix_art_res ON artifacts(tenant_id, resource_id);

CREATE TABLE IF NOT EXISTS extractions(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, artifact_id TEXT NOT NULL, resource_id TEXT NOT NULL, run_id TEXT,
  kind TEXT NOT NULL, parser_name TEXT NOT NULL, parser_version TEXT NOT NULL, status TEXT NOT NULL,
  content TEXT, warnings TEXT, created_at TEXT NOT NULL, UNIQUE(artifact_id, parser_name, parser_version));
CREATE INDEX IF NOT EXISTS ix_ext_art ON extractions(tenant_id, artifact_id);

CREATE TABLE IF NOT EXISTS audit_log(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, tenant_id TEXT, actor TEXT NOT NULL, action TEXT NOT NULL,
  object_type TEXT, object_id TEXT, details TEXT, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TABLE IF NOT EXISTS domains(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, key TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE', created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  UNIQUE(tenant_id, key));
CREATE INDEX IF NOT EXISTS ix_domains_tenant ON domains(tenant_id, status);

CREATE TABLE IF NOT EXISTS domain_classifications(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, source_id TEXT NOT NULL, domain_id TEXT NOT NULL,
  confidence REAL NOT NULL, evidence TEXT NOT NULL, method TEXT NOT NULL, run_id TEXT, created_at TEXT NOT NULL,
  UNIQUE(tenant_id, source_id, domain_id));
CREATE INDEX IF NOT EXISTS ix_domclass_source ON domain_classifications(tenant_id, source_id);

CREATE TABLE IF NOT EXISTS facts(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, source_id TEXT NOT NULL, resource_id TEXT NOT NULL,
  artifact_id TEXT NOT NULL, extraction_id TEXT, run_id TEXT NOT NULL, fact_type TEXT NOT NULL,
  domain_id TEXT, relevance_status TEXT NOT NULL DEFAULT 'PENDING', relevance_confidence REAL,
  payload TEXT NOT NULL, evidence_text TEXT NOT NULL, evidence_verified INTEGER NOT NULL DEFAULT 0,
  method TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_facts_source ON facts(tenant_id, source_id, relevance_status);
CREATE INDEX IF NOT EXISTS ix_facts_domain ON facts(tenant_id, domain_id);
CREATE INDEX IF NOT EXISTS ix_facts_resource ON facts(tenant_id, resource_id);

CREATE TABLE IF NOT EXISTS entities(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, domain_id TEXT, entity_type TEXT NOT NULL,
  canonical_name TEXT NOT NULL, normalized_key TEXT NOT NULL, attributes TEXT NOT NULL DEFAULT '{}',
  resolution_status TEXT NOT NULL DEFAULT 'ACTIVE', confidence REAL NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_entities_tenant ON entities(tenant_id, domain_id, entity_type);
CREATE INDEX IF NOT EXISTS ix_entities_key ON entities(tenant_id, domain_id, entity_type, normalized_key);

CREATE TABLE IF NOT EXISTS entity_mentions(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, fact_id TEXT NOT NULL, entity_id TEXT, source_id TEXT,
  mention_text TEXT NOT NULL, normalized_key TEXT NOT NULL, entity_type TEXT NOT NULL,
  confidence REAL NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_mentions_entity ON entity_mentions(tenant_id, entity_id);
CREATE INDEX IF NOT EXISTS ix_mentions_fact ON entity_mentions(tenant_id, fact_id);

CREATE TABLE IF NOT EXISTS merge_history(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, surviving_entity_id TEXT NOT NULL, merged_entity_id TEXT NOT NULL,
  reason TEXT NOT NULL, confidence REAL NOT NULL, evidence TEXT NOT NULL, performed_by TEXT NOT NULL,
  created_at TEXT NOT NULL, reverted_at TEXT);
CREATE INDEX IF NOT EXISTS ix_merge_surviving ON merge_history(tenant_id, surviving_entity_id);

CREATE TABLE IF NOT EXISTS relationships(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, subject_entity_id TEXT NOT NULL, predicate TEXT NOT NULL,
  object_entity_id TEXT NOT NULL, confidence REAL NOT NULL, evidence TEXT NOT NULL,
  fact_id TEXT, source_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'ACTIVE', created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_rels_subject ON relationships(tenant_id, subject_entity_id, status);
CREATE INDEX IF NOT EXISTS ix_rels_object ON relationships(tenant_id, object_entity_id, status);

CREATE TABLE IF NOT EXISTS assertions(
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, entity_id TEXT NOT NULL, attribute TEXT NOT NULL,
  value TEXT NOT NULL, source_id TEXT NOT NULL, resource_id TEXT, fact_id TEXT,
  assertion_type TEXT NOT NULL DEFAULT 'FACT', confidence REAL NOT NULL, evidence TEXT NOT NULL,
  observed_at TEXT NOT NULL, resolution_status TEXT NOT NULL DEFAULT 'ACTIVE', created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_assertions_entity ON assertions(tenant_id, entity_id, attribute, resolution_status);

CREATE TABLE IF NOT EXISTS canonical_values(
  tenant_id TEXT NOT NULL, entity_id TEXT NOT NULL, attribute TEXT NOT NULL, value TEXT NOT NULL,
  confidence REAL NOT NULL, based_on TEXT NOT NULL, policy_version TEXT NOT NULL, computed_at TEXT NOT NULL,
  PRIMARY KEY(tenant_id, entity_id, attribute));

CREATE TABLE IF NOT EXISTS process_locks(
  name TEXT PRIMARY KEY, holder TEXT NOT NULL, acquired_at TEXT NOT NULL, expires_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS idempotency(
  tenant_id TEXT NOT NULL, key TEXT NOT NULL, request_hash TEXT NOT NULL, response TEXT, created_at TEXT NOT NULL,
  PRIMARY KEY(tenant_id, key));
"""


def _decode(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    d = dict(row)
    for k in _JSON_FIELDS:
        v = d.get(k)
        if isinstance(v, str):
            try:
                d[k] = json.loads(v)
            except ValueError:
                pass
    return d


def _dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


class Store:
    def __init__(self, path: str = ":memory:"):
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._depth = 0
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys=ON")
            if path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ plumbing
    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._depth > 0:
                self._depth += 1
                try:
                    yield self._conn
                finally:
                    self._depth -= 1
                return
            self._conn.execute("BEGIN IMMEDIATE")
            self._depth = 1
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            finally:
                self._depth = 0

    def _one(self, sql: str, params: tuple = ()) -> dict[str, Any] | None:
        with self._lock:
            return _decode(self._conn.execute(sql, params).fetchone())

    def _all(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [_decode(r) for r in self._conn.execute(sql, params).fetchall()]  # type: ignore[misc]

    def _page(self, table: str, where: str, params: tuple, cursor: int, limit: int,
              order_extra: str = "") -> tuple[list[dict[str, Any]], int | None]:
        limit = max(1, min(int(limit), 500))
        rows = self._all(
            f"SELECT rowid AS _rowid, * FROM {table} WHERE {where} AND rowid > ? ORDER BY rowid{order_extra} LIMIT ?",
            params + (int(cursor), limit + 1))
        nxt = None
        if len(rows) > limit:
            rows = rows[:limit]
            nxt = rows[-1]["_rowid"]
        for r in rows:
            r.pop("_rowid", None)
        return rows, nxt

    # ------------------------------------------------------------------ audit
    def audit(self, tenant_id: str | None, actor: str, action: str, object_type: str | None = None,
              object_id: str | None = None, details: dict[str, Any] | None = None) -> None:
        with self._tx() as c:
            last = c.execute("SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
            prev = last[0] if last else "0" * 64
            ts = now_iso()
            det = redact(_dumps(details or {}))
            body = _dumps([ts, tenant_id, actor, action, object_type, object_id, det])
            h = hashlib.sha256((prev + body).encode()).hexdigest()
            c.execute("INSERT INTO audit_log(ts,tenant_id,actor,action,object_type,object_id,details,prev_hash,entry_hash)"
                      " VALUES(?,?,?,?,?,?,?,?,?)", (ts, tenant_id, actor, action, object_type, object_id, det, prev, h))

    def verify_audit_chain(self) -> bool:
        prev = "0" * 64
        for r in self._all("SELECT * FROM audit_log ORDER BY seq"):
            body = _dumps([r["ts"], r["tenant_id"], r["actor"], r["action"], r["object_type"], r["object_id"], r["details"]
                           if isinstance(r["details"], str) else _dumps(r["details"])])
            if r["prev_hash"] != prev or hashlib.sha256((prev + body).encode()).hexdigest() != r["entry_hash"]:
                return False
            prev = r["entry_hash"]
        return True

    # ------------------------------------------------------------------ cross-process locks
    # A real distributed lock, not a Python threading.Lock: backed by the SAME sqlite file every
    # process/connection shares, so it serialises correctly across multiple worker PROCESSES, not
    # just threads of one process. Lease-based (ttl + expiry), matching the same philosophy as task
    # leases elsewhere in DCPM: a crashed holder's lock is reclaimed by the next acquire attempt
    # without needing a separate reaper, though recover_stale_locks() is exposed for a startup sweep.
    def try_acquire_lock(self, name: str, holder: str, ttl_seconds: float) -> bool:
        with self._tx() as c:
            now = now_iso()
            c.execute("DELETE FROM process_locks WHERE name=? AND expires_at<?", (name, now))
            expires = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat(timespec="seconds")
            try:
                c.execute("INSERT INTO process_locks(name,holder,acquired_at,expires_at) VALUES(?,?,?,?)", (name, holder, now, expires))
                return True
            except sqlite3.IntegrityError:
                return False

    def release_lock(self, name: str, holder: str) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM process_locks WHERE name=? AND holder=?", (name, holder))

    def recover_stale_locks(self) -> int:
        with self._tx() as c:
            return c.execute("DELETE FROM process_locks WHERE expires_at < ?", (now_iso(),)).rowcount

    # ------------------------------------------------------------------ idempotency
    def idempotency_begin(self, tenant_id: str, key: str, request_hash: str) -> dict[str, Any] | None:
        """Return the stored response for a replay, None if this is a new key. Raises on key reuse with another body."""
        with self._tx() as c:
            row = c.execute("SELECT request_hash, response FROM idempotency WHERE tenant_id=? AND key=?", (tenant_id, key)).fetchone()
            if row:
                if row["request_hash"] != request_hash:
                    raise DCPMError("IDEMPOTENCY_KEY_REUSED", "Idempotency-Key was used with a different request")
                if row["response"] is None:
                    raise DCPMError("CONFLICT", "a request with this Idempotency-Key is still in progress")
                return json.loads(row["response"])
            c.execute("INSERT INTO idempotency(tenant_id,key,request_hash,response,created_at) VALUES(?,?,?,NULL,?)",
                      (tenant_id, key, request_hash, now_iso()))
            return None

    def idempotency_finish(self, tenant_id: str, key: str, response: dict[str, Any] | None) -> None:
        with self._tx() as c:
            if response is None:
                c.execute("DELETE FROM idempotency WHERE tenant_id=? AND key=? AND response IS NULL", (tenant_id, key))
            else:
                c.execute("UPDATE idempotency SET response=? WHERE tenant_id=? AND key=?", (_dumps(response), tenant_id, key))

    # ------------------------------------------------------------------ sources
    def create_source(self, tenant_id: str, name: str, locator: str, scope: dict, config: dict) -> dict[str, Any]:
        sid, ts = new_id("src"), now_iso()
        with self._tx() as c:
            c.execute("INSERT INTO sources(id,tenant_id,name,locator,status,scope,config,created_at,updated_at)"
                      " VALUES(?,?,?,?,?,?,?,?,?)", (sid, tenant_id, name, locator, "REGISTERED", _dumps(scope), _dumps(config), ts, ts))
        return self.get_source(tenant_id, sid)  # type: ignore[return-value]

    def get_source(self, tenant_id: str, source_id: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM sources WHERE id=? AND tenant_id=?", (source_id, tenant_id))

    def list_sources(self, tenant_id: str, cursor: int = 0, limit: int = 50):
        return self._page("sources", "tenant_id=?", (tenant_id,), cursor, limit)

    def set_source_status(self, tenant_id: str, source_id: str, new: str, allowed_from: tuple[str, ...] | None = None) -> bool:
        assert new in SOURCE_STATES
        with self._tx() as c:
            if allowed_from is None:
                cur = c.execute("UPDATE sources SET status=?, updated_at=? WHERE id=? AND tenant_id=? AND status!='DISABLED'",
                                (new, now_iso(), source_id, tenant_id))
            else:
                marks = ",".join("?" * len(allowed_from))
                cur = c.execute(f"UPDATE sources SET status=?, updated_at=? WHERE id=? AND tenant_id=? AND status IN ({marks})",
                                (new, now_iso(), source_id, tenant_id, *allowed_from))
            return cur.rowcount == 1

    def update_source(self, tenant_id: str, source_id: str, *, name: str | None = None, config: dict | None = None) -> None:
        with self._tx() as c:
            if name is not None:
                c.execute("UPDATE sources SET name=?, updated_at=? WHERE id=? AND tenant_id=?", (name, now_iso(), source_id, tenant_id))
            if config is not None:
                c.execute("UPDATE sources SET config=?, updated_at=? WHERE id=? AND tenant_id=?", (_dumps(config), now_iso(), source_id, tenant_id))

    def disable_source(self, tenant_id: str, source_id: str) -> bool:
        with self._tx() as c:
            cur = c.execute("UPDATE sources SET status='DISABLED', disabled_at=?, updated_at=? WHERE id=? AND tenant_id=?",
                            (now_iso(), now_iso(), source_id, tenant_id))
            return cur.rowcount == 1

    # ------------------------------------------------------------------ discovery
    def create_discovery(self, tenant_id: str, source_id: str) -> str:
        did = new_id("dsc")
        with self._tx() as c:
            c.execute("UPDATE sources SET discovery_version=discovery_version+1 WHERE id=? AND tenant_id=?", (source_id, tenant_id))
            v = c.execute("SELECT discovery_version FROM sources WHERE id=? AND tenant_id=?", (source_id, tenant_id)).fetchone()[0]
            c.execute("INSERT INTO discovery_reports(id,tenant_id,source_id,version,status,created_at) VALUES(?,?,?,?,?,?)",
                      (did, tenant_id, source_id, v, "RUNNING", now_iso()))
        return did

    def finish_discovery(self, tenant_id: str, discovery_id: str, status: str, report: dict | None, error: dict | None) -> None:
        with self._tx() as c:
            c.execute("UPDATE discovery_reports SET status=?, report=?, error=?, finished_at=? WHERE id=? AND tenant_id=?",
                      (status, _dumps(report) if report is not None else None, _dumps(error) if error else None,
                       now_iso(), discovery_id, tenant_id))

    def get_discovery(self, tenant_id: str, discovery_id: str):
        return self._one("SELECT * FROM discovery_reports WHERE id=? AND tenant_id=?", (discovery_id, tenant_id))

    def list_discoveries(self, tenant_id: str, source_id: str, cursor: int = 0, limit: int = 50):
        return self._page("discovery_reports", "tenant_id=? AND source_id=?", (tenant_id, source_id), cursor, limit)

    def latest_discovery(self, tenant_id: str, source_id: str):
        return self._one("SELECT * FROM discovery_reports WHERE tenant_id=? AND source_id=? AND status='COMPLETED' "
                         "ORDER BY version DESC LIMIT 1", (tenant_id, source_id))

    # ------------------------------------------------------------------ plans
    def create_plan(self, tenant_id: str, source_id: str, plan: dict, plan_hash: str, generated_by: str,
                    diagnostics: list, discovery_id: str | None, status: str) -> dict[str, Any]:
        pid = new_id("pln")
        with self._tx() as c:
            v = (c.execute("SELECT COALESCE(MAX(version),0) FROM plans WHERE source_id=?", (source_id,)).fetchone()[0]) + 1
            c.execute("INSERT INTO plans(id,tenant_id,source_id,version,status,plan,plan_hash,generated_by,diagnostics,discovery_id,created_at)"
                      " VALUES(?,?,?,?,?,?,?,?,?,?,?)", (pid, tenant_id, source_id, v, status, _dumps(plan), plan_hash,
                                                          generated_by, _dumps(diagnostics), discovery_id, now_iso()))
        return self.get_plan(tenant_id, pid)  # type: ignore[return-value]

    def get_plan(self, tenant_id: str, plan_id: str):
        return self._one("SELECT * FROM plans WHERE id=? AND tenant_id=?", (plan_id, tenant_id))

    def list_plans(self, tenant_id: str, source_id: str, cursor: int = 0, limit: int = 50):
        return self._page("plans", "tenant_id=? AND source_id=?", (tenant_id, source_id), cursor, limit)

    def set_plan_status(self, tenant_id: str, plan_id: str, status: str, diagnostics: list | None = None,
                        allowed_from: tuple[str, ...] | None = None) -> bool:
        with self._tx() as c:
            sql, params = "UPDATE plans SET status=?" + (", diagnostics=?" if diagnostics is not None else ""), [status]
            if diagnostics is not None:
                params.append(_dumps(diagnostics))
            sql += " WHERE id=? AND tenant_id=?"
            params += [plan_id, tenant_id]
            if allowed_from:
                sql += f" AND status IN ({','.join('?' * len(allowed_from))})"
                params += list(allowed_from)
            return c.execute(sql, params).rowcount == 1

    def activate_plan(self, tenant_id: str, source_id: str, plan_id: str) -> None:
        with self._tx() as c:
            c.execute("UPDATE plans SET status='SUPERSEDED' WHERE tenant_id=? AND source_id=? AND status='ACTIVE'", (tenant_id, source_id))
            cur = c.execute("UPDATE plans SET status='ACTIVE', activated_at=? WHERE id=? AND tenant_id=? AND source_id=? AND status='VALIDATED'",
                            (now_iso(), plan_id, tenant_id, source_id))
            if cur.rowcount != 1:
                raise DCPMError("CONFLICT", "only a VALIDATED plan can be activated")
            c.execute("UPDATE sources SET active_plan_id=?, updated_at=? WHERE id=? AND tenant_id=?", (plan_id, now_iso(), source_id, tenant_id))

    def deactivate_plan(self, tenant_id: str, source_id: str, plan_id: str) -> bool:
        with self._tx() as c:
            cur = c.execute("UPDATE plans SET status='VALIDATED' WHERE id=? AND tenant_id=? AND source_id=? AND status='ACTIVE'",
                            (plan_id, tenant_id, source_id))
            if cur.rowcount == 1:
                c.execute("UPDATE sources SET active_plan_id=NULL, updated_at=? WHERE id=? AND tenant_id=? AND active_plan_id=?",
                          (now_iso(), source_id, tenant_id, plan_id))
            return cur.rowcount == 1

    # ------------------------------------------------------------------ runs & tasks
    def create_run(self, tenant_id: str, source_id: str, plan: dict, run_type: str, budget: dict) -> dict[str, Any]:
        rid = new_id("run")
        with self._tx() as c:
            busy = c.execute(f"SELECT 1 FROM runs WHERE tenant_id=? AND source_id=? AND status IN ({','.join('?' * len(ACTIVE_RUN_STATES))})",
                             (tenant_id, source_id, *ACTIVE_RUN_STATES)).fetchone()
            if busy:
                raise DCPMError("CONFLICT", "another run is already active for this source")
            c.execute("INSERT INTO runs(id,tenant_id,source_id,plan_id,plan_version,plan_hash,run_type,status,budget,created_at)"
                      " VALUES(?,?,?,?,?,?,?,?,?,?)", (rid, tenant_id, source_id, plan["id"], plan["version"], plan["plan_hash"],
                                                      run_type, "PENDING", _dumps(budget), now_iso()))
        return self.get_run(tenant_id, rid)  # type: ignore[return-value]

    def get_run(self, tenant_id: str, run_id: str):
        return self._one("SELECT * FROM runs WHERE id=? AND tenant_id=?", (run_id, tenant_id))

    def list_runs(self, tenant_id: str, source_id: str, cursor: int = 0, limit: int = 50):
        return self._page("runs", "tenant_id=? AND source_id=?", (tenant_id, source_id), cursor, limit)

    def update_run(self, tenant_id: str, run_id: str, **fields: Any) -> None:
        allowed = {"status", "statistics", "error_summary", "started_at", "completed_at"}
        if not fields or set(fields) - allowed:
            raise ValueError("bad run fields")
        sets = ", ".join(f"{k}=?" for k in fields)
        vals = [_dumps(v) if k in ("statistics", "error_summary") and v is not None else v for k, v in fields.items()]
        with self._tx() as c:
            c.execute(f"UPDATE runs SET {sets} WHERE id=? AND tenant_id=?", (*vals, run_id, tenant_id))

    def claim_run(self, tenant_id: str, run_id: str, from_states: tuple[str, ...]) -> bool:
        with self._tx() as c:
            marks = ",".join("?" * len(from_states))
            cur = c.execute(f"UPDATE runs SET status='RUNNING', started_at=COALESCE(started_at, ?), completed_at=NULL "
                            f"WHERE id=? AND tenant_id=? AND status IN ({marks})", (now_iso(), run_id, tenant_id, *from_states))
            return cur.rowcount == 1

    def recover_interrupted_runs(self) -> list[dict[str, Any]]:
        """Called once at start-up: nothing can be RUNNING in a freshly started process."""
        with self._tx() as c:
            rows = [dict(r) for r in c.execute("SELECT id, tenant_id, source_id FROM runs WHERE status IN ('RUNNING','PENDING')").fetchall()]
            c.execute("UPDATE runs SET status='INTERRUPTED' WHERE status IN ('RUNNING','PENDING')")
            for r in rows:
                c.execute("UPDATE sources SET status='DEGRADED', updated_at=? WHERE id=? AND tenant_id=? AND status IN ('SYNCING','INITIAL_ACQUISITION')",
                          (now_iso(), r["source_id"], r["tenant_id"]))
        return rows

    def upsert_task(self, tenant_id: str, run_id: str, op_id: str, op_type: str, status: str, *, output: Any = None,
                    error: dict | None = None, warnings: list | None = None, started: bool = False, finished: bool = False) -> None:
        with self._tx() as c:
            row = c.execute("SELECT attempt, status FROM tasks WHERE run_id=? AND op_id=?", (run_id, op_id)).fetchone()
            ts = now_iso()
            if row is None:
                c.execute("INSERT INTO tasks(id,run_id,tenant_id,op_id,op_type,status,attempt,output,error,warnings,started_at,completed_at)"
                          " VALUES(?,?,?,?,?,?,1,?,?,?,?,?)",
                          (new_id("tsk"), run_id, tenant_id, op_id, op_type, status,
                           _dumps(output) if output is not None else None, _dumps(error) if error else None,
                           _dumps(warnings) if warnings else None, ts if started else None, ts if finished else None))
            else:
                attempt = row["attempt"] + (1 if started and row["status"] != "PENDING" else 0)
                c.execute("UPDATE tasks SET status=?, attempt=?, output=?, error=?, warnings=?, "
                          "started_at=COALESCE(?, started_at), completed_at=? WHERE run_id=? AND op_id=?",
                          (status, attempt, _dumps(output) if output is not None else None, _dumps(error) if error else None,
                           _dumps(warnings) if warnings else None, ts if started else None, ts if finished else None, run_id, op_id))

    def get_tasks(self, tenant_id: str, run_id: str) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM tasks WHERE run_id=? AND tenant_id=? ORDER BY rowid", (run_id, tenant_id))

    # ------------------------------------------------------------------ resources / graph
    def upsert_resource(self, tenant_id: str, source_id: str, nu: NormalizedUrl, run_id: str | None, depth: int,
                        resource_type: str = "WEB_PAGE", status: str = "DISCOVERED", reason: str | None = None) -> str:
        with self._tx() as c:
            row = c.execute("SELECT id, depth FROM resources WHERE tenant_id=? AND source_id=? AND canonical_key=?",
                            (tenant_id, source_id, nu.key)).fetchone()
            ts = now_iso()
            if row:
                c.execute("UPDATE resources SET last_seen_at=?, depth=MIN(depth, ?) WHERE id=?", (ts, depth, row["id"]))
                return row["id"]
            rid = new_id("res")
            c.execute("INSERT INTO resources(id,tenant_id,source_id,canonical_key,canonical_uri,original_uri,resource_type,status,status_reason,"
                      "depth,first_seen_at,last_seen_at,discovered_run_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (rid, tenant_id, source_id, nu.key, nu.url, nu.url, resource_type, status, reason, depth, ts, ts, run_id))
            return rid

    def set_resource_status(self, tenant_id: str, resource_id: str, status: str, reason: str | None = None,
                            only_if_not: tuple[str, ...] = ()) -> None:
        with self._tx() as c:
            sql = "UPDATE resources SET status=?, status_reason=?, last_seen_at=? WHERE id=? AND tenant_id=?"
            params: list[Any] = [status, reason, now_iso(), resource_id, tenant_id]
            if only_if_not:
                sql += f" AND status NOT IN ({','.join('?' * len(only_if_not))})"
                params += list(only_if_not)
            c.execute(sql, params)

    def add_relation(self, tenant_id: str, source_id: str, run_id: str | None, src_res: str, tgt_res: str, rel_type: str) -> None:
        if src_res == tgt_res:
            return
        with self._tx() as c:
            c.execute("INSERT OR IGNORE INTO relations(id,tenant_id,source_id,run_id,source_resource_id,target_resource_id,rel_type,created_at)"
                      " VALUES(?,?,?,?,?,?,?,?)", (new_id("rel"), tenant_id, source_id, run_id, src_res, tgt_res, rel_type, now_iso()))

    def record_artifact(self, tenant_id: str, resource_id: str, run_id: str | None, *, sha256: str, size: int, mime: str | None,
                        http_status: int, etag: str | None, last_modified: str | None, title: str | None = None) -> tuple[dict[str, Any], bool]:
        """Idempotent: same (resource, hash) returns the existing artifact. New hash => version+1 (content changed)."""
        with self._tx() as c:
            ts = now_iso()
            row = c.execute("SELECT id FROM artifacts WHERE resource_id=? AND sha256=? AND tenant_id=?", (resource_id, sha256, tenant_id)).fetchone()
            created = row is None
            if row:
                aid = row["id"]
                c.execute("UPDATE artifacts SET last_seen_at=?, etag=COALESCE(?, etag), last_modified=COALESCE(?, last_modified) WHERE id=?",
                          (ts, etag, last_modified, aid))
            else:
                aid = new_id("art")
                v = c.execute("SELECT COALESCE(MAX(version),0) FROM artifacts WHERE resource_id=?", (resource_id,)).fetchone()[0] + 1
                c.execute("INSERT INTO artifacts(id,tenant_id,resource_id,run_id,version,sha256,size_bytes,mime_type,http_status,etag,last_modified,captured_at,last_seen_at)"
                          " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (aid, tenant_id, resource_id, run_id, v, sha256, size, mime, http_status, etag, last_modified, ts, ts))
            c.execute("UPDATE resources SET status='FETCHED', status_reason=NULL, mime_type=?, content_hash=?, current_artifact_id=?, "
                      "last_fetched_at=?, last_seen_at=?, title=COALESCE(?, title) WHERE id=? AND tenant_id=?",
                      (mime, sha256, aid, ts, ts, title, resource_id, tenant_id))
        return self.get_artifact(tenant_id, aid), created  # type: ignore[return-value]

    def get_resource(self, tenant_id: str, resource_id: str):
        return self._one("SELECT * FROM resources WHERE id=? AND tenant_id=?", (resource_id, tenant_id))

    def list_resources(self, tenant_id: str, source_id: str, status: str | None = None, cursor: int = 0, limit: int = 50):
        if status:
            return self._page("resources", "tenant_id=? AND source_id=? AND status=?", (tenant_id, source_id, status), cursor, limit)
        return self._page("resources", "tenant_id=? AND source_id=?", (tenant_id, source_id), cursor, limit)

    def resource_children(self, tenant_id: str, resource_id: str, limit: int = 500) -> list[dict[str, Any]]:
        return self._all("SELECT r.id AS resource_id, r.canonical_uri, r.status, r.resource_type, rel.rel_type FROM relations rel "
                         "JOIN resources r ON r.id = rel.target_resource_id AND r.tenant_id = rel.tenant_id "
                         "WHERE rel.tenant_id=? AND rel.source_resource_id=? ORDER BY rel.rowid LIMIT ?", (tenant_id, resource_id, limit))

    def resource_status_counts(self, tenant_id: str, source_id: str) -> dict[str, int]:
        rows = self._all("SELECT status, COUNT(*) AS n FROM resources WHERE tenant_id=? AND source_id=? GROUP BY status", (tenant_id, source_id))
        return {r["status"]: r["n"] for r in rows}

    def set_resource_title(self, tenant_id: str, resource_id: str, title: str | None) -> None:
        if title:
            with self._tx() as c:
                c.execute("UPDATE resources SET title=? WHERE id=? AND tenant_id=?", (title[:300], resource_id, tenant_id))

    def active_run_id(self, tenant_id: str, source_id: str) -> str | None:
        r = self._one("SELECT id FROM runs WHERE tenant_id=? AND source_id=? AND status IN ('PENDING','RUNNING')", (tenant_id, source_id))
        return r["id"] if r else None

    def active_run_exists(self, tenant_id: str, source_id: str) -> bool:
        return self.active_run_id(tenant_id, source_id) is not None

    def discovery_running(self, tenant_id: str, source_id: str) -> bool:
        return self._one("SELECT 1 AS x FROM discovery_reports WHERE tenant_id=? AND source_id=? AND status='RUNNING'",
                         (tenant_id, source_id)) is not None

    def recover_discoveries(self) -> int:
        with self._tx() as c:
            return c.execute("UPDATE discovery_reports SET status='FAILED', error=?, finished_at=? WHERE status='RUNNING'",
                             (_dumps({"code": "INTERNAL_ERROR", "message": "interrupted by restart"}), now_iso())).rowcount

    def get_artifact(self, tenant_id: str, artifact_id: str):
        return self._one("SELECT * FROM artifacts WHERE id=? AND tenant_id=?", (artifact_id, tenant_id))

    def list_artifacts(self, tenant_id: str, resource_id: str):
        return self._all("SELECT * FROM artifacts WHERE tenant_id=? AND resource_id=? ORDER BY version", (tenant_id, resource_id))

    # ------------------------------------------------------------------ domains
    def find_domain_by_key(self, tenant_id: str, key: str):
        return self._one("SELECT * FROM domains WHERE tenant_id=? AND key=? AND status='ACTIVE'", (tenant_id, key))

    def list_domains(self, tenant_id: str, cursor: int = 0, limit: int = 100):
        return self._page("domains", "tenant_id=? AND status='ACTIVE'", (tenant_id,), cursor, limit)

    def get_domain(self, tenant_id: str, domain_id: str):
        return self._one("SELECT * FROM domains WHERE id=? AND tenant_id=?", (domain_id, tenant_id))

    def create_domain(self, tenant_id: str, key: str, title: str, description: str, created_by: str) -> dict[str, Any]:
        did = new_id("dom")
        with self._tx() as c:
            c.execute("INSERT INTO domains(id,tenant_id,key,title,description,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                      (did, tenant_id, key, title, description, created_by, now_iso()))
        return self.get_domain(tenant_id, did)  # type: ignore[return-value]

    def record_domain_classification(self, tenant_id: str, source_id: str, domain_id: str, confidence: float,
                                     evidence: list[str], method: str, run_id: str | None) -> str:
        cid = new_id("dcl")
        with self._tx() as c:
            c.execute("INSERT INTO domain_classifications(id,tenant_id,source_id,domain_id,confidence,evidence,method,run_id,created_at)"
                      " VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,source_id,domain_id) DO UPDATE SET"
                      " confidence=excluded.confidence, evidence=excluded.evidence, method=excluded.method, run_id=excluded.run_id",
                      (cid, tenant_id, source_id, domain_id, confidence, _dumps(evidence), method, run_id, now_iso()))
        return cid

    def list_domain_classifications(self, tenant_id: str, source_id: str):
        return self._all("SELECT * FROM domain_classifications WHERE tenant_id=? AND source_id=? ORDER BY confidence DESC",
                         (tenant_id, source_id))

    # ------------------------------------------------------------------ facts
    def create_fact(self, tenant_id: str, *, source_id: str, resource_id: str, artifact_id: str, extraction_id: str | None,
                    run_id: str, fact_type: str, payload: dict, evidence_text: str, evidence_verified: bool, method: str,
                    domain_id: str | None = None, relevance_status: str = "PENDING", relevance_confidence: float | None = None) -> dict[str, Any]:
        fid = new_id("fct")
        with self._tx() as c:
            c.execute("INSERT INTO facts(id,tenant_id,source_id,resource_id,artifact_id,extraction_id,run_id,fact_type,domain_id,"
                      "relevance_status,relevance_confidence,payload,evidence_text,evidence_verified,method,created_at)"
                      " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (fid, tenant_id, source_id, resource_id, artifact_id, extraction_id, run_id, fact_type, domain_id,
                       relevance_status, relevance_confidence, _dumps(payload), evidence_text, int(evidence_verified), method, now_iso()))
        return self.get_fact(tenant_id, fid)  # type: ignore[return-value]

    def get_fact(self, tenant_id: str, fact_id: str):
        return self._one("SELECT * FROM facts WHERE id=? AND tenant_id=?", (fact_id, tenant_id))

    def set_fact_relevance(self, tenant_id: str, fact_id: str, domain_id: str | None, status: str, confidence: float | None) -> None:
        with self._tx() as c:
            c.execute("UPDATE facts SET domain_id=?, relevance_status=?, relevance_confidence=? WHERE id=? AND tenant_id=?",
                      (domain_id, status, confidence, fact_id, tenant_id))

    def list_facts(self, tenant_id: str, source_id: str, relevance_status: str | None = None, cursor: int = 0, limit: int = 100):
        if relevance_status:
            return self._page("facts", "tenant_id=? AND source_id=? AND relevance_status=?", (tenant_id, source_id, relevance_status), cursor, limit)
        return self._page("facts", "tenant_id=? AND source_id=?", (tenant_id, source_id), cursor, limit)

    def facts_for_run(self, tenant_id: str, run_id: str) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM facts WHERE tenant_id=? AND run_id=? ORDER BY rowid", (tenant_id, run_id))

    # ------------------------------------------------------------------ entities & mentions
    def find_entity_by_key(self, tenant_id: str, domain_id: str | None, entity_type: str, normalized_key: str):
        return self._one("SELECT * FROM entities WHERE tenant_id=? AND domain_id IS ? AND entity_type=? AND normalized_key=? "
                         "AND resolution_status='ACTIVE'", (tenant_id, domain_id, entity_type, normalized_key))

    def create_entity(self, tenant_id: str, domain_id: str | None, entity_type: str, canonical_name: str,
                      normalized_key: str, confidence: float, attributes: dict | None = None) -> dict[str, Any]:
        eid = new_id("ent")
        ts = now_iso()
        with self._tx() as c:
            c.execute("INSERT INTO entities(id,tenant_id,domain_id,entity_type,canonical_name,normalized_key,attributes,"
                      "confidence,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (eid, tenant_id, domain_id, entity_type, canonical_name, normalized_key, _dumps(attributes or {}),
                       confidence, ts, ts))
        return self.get_entity(tenant_id, eid)  # type: ignore[return-value]

    def get_entity(self, tenant_id: str, entity_id: str):
        return self._one("SELECT * FROM entities WHERE id=? AND tenant_id=?", (entity_id, tenant_id))

    def list_entities(self, tenant_id: str, domain_id: str | None = None, cursor: int = 0, limit: int = 100):
        if domain_id:
            return self._page("entities", "tenant_id=? AND domain_id=? AND resolution_status='ACTIVE'", (tenant_id, domain_id), cursor, limit)
        return self._page("entities", "tenant_id=? AND resolution_status='ACTIVE'", (tenant_id,), cursor, limit)

    def candidate_entities(self, tenant_id: str, domain_id: str | None, entity_type: str, limit: int = 200) -> list[dict[str, Any]]:
        """Blocking set for resolution: same tenant/domain/type, active entities only."""
        return self._all("SELECT * FROM entities WHERE tenant_id=? AND domain_id IS ? AND entity_type=? AND resolution_status='ACTIVE' "
                         "ORDER BY rowid LIMIT ?", (tenant_id, domain_id, entity_type, limit))

    def add_mention(self, tenant_id: str, fact_id: str, entity_id: str | None, mention_text: str, normalized_key: str,
                    entity_type: str, confidence: float, source_id: str | None = None) -> str:
        mid = new_id("men")
        with self._tx() as c:
            c.execute("INSERT INTO entity_mentions(id,tenant_id,fact_id,entity_id,source_id,mention_text,normalized_key,entity_type,confidence,created_at)"
                      " VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (mid, tenant_id, fact_id, entity_id, source_id, mention_text, normalized_key, entity_type, confidence, now_iso()))
        return mid

    def entity_mentions(self, tenant_id: str, entity_id: str) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM entity_mentions WHERE tenant_id=? AND entity_id=? ORDER BY rowid", (tenant_id, entity_id))

    def set_entity_confidence(self, tenant_id: str, entity_id: str, confidence: float) -> None:
        with self._tx() as c:
            c.execute("UPDATE entities SET confidence=?, updated_at=? WHERE id=? AND tenant_id=?",
                      (confidence, now_iso(), entity_id, tenant_id))

    def merge_entities(self, tenant_id: str, surviving_id: str, merged_id: str, *, reason: str, confidence: float,
                       evidence: list[str], performed_by: str) -> str:
        """Reversible: the merged entity is marked MERGED (never deleted); its mentions/assertions/relationships are repointed."""
        if surviving_id == merged_id:
            raise DCPMError("VALIDATION_ERROR", "an entity cannot be merged into itself")
        hid = new_id("mrg")
        with self._tx() as c:
            row = c.execute("SELECT resolution_status FROM entities WHERE id=? AND tenant_id=?", (merged_id, tenant_id)).fetchone()
            if row is None or row["resolution_status"] != "ACTIVE":
                raise DCPMError("CONFLICT", "the entity being merged must exist and be ACTIVE")
            if c.execute("SELECT resolution_status FROM entities WHERE id=? AND tenant_id=?", (surviving_id, tenant_id)).fetchone() is None:
                raise DCPMError("CONFLICT", "the surviving entity does not exist")
            c.execute("UPDATE entities SET resolution_status='MERGED', updated_at=? WHERE id=? AND tenant_id=?", (now_iso(), merged_id, tenant_id))
            c.execute("UPDATE entity_mentions SET entity_id=? WHERE tenant_id=? AND entity_id=?", (surviving_id, tenant_id, merged_id))
            c.execute("UPDATE assertions SET entity_id=? WHERE tenant_id=? AND entity_id=?", (surviving_id, tenant_id, merged_id))
            c.execute("UPDATE relationships SET subject_entity_id=? WHERE tenant_id=? AND subject_entity_id=?", (surviving_id, tenant_id, merged_id))
            c.execute("UPDATE relationships SET object_entity_id=? WHERE tenant_id=? AND object_entity_id=?", (surviving_id, tenant_id, merged_id))
            c.execute("INSERT INTO merge_history(id,tenant_id,surviving_entity_id,merged_entity_id,reason,confidence,evidence,performed_by,created_at)"
                      " VALUES(?,?,?,?,?,?,?,?,?)", (hid, tenant_id, surviving_id, merged_id, reason, confidence, _dumps(evidence), performed_by, now_iso()))
        return hid

    def revert_merge(self, tenant_id: str, merge_id: str) -> None:
        with self._tx() as c:
            row = c.execute("SELECT * FROM merge_history WHERE id=? AND tenant_id=?", (merge_id, tenant_id)).fetchone()
            if row is None or row["reverted_at"] is not None:
                raise DCPMError("CONFLICT", "merge not found or already reverted")
            c.execute("UPDATE entities SET resolution_status='ACTIVE', updated_at=? WHERE id=? AND tenant_id=?",
                      (now_iso(), row["merged_entity_id"], tenant_id))
            c.execute("UPDATE merge_history SET reverted_at=? WHERE id=?", (now_iso(), merge_id))
            # Note: mentions/assertions/relationships created *after* the merge stay on the surviving
            # entity; revert restores independence going forward rather than rewriting history.

    def merge_history_for(self, tenant_id: str, entity_id: str) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM merge_history WHERE tenant_id=? AND (surviving_entity_id=? OR merged_entity_id=?) ORDER BY rowid",
                         (tenant_id, entity_id, entity_id))

    # ------------------------------------------------------------------ relationships
    def create_relationship(self, tenant_id: str, subject_id: str, predicate: str, object_id: str, *, confidence: float,
                            evidence: list[str], source_id: str, fact_id: str | None) -> str:
        rid = new_id("rl")
        with self._tx() as c:
            c.execute("INSERT INTO relationships(id,tenant_id,subject_entity_id,predicate,object_entity_id,confidence,evidence,"
                      "fact_id,source_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (rid, tenant_id, subject_id, predicate, object_id, confidence, _dumps(evidence), fact_id, source_id, now_iso()))
        return rid

    def relationships_of(self, tenant_id: str, entity_id: str) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM relationships WHERE tenant_id=? AND status='ACTIVE' AND "
                         "(subject_entity_id=? OR object_entity_id=?) ORDER BY rowid", (tenant_id, entity_id, entity_id))

    # ------------------------------------------------------------------ assertions & canonical values
    def add_assertion(self, tenant_id: str, entity_id: str, attribute: str, value: Any, *, source_id: str,
                      resource_id: str | None, fact_id: str | None, confidence: float, evidence: list[str],
                      observed_at: str, assertion_type: str = "FACT") -> str:
        aid = new_id("asr")
        with self._tx() as c:
            c.execute("INSERT INTO assertions(id,tenant_id,entity_id,attribute,value,source_id,resource_id,fact_id,"
                      "assertion_type,confidence,evidence,observed_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (aid, tenant_id, entity_id, attribute, _dumps(value), source_id, resource_id, fact_id,
                       assertion_type, confidence, _dumps(evidence), observed_at, now_iso()))
        return aid

    def assertions_for(self, tenant_id: str, entity_id: str, attribute: str | None = None) -> list[dict[str, Any]]:
        if attribute:
            return self._all("SELECT * FROM assertions WHERE tenant_id=? AND entity_id=? AND attribute=? AND resolution_status='ACTIVE' "
                             "ORDER BY observed_at", (tenant_id, entity_id, attribute))
        return self._all("SELECT * FROM assertions WHERE tenant_id=? AND entity_id=? AND resolution_status='ACTIVE' ORDER BY attribute, observed_at",
                         (tenant_id, entity_id))

    def set_canonical_value(self, tenant_id: str, entity_id: str, attribute: str, value: Any, confidence: float,
                            based_on: list[str], policy_version: str) -> None:
        with self._tx() as c:
            c.execute("INSERT INTO canonical_values(tenant_id,entity_id,attribute,value,confidence,based_on,policy_version,computed_at)"
                      " VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,entity_id,attribute) DO UPDATE SET"
                      " value=excluded.value, confidence=excluded.confidence, based_on=excluded.based_on,"
                      " policy_version=excluded.policy_version, computed_at=excluded.computed_at",
                      (tenant_id, entity_id, attribute, _dumps(value), confidence, _dumps(based_on), policy_version, now_iso()))

    def get_canonical_value(self, tenant_id: str, entity_id: str, attribute: str):
        return self._one("SELECT * FROM canonical_values WHERE tenant_id=? AND entity_id=? AND attribute=?", (tenant_id, entity_id, attribute))

    def canonical_values_for(self, tenant_id: str, entity_id: str) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM canonical_values WHERE tenant_id=? AND entity_id=? ORDER BY attribute", (tenant_id, entity_id))

    # ------------------------------------------------------------------ extractions
    def upsert_extraction(self, tenant_id: str, artifact_id: str, resource_id: str, run_id: str | None, *, kind: str,
                          parser_name: str, parser_version: str, status: str, content: Any, warnings: list[str]) -> str:
        with self._tx() as c:
            row = c.execute("SELECT id FROM extractions WHERE artifact_id=? AND parser_name=? AND parser_version=? AND tenant_id=?",
                            (artifact_id, parser_name, parser_version, tenant_id)).fetchone()
            if row:
                c.execute("UPDATE extractions SET status=?, content=?, warnings=?, run_id=?, kind=? WHERE id=?",
                          (status, _dumps(content), _dumps(warnings), run_id, kind, row["id"]))
                return row["id"]
            eid = new_id("ext")
            c.execute("INSERT INTO extractions(id,tenant_id,artifact_id,resource_id,run_id,kind,parser_name,parser_version,status,content,warnings,created_at)"
                      " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (eid, tenant_id, artifact_id, resource_id, run_id, kind, parser_name, parser_version,
                                                         status, _dumps(content), _dumps(warnings), now_iso()))
            return eid

    def list_extractions(self, tenant_id: str, artifact_id: str):
        return self._all("SELECT * FROM extractions WHERE tenant_id=? AND artifact_id=? ORDER BY rowid", (tenant_id, artifact_id))

    def get_extraction(self, tenant_id: str, extraction_id: str):
        return self._one("SELECT * FROM extractions WHERE id=? AND tenant_id=?", (extraction_id, tenant_id))
