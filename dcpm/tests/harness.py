import dataclasses
import tempfile
import threading

from dcpm.compiler.compiler import Compiler
from dcpm.discovery.engine import DiscoveryEngine
from dcpm.runtime.manager import RunManager
from dcpm.security.netguard import SafeFetcher
from dcpm.storage.blobs import BlobStore
from dcpm.storage.db import Store
from tests.support import TEST_POLICY


class Env:
    def __init__(self, site, policy=None, tenant="t1", gateway=None, resolver=None):
        self.tmp = tempfile.TemporaryDirectory()
        self.policy = policy or TEST_POLICY
        self.store = Store()
        self.blobs = BlobStore(self.tmp.name)
        self.mgr = RunManager(self.store, self.blobs, self.policy, resolver=resolver)
        self.engine = DiscoveryEngine(self.policy, SafeFetcher(self.policy, resolver=resolver), sleep=lambda s: None)
        self.compiler = Compiler(self.policy, gateway)
        self.site, self.tenant = site, tenant

    def close(self):
        self.mgr.shutdown()
        self.store.close()
        self.tmp.cleanup()

    def source(self, domains=("127.0.0.1",), locator=None, config=None):
        return self.store.create_source(self.tenant, "s", locator or self.site.base + "/", {"allowed_domains": list(domains)}, config or {})

    def discover(self, src):
        from dcpm.security.urls import Scope
        rep = self.engine.discover(src["locator"], Scope(tuple(src["scope"]["allowed_domains"])))
        did = self.store.create_discovery(self.tenant, src["id"])
        self.store.finish_discovery(self.tenant, did, "COMPLETED" if rep["status"] == "COMPLETED" else rep["status"], rep, None)
        return rep, did

    def compile_activate(self, src, rep, did, use_ai=False):
        res = self.compiler.compile(src, rep, use_ai=use_ai)
        row = self.store.create_plan(self.tenant, src["id"], res.plan, res.plan_hash, res.generated_by, res.diagnostics, did, "VALIDATED")
        self.store.activate_plan(self.tenant, src["id"], row["id"])
        self.store.set_source_status(self.tenant, src["id"], "READY", ("REGISTERED", "DISCOVERED"))
        return self.store.get_plan(self.tenant, row["id"])

    def run_plan(self, src, plan_row, timeout=60):
        src = self.store.get_source(self.tenant, src["id"])
        run = self.mgr.start(self.tenant, src, plan_row)
        self.mgr.wait(run["id"], timeout)
        return self.store.get_run(self.tenant, run["id"])

    def full(self, src):
        rep, did = self.discover(src)
        plan = self.compile_activate(src, rep, did)
        return rep, plan, self.run_plan(src, plan)
