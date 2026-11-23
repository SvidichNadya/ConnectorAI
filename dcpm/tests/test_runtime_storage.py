import dataclasses
import json
import threading
import time
import unittest

from dcpm.errors import DCPMError
from dcpm.plan.validator import plan_hash
from dcpm.processing.pdf_sandbox import extract_pdf
from dcpm.storage.blobs import BlobStore
from dcpm.storage.db import Store
from tests.harness import Env
from tests.support import Site, TEST_POLICY, make_pdf
import tempfile


def install(env, src, did, ops, strategy="t"):
    plan = {"plan_version": "1.0", "source_id": src["id"], "strategy": strategy, "operations": ops}
    row = env.store.create_plan("t1", src["id"], plan, plan_hash(plan), "test", [], did, "VALIDATED")
    env.store.activate_plan("t1", src["id"], row["id"])
    env.store.set_source_status("t1", src["id"], "READY", ("REGISTERED", "DISCOVERED", "ACTIVE", "PARTIAL", "FAILED", "READY"))
    return env.store.get_plan("t1", row["id"])


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.site = Site()

    def tearDown(self):
        self.site.close()

    def test_xxe_is_not_expanded(self):
        env = Env(self.site)
        self.addCleanup(env.close)
        src = env.source()
        _, did = env.discover(src)
        prow = install(env, src, did, [{"id": "s", "type": "sitemap.collect", "inputs": {"url": self.site.base + "/xxe.xml"}}])
        run = env.run_plan(src, prow)
        self.assertEqual(run["status"], "FAILED")
        self.assertEqual(env.store.get_tasks("t1", run["id"])[0]["error"]["code"], "PARSE_FAILED")

    def test_resume_skips_completed_operations(self):
        env = Env(self.site)
        self.addCleanup(env.close)
        src = env.source()
        _, did = env.discover(src)
        prow = install(env, src, did, [{"id": "one", "type": "http.fetch", "inputs": {"url": self.site.base + "/a"}},
                                       {"id": "two", "type": "http.fetch", "inputs": {"url": self.site.base + "/b"}}])
        run = env.store.create_run("t1", src["id"], prow, "INITIAL", {})
        env.store.upsert_task("t1", run["id"], "one", "http.fetch", "COMPLETED", output={"outputs": {"response": {}}, "partial": False}, finished=True)
        env.store.update_run("t1", run["id"], status="INTERRUPTED")
        env.mgr.resume("t1", run["id"])
        env.mgr.wait(run["id"])
        done = env.store.get_run("t1", run["id"])
        self.assertEqual(done["status"], "COMPLETED")
        self.assertEqual(self.site.count("/a"), 0)     # not redone
        self.assertEqual(self.site.count("/b"), 1)

    def test_recover_marks_orphaned_runs_interrupted(self):
        env = Env(self.site)
        self.addCleanup(env.close)
        src = env.source()
        _, did = env.discover(src)
        prow = install(env, src, did, [{"id": "one", "type": "http.fetch", "inputs": {"url": self.site.base + "/a"}}])
        run = env.store.create_run("t1", src["id"], prow, "INITIAL", {})
        env.store.claim_run("t1", run["id"], ("PENDING",))
        env.store.set_source_status("t1", src["id"], "INITIAL_ACQUISITION")
        self.assertEqual(env.mgr.recover(), 1)
        self.assertEqual(env.store.get_run("t1", run["id"])["status"], "INTERRUPTED")
        self.assertEqual(env.store.get_source("t1", src["id"])["status"], "DEGRADED")

    def test_cancel_and_single_active_run(self):
        pol = dataclasses.replace(TEST_POLICY, min_request_interval_s=0.4)
        env = Env(self.site, policy=pol)
        self.addCleanup(env.close)
        src = env.source()
        _, did = env.discover(src)
        prow = install(env, src, did, [{"id": "c", "type": "crawl.recursive", "inputs": {"seeds": [self.site.base + "/"], "max_depth": 3, "max_resources": 40}}])
        run = env.mgr.start("t1", env.store.get_source("t1", src["id"]), prow)
        with self.assertRaises(DCPMError) as c:      # second concurrent run refused
            env.mgr.start("t1", env.store.get_source("t1", src["id"]), prow)
        self.assertEqual(c.exception.code, "CONFLICT")
        time.sleep(0.6)
        t0 = time.time()
        env.mgr.cancel("t1", run["id"])
        env.mgr.wait(run["id"], 15)
        self.assertLess(time.time() - t0, 5)
        self.assertEqual(env.store.get_run("t1", run["id"])["status"], "CANCELLED")

    def test_pdf_sandbox(self):
        self.assertIn("Hello", extract_pdf(make_pdf("Hello"), TEST_POLICY)["pages"][0]["text"])
        with self.assertRaises(DCPMError) as c:
            extract_pdf(b"<html>not a pdf</html>", TEST_POLICY)
        self.assertEqual(c.exception.code, "UNSUPPORTED_FORMAT")
        try:
            extract_pdf(b"%PDF-1.4\n" + b"garbage" * 100, TEST_POLICY)   # must not crash the caller
        except DCPMError as e:
            self.assertIn(e.code, ("PARSE_FAILED", "UNSUPPORTED_FORMAT"))
        tiny = dataclasses.replace(TEST_POLICY, pdf_memory_bytes=40 * 1024 * 1024)  # memory cap really applies
        with self.assertRaises(DCPMError) as c:
            extract_pdf(make_pdf("x"), tiny)
        self.assertEqual(c.exception.code, "PARSE_FAILED")

    def test_extraction_handles_mislabelled_content(self):
        env = Env(self.site)
        self.addCleanup(env.close)
        self.site.routes["/lying.pdf"] = lambda h, s: (200, {"Content-Type": "application/pdf"}, b"<html><body><p>I am html</p></body></html>")
        self.site.routes["/data.csv"] = lambda h, s: (200, {"Content-Type": "text/csv"}, b"a;b\n1;2\n3;4\n")
        self.site.routes["/data.json"] = lambda h, s: (200, {"Content-Type": "application/json"}, b'[{"x":1},{"x":2}]')
        self.site.routes["/blob.bin"] = lambda h, s: (200, {"Content-Type": "application/octet-stream"}, b"\x00\x01\x02" * 50)
        src = env.source()
        _, did = env.discover(src)
        urls = [self.site.base + p for p in ("/lying.pdf", "/data.csv", "/data.json", "/blob.bin")]
        prow = install(env, src, did, [{"id": "f", "type": "http.fetch_many", "inputs": {"urls": urls}},
                                       {"id": "e", "type": "content.extract", "depends_on": ["f"], "inputs": {"responses": "$f.responses"}}])
        run = env.run_plan(src, prow)
        self.assertEqual(run["status"], "COMPLETED_WITH_WARNINGS", run["statistics"]["limitations"])
        res = {r["canonical_uri"].rsplit("/", 1)[1]: r for r in env.store.list_resources("t1", src["id"], limit=50)[0]}
        ex = {k: env.store.list_extractions("t1", env.store.list_artifacts("t1", v["id"])[0]["id"])[0] for k, v in res.items() if k in ("lying.pdf", "data.csv", "data.json", "blob.bin")}
        self.assertEqual(ex["lying.pdf"]["kind"], "html")
        self.assertTrue(any("differs" in w for w in ex["lying.pdf"]["warnings"]))
        self.assertEqual(ex["data.csv"]["content"]["rows"], [["1", "2"], ["3", "4"]])
        self.assertEqual(ex["data.json"]["content"]["count"], 2)
        self.assertEqual(ex["blob.bin"]["status"], "UNSUPPORTED")


class StorageTests(unittest.TestCase):
    def test_tenant_isolation_in_store(self):
        s = Store()
        a = s.create_source("tA", "n", "https://e.org/", {"allowed_domains": ["e.org"]}, {})
        self.assertIsNone(s.get_source("tB", a["id"]))
        self.assertEqual(s.list_sources("tB")[0], [])
        self.assertFalse(s.disable_source("tB", a["id"]))
        self.assertEqual(s.get_source("tA", a["id"])["status"], "REGISTERED")

    def test_blob_store_safety(self):
        with tempfile.TemporaryDirectory() as d:
            b = BlobStore(d)
            sha = b.put("t1", b"hello")
            self.assertEqual(b.put("t1", b"hello"), sha)
            self.assertEqual(b.get("t1", sha), b"hello")
            with self.assertRaises(DCPMError):
                b.get("t2", sha)                       # other tenants cannot read it
            for bad in [("../x", sha), ("t1", "../../etc/passwd"), ("t1/..", sha), ("", sha), ("t1", sha[:-1])]:
                with self.assertRaises(DCPMError, msg=str(bad)):
                    b.get(*bad)
            with self.assertRaises(DCPMError):
                b.put("../evil", b"x")
            path = b._path("t1", sha)
            path.write_bytes(b"tampered")
            with self.assertRaises(DCPMError) as c:
                b.get("t1", sha)
            self.assertIn("integrity", c.exception.message)

    def test_audit_chain(self):
        s = Store()
        s.audit("t", "a", "x", details={"api_key": "sk-abcdefghijklmnopqrstuvwxyz"})
        s.audit("t", "a", "y")
        self.assertTrue(s.verify_audit_chain())
        import sqlite3
        with self.assertRaises(sqlite3.DatabaseError):
            s._conn.execute("DELETE FROM audit_log")
        with self.assertRaises(sqlite3.DatabaseError):
            s._conn.execute("UPDATE audit_log SET action='z'")
        self.assertNotIn("abcdefghijklmnop", json.dumps(s._all("SELECT details FROM audit_log")))

    def test_idempotency(self):
        s = Store()
        self.assertIsNone(s.idempotency_begin("t", "k", "h1"))
        with self.assertRaises(DCPMError) as c:
            s.idempotency_begin("t", "k", "h1")        # still in progress
        self.assertEqual(c.exception.code, "CONFLICT")
        s.idempotency_finish("t", "k", {"ok": 1})
        self.assertEqual(s.idempotency_begin("t", "k", "h1"), {"ok": 1})
        with self.assertRaises(DCPMError) as c:
            s.idempotency_begin("t", "k", "h2")
        self.assertEqual(c.exception.code, "IDEMPOTENCY_KEY_REUSED")
        self.assertIsNone(s.idempotency_begin("other", "k", "h2"))   # keys are per tenant


if __name__ == "__main__":
    unittest.main()
