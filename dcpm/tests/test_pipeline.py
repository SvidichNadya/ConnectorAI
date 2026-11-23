import json
import unittest

from dcpm.errors import DCPMError
from tests.harness import Env
from tests.support import Site, TEST_POLICY, html


class PipelineBase(unittest.TestCase):
    def setUp(self):
        self.site = Site()
        self.env = Env(self.site)

    def tearDown(self):
        self.env.close()
        self.site.close()

    def resources(self, src):
        rows, _ = self.env.store.list_resources("t1", src["id"], limit=500)
        return {r["canonical_uri"].replace(self.site.base, ""): r for r in rows}


class DiscoveryTests(PipelineBase):
    def test_report_has_verified_capabilities(self):
        rep, _ = self.env.discover(self.env.source())
        caps = {c["name"]: c for c in rep["capabilities"]}
        self.assertEqual(rep["status"], "COMPLETED")
        self.assertEqual(caps["http_html"]["status"], "VERIFIED")
        self.assertEqual(caps["sitemap"]["status"], "VERIFIED")
        self.assertEqual(caps["openapi"]["status"], "VERIFIED")
        self.assertEqual(caps["robots_txt"]["status"], "VERIFIED")
        self.assertEqual(rep["recommended_strategy"], "sitemap_then_crawl")
        self.assertIn("/items", rep["observations"]["openapi"]["get_paths"])
        self.assertNotIn("/items/{id}", rep["observations"]["openapi"]["get_paths"])  # parameterised path skipped
        self.assertNotIn("/other", rep["observations"]["openapi"]["get_paths"])        # POST-only skipped

    def test_unreachable_and_auth_and_blocked(self):
        s = self.env.source(locator=self.site.base + "/auth")
        rep, _ = self.env.discover(s)
        self.assertEqual(rep["status"], "NEEDS_AUTH")
        self.assertTrue(rep["authentication"]["required"])
        s2 = self.env.source(locator="http://169.254.169.254/")
        s2["scope"]["allowed_domains"] = ["169.254.169.254"]
        rep, _ = self.env.discover(s2)
        self.assertEqual(rep["status"], "BLOCKED")
        self.assertEqual(rep["error"]["code"], "SSRF_BLOCKED")

    def test_json_root_detects_pagination(self):
        rep, _ = self.env.discover(self.env.source(locator=self.site.base + "/api/items"))
        self.assertEqual(rep["recommended_strategy"], "rest_json")
        self.assertEqual(rep["pagination"]["type"], "link_header")


class RunTests(PipelineBase):
    def test_full_crawl_via_sitemap(self):
        src = self.env.source()
        rep, plan, run = self.env.full(src)
        self.assertEqual(plan["generated_by"], "rules")
        self.assertIn(run["status"], ("COMPLETED", "COMPLETED_WITH_WARNINGS"), run.get("statistics"))
        res = self.resources(src)
        for p in ("/a", "/b", "/c"):
            self.assertEqual(res[p]["status"], "FETCHED", p)
        self.assertNotIn("http://evil.example/x", [r["canonical_uri"] for r in res.values() if r["status"] == "FETCHED"])
        self.assertEqual(self.env.store.get_source("t1", src["id"])["status"], "ACTIVE")

    def test_recursive_crawl_semantics(self):
        """Cycles, duplicates, scope, robots, attachments, dead links, provenance."""
        src = self.env.source()
        rep, did = self.env.discover(src)
        plan = {"plan_version": "1.0", "source_id": src["id"], "strategy": "t", "operations": [
            {"id": "crawl", "type": "crawl.recursive", "inputs": {"seeds": [self.site.base + "/"], "max_depth": 3, "max_resources": 50}},
            {"id": "extract", "type": "content.extract", "depends_on": ["crawl"], "inputs": {"responses": "$crawl.responses"}}]}
        from dcpm.plan.validator import plan_hash
        row = self.env.store.create_plan("t1", src["id"], plan, plan_hash(plan), "test", [], did, "VALIDATED")
        self.env.store.activate_plan("t1", src["id"], row["id"])
        self.env.store.set_source_status("t1", src["id"], "READY")
        run = self.env.run_plan(src, self.env.store.get_plan("t1", row["id"]))
        res = self.resources(src)
        self.assertEqual(run["status"], "COMPLETED_WITH_WARNINGS", run["statistics"]["limitations"])
        self.assertEqual(self.site.count("/dup"), 1)                      # utm param stripped + sorted query => one fetch
        self.assertEqual(self.site.count("/loop"), 1)                     # cycle terminated
        self.assertEqual(self.site.count("/a"), 1)
        self.assertEqual(res["/missing"]["status"], "UNAVAILABLE")        # 404 != deleted
        self.assertEqual(res["/private/secret"]["status"], "BLOCKED")     # robots
        self.assertEqual(res["/private/secret"]["status_reason"], "ROBOTS_DISALLOWED")
        self.assertEqual(self.site.count("/private/secret"), 0)           # never requested
        self.assertEqual(res["/doc.pdf"]["status"], "FETCHED")
        oos = [r for r in res.values() if r["status_reason"] == "OUT_OF_SCOPE"]
        self.assertEqual(len(oos), 1)
        self.assertFalse(any("mailto" in u or "javascript" in u for u in res))
        # graph keeps every discovery path (home -> a, and loop -> home etc.)
        kids = {c["canonical_uri"].replace(self.site.base, ""): c["rel_type"] for c in self.env.store.resource_children("t1", res["/"]["id"])}
        self.assertEqual(kids["/doc.pdf"], "ATTACHMENT_OF")
        self.assertEqual(kids["/a"], "LINKS_TO")
        # provenance + raw preserved + extraction
        art = self.env.store.list_artifacts("t1", res["/doc.pdf"]["id"])[0]
        self.assertEqual(self.env.blobs.get("t1", art["sha256"])[:5], b"%PDF-")
        ex = self.env.store.list_extractions("t1", art["id"])[0]
        self.assertEqual(ex["status"], "OK")
        self.assertIn("Hello PDF world", ex["content"]["pages"][0]["text"])
        home_art = self.env.store.list_artifacts("t1", res["/"]["id"])[0]
        self.assertEqual(self.env.store.list_extractions("t1", home_art["id"])[0]["content"]["title"], "Home")

    def test_budget_makes_run_partial_not_silent(self):
        src = self.env.source()
        rep, did = self.env.discover(src)
        plan = {"plan_version": "1.0", "source_id": src["id"], "strategy": "t", "operations": [
            {"id": "crawl", "type": "crawl.recursive", "inputs": {"seeds": [self.site.base + "/"], "max_depth": 3, "max_resources": 3}}]}
        from dcpm.plan.validator import plan_hash
        row = self.env.store.create_plan("t1", src["id"], plan, plan_hash(plan), "t", [], did, "VALIDATED")
        self.env.store.activate_plan("t1", src["id"], row["id"])
        self.env.store.set_source_status("t1", src["id"], "READY")
        run = self.env.run_plan(src, self.env.store.get_plan("t1", row["id"]))
        self.assertEqual(run["status"], "PARTIAL")
        self.assertEqual(self.env.store.get_source("t1", src["id"])["status"], "PARTIAL")
        self.assertTrue(any("not fetched" in l for l in run["statistics"]["limitations"]))
        self.assertGreater(run["statistics"]["resources_by_status"].get("DISCOVERED", 0), 0)  # unvisited stay DISCOVERED

    def test_rest_pagination_styles(self):
        from dcpm.plan.validator import plan_hash
        src = self.env.source()
        _, did = self.env.discover(src)
        b = self.site.base
        cases = [("link", {"url": b + "/api/items", "pagination": "link_header", "items_path": "items"}, 9),
                 ("auto", {"url": b + "/api/items", "pagination": "auto", "items_path": "items"}, 9),
                 ("cursor", {"url": b + "/api/cursor", "pagination": "cursor", "items_path": "data", "next_path": "meta.next_cursor"}, 3),
                 ("page", {"url": b + "/api/pages", "pagination": "page", "items_path": ""}, 3)]
        for name, inputs, n_items in cases:
            plan = {"plan_version": "1.0", "source_id": src["id"], "strategy": name, "operations": [
                {"id": "api", "type": "rest.paginate", "inputs": inputs},
                {"id": "extract", "type": "content.extract", "depends_on": ["api"], "inputs": {"responses": "$api.responses"}}]}
            row = self.env.store.create_plan("t1", src["id"], plan, plan_hash(plan), "t", [], did, "VALIDATED")
            self.env.store.set_source_status("t1", src["id"], "READY")
            self.env.store.activate_plan("t1", src["id"], row["id"])
            run = self.env.run_plan(src, self.env.store.get_plan("t1", row["id"]))
            msgs = " ".join(run["statistics"]["limitations"])
            self.assertIn(run["status"], ("COMPLETED_WITH_WARNINGS", "COMPLETED"), (name, run["statistics"]))
            self.assertIn(f"{n_items} item(s)", msgs, name)

    def test_rest_loop_and_max_pages_are_flagged(self):
        from dcpm.plan.validator import plan_hash
        src = self.env.source()
        _, did = self.env.discover(src)
        for url, pages, expect in [("/api/loop", 5, "loop"), ("/api/items", 2, "max_pages")]:
            plan = {"plan_version": "1.0", "source_id": src["id"], "strategy": "t", "operations": [
                {"id": "api", "type": "rest.paginate", "inputs": {"url": self.site.base + url, "pagination": "auto", "items_path": "items", "max_pages": pages}}]}
            row = self.env.store.create_plan("t1", src["id"], plan, plan_hash(plan), "t", [], did, "VALIDATED")
            self.env.store.set_source_status("t1", src["id"], "READY")
            self.env.store.activate_plan("t1", src["id"], row["id"])
            run = self.env.run_plan(src, self.env.store.get_plan("t1", row["id"]))
            if expect == "max_pages":
                self.assertEqual(run["status"], "PARTIAL")
            self.assertTrue(any(expect in l for l in run["statistics"]["limitations"]), run["statistics"]["limitations"])

    def test_retry_recovers_and_hard_failure_is_reported(self):
        from dcpm.plan.validator import plan_hash
        src = self.env.source()
        _, did = self.env.discover(src)

        def go(url):
            plan = {"plan_version": "1.0", "source_id": src["id"], "strategy": "t", "operations": [
                {"id": "f", "type": "http.fetch", "inputs": {"url": self.site.base + url}},
                {"id": "g", "type": "html.parse", "depends_on": ["f"], "inputs": {"response": "$f.response"}}]}
            row = self.env.store.create_plan("t1", src["id"], plan, plan_hash(plan), "t", [], did, "VALIDATED")
            self.env.store.set_source_status("t1", src["id"], "READY", ("ACTIVE", "FAILED", "BLOCKED", "PARTIAL", "READY", "REGISTERED", "DISCOVERED"))
            self.env.store.activate_plan("t1", src["id"], row["id"])
            run = self.env.run_plan(src, self.env.store.get_plan("t1", row["id"]))
            return run, self.env.store.get_tasks("t1", run["id"])
        run, _ = go("/flaky")
        self.assertEqual(run["status"], "COMPLETED")                       # 503 then 200
        run, tasks = go("/always503")
        self.assertEqual(run["status"], "FAILED")
        self.assertEqual([t["status"] for t in tasks], ["FAILED", "SKIPPED"])  # dependants never run on missing data
        self.assertEqual(tasks[0]["error"]["code"], "SOURCE_UNAVAILABLE")
        self.assertTrue(tasks[0]["error"]["retryable"])
        run, _ = go("/auth")
        self.assertEqual(run["status"], "BLOCKED")
        run, _ = go("/forbidden")
        self.assertEqual(run["status"], "BLOCKED")

    def test_content_versioning_and_unchanged_detection(self):
        src = self.env.source()
        rep, did = self.env.discover(src)
        from dcpm.plan.validator import plan_hash
        plan = {"plan_version": "1.0", "source_id": src["id"], "strategy": "t", "operations": [
            {"id": "f", "type": "http.fetch", "inputs": {"url": self.site.base + "/changing"}}]}
        row = self.env.store.create_plan("t1", src["id"], plan, plan_hash(plan), "t", [], did, "VALIDATED")
        self.env.store.activate_plan("t1", src["id"], row["id"])
        self.env.store.set_source_status("t1", src["id"], "READY")
        prow = self.env.store.get_plan("t1", row["id"])
        self.env.run_plan(src, prow)
        self.env.run_plan(src, prow)                      # unchanged
        self.site.state["version"] = 2
        self.env.run_plan(src, prow)                      # changed
        rid = self.resources(src)["/changing"]["id"]
        arts = self.env.store.list_artifacts("t1", rid)
        self.assertEqual([a["version"] for a in arts], [1, 2])          # same content did not create a version
        self.assertIn(b"version 1", self.env.blobs.get("t1", arts[0]["sha256"]))  # old raw is preserved
        self.assertEqual(self.env.store.get_resource("t1", rid)["current_artifact_id"], arts[1]["id"])

    def test_failed_refetch_marks_stale_never_gone(self):
        src = self.env.source()
        rep, did = self.env.discover(src)
        from dcpm.plan.validator import plan_hash
        url = self.site.base + "/changing"
        plan = {"plan_version": "1.0", "source_id": src["id"], "strategy": "t", "operations": [{"id": "f", "type": "http.fetch", "inputs": {"url": url}}]}
        row = self.env.store.create_plan("t1", src["id"], plan, plan_hash(plan), "t", [], did, "VALIDATED")
        self.env.store.activate_plan("t1", src["id"], row["id"])
        self.env.store.set_source_status("t1", src["id"], "READY")
        prow = self.env.store.get_plan("t1", row["id"])
        self.env.run_plan(src, prow)
        del self.site.routes["/changing"]
        run = self.env.run_plan(src, prow)
        self.assertEqual(run["status"], "FAILED")
        r = self.resources(src)["/changing"]
        self.assertEqual(r["status"], "STALE")
        self.assertTrue(r["current_artifact_id"])

    def test_tampered_plan_is_refused_at_run_time(self):
        src = self.env.source()
        rep, did = self.env.discover(src)
        plan = self.env.compile_activate(src, rep, did)
        evil = json.loads(json.dumps(plan["plan"]))
        evil["operations"][0]["inputs"]["url"] = "http://169.254.169.254/"
        with self.env.store._tx() as c:
            c.execute("UPDATE plans SET plan=? WHERE id=?", (json.dumps(evil), plan["id"]))
        # start() re-validates and refuses before any run exists
        with self.assertRaises(DCPMError) as c:
            self.env.mgr.start("t1", self.env.store.get_source("t1", src["id"]), self.env.store.get_plan("t1", plan["id"]))
        self.assertEqual(c.exception.code, "PLAN_INVALID")


if __name__ == "__main__":
    unittest.main()
