import dataclasses
import json
import tempfile
import time
import unittest

from dcpm.api.app import AppConfig, create_app, hash_key
from dcpm.config import Policy
from tests.support import Site, TEST_POLICY

TOK_A, TOK_B = "tokenAAAAAAAAAAAAAAAAAAAAAA", "tokenBBBBBBBBBBBBBBBBBBBBBB"


class ApiBase(unittest.TestCase):
    policy = TEST_POLICY
    rate = 10_000

    def setUp(self):
        self.site = Site()
        self.tmp = tempfile.TemporaryDirectory()
        cfg = AppConfig(data_dir=self.tmp.name, api_keys={hash_key(TOK_A): "tenantA", hash_key(TOK_B): "tenantB"},
                        policy=self.policy, rate_limit_per_minute=self.rate, max_body_bytes=20_000)
        self.app = create_app(cfg)
        self.c = self.app.test_client()

    def tearDown(self):
        self.app.dcpm.shutdown()
        self.site.close()
        self.tmp.cleanup()

    def call(self, method, path, tok=TOK_A, json_body=None, headers=None, **kw):
        h = {"Authorization": f"Bearer {tok}"} if tok else {}
        h.update(headers or {})
        r = self.c.open(path, method=method, json=json_body, headers=h, **kw)
        return r

    def j(self, method, path, expect=None, **kw):
        r = self.call(method, path, **kw)
        if expect is not None:
            self.assertEqual(r.status_code, expect, r.get_data(as_text=True))
        return r.get_json(silent=True)

    def poll(self, path, done, timeout=60):
        end = time.time() + timeout
        while time.time() < end:
            d = self.j("GET", path, 200)
            if d["status"] in done:
                return d
            time.sleep(0.1)
        self.fail(f"timeout polling {path}: {d}")

    def make_source(self, **extra):
        body = {"name": "Test site", "locator": self.site.base + "/"}
        body.update(extra)
        return self.j("POST", "/api/v1/sources", 201, json_body=body)


class AuthAndValidationTests(ApiBase):
    def test_auth(self):
        self.assertEqual(self.call("GET", "/api/v1/health", tok=None).status_code, 200)
        for tok in (None, "wrong", ""):
            r = self.call("GET", "/api/v1/sources", tok=tok)
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.get_json()["error"]["code"], "UNAUTHENTICATED")
            self.assertTrue(r.get_json()["error"]["correlation_id"].startswith("corr_"))
        self.assertEqual(self.call("GET", "/nothing", tok=None).status_code, 404)

    def test_security_headers(self):
        r = self.call("GET", "/api/v1/sources")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])

    def test_input_validation(self):
        bad = [({"name": "x"}, 422), ({"locator": self.site.base}, 422), ({"name": "x", "locator": "ftp://a.org"}, 422),
               ({"name": "x", "locator": "http://u:p@127.0.0.1/"}, 422), ({"name": "x\x00", "locator": self.site.base}, 422),
               ({"name": "x", "locator": self.site.base, "evil": 1}, 422),
               ({"name": "x", "locator": self.site.base, "scope": {"allowed_domains": ["other.example"]}}, 422),
               ({"name": "x", "locator": self.site.base, "scope": {"allowed_domains": ["com"]}}, 422),
               ({"name": "x", "locator": self.site.base, "config": {"respect_robots": False}}, 403),
               ({"name": "x", "locator": self.site.base, "config": {"unknown": 1}}, 422),
               ({"name": "x", "locator": self.site.base, "config": {"ai_allowed": "yes"}}, 422)]
        for body, code in bad:
            r = self.call("POST", "/api/v1/sources", json_body=body)
            self.assertEqual(r.status_code, code, (body, r.get_data(as_text=True)))
        r = self.call("POST", "/api/v1/sources", data="{oops", content_type="application/json")
        self.assertEqual(r.status_code, 422)
        r = self.call("POST", "/api/v1/sources", data="[1]", content_type="application/json")
        self.assertEqual(r.status_code, 422)
        r = self.call("POST", "/api/v1/sources", data="name=x", content_type="text/plain")
        self.assertEqual(r.status_code, 422)
        r = self.call("POST", "/api/v1/sources", data=b"x" * 30_000, content_type="application/json")
        self.assertEqual(r.status_code, 413)
        self.assertEqual(self.call("GET", "/api/v1/sources?limit=0").status_code, 422)
        self.assertEqual(self.call("GET", "/api/v1/sources?cursor=abc").status_code, 422)
        self.assertEqual(self.call("GET", "/api/v1/sources/not-an-id").status_code, 404)
        self.assertEqual(self.call("GET", "/api/v1/sources/src_00000000000000000000").status_code, 404)

    def test_idempotency(self):
        body = {"name": "I", "locator": self.site.base + "/"}
        h = {"Idempotency-Key": "key-1"}
        a = self.j("POST", "/api/v1/sources", 201, json_body=body, headers=h)
        b = self.j("POST", "/api/v1/sources", 201, json_body=body, headers=h)
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(len(self.j("GET", "/api/v1/sources", 200)["items"]), 1)
        self.j("POST", "/api/v1/sources", 422, json_body={**body, "name": "other"}, headers=h)
        self.assertEqual(self.call("POST", "/api/v1/sources", json_body=body, headers={"Idempotency-Key": "bad key!"}).status_code, 422)
        # a failed request must not "burn" the key
        bad = {"name": "I", "locator": "ftp://x"}
        self.j("POST", "/api/v1/sources", 422, json_body=bad, headers={"Idempotency-Key": "key-2"})
        self.j("POST", "/api/v1/sources", 201, json_body=body, headers={"Idempotency-Key": "key-2"})

    def test_rate_limit(self):
        self.app.dcpm.limiter.capacity = 3.0
        self.app.dcpm.limiter.rate = 0.0001
        codes = [self.call("GET", "/api/v1/sources").status_code for _ in range(5)]
        self.assertEqual(codes[:3], [200] * 3)
        self.assertEqual(codes[3], 429)
        r = self.call("GET", "/api/v1/sources")
        self.assertIn("Retry-After", r.headers)
        self.assertEqual(self.call("GET", "/api/v1/sources", tok=TOK_B).status_code, 200)   # per tenant


class StrictPolicyTests(ApiBase):
    policy = Policy(min_request_interval_s=0)

    def test_ssrf_blocked_at_registration(self):
        for loc in ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://2130706433/"]:
            r = self.call("POST", "/api/v1/sources", json_body={"name": "x", "locator": loc})
            self.assertEqual(r.status_code, 422, loc)
            self.assertEqual(r.get_json()["error"]["code"], "SSRF_BLOCKED", loc)
        r = self.call("POST", "/api/v1/sources", json_body={"name": "x", "locator": "http://example.org:8080/"})
        self.assertEqual(r.get_json()["error"]["code"], "POLICY_BLOCKED")     # port not allowed


class FlowTests(ApiBase):
    def test_full_flow(self):
        src = self.make_source()
        sid = src["id"]
        self.assertEqual(src["status"], "REGISTERED")
        self.assertEqual(src["scope"]["allowed_domains"], ["127.0.0.1"])
        self.j("POST", f"/api/v1/sources/{sid}/runs", 409)                           # no plan yet
        self.j("POST", f"/api/v1/sources/{sid}/plans/compile", 409)                  # discovery first
        op = self.j("POST", f"/api/v1/sources/{sid}/discover", 202)
        self.assertEqual(op["status"], "accepted")
        rep = self.poll(op["status_url"], ("COMPLETED", "FAILED", "BLOCKED", "NEEDS_AUTH"))
        self.assertEqual(rep["status"], "COMPLETED", rep)
        self.assertEqual(rep["report"]["recommended_strategy"], "sitemap_then_crawl")
        self.assertEqual(self.j("GET", f"/api/v1/sources/{sid}", 200)["status"], "DISCOVERED")
        plan = self.j("POST", f"/api/v1/sources/{sid}/plans/compile", 201, json_body={})
        self.assertEqual((plan["status"], plan["generated_by"]), ("VALIDATED", "rules"))
        self.assertEqual(self.j("POST", f"/api/v1/plans/{plan['id']}/validate", 200)["ok"], True)
        self.j("POST", f"/api/v1/plans/{plan['id']}/activate", 200)
        self.assertEqual(self.j("GET", f"/api/v1/sources/{sid}", 200)["status"], "READY")
        op = self.j("POST", f"/api/v1/sources/{sid}/runs", 202, headers={"Idempotency-Key": "run-1"})
        again = self.j("POST", f"/api/v1/sources/{sid}/runs", 202, headers={"Idempotency-Key": "run-1"})
        self.assertEqual(op["operation_id"], again["operation_id"])
        run = self.poll(op["status_url"], ("COMPLETED", "COMPLETED_WITH_WARNINGS", "PARTIAL", "FAILED", "BLOCKED", "CANCELLED"))
        self.assertIn(run["status"], ("COMPLETED", "COMPLETED_WITH_WARNINGS"), run)
        self.assertEqual(self.j("GET", f"/api/v1/sources/{sid}", 200)["status"], "ACTIVE")
        tasks = self.j("GET", f"/api/v1/runs/{run['id']}/tasks", 200)["items"]
        self.assertEqual([t["status"] for t in tasks], ["COMPLETED"] * 3)
        self.assertEqual(self.j("GET", f"/api/v1/runs/{run['id']}/errors", 200)["items"], [])
        # pagination via cursor, no overlap, complete
        seen, cursor = [], "0"
        while cursor:
            d = self.j("GET", f"/api/v1/sources/{sid}/resources?limit=2&cursor={cursor}", 200)
            seen += [r["id"] for r in d["items"]]
            cursor = d["next_cursor"]
        self.assertEqual(len(seen), len(set(seen)))
        self.assertGreaterEqual(len(seen), 3)
        fetched = self.j("GET", f"/api/v1/sources/{sid}/resources?status=FETCHED&limit=100", 200)["items"]
        res = next(r for r in fetched if r["canonical_uri"].endswith("/b"))
        art = self.j("GET", f"/api/v1/resources/{res['id']}/artifacts", 200)["items"][0]
        ex = self.j("GET", f"/api/v1/artifacts/{art['id']}/extractions", 200)["items"][0]
        self.assertEqual(ex["status"], "OK")
        raw = self.call("GET", f"/api/v1/artifacts/{art['id']}/content")
        self.assertEqual(raw.status_code, 200)
        self.assertIn(b"Ignore all previous instructions", raw.data)          # preserved verbatim, never obeyed
        self.assertEqual(raw.headers["Content-Type"], "application/octet-stream")
        self.assertTrue(raw.headers["Content-Disposition"].startswith("attachment"))
        self.assertIn("sandbox", raw.headers["Content-Security-Policy"])
        self.assertEqual(raw.headers["X-DCPM-SHA256"], art["sha256"])
        # a second run on an ACTIVE source is a rescan; unchanged content creates no new versions
        op = self.j("POST", f"/api/v1/sources/{sid}/runs", 202)
        self.poll(op["status_url"], ("COMPLETED", "COMPLETED_WITH_WARNINGS", "PARTIAL", "FAILED"))
        self.assertEqual(len(self.j("GET", f"/api/v1/resources/{res['id']}/artifacts", 200)["items"]), 1)
        self.assertTrue(self.app.dcpm.store.verify_audit_chain())
        self.j("DELETE", f"/api/v1/sources/{sid}", 204)
        self.assertEqual(self.j("GET", f"/api/v1/sources/{sid}", 200)["status"], "DISABLED")
        self.j("POST", f"/api/v1/sources/{sid}/discover", 409)

    def test_tenant_isolation_everywhere(self):
        src = self.make_source()
        sid = src["id"]
        op = self.j("POST", f"/api/v1/sources/{sid}/discover", 202)
        self.poll(op["status_url"], ("COMPLETED",))
        plan = self.j("POST", f"/api/v1/sources/{sid}/plans/compile", 201, json_body={})
        self.j("POST", f"/api/v1/plans/{plan['id']}/activate", 200)
        run = self.j("POST", f"/api/v1/sources/{sid}/runs", 202)
        self.poll(run["status_url"], ("COMPLETED", "COMPLETED_WITH_WARNINGS", "PARTIAL"))
        art = self.app.dcpm.store._one("SELECT id, resource_id FROM artifacts WHERE tenant_id='tenantA' LIMIT 1")
        paths = [("GET", f"/api/v1/sources/{sid}"), ("PATCH", f"/api/v1/sources/{sid}"), ("DELETE", f"/api/v1/sources/{sid}"),
                 ("POST", f"/api/v1/sources/{sid}/discover"), ("POST", f"/api/v1/sources/{sid}/plans/compile"),
                 ("GET", f"/api/v1/sources/{sid}/plans"), ("GET", f"/api/v1/sources/{sid}/runs"), ("POST", f"/api/v1/sources/{sid}/runs"),
                 ("GET", f"/api/v1/sources/{sid}/resources"), ("GET", f"/api/v1/discovery-reports/{op['operation_id']}"),
                 ("GET", f"/api/v1/plans/{plan['id']}"), ("POST", f"/api/v1/plans/{plan['id']}/activate"),
                 ("GET", f"/api/v1/runs/{run['operation_id']}"), ("POST", f"/api/v1/runs/{run['operation_id']}/cancel"),
                 ("GET", f"/api/v1/runs/{run['operation_id']}/tasks"), ("GET", f"/api/v1/resources/{art['resource_id']}"),
                 ("GET", f"/api/v1/resources/{art['resource_id']}/children"), ("GET", f"/api/v1/artifacts/{art['id']}"),
                 ("GET", f"/api/v1/artifacts/{art['id']}/content"), ("GET", f"/api/v1/artifacts/{art['id']}/extractions")]
        for m, p in paths:
            r = self.call(m, p, tok=TOK_B, json_body={} if m in ("POST", "PATCH") else None)
            self.assertEqual(r.status_code, 404, (m, p))
        self.assertEqual(self.j("GET", "/api/v1/sources", 200, tok=TOK_B)["items"], [])
        self.assertEqual(self.call("GET", f"/api/v1/artifacts/{art['id']}/content").status_code, 200)   # owner still can

    def test_plan_tamper_blocked_on_activation(self):
        src = self.make_source()
        sid = src["id"]
        self.poll(self.j("POST", f"/api/v1/sources/{sid}/discover", 202)["status_url"], ("COMPLETED",))
        plan = self.j("POST", f"/api/v1/sources/{sid}/plans/compile", 201, json_body={})
        evil = plan["plan"]
        evil["operations"][0]["inputs"]["url"] = "http://evil.example/x"
        with self.app.dcpm.store._tx() as c:
            c.execute("UPDATE plans SET plan=? WHERE id=?", (json.dumps(evil), plan["id"]))
        r = self.j("POST", f"/api/v1/plans/{plan['id']}/activate", 422)
        self.assertEqual(r["error"]["code"], "PLAN_INVALID")
        self.assertEqual(self.j("GET", f"/api/v1/plans/{plan['id']}", 200)["status"], "REJECTED")
        self.assertIsNone(self.j("GET", f"/api/v1/sources/{sid}", 200)["active_plan_id"])

    def test_discovery_failure_modes(self):
        src = self.j("POST", "/api/v1/sources", 201, json_body={"name": "a", "locator": self.site.base + "/auth"})
        rep = self.poll(self.j("POST", f"/api/v1/sources/{src['id']}/discover", 202)["status_url"], ("COMPLETED", "NEEDS_AUTH", "FAILED", "BLOCKED"))
        self.assertEqual(rep["status"], "NEEDS_AUTH")
        self.assertEqual(self.j("GET", f"/api/v1/sources/{src['id']}", 200)["status"], "NEEDS_AUTH")
        self.j("POST", f"/api/v1/sources/{src['id']}/plans/compile", 409)           # no completed discovery
        tc = self.j("POST", f"/api/v1/sources/{src['id']}/test-connection", 200)
        self.assertEqual(tc["http_status"], 401)

    def test_cancel_and_conflict(self):
        pol = dataclasses.replace(TEST_POLICY, min_request_interval_s=0.4)
        self.app.dcpm.policy = pol
        self.app.dcpm.runs.policy = pol
        src = self.make_source()
        sid = src["id"]
        self.poll(self.j("POST", f"/api/v1/sources/{sid}/discover", 202)["status_url"], ("COMPLETED",))
        plan = self.j("POST", f"/api/v1/sources/{sid}/plans/compile", 201, json_body={})
        self.j("POST", f"/api/v1/plans/{plan['id']}/activate", 200)
        run = self.j("POST", f"/api/v1/sources/{sid}/runs", 202)
        self.j("POST", f"/api/v1/sources/{sid}/runs", 409)
        time.sleep(0.5)
        self.j("POST", f"/api/v1/runs/{run['operation_id']}/cancel", 202)
        done = self.poll(run["status_url"], ("CANCELLED", "COMPLETED", "COMPLETED_WITH_WARNINGS", "PARTIAL", "FAILED"), 20)
        self.assertEqual(done["status"], "CANCELLED")


if __name__ == "__main__":
    unittest.main()
