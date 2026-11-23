"""End-to-end: acquisition -> content.extract -> semantic.process, talking to a REAL local HTTP
server over the OpenAI-chat-completions wire protocol (MockLocalModel), exercising LocalLLMClient's
actual network path exactly as it would run against a real Ollama/llama.cpp server. The server's
answers are generated mechanically from what it is given (it is not a real model), but every byte
travels over a real socket through real validation, so this proves the integration - not just the
pure functions - end to end.
"""
import json
import re
import unittest

from dcpm.plan.validator import plan_hash
from dcpm.semantic.llm import LocalLLMClient, LocalLLMConfig
from tests.harness import Env
from tests.support import MockLocalModel, Site, html


def _block(user: str, label: str):
    m = re.search(r'label="%s">\n(.*?)\n</untrusted_data>' % re.escape(label), user, re.S)
    return json.loads(m.group(1)) if m else None


def smart_responder(req: dict) -> str:
    system = req["messages"][0]["content"]
    user = req["messages"][1]["content"]
    if "judge candidate text spans" in system:
        cands = _block(user, "candidates") or []
        type_map = {"NAME": "ORGANIZATION", "MONEY": "MONEY", "DATE": "DATE", "EMAIL": "CONTACT", "PERCENT": "PERCENTAGE"}
        out_cands = [{"id": c["id"], "entity_type": type_map.get(c["kind"], "OTHER"), "relevance": "DOMAIN_RELEVANT", "confidence": 0.85}
                     for c in cands]
        names = [c for c in cands if c["kind"] == "NAME"]
        moneys = [c for c in cands if c["kind"] == "MONEY"]
        rels = []
        if len(names) >= 2:
            rels.append({"subject_id": names[0]["id"], "predicate": "acquired", "object_id": names[1]["id"],
                        "assertion_type": "FACT", "confidence": 0.9, "evidence": names[0]["context"]})
        if names and moneys:
            rels.append({"subject_id": names[0]["id"], "predicate": "deal value", "object_id": moneys[0]["id"],
                        "assertion_type": "FACT", "confidence": 0.8, "evidence": moneys[0]["context"]})
        return json.dumps({"candidates": out_cands, "relationships": rels})
    if "decide whether a newly mentioned entity" in system:
        mention = _block(user, "mention") or {}
        existing = _block(user, "existing_entities") or []
        hit = next((e for e in existing if e["name"].strip().lower() == mention.get("text", "").strip().lower()), None)
        if hit:
            return json.dumps({"verdict": "AUTO_MERGE", "target_id": hit["id"], "confidence": 0.95, "reasoning": "same name, same context"})
        return json.dumps({"verdict": "KEEP_SEPARATE", "target_id": None, "confidence": 0.6, "reasoning": "no clear match"})
    if "classify a data source into a subject domain" in system:
        sample = _block(user, "sample") or ""
        return json.dumps({"action": "new", "new_domain": {"key": "business_news", "title": "Business News",
                                                            "description": "corporate deals and acquisitions"},
                           "confidence": 0.9, "evidence": [sample[:40]] if sample else []})
    return "{}"


NEWS_TEXT = ("Acme Corp acquired Beta Industries on 2024-03-15 for $5,000,000.00. "
            "Press contact: press@acme.example.")


class SemanticE2ETests(unittest.TestCase):
    def setUp(self):
        self.site = Site()
        self.site.routes["/news"] = lambda h, s: (200, {}, html(f"<p>{NEWS_TEXT}</p>", "Acme-Beta Deal"))
        self.mock = MockLocalModel([smart_responder] * 200)
        self.addCleanup(self.mock.close)
        llm = LocalLLMClient(LocalLLMConfig(model="test-model", base_url=self.mock.base_url, max_retries=0))
        self.env = Env(self.site)
        self.env.mgr.llm = llm
        self.env.compiler.gateway = llm
        self.addCleanup(self.env.close)
        self.addCleanup(self.site.close)

    def install(self, src, did):
        plan = {"plan_version": "1.0", "source_id": src["id"], "strategy": "t", "operations": [
            {"id": "c", "type": "crawl.recursive", "inputs": {"seeds": [self.site.base + "/news"], "max_depth": 0, "max_resources": 5}},
            {"id": "e", "type": "content.extract", "depends_on": ["c"], "inputs": {"responses": "$c.responses"}},
            {"id": "s", "type": "semantic.process", "depends_on": ["e"], "inputs": {"extractions": "$e.extractions"}}]}
        row = self.env.store.create_plan("t1", src["id"], plan, plan_hash(plan), "test", [], did, "VALIDATED")
        self.env.store.set_source_status("t1", src["id"], "READY", ("REGISTERED", "DISCOVERED", "ACTIVE", "PARTIAL", "FAILED", "READY"))
        self.env.store.activate_plan("t1", src["id"], row["id"])
        return self.env.store.get_plan("t1", row["id"])

    def test_full_pipeline_creates_domain_entities_relationship_and_assertion(self):
        src = self.env.source(config={"ai_allowed": True})
        _, did = self.env.discover(src)
        prow = self.install(src, did)
        run = self.env.run_plan(src, prow)
        self.assertIn(run["status"], ("COMPLETED", "COMPLETED_WITH_WARNINGS"), run.get("statistics"))

        domains = self.env.store.list_domains("t1")[0]
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0]["key"], "business_news")

        entities = self.env.store.list_entities("t1", domains[0]["id"])[0]
        names = {e["canonical_name"] for e in entities}
        self.assertIn("Acme Corp", names)
        self.assertIn("Beta Industries", names)
        acme = next(e for e in entities if e["canonical_name"] == "Acme Corp")
        beta = next(e for e in entities if e["canonical_name"] == "Beta Industries")

        rels = self.env.store.relationships_of("t1", acme["id"])
        self.assertEqual(len(rels), 1)
        self.assertEqual((rels[0]["predicate"], rels[0]["object_entity_id"]), ("acquired", beta["id"]))
        self.assertIn(NEWS_TEXT.split(".")[0][:10], rels[0]["evidence"][0])

        assertions = self.env.store.assertions_for("t1", acme["id"])
        self.assertTrue(any(a["attribute"] == "deal_value" for a in assertions))
        cv = self.env.store.get_canonical_value("t1", acme["id"], "deal_value")
        self.assertIsNotNone(cv)
        self.assertIn("5,000,000", cv["value"])

        facts = self.env.store.list_facts("t1", src["id"])[0]
        self.assertTrue(facts)
        self.assertTrue(any(f["relevance_status"] == "DOMAIN_RELEVANT" for f in facts))

    def test_rescans_reuse_the_same_entity_via_auto_merge_not_duplicate(self):
        src = self.env.source(config={"ai_allowed": True})
        _, did = self.env.discover(src)
        prow = self.install(src, did)
        self.env.run_plan(src, prow)
        run2 = self.env.run_plan(src, prow)
        self.assertIn(run2["status"], ("COMPLETED", "COMPLETED_WITH_WARNINGS"))

        domains = self.env.store.list_domains("t1")[0]
        self.assertEqual(len(domains), 1)   # domain classification cached, not recreated
        entities = self.env.store.list_entities("t1", domains[0]["id"])[0]
        acme_entities = [e for e in entities if e["canonical_name"] == "Acme Corp"]
        self.assertEqual(len(acme_entities), 1)   # NOT duplicated across the two runs
        mentions = self.env.store.entity_mentions("t1", acme_entities[0]["id"])
        self.assertEqual(len(mentions), 2)        # but both mentions were recorded

    def test_without_ai_allowed_semantic_still_runs_deterministically(self):
        src = self.env.source(config={"ai_allowed": False})
        _, did = self.env.discover(src)
        prow = self.install(src, did)
        run = self.env.run_plan(src, prow)
        self.assertIn(run["status"], ("COMPLETED", "COMPLETED_WITH_WARNINGS", "PARTIAL"))
        self.assertEqual(len(self.mock.calls), 0)   # the local model was never called
        domains = self.env.store.list_domains("t1")[0]
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0]["created_by"], "system:rules")
        entities = self.env.store.list_entities("t1")[0]
        self.assertTrue(entities)   # rule-based candidate typing still produced something


if __name__ == "__main__":
    unittest.main()
