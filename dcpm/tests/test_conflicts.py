import unittest

from dcpm.semantic.conflicts import compute_canonical, recompute_and_store
from dcpm.storage.db import Store


def A(value, source_id, confidence=0.8, observed_at="2024-01-01T00:00:00+00:00", assertion_type="FACT", aid="a0"):
    return {"id": aid, "value": value, "source_id": source_id, "confidence": confidence,
           "observed_at": observed_at, "assertion_type": assertion_type}


class ComputeCanonicalTests(unittest.TestCase):
    def test_no_assertions(self):
        self.assertIsNone(compute_canonical([]))

    def test_single_assertion(self):
        r = compute_canonical([A("Example Ltd.", "src_1", aid="a1")])
        self.assertEqual((r.value, r.corroboration, r.contested), ("Example Ltd.", 1, False))

    def test_corroboration_by_distinct_source_not_by_count(self):
        """Research doc example: 20 sites re-publish one press release - must not out-vote a single
        better-corroborated independent source."""
        many_from_one_source = [A("Example Group", "src_press_release", aid=f"a{i}") for i in range(20)]
        two_independent = [A("Example Ltd.", "src_registry", aid="b1"), A("Example Ltd.", "src_news", aid="b2")]
        r = compute_canonical(many_from_one_source + two_independent)
        self.assertEqual(r.value, "Example Ltd.")
        self.assertEqual(r.corroboration, 2)
        self.assertTrue(r.contested)

    def test_recency_breaks_ties_between_equally_corroborated_values(self):
        rows = [A("v1", "s1", observed_at="2022-01-01T00:00:00+00:00", aid="a1"),
               A("v2", "s2", observed_at="2024-01-01T00:00:00+00:00", aid="a2")]
        r = compute_canonical(rows)
        self.assertEqual(r.value, "v2")

    def test_plan_and_forecast_do_not_outvote_facts(self):
        rows = [A("will reach 10M", "s1", assertion_type="FORECAST", aid="a1"),
               A("will reach 10M", "s2", assertion_type="FORECAST", aid="a2"),
               A("reached 8M", "s3", assertion_type="FACT", aid="a3")]
        r = compute_canonical(rows)
        self.assertEqual(r.value, "reached 8M")

    def test_only_forecasts_present_still_returns_something(self):
        rows = [A("maybe 10M", "s1", assertion_type="FORECAST", aid="a1")]
        r = compute_canonical(rows)
        self.assertEqual(r.value, "maybe 10M")

    def test_based_on_lists_exact_contributing_ids(self):
        rows = [A("Example Ltd.", "s1", aid="x1"), A("Example Ltd.", "s2", aid="x2"), A("Other", "s3", aid="x3")]
        r = compute_canonical(rows)
        self.assertEqual(sorted(r.based_on), ["x1", "x2"])

    def test_confidence_reflects_share_of_total_sources(self):
        rows = [A("A", "s1", aid="a"), A("A", "s2", aid="b"), A("B", "s3", aid="c")]
        r = compute_canonical(rows)
        self.assertAlmostEqual(r.confidence, 2 / 3, places=3)

    def test_non_contested_when_only_one_distinct_value(self):
        rows = [A("A", "s1", aid="a"), A("A", "s2", aid="b"), A("A", "s3", aid="c")]
        r = compute_canonical(rows)
        self.assertFalse(r.contested)


class RecomputeAndStoreTests(unittest.TestCase):
    def test_persists_and_is_reversible_by_recompute(self):
        store = Store()
        dom = store.create_domain("t1", "ecom", "E", "d", "test")
        ent = store.create_entity("t1", dom["id"], "ORGANIZATION", "Example Ltd.", "example ltd", 0.9)
        store.add_assertion("t1", ent["id"], "company_name", "Example Group", source_id="src_pr",
                            resource_id=None, fact_id=None, confidence=0.6, evidence=["x"], observed_at="2024-01-01T00:00:00+00:00")
        store.add_assertion("t1", ent["id"], "company_name", "Example Ltd.", source_id="src_registry",
                            resource_id=None, fact_id=None, confidence=0.9, evidence=["y"], observed_at="2024-02-01T00:00:00+00:00")
        r1 = recompute_and_store(store, "t1", ent["id"], "company_name")
        self.assertEqual(r1.value, "Example Ltd.")
        cv = store.get_canonical_value("t1", ent["id"], "company_name")
        self.assertEqual(cv["value"], "Example Ltd.")
        # a second independent source confirms "Example Group" -> canonical view can shift, but nothing
        # was deleted: both original assertions are still there to recompute from.
        store.add_assertion("t1", ent["id"], "company_name", "Example Group", source_id="src_other_registry",
                            resource_id=None, fact_id=None, confidence=0.9, evidence=["z"], observed_at="2024-03-01T00:00:00+00:00")
        r2 = recompute_and_store(store, "t1", ent["id"], "company_name")
        self.assertEqual(r2.value, "Example Group")
        self.assertEqual(len(store.assertions_for("t1", ent["id"], "company_name")), 3)   # nothing deleted

    def test_tenant_isolation(self):
        store = Store()
        self.assertEqual(recompute_and_store(store, "tB", "ent_nonexistent", "x"), None)


if __name__ == "__main__":
    unittest.main()
