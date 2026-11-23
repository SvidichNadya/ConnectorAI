import unittest

from dcpm.semantic.candidates import spot_candidates


class CandidateTests(unittest.TestCase):
    def test_basic_kinds(self):
        t = ("Mercury Inc. acquired Orbit Systems LLC on 2023-04-01 for $1,250,000.50 (12.5%). "
             "Contact: info@mercury.example or https://mercury.example/about.")
        cs = {c.kind: c.text for c in spot_candidates(t)}
        self.assertEqual(cs["EMAIL"], "info@mercury.example")
        self.assertEqual(cs["URL"], "https://mercury.example/about")
        self.assertEqual(cs["MONEY"], "$1,250,000.50")
        self.assertEqual(cs["PERCENT"], "12.5%")
        self.assertEqual(cs["DATE"], "2023-04-01")
        self.assertIn("Mercury Inc", [c.text for c in spot_candidates(t) if c.kind == "NAME"])

    def test_every_candidate_offset_matches_source_text(self):
        t = "Иванов И.И. работает в ООО «Ромашка» с 2020-01-15. See https://a.example/x?y=1, email a@b.co, 5%."
        for c in spot_candidates(t):
            self.assertEqual(t[c.start:c.end], c.text)
            self.assertIn(c.text, c.context)

    def test_no_overlap_and_deterministic(self):
        t = "Dr. John Smith met Jane Doe. " * 5 + "https://x.example/" + "a" * 300
        a = spot_candidates(t)
        b = spot_candidates(t)
        self.assertEqual([c.to_dict() for c in a], [c.to_dict() for c in b])
        spans = sorted((c.start, c.end) for c in a)
        for (s1, e1), (s2, e2) in zip(spans, spans[1:]):
            self.assertLessEqual(e1, s2)

    def test_empty_and_huge_input_bounded(self):
        self.assertEqual(spot_candidates(""), [])
        big = ("John Smith met Jane Doe on 2024-01-01. " * 2000)
        cs = spot_candidates(big, max_candidates=50)
        self.assertEqual(len(cs), 50)

    def test_stopword_leading_capital_not_treated_as_name_alone(self):
        t = "The Report was filed. This Document mentions Acme Corp."
        names = [c.text for c in spot_candidates(t) if c.kind == "NAME"]
        self.assertIn("Acme Corp", names)
        self.assertNotIn("The Report", names)
        self.assertNotIn("This Document", names)

    def test_ids_are_stable_c0_c1(self):
        cs = spot_candidates("Acme Corp and Beta LLC signed a deal on 2024-05-05.")
        self.assertEqual([c.id for c in cs], [f"c{i}" for i in range(len(cs))])


if __name__ == "__main__":
    unittest.main()
