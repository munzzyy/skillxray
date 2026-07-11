"""Labeled-corpus gate. Every malicious fixture must be caught (recall) and every
benign fixture must stay clean (precision). These are the floors CI enforces — a
rule change that starts missing real attacks or flagging safe skills fails here.
"""

import unittest
from pathlib import Path

from skillxray.scanner import scan_path
from skillxray.finding import Severity, SECURITY_CATEGORIES

CORPUS = Path(__file__).parent / "corpus"


def _security_worst(result):
    sev = [f.severity for f in result.findings if f.category in SECURITY_CATEGORIES]
    return max(sev) if sev else None


class MaliciousRecall(unittest.TestCase):
    def test_every_malicious_skill_is_flagged(self):
        roots = sorted((CORPUS / "malicious").iterdir())
        self.assertTrue(roots, "no malicious fixtures found")
        for root in roots:
            if not root.is_dir():
                continue
            with self.subTest(skill=root.name):
                r = scan_path(root)
                worst = _security_worst(r)
                self.assertIsNotNone(worst, f"{root.name}: nothing flagged")
                self.assertGreaterEqual(
                    worst, Severity.HIGH,
                    f"{root.name}: worst finding {worst} < HIGH")
                self.assertIn(r.grade, ("D", "F"),
                              f"{root.name}: grade {r.grade} too lenient")


class BenignPrecision(unittest.TestCase):
    def test_every_benign_skill_is_clean(self):
        roots = sorted((CORPUS / "benign").iterdir())
        self.assertTrue(roots, "no benign fixtures found")
        for root in roots:
            if not root.is_dir():
                continue
            with self.subTest(skill=root.name):
                r = scan_path(root)
                loud = [f for f in r.findings
                        if f.category in SECURITY_CATEGORIES
                        and f.severity >= Severity.HIGH]
                self.assertEqual(loud, [], f"{root.name}: false positives {[f.title for f in loud]}")
                self.assertIn(r.grade, ("A", "B"),
                              f"{root.name}: grade {r.grade} — unexpected penalty")


if __name__ == "__main__":
    unittest.main()
