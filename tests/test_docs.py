"""docs/rules.md drift check: every RULE_ID in the code appears as a heading
in the doc, the doc documents nothing that no longer exists, and every rule
carries the SARIF metadata the Security tab needs."""

import re
import unittest
from pathlib import Path

from skillxray.rules import RULE_METADATA

ROOT = Path(__file__).parent.parent


def _rule_ids_in_code():
    ids = set()
    for py in (ROOT / "skillxray" / "rules").glob("*.py"):
        if py.name in ("__init__.py", "_util.py"):
            continue
        m = re.search(r'^RULE_ID\s*=\s*["\']([^"\']+)["\']', py.read_text(), re.MULTILINE)
        if m:
            ids.add(m.group(1))
    return ids


def _rule_ids_in_doc():
    doc = (ROOT / "docs" / "rules.md").read_text()
    return set(re.findall(r"^##\s+(SX-[A-Z]+)", doc, re.MULTILINE))


class RulesDoc(unittest.TestCase):
    def test_every_rule_is_documented(self):
        undocumented = _rule_ids_in_code() - _rule_ids_in_doc()
        self.assertFalse(undocumented, f"in code but not docs/rules.md: {sorted(undocumented)}")

    def test_doc_has_no_ghost_rules(self):
        ghosts = _rule_ids_in_doc() - _rule_ids_in_code()
        self.assertFalse(ghosts, f"in docs/rules.md but not code: {sorted(ghosts)}")

    def test_doc_is_not_empty(self):
        self.assertGreaterEqual(len(_rule_ids_in_doc()), 5)


class RuleMetadata(unittest.TestCase):
    def test_every_rule_has_sarif_metadata(self):
        self.assertEqual(set(RULE_METADATA), _rule_ids_in_code())
        for rid, meta in RULE_METADATA.items():
            with self.subTest(rule=rid):
                self.assertTrue(meta["name"], rid)
                self.assertGreater(len(meta["description"]), 40, rid)
                self.assertIn(meta["level"], ("error", "warning", "note"), rid)
                self.assertTrue(meta["help_uri"].endswith("#" + rid.lower()), rid)

    def test_every_rule_declares_one_owasp_tag(self):
        for rid, meta in RULE_METADATA.items():
            with self.subTest(rule=rid):
                ast = [t for t in meta["tags"] if re.fullmatch(r"AST\d{2}", t)]
                self.assertEqual(len(ast), 1, f"{rid} tags: {meta['tags']}")

    def test_owasp_tags_are_documented(self):
        doc = (ROOT / "docs" / "rules.md").read_text()
        for rid, meta in RULE_METADATA.items():
            ast = next(t for t in meta["tags"] if re.fullmatch(r"AST\d{2}", t))
            section = re.search(r"^## %s\n(.*?)(?=^## |\Z)" % rid, doc, re.M | re.S)
            with self.subTest(rule=rid):
                self.assertIsNotNone(section, rid)
                self.assertIn(ast, section.group(1),
                              f"{rid} is tagged {ast} in code but its docs section does not say so")
