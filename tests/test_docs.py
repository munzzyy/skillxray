"""docs/rules.md drift check: every RULE_ID in the code appears as a heading
in the doc, and the doc documents nothing that no longer exists."""

import re
import unittest
from pathlib import Path

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
