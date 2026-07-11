"""Detect hidden or deceptive Unicode used to smuggle instructions past a human
reviewer while the model still reads them.

This is a real and well-documented attack surface for prompt-driven tooling:
  - Bidirectional control characters (Trojan Source, CVE-2021-42574) can reorder
    how source or text renders versus how it is parsed.
  - Unicode "tag" characters (U+E0000–U+E007F) encode invisible ASCII — the
    classic way to hide instructions inside otherwise-plain text.
  - Zero-width and other invisible characters break up words to dodge keyword
    scanners, or hide content entirely.

These checks are deterministic and near-zero false positive: legitimate skill
docs almost never contain bidi overrides or tag characters.
"""

from __future__ import annotations

from ..finding import Finding, Category, Severity, line_col, snippet_for
from ..discovery import SkillUnit
from ._util import text_targets

RULE_ID = "SX-UNI"

# name -> (severity, human description)
_INVISIBLE = {
    0x200B: "zero-width space",
    0x200C: "zero-width non-joiner",
    0x200D: "zero-width joiner",
    0x2060: "word joiner",
    0xFEFF: "zero-width no-break space (BOM)",
    0x00AD: "soft hyphen",
    0x180E: "Mongolian vowel separator",
    0x2061: "function application",
    0x2062: "invisible times",
    0x2063: "invisible separator",
    0x2064: "invisible plus",
}
_BIDI = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
}
_SEPARATORS = {
    0x2028: "line separator",
    0x2029: "paragraph separator",
}


def _is_tag_char(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE007F


def check(unit: SkillUnit) -> list:
    findings: list = []
    for t in text_targets(unit):
        text = t.text
        # A BOM at position 0 is benign and common; only flag it mid-file.
        for i, ch in enumerate(text):
            cp = ord(ch)
            if cp == 0xFEFF and i == 0:
                continue
            if _is_tag_char(cp):
                findings.append(_f(
                    t, text, i, Severity.CRITICAL,
                    "Invisible Unicode tag character",
                    f"U+{cp:04X} is a Unicode tag character. These are invisible and "
                    "are the standard way to smuggle hidden ASCII instructions into "
                    "text a model will read but a human will not.",
                    "Remove the tag characters. If you need literal tags, document them explicitly.",
                ))
            elif cp in _BIDI:
                findings.append(_f(
                    t, text, i, Severity.CRITICAL,
                    "Bidirectional control character",
                    f"U+{cp:04X} ({_BIDI[cp]}) can make the rendered text differ from "
                    "what is actually parsed (Trojan Source, CVE-2021-42574).",
                    "Remove bidi overrides unless the file genuinely mixes RTL and LTR script.",
                ))
            elif cp in _SEPARATORS:
                findings.append(_f(
                    t, text, i, Severity.MEDIUM,
                    "Unusual line/paragraph separator",
                    f"U+{cp:04X} ({_SEPARATORS[cp]}) is an uncommon separator that some "
                    "tools render as a newline and others do not — a known way to hide "
                    "a trailing instruction on its own visual line.",
                    "Replace with a normal newline.",
                ))
            elif cp in _INVISIBLE:
                sev = Severity.HIGH if _in_word(text, i) else Severity.MEDIUM
                findings.append(_f(
                    t, text, i, sev,
                    "Invisible character",
                    f"U+{cp:04X} ({_INVISIBLE[cp]}) is invisible. "
                    + ("It sits inside a word, which is a common trick to break up a "
                       "keyword so scanners miss it." if sev == Severity.HIGH else
                       "It carries no visible meaning here."),
                    "Delete the invisible character.",
                ))
    return findings


def _in_word(text: str, i: int) -> bool:
    left = text[i - 1] if i > 0 else ""
    right = text[i + 1] if i + 1 < len(text) else ""
    return left.isalnum() and right.isalnum()


def _f(target, text, i, sev, title, detail, remediation) -> Finding:
    line, col = line_col(text, i)
    return Finding(
        rule_id=RULE_ID,
        category=Category.UNICODE,
        severity=sev,
        title=title,
        detail=detail,
        file=target.relpath,
        line=line,
        column=col,
        snippet=snippet_for(text, i),
        remediation=remediation,
    )
