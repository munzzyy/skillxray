"""Detect hardcoded credentials shipped inside a skill. A leaked key is both a
security problem for whoever published it and a strong smell that the skill was
not written carefully. Patterns are specific, high-precision formats so false
positives stay rare.
"""

from __future__ import annotations

from .. import secret_shapes
from ..finding import Finding, Category, Severity, line_col
from ..discovery import SkillUnit
from ._util import text_targets

RULE_ID = "SX-SEC"
RULE_NAME = "Hardcoded secrets"
RULE_DESCRIPTION = (
    "Credentials committed into the skill: cloud keys, provider API keys, "
    "tokens, and private key blocks. Matched values are redacted in the report."
)
RULE_TAGS = ("security", "AST04")
RULE_LEVEL = "error"

_PATTERNS = [(rx, Severity.parse(sev), label) for rx, sev, label in secret_shapes.PATTERNS]


def check(unit: SkillUnit) -> list:
    findings: list = []
    for t in text_targets(unit):
        text = t.text
        for rx, sev, label in _PATTERNS:
            for m in rx.finditer(text):
                findings.append(_mk(t, text, m.start(), sev,
                    f"Hardcoded {label}",
                    f"A {label} appears to be committed into the skill.",
                    "Remove the credential and rotate it - anything pushed to git is compromised. Load secrets from the environment at runtime."))
        for rx in (secret_shapes.GENERIC, secret_shapes.GENERIC_UNQUOTED):
            for m in rx.finditer(text):
                if not secret_shapes.looks_real(m.group(2).strip()):
                    continue
                findings.append(_mk(t, text, m.start(), Severity.LOW,
                    "Possible hardcoded secret",
                    f"A {m.group(1)} is assigned a literal value. If this is a real credential, it is leaked.",
                    "Load secrets from the environment, not from a literal in the skill."))
    return findings


def _mk(t, text, i, sev, title, detail, remediation) -> Finding:
    line, col = line_col(text, i)
    return Finding(
        rule_id=RULE_ID,
        category=Category.SECRET,
        severity=sev,
        title=title,
        detail=detail,
        file=t.relpath,
        line=line,
        column=col,
        snippet=secret_shapes.REDACTED,
        remediation=remediation,
    )
