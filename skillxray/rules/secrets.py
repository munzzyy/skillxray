"""Detect hardcoded credentials shipped inside a skill. A leaked key is both a
security problem for whoever published it and a strong smell that the skill was
not written carefully. Patterns are specific, high-precision formats so false
positives stay rare.
"""

from __future__ import annotations

import re

from ..finding import Finding, Category, Severity, line_col, snippet_for
from ..discovery import SkillUnit
from ._util import text_targets

RULE_ID = "SX-SEC"

# (compiled, severity, label)
_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     Severity.CRITICAL, "private key block"),
    (re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"), Severity.CRITICAL, "Stripe live secret key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.HIGH, "AWS access key id"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.HIGH, "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), Severity.HIGH, "GitHub fine-grained PAT"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), Severity.HIGH, "Anthropic API key"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"), Severity.HIGH, "OpenAI API key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Severity.HIGH, "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH, "Google API key"),
    (re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b"), Severity.HIGH, "GitLab personal access token"),
    (re.compile(r"\bhooks\.slack\.com/services/T[A-Za-z0-9/]{20,}"), Severity.MEDIUM, "Slack incoming webhook"),
]

# Generic assignment of something key-shaped. Kept LOW and placeholder-filtered.
_GENERIC = re.compile(
    r"(?i)\b(api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|password|passwd)\b"
    r"\s*[:=]\s*[\"']([^\"'\n]{12,})[\"']"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:your|my|the|a|some|example|sample|dummy|test|fake|placeholder|change[_-]?me|"
    r"xxx+|\.{3,}|<[^>]+>|\$\{?[a-z_]+\}?|todo|redacted|none|null|abc123|password)")


def check(unit: SkillUnit) -> list:
    findings: list = []
    for t in text_targets(unit):
        text = t.text
        for rx, sev, label in _PATTERNS:
            for m in rx.finditer(text):
                findings.append(_mk(t, text, m.start(), sev,
                    f"Hardcoded {label}",
                    f"A {label} appears to be committed into the skill.",
                    "Remove the credential and rotate it — anything pushed to git is compromised. Load secrets from the environment at runtime."))
        for m in _GENERIC.finditer(text):
            value = m.group(2).strip()
            if _PLACEHOLDER.match(value):
                continue
            if len(set(value)) < 6:  # low-entropy filler like "aaaaaaaaaaaa"
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
        snippet="(redacted)",  # never echo the secret itself back
        remediation=remediation,
    )
