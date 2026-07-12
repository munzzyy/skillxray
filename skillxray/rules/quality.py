"""Hygiene checks. Not security, but a skill that is malformed, undocumented, or
bloated wastes context and is harder to trust. These feed a small hygiene score
shown alongside the security grade, and the notable failures surface as findings.
"""

from __future__ import annotations

import re

from ..finding import Finding, Category, Severity, escape_control_chars
from ..discovery import MAX_FILE_BYTES, SkillUnit

RULE_ID = "SX-QLT"

_LINK = re.compile(r"\]\(([^)]+)\)")           # markdown [text](path)
_LOCAL_REF = re.compile(r"(?:\./|(?<=\s))([\w./-]+\.(?:py|sh|js|md|json|txt))\b")
_B64_LINE = re.compile(r"^[A-Za-z0-9+/]{500,}={0,2}$", re.MULTILINE)


def hygiene_checks(unit: SkillUnit) -> list:
    """Return [(name, ok, detail)] — the score is passed/total of these."""
    checks: list = []
    fm = unit.frontmatter or {}
    has_md = unit.skill_md is not None
    checks.append(("has SKILL.md", has_md,
                   "" if has_md else "no SKILL.md found in this unit"))

    name = fm.get("name")
    ok_name = isinstance(name, str) and bool(name.strip())
    checks.append(("has name", ok_name, "" if ok_name else "frontmatter is missing a name"))

    desc = fm.get("description")
    ok_desc = isinstance(desc, str) and bool(desc.strip())
    checks.append(("has description", ok_desc,
                   "" if ok_desc else "frontmatter is missing a description"))

    if ok_desc:
        n = len(desc)
        ok_len = 20 <= n <= 1024
        checks.append(("description length sane", ok_len,
                       "" if ok_len else f"description is {n} chars (want 20–1024)"))

    if has_md:
        words = len(unit.skill_md.text.split())
        ok_size = words <= 5000
        checks.append(("SKILL.md not bloated", ok_size,
                       "" if ok_size else f"SKILL.md is ~{words} words; large bodies bloat the context window"))

    has_license = any(f.path.name.lower().startswith("license") or
                      f.path.name.lower().startswith("copying") for f in unit.files)
    checks.append(("has license", has_license,
                   "" if has_license else "no LICENSE file in the skill"))

    broken = _broken_refs(unit)
    # A link target is text pulled straight out of the skill's own markdown --
    # just as untrusted as anything else in the file -- so it gets the same
    # control-byte escaping as a snippet before it goes into a finding detail.
    checks.append(("no broken file refs", not broken,
                   "" if not broken else
                   f"references missing files: {', '.join(escape_control_chars(b) for b in broken[:5])}"))
    return checks


def _broken_refs(unit: SkillUnit) -> list:
    if unit.skill_md is None:
        return []
    present = {f.relpath.replace("\\", "/") for f in unit.files}
    present |= {f.path.name for f in unit.files}
    text = unit.skill_md.text
    refs = set()
    for m in _LINK.finditer(text):
        refs.add(m.group(1))
    missing = []
    for r in refs:
        r = r.strip()
        if not r or r.startswith(("http://", "https://", "#", "mailto:")):
            continue
        cand = r.lstrip("./").split("#")[0].replace("\\", "/")
        if not cand:
            continue
        base = cand.split("/")[-1]
        if cand not in present and base not in present:
            missing.append(cand)
    return sorted(missing)


def check(unit: SkillUnit) -> list:
    findings: list = []
    for name, ok, detail in hygiene_checks(unit):
        if ok:
            continue
        # Surface the meaningful ones as findings; keep them LOW/INFO.
        sev = Severity.LOW if name in ("has SKILL.md", "has name", "has description",
                                       "no broken file refs", "SKILL.md not bloated") else Severity.INFO
        findings.append(Finding(
            rule_id=RULE_ID,
            category=Category.QUALITY,
            severity=sev,
            title=f"Hygiene: {name} failed",
            detail=detail or f"check '{name}' did not pass",
            file=unit.skill_md.relpath if unit.skill_md else "",
            line=0,
            column=0,
            snippet="",
            remediation="Fix the skill metadata/layout so it is well-formed and easy to trust.",
        ))
    # Large embedded base64 blobs are a bloat + obfuscation smell.
    if unit.skill_md is not None:
        for m in _B64_LINE.finditer(unit.skill_md.text):
            from ..finding import line_col
            line, col = line_col(unit.skill_md.text, m.start())
            findings.append(Finding(
                rule_id=RULE_ID,
                category=Category.QUALITY,
                severity=Severity.LOW,
                title="Large embedded blob",
                detail="A very long base64-looking line is embedded in SKILL.md. It bloats context and can hide content from a reviewer.",
                file=unit.skill_md.relpath,
                line=line,
                column=col,
                snippet="(long base64 line)",
                remediation="Move large assets to a referenced file instead of inlining them.",
            ))
    # discovery.py caps how much of a file it reads and flags the ones it had
    # to truncate or couldn't decode cleanly, but nothing surfaced that flag
    # anywhere -- a payload sitting past the 2 MB mark was silently unscanned
    # and the report never said so. Make a partial scan visible.
    for t in unit.files:
        if t.oversized:
            findings.append(Finding(
                rule_id=RULE_ID,
                category=Category.QUALITY,
                severity=Severity.LOW,
                title="File exceeds the scan size limit",
                detail=f"Only the first {MAX_FILE_BYTES:,} bytes of this file were read; "
                       "anything past that point was never scanned.",
                file=t.relpath,
                line=0,
                column=0,
                snippet="",
                remediation="Split large files up, or treat an oversized file in a skill as "
                            "worth a manual look -- this scanner couldn't see all of it.",
            ))
        if t.decode_error:
            findings.append(Finding(
                rule_id=RULE_ID,
                category=Category.QUALITY,
                severity=Severity.INFO,
                title="File is not valid UTF-8",
                detail="This file could not be decoded cleanly as UTF-8; invalid bytes were "
                       "replaced before scanning, which can mask or distort its content.",
                file=t.relpath,
                line=0,
                column=0,
                snippet="",
                remediation="Confirm the encoding is intentional for a text file in the skill.",
            ))
    return findings
