"""Flag opaque payloads and untrusted fetches in a skill's supply chain.

Four shapes a reviewer cannot read and a pattern scanner cannot see through:

  - a bundled ``.pyc`` with no matching ``.py`` source. Compiled bytecode with
    the source removed is executable content deliberately made unreadable.
  - a download of a GitHub release asset belonging to an account other than the
    skill's own. The URL looks like a first-party fetch and is not one.
  - a password-protected archive. The scanner cannot open it, and neither can
    the person reviewing the skill.
  - a symlink out of the skill. Whatever it points at is not part of the
    skill, and on the machine that installs it, it can point at anything.

Snyk's survey of public skills names the first three as live patterns, so a
clean grade from a scanner that never looks at them is a fail-open.
"""

from __future__ import annotations

import re

from ..finding import Finding, Category, Severity, escape_control_chars
from ..discovery import (MAX_ARCHIVE_BYTES, MAX_ARCHIVE_MEMBERS, MAX_ARCHIVE_TOTAL,
                         MAX_FILE_BYTES, SkillUnit)
from ._util import text_targets

RULE_ID = "SX-SUP"
RULE_NAME = "Opaque or untrusted supply chain"
RULE_DESCRIPTION = (
    "Content a reviewer cannot read: compiled bytecode shipped without its "
    "source, release assets pulled from an unrelated GitHub account, "
    "password-protected archives, and symlinks that point out of the skill."
)
RULE_TAGS = ("security", "supply-chain", "AST01")
RULE_LEVEL = "error"

_I = re.IGNORECASE

_RELEASE_URL = re.compile(
    r"https?://github\.com/([A-Za-z0-9][A-Za-z0-9._-]*)/([A-Za-z0-9._-]+)/releases/download/",
    _I,
)
_GITHUB_OWNER = re.compile(r"github\.com[/:]([A-Za-z0-9][A-Za-z0-9._-]*)", _I)

# Archive tools being handed a password. Each form is tool-specific on purpose:
# a bare `--password` also appears in ordinary docs about logging in.
_ENCRYPTED_CMD = re.compile(
    r"\bunzip\b[^\n]*\s-P\s*\S|"
    r"\b(?:7z|7za|7zr)\b[^\n]*\s-p\S|"
    r"\bzip\b[^\n]*\s(?:-P|--password)\s*\S|"
    r"\bunrar\b[^\n]*\s-p\S|"
    r"\brar\b[^\n]*\s-hp\S",
    _I,
)

_ZIP_LOCAL_HEADER = b"PK\x03\x04"
_PYC_TAG = re.compile(r"\.(?:cpython|pypy)-[0-9]+.*$", _I)

# Frontmatter keys that can name where the skill actually comes from.
_ORIGIN_KEYS = ("repository", "repo", "homepage", "source", "url", "origin", "author")


def check(unit: SkillUnit) -> list:
    findings: list = []
    findings += _orphan_bytecode(unit)
    findings += _encrypted_archives(unit)
    findings += _foreign_release_downloads(unit)
    findings += _escaping_symlinks(unit)
    findings += _archive_notes(unit)
    findings += _truncated_files(unit)
    return findings


def _truncated_files(unit: SkillUnit) -> list:
    # A payload pushed past the read limit with padding is invisible to every
    # other rule, so the truncation itself has to be able to fail a gate.
    return [_mk(
        Severity.MEDIUM, t.relpath,
        "File exceeds the scan size limit",
        f"Only the first {MAX_FILE_BYTES:,} bytes of this file were read; anything "
        "past that point was never scanned. Padding a file past the limit is a way "
        "to hide a payload from a scanner.",
        "Split large files up, or review the rest of this one by hand before trusting it.",
    ) for t in unit.files if t.oversized]


# note code -> (severity, title, what happened, fix)
_ARCHIVE_NOTES = {
    "encrypted": (Severity.HIGH, "Password-protected archive",
                  "These members are encrypted, so their contents cannot be scanned or "
                  "reviewed. An encrypted payload inside a skill has no honest use",
                  "Ship the files unencrypted so they can be read before they are trusted."),
    "too-large": (Severity.MEDIUM, "Archive too large to scan",
                  f"The archive is over the {MAX_ARCHIVE_BYTES:,}-byte limit, so it was "
                  "not opened and nothing inside it was scanned",
                  "Ship the files unpacked, or review the archive by hand."),
    "unreadable": (Severity.MEDIUM, "Archive could not be read",
                   "This is named like a zip bundle but is not a readable zip: it is "
                   "truncated, corrupt, or something else. Nothing inside it was scanned",
                   "Rebuild the bundle, or review it by hand before trusting it."),
    "too-many": (Severity.MEDIUM, "Archive only partly scanned",
                 f"Only the first {MAX_ARCHIVE_MEMBERS:,} entries were read; the rest "
                 "were never scanned",
                 "Review the remaining entries by hand, or ship the files unpacked."),
    "too-much": (Severity.MEDIUM, "Archive only partly scanned",
                 f"Reading stopped at {MAX_ARCHIVE_TOTAL:,} uncompressed bytes, so this "
                 "member and everything after it were not fully scanned",
                 "Review the rest by hand, or ship the files unpacked."),
    "nested": (Severity.MEDIUM, "Nested archive not scanned",
               "An archive inside an archive is not opened, so these were not scanned",
               "Ship nested bundles unpacked so they can be read."),
    "bad-member": (Severity.MEDIUM, "Archive member could not be read",
                   "These members failed to decompress (bad checksum, unsupported "
                   "compression, or truncated data), so they were not scanned",
                   "Rebuild the archive, or review those members by hand."),
}


def _archive_notes(unit: SkillUnit) -> list:
    findings = []
    for t in unit.files:
        by_code: dict = {}
        for code, detail in t.notes:
            by_code.setdefault(code, []).append(detail)
        for code, details in by_code.items():
            sev, title, what, fix = _ARCHIVE_NOTES[code]
            named = [d for d in details if d]
            if named:
                shown = ", ".join(named[:3]) + (f" and {len(named) - 3} more" if len(named) > 3 else "")
                what = f"{what}: {shown}."
            else:
                what += "."
            findings.append(_mk(sev, t.relpath, title, what, fix))
    return findings


def _escaping_symlinks(unit: SkillUnit) -> list:
    findings = []
    for t in unit.files:
        if t.kind != "symlink":
            continue
        link = escape_control_chars(t.link)
        if len(link) > 200:
            link = link[:199] + "..."
        findings.append(_mk(
            Severity.MEDIUM, t.relpath,
            "Symlink points outside the skill",
            f"This file is a symlink to `{link}`, which is outside the skill. "
            "skillxray does not follow it, so whatever it points at was not "
            "scanned, and on the machine that installs the skill it can point "
            "at any file there.",
            "Ship the file itself instead of a link out of the skill.",
        ))
    return findings


def _orphan_bytecode(unit: SkillUnit) -> list:
    sources = set()
    for t in unit.files:
        name = t.path.name
        if name.lower().endswith(".py"):
            sources.add(name[:-3].lower())
    findings = []
    for t in unit.files:
        if not t.path.name.lower().endswith(".pyc"):
            continue
        stem = _PYC_TAG.sub("", t.path.name[:-4])
        if stem.lower() in sources:
            continue
        findings.append(_mk(
            Severity.HIGH, t.relpath,
            "Compiled Python without its source",
            f"{escape_control_chars(t.path.name)} is compiled bytecode and no matching "
            ".py source ships with the skill. Nobody - reviewer or scanner - can read "
            "what it does, and the agent will still import and run it.",
            "Ship the .py source, or drop the bytecode. A skill should be readable end to end.",
        ))
    return findings


def _encrypted_archives(unit: SkillUnit) -> list:
    findings = []
    for t in unit.files:
        # An opened archive reports its encrypted members through its notes.
        if not t.archive and _is_encrypted_zip(t.raw):
            findings.append(_mk(
                Severity.HIGH, t.relpath,
                "Password-protected archive",
                "This archive is encrypted, so its contents cannot be scanned or "
                "reviewed. An encrypted payload inside a skill has no honest use.",
                "Ship the files unencrypted so they can be read before they are trusted.",
            ))
    for t in text_targets(unit):
        for m in _ENCRYPTED_CMD.finditer(t.text):
            findings.append(_mk(
                Severity.HIGH, t.relpath,
                "Extracts a password-protected archive",
                "The skill unpacks an archive with a password, which is how a payload "
                "gets past both a scanner and the person reading the skill.",
                "Remove the encryption. Anything a skill runs should be reviewable.",
                line=t.text.count("\n", 0, m.start()) + 1,
            ))
    return findings


def _is_encrypted_zip(raw: bytes) -> bool:
    # Bit 0 of the local file header's general-purpose flag means the entry is
    # encrypted. Reading the first header is enough: a zip whose first entry is
    # encrypted is an encrypted zip for review purposes.
    if not raw.startswith(_ZIP_LOCAL_HEADER) or len(raw) < 8:
        return False
    flags = int.from_bytes(raw[6:8], "little")
    return bool(flags & 0x1)


def _known_owners(unit: SkillUnit) -> set:
    owners = set()
    fm = unit.frontmatter or {}
    for key in _ORIGIN_KEYS:
        value = fm.get(key)
        if isinstance(value, list):
            value = " ".join(str(v) for v in value)
        if not isinstance(value, str):
            continue
        for m in _GITHUB_OWNER.finditer(value):
            owners.add(m.group(1).lower())
    return owners


def _foreign_release_downloads(unit: SkillUnit) -> list:
    owners = _known_owners(unit)
    findings = []
    seen = set()
    for t in text_targets(unit):
        for m in _RELEASE_URL.finditer(t.text):
            owner = m.group(1).lower()
            if owner in owners:
                continue
            key = (t.relpath, owner, m.group(2).lower())
            if key in seen:
                continue
            seen.add(key)
            line = t.text.count("\n", 0, m.start()) + 1
            if owners:
                findings.append(_mk(
                    Severity.HIGH, t.relpath,
                    "Downloads a release asset from an unrelated account",
                    f"Fetches a GitHub release asset from {owner!r}, which is not an "
                    "account this skill claims as its own. A binary from a third-party "
                    "account is an unreviewed dependency wearing a familiar URL.",
                    "Fetch assets from the skill's own repository, or vendor and review the file.",
                    line=line,
                ))
            else:
                findings.append(_mk(
                    Severity.MEDIUM, t.relpath,
                    "Downloads a release asset from an unattributable account",
                    f"Fetches a GitHub release asset from {owner!r}. The skill declares "
                    "no repository of its own, so there is nothing to check that account "
                    "against.",
                    "Declare the skill's repository in frontmatter, and confirm the asset's owner by hand.",
                    line=line,
                ))
    return findings


def _mk(severity, rel, title, detail, remediation, line: int = 0) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        category=Category.SUPPLY_CHAIN,
        severity=severity,
        title=title,
        detail=detail,
        file=rel,
        line=line,
        column=0,
        snippet="",
        remediation=remediation,
    )
