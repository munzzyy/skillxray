"""Rule registry. Each rule module exposes `check(unit) -> list[Finding]` plus the
metadata that describes it: RULE_ID, RULE_NAME, RULE_DESCRIPTION, RULE_TAGS and
RULE_LEVEL. The metadata is what fills in SARIF rule objects, so the GitHub
Security tab shows a description and a link instead of a bare rule id."""

from __future__ import annotations

from . import (
    dangerous_commands,
    exfiltration,
    injection,
    permissions,
    quality,
    secrets,
    supply_chain,
    unicode_smuggling,
)

# Order is cosmetic; findings are sorted by severity at report time.
_MODULES = [
    unicode_smuggling,
    injection,
    dangerous_commands,
    exfiltration,
    secrets,
    permissions,
    supply_chain,
    quality,
]

ALL_RULES = [m.check for m in _MODULES]

DOCS_URL = "https://github.com/munzzyy/skillxray/blob/main/docs/rules.md"

RULE_METADATA = {
    m.RULE_ID: {
        "name": m.RULE_NAME,
        "description": m.RULE_DESCRIPTION,
        "tags": list(m.RULE_TAGS),
        "level": m.RULE_LEVEL,
        "help_uri": f"{DOCS_URL}#{m.RULE_ID.lower()}",
    }
    for m in _MODULES
}


def run_all(unit, enabled: "set[str] | None" = None) -> list:
    """Run every rule against a unit. `enabled`, when given, is the set of
    rule ids allowed to report - everything else is skipped before it ever
    touches the unit's files. `None` means every rule runs, which is the
    default and keeps every existing caller unchanged."""
    findings = []
    for module in _MODULES:
        if enabled is not None and module.RULE_ID not in enabled:
            continue
        findings.extend(module.check(unit))
    return findings
