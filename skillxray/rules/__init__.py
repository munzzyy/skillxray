"""Rule registry. Each rule module exposes `check(unit) -> list[Finding]`."""

from __future__ import annotations

from . import (
    dangerous_commands,
    exfiltration,
    injection,
    permissions,
    quality,
    secrets,
    unicode_smuggling,
)

# Order is cosmetic; findings are sorted by severity at report time.
ALL_RULES = [
    unicode_smuggling.check,
    injection.check,
    dangerous_commands.check,
    exfiltration.check,
    secrets.check,
    permissions.check,
    quality.check,
]


def run_all(unit) -> list:
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(unit))
    return findings
