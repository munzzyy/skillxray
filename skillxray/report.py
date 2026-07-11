"""Render a ScanResult as human text, JSON, or SARIF."""

from __future__ import annotations

import json

from . import __version__
from .finding import Severity, ScanResult

_COLOR = {
    Severity.CRITICAL: "\033[1;37;41m",  # white on red
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_GRADE_COLOR = {"A": "\033[32m", "B": "\033[32m", "C": "\033[33m",
                "D": "\033[33m", "F": "\033[1;31m"}


def render_human(result: ScanResult, color: bool = True) -> str:
    def c(code, s):
        return f"{code}{s}{_RESET}" if color else s

    lines = []
    counts = result.counts()
    total = sum(counts.values())

    lines.append("")
    lines.append(f"  skillxray  {result.root}")
    lines.append(f"  {result.units} unit(s), {result.scanned_files} file(s) scanned")
    lines.append("")

    if not result.findings:
        lines.append(c("\033[32m", "  No findings. Nothing suspicious surfaced."))
    for f in result.findings:
        tag = c(_COLOR[f.severity], f" {f.severity.label.upper():^8} ")
        loc = f.file + (f":{f.line}" if f.line else "")
        lines.append(f"  {tag} {f.title}  [{f.rule_id} · {f.category}]")
        lines.append(f"           {loc}")
        lines.append(f"           {f.detail}")
        if f.snippet:
            lines.append(c("\033[90m", f"           > {f.snippet}"))
        if f.remediation:
            lines.append(c("\033[90m", f"           fix: {f.remediation}"))
        lines.append("")

    # Summary
    parts = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        if counts[sev]:
            parts.append(c(_COLOR[sev], f"{counts[sev]} {sev.label}"))
    summary = "  " + (", ".join(parts) if parts else "0 findings")
    lines.append(summary + f"   ({total} total)")

    gc = _GRADE_COLOR.get(result.grade, "")
    lines.append("")
    lines.append(f"  Security grade: {c(gc, result.grade)}  ({result.grade_score}/100)"
                 f"    Hygiene: {result.hygiene_passed}/{result.hygiene_total}")
    lines.append("")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    payload = {
        "tool": "skillxray",
        "version": __version__,
        "root": result.root,
        "units": result.units,
        "scanned_files": result.scanned_files,
        "grade": result.grade,
        "grade_score": result.grade_score,
        "hygiene": {
            "passed": result.hygiene_passed,
            "total": result.hygiene_total,
            "checks": [
                {"name": n, "ok": ok, "detail": d}
                for n, ok, d in result.hygiene_checks
            ],
        },
        "counts": {s.label: result.counts()[s] for s in Severity},
        "findings": [
            {
                "rule_id": f.rule_id,
                "category": f.category.value,
                "severity": f.severity.label,
                "title": f.title,
                "detail": f.detail,
                "file": f.file,
                "line": f.line,
                "column": f.column,
                "snippet": f.snippet,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
    }
    return json.dumps(payload, indent=2)


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_sarif(result: ScanResult) -> str:
    rule_ids = sorted({f.rule_id for f in result.findings})
    rules = [{"id": rid, "name": rid} for rid in rule_ids]
    sarif_results = []
    for f in result.findings:
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.file or "unknown"},
            }
        }
        if f.line:
            loc["physicalLocation"]["region"] = {
                "startLine": f.line,
                "startColumn": max(1, f.column),
            }
        sarif_results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}: {f.detail}"},
            "properties": {"security-severity": _sec_severity(f.severity),
                           "category": f.category.value},
            "locations": [loc],
        })
    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "skillxray",
                "informationUri": "https://github.com/munzzyy/skillxray",
                "version": __version__,
                "rules": rules,
            }},
            "results": sarif_results,
        }],
    }
    return json.dumps(doc, indent=2)


def _sec_severity(sev: Severity) -> str:
    # GitHub code-scanning numeric band (0.0–10.0).
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }[sev]
