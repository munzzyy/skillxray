"""Turn findings into a security letter grade.

The score starts at 100 and loses points per security finding by severity. Two
hard caps encode the opinion that matters: any unresolved CRITICAL means "do not
install" (grade F), and any HIGH keeps it out of the top band (at most C). Quality
findings do not affect the security grade.
"""

from __future__ import annotations

from .finding import Severity, SECURITY_CATEGORIES

_WEIGHT = {
    Severity.CRITICAL: 45,
    Severity.HIGH: 15,
    Severity.MEDIUM: 6,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


def grade(findings) -> tuple[str, int]:
    sec = [f for f in findings if f.category in SECURITY_CATEGORIES]
    score = 100
    n_crit = n_high = 0
    for f in sec:
        score -= _WEIGHT.get(f.severity, 0)
        if f.severity == Severity.CRITICAL:
            n_crit += 1
        elif f.severity == Severity.HIGH:
            n_high += 1
    score = max(0, min(100, score))

    if n_crit:
        return "F", score
    if n_high:
        score = min(score, 76)  # keep out of the A/B band
    return _letter(score), score


def _letter(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    return "F"
