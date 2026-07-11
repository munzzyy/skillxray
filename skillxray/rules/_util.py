"""Shared helpers for rule modules."""

from __future__ import annotations

import re
from typing import Iterable, Iterator

from ..discovery import ScanTarget, SkillUnit
from ..finding import Finding, Category, Severity, line_col, snippet_for


def text_targets(unit: SkillUnit, kinds: Iterable[str] | None = None) -> Iterator[ScanTarget]:
    kset = set(kinds) if kinds else None
    for t in unit.files:
        if not t.is_text:
            continue
        if kset is not None and t.kind not in kset:
            continue
        yield t


def finding_at(
    target: ScanTarget,
    index: int,
    *,
    rule_id: str,
    category: Category,
    severity: Severity,
    title: str,
    detail: str,
    remediation: str = "",
) -> Finding:
    line, col = line_col(target.text, index)
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        detail=detail,
        file=target.relpath,
        line=line,
        column=col,
        snippet=snippet_for(target.text, index),
        remediation=remediation,
    )


def iter_matches(pattern: re.Pattern, text: str) -> Iterator[re.Match]:
    return pattern.finditer(text)


# Fenced code blocks in markdown, so command rules can look at examples too.
_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)


def code_blocks(text: str) -> Iterator[tuple[int, str]]:
    """Yield (start_index, block_text) for each fenced block."""
    for m in _FENCE.finditer(text):
        yield m.start(1), m.group(1)
