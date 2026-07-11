"""Shared test helpers."""

from __future__ import annotations

import tempfile
from pathlib import Path

from skillxray.scanner import scan_path
from skillxray.finding import Category


def scan_files(files: dict):
    """Write {relpath: str|bytes} into a temp skill dir and scan it."""
    tmp = tempfile.mkdtemp(prefix="sx-test-")
    root = Path(tmp) / "skill"
    root.mkdir()
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
    return scan_path(root)


def by_cat(result, cat: Category):
    return [f for f in result.findings if f.category == cat]


def titles(result):
    return [f.title for f in result.findings]
