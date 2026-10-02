"""Scan orchestration: discover units, run every rule, aggregate, grade."""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .discovery import ArchiveBudget, discover, MAX_FILE_BYTES
from .finding import ScanResult
from .grade import grade
from .rules import run_all
from .rules.quality import hygiene_checks


def scan_paths(paths: list[str | Path], exclude=(), enabled=None,
               follow_links: bool = True) -> ScanResult:
    if not paths:
        return ScanResult(root=".")

    units = []
    seen_roots: set = set()
    read: set = set()
    budget = ArchiveBudget()
    lone = any(_is_lone_file(Path(p)) for p in paths)
    # Named files go last, so one a named folder already holds is read once, as part of it.
    for target in sorted((Path(p) for p in paths), key=_is_lone_file):
        base = target if target.is_dir() else target.parent
        if _is_lone_file(target) and os.path.realpath(target) in read:
            continue
        for unit in discover(target, rel_base=base, exclude=exclude, budget=budget,
                             follow_links=follow_links):
            # pre-commit can hand us several files from one skill; scanning the
            # same unit twice would double every finding.
            key = (str(unit.root.resolve()), _is_lone_file(target) and os.path.realpath(target))
            if key in seen_roots:
                continue
            seen_roots.add(key)
            if lone:
                read.update(os.path.realpath(t.path) for t in unit.files
                            if isinstance(t.path, Path) and t.kind != "symlink")
            units.append((unit, _uri_base(base)))

    result = ScanResult(root=str(paths[0]) if len(paths) == 1 else "[multiple]")
    result.units = len(units)
    scanned = 0
    hygiene: dict = {}
    for unit, uri_base in units:
        scanned += sum(1 for f in unit.files if f.is_text)
        # Tag every finding with the unit it came from: in a multi-skill scan
        # the file path alone does not say which skill is the bad one.
        anchor = _anchor(unit)
        result.findings.extend(
            dataclasses.replace(f, unit=unit.name, uri_base=uri_base, anchor=anchor)
            for f in run_all(unit, enabled=enabled)
        )
        # Keep the hygiene summary from the primary (or first) unit.
        for name, ok, detail in hygiene_checks(unit):
            # Worst-case across units: a check fails if it fails in any unit.
            if name not in hygiene:
                hygiene[name] = (ok, detail)
            elif hygiene[name][0] and not ok:
                hygiene[name] = (ok, detail)
    result.scanned_files = scanned
    result.hygiene_checks = [(n, ok, d) for n, (ok, d) in hygiene.items()]
    result.findings.sort(key=lambda f: f.sort_key())
    result.grade, result.grade_score = grade(result.findings)
    return result


def _is_lone_file(target: Path) -> bool:
    """A named file that becomes a unit of its own: anything but a SKILL.md,
    which stands for the whole skill around it."""
    return target.is_file() and target.name.lower() != "skill.md"


def _anchor(unit) -> str:
    """Where SARIF pins a finding about the whole unit, since code scanning
    rejects a result with no location: its plugin.json, else its first file."""
    files = sorted((t for t in unit.files if isinstance(t.path, Path) and t.kind != "symlink"),
                   key=lambda t: t.relpath)
    for manifest in (unit.root / ".claude-plugin" / "plugin.json", unit.root / "plugin.json"):
        for t in files:
            if t.path == manifest:
                return t.relpath
    return files[0].relpath if files else ""


def _uri_base(folder: Path) -> str:
    """The folder relative to the working directory, so SARIF locations
    resolve from where the scan ran. Empty when it lies outside (a --git
    clone, a temp dir), which leaves them relative to the folder itself."""
    try:
        rel = Path(os.path.abspath(folder)).relative_to(os.getcwd()).as_posix()
    except ValueError:
        return ""
    return "" if rel == "." else rel


def scan_path(path, exclude=(), enabled=None, follow_links: bool = True) -> ScanResult:
    return scan_paths([path], exclude=exclude, enabled=enabled, follow_links=follow_links)


# Cap the pack transfer at a bit above MAX_FILE_BYTES. This keeps the clone
# itself from ballooning on a repo carrying oversized blobs outside the
# checked-out tip (other branches, history git would otherwise still touch
# during negotiation) -- a cheap, no-dependency narrowing of the attack
# surface alongside the per-file truncation discovery.py already does on
# whatever does land on disk.
_CLONE_BLOB_LIMIT = MAX_FILE_BYTES * 2


def scan_git(url: str, ref: str | None = None, exclude=(), enabled=None) -> ScanResult:
    """Clone a repo shallowly into a temp dir and scan it. Read-only: nothing
    from the cloned repo is executed, and git hooks are disabled during clone."""
    tmp = tempfile.mkdtemp(prefix="skillxray-")
    dest = Path(tmp) / "repo"
    cmd = [
        "git", "-c", "core.hooksPath=/dev/null",
        "clone", "--depth", "1", "--quiet",
        f"--filter=blob:limit={_CLONE_BLOB_LIMIT}",
    ]
    if ref:
        cmd += ["--branch", ref]
    # `--` stops git from reading a url that begins with `-` as an option
    # (e.g. --upload-pack=..., which would run an arbitrary command).
    cmd += ["--", url, str(dest)]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=180)
        result = scan_path(dest, exclude=exclude, enabled=enabled, follow_links=False)
        result.root = url
        # Uris stay relative to the clone, even when the temp dir it sits in is under cwd.
        result.findings = [dataclasses.replace(f, uri_base="") for f in result.findings]
        return result
    except FileNotFoundError:
        raise RuntimeError("git is not installed; --git needs git on PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError("git clone timed out")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"git clone failed: {e.stderr.strip() or e}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def scan_git_many(urls: list[str], ref: str | None = None, exclude=(), enabled=None) -> ScanResult:
    """Scan several repos in one call and merge them into a single result, the
    same way scan_paths() merges several local units - so one --fail-on
    threshold can gate a whole list of repos instead of needing one process
    invocation per URL."""
    if len(urls) == 1:
        return scan_git(urls[0], ref, exclude=exclude, enabled=enabled)

    merged = ScanResult(root="[multiple]")
    hygiene: dict = {}
    for url in urls:
        one = scan_git(url, ref, exclude=exclude, enabled=enabled)
        merged.units += one.units
        merged.scanned_files += one.scanned_files
        merged.findings.extend(one.findings)
        for name, ok, detail in one.hygiene_checks:
            # Worst-case across repos, same rule scan_paths() uses across units.
            if name not in hygiene or (hygiene[name][0] and not ok):
                hygiene[name] = (ok, detail)
    merged.hygiene_checks = [(n, ok, d) for n, (ok, d) in hygiene.items()]
    merged.findings.sort(key=lambda f: f.sort_key())
    merged.grade, merged.grade_score = grade(merged.findings)
    return merged
