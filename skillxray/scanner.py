"""Scan orchestration: discover units, run every rule, aggregate, grade."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from .discovery import discover
from .finding import ScanResult
from .grade import grade
from .rules import run_all
from .rules.quality import hygiene_checks


def scan_path(path) -> ScanResult:
    path = Path(path)
    units = discover(path)
    result = ScanResult(root=str(path))
    result.units = len(units)
    scanned = 0
    hygiene: dict = {}
    for unit in units:
        scanned += sum(1 for f in unit.files if f.is_text)
        result.findings.extend(run_all(unit))
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


def scan_git(url: str, ref: str | None = None) -> ScanResult:
    """Clone a repo shallowly into a temp dir and scan it. Read-only: nothing
    from the cloned repo is executed, and git hooks are disabled during clone."""
    tmp = tempfile.mkdtemp(prefix="skillxray-")
    dest = Path(tmp) / "repo"
    cmd = [
        "git", "-c", "core.hooksPath=/dev/null",
        "clone", "--depth", "1", "--quiet",
    ]
    if ref:
        cmd += ["--branch", ref]
    # `--` stops git from reading a url that begins with `-` as an option
    # (e.g. --upload-pack=…, which would run an arbitrary command).
    cmd += ["--", url, str(dest)]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=180)
        result = scan_path(dest)
        result.root = url
        return result
    except FileNotFoundError:
        raise RuntimeError("git is not installed; --git needs git on PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError("git clone timed out")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"git clone failed: {e.stderr.strip() or e}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
