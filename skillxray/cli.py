"""Command-line interface for skillxray."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .finding import SECURITY_CATEGORIES, Severity
from .report import render_human, render_json, render_sarif
from .scanner import scan_paths, scan_git


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="skillxray",
        description="Security and hygiene scanner for AI agent skills (SKILL.md, plugins, MCP bundles).",
    )
    p.add_argument("target", nargs="*", default=["."],
                   help="path to a skill dir, a SKILL.md, or a directory of skills (default: .)")
    p.add_argument("--git", metavar="URL",
                   help="clone a git repo (shallow, read-only) and scan it instead of a local path")
    p.add_argument("--ref", metavar="NAME", help="branch/tag to clone with --git")
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="machine-readable JSON output")
    out.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 (for GitHub code scanning)")
    p.add_argument("--fail-on", default="high", metavar="SEVERITY",
                   help="exit non-zero if any security finding is at or above this severity "
                        "(critical|high|medium|low|info|none; default: high). Hygiene "
                        "findings never fail the build.")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="skip paths matching this glob, relative to the scanned path "
                        "(repeatable, e.g. --exclude 'tests/corpus/*')")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color")
    p.add_argument("--quiet", action="store_true", help="only print the summary line and grade")
    p.add_argument("--version", action="version", version=f"skillxray {__version__}")
    return p


class UsageError(Exception):
    """A flag the user got wrong. Exit code 2, never 1 - see main()."""


def _fail_threshold(value: str):
    value = value.strip().lower()
    if value in ("none", "off", "never"):
        return None
    try:
        return Severity.parse(value)
    except ValueError:
        raise UsageError(f"invalid --fail-on value {value!r}")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        threshold = _fail_threshold(args.fail_on)
    except UsageError as e:
        # Exit 2, not 1. A pipeline reads 1 as "skillxray found something"; a
        # misspelled flag means the scan never ran at all, and reporting that as
        # a detection is the wrong kind of wrong in both directions.
        print(f"skillxray: {e}", file=sys.stderr)
        return 2

    try:
        if args.git:
            result = scan_git(args.git, args.ref, exclude=args.exclude)
        else:
            for target_path in args.target:
                if not os.path.exists(target_path):
                    print(f"skillxray: no such path: {target_path}", file=sys.stderr)
                    return 2
            result = scan_paths(args.target, exclude=args.exclude)
    except RuntimeError as e:
        print(f"skillxray: {e}", file=sys.stderr)
        return 2

    color = not args.no_color and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    if args.json:
        print(render_json(result))
    elif args.sarif:
        print(render_sarif(result))
    elif args.quiet:
        print(f"{result.grade} ({result.grade_score}/100) - "
              f"{sum(result.counts().values())} finding(s), "
              f"hygiene {result.hygiene_passed}/{result.hygiene_total}")
    else:
        print(render_human(result, color=color))

    if threshold is not None:
        # Security findings only. Hygiene is reported next to the grade, not
        # folded into it, and a missing LICENSE should never red a build that
        # asked to gate on low-severity security issues.
        worst = max((f.severity for f in result.findings
                     if f.category in SECURITY_CATEGORIES), default=None)
        if worst is not None and worst >= threshold:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
