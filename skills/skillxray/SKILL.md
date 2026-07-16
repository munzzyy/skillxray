---
name: skillxray
description: Scan an AI agent skill, plugin, or MCP bundle for security and hygiene problems before installing or trusting it - prompt injection in the instructions, hidden/invisible Unicode, dangerous commands (curl-pipe-sh, reverse shells), data exfiltration, hardcoded secrets, and auto-running hooks. Use before adding a third-party skill or plugin, before wiring up an MCP server someone else wrote, or whenever you're about to trust a SKILL.md you didn't write. Returns an A-F grade and a per-finding report.
---

# skillxray

Run this before you install or trust an AI agent skill you didn't write - a
SKILL.md, a Claude Code plugin, an MCP bundle, or a whole directory of them.
It reads the files and flags what a quick glance would miss: instructions
aimed at the agent instead of the user, invisible Unicode, curl-pipe-sh and
reverse shells, exfiltration to an outside host, leaked keys, and hooks that
run on their own. It tells you what's wrong and where; it doesn't fix it for
you.

## When to use it

Before:
- installing a third-party skill, plugin, or MCP server someone else wrote
- trusting a `SKILL.md` pulled from a repo or a registry
- adding a skill bundle to a shared or automated environment

Run it and read the findings before the skill is live, not after.

## How to run it

Point it at a skill directory, a single `SKILL.md`, or a directory of skills:

```bash
skillxray <path> --json
```

`<path>` defaults to the current directory. To vet something you haven't
cloned yet, let skillxray do the shallow read-only clone itself:

```bash
skillxray --git https://github.com/owner/some-skill --ref main --json
```

`--json` gives machine-readable output; `--sarif` emits SARIF 2.1.0 for the
GitHub Security tab; leave both off for the colored human report. `--quiet`
prints just the summary line and grade.

## Reading the result

Every scan ends in a letter grade, A through F. Any critical finding drops it
straight to F; high-severity findings cap it below an A. The grade is the
five-second read; the findings under it are the reason.

The exit code is what to gate on in CI or a script: skillxray exits non-zero
when any finding lands at or above `--fail-on` (`critical|high|medium|low|info|none`,
default `high`). So a default run passes on low/medium hygiene notes and fails
on the things that actually get you owned.

A clean grade means skillxray didn't find one of the patterns it checks for,
not that the skill is safe to run blind. Read what it flagged, and for
anything it grades below an A, understand the specific finding before you
decide to trust the skill anyway - the report names the rule and the line so
you can go look.
