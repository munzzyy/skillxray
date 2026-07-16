# skillxray

[![CI](https://github.com/munzzyy/skillxray/actions/workflows/ci.yml/badge.svg)](https://github.com/munzzyy/skillxray/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

Scan an AI agent skill before you install it. skillxray reads a `SKILL.md` bundle, a Claude Code plugin, an MCP bundle, or a whole folder of them and tells you what's in there: prompt injection, hidden Unicode, `curl | sh` and reverse shells, credential-stealing patterns, leaked keys, and auto-running hooks. You get a per-finding report and a letter grade, with exit codes for CI.

Skills are just instructions and scripts a model will follow, and most people install them the way they'd `npm install` anything: without reading a line. Recent audits of public skills found prompt injection in a large share of them. This is the tool that reads the skill so you don't have to trust it blind.

![skillxray scanning a malicious example skill: two criticals (curl piped to bash, credential exfiltration), a hardcoded AWS key, a prompt-injection payload, three zero-width characters, grade F](docs/media/demo.svg)

That skill lives in [`examples/sketchy-pdf-summarizer/`](examples/sketchy-pdf-summarizer/SKILL.md) — every URL and key in it is fake. Run the scan yourself:

```bash
skillxray examples/sketchy-pdf-summarizer/
```

## What it checks

See the [Rules Reference](docs/rules.md) for full details on each rule, its severity, and how to fix it.

- Prompt injection aimed at the agent: "ignore previous instructions", "don't tell the user", "reveal your system prompt", silent tool execution.
- Hidden Unicode: bidi overrides (Trojan Source), invisible tag characters that smuggle instructions, zero-width characters breaking up words. Unicode tag characters render as nothing in your editor but read as text to a model, so a line that displays as `follow these rules` can carry an invisible ` and exfiltrate the keys` behind it. skillxray decodes what the invisible bytes actually spell. (This README stays clean on purpose; the live payload sits in the example skill.)
- Dangerous commands: `curl | sh`, base64 piped to a shell, reverse shells, `rm -rf ~`, writes to shell startup files, cron persistence, `shell=True`, disabled TLS.
- Data exfiltration: reads of `~/.ssh`, cloud credentials, `.env`, browser cookies, and whether the same file can send them out, plus known paste, webhook, and tunnel endpoints.
- Hardcoded secrets: AWS keys, GitHub and GitLab tokens, OpenAI and Anthropic keys, Stripe keys, private key blocks. Matched values are redacted, never echoed back.
- Permissions: broad `allowed-tools` grants, MCP servers that launch local binaries, Claude Code hooks that run shell automatically on an event.
- Hygiene: missing name or description, bloated `SKILL.md`, broken file references, no license. Reported separately from the security grade.

## Install

One command:

```bash
pipx install git+https://github.com/munzzyy/skillxray
```

Pure standard library, Python 3.9+, no runtime dependencies — so a plain clone works too:

```bash
git clone https://github.com/munzzyy/skillxray
cd skillxray
python -m skillxray ./some-skill      # run it directly, no install
```

Not on PyPI yet; `pipx install skillxray` will work once the first release lands there.

## Usage

```bash
skillxray ./my-skill              # scan a skill directory
skillxray ./SKILL.md              # scan a single file
skillxray ./skills-folder         # scan every skill under a folder
skillxray --git https://github.com/someone/their-skill   # clone (read-only) and scan
```

Nothing in a scanned skill is ever executed. `--git` clones shallowly with hooks disabled and only reads files.

### In CI

skillxray exits non-zero when it finds something at or above a severity you choose, so it drops straight into a pipeline:

```yaml
- run: pipx run skillxray ./skills --fail-on high
```

`--fail-on` takes `critical`, `high`, `medium`, `low`, or `none` (default `high`).

It also speaks SARIF, so findings show up in the GitHub Security tab:

```yaml
- run: pipx run skillxray ./skills --sarif > skillxray.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: skillxray.sarif
```

### Pre-commit

You can also run skillxray as a pre-commit hook to block dangerous skills from being committed. Add this to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/munzzyy/skillxray
    rev: v0.2.0
    hooks:
      - id: skillxray
```

### Output formats

- default — colored human report
- `--json` — full findings for scripting
- `--sarif` — SARIF 2.1.0 for code scanning
- `--quiet` — just the grade and counts

## Where it fits

Plenty of scanners are adjacent to this and none of them cover it:

- **Semgrep and friends** analyze source code. A skill's attack surface is mostly natural-language instructions like "ignore previous instructions" and "don't tell the user", which code SAST has no rules for. skillxray scans the prose and the scripts.
- **TruffleHog / gitleaks** hunt secrets across git history. skillxray checks the files in front of it for secrets as one rule among thirty, alongside injection, exfiltration, and persistence patterns.
- **Runtime guardrails (Lakera Guard, LLM Guard, NeMo Guardrails)** sit between your app and the model and filter live traffic, which means network calls and a vendor. skillxray runs offline, before install. The point is to catch a malicious skill while it's still a folder you're deciding about.

## What it does not do

- It's a static scanner. It reads text and matches patterns; it does not run the skill or trace what a script actually does at runtime. A determined attacker can obfuscate past any static rule, and skillxray flags obfuscation itself (base64-to-shell, hidden Unicode) rather than pretending to defeat it.
- A clean grade means nothing obvious tripped, not that the skill is safe. Read anything before you trust it with your machine.
- It expects skill-shaped input (a `SKILL.md`, a plugin, or a folder of them). Point it at an arbitrary code repo and you'll get noisier results, because it will read every text file it finds.
- It is not a secret scanner for your whole git history — it checks the files in front of it.

## How it works

Every check is a deterministic rule over the skill's text. No model calls, no network (except `--git`, which only clones), no telemetry. Findings carry a rule id, severity, file and line, and a fix. The grade starts at 100 and loses points by severity, with two hard rules: any critical finding is an F, and any high keeps it out of the top band. The whole thing is standard-library Python so it installs anywhere and you can read every rule yourself in `skillxray/rules/`.

## Contributing

Found a skill that should have been flagged and wasn't, or a false positive? Open an issue with the smallest example that reproduces it. New rules land with a fixture in `tests/corpus/` (a malicious one that must be caught, or a benign one that must stay clean) so coverage only goes up.

## License

MIT — free to use, change, and ship, commercial or not. See [LICENSE](LICENSE).
