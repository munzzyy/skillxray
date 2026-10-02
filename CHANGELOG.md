# Changelog

## Unreleased

Several of these widen what a scan reads. A skill or repo that graded A on v0.2.1 can grade lower now, so check your `--fail-on` gate after you upgrade. Did a grade move in a way that looks wrong? Please open an [issue](https://github.com/munzzyy/skillxray/issues).

- A folder scan reads the files that sit outside every skill and plugin in it and reports them under `(repo root)`. That covers a repo's install script, its README and its `.claude/settings.json`. This changes grades for the action's default `path: .`.
- A lone file other than a SKILL.md, like an install script or a `plugin.json`, is scanned on its own. It used to read nothing and grade A. A scan that reads no text files at all says so on stderr.
- Hook commands and MCP server launch lines in `plugin.json`, `hooks.json`, `.mcp.json` and the settings files get the SX-CMD patterns. Hooks on any event name are reported, not only the nine it knew before.
- Zip bundles (`.zip`, `.skill`, `.mcpb`, `.dxt`) are opened in memory and every member is scanned. Whatever stops a full read is an SX-SUP medium: an encrypted member, a nested archive or a zip that inflates far past its size.
- A symlink that points out of a skill is reported at medium and never followed. FIFOs and device files are skipped.
- A text file cut at the 2 MB read limit is an SX-SUP medium instead of a hygiene note, so a medium gate fails on it. Images and other binaries are not reported.
- SX-INJ also reads data files and scripts. A script's hits are one severity lower, since scripts embed prompt text for honest reasons too.
- A run of hidden tag characters is one finding that says what it decodes to. The report prints invisible characters as markers like `<U+202E>`.
- Frontmatter block scalars (`|`, `>`) and wrapped values parse the way YAML reads them.
- Matched secrets are redacted in every rule's snippet and detail, not only SX-SEC's.
- Discord and Telegram bot tokens are detected.
- `s3-transfer.sh` and `profile.io` no longer match as collector endpoints.
- `--select` and `--ignore` run or skip rules by id.
- `--git` takes several URLs and gates them under one `--fail-on`.
- `--ref` without `--git`, and `--git` together with a local path, exit 2 instead of being ignored.
- SARIF locations resolve from the directory you ran in. A finding inside a bundle points at the bundle. Every result has a location, which code scanning needs to accept the upload.
- The action's `result` output is `error` when skillxray could not run, instead of `fail`. A new `upload-sarif` input turns the upload off.
- CI runs the packaged action and tests Python 3.10 and 3.14 too. The release workflow stops when the tag doesn't match the package version.
- Relicensed from MIT to GPL-3.0-or-later.

## 0.2.1 (2026-08-02)

Tagged only. It has no GitHub Release.

- Extensionless and batch scripts are read. A shebang decides whether a file is a script.
- Pointing at a SKILL.md scans the whole skill it belongs to, which is what pre-commit does.
- A scan of several skills says which skill each finding came from.
- New SX-SUP rule: compiled `.pyc` without its source, release assets from an account the skill doesn't claim, and password-protected archives.
- SARIF results carry their OWASP Agentic Skills Top 10 tag and link to the [rules reference](https://github.com/munzzyy/skillxray/blob/main/docs/rules.md).
- `--exclude` takes globs.
- Exit codes mean one thing each: 0 clean, 1 a finding at or above `--fail-on`, 2 skillxray could not run.
- The action installs the code at the ref you pin instead of the newest PyPI release.
- Relicensed from the Prosperity Public License to MIT.

## 0.2.0 (2026-07-15)

- A terminal demo and a runnable, inert malicious example skill in `examples/`.
- Closed gaps around eval and exec, terminal escapes in the report, oversized files and secret and injection patterns. A regex that could backtrack for a long time is gone.
- A rules reference, `docs/rules.md`, with a test that fails when it drifts from the code.
- A pre-commit hook.
- Workflow actions pinned to commit SHAs, and checkout no longer keeps its credentials.

## 0.1.1 (2026-07-11)

- A `--git` URL that starts with `-` can't be read as a git option anymore.
- Files over 2 MB are scanned up to the limit and flagged instead of skipped.
- Frontmatter with no closing `---`, or closed with `...`, is still parsed.
- An MCP server that launches an arbitrary command is high, not medium.
- The destructive-delete pattern catches `-fr` as well as `-rf` and no longer backtracks.
- The temporary clone directory is removed after a scan.

## 0.1.0 (2026-07-11)

First release.
