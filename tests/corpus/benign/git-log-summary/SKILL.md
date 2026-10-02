---
name: git-log-summary
description: Summarizes recent commits on the current branch in plain language.
license: MIT
allowed-tools: Bash(git:*)
---

# Git log summary

Reads the last few commits with `git log --oneline -20` and groups them by
area. See [usage](docs/usage.md) for the options and [the license](LICENSE).
