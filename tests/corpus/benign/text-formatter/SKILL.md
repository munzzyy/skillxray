---
name: text-formatter
description: Cleans up pasted text — normalizes whitespace, fixes smart quotes, and wraps long lines.
license: MIT
---

# Text formatter

This skill acts as a tidy-up pass for pasted prose. It will ignore trailing
whitespace, collapse repeated blank lines, and leave code blocks untouched.

The rules are simple: normalize, don't rewrite. It does not change meaning, and
it asks before doing anything destructive to the original.

## Notes

You can paste examples that mention commands like `curl` or `rm` in prose — the
formatter treats them as plain text and never runs them.
