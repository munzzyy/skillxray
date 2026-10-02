# Security

skillxray exists to read hostile input: agent skills that may contain prompt
injection, obfuscated commands, or worse. It is static by design - it reads
files, matches patterns, and prints a report. It never executes anything from
the skill it is scanning, never imports it, and never talks to the network. It
only opens regular files, and it does not follow a symlink that points outside
the skill. The one link it does follow is a skill folder symlinked into a
local folder of skills, and never one inside a `--git` clone.

That makes the scanner itself the attack surface. A skill crafted to crash the
parser, to hide a finding from it, or to smuggle terminal escape sequences into
the report so they run in your terminal when you read it - any of those is a
vulnerability in skillxray, and exactly the kind of report we want. A missed
detection (a payload the scanner should reasonably catch but doesn't) is
welcome as a regular issue with a sample.

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private
reporting instead:

https://github.com/munzzyy/skillxray/security/advisories/new

Include what you found, how to reproduce it, and the impact you would expect.

## Supported versions

Fixes land on the latest tagged version; there is no backport policy.
