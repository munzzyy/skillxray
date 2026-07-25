"""Flag dangerous shell/interpreter invocations in bundled scripts and in the
command examples a skill hands to the agent.

We scan script files in full, plus fenced (``` and ~~~), indented, and inline
code in Markdown (the model may run those examples). We deliberately do NOT scan
ordinary prose for the whole pattern set, which would flood the report with false
positives on docs that merely mention a command. The exception is a short list of
unmistakable remote-exec / reverse-shell shapes (curl|sh, /dev/tcp, base64|sh),
which we do flag even in prose: "just run curl | sh" is an instruction to the
agent no matter where it sits, and those shapes practically never appear
innocently.
"""

from __future__ import annotations

import re

from ..finding import Finding, Category, Severity, line_col, snippet_for
from ..discovery import SkillUnit
from ._util import code_blocks, indented_blocks

RULE_ID = "SX-CMD"
_I = re.IGNORECASE

# (compiled, severity, title, detail, remediation)
_PATTERNS = [
    # Require a real argument (a URL/flag) between the downloader and the pipe:
    # `curl <url> | sh` always has one. That stops a Markdown table row like
    # `| fetch | bash |` from reading its column `|` as a shell pipe -- there the
    # command word sits alone in a cell, immediately followed by the delimiter.
    (re.compile(r"\b(?:curl|wget|fetch)\b\s+[^\s|][^\n]*?\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|python3?|node|ruby|perl)\b", _I),
     Severity.CRITICAL, "Remote script piped to an interpreter",
     "Downloads code and runs it in one step (curl | sh). The remote content is trusted blindly and can change at any time.",
     "Download to a file, review it, then run it. Never pipe a network response straight into a shell."),
    (re.compile(r"\bbase64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:sh|bash|zsh|python3?|node|perl)\b", _I),
     Severity.CRITICAL, "Base64-decoded payload piped to a shell",
     "Decodes an obfuscated blob and executes it - a common way to hide malicious commands from a reviewer.",
     "Remove the obfuscation. Executable logic should be readable in the clear."),
    (re.compile(r"/dev/(?:tcp|udp)/[0-9A-Za-z.\-]+/\d+"),
     Severity.CRITICAL, "Reverse-shell socket",
     "Opens a raw TCP/UDP socket to a host:port, the signature of a reverse shell.",
     "Remove it. A skill has no legitimate need for a raw network shell."),
    # `-e` must actually hand netcat a program to run (a path or a shell/exe),
    # the way a real bind/reverse shell does: `nc ... -e /bin/sh`. Prose like
    # "NC homeowners file before the -e exemption deadline" has `-e` followed by
    # an ordinary word, not an executable, so it no longer matches.
    (re.compile(r"\b(?:nc|ncat|netcat)\b[^\n]*\s-e\s+(?:[/~.]\S*|[a-z]:\\\S*|(?:sh|bash|zsh|dash|ash|ksh|cmd|powershell|python\d?|perl|ruby|node)(?:\.exe)?\b)", _I),
     Severity.CRITICAL, "Netcat command execution",
     "netcat with -e wires a program's I/O to a socket - a reverse/bind shell.",
     "Remove it."),
    (re.compile(r"\bsocat\b[^\n]*\bEXEC\b"),
     Severity.CRITICAL, "socat command execution",
     "socat EXEC bridges a process to a socket - a reverse/bind shell.",
     "Remove it."),
    (re.compile(r"\bbash\s+-i\b[^\n]*>&", _I),
     Severity.CRITICAL, "Interactive shell redirected to a socket",
     "An interactive bash redirected to a network descriptor is a reverse shell.",
     "Remove it."),
    (re.compile(r"\brm\s+-(?=[a-z]*r)(?=[a-z]*f)[a-z]+\b[^\n|;&]*?(?:\s/(?:\s|$|['\"])|\s~(?:/|\s|$)|\$HOME|\s/\*|--no-preserve-root)", _I),
     Severity.HIGH, "Destructive recursive delete",
     "A recursive force-delete aimed at a home directory, filesystem root, or a broad glob.",
     "Scope deletes to a specific project path and never target ~ or /."),
    (re.compile(r">>?\s*(?:~|\$HOME)?/?\.(?:bashrc|bash_profile|zshrc|zprofile|profile|zlogin)\b", _I),
     Severity.HIGH, "Writes to a shell startup file",
     "Modifying a shell rc file installs persistence that runs on every new shell.",
     "Do not edit the user's shell startup files."),
    (re.compile(r"\bcrontab\s+-", _I),
     Severity.HIGH, "Installs a cron job",
     "Editing crontab installs scheduled persistence.",
     "Remove scheduled-task installation from a skill."),
    (re.compile(r"authorized_keys", _I),
     Severity.HIGH, "Touches SSH authorized_keys",
     "Writing authorized_keys grants persistent remote SSH access.",
     "Remove any handling of authorized_keys."),
    # `eval "$(...)"` (shell, needs whitespace before the opener) and
    # `eval(...)`/`exec(...)` (language-level call, no space at all -- Python's
    # exec(eval(compile(base64.b64decode(...)))) is the common obfuscated-
    # payload shape) are both "run this constructed thing," just spelled
    # differently. `eval\s*\(` stops at "evaluate(": after "eval" comes "uate",
    # not whitespace-then-"(", so it never fires on that word. The `(?<![.\w])`
    # keeps the bare builtins (`exec(`, `eval(`) but skips the method call
    # `regex.exec(str)` -- running a regex, not code -- which is the common tell.
    (re.compile(r"\beval\s+[\"'`$(]|(?<![.\w])(?:eval|exec)\s*\("),
     Severity.HIGH, "Dynamic shell eval",
     "eval runs a constructed string as a command, which hides what actually executes.",
     "Replace eval with a direct, readable command."),
    (re.compile(r"\bchmod\s+(?:-[a-zA-Z]+\s+)*777\b"),
     Severity.MEDIUM, "World-writable permissions",
     "chmod 777 makes a file writable by anyone on the machine.",
     "Grant the least permission the task needs."),
    (re.compile(r"\b(?:os\.system|subprocess\.(?:call|run|Popen|check_output|check_call))\s*\([^)]*shell\s*=\s*True", ),
     Severity.MEDIUM, "Python shell=True subprocess",
     "shell=True lets shell metacharacters in any interpolated value execute - a command-injection footgun.",
     "Pass an argument list and shell=False."),
    (re.compile(r"\b(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|curl\b[^\n]*\s(?:-k|--insecure)\b|--no-check-certificate|verify\s*=\s*False)", ),
     Severity.MEDIUM, "TLS verification disabled",
     "Disabling certificate verification exposes the transfer to interception.",
     "Keep TLS verification on."),
    (re.compile(r"\b(?:pip3?|pipx)\s+install\s+[^\n]*(?:git\+|https?://)", _I),
     Severity.MEDIUM, "Installs a package from a URL",
     "Installing directly from a URL or git ref bypasses the registry and pins nothing - a supply-chain risk.",
     "Install pinned, published packages from the registry."),
    (re.compile(r"\bnpm\s+(?:i|install|add)\s+[^\n]*(?:git\+|https?://|github:)", _I),
     Severity.MEDIUM, "Installs a package from a URL",
     "Installing from a URL or git ref bypasses the registry and version pinning.",
     "Install pinned, published packages."),
    (re.compile(r"\bsudo\b", ),
     Severity.LOW, "Uses sudo",
     "The skill escalates privileges. Worth a look to confirm it is necessary.",
     "Avoid requiring root unless the task truly needs it."),
]

# inline code spans in markdown: `...`
_INLINE = re.compile(r"`([^`\n]+)`")

# The unmistakable remote-exec / reverse-shell shapes we flag even in prose.
# These never appear innocently, so "just run curl | sh" gets caught whether it
# sits in a fence, indented, inline, or in a plain sentence.
_PROSE_TITLES = {
    "Remote script piped to an interpreter",
    "Base64-decoded payload piped to a shell",
    "Reverse-shell socket",
    "Netcat command execution",
    "socat command execution",
    "Interactive shell redirected to a socket",
}
_PROSE_PATTERNS = [p for p in _PATTERNS if p[2] in _PROSE_TITLES]


def _regions(unit: SkillUnit):
    """Yield (target, base_offset, region_text) for command-bearing regions."""
    for t in unit.files:
        if not t.is_text:
            continue
        if t.kind == "script":
            yield t, 0, t.text
        elif t.kind == "markdown":
            for base, block in code_blocks(t.text):
                yield t, base, block
            for base, block in indented_blocks(t.text):
                yield t, base, block
            for m in _INLINE.finditer(t.text):
                yield t, m.start(1), m.group(1)
            # Prose gets only the unmistakable remote-exec shapes.
            yield t, 0, t.text, _PROSE_PATTERNS


def check(unit: SkillUnit) -> list:
    findings: list = []
    seen: set = set()
    for region_info in _regions(unit):
        # Most regions run the full pattern set; prose passes a narrowed one.
        if len(region_info) == 4:
            t, base, region, patterns = region_info
        else:
            t, base, region = region_info
            patterns = _PATTERNS
        for rx, sev, title, detail, remediation in patterns:
            for m in rx.finditer(region):
                abs_i = base + m.start()
                dedupe = (t.relpath, abs_i, title)
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                line, col = line_col(t.text, abs_i)
                findings.append(Finding(
                    rule_id=RULE_ID,
                    category=Category.DANGEROUS_COMMAND,
                    severity=sev,
                    title=title,
                    detail=detail,
                    file=t.relpath,
                    line=line,
                    column=col,
                    snippet=snippet_for(t.text, abs_i),
                    remediation=remediation,
                ))
    return findings
