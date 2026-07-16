"""Flag dangerous shell/interpreter invocations in bundled scripts and in the
command examples a skill hands to the agent.

We scan script files in full, plus fenced and inline code in Markdown (the model
may run those examples). We deliberately do NOT scan ordinary prose for commands
— that is the injection rule's job and scanning prose here would flood the report
with false positives on documentation that merely mentions a command.
"""

from __future__ import annotations

import re

from ..finding import Finding, Category, Severity, line_col, snippet_for
from ..discovery import SkillUnit
from ._util import code_blocks

RULE_ID = "SX-CMD"
_I = re.IGNORECASE

# (compiled, severity, title, detail, remediation)
_PATTERNS = [
    (re.compile(r"\b(?:curl|wget|fetch)\b[^\n]*?\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|python3?|node|ruby|perl)\b", _I),
     Severity.CRITICAL, "Remote script piped to an interpreter",
     "Downloads code and runs it in one step (curl | sh). The remote content is trusted blindly and can change at any time.",
     "Download to a file, review it, then run it. Never pipe a network response straight into a shell."),
    (re.compile(r"\bbase64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:sh|bash|zsh|python3?|node|perl)\b", _I),
     Severity.CRITICAL, "Base64-decoded payload piped to a shell",
     "Decodes an obfuscated blob and executes it — a common way to hide malicious commands from a reviewer.",
     "Remove the obfuscation. Executable logic should be readable in the clear."),
    (re.compile(r"/dev/(?:tcp|udp)/[0-9A-Za-z.\-]+/\d+"),
     Severity.CRITICAL, "Reverse-shell socket",
     "Opens a raw TCP/UDP socket to a host:port, the signature of a reverse shell.",
     "Remove it. A skill has no legitimate need for a raw network shell."),
    (re.compile(r"\b(?:nc|ncat|netcat)\b[^\n]*\s-e\b", _I),
     Severity.CRITICAL, "Netcat command execution",
     "netcat with -e wires a program's I/O to a socket — a reverse/bind shell.",
     "Remove it."),
    (re.compile(r"\bsocat\b[^\n]*\bEXEC\b"),
     Severity.CRITICAL, "socat command execution",
     "socat EXEC bridges a process to a socket — a reverse/bind shell.",
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
     "shell=True lets shell metacharacters in any interpolated value execute — a command-injection footgun.",
     "Pass an argument list and shell=False."),
    (re.compile(r"\b(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|curl\b[^\n]*\s(?:-k|--insecure)\b|--no-check-certificate|verify\s*=\s*False)", ),
     Severity.MEDIUM, "TLS verification disabled",
     "Disabling certificate verification exposes the transfer to interception.",
     "Keep TLS verification on."),
    (re.compile(r"\b(?:pip3?|pipx)\s+install\s+[^\n]*(?:git\+|https?://)", _I),
     Severity.MEDIUM, "Installs a package from a URL",
     "Installing directly from a URL or git ref bypasses the registry and pins nothing — a supply-chain risk.",
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
            for m in _INLINE.finditer(t.text):
                yield t, m.start(1), m.group(1)


def check(unit: SkillUnit) -> list:
    findings: list = []
    seen: set = set()
    for t, base, region in _regions(unit):
        for rx, sev, title, detail, remediation in _PATTERNS:
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
