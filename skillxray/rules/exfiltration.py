"""Detect data-exfiltration shapes: reading sensitive files, and sending data to
collector/tunnel endpoints. The strongest signal is the combination — a file
that both reads secrets AND has a way to send them off the machine.
"""

from __future__ import annotations

import re

from ..finding import Finding, Category, Severity, line_col, snippet_for
from ..discovery import SkillUnit
from ._util import text_targets

RULE_ID = "SX-EXF"
_I = re.IGNORECASE

# Endpoints whose whole purpose is receiving exfiltrated data / out-of-band callbacks.
_SINK = re.compile(
    r"(?:"
    r"webhook\.site|requestbin\.\w+|(?:pipedream\.net)|"
    r"\bhooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|"
    r"[0-9a-z-]+\.ngrok(?:-free)?\.(?:io|app|dev)|[0-9a-z-]+\.trycloudflare\.com|[0-9a-z-]+\.lhr\.life|"
    r"pastebin\.com|hastebin\.com|termbin\.com|transfer\.sh|0x0\.st|file\.io|"
    r"\.oast\.(?:fun|live|pro|online|site|me)|burpcollaborator\.net|interact\.sh|"
    r"dnslog\.cn|canarytokens\.\w+|requestrepo\.com"
    r")",
    _I,
)

# Reading credential / secret material from disk.
_SENSITIVE = re.compile(
    r"(?:"
    r"~/\.ssh\b|\bid_rsa\b|\bid_ed25519\b|/\.ssh/|"
    r"~/\.aws/credentials|\.aws/credentials|"
    r"~/\.config/gcloud|~/\.netrc|\.netrc\b|"
    r"~/\.docker/config\.json|~/\.kube/config|"
    r"~/\.gnupg|/etc/shadow|/etc/passwd\b|"
    r"~/\.config/gh/hosts\.yml|~/\.claude\b|~/\.config/claude|"
    r"Login\s?Data|/Cookies\b|cookies\.sqlite|"
    r"security\s+find-generic-password|"
    r"\.env(?:\.local|\.production)?\b"
    r")",
    _I,
)

# Ways to move bytes off the machine (used only to decide the read+send combo).
_EGRESS = re.compile(
    r"(?:"
    r"\bcurl\b|\bwget\b|\bnc\b|\bncat\b|"
    r"requests\.(?:post|put|get|patch)|urllib\.request|urlopen|http\.client|httpx\.|aiohttp|"
    r"\bfetch\s*\(|XMLHttpRequest|axios\.|"
    r"socket\.\w*\(|/dev/tcp/|"
    r"Invoke-WebRequest|Invoke-RestMethod|"
    r"https?://"
    r")",
    _I,
)

# Dumping the environment straight to the network.
_ENV_EXFIL = re.compile(r"\b(?:printenv|env|set)\b[^\n|]*\|\s*(?:curl|wget|nc|ncat|http)", _I)


def check(unit: SkillUnit) -> list:
    findings: list = []
    for t in text_targets(unit, kinds=("script", "markdown", "manifest")):
        text = t.text

        for m in _ENV_EXFIL.finditer(text):
            findings.append(_mk(t, text, m.start(), Severity.HIGH,
                "Environment piped to the network",
                "Dumps environment variables (which routinely hold secrets) straight to a network command.",
                "Never send environment variables off the machine."))

        for m in _SINK.finditer(text):
            findings.append(_mk(t, text, m.start(), Severity.HIGH,
                "Known data-collection endpoint",
                f"References {m.group(0)!r}, a tunnel/paste/webhook endpoint whose purpose is receiving data out-of-band.",
                "Remove the endpoint. Skills should not phone home to collector services."))

        sens = list(_SENSITIVE.finditer(text))
        has_egress = _EGRESS.search(text) is not None
        if sens and has_egress:
            m = sens[0]
            findings.append(_mk(t, text, m.start(), Severity.CRITICAL,
                "Reads sensitive files and can send them out",
                f"This file references credential material ({m.group(0)!r}) and also contains network-egress code — the shape of a credential stealer.",
                "Separate any legitimate file access from network calls, and never read credential stores."))
        else:
            for m in sens:
                findings.append(_mk(t, text, m.start(), Severity.MEDIUM,
                    "References a sensitive credential path",
                    f"Reads or names {m.group(0)!r}, a location that holds secrets. Confirm the skill has a real need for it.",
                    "Avoid touching credential stores unless it is the skill's explicit, documented purpose."))
    return findings


def _mk(t, text, i, sev, title, detail, remediation) -> Finding:
    line, col = line_col(text, i)
    return Finding(
        rule_id=RULE_ID,
        category=Category.EXFILTRATION,
        severity=sev,
        title=title,
        detail=detail,
        file=t.relpath,
        line=line,
        column=col,
        snippet=snippet_for(text, i),
        remediation=remediation,
    )
