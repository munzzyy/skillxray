"""Credential shapes. SX-SEC reports them, and redact() strips them out of
every snippet and detail, so a key that happens to sit on a line another rule
flags is never echoed back either.

This lives outside rules/ because finding.py needs redact(), and the rules
package imports finding.py.
"""

from __future__ import annotations

import re

REDACTED = "(redacted)"

# (compiled, severity name, label)
PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     "critical", "private key block"),
    (re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"), "critical", "Stripe live secret key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high", "AWS access key id"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "high", "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), "high", "GitHub fine-grained PAT"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "high", "Anthropic API key"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"), "high", "OpenAI API key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high", "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high", "Google API key"),
    (re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b"), "high", "GitLab personal access token"),
    (re.compile(r"\bhooks\.slack\.com/services/T[A-Za-z0-9/]{20,}"), "medium", "Slack incoming webhook"),
    # Discord bot token: base64 bot id, then a fixed-width timestamp segment,
    # then a 27-char HMAC segment, dot-separated. The `Bot ` header form is
    # the same token with the prefix skills sometimes paste in whole.
    (re.compile(r"\b[MN][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}\b"),
     "high", "Discord bot token"),
    (re.compile(r"\bBot [A-Za-z\d_-]{59,68}\b"), "high", "Discord bot token"),
    # Telegram bot token: numeric bot id, colon, 35-char secret.
    (re.compile(r"\b\d{8,10}:[A-Za-z\d_-]{35}\b"), "high", "Telegram bot token"),
]

# A key ending in one of these tokens, optionally prefixed by another
# identifier segment. STRIPE_SECRET_KEY is exactly as live as SECRET_KEY on
# its own, but "_" is a word character, so a plain \b...\b never sees the
# prefixed form -- there's no boundary between the prefix and the token.
# Capturing (matches the original single-group key) so the prefix shows up in
# the finding text too -- "A STRIPE_SECRET_KEY is assigned..." is a more
# useful message than just "A secret_key is assigned...".
_SECRET_KEY = (
    r"\b([\w-]*(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|"
    r"password|passwd))\b"
)

# Generic assignment of something key-shaped. Kept LOW and placeholder-filtered.
GENERIC = re.compile(r"(?i)" + _SECRET_KEY + r"\s*[:=]\s*[\"']([^\"'\n]{12,})[\"']")
# Unquoted form -- .env files and shell exports routinely skip the quotes
# entirely (`STRIPE_SECRET_KEY=sk_live_...`), and that is exactly as live a
# leak as the quoted form above.
GENERIC_UNQUOTED = re.compile(r"(?i)" + _SECRET_KEY + r"\s*[:=]\s*([^\s;&|`\"'\n]{12,})")
_PLACEHOLDER = re.compile(
    r"(?i)^(?:your|my|the|a|some|example|sample|dummy|test|fake|placeholder|change[_-]?me|"
    r"xxx+|\.{3,}|<[^>]+>|\$\{?[a-z_]+\}?|todo|redacted|none|null|abc123|password)")


def looks_real(value: str) -> bool:
    """False for placeholders and low-entropy filler like "aaaaaaaaaaaa"."""
    return not _PLACEHOLDER.match(value) and len(set(value)) >= 6


def _redact_value(m: re.Match) -> str:
    if not looks_real(m.group(2).strip()):
        return m.group(0)
    whole, start = m.group(0), m.start(0)
    return whole[: m.start(2) - start] + REDACTED + whole[m.end(2) - start:]


def redact(text: str) -> str:
    """Replace every credential-shaped value in text with REDACTED."""
    for rx, _sev, _label in PATTERNS:
        text = rx.sub(REDACTED, text)
    for rx in (GENERIC, GENERIC_UNQUOTED):
        text = rx.sub(_redact_value, text)
    return text
