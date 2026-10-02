"""Core types: severities, categories, findings, and text helpers."""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import Optional

from .secret_shapes import redact


class Severity(enum.IntEnum):
    """Ordered so comparisons and sorting work (higher = worse)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {name!r}")


class Category(str, enum.Enum):
    INJECTION = "prompt-injection"
    UNICODE = "hidden-unicode"
    DANGEROUS_COMMAND = "dangerous-command"
    EXFILTRATION = "data-exfiltration"
    SECRET = "hardcoded-secret"
    PERMISSION = "permissions"
    SUPPLY_CHAIN = "supply-chain"
    QUALITY = "quality"

    def __str__(self) -> str:  # nicer output in reports
        return self.value


# Categories that count toward the security grade. QUALITY is hygiene, not security.
SECURITY_CATEGORIES = frozenset(
    c for c in Category if c is not Category.QUALITY
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: Category
    severity: Severity
    title: str
    detail: str
    file: str  # path relative to the scanned root, or "" if not file-bound
    line: int = 0  # 1-based; 0 = not line-bound
    column: int = 0  # 1-based
    snippet: str = ""
    remediation: str = ""
    unit: str = ""  # name of the skill unit the finding came from
    uri_base: str = ""  # scanned folder relative to the working directory, for SARIF

    def sort_key(self):
        # Worst first, then by location for stable output.
        return (-int(self.severity), self.category.value, self.file, self.line)


@dataclass
class ScanResult:
    root: str
    findings: list = field(default_factory=list)
    hygiene_checks: list = field(default_factory=list)  # list[(name, bool, detail)]
    scanned_files: int = 0
    units: int = 0
    grade: str = "A"
    grade_score: int = 100

    @property
    def hygiene_passed(self) -> int:
        return sum(1 for _n, ok, _d in self.hygiene_checks if ok)

    @property
    def hygiene_total(self) -> int:
        return len(self.hygiene_checks)

    def counts(self) -> dict:
        out = {s: 0 for s in Severity}
        for f in self.findings:
            out[f.severity] += 1
        return out


def line_col(text: str, index: int) -> tuple[int, int]:
    """1-based (line, column) for a character offset into text."""
    if index < 0:
        index = 0
    if index > len(text):
        index = len(text)
    line = text.count("\n", 0, index) + 1
    last_nl = text.rfind("\n", 0, index)
    col = index - last_nl  # last_nl is -1 when none, giving 1-based col
    return line, col


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
# Characters that render as nothing or reorder the text around them: bidi
# controls, zero-width and other invisible format characters, the line and
# paragraph separators, and the tag block.
_INVISIBLE_RE = re.compile(
    "[\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff"
    "\U000e0000-\U000e007f]"
)


def escape_control_chars(text: str) -> str:
    """Replace any C0/C1 control byte -- ESC included -- with a visible \\xNN
    placeholder, and any invisible or reordering character with <U+XXXX>.
    Snippets and finding details are built from scanned file content, which
    is untrusted: without this, a crafted file can plant terminal escape codes
    that survive verbatim into the printed report, or hide the very text a
    finding is pointing at."""
    text = _CONTROL_RE.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)
    return _INVISIBLE_RE.sub(lambda m: f"<U+{ord(m.group(0)):04X}>", text)


def snippet_for(text: str, index: int, width: int = 120) -> str:
    """The single source line containing `index`, trimmed, with any credential
    redacted, and truncated."""
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end == -1:
        end = len(text)
    # Redact before truncating, or a key cut at the edge slips past the patterns.
    line = escape_control_chars(redact(text[start:end].strip()[: width + 512]))
    if len(line) > width:
        line = line[: width - 1] + "..."
    return line
