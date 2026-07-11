"""Find skill units on disk and load their files for scanning.

A "skill unit" is one of:
  - a directory containing a SKILL.md (an Agent Skill),
  - a directory containing .claude-plugin/plugin.json (a Claude Code plugin),
  - a lone SKILL.md pointed at directly.

We deliberately avoid a YAML dependency. Frontmatter is parsed by a small,
tolerant reader that handles the scalars and simple lists skills actually use
(name, description, license, allowed-tools). It is not a general YAML parser and
does not try to be — it only needs enough to reason about a handful of keys.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

TEXT_EXTS = {
    ".md", ".markdown", ".txt", ".sh", ".bash", ".zsh", ".py", ".js", ".mjs",
    ".cjs", ".ts", ".rb", ".pl", ".ps1", ".json", ".yaml", ".yml", ".toml",
    ".cfg", ".ini", ".env", ".rst",
}
SCRIPT_EXTS = {
    ".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb",
    ".pl", ".ps1",
}
# SKILL.md is intentionally NOT here — it is markdown prose (with frontmatter),
# and the command/injection rules need to read it as markdown. Its manifest-like
# frontmatter is handled through unit.frontmatter, not the file kind.
MANIFEST_NAMES = {
    "plugin.json", ".mcp.json", "mcp.json", "hooks.json", "settings.json",
}
# Directories never worth scanning.
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
             "build", ".mypy_cache", ".pytest_cache", ".idea", ".vscode"}
MAX_FILE_BYTES = 2_000_000  # skip anything larger; skills should be small


def classify(path: Path) -> str:
    name = path.name.lower()
    ext = path.suffix.lower()
    if name in MANIFEST_NAMES or name.endswith(".mcp.json"):
        return "manifest"
    if ext in {".md", ".markdown", ".rst", ".txt"}:
        return "markdown"
    if ext in SCRIPT_EXTS:
        return "script"
    if ext in TEXT_EXTS:
        return "data"
    return "binary"


@dataclass
class ScanTarget:
    path: Path
    relpath: str
    kind: str  # markdown | script | manifest | data | binary
    raw: bytes = b""
    text: str = ""
    decode_error: bool = False

    @property
    def is_text(self) -> bool:
        return self.kind != "binary"


@dataclass
class SkillUnit:
    root: Path
    kind: str  # skill | plugin | loose
    skill_md: Optional[ScanTarget] = None
    files: list = field(default_factory=list)  # list[ScanTarget]
    frontmatter: dict = field(default_factory=dict)

    @property
    def name(self) -> str:
        fm_name = self.frontmatter.get("name")
        if isinstance(fm_name, str) and fm_name.strip():
            return fm_name.strip()
        return self.root.name


def _read(path: Path, root: Path) -> Optional[ScanTarget]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    kind = classify(path)
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = path.name
    target = ScanTarget(path=path, relpath=rel, kind=kind, raw=raw)
    if kind == "binary":
        # Salvage files with an unknown extension that are really UTF-8 text
        # (e.g. .pem keys, extensionless configs) so their contents get scanned.
        if b"\x00" not in raw:
            try:
                target.text = raw.decode("utf-8")
                target.kind = "data"
            except UnicodeDecodeError:
                pass
    else:
        try:
            target.text = raw.decode("utf-8")
        except UnicodeDecodeError:
            target.text = raw.decode("utf-8", errors="replace")
            target.decode_error = True
    return target


def _iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            yield Path(dirpath) / fn


def parse_frontmatter(text: str) -> dict:
    """Read the leading `---` fenced block into a flat dict.

    Supports `key: value`, quoted values, and simple block/inline lists. Nested
    mappings are ignored (returned as raw strings) — good enough for the keys we
    care about, and never raises on malformed input.
    """
    if not text.startswith("---"):
        # tolerate a leading blank line / BOM
        stripped = text.lstrip("\ufeff\n\r ")
        if not stripped.startswith("---"):
            return {}
        text = stripped
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    body = []
    closed = False
    for ln in lines[1:]:
        if ln.strip() == "---":
            closed = True
            break
        body.append(ln)
    if not closed:
        return {}
    out: dict = {}
    key = None
    for ln in body:
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        if ln[:1] in (" ", "\t") and ln.strip().startswith("- ") and key:
            out.setdefault(key, [])
            if isinstance(out[key], list):
                out[key].append(_scalar(ln.strip()[2:]))
            continue
        if ":" not in ln:
            continue
        k, _, v = ln.partition(":")
        key = k.strip()
        v = v.strip()
        if v == "":
            out[key] = []  # may be filled by following block list
        elif v.startswith("[") and v.endswith("]"):
            inner = v[1:-1].strip()
            out[key] = [_scalar(x) for x in _split_inline(inner)] if inner else []
        else:
            out[key] = _scalar(v)
    return out


def _split_inline(inner: str) -> list:
    parts, buf, quote = [], [], None
    for ch in inner:
        if quote:
            if ch == quote:
                quote = None
            else:
                buf.append(ch)
        elif ch in "\"'":
            quote = ch
        elif ch == ",":
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p]


def _scalar(v: str):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def discover(path: Path) -> list:
    """Return the skill units under `path` (or the single unit it names)."""
    path = Path(path)
    units: list = []

    if path.is_file() and path.name.lower() == "skill.md":
        root = path.parent
        unit = _build_unit(root, kind="skill", limit_to_file=path)
        if unit:
            units.append(unit)
        return units

    if not path.is_dir():
        return units

    # A directory that is itself a single skill/plugin.
    direct = _unit_kind(path)
    if direct:
        unit = _build_unit(path, kind=direct)
        if unit:
            units.append(unit)
        return units

    # Otherwise treat it as a collection: find nested skill/plugin roots.
    seen_roots: set = set()
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        d = Path(dirpath)
        kind = _unit_kind(d)
        if kind and d not in seen_roots:
            # avoid nesting a skill inside an already-claimed plugin root
            if any(str(d).startswith(str(r) + os.sep) for r in seen_roots):
                continue
            unit = _build_unit(d, kind=kind)
            if unit:
                units.append(unit)
                seen_roots.add(d)
    if not units:
        # No formal skill markers: scan the directory as a loose unit so the
        # user still gets results instead of silence.
        unit = _build_unit(path, kind="loose")
        if unit and unit.files:
            units.append(unit)
    return units


def _unit_kind(d: Path) -> Optional[str]:
    if (d / "SKILL.md").is_file():
        return "skill"
    if (d / ".claude-plugin" / "plugin.json").is_file() or (d / "plugin.json").is_file():
        return "plugin"
    return None


def _build_unit(root: Path, kind: str, limit_to_file: Optional[Path] = None) -> Optional[SkillUnit]:
    unit = SkillUnit(root=root, kind=kind)
    if limit_to_file is not None:
        t = _read(limit_to_file, root)
        if t:
            unit.files.append(t)
            unit.skill_md = t
    else:
        for fp in _iter_files(root):
            t = _read(fp, root)
            if t is None:
                continue
            unit.files.append(t)
            if fp.name.lower() == "skill.md" and unit.skill_md is None:
                unit.skill_md = t
    if unit.skill_md is not None:
        unit.frontmatter = parse_frontmatter(unit.skill_md.text)
    return unit
