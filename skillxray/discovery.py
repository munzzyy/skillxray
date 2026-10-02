"""Find skill units on disk and load their files for scanning.

A "skill unit" is one of:
  - a directory containing a SKILL.md (an Agent Skill),
  - a directory containing .claude-plugin/plugin.json (a Claude Code plugin),
  - a lone SKILL.md pointed at directly,
  - a lone zip bundle (.zip, .skill, .mcpb, .dxt) pointed at directly,
  - the files of a scanned folder that sit outside every skill and plugin in
    it (a repo's installer, README and settings), labeled ROOT_LABEL.

We deliberately avoid a YAML dependency. Frontmatter is parsed by a small,
tolerant reader that handles the scalars and simple lists skills actually use
(name, description, license, allowed-tools). It is not a general YAML parser and
does not try to be - it only needs enough to reason about a handful of keys.
"""

from __future__ import annotations

import fnmatch
import os
import re
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Optional

from .finding import escape_control_chars

# Anything that can carry executable logic. Windows batch and PowerShell modules
# belong here as much as .sh does: a payload in setup.bat is still a payload, and
# leaving an extension out of this set means the command and exfiltration rules
# never read the file at all.
SCRIPT_EXTS = {
    ".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb",
    ".pl", ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".fish", ".ksh",
    ".command", ".tcl", ".lua", ".php",
}
TEXT_EXTS = SCRIPT_EXTS | {
    ".md", ".markdown", ".txt", ".json", ".yaml", ".yml", ".toml",
    ".cfg", ".ini", ".env", ".rst",
}
# SKILL.md is intentionally NOT here - it is markdown prose (with frontmatter),
# and the command/injection rules need to read it as markdown. Its manifest-like
# frontmatter is handled through unit.frontmatter, not the file kind.
MANIFEST_NAMES = {
    "plugin.json", ".mcp.json", "mcp.json", "hooks.json", "settings.json",
    "settings.local.json",
}
# Directories never worth scanning.
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
             "build", ".mypy_cache", ".pytest_cache", ".idea", ".vscode"}
MAX_FILE_BYTES = 2_000_000  # skip anything larger; skills should be small
ROOT_LABEL = "(repo root)"

# Zip containers skills and MCP bundles ship in. Members are read in memory,
# never written to disk, and an archive inside one is reported, not opened.
ARCHIVE_EXTS = {".zip", ".skill", ".mcpb", ".dxt"}
MAX_ARCHIVE_BYTES = 50_000_000
MAX_ARCHIVE_MEMBERS = 2_000
MAX_ARCHIVE_TOTAL = 50_000_000  # uncompressed bytes read from one archive
_ZIP_MAGIC = b"PK\x03\x04"

# A shebang line naming a real interpreter. Extension lists always have holes,
# so the file's own first line gets the final say: an extensionless `install`
# that starts with `#!/bin/bash` is a script whatever it is called.
_SHEBANG = re.compile(
    r"^#!\s*\S*?\b(?:sh|bash|zsh|dash|ksh|fish|tcsh|csh|python[0-9.]*|perl|ruby|"
    r"node|deno|bun|php|lua|tclsh|osascript|pwsh|powershell|env)\b"
)


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
    kind: str  # markdown | script | manifest | data | binary | symlink
    raw: bytes = b""
    text: str = ""
    decode_error: bool = False
    oversized: bool = False  # bigger than MAX_FILE_BYTES; only the prefix was read
    link: str = ""  # kind == "symlink": where it points, never followed
    archive: bool = False  # opened as a zip; its members follow it in unit.files
    notes: list = field(default_factory=list)  # [(code, detail)] from reading the archive

    @property
    def is_text(self) -> bool:
        return self.kind not in ("binary", "symlink")


@dataclass
class SkillUnit:
    root: Path
    kind: str  # skill | plugin | loose | root
    skill_md: Optional[ScanTarget] = None
    files: list = field(default_factory=list)  # list[ScanTarget]
    frontmatter: dict = field(default_factory=dict)
    label: str = ""

    @property
    def name(self) -> str:
        if self.label:
            return self.label
        fm_name = self.frontmatter.get("name")
        if isinstance(fm_name, str) and fm_name.strip():
            return fm_name.strip()
        return self.root.name


def _inside(path: Path, root: Path) -> bool:
    try:
        Path(os.path.realpath(path)).relative_to(os.path.realpath(root))
        return True
    except ValueError:
        return False


def _read(path: Path, root: Path, unit_root: Optional[Path] = None) -> Optional[ScanTarget]:
    # Relative paths are emitted verbatim into the report, into JSON, and into
    # SARIF artifactLocation.uri, which must be a forward-slash URI reference.
    # Normalize once here so every renderer agrees and Windows output is usable.
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = path.name
    rel = rel.replace(os.sep, "/")
    if os.altsep:
        rel = rel.replace(os.altsep, "/")
    # Never fail open on a big file: instead of skipping it wholesale (which lets
    # an attacker hide a payload behind 2 MB of padding), scan the first
    # MAX_FILE_BYTES and flag it oversized so the prefix is still checked.
    oversized = False
    try:
        # A link out of the skill can reach any file on the machine running the
        # scan, or /dev/stdin and hang it, so it is reported and never opened.
        if unit_root is not None and path.is_symlink() and not _inside(path, unit_root):
            return ScanTarget(path=path, relpath=rel, kind="symlink", link=os.readlink(path))
        st = path.stat()
        if not stat.S_ISREG(st.st_mode):
            return None  # a FIFO or device blocks or never ends; neither holds skill text
        oversized = st.st_size > MAX_FILE_BYTES
        with open(path, "rb") as fh:
            raw = fh.read(MAX_FILE_BYTES)
    except OSError:
        return None
    return _decode(ScanTarget(path=path, relpath=rel, kind=classify(path), raw=raw,
                              oversized=oversized))


def _decode(target: ScanTarget) -> ScanTarget:
    raw = target.raw
    if target.kind == "binary":
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
    # The shebang wins over the extension, but never demotes markdown or a
    # manifest: those are read whole by their own rules already.
    if target.kind == "data" and _SHEBANG.match(target.text):
        target.kind = "script"
    return target


def _archive_members(t: ScanTarget) -> list:
    """The archive's members as ScanTargets named `archive!member`. Whatever
    stops a full read becomes a note on the archive for SX-SUP to report."""
    try:
        size = t.path.stat().st_size
    except OSError:
        return []
    if size > MAX_ARCHIVE_BYTES:
        t.notes.append(("too-large", f"{size:,} bytes"))
        return []
    try:
        zf = zipfile.ZipFile(t.path)
    except Exception:  # hostile input: a parse failure is a finding, never a traceback
        t.notes.append(("unreadable", ""))
        return []
    members: list = []
    total = 0
    with zf:
        t.archive = True
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            t.notes.append(("too-many", f"{len(infos):,} entries"))
            infos = infos[:MAX_ARCHIVE_MEMBERS]
        for info in infos:
            name = escape_control_chars(info.filename)
            if info.flag_bits & 0x1:
                t.notes.append(("encrypted", name))
                continue
            if PurePosixPath(info.filename).suffix.lower() in ARCHIVE_EXTS:
                t.notes.append(("nested", name))
                continue
            budget = min(MAX_FILE_BYTES, MAX_ARCHIVE_TOTAL - total)
            if budget <= 0:
                t.notes.append(("too-much", name))
                break
            try:
                with zf.open(info) as fh:
                    raw = fh.read(budget)
            except Exception:  # bad CRC, unsupported compression, truncated data
                t.notes.append(("bad-member", name))
                continue
            total += len(raw)
            if raw.startswith(_ZIP_MAGIC):
                t.notes.append(("nested", name))
                continue
            members.append(_decode(ScanTarget(
                path=PurePosixPath(info.filename), relpath=f"{t.relpath}!{name}",
                kind=classify(PurePosixPath(info.filename)), raw=raw,
                oversized=info.file_size > MAX_FILE_BYTES)))
            if len(raw) < min(info.file_size, MAX_FILE_BYTES):
                t.notes.append(("too-much", name))
                break
    return members


def _norm(rel: str) -> str:
    rel = rel.replace(os.sep, "/")
    return rel.replace(os.altsep, "/") if os.altsep else rel


def excluded(rel: str, patterns) -> bool:
    """True if a scan-root-relative path matches any --exclude glob.

    Matching happens on the POSIX-normalized form so one glob behaves the same
    on Windows, and a bare directory glob covers everything under it.
    """
    if not patterns:
        return False
    rel = _norm(rel)
    for pat in patterns:
        pat = _norm(pat)
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat.rstrip("/") + "/*"):
            return True
    return False


def _rel_to(path: Path, base: Path) -> str:
    try:
        return _norm(str(path.relative_to(base)))
    except ValueError:
        return _norm(str(path))


def _iter_files(root: Path, rel_base: Path, exclude=()):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS
            and not excluded(_rel_to(Path(dirpath) / d, rel_base), exclude)
        ]
        for fn in filenames:
            fp = Path(dirpath) / fn
            if excluded(_rel_to(fp, rel_base), exclude):
                continue
            yield fp


def parse_frontmatter(text: str) -> dict:
    """Read the leading `---` fenced block into a flat dict.

    Supports `key: value`, quoted values, and simple block/inline lists. Nested
    mappings are ignored (returned as raw strings) - good enough for the keys we
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
    for ln in lines[1:]:
        # `---` or `...` both close a YAML document. Don't bail on an unclosed
        # block either: a tolerant parser in the agent would still read those
        # keys, so we parse whatever frontmatter is present rather than fail open.
        if ln.strip() in ("---", "..."):
            break
        body.append(ln)
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


def discover(path: Path, rel_base: Optional[Path] = None, exclude=()) -> list:
    """Return the skill units under `path` (or the single unit it names).

    `rel_base` is the folder the user asked for, or the folder holding the file
    they named. Every finding's file is reported relative to it, so a scan of a
    folder of skills says `alpha/SKILL.md` instead of a bare `SKILL.md` that
    nothing can be traced to, and naming a skill's SKILL.md reports the same
    paths as naming its folder.
    """
    path = Path(path)
    units: list = []
    if rel_base is None:
        rel_base = path if path.is_dir() else path.parent

    if path.is_file() and path.suffix.lower() in ARCHIVE_EXTS:
        units.append(_build_unit(path.parent, kind="loose", rel_base=rel_base,
                                 exclude=exclude, paths=[path]))
        return units

    if path.is_file() and path.name.lower() == "skill.md":
        # Scan the whole skill, not just the markdown. Pre-commit hands us the
        # SKILL.md path and nothing else, and most payloads live in a sibling
        # script - limiting the unit to one file meant the hook the README
        # advertises passed every skill whose payload was not inline.
        unit = _build_unit(path.parent, kind="skill", rel_base=rel_base, exclude=exclude)
        if unit:
            units.append(unit)
        return units

    if not path.is_dir():
        return units

    # A directory that is itself a single skill/plugin.
    direct = _unit_kind(path)
    if direct:
        unit = _build_unit(path, kind=direct, rel_base=rel_base, exclude=exclude)
        if unit:
            units.append(unit)
        return units

    # Otherwise treat it as a collection: find nested skill/plugin roots. A
    # unit never nests inside another, so the walk stops at each one, and every
    # file it passes on the way is a leftover that belongs to no unit.
    leftovers: list = []
    for dirpath, dirnames, filenames in os.walk(path):
        d = Path(dirpath)
        kind = _unit_kind(d) if d != path else None
        if kind:
            units.append(_build_unit(d, kind=kind, rel_base=rel_base, exclude=exclude))
            dirnames[:] = []
            continue
        dirnames[:] = [
            dn for dn in dirnames
            if dn not in SKIP_DIRS
            and not excluded(_rel_to(d / dn, rel_base), exclude)
        ]
        for fn in filenames:
            fp = d / fn
            if not excluded(_rel_to(fp, rel_base), exclude):
                leftovers.append(fp)
    if not units:
        # No formal skill markers: scan the directory as a loose unit so the
        # user still gets results instead of silence.
        unit = _build_unit(path, kind="loose", rel_base=rel_base, exclude=exclude)
        if unit.files:
            units.append(unit)
    elif leftovers:
        # A repo with a skills/ folder still ships its installer, README and
        # hooks at the root, and those run too.
        units.append(_build_unit(path, kind="root", rel_base=rel_base,
                                 exclude=exclude, paths=leftovers, label=ROOT_LABEL))
    return units


def _unit_kind(d: Path) -> Optional[str]:
    if (d / "SKILL.md").is_file():
        return "skill"
    if (d / ".claude-plugin" / "plugin.json").is_file() or (d / "plugin.json").is_file():
        return "plugin"
    return None


def _build_unit(root: Path, kind: str, rel_base: Optional[Path] = None,
                exclude=(), paths=None, label: str = "") -> SkillUnit:
    unit = SkillUnit(root=root, kind=kind, label=label)
    base = root if rel_base is None else rel_base
    if paths is None:
        paths = _iter_files(root, base, exclude)
    for fp in paths:
        t = _read(fp, base, unit_root=root)
        if t is None:
            continue
        unit.files.append(t)
        if t.kind != "symlink" and fp.suffix.lower() in ARCHIVE_EXTS:
            unit.files.extend(_archive_members(t))
        if (kind != "root" and t.is_text and fp.name.lower() == "skill.md"
                and unit.skill_md is None):
            unit.skill_md = t
    if unit.skill_md is not None:
        unit.frontmatter = parse_frontmatter(unit.skill_md.text)
    return unit
