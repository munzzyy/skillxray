"""Review what a skill or plugin is allowed to do: broad tool grants, auto-running
hooks, and MCP servers that launch local binaries. These are not exploits on their
own, but they are the capability that turns a bad instruction into a real action,
so a reviewer should always see them.
"""

from __future__ import annotations

from ..finding import Finding, Category, Severity, escape_control_chars
from ..secret_shapes import redact
from ..discovery import SkillUnit
from . import _manifest

RULE_ID = "SX-PRM"
RULE_NAME = "Permissions and capability"
RULE_DESCRIPTION = (
    "What the skill is allowed to do: broad tool grants, MCP servers that launch "
    "local binaries, and hooks that run shell automatically on an event."
)
RULE_TAGS = ("security", "AST03")
RULE_LEVEL = "warning"


def check(unit: SkillUnit) -> list:
    findings: list = []
    findings += _allowed_tools(unit)
    for t in unit.files:
        if t.kind != "manifest":
            continue
        name = t.path.name.lower()
        if name.endswith(".json"):
            findings += _json_manifest(unit, t)
    return findings


def _allowed_tools(unit: SkillUnit) -> list:
    fm = unit.frontmatter or {}
    tools = None
    for key in ("allowed-tools", "allowed_tools", "allowedTools", "tools"):
        if key in fm:
            tools = fm[key]
            break
    if tools is None:
        return []
    if isinstance(tools, str):
        items = [x.strip() for x in tools.replace(",", " ").split()]
    elif isinstance(tools, list):
        items = [str(x).strip() for x in tools]
    else:
        return []
    rel = unit.skill_md.relpath if unit.skill_md else "SKILL.md"
    findings = []
    lowered = [i.lower() for i in items]
    if any(i in ("*", "all") for i in lowered):
        findings.append(_mk(RULE_ID, Category.PERMISSION, Severity.MEDIUM, rel,
            "Skill requests all tools",
            "The frontmatter grants every tool (\"*\"). That includes shell and network access. Grant only what the skill uses.",
            "List the specific tools the skill needs."))
    elif any("bash" in i or "shell" in i for i in lowered):
        findings.append(_mk(RULE_ID, Category.PERMISSION, Severity.INFO, rel,
            "Skill can run shell commands",
            "The frontmatter grants Bash/shell. Combined with any injected instruction, that is arbitrary command execution - worth confirming it is needed.",
            "Keep shell access only if the skill genuinely runs commands."))
    return findings


def _json_manifest(unit: SkillUnit, t) -> list:
    data = _manifest.load(t)
    if data is None:
        return [_mk(RULE_ID, Category.PERMISSION, Severity.LOW, t.relpath,
                    "Manifest is not valid JSON",
                    "This manifest could not be parsed, so its declared permissions could not be reviewed.",
                    "Fix the JSON so tools (and reviewers) can read it.")]
    findings = []
    findings += _scan_hooks(t.relpath, data)
    findings += _scan_mcp(t.relpath, data)
    return findings


def _scan_hooks(rel: str, data) -> list:
    findings = []
    for event, cmd in _manifest.hook_commands(data):
        event = _trim(event, 40)  # an untrusted key that lands in the title
        findings.append(_mk(RULE_ID, Category.PERMISSION, Severity.HIGH, rel,
            f"Auto-running hook on {event}",
            f"A {event} hook runs `{_trim(cmd)}` automatically when the event fires - shell execution with the model out of the loop. Review it as carefully as any executable.",
            "Confirm the hook command is safe and expected; auto-run hooks are a direct code-execution path."))
    return findings


def _scan_mcp(rel: str, data) -> list:
    findings = []
    for sname, cfg in _manifest.mcp_servers(data):
        # The server name is a JSON key and the url is a JSON value, both read
        # straight out of an untrusted manifest. They get the same control-byte
        # escaping as any other scanned text, or a crafted plugin.json can paint
        # a forged verdict into the report with terminal escape sequences.
        safe_name = _trim(sname)
        parts = _manifest.launch_parts(cfg)
        if parts:
            sev = Severity.MEDIUM if parts[0] in ("npx", "uvx", "bunx", "pnpm", "yarn") else Severity.HIGH
            findings.append(_mk(RULE_ID, Category.PERMISSION, sev, rel,
                f"MCP server '{safe_name}' launches a local process",
                f"Starts `{_trim(' '.join(parts))}`. Whatever that command resolves to runs on the machine with the skill's trust.",
                "Confirm the command and any fetched package are trusted and pinned."))
        elif cfg.get("url"):
            findings.append(_mk(RULE_ID, Category.PERMISSION, Severity.INFO, rel,
                f"MCP server '{safe_name}' is remote",
                f"Connects to {_trim(cfg.get('url'))}. Tool definitions come from that server and are outside this skill's control.",
                "Make sure the remote server is one you trust."))
    return findings


def _trim(s: str, n: int = 80) -> str:
    s = escape_control_chars(redact(" ".join(str(s).split())[: n + 512]))
    return s if len(s) <= n else s[: n - 1] + "..."


def _mk(rule_id, category, severity, rel, title, detail, remediation) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        detail=detail,
        file=rel,
        line=0,
        column=0,
        snippet="",
        remediation=remediation,
    )
