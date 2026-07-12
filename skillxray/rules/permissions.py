"""Review what a skill or plugin is allowed to do: broad tool grants, auto-running
hooks, and MCP servers that launch local binaries. These are not exploits on their
own, but they are the capability that turns a bad instruction into a real action,
so a reviewer should always see them.
"""

from __future__ import annotations

import json

from ..finding import Finding, Category, Severity, escape_control_chars
from ..discovery import SkillUnit

RULE_ID = "SX-PRM"

# Claude Code hook events — a command under any of these runs shell automatically
# when the event fires, without the model choosing to.
_HOOK_EVENTS = {
    "PreToolUse", "PostToolUse", "UserPromptSubmit", "Notification",
    "Stop", "SubagentStop", "SessionStart", "SessionEnd", "PreCompact",
}


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
            "The frontmatter grants Bash/shell. Combined with any injected instruction, that is arbitrary command execution — worth confirming it is needed.",
            "Keep shell access only if the skill genuinely runs commands."))
    return findings


def _json_manifest(unit: SkillUnit, t) -> list:
    try:
        data = json.loads(t.text)
    except (ValueError, TypeError):
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
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return findings
    for event, entries in hooks.items():
        if event not in _HOOK_EVENTS:
            continue
        commands = _collect_hook_commands(entries)
        for cmd in commands:
            findings.append(_mk(RULE_ID, Category.PERMISSION, Severity.HIGH, rel,
                f"Auto-running hook on {event}",
                f"A {event} hook runs `{_trim(cmd)}` automatically when the event fires — shell execution with the model out of the loop. Review it as carefully as any executable.",
                "Confirm the hook command is safe and expected; auto-run hooks are a direct code-execution path."))
    return findings


def _collect_hook_commands(entries) -> list:
    out = []
    if isinstance(entries, list):
        for e in entries:
            if isinstance(e, dict):
                inner = e.get("hooks")
                if isinstance(inner, list):
                    for h in inner:
                        if isinstance(h, dict) and h.get("command"):
                            out.append(str(h["command"]))
                elif e.get("command"):
                    out.append(str(e["command"]))
    return out


def _scan_mcp(rel: str, data) -> list:
    findings = []
    servers = None
    if isinstance(data, dict):
        servers = data.get("mcpServers") or data.get("mcp_servers")
    if not isinstance(servers, dict):
        return findings
    for sname, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = cfg.get("command")
        if cmd:
            args = cfg.get("args") or []
            full = " ".join([str(cmd)] + [str(a) for a in args]) if isinstance(args, list) else str(cmd)
            sev = Severity.MEDIUM if str(cmd) in ("npx", "uvx", "bunx", "pnpm", "yarn") else Severity.HIGH
            findings.append(_mk(RULE_ID, Category.PERMISSION, sev, rel,
                f"MCP server '{sname}' launches a local process",
                f"Starts `{_trim(full)}`. Whatever that command resolves to runs on the machine with the skill's trust.",
                "Confirm the command and any fetched package are trusted and pinned."))
        elif cfg.get("url"):
            findings.append(_mk(RULE_ID, Category.PERMISSION, Severity.INFO, rel,
                f"MCP server '{sname}' is remote",
                f"Connects to {cfg.get('url')}. Tool definitions come from that server and are outside this skill's control.",
                "Make sure the remote server is one you trust."))
    return findings


def _trim(s: str, n: int = 80) -> str:
    s = escape_control_chars(" ".join(str(s).split()))
    return s if len(s) <= n else s[: n - 1] + "…"


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
