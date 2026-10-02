"""The parts of a JSON manifest that run something: hook commands and MCP
server launch lines. SX-PRM reports that they exist, SX-CMD reads what they
say, and both need the same view of the file."""

from __future__ import annotations

import json


def load(target):
    """The parsed JSON, or None when the file is not valid JSON."""
    try:
        return json.loads(target.text)
    except (ValueError, TypeError, RecursionError):
        return None


def hook_commands(data) -> list:
    """[(event, command)] for every hook under every event name. The event
    list grows with each Claude Code release, so none is assumed."""
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return []
    out = []
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        for e in entries:
            if not isinstance(e, dict):
                continue
            inner = e.get("hooks")
            if isinstance(inner, list):
                for h in inner:
                    if isinstance(h, dict) and h.get("command"):
                        out.append((str(event), str(h["command"])))
            elif e.get("command"):
                out.append((str(event), str(e["command"])))
    return out


def mcp_servers(data) -> list:
    """[(name, config)] for each server entry that is a mapping."""
    servers = None
    if isinstance(data, dict):
        servers = data.get("mcpServers") or data.get("mcp_servers")
    if not isinstance(servers, dict):
        return []
    return [(str(name), cfg) for name, cfg in servers.items() if isinstance(cfg, dict)]


def launch_parts(cfg) -> list:
    """The command and its args as separate strings, or [] for a server that
    launches nothing locally."""
    cmd = cfg.get("command")
    if not cmd:
        return []
    args = cfg.get("args") or []
    if not isinstance(args, list):
        return [str(cmd)]
    return [str(cmd)] + [str(a) for a in args]
