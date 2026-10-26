#!/usr/bin/env python3
"""
run_agent.py
============
Runs any agent template in Agents/ on the Claude Agent SDK, with the approval
gate enforced in code rather than in the prompt.

    python Agents/tools/run_agent.py soc-triage --dry-run
    python Agents/tools/run_agent.py soc-triage --offline --prompt "Triage incident 48213."
    python Agents/tools/run_agent.py threat-hunter --prompt "Service accounts signed in interactively..."

--dry-run prints exactly what would be handed to the SDK and exits. It needs
no SDK, no API key, and no network - read it before you run anything.

A real run needs:

    pip install claude-agent-sdk                               # and an ANTHROPIC_API_KEY
    pip install -r demos/empowering-soc-teams/requirements.txt # only for --offline

How agent.json maps onto the SDK - the same mapping you would do by hand in
Security Copilot, Copilot Studio, or Foundry:

    system_prompt                     -> system_prompt
    output_schema                     -> output_format (json_schema)
    tool_allow_list.read              -> allowed_tools (runs without asking)
    tool_allow_list.write_requires_.. -> can_use_tool: stops and asks YOU, logs the answer
    everything else                   -> can_use_tool: refused, logged
    built-in tools (Bash, Write, ...) -> tools=[]: not available at all
    guardrails.max_tool_calls_per_run -> max_turns

--offline swaps in the replay MCP server and synthetic CONTOSO-PROD data, and
stands up local stubs for the write tools so you can watch the gate work.
The stubs record the call and write nothing.

The hosted Sentinel MCP server sits behind Entra OAuth. This runner does not do
the OAuth dance: put a delegated access token in SENTINEL_MCP_TOKEN, or use the
claude.ai connector / VS Code as described in
demos/empowering-soc-teams/01-mcp-connection/.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

AGENTS_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = AGENTS_DIR.parent
RUNS_DIR = AGENTS_DIR / "runs"


# --- loading -----------------------------------------------------------------

def find_agent(name: str) -> tuple[Path, dict[str, Any]]:
    for path in sorted(AGENTS_DIR.glob("[0-9][0-9]-*/agent.json")):
        agent = json.loads(path.read_text(encoding="utf-8"))
        if name in (agent["id"], path.parent.name):
            return path, agent
    known = [p.parent.name for p in AGENTS_DIR.glob("[0-9][0-9]-*/agent.json")]
    sys.exit(f"no agent named '{name}'. Known: {', '.join(sorted(known))}")


def mcp_name(server: str, tool: str) -> str:
    return f"mcp__{server}__{tool}"


# --- plan --------------------------------------------------------------------

def build_plan(agent: dict[str, Any], offline: bool) -> dict[str, Any]:
    """Everything the SDK will be given, as plain data. --dry-run prints this."""
    allow = agent["tool_allow_list"]
    writes = list(allow.get("write_requires_approval", []))
    servers: dict[str, Any] = {}
    read_tools: list[str] = []
    write_tools: list[str] = []

    if offline:
        profile = agent.get("offline_profile")
        if not profile:
            sys.exit(f"{agent['id']} has no offline_profile. Run it against a tenant, or use the demo scripts.")
        for s in profile["mcp_servers"]:
            servers[s["name"]] = {
                "type": "stdio",
                "command": sys.executable if s["command"] == "python" else s["command"],
                "args": [str(REPO_ROOT / a) if a.endswith(".py") else a for a in s.get("args", [])],
            }
            read_tools += [mcp_name(s["name"], t) for t in profile["read"]]
        if writes:
            servers["offline-write-stubs"] = {"type": "sdk", "tools": writes}
            write_tools = [mcp_name("offline-write-stubs", t) for t in writes]
    else:
        token = os.getenv("SENTINEL_MCP_TOKEN")
        for s in agent["mcp_servers"]:
            servers[s["name"]] = {"type": "http", "url": s["url"]}
            if token:
                servers[s["name"]]["headers"] = {"Authorization": "Bearer <SENTINEL_MCP_TOKEN>"}
            served = s.get("tools", allow.get("read", []) + writes)
            read_tools += [mcp_name(s["name"], t) for t in served if t in allow.get("read", [])]
            write_tools += [mcp_name(s["name"], t) for t in served if t in writes]

    return {
        "agent": agent["id"],
        "profile": "offline" if offline else "hosted",
        "system_prompt": agent["system_prompt"],
        "mcp_servers": servers,
        "allowed_tools": read_tools,
        "requires_approval": write_tools,
        "never": allow.get("never", []),
        "builtin_tools": [],
        "max_turns": agent["guardrails"].get("max_tool_calls_per_run", 30),
        "output_format": {"type": "json_schema", "schema": agent["output_schema"]},
    }


# --- run log -----------------------------------------------------------------

class RunLog:
    """What observability.logged_per_run asks for. Written to Agents/runs/."""

    def __init__(self, agent: dict[str, Any], plan: dict[str, Any], prompt: str):
        self.record: dict[str, Any] = {
            "agent": agent["id"],
            "version": agent["version"],
            "identity": agent["identity"].get("principal"),
            "profile": plan["profile"],
            "started": datetime.now(timezone.utc).isoformat(),
            "prompt": prompt,
            "tool_calls": [],
            "decisions": [],
            "refused": [],
            "proposal": None,
        }

    def save(self) -> Path:
        RUNS_DIR.mkdir(exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = RUNS_DIR / f"{self.record['agent']}-{stamp}.json"
        path.write_text(json.dumps(self.record, indent=2, default=str), encoding="utf-8")
        return path


# --- the gate ----------------------------------------------------------------

def ask_human(tool: str, args: dict[str, Any]) -> tuple[str, str]:
    print("\n" + "=" * 72)
    print(f"  APPROVAL REQUIRED  {tool}")
    print("=" * 72)
    print(json.dumps(args, indent=2))
    while True:
        choice = input("\n  [a]pprove  [r]eject > ").strip().lower()
        if choice in ("a", "approve"):
            return "approved", ""
        if choice in ("r", "reject"):
            return "rejected", input("  reason > ").strip() or "no reason given"


async def run(agent: dict[str, Any], plan: dict[str, Any], prompt: str, model: str | None) -> int:
    try:
        from claude_agent_sdk import (
            AssistantMessage, ClaudeAgentOptions, ClaudeSDKClient, ResultMessage,
            TextBlock, ToolUseBlock, create_sdk_mcp_server, tool,
        )
        from claude_agent_sdk.types import PermissionResultAllow, PermissionResultDeny
    except ImportError:
        print("claude-agent-sdk is not installed: pip install claude-agent-sdk")
        print("Or run with --dry-run to see the plan without it.")
        return 2

    log = RunLog(agent, plan, prompt)
    approval_needed = set(plan["requires_approval"])

    servers: dict[str, Any] = {}
    for name, cfg in plan["mcp_servers"].items():
        if cfg["type"] == "sdk":
            stubs = []
            for t in cfg["tools"]:
                def make(tool_name: str):
                    @tool(tool_name, f"OFFLINE STUB for {tool_name}. Records the call; writes nothing.",
                          {"type": "object", "properties": {
                              "incident": {"type": "integer"},
                              "value": {"type": "string", "description": "comment text, classification, or assignee"},
                          }, "required": ["incident", "value"]})
                    async def stub(args: dict[str, Any]) -> dict[str, Any]:
                        return {"content": [{"type": "text", "text": json.dumps(
                            {"status": "recorded", "tool": tool_name, "args": args,
                             "note": "offline stub - nothing was written"})}]}
                    return stub
                stubs.append(make(t))
            servers[name] = create_sdk_mcp_server(name=name, tools=stubs)
        elif cfg["type"] == "http" and "headers" in cfg:
            servers[name] = {**cfg, "headers": {"Authorization": f"Bearer {os.environ['SENTINEL_MCP_TOKEN']}"}}
        else:
            servers[name] = cfg

    async def gate(tool_name: str, args: dict[str, Any], _ctx: Any):
        if tool_name in approval_needed:
            outcome, reason = await asyncio.to_thread(ask_human, tool_name, args)
            log.record["decisions"].append({
                "tool": tool_name, "args": args, "outcome": outcome, "reason": reason,
                "by": os.getenv("USERNAME") or os.getenv("USER") or "unknown",
                "at": datetime.now(timezone.utc).isoformat(),
            })
            if outcome == "approved":
                return PermissionResultAllow()
            return PermissionResultDeny(message=f"Rejected by the analyst: {reason}. Re-plan with that as input.")
        log.record["refused"].append({"tool": tool_name, "args": args})
        return PermissionResultDeny(message=f"{tool_name} is not on this agent's allow-list.")

    options = ClaudeAgentOptions(
        system_prompt=plan["system_prompt"],
        mcp_servers=servers,
        strict_mcp_config=True,
        setting_sources=[],
        tools=[],
        allowed_tools=plan["allowed_tools"],
        can_use_tool=gate,
        permission_mode="default",
        max_turns=plan["max_turns"],
        output_format=plan["output_format"],
        model=model,
    )

    async with ClaudeSDKClient(options=options) as client:
        await client.query(prompt)
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock) and block.text.strip():
                        print(block.text)
                    elif isinstance(block, ToolUseBlock):
                        print(f"  -> {block.name} {json.dumps(block.input)}")
                        log.record["tool_calls"].append({"tool": block.name, "args": block.input})
            elif isinstance(message, ResultMessage):
                log.record["proposal"] = message.structured_output
                log.record["is_error"] = message.is_error
                log.record["cost_usd"] = message.total_cost_usd

    if log.record["proposal"] is not None:
        print("\n" + json.dumps(log.record["proposal"], indent=2))
    print(f"\n  run log: {log.save().relative_to(REPO_ROOT).as_posix()}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an Agents/ template on the Claude Agent SDK.")
    parser.add_argument("agent", help="agent id or folder, e.g. soc-triage or 01-soc-triage")
    parser.add_argument("--prompt", help="the task; defaults to the first offline try_with prompt")
    parser.add_argument("--offline", action="store_true", help="replay MCP server + synthetic data + write stubs")
    parser.add_argument("--dry-run", action="store_true", help="print the plan and exit; needs nothing installed")
    parser.add_argument("--model", help="model id; defaults to the SDK's default")
    args = parser.parse_args()

    _, agent = find_agent(args.agent)
    plan = build_plan(agent, args.offline)
    prompt = args.prompt or (agent.get("offline_profile", {}).get("try_with") or [""])[0]

    if args.dry_run:
        print(json.dumps({**plan, "prompt": prompt}, indent=2))
        return 0
    if not prompt:
        sys.exit("give the agent a task with --prompt")
    return asyncio.run(run(agent, plan, prompt, args.model))


if __name__ == "__main__":
    sys.exit(main())
