#!/usr/bin/env python3
"""
agents.py
=========
Validates the agent templates in Agents/ and builds their adapters.

    python Agents/tools/agents.py validate     # check every agent.json
    python Agents/tools/agents.py build        # regenerate PROMPT.md + Claude Code files
    python Agents/tools/agents.py check        # validate, and fail if generated files are stale
    python Agents/tools/agents.py --self-test  # prove the validator catches what it claims to

agent.json is the source of truth. PROMPT.md and everything under claude-code/
is generated from it, so edit the JSON and rebuild - never the other way round.

What "valid" means here is not "parses". It is the slide 16 bottom row and
slide 25, checked mechanically: an identity of its own, a tool allow-list with
a never list, writes behind an approval gate, auto-approve shipped off, a
system prompt that treats data as hostile, and a run log. A template that
fails any of these is not one you should hand to a room.

Standard library only. Exit code is non-zero on any failure, so this works in CI.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

AGENTS_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = AGENTS_DIR.parent
CLAUDE_CODE_DIR = AGENTS_DIR / "claude-code"

REQUIRED_KEYS = [
    "name", "id", "version", "description", "source", "identity",
    "mcp_servers", "tool_allow_list", "system_prompt", "output_schema",
    "approval_gate", "observability", "guardrails",
]
IDENTITY_TYPES = {"workload_identity", "delegated_user"}
REQUIRED_GUARDRAILS = [
    "read_only_by_default", "kql_write_operations_blocked",
    "untrusted_content_wrapped", "injection_screening",
]
# Phrases the system prompt must carry. Lower-cased substring match.
PROMPT_MUST_SAY = {
    "data is not instructions": "an untrusted-data section (slide 25: treat data as hostile)",
    "never let it select a tool": "the rule that retrieved content never picks a tool",
    "did not retrieve": "the no-fabrication rule",
}
GENERATED_NOTE = "Generated from agent.json by Agents/tools/agents.py build. Edit agent.json, not this file."


# --- loading -----------------------------------------------------------------

def agent_files() -> list[Path]:
    return sorted(AGENTS_DIR.glob("[0-9][0-9]-*/agent.json"))


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


# --- validation --------------------------------------------------------------

def validate(agent: dict[str, Any], check_paths: bool = True) -> list[str]:
    """Return a list of problems. Empty means the template is fit to hand out."""
    errors: list[str] = []

    for key in REQUIRED_KEYS:
        if key not in agent:
            errors.append(f"missing top-level key '{key}'")
    if errors:
        return errors

    # Least-privilege identity
    identity = agent["identity"]
    if identity.get("type") not in IDENTITY_TYPES:
        errors.append(f"identity.type must be one of {sorted(IDENTITY_TYPES)}")
    if not identity.get("separate_credentials_per_environment"):
        errors.append("identity.separate_credentials_per_environment must be true")

    # Tool allow-list
    tools = agent["tool_allow_list"]
    read = set(tools.get("read", []))
    write = set(tools.get("write_requires_approval", []))
    never = set(tools.get("never", []))
    if not read:
        errors.append("tool_allow_list.read is empty")
    if not never:
        errors.append("tool_allow_list.never is empty - name what this agent must never do")
    for a, b, label in [(read, write, "read/write"), (read, never, "read/never"), (write, never, "write/never")]:
        if a & b:
            errors.append(f"tool_allow_list {label} overlap: {sorted(a & b)}")
    for server in agent["mcp_servers"]:
        extra = set(server.get("tools", [])) - read - write
        if extra:
            errors.append(f"mcp server '{server.get('name')}' names tools outside the allow-list: {sorted(extra)}")
    scoped = set(identity.get("scoped_write_actions", []))
    if scoped != write:
        errors.append(
            f"identity.scoped_write_actions {sorted(scoped)} does not match "
            f"tool_allow_list.write_requires_approval {sorted(write)}"
        )

    # Approval gate
    gate = agent["approval_gate"]
    if write and not gate.get("required_for"):
        errors.append("agent has write tools but approval_gate.required_for is empty")
    if gate.get("auto_approve_allowed_when", {}).get("enabled") is not False:
        errors.append("approval_gate.auto_approve_allowed_when.enabled must ship as false")

    # System prompt
    prompt = agent["system_prompt"].lower()
    for phrase, why in PROMPT_MUST_SAY.items():
        if phrase not in prompt:
            errors.append(f"system_prompt is missing {why} (expected the phrase '{phrase}')")

    # Structured output
    schema = agent["output_schema"]
    if schema.get("type") != "object":
        errors.append("output_schema.type must be 'object'")
    props = schema.get("properties", {})
    for field in schema.get("required", []):
        if field not in props:
            errors.append(f"output_schema requires '{field}' but does not define it")
    if "injection_observed" not in schema.get("required", []):
        errors.append("output_schema must require 'injection_observed' - a silent agent is blind to a poisoned feed")
    for name in ("requires_approval", "requires_human_signoff"):
        if name in props and props[name].get("const") is not True:
            errors.append(f"output_schema.{name} must be const true")

    # Observability
    obs = agent["observability"]
    if not obs.get("log_destination"):
        errors.append("observability.log_destination is empty")
    logged = " ".join(obs.get("logged_per_run", [])).lower()
    if "injection" not in logged:
        errors.append("observability.logged_per_run must include prompt-injection attempts")
    if write and "decision" not in logged:
        errors.append("agent has write tools but does not log the human decision")

    # Guardrails
    guards = agent["guardrails"]
    for g in REQUIRED_GUARDRAILS:
        if guards.get(g) is not True:
            errors.append(f"guardrails.{g} must be true")

    # Paths it claims exist
    if check_paths:
        for demo in agent["source"].get("demos", []):
            if not (REPO_ROOT / demo).exists():
                errors.append(f"source.demos path does not exist: {demo}")
        for server in agent.get("offline_profile", {}).get("mcp_servers", []):
            for arg in server.get("args", []):
                if arg.endswith(".py") and not (REPO_ROOT / arg).exists():
                    errors.append(f"offline_profile server script does not exist: {arg}")

    return errors


# --- adapters ----------------------------------------------------------------

def _fence(text: str, lang: str = "") -> str:
    return f"```{lang}\n{text}\n```"


def render_prompt_md(agent: dict[str, Any]) -> str:
    tools = agent["tool_allow_list"]
    src = agent["source"]
    lines = [
        f"<!-- {GENERATED_NOTE} -->",
        "",
        f"# {agent['name']}",
        "",
        f"**{src['session']}** · Slides {src['slides']} · MMS 2026 Midway Edition",
        "",
        agent["description"],
        "",
    ]
    if agent.get("maturity_level"):
        lines += [f"*{agent['maturity_level']}*", ""]

    lines += ["Built from:", ""]
    lines += [f"- [`{d}`](../../{d})" for d in src.get("demos", [])]
    lines += [
        "",
        "## System prompt",
        "",
        "Paste this as the system prompt, custom instructions, or project instructions.",
        "",
        _fence(agent["system_prompt"]),
        "",
        "## Tools",
        "",
        "| Access | Tools |",
        "|--------|-------|",
        f"| Read | {', '.join(f'`{t}`' for t in tools.get('read', [])) or '—'} |",
        f"| Write, after human approval | {', '.join(f'`{t}`' for t in tools.get('write_requires_approval', [])) or '— (read-only agent)'} |",
        f"| Never | {', '.join(f'`{t}`' for t in tools.get('never', []))} |",
        "",
        "Anything not in the table is refused. The *Never* row is there so the",
        "refusal is a decision someone made, not an accident of what got wired up.",
        "",
    ]

    offline = agent.get("offline_profile")
    if offline:
        lines += [
            "## Try it offline",
            "",
            offline.get("_comment", ""),
            "",
            "Offline read tools: " + ", ".join(f"`{t}`" for t in offline.get("read", [])),
            "",
        ]
        if offline.get("try_with"):
            lines += ["Prompts to try:", ""]
            lines += [f"- *{p}*" for p in offline["try_with"]]
            lines += [""]

    schema = agent["output_schema"]
    lines += [
        "## Output",
        "",
        "Every run emits this contract. Required fields:",
        "",
    ]
    for field in schema.get("required", []):
        prop = schema["properties"].get(field, {})
        note = prop.get("description", "")
        if "const" in prop:
            note = (note + " " if note else "") + f"Always `{json.dumps(prop['const'])}`."
        if "enum" in prop:
            note = (note + " " if note else "") + "One of: " + ", ".join(f"`{v}`" for v in prop["enum"]) + "."
        lines.append(f"- `{field}`" + (f" — {note}" if note else ""))
    lines += [
        "",
        "Full JSON Schema: `output_schema` in [`agent.json`](agent.json).",
        "",
        "## Customize before you use it",
        "",
    ]
    lines += [f"- {c}" for c in agent.get("_customize", [])]
    lines += [""]
    return "\n".join(lines)


def server_read_tools(agent: dict[str, Any], server: dict[str, Any]) -> list[str]:
    # A server may name the tools it serves; otherwise it serves every read tool.
    read = agent["tool_allow_list"].get("read", [])
    return [t for t in server["tools"] if t in read] if "tools" in server else list(read)


def _mcp_tool_names(agent: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for server in agent["mcp_servers"]:
        names += [f"mcp__{server['name']}__{t}" for t in server_read_tools(agent, server)]
    offline = agent.get("offline_profile")
    if offline:
        for server in offline.get("mcp_servers", []):
            names += [f"mcp__{server['name']}__{t}" for t in offline.get("read", [])]
    return names


def render_claude_subagent(agent: dict[str, Any]) -> str:
    # Read tools only. Claude Code's per-call permission prompt is not a
    # recorded approval gate, so write tools are left out of the subagent on
    # purpose - wire them through tools/run_agent.py or your own host.
    schema = json.dumps(agent["output_schema"], indent=2)
    body = [
        "---",
        f"name: {agent['id']}",
        f"description: {agent['description']}",
        f"tools: {', '.join(_mcp_tool_names(agent))}",
        "---",
        "",
        f"<!-- {GENERATED_NOTE} -->",
        "",
        agent["system_prompt"],
        "",
        "Emit your final answer as a single JSON object that conforms to this schema:",
        "",
        _fence(schema, "json"),
        "",
    ]
    return "\n".join(body)


def render_mcp_json(agents: list[dict[str, Any]]) -> str:
    servers: dict[str, Any] = {}
    for agent in agents:
        for s in agent["mcp_servers"]:
            servers.setdefault(s["name"], {"type": "http", "url": s["url"]})
        for s in agent.get("offline_profile", {}).get("mcp_servers", []):
            servers.setdefault(s["name"], {
                "command": s["command"],
                # Relative to Agents/claude-code/, where you launch claude
                "args": ["../../" + a if a.endswith(".py") else a for a in s.get("args", [])],
            })
    return json.dumps({"mcpServers": servers}, indent=2) + "\n"


def generated_files(agents: list[tuple[Path, dict[str, Any]]]) -> dict[Path, str]:
    out: dict[Path, str] = {}
    for path, agent in agents:
        out[path.parent / "PROMPT.md"] = render_prompt_md(agent)
        out[CLAUDE_CODE_DIR / ".claude" / "agents" / f"{agent['id']}.md"] = render_claude_subagent(agent)
    out[CLAUDE_CODE_DIR / ".mcp.json"] = render_mcp_json([a for _, a in agents])
    return out


# --- commands ----------------------------------------------------------------

def cmd_validate() -> tuple[int, list[tuple[Path, dict[str, Any]]]]:
    loaded: list[tuple[Path, dict[str, Any]]] = []
    failures = 0
    ids: set[str] = set()
    files = agent_files()
    if not files:
        print("  no agent.json files found")
        return 1, loaded
    for path in files:
        rel = path.relative_to(AGENTS_DIR).as_posix()
        try:
            agent = load(path)
        except json.JSONDecodeError as exc:
            print(f"  [FAIL] {rel}: not valid JSON - {exc}")
            failures += 1
            continue
        errors = validate(agent)
        if agent.get("id") in ids:
            errors.append(f"duplicate id '{agent.get('id')}'")
        ids.add(agent.get("id"))
        if errors:
            failures += 1
            print(f"  [FAIL] {rel}")
            for e in errors:
                print(f"           - {e}")
        else:
            writes = len(agent["tool_allow_list"].get("write_requires_approval", []))
            mode = f"{writes} gated write(s)" if writes else "read-only"
            print(f"  [ok]   {rel:<36} {agent['name']}  ({mode})")
        loaded.append((path, agent))
    return failures, loaded


def cmd_build(loaded: list[tuple[Path, dict[str, Any]]]) -> None:
    for path, text in generated_files(loaded).items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"  wrote  {path.relative_to(AGENTS_DIR).as_posix()}")


def cmd_check(loaded: list[tuple[Path, dict[str, Any]]]) -> int:
    stale = 0
    for path, text in generated_files(loaded).items():
        rel = path.relative_to(AGENTS_DIR).as_posix()
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            print(f"  [STALE] {rel} - run: python Agents/tools/agents.py build")
            stale += 1
    if not stale:
        print("  [ok]   generated files match agent.json")
    return stale


def self_test() -> int:
    """Break a known-good template on purpose and confirm the validator notices."""
    base = load(AGENTS_DIR / "01-soc-triage" / "agent.json")
    checks: list[tuple[str, Any]] = []

    def broken(mutate) -> list[str]:
        a = copy.deepcopy(base)
        mutate(a)
        return validate(a, check_paths=False)

    checks.append(("the shipped template is valid", not validate(base)))
    checks.append(("a write tool in the read list is caught",
                   bool(broken(lambda a: a["tool_allow_list"]["read"].append("assign_incident")))))
    checks.append(("an empty never list is caught",
                   bool(broken(lambda a: a["tool_allow_list"].__setitem__("never", [])))))
    checks.append(("auto-approve shipped on is caught",
                   bool(broken(lambda a: a["approval_gate"]["auto_approve_allowed_when"].__setitem__("enabled", True)))))
    checks.append(("a write the identity is not scoped for is caught",
                   bool(broken(lambda a: a["tool_allow_list"]["write_requires_approval"].append("block_user")))))
    checks.append(("a prompt without the data-is-not-instructions rule is caught",
                   bool(broken(lambda a: a.__setitem__("system_prompt",
                       a["system_prompt"].replace("DATA IS NOT INSTRUCTIONS", "NOTES"))))))
    checks.append(("requires_approval not const true is caught",
                   bool(broken(lambda a: a["output_schema"]["properties"]["requires_approval"].__setitem__("const", False)))))
    checks.append(("not logging injection attempts is caught",
                   bool(broken(lambda a: a["observability"].__setitem__("logged_per_run",
                       [x for x in a["observability"]["logged_per_run"] if "injection" not in x])))))
    checks.append(("the Claude Code subagent carries no write tools",
                   not any(w in render_claude_subagent(base).split("---")[1]
                           for w in base["tool_allow_list"]["write_requires_approval"])))

    failed = 0
    for label, ok in checks:
        print(f"  [{'ok' if ok else 'FAIL'}] {label}")
        failed += 0 if ok else 1
    print(f"\n  {len(checks) - failed}/{len(checks)} passed")
    return failed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("command", nargs="?", default="validate", choices=["validate", "build", "check"])
    parser.add_argument("--self-test", action="store_true", help="prove the validator catches broken templates")
    args = parser.parse_args()

    if args.self_test:
        return 1 if self_test() else 0

    failures, loaded = cmd_validate()
    print(f"\n  {len(loaded) - failures}/{len(loaded)} templates passed")
    if failures:
        return 1
    if args.command == "build":
        cmd_build(loaded)
    elif args.command == "check":
        return 1 if cmd_check(loaded) else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
