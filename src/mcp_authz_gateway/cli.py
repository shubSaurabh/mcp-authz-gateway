"""Command line: run the gateway, check policies, and approve or deny queued calls."""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from pathlib import Path

from . import __version__
from .policy import PolicyError, load_policy
from .store import Store


def _minutes(text: str) -> int:
    m = re.fullmatch(r"(\d+)\s*([mh]?)", text.strip())
    if not m:
        raise argparse.ArgumentTypeError("use e.g. 15m or 2h")
    return int(m.group(1)) * (60 if m.group(2) == "h" else 1)


def _fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def cmd_run(a) -> int:
    from .proxy import Gateway
    command = a.command[1:] if a.command and a.command[0] == "--" else a.command
    if not command:
        print("error: give the upstream server command after --", file=sys.stderr)
        return 2
    policy = load_policy(a.policy)
    name = a.name or Path(command[0]).name
    return Gateway(command, policy, Store(a.db), name).run()


def cmd_check(a) -> int:
    policy = load_policy(a.policy)
    print(f"{a.policy}: OK, {len(policy.rules)} rule(s), default '{policy.default}', "
          f"approval mode '{policy.approval.mode}'")
    if a.tool:
        args = json.loads(a.args) if a.args else {}
        d = policy.evaluate(a.server, a.tool, args)
        print(f"{a.server}.{a.tool} -> {d.effect.upper()} ({d.reason})")
        if policy.is_hidden(a.server, a.tool):
            print("This tool is hidden from the agent's tool list.")
    return 0


def cmd_pending(a) -> int:
    items = Store(a.db).pending()
    if not items:
        print("Nothing waiting for approval.")
    for p in items:
        print(f"[{p['id']}] {_fmt_time(p['created'])}  {p['server']}.{p['tool']}  ({p['reason']})")
        print("    " + json.dumps(json.loads(p["args"]))[:400])
    return 0


def cmd_decide(a, approve: bool) -> int:
    minutes = getattr(a, "for_", 0) or 0
    if not Store(a.db).decide(a.id, approve, grant_minutes=minutes, by="cli"):
        print(f"No pending approval with id {a.id}", file=sys.stderr)
        return 1
    print(("Approved" if approve else "Denied") + f" {a.id}" + (f" with a {minutes} min grant" if minutes else ""))
    return 0


def cmd_grants(a) -> int:
    store = Store(a.db)
    if a.revoke is not None:
        ok = store.revoke(a.revoke)
        print("Revoked" if ok else "No active grant with that id")
        return 0 if ok else 1
    gs = store.grants()
    if not gs:
        print("No active grants.")
    for g in gs:
        print(f"#{g['id']}  {g['server']}.{g['tool']}  until {_fmt_time(g['expires'])}")
    return 0


def cmd_audit(a) -> int:
    store = Store(a.db)
    if a.verify:
        ok, msg = store.verify_audit()
        print(("OK: " if ok else "TAMPERED: ") + msg)
        return 0 if ok else 1
    for r in store.audit_records(limit=a.limit):
        if a.jsonl:
            print(json.dumps(r))
        else:
            print(f"{_fmt_time(r['ts'])}  {r['decision']:<5}  {r['server']}.{r['tool']}  {r['reason']}")
    return 0


def cmd_console(a) -> int:
    from .console import serve
    grant = load_policy(a.policy).approval.grant_minutes if a.policy else 15
    serve(Store(a.db), port=a.port, grant_minutes=grant, open_browser=not a.no_browser)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp-authz-gateway",
                                description="Policy, human approval and audit for AI agent tool calls over MCP.")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--db", help="state database (default ~/.local/state/mcp-authz-gateway/gateway.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="proxy an MCP server: run --policy p.yaml -- <server command>")
    r.add_argument("--policy", required=True)
    r.add_argument("--name", help="server name used in rules and logs (default: command name)")
    r.add_argument("-v", "--verbose", action="store_true")
    r.add_argument("command", nargs=argparse.REMAINDER)
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("check", help="validate a policy, optionally dry-run one call")
    c.add_argument("--policy", required=True)
    c.add_argument("--server", default="*")
    c.add_argument("--tool")
    c.add_argument("--args", help="JSON arguments for the dry run")
    c.set_defaults(func=cmd_check)

    sub.add_parser("pending", help="list calls waiting for approval").set_defaults(func=cmd_pending)
    ap = sub.add_parser("approve", help="approve a queued call")
    ap.add_argument("id")
    ap.add_argument("--for", dest="for_", type=_minutes, default=0, help="also allow the tool for e.g. 15m")
    ap.set_defaults(func=lambda a: cmd_decide(a, True))
    dn = sub.add_parser("deny", help="deny a queued call")
    dn.add_argument("id")
    dn.set_defaults(func=lambda a: cmd_decide(a, False))

    g = sub.add_parser("grants", help="list or revoke time-limited grants")
    g.add_argument("--revoke", type=int, metavar="ID")
    g.set_defaults(func=cmd_grants)

    au = sub.add_parser("audit", help="show or verify the audit log")
    au.add_argument("--limit", type=int, default=50)
    au.add_argument("--jsonl", action="store_true", help="print JSON lines (for a SIEM)")
    au.add_argument("--verify", action="store_true", help="check the hash chain")
    au.set_defaults(func=cmd_audit)

    co = sub.add_parser("console", help="local web page for approvals, grants and audit")
    co.add_argument("--port", type=int, default=8787)
    co.add_argument("--policy", help="read grant length from this policy")
    co.add_argument("--no-browser", action="store_true")
    co.set_defaults(func=cmd_console)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    logging.basicConfig(stream=sys.stderr, format="[mcp-authz-gateway] %(levelname)s %(message)s",
                        level=logging.DEBUG if getattr(a, "verbose", False) else logging.INFO)
    try:
        return a.func(a)
    except PolicyError as e:
        print(f"policy error: {e}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"invalid JSON: {e}", file=sys.stderr)
        return 2
