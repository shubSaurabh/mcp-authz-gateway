"""The stdio proxy. The MCP client launches the gateway instead of the real server; the gateway
launches the real server and relays JSON-RPC both ways, enforcing policy on `tools/call` and
filtering `tools/list`. Everything else passes through untouched.

    client (Claude, IDE, agent) <-stdio-> gateway <-stdio-> upstream MCP server
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import threading
import time
import uuid
from typing import IO, Any

from .policy import Decision, Policy
from .redact import redact
from .store import Store

log = logging.getLogger("mcp_authz_gateway")


class Gateway:
    def __init__(self, command: list[str], policy: Policy, store: Store, server: str,
                 client_in: IO[bytes] | None = None, client_out: IO[bytes] | None = None):
        self.command = command
        self.policy = policy
        self.store = store
        self.server = server
        self.client_in = client_in or sys.stdin.buffer
        self.client_out = client_out or sys.stdout.buffer
        self.proc: subprocess.Popen | None = None
        self._out_lock = threading.Lock()
        self._up_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._list_ids: set = set()   # client request ids whose tools/list response we filter
        self._call_ids: set = set()   # client request ids whose tools/call result we redact
        self._waiting: dict[str, tuple[threading.Event, dict]] = {}  # our own requests to the client
        self._cancelled: set = set()
        self.client_can_elicit = False

    # ---- plumbing ----------------------------------------------------------------------------
    def _id_key(self, msg_id: Any) -> str:
        return json.dumps(msg_id)

    def send_client(self, msg: dict) -> None:
        data = json.dumps(msg, separators=(",", ":")).encode() + b"\n"
        with self._out_lock:
            self.client_out.write(data)
            self.client_out.flush()

    def send_upstream(self, raw: bytes | dict) -> None:
        if isinstance(raw, dict):
            raw = json.dumps(raw, separators=(",", ":")).encode()
        with self._up_lock:
            try:
                self.proc.stdin.write(raw.rstrip(b"\n") + b"\n")
                self.proc.stdin.flush()
            except (BrokenPipeError, ValueError, OSError):
                log.error("upstream server is not accepting input")

    def run(self) -> int:
        if not shutil.which(self.command[0]):
            log.error("upstream command not found: %s", self.command[0])
            return 127
        self.proc = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        threading.Thread(target=self._pump_upstream, name="upstream", daemon=True).start()
        try:
            self._pump_client()
        finally:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.terminate()
                self.proc.wait(timeout=5)
        return self.proc.returncode or 0

    # ---- client -> upstream ------------------------------------------------------------------
    def _pump_client(self) -> None:
        for line in iter(self.client_in.readline, b""):
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                self.send_upstream(line)  # not ours to judge; the server will reject it
                continue
            # JSON-RPC batches are split so a tools/call can never slip through inside one.
            for m in msg if isinstance(msg, list) else [msg]:
                self.handle_client_message(m)

    def handle_client_message(self, msg: Any) -> None:
        if not isinstance(msg, dict):
            self.send_upstream(json.dumps(msg).encode())
            return
        method = msg.get("method")
        if method is None and "id" in msg:
            key = self._id_key(msg["id"])
            with self._state_lock:
                waiter = self._waiting.get(key)
            if waiter:
                waiter[1]["response"] = msg
                waiter[0].set()
                return
        elif method == "initialize":
            caps = (msg.get("params") or {}).get("capabilities") or {}
            self.client_can_elicit = "elicitation" in caps
        elif method == "tools/list" and "id" in msg:
            with self._state_lock:
                self._list_ids.add(self._id_key(msg["id"]))
        elif method == "tools/call" and "id" in msg:
            threading.Thread(target=self._handle_call, args=(msg,), daemon=True).start()
            return
        elif method == "notifications/cancelled":
            rid = (msg.get("params") or {}).get("requestId")
            with self._state_lock:
                self._cancelled.add(self._id_key(rid))
        self.send_upstream(json.dumps(msg, separators=(",", ":")).encode())

    def _handle_call(self, msg: dict) -> None:
        params = msg.get("params") or {}
        tool = str(params.get("name", ""))
        args = params.get("arguments") or {}
        safe_args, _ = redact(args)
        decision = self.policy.evaluate(self.server, tool, args)

        if decision.effect == "ask":
            grant = self.store.active_grant(self.server, tool)
            if grant:
                mins = max(1, int((grant["expires"] - time.time()) / 60))
                decision = Decision("allow", decision.rule, f"time-limited grant #{grant['id']} ({mins} min left)")
            else:
                decision = self._ask_human(msg["id"], tool, safe_args, decision)

        self.store.audit(self.server, tool, decision.effect, decision.rule, decision.reason, safe_args)
        log.info("%s %s.%s: %s", decision.effect.upper(), self.server, tool, decision.reason)

        if decision.effect == "allow":
            if self.policy.redact_results:
                with self._state_lock:
                    self._call_ids.add(self._id_key(msg["id"]))
            self.send_upstream(msg)
        elif self._id_key(msg["id"]) not in self._cancelled:
            self.send_client({
                "jsonrpc": "2.0", "id": msg["id"],
                "result": {"isError": True, "content": [{"type": "text", "text":
                    f"Blocked by mcp-authz-gateway: {decision.reason}. Do not retry this call unless the user asks."}]},
            })

    # ---- human approval ----------------------------------------------------------------------
    def _ask_human(self, req_id: Any, tool: str, args: Any, decision: Decision) -> Decision:
        mode = self.policy.approval.mode
        if mode == "elicit" or (mode == "auto" and self.client_can_elicit):
            result = self._elicit(tool, args, decision)
            if result is not None:
                return result
            if mode == "elicit":
                return Decision("deny", decision.rule, "approval prompt failed or was dismissed")
        return self._queue(req_id, tool, args, decision)

    def _elicit(self, tool: str, args: Any, decision: Decision) -> Decision | None:
        minutes = self.policy.approval.grant_minutes
        gid = f"mcp-authz-gw-{uuid.uuid4().hex}"
        key = self._id_key(gid)
        event, box = threading.Event(), {}
        with self._state_lock:
            self._waiting[key] = (event, box)
        preview = json.dumps(args, indent=2)[:1500]
        self.send_client({
            "jsonrpc": "2.0", "id": gid, "method": "elicitation/create",
            "params": {
                "message": f"The agent wants to call '{tool}' on server '{self.server}' ({decision.reason}).\n\n"
                           f"Arguments:\n{preview}",
                "requestedSchema": {
                    "type": "object",
                    "properties": {"decision": {
                        "type": "string", "title": "Decision",
                        "enum": ["once", "grant", "deny"],
                        "enumNames": ["Allow once", f"Allow '{tool}' for {minutes} minutes", "Deny"],
                    }},
                    "required": ["decision"],
                },
            },
        })
        got = event.wait(self.policy.approval.timeout)
        with self._state_lock:
            self._waiting.pop(key, None)
        if not got:
            return Decision("deny", decision.rule, f"no answer within {int(self.policy.approval.timeout)}s")
        resp = box["response"]
        if "error" in resp:
            log.warning("client rejected elicitation: %s", resp["error"])
            return None
        result = resp.get("result") or {}
        choice = (result.get("content") or {}).get("decision")
        if result.get("action") != "accept" or choice == "deny":
            return Decision("deny", decision.rule, "denied by the user")
        if choice == "grant":
            self.store.add_grant(self.server, tool, minutes)
            return Decision("allow", decision.rule, f"approved by the user for {minutes} minutes")
        return Decision("allow", decision.rule, "approved once by the user")

    def _queue(self, req_id: Any, tool: str, args: Any, decision: Decision) -> Decision:
        aid = self.store.create_approval(self.server, tool, args, decision.reason)
        log.warning("approval needed [%s] %s.%s - run: mcp-authz-gateway approve %s (or open the console)",
                    aid, self.server, tool, aid)
        _notify(f"Agent wants to run {tool}", f"Approve with: mcp-authz-gateway approve {aid}")
        deadline = time.monotonic() + self.policy.approval.timeout
        while time.monotonic() < deadline:
            if self._id_key(req_id) in self._cancelled:
                self.store.expire(aid)
                return Decision("deny", decision.rule, "request cancelled by the client")
            row = self.store.get_approval(aid)
            if row and row["status"] == "approved":
                extra = f" plus {row['grant_minutes']} min grant" if row["grant_minutes"] else ""
                return Decision("allow", decision.rule, f"approved via queue ({aid}){extra}")
            if row and row["status"] == "denied":
                return Decision("deny", decision.rule, f"denied via queue ({aid})")
            time.sleep(0.25)
        self.store.expire(aid)
        return Decision("deny", decision.rule, f"approval {aid} timed out after {int(self.policy.approval.timeout)}s")

    # ---- upstream -> client ------------------------------------------------------------------
    def _pump_upstream(self) -> None:
        for line in iter(self.proc.stdout.readline, b""):
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                with self._out_lock:
                    self.client_out.write(line)
                    self.client_out.flush()
                continue
            self.handle_upstream_message(msg)
        log.info("upstream server closed its output")

    def handle_upstream_message(self, msg: Any) -> None:
        if isinstance(msg, dict) and "id" in msg and "method" not in msg:
            key = self._id_key(msg["id"])
            with self._state_lock:
                is_list = key in self._list_ids
                is_call = key in self._call_ids
                self._list_ids.discard(key)
                self._call_ids.discard(key)
            result = msg.get("result")
            if is_list and isinstance(result, dict) and isinstance(result.get("tools"), list):
                tools = result["tools"]
                kept = [t for t in tools if not self.policy.is_hidden(self.server, str(t.get("name", "")))]
                if len(kept) != len(tools):
                    log.info("hid %d denied tool(s) from the agent", len(tools) - len(kept))
                msg = {**msg, "result": {**result, "tools": kept}}
            elif is_call and isinstance(result, dict):
                clean, n = redact(result, mask_keys=False)
                if n:
                    log.warning("masked %d secret(s) in a tool result before the agent saw it", n)
                    msg = {**msg, "result": clean}
        self.send_client(msg)


def _notify(title: str, body: str) -> None:
    if shutil.which("notify-send"):
        subprocess.Popen(["notify-send", "-a", "mcp-authz-gateway", title, body],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif shutil.which("osascript"):
        subprocess.Popen(["osascript", "-e", f'display notification "{body}" with title "{title}"'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
