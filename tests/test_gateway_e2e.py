"""Drives the real gateway process over stdio, the way an MCP client would."""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path

from mcp_authz_gateway.store import Store

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
POLICY = textwrap.dedent("""
    default: ask
    approval: {mode: MODE, timeout: 5, grant_minutes: 10}
    rules:
      - {name: reads ok, tool: read_file, effect: allow}
      - {name: no deletes, tool: delete_file, effect: deny}
      - {name: writes ask, tool: write_file, effect: ask}
""")


class Client:
    def __init__(self, tmp, mode="queue", elicit=False):
        policy = Path(tmp) / "policy.yaml"
        policy.write_text(POLICY.replace("MODE", mode))
        self.db = Path(tmp) / "g.db"
        env = {**os.environ, "PYTHONPATH": str(SRC)}
        self.p = subprocess.Popen(
            [sys.executable, "-m", "mcp_authz_gateway", "--db", str(self.db), "run", "--policy", str(policy),
             "--name", "fs", "--", sys.executable, str(HERE / "fake_server.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        self.next_id = 0
        caps = {"elicitation": {}} if elicit else {}
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": caps,
                                    "clientInfo": {"name": "test", "version": "1"}})

    def send(self, msg):
        self.p.stdin.write((json.dumps(msg) + "\n").encode())
        self.p.stdin.flush()

    def read(self):
        return json.loads(self.p.stdout.readline())

    def request(self, method, params=None, on_request=None):
        self.next_id += 1
        mid = self.next_id
        self.send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})
        while True:
            msg = self.read()
            if "method" in msg and on_request:      # a request from the gateway (elicitation)
                self.send({"jsonrpc": "2.0", "id": msg["id"], "result": on_request(msg)})
                continue
            if msg.get("id") == mid:
                return msg

    def call(self, tool, on_request=None, **args):
        return self.request("tools/call", {"name": tool, "arguments": args}, on_request)["result"]

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


class GatewayE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_list_filter_allow_deny_and_redaction(self):
        c = Client(self.tmp.name)
        tools = [t["name"] for t in c.request("tools/list")["result"]["tools"]]
        self.assertNotIn("delete_file", tools)
        self.assertIn("read_file", tools)

        r = c.call("read_file", path="/tmp/notes.md")
        self.assertNotIn("isError", r)
        r = c.call("read_file", path="/tmp/config.txt")
        self.assertIn("[REDACTED:aws-access-key]", r["content"][0]["text"])
        self.assertNotIn("AKIA", r["content"][0]["text"])

        r = c.call("delete_file", path="/tmp/x")
        self.assertTrue(r["isError"])
        self.assertIn("Blocked", r["content"][0]["text"])
        c.close()

        store = Store(c.db)
        self.assertEqual([a["decision"] for a in store.audit_records()], ["allow", "allow", "deny"])
        self.assertTrue(store.verify_audit()[0])

    def test_queue_approval_then_grant(self):
        c = Client(self.tmp.name, mode="queue")
        store = Store(c.db)

        def approver():
            for _ in range(80):
                pending = store.pending()
                if pending:
                    store.decide(pending[0]["id"], True, grant_minutes=10)
                    return
                time.sleep(0.05)
        threading.Thread(target=approver).start()
        r = c.call("write_file", path="/tmp/a", content="x")
        self.assertNotIn("isError", r)
        # the grant now covers the next call without asking
        r = c.call("write_file", path="/tmp/b", content="y")
        self.assertNotIn("isError", r)
        self.assertEqual(store.pending(), [])
        c.close()
        reasons = [a["reason"] for a in store.audit_records()]
        self.assertIn("grant", reasons[-1])

    def test_queue_timeout_denies(self):
        policy_tmp = self.tmp.name
        c = Client(policy_tmp, mode="queue")
        start = time.monotonic()
        r = c.call("write_file", path="/tmp/a")
        self.assertTrue(r["isError"])
        self.assertGreaterEqual(time.monotonic() - start, 4.5)
        c.close()

    def test_elicitation_in_client(self):
        c = Client(self.tmp.name, mode="auto", elicit=True)
        seen = []

        def answer(choice):
            def on_request(msg):
                seen.append(msg)
                return {"action": "accept", "content": {"decision": choice}}
            return on_request
        r = c.call("write_file", on_request=answer("deny"), path="/tmp/a")
        self.assertTrue(r["isError"])
        r = c.call("write_file", on_request=answer("once"), path="/tmp/a")
        self.assertNotIn("isError", r)
        self.assertEqual(seen[0]["method"], "elicitation/create")
        self.assertIn("write_file", seen[0]["params"]["message"])
        c.close()

    def test_batch_cannot_bypass_policy(self):
        c = Client(self.tmp.name)
        c.send([{"jsonrpc": "2.0", "id": 99, "method": "tools/call",
                 "params": {"name": "delete_file", "arguments": {"path": "/x"}}}])
        msg = c.read()
        self.assertEqual(msg["id"], 99)
        self.assertTrue(msg["result"]["isError"])
        c.close()


if __name__ == "__main__":
    unittest.main()
