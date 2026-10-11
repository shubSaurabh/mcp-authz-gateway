"""A minimal MCP server over stdio, used by the end-to-end tests."""
import json
import sys

TOOLS = ["read_file", "write_file", "delete_file", "run_command"]
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg or "method" not in msg:
        continue
    method, mid = msg["method"], msg["id"]
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": n, "inputSchema": {"type": "object"}} for n in TOOLS]}
    elif method == "tools/call":
        args = msg["params"].get("arguments", {})
        text = "ran " + msg["params"]["name"] + " " + json.dumps(args, sort_keys=True)
        if args.get("path", "").endswith("config.txt"):
            text += "\naws_key=AKIAABCDEFGHIJKLMNOP"
        result = {"content": [{"type": "text", "text": text}]}
    else:
        result = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}) + "\n")
    sys.stdout.flush()
