"""A small local web page for approving queued tool calls, listing grants and reading the audit log.

It listens on 127.0.0.1 only. Because any website you visit can send requests to localhost, every
request must carry a random token from the startup URL, and the Host header must be localhost
(blocks DNS-rebinding). Approve and deny are POST-only.
"""
from __future__ import annotations

import html
import json
import secrets
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .store import Store

PAGE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP Authz Gateway</title><meta http-equiv="refresh" content="3">
<style>
:root{{--bg:#f7f7f5;--fg:#1d1d1b;--muted:#6b6b66;--card:#fff;--line:#e3e3de;--ok:#1f7a4d;--no:#b3261e;--accent:#2f5bd3}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151514;--fg:#ececea;--muted:#9a9a94;--card:#1f1f1d;--line:#33332f;--ok:#4cc38a;--no:#f2766b;--accent:#7a9cff}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}}
main{{max-width:960px;margin:0 auto;padding:24px 16px}}h1{{font-size:20px;margin:0 0 4px}}h2{{font-size:15px;margin:28px 0 8px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:8px 0}}
pre{{white-space:pre-wrap;word-break:break-word;font-size:13px;background:var(--bg);padding:8px;border-radius:6px;margin:8px 0}}
button{{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:6px;padding:6px 12px;cursor:pointer;margin-right:6px}}
button.ok{{border-color:var(--ok);color:var(--ok)}}button.no{{border-color:var(--no);color:var(--no)}}
table{{width:100%;border-collapse:collapse;font-size:13px}}td,th{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}}
.allow{{color:var(--ok)}}.deny{{color:var(--no)}}.muted{{color:var(--muted)}}form{{display:inline}}
.wrap{{overflow-x:auto}}
</style></head><body><main>
<h1>MCP Authz Gateway</h1><div class="muted">{chain}</div>
<h2>Waiting for approval</h2>{pending}
<h2>Active grants</h2>{grants}
<h2>Recent decisions</h2><div class="wrap">{audit}</div>
</main></body></html>"""


def _t(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def render(store: Store, token: str, grant_minutes: int) -> str:
    e = html.escape
    pend = store.pending()
    pending = "".join(
        f"""<div class="card"><b>{e(p['server'])} &rsaquo; {e(p['tool'])}</b> <span class="muted">#{p['id']} · {_t(p['created'])}</span>
<div class="muted">{e(p['reason'])}</div><pre>{e(json.dumps(json.loads(p['args']), indent=2))}</pre>
<form method="post" action="/decide?token={token}"><input type="hidden" name="id" value="{p['id']}">
<button class="ok" name="action" value="once">Allow once</button>
<button class="ok" name="action" value="grant">Allow {e(p['tool'])} for {grant_minutes} min</button>
<button class="no" name="action" value="deny">Deny</button></form></div>"""
        for p in pend
    ) or '<div class="muted">Nothing waiting.</div>'
    grants = "".join(
        f"""<div class="card">{e(g['server'])} &rsaquo; <b>{e(g['tool'])}</b> until {_t(g['expires'])}
<form method="post" action="/revoke?token={token}"><input type="hidden" name="id" value="{g['id']}">
<button class="no">Revoke</button></form></div>"""
        for g in store.grants()
    ) or '<div class="muted">No active grants.</div>'
    rows = "".join(
        f"<tr><td>{_t(r['ts'])}</td><td class='{e(r['decision'])}'>{e(r['decision'])}</td>"
        f"<td>{e(r['server'])} &rsaquo; {e(r['tool'])}</td><td>{e(r['reason'])}</td></tr>"
        for r in reversed(store.audit_records(limit=50))
    )
    audit = f"<table><tr><th>Time</th><th>Decision</th><th>Tool</th><th>Why</th></tr>{rows}</table>" if rows \
        else '<div class="muted">No tool calls yet.</div>'
    ok, msg = store.verify_audit()
    chain = ("Audit chain intact: " if ok else "AUDIT CHAIN BROKEN: ") + msg
    return PAGE.format(pending=pending, grants=grants, audit=audit, chain=e(chain))


def serve(store: Store, port: int = 8787, grant_minutes: int = 15, open_browser: bool = True) -> None:
    token = secrets.token_urlsafe(24)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _guard(self) -> dict | None:
            url = urlparse(self.path)
            q = parse_qs(url.query)
            if self.headers.get("Host") not in allowed_hosts or \
                    not secrets.compare_digest(q.get("token", [""])[0], token):
                self.send_error(403, "Open the console using the URL printed in the terminal")
                return None
            return {"path": url.path}

        def do_GET(self):
            if not self._guard():
                return
            body = render(store, token, grant_minutes).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            g = self._guard()
            if not g:
                return
            n = int(self.headers.get("Content-Length") or 0)
            form = parse_qs(self.rfile.read(min(n, 4096)).decode())
            item = form.get("id", [""])[0]
            if g["path"] == "/decide":
                action = form.get("action", [""])[0]
                store.decide(item, approve=action in ("once", "grant"),
                             grant_minutes=grant_minutes if action == "grant" else 0, by="console")
            elif g["path"] == "/revoke" and item.isdigit():
                store.revoke(int(item))
            self.send_response(303)
            self.send_header("Location", f"/?token={token}")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/?token={token}"
    print(f"Approval console: {url}\nPress Ctrl+C to stop.", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
