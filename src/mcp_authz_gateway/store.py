"""SQLite state shared by every gateway process on the machine: the approval queue, time-limited
grants, and a hash-chained audit log in which each record commits to the one before it."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


def default_db_path() -> Path:
    env = os.environ.get("MCP_AUTHZ_GATEWAY_DB")
    if env:
        return Path(env)
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return base / "mcp-authz-gateway" / "gateway.db"


SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY, created REAL NOT NULL, server TEXT NOT NULL, tool TEXT NOT NULL,
    args TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
    grant_minutes INTEGER NOT NULL DEFAULT 0, decided REAL, decided_by TEXT
);
CREATE TABLE IF NOT EXISTS grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT, server TEXT NOT NULL, tool TEXT NOT NULL,
    created REAL NOT NULL, expires REAL NOT NULL, approval_id TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, server TEXT NOT NULL, tool TEXT NOT NULL,
    decision TEXT NOT NULL, rule TEXT NOT NULL, reason TEXT NOT NULL, args TEXT NOT NULL,
    prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
"""
GENESIS = "0" * 64
AUDIT_FIELDS = ("ts", "server", "tool", "decision", "rule", "reason", "args")


def _record_hash(prev_hash: str, record: dict[str, Any]) -> str:
    body = json.dumps({k: record[k] for k in AUDIT_FIELDS}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


class Store:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        # One short-lived connection per operation keeps this safe across threads and processes.
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
        finally:
            conn.close()

    # ---- audit -------------------------------------------------------------------------------
    def audit(self, server: str, tool: str, decision: str, rule: str, reason: str, args: Any) -> int:
        record = {
            "ts": round(time.time(), 6), "server": server, "tool": tool, "decision": decision,
            "rule": rule, "reason": reason, "args": json.dumps(args, sort_keys=True, default=str),
        }
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")  # serialise writers so the chain never forks
            row = c.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS
            h = _record_hash(prev, record)
            cur = c.execute(
                "INSERT INTO audit (ts, server, tool, decision, rule, reason, args, prev_hash, hash)"
                " VALUES (:ts, :server, :tool, :decision, :rule, :reason, :args, :prev, :hash)",
                {**record, "prev": prev, "hash": h},
            )
            c.execute("COMMIT")
            return cur.lastrowid

    def audit_records(self, limit: int | None = None) -> list[dict[str, Any]]:
        q = "SELECT * FROM audit ORDER BY seq DESC" + (" LIMIT ?" if limit else "")
        with self._conn() as c:
            rows = c.execute(q, (limit,) if limit else ()).fetchall()
        return [dict(r) for r in reversed(rows)]

    def verify_audit(self) -> tuple[bool, str]:
        """Recompute the chain. Detects edited, inserted or deleted rows (not truncation of the tail)."""
        prev = GENESIS
        n = 0
        with self._conn() as c:
            for row in c.execute("SELECT * FROM audit ORDER BY seq"):
                r = dict(row)
                if r["prev_hash"] != prev:
                    return False, f"chain broken before record {r['seq']} (a record was removed or reordered)"
                if _record_hash(prev, r) != r["hash"]:
                    return False, f"record {r['seq']} was modified"
                prev = r["hash"]
                n += 1
        return True, f"{n} records verified; head {prev[:16]}"

    # ---- approvals ---------------------------------------------------------------------------
    def create_approval(self, server: str, tool: str, args: Any, reason: str) -> str:
        aid = uuid.uuid4().hex[:8]
        with self._conn() as c:
            c.execute(
                "INSERT INTO approvals (id, created, server, tool, args, reason) VALUES (?, ?, ?, ?, ?, ?)",
                (aid, time.time(), server, tool, json.dumps(args, sort_keys=True, default=str), reason),
            )
        return aid

    def get_approval(self, aid: str) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM approvals WHERE id = ?", (aid,)).fetchone()
        return dict(row) if row else None

    def pending(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM approvals WHERE status = 'pending' ORDER BY created").fetchall()
        return [dict(r) for r in rows]

    def decide(self, aid: str, approve: bool, grant_minutes: int = 0, by: str = "cli") -> bool:
        """Approve or deny a pending request. With grant_minutes, also allow the tool for that long."""
        status = "approved" if approve else "denied"
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT * FROM approvals WHERE id = ? AND status = 'pending'", (aid,)).fetchone()
            if not row:
                c.execute("ROLLBACK")
                return False
            now = time.time()
            c.execute(
                "UPDATE approvals SET status = ?, decided = ?, decided_by = ?, grant_minutes = ? WHERE id = ?",
                (status, now, by, grant_minutes if approve else 0, aid),
            )
            if approve and grant_minutes > 0:
                c.execute(
                    "INSERT INTO grants (server, tool, created, expires, approval_id) VALUES (?, ?, ?, ?, ?)",
                    (row["server"], row["tool"], now, now + grant_minutes * 60, aid),
                )
            c.execute("COMMIT")
        return True

    def expire(self, aid: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE approvals SET status = 'expired', decided = ? WHERE id = ? AND status = 'pending'",
                      (time.time(), aid))

    # ---- grants ------------------------------------------------------------------------------
    def add_grant(self, server: str, tool: str, minutes: int, approval_id: str | None = None) -> None:
        now = time.time()
        with self._conn() as c:
            c.execute(
                "INSERT INTO grants (server, tool, created, expires, approval_id) VALUES (?, ?, ?, ?, ?)",
                (server, tool, now, now + minutes * 60, approval_id),
            )

    def active_grant(self, server: str, tool: str) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM grants WHERE server = ? AND tool = ? AND expires > ? ORDER BY expires DESC LIMIT 1",
                (server, tool, time.time()),
            ).fetchone()
        return dict(row) if row else None

    def grants(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM grants WHERE expires > ? ORDER BY expires", (time.time(),)).fetchall()
        return [dict(r) for r in rows]

    def revoke(self, grant_id: int) -> bool:
        with self._conn() as c:
            cur = c.execute("UPDATE grants SET expires = ? WHERE id = ? AND expires > ?",
                            (time.time(), grant_id, time.time()))
        return cur.rowcount > 0
