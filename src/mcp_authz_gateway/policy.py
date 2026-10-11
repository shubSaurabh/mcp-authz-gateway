"""Policy engine: decides whether an agent's tool call is allowed, denied, or needs a human.

Rules are checked top to bottom and the first rule that matches wins. A rule matches when the
server and tool name match its patterns and every condition in `when` holds for the call's
arguments. Conditions fail closed: a missing argument or a value of the wrong type never matches.
"""
from __future__ import annotations

import fnmatch
import posixpath
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

EFFECTS = ("allow", "deny", "ask")
OPERATORS = ("equals", "one_of", "glob", "not_glob", "regex", "not_regex", "max_length", "exists")
_MISSING = object()


class PolicyError(ValueError):
    """The policy file is malformed."""


@dataclass
class Decision:
    effect: str
    rule: str
    reason: str


@dataclass
class RateLimit:
    count: int
    window: float
    _hits: deque = field(default_factory=deque, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @classmethod
    def parse(cls, text: str) -> "RateLimit":
        m = re.fullmatch(r"\s*(\d+)\s*/\s*(s|sec|second|m|min|minute|h|hour)\s*", str(text))
        if not m:
            raise PolicyError(f"bad rate_limit {text!r}; use e.g. '30/min'")
        window = {"s": 1, "m": 60, "h": 3600}[m.group(2)[0]]
        return cls(int(m.group(1)), float(window))

    def hit(self, now: float | None = None) -> bool:
        """Record a call. Returns False if it exceeds the limit."""
        now = time.monotonic() if now is None else now
        with self._lock:
            while self._hits and now - self._hits[0] >= self.window:
                self._hits.popleft()
            if len(self._hits) >= self.count:
                return False
            self._hits.append(now)
            return True


@dataclass
class Rule:
    name: str
    tools: list[str]
    effect: str
    servers: list[str] = field(default_factory=lambda: ["*"])
    when: dict[str, dict[str, Any]] = field(default_factory=dict)
    rate_limit: RateLimit | None = None

    def matches_tool(self, server: str, tool: str) -> bool:
        return any(fnmatch.fnmatchcase(server, s) for s in self.servers) and any(
            fnmatch.fnmatchcase(tool, t) for t in self.tools
        )

    def conditions_hold(self, args: dict[str, Any]) -> bool:
        return all(_check(_get(args, key), ops) for key, ops in self.when.items())


def _get(args: Any, dotted: str) -> Any:
    cur = args
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _normalize(value: str) -> str:
    # Collapse "..", "." and repeated slashes so "/safe/../etc/passwd" cannot pass a "/safe/**" glob.
    if "/" in value or "\\" in value:
        value = value.replace("\\", "/")
        lead = "/" if value.startswith("/") else ""
        value = posixpath.normpath(value)
        if lead and not value.startswith("/"):
            value = lead + value
    return value


def _as_list(v: Any) -> list:
    return v if isinstance(v, list) else [v]


def _check(value: Any, ops: dict[str, Any]) -> bool:
    for op, expected in ops.items():
        if op == "exists":
            if (value is not _MISSING) != bool(expected):
                return False
            continue
        if value is _MISSING:
            return False
        if op == "equals":
            if value != expected:
                return False
        elif op == "one_of":
            if value not in _as_list(expected):
                return False
        elif op == "max_length":
            if not isinstance(value, (str, list, dict)) or len(value) > int(expected):
                return False
        else:
            if not isinstance(value, str):
                return False
            if op in ("glob", "not_glob"):
                hit = any(fnmatch.fnmatchcase(_normalize(value), g) for g in _as_list(expected))
            else:
                hit = any(re.search(r, value) for r in _as_list(expected))
            if hit == op.startswith("not_"):
                return False
    return True


@dataclass
class ApprovalSettings:
    mode: str = "auto"  # auto: ask in the MCP client if it supports elicitation, else the approval queue
    timeout: float = 120.0
    grant_minutes: int = 15


@dataclass
class Policy:
    rules: list[Rule]
    default: str = "ask"
    hide_denied_tools: bool = True
    redact_results: bool = True
    approval: ApprovalSettings = field(default_factory=ApprovalSettings)

    def evaluate(self, server: str, tool: str, args: dict[str, Any] | None) -> Decision:
        args = args if isinstance(args, dict) else {}
        for rule in self.rules:
            if not rule.matches_tool(server, tool) or not rule.conditions_hold(args):
                continue
            if rule.rate_limit and rule.effect != "deny" and not rule.rate_limit.hit():
                limit = rule.rate_limit
                return Decision("deny", rule.name, f"rate limit {limit.count} per {int(limit.window)}s exceeded")
            return Decision(rule.effect, rule.name, f"matched rule '{rule.name}'")
        return Decision(self.default, "default", f"no rule matched; default is {self.default}")

    def is_hidden(self, server: str, tool: str) -> bool:
        """True if every call to this tool would be denied, so the agent need not see it."""
        if not self.hide_denied_tools:
            return False
        for rule in self.rules:
            if rule.matches_tool(server, tool):
                if rule.when:
                    if rule.effect != "deny":
                        return False  # some calls may pass
                    continue  # a conditional deny leaves later rules to decide the rest
                return rule.effect == "deny"
        return self.default == "deny"


def parse_policy(data: dict[str, Any]) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping")
    default = data.get("default", "ask")
    if default not in EFFECTS:
        raise PolicyError(f"default must be one of {EFFECTS}")
    rules = []
    for i, raw in enumerate(data.get("rules") or [], 1):
        if not isinstance(raw, dict):
            raise PolicyError(f"rule {i} must be a mapping")
        tools = raw.get("tools", raw.get("tool"))
        if not tools:
            raise PolicyError(f"rule {i} needs 'tool' or 'tools'")
        effect = raw.get("effect")
        if effect not in EFFECTS:
            raise PolicyError(f"rule {i}: effect must be one of {EFFECTS}")
        when = raw.get("when") or {}
        if not isinstance(when, dict):
            raise PolicyError(f"rule {i}: 'when' must map argument names to conditions")
        for arg, ops in when.items():
            if not isinstance(ops, dict) or not ops:
                raise PolicyError(f"rule {i}: condition for '{arg}' must be a mapping like {{glob: ...}}")
            bad = set(ops) - set(OPERATORS)
            if bad:
                raise PolicyError(f"rule {i}: unknown operator(s) {sorted(bad)}; use {OPERATORS}")
            for op in ("regex", "not_regex"):
                for r in _as_list(ops.get(op, [])):
                    try:
                        re.compile(r)
                    except re.error as e:
                        raise PolicyError(f"rule {i}: bad regex {r!r}: {e}") from e
        rules.append(
            Rule(
                name=str(raw.get("name") or f"rule {i}"),
                tools=[str(t) for t in _as_list(tools)],
                effect=effect,
                servers=[str(s) for s in _as_list(raw.get("servers", raw.get("server", "*")))],
                when=when,
                rate_limit=RateLimit.parse(raw["rate_limit"]) if raw.get("rate_limit") else None,
            )
        )
    ap = data.get("approval") or {}
    approval = ApprovalSettings(
        mode=ap.get("mode", "auto"),
        timeout=float(ap.get("timeout", 120)),
        grant_minutes=int(ap.get("grant_minutes", 15)),
    )
    if approval.mode not in ("auto", "elicit", "queue"):
        raise PolicyError("approval.mode must be auto, elicit or queue")
    return Policy(
        rules=rules,
        default=default,
        hide_denied_tools=bool(data.get("hide_denied_tools", True)),
        redact_results=bool(data.get("redact_results", True)),
        approval=approval,
    )


def load_policy(path: str | Path) -> Policy:
    try:
        data = yaml.safe_load(Path(path).read_text())
    except yaml.YAMLError as e:
        raise PolicyError(f"{path}: invalid YAML: {e}") from e
    return parse_policy(data or {})
