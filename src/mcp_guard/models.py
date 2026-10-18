"""Core data types shared by every part of the gateway.

- ``ToolSpec``    a tool as an MCP server advertises it (what gets hash-pinned)
- ``ToolCall``    a call the agent proposes, before the gateway lets it run
- ``ToolResult``  what a tool returned; always treated as untrusted content
- ``Verdict``     ALLOW / BLOCK / ESCALATE
- ``Decision``    a verdict plus the rule IDs and a short reason
- ``AuditRecord`` one line of the hash-chained audit log

Everything here is plain data: no I/O, no policy.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

# Server names may not contain "." so that "server.tool" splits unambiguously.
# Tool names follow the MCP spec's allowed characters (which include ".").
SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8, no NaN/Infinity.

    Used for hash pinning (registry) and, later, for audit-log hashes, so the
    same logical object always produces the same bytes.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def utc_now_iso() -> str:
    """Current UTC time as ``2026-10-18T14:02:11Z`` (second precision)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_server_name(name: Any) -> str:
    if not isinstance(name, str) or not SERVER_NAME_RE.match(name):
        raise ValueError(
            f"invalid server name {name!r}: use 1-64 of [A-Za-z0-9_-], no dots"
        )
    return name


def validate_tool_name(name: Any) -> str:
    if not isinstance(name, str) or not TOOL_NAME_RE.match(name):
        raise ValueError(f"invalid tool name {name!r}: use 1-128 of [A-Za-z0-9_.-]")
    return name


def qualify(server: str, tool: str) -> str:
    """Server-qualified tool name, e.g. ``mail.send_email``."""
    return f"{server}.{tool}"


def split_qualified(qualified: str) -> tuple[str, str]:
    """Inverse of :func:`qualify`. Splits on the first dot."""
    server, sep, tool = qualified.partition(".")
    if not sep:
        raise ValueError(f"not a server-qualified tool name: {qualified!r}")
    return validate_server_name(server), validate_tool_name(tool)


# --------------------------------------------------------------------------
# Tools


@dataclass(frozen=True)
class ToolSpec:
    """A tool definition as advertised by an MCP server.

    Only these four fields are pinned (see ``registry.canonical_tool``).
    """

    server: str
    name: str
    description: str = ""
    input_schema: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        validate_server_name(self.server)
        validate_tool_name(self.name)
        if not isinstance(self.description, str):
            raise ValueError(f"{self.qualified_name}: description must be a string")
        if not isinstance(self.input_schema, Mapping):
            raise ValueError(f"{self.qualified_name}: inputSchema must be a mapping")
        object.__setattr__(self, "input_schema", copy.deepcopy(dict(self.input_schema)))

    @property
    def qualified_name(self) -> str:
        return qualify(self.server, self.name)

    @classmethod
    def from_mcp(cls, server: str, tool: Mapping[str, Any]) -> "ToolSpec":
        """Build from an MCP ``tools/list`` entry (``name``, ``description``,
        ``inputSchema``). Other keys (title, annotations, ...) are ignored."""
        if not isinstance(tool, Mapping):
            raise ValueError(f"tool advertised by {server!r} is not a mapping")
        return cls(
            server=server,
            name=tool.get("name"),  # type: ignore[arg-type]  # validated in __post_init__
            description=tool.get("description", ""),
            input_schema=tool.get("inputSchema", {}),
        )

    def to_mcp(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": copy.deepcopy(dict(self.input_schema)),
        }


@dataclass(frozen=True)
class ToolCall:
    """A tool call the agent proposes.

    ``call_chain`` holds the qualified names of the calls made earlier in the
    same session, oldest first. ``task`` is the engineer's original request.
    """

    server: str
    tool: str
    args: Mapping[str, Any] = field(default_factory=dict)
    task: str = ""
    session: str = ""
    call_chain: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_server_name(self.server)
        validate_tool_name(self.tool)
        if not isinstance(self.args, Mapping):
            raise ValueError(f"{self.qualified_name}: args must be a mapping")
        if not all(isinstance(k, str) for k in self.args):
            raise ValueError(f"{self.qualified_name}: arg names must be strings")
        if not isinstance(self.task, str) or not isinstance(self.session, str):
            raise ValueError("task and session must be strings")
        # Own a private copy so later mutation by the caller can't change a call
        # after the gateway has judged it.
        object.__setattr__(self, "args", copy.deepcopy(dict(self.args)))
        object.__setattr__(self, "call_chain", tuple(self.call_chain))

    @property
    def qualified_name(self) -> str:
        return qualify(self.server, self.tool)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], **context: Any) -> "ToolCall":
        """Build from ``{server, tool, args}`` (e.g. a YAML case step).

        Keyword ``context`` (task, session, call_chain) fills fields the dict
        does not carry.
        """
        if not isinstance(data, Mapping):
            raise ValueError("call must be a mapping with server, tool, args")
        missing = [k for k in ("server", "tool") if k not in data]
        if missing:
            raise ValueError(f"call is missing {', '.join(missing)}")
        unknown = set(data) - {"server", "tool", "args"}
        if unknown:
            raise ValueError(f"call has unknown keys: {sorted(unknown)}")
        return cls(
            server=data["server"],
            tool=data["tool"],
            args=data.get("args") or {},
            **context,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "tool": self.tool,
            "args": copy.deepcopy(dict(self.args)),
            "task": self.task,
            "session": self.session,
            "call_chain": list(self.call_chain),
        }


@dataclass(frozen=True)
class ToolResult:
    """Output of a tool call. ``untrusted`` is True for every tool output by
    design: the gateway never assumes a tool's output is safe to obey."""

    call: ToolCall
    output: str
    untrusted: bool = True
    error: bool = False


# --------------------------------------------------------------------------
# Decisions


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"

    @classmethod
    def parse(cls, value: Any) -> "Verdict":
        if isinstance(value, Verdict):
            return value
        try:
            return cls(str(value).upper())
        except ValueError:
            raise ValueError(
                f"unknown decision {value!r}; expected one of "
                f"{', '.join(v.value for v in cls)}"
            ) from None

    def __str__(self) -> str:  # so f-strings print "BLOCK", not "Verdict.BLOCK"
        return self.value


@dataclass(frozen=True)
class Decision:
    """The gateway's answer for one proposed call."""

    verdict: Verdict
    rules: tuple[str, ...] = ()
    reason: str = ""
    tainted_args: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "verdict", Verdict.parse(self.verdict))
        object.__setattr__(self, "rules", tuple(self.rules))
        object.__setattr__(self, "tainted_args", tuple(self.tainted_args))
        if any(not isinstance(r, str) or not r for r in self.rules):
            raise ValueError("rule IDs must be non-empty strings")

    @classmethod
    def allow(cls, reason: str = "", rules: tuple[str, ...] = ()) -> "Decision":
        return cls(Verdict.ALLOW, rules, reason)

    @classmethod
    def block(cls, rules: tuple[str, ...] | list[str], reason: str,
              tainted_args: tuple[str, ...] | list[str] = ()) -> "Decision":
        return cls(Verdict.BLOCK, tuple(rules), reason, tuple(tainted_args))

    @classmethod
    def escalate(cls, rules: tuple[str, ...] | list[str], reason: str,
                 tainted_args: tuple[str, ...] | list[str] = ()) -> "Decision":
        return cls(Verdict.ESCALATE, tuple(rules), reason, tuple(tainted_args))

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW


# --------------------------------------------------------------------------
# Audit log


# Field order matches the record shown in the project plan (section 5).
AUDIT_FIELDS = (
    "ts", "seq", "session", "server", "tool", "decision", "rules", "reason",
    "tainted_args", "approver", "prev_hash", "hash",
)


@dataclass(frozen=True)
class AuditRecord:
    """One decision in the audit log.

    ``hash`` is SHA-256 over the record without ``hash`` (including
    ``prev_hash``); computing and checking it is ``audit_log``'s job (M5).
    """

    ts: str
    seq: int
    session: str
    server: str
    tool: str
    decision: Verdict
    rules: tuple[str, ...] = ()
    reason: str = ""
    tainted_args: tuple[str, ...] = ()
    approver: str | None = None
    prev_hash: str = ""
    hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.seq, int) or isinstance(self.seq, bool) or self.seq < 0:
            raise ValueError("seq must be a non-negative integer")
        object.__setattr__(self, "decision", Verdict.parse(self.decision))
        object.__setattr__(self, "rules", tuple(self.rules))
        object.__setattr__(self, "tainted_args", tuple(self.tainted_args))

    def to_dict(self, include_hash: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "ts": self.ts,
            "seq": self.seq,
            "session": self.session,
            "server": self.server,
            "tool": self.tool,
            "decision": self.decision.value,
            "rules": list(self.rules),
            "reason": self.reason,
            "tainted_args": list(self.tainted_args),
            "approver": self.approver,
            "prev_hash": self.prev_hash,
        }
        if include_hash:
            d["hash"] = self.hash
        return d

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AuditRecord":
        unknown = set(data) - set(AUDIT_FIELDS)
        if unknown:
            raise ValueError(f"audit record has unknown fields: {sorted(unknown)}")
        missing = {"ts", "seq", "session", "server", "tool", "decision"} - set(data)
        if missing:
            raise ValueError(f"audit record is missing fields: {sorted(missing)}")
        return cls(**{k: data[k] for k in AUDIT_FIELDS if k in data})

    @classmethod
    def for_decision(cls, call: ToolCall, decision: Decision, *, seq: int,
                     prev_hash: str, approver: str | None = None,
                     ts: str | None = None) -> "AuditRecord":
        return cls(
            ts=ts or utc_now_iso(),
            seq=seq,
            session=call.session,
            server=call.server,
            tool=call.tool,
            decision=decision.verdict,
            rules=decision.rules,
            reason=decision.reason,
            tainted_args=decision.tainted_args,
            approver=approver,
            prev_hash=prev_hash,
        )
