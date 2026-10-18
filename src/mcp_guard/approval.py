"""Approval gate: a human decides on irreversible or escalated calls.

Three approvers:

- ``AutoDeny``     the default; nothing escalated runs (CI, red team, unattended use)
- ``CLIApprover``  asks on the terminal and shows the call, the rules and the reason
- ``AutoApprove``  approves everything; for tests only

Rule R3 escalations (irreversible actions) always come here; the optional
LLM judge is never allowed to approve them.
"""

from __future__ import annotations

import getpass
import json
from dataclasses import dataclass
from typing import Callable, Protocol

from .models import Decision, ToolCall


@dataclass(frozen=True)
class ApprovalResult:
    approved: bool
    approver: str
    note: str = ""


class Approver(Protocol):
    def review(self, call: ToolCall, decision: Decision) -> ApprovalResult: ...


class AutoDeny:
    name = "auto-deny"

    def review(self, call: ToolCall, decision: Decision) -> ApprovalResult:
        return ApprovalResult(False, self.name, "no human approver configured")


class AutoApprove:
    """Approves everything. Tests only: never use it to run real tools."""

    name = "auto-approve"

    def review(self, call: ToolCall, decision: Decision) -> ApprovalResult:
        return ApprovalResult(True, self.name, "auto-approved (test approver)")


class CLIApprover:
    """Prompt on the terminal. ``ask``/``say`` are injectable for tests."""

    def __init__(self, ask: Callable[[str], str] = input, say: Callable[[str], None] = print,
                 name: str | None = None):
        self.ask, self.say = ask, say
        self.name = name or _user()

    def review(self, call: ToolCall, decision: Decision) -> ApprovalResult:
        self.say("")
        self.say(f"Approval needed: {call.qualified_name}")
        self.say(f"  task:   {call.task or '(none)'}")
        self.say(f"  args:   {json.dumps(dict(call.args), ensure_ascii=False)[:500]}")
        self.say(f"  rules:  {', '.join(decision.rules)}")
        self.say(f"  reason: {decision.reason}")
        try:
            answer = self.ask("Approve this call? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        approved = answer in ("y", "yes")
        return ApprovalResult(approved, self.name, "approved at the terminal" if approved else "denied")


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no user name in some sandboxes
        return "cli"
