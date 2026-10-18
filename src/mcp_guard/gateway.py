"""Gateway: the single path from a proposed tool call to a tool.

Pipeline (section 5 of the plan):

    1. Registry check   tool verified (pinned, hash matches, not shadowed, R7 clean)?  else BLOCK REGISTRY
    2. Taint tracker    per-session record of untrusted outputs
    3. Auditor          policy lookup + rules R1-R6 -> ALLOW / BLOCK / ESCALATE
    4. Egress           R4 again as its own step, so it holds even if the rule set changes
    5. Approval gate    ESCALATE -> approver (default: auto-deny)
    6. Token broker     strip agent-supplied credentials; attach the tool's scoped token
    7. Audit log        one hash-chained record per decision (and per registry event)

Then the tool runs, and its output is recorded as untrusted before it goes
back to the agent.

A ``Gateway`` instance is an executor for ``mock.agent.MockAgent.replay``:
``gateway(call, scripted_output) -> StepOutcome``.
"""

from __future__ import annotations

import dataclasses
import time
from collections import defaultdict
from typing import Any, Iterable, Protocol

from .approval import Approver, AutoDeny
from .audit_log import AuditLog
from .auditor import AuditResult, Auditor, combine
from .models import Decision, StepOutcome, ToolCall, ToolResult, ToolSpec, Verdict
from .policy import Policy
from .registry import BLOCKING_EVENTS, Lockfile, Registry, verify
from .rules import RuleContext, r4_egress, r7_check
from .taint import TaintTracker
from .tokens import TokenBroker, strip_credentials


class ToolHost(Protocol):
    """Anything that can run a tool call (the mock host, later a real MCP client)."""

    def invoke(self, call: ToolCall, scripted_output: str | None = None,
               credential: Any = None) -> ToolResult: ...


class Gateway:
    def __init__(self, registry: Registry, policy: Policy, host: ToolHost,
                 auditor: Auditor | None = None, approver: Approver | None = None,
                 broker: TokenBroker | None = None, log: AuditLog | None = None):
        self.registry = registry
        self.policy = policy
        self.host = host
        self.auditor = auditor or Auditor(policy)
        self.approver = approver or AutoDeny()
        self.broker = broker or TokenBroker(policy)
        self.log = log if log is not None else AuditLog()
        self._taint: dict[str, TaintTracker] = {}
        self._steps: dict[str, int] = defaultdict(int)
        self.last_audit: AuditResult | None = None
        self.last_stripped: list[str] = []
        #: Time spent deciding the last call, in nanoseconds: registry check
        #: through egress. Excludes approval, the tool itself and log I/O.
        self.last_latency_ns: int = 0
        for event in registry.events:
            if event.kind in BLOCKING_EVENTS:
                self.log.log_event(event.server, event.tool, event.kind.value, event.detail)

    @classmethod
    def build(cls, advertised: Iterable[ToolSpec], lock: Lockfile, policy: Policy,
              host: ToolHost, **kwargs: Any) -> "Gateway":
        """Verify the advertised tools (pins, shadowing, R7) and build a gateway."""
        registry = verify(advertised, lock, description_check=r7_check)
        return cls(registry, policy, host, **kwargs)

    def taint(self, session: str) -> TaintTracker:
        if session not in self._taint:
            self._taint[session] = TaintTracker(min_len=self.policy.min_substring)
        return self._taint[session]

    def _registry_block(self, call: ToolCall) -> Decision:
        events = [e for e in self.registry.events if e.qualified_name == call.qualified_name]
        why = "; ".join(f"{e.kind}: {e.detail}" for e in events) or "not a verified tool"
        return Decision.block(["REGISTRY"], f"{call.qualified_name} is disabled ({why})")

    def _decide(self, call: ToolCall, taint: TaintTracker) -> Decision:
        # 1. Registry
        if not self.registry.is_allowed(call.server, call.tool):
            self.last_audit = None
            return self._registry_block(call)
        # 2-3. Taint + auditor
        audit = self.auditor.audit(call, taint)
        self.last_audit = audit
        decision = audit.decision
        # 4. Egress, independent of the auditor's rule set
        tool = self.policy.tool(call.qualified_name)
        if tool is not None and "R4" not in decision.rules:
            egress = r4_egress(RuleContext(call, self.policy, tool, taint))
            if egress:
                decision = combine(list(audit.findings) + egress)
        return decision

    def handle(self, call: ToolCall, scripted_output: str | None = None) -> StepOutcome:
        start = time.perf_counter_ns()
        self._steps[call.session] += 1
        step = self._steps[call.session]
        taint = self.taint(call.session)
        self.last_stripped = []

        decision = self._decide(call, taint)
        self.last_latency_ns = time.perf_counter_ns() - start

        if decision.verdict is Verdict.BLOCK:
            self.log.log_decision(call, decision)
            return StepOutcome(decision)

        # 5. Approval gate
        approver = approved = None
        if decision.verdict is Verdict.ESCALATE:
            review = self.approver.review(call, decision)
            approver, approved = review.approver, review.approved
            if not approved:
                self.log.log_decision(call, decision, approver, False)
                return StepOutcome(decision, None, approver, False)

        # 6. Token broker: no agent-supplied credential reaches the tool.
        clean_args, stripped = strip_credentials(call.args)
        self.last_stripped = stripped
        run_call = dataclasses.replace(call, args=clean_args) if stripped else call
        token = self.broker.token_for(call.qualified_name)

        # 7. Log the decision before the tool runs, so a crash mid-call still leaves a record.
        self.log.log_decision(call, decision, approver, approved)
        result = self.host.invoke(run_call, scripted_output, credential=token)
        taint.record(result, step)
        return StepOutcome(decision, result, approver, approved)

    __call__ = handle
