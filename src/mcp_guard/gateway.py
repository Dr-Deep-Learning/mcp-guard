"""Gateway: the single path from a proposed tool call to a tool.

Pipeline (section 5 of the plan); steps marked M5 are not built yet:

    1. Registry check   tool verified (pinned, hash matches, not shadowed)?  -> else BLOCK REGISTRY
    2. Taint tracker    per-session record of untrusted outputs
    3. Auditor          policy lookup + rules R1-R6 -> ALLOW / BLOCK / ESCALATE
    4. Egress           (R4 runs inside the auditor today; own step in M5)
    5. Approval gate    M5. Until then ESCALATE means "held": the call does not run.
    6. Token broker     M5
    7. Audit log        M5

Only an ALLOW runs. Its output is recorded as untrusted before it goes back
to the agent.

A ``Gateway`` instance is an executor for ``mock.agent.MockAgent.replay``:
``gateway(call, scripted_output) -> StepOutcome``.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Protocol

from .auditor import AuditResult, Auditor
from .models import Decision, StepOutcome, ToolCall, ToolResult, ToolSpec
from .policy import Policy
from .registry import Lockfile, Registry, verify
from .rules import r7_check
from .taint import TaintTracker


class ToolHost(Protocol):
    """Anything that can run a tool call (the mock host, later a real MCP client)."""

    def invoke(self, call: ToolCall, scripted_output: str | None = None) -> ToolResult: ...


class Gateway:
    def __init__(self, registry: Registry, policy: Policy, host: ToolHost,
                 auditor: Auditor | None = None):
        self.registry = registry
        self.policy = policy
        self.host = host
        self.auditor = auditor or Auditor(policy)
        self._taint: dict[str, TaintTracker] = {}
        self._steps: dict[str, int] = defaultdict(int)
        self.last_audit: AuditResult | None = None

    @classmethod
    def build(cls, advertised: Iterable[ToolSpec], lock: Lockfile, policy: Policy,
              host: ToolHost, auditor: Auditor | None = None) -> "Gateway":
        """Verify the advertised tools (pins, shadowing, R7) and build a gateway."""
        registry = verify(advertised, lock, description_check=r7_check)
        return cls(registry, policy, host, auditor)

    def taint(self, session: str) -> TaintTracker:
        if session not in self._taint:
            self._taint[session] = TaintTracker(min_len=self.policy.min_substring)
        return self._taint[session]

    def _registry_block(self, call: ToolCall) -> Decision:
        events = [e for e in self.registry.events if e.qualified_name == call.qualified_name]
        why = "; ".join(f"{e.kind}: {e.detail}" for e in events) or "not a verified tool"
        return Decision.block(["REGISTRY"], f"{call.qualified_name} is disabled ({why})")

    def handle(self, call: ToolCall, scripted_output: str | None = None) -> StepOutcome:
        self._steps[call.session] += 1
        step = self._steps[call.session]

        # 1. Registry
        if not self.registry.is_allowed(call.server, call.tool):
            self.last_audit = None
            return StepOutcome(self._registry_block(call))

        # 2-3. Taint + auditor
        taint = self.taint(call.session)
        audit = self.auditor.audit(call, taint)
        self.last_audit = audit
        if not audit.decision.allowed:
            return StepOutcome(audit.decision)  # BLOCK, or ESCALATE held until M5

        # Run, and mark the output untrusted for every later call.
        result = self.host.invoke(call, scripted_output)
        taint.record(result, step)
        return StepOutcome(audit.decision, result)

    __call__ = handle
