"""Auditor: run the rules and combine them into one Decision (the cascade).

1. Policy lookup: a tool the policy does not list is blocked (``POLICY``).
2. Deterministic rules R1-R6, all of them, so the decision lists every rule
   that fired (useful in the audit log and the red-team report).
3. Combine: any BLOCK -> BLOCK; else any ESCALATE -> ESCALATE; else ALLOW.
   Rule IDs are listed BLOCK rules first, then ESCALATE rules, each in ID order.
4. Optional judge, only on ESCALATE and never for R3 (irreversible actions
   always go to a human). The judge may return ALLOW, BLOCK or ESCALATE.
   Off by default; CI never uses it.

Cheap checks decide most calls; the expensive judge only sees the ambiguous
remainder. That is the cost argument for the cascade.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Sequence

from .models import Decision, ToolCall, Verdict
from .policy import Policy
from .rules import CALL_RULES, Finding, Rule, RuleContext
from .taint import TaintTracker

# judge(call, findings) -> Verdict | None  (None = no opinion; keep ESCALATE)
Judge = Callable[[ToolCall, Sequence[Finding]], "Verdict | None"]

_SEVERITY = {Verdict.BLOCK: 0, Verdict.ESCALATE: 1, Verdict.ALLOW: 2}


def _rule_key(rule_id: str) -> tuple[int, str]:
    digits = rule_id[1:]
    return (int(digits), rule_id) if rule_id.startswith("R") and digits.isdigit() else (999, rule_id)


def combine(findings: Sequence[Finding]) -> Decision:
    if not findings:
        return Decision.allow("no rule fired")
    verdict = min((f.verdict for f in findings), key=_SEVERITY.__getitem__)
    ordered = sorted(findings, key=lambda f: (_SEVERITY[f.verdict], _rule_key(f.rule)))
    rules = tuple(dict.fromkeys(f.rule for f in ordered))
    reason = "; ".join(f"{f.rule}: {f.reason}" for f in ordered)
    tainted = tuple(dict.fromkeys(a for f in ordered if f.rule == "R1" for a in f.args))
    return Decision(verdict, rules, reason, tainted)


@dataclass(frozen=True)
class AuditResult:
    decision: Decision
    findings: tuple[Finding, ...] = ()
    judged: bool = False


@dataclass
class Auditor:
    policy: Policy
    rules: Sequence[Rule] = field(default_factory=lambda: CALL_RULES)
    judge: Judge | None = None

    def audit(self, call: ToolCall, taint: TaintTracker) -> AuditResult:
        tool = self.policy.tool(call.qualified_name)
        if tool is None:
            return AuditResult(Decision.block(
                ["POLICY"], f"{call.qualified_name} is not listed in the policy"))

        ctx = RuleContext(call, self.policy, tool, taint)
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule(ctx))
        decision = combine(findings)

        if (self.judge is not None and decision.verdict is Verdict.ESCALATE
                and "R3" not in decision.rules):
            verdict = self.judge(call, findings)
            if verdict is not None and Verdict.parse(verdict) is not Verdict.ESCALATE:
                decision = Decision(Verdict.parse(verdict), decision.rules + ("JUDGE",),
                                    decision.reason + f"; JUDGE: {Verdict.parse(verdict)}",
                                    decision.tainted_args)
            return AuditResult(decision, tuple(findings), judged=True)
        return AuditResult(decision, tuple(findings))
