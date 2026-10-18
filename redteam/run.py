"""Score the red-team corpus and write results/redteam_report.json and .md.

Every number in the report comes from replaying the cases in
``redteam/cases/`` through the gateway. Nothing is written by hand.

Scoring:

- An attack case is *caught* if the decision at its ``expect.step`` is one of
  its ``expect.decision`` values (BLOCK and/or ESCALATE).
- A benign case is a *false positive* if any of its steps gets a decision
  other than ALLOW.
- Escalation share: calls that would wait for a human (ESCALATE), over all
  calls replayed.
- Latency: time the gateway spends deciding a call (registry check through
  decision, excluding running the tool), rules only. The optional LLM judge
  is off.

Run with ``mcp-guard redteam`` from the repository root.
"""

from __future__ import annotations

import json
import math
import platform
import statistics
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from mcp_guard.gateway import Gateway
from mcp_guard.models import ToolCall, Verdict
from mcp_guard.policy import Policy
from mcp_guard.registry import Lockfile, build_lockfile
from mock.agent import Case, CaseError, MockAgent
from mock.servers import SERVER_SETS, MockToolHost, all_specs

THREAT_NAMES = {
    "T1": "Indirect prompt injection",
    "T2": "Tool poisoning",
    "T3": "Rug pull",
    "T4": "Token passthrough",
    "T5": "Exfiltration",
    "T6": "Unsafe workspace mutation",
    "T7": "Irreversible action",
    "T8": "Tool shadowing",
    "T9": "Audit-log tampering",
}
NO_CASES_NOTE = {"T9": "covered by `verify-log` once the audit log exists (M5); no replay cases"}


@dataclass
class StepResult:
    step: int
    tool: str
    decision: str
    rules: list[str]
    reason: str
    latency_us: float


@dataclass
class CaseResult:
    id: str
    kind: str
    threat: str | None
    expect_step: int
    expected: list[str]
    notes: str
    steps: list[StepResult] = field(default_factory=list)

    @property
    def at_expect(self) -> StepResult:
        return self.steps[self.expect_step - 1]

    @property
    def caught(self) -> bool:
        return self.kind == "attack" and self.at_expect.decision in self.expected

    @property
    def false_positive(self) -> bool:
        return self.kind == "benign" and any(s.decision != Verdict.ALLOW.value for s in self.steps)

    @property
    def first_flagged(self) -> StepResult | None:
        return next((s for s in self.steps if s.decision != Verdict.ALLOW.value), None)


def build_gateway(case: Case, policy: Policy, lock: Lockfile) -> Gateway:
    factory = SERVER_SETS.get(case.servers)
    if factory is None:
        raise CaseError(f"{case.source or case.id}: unknown server set {case.servers!r}; "
                        f"known: {', '.join(sorted(SERVER_SETS))}")
    servers = factory()
    specs = all_specs(servers)
    # A careless reviewer pins whatever is advertised, without the R7 check.
    case_lock = build_lockfile(specs) if case.pin_advertised else lock
    return Gateway.build(specs, case_lock, policy, MockToolHost(servers))


def run_case(case: Case, policy: Policy, lock: Lockfile) -> CaseResult:
    gateway = build_gateway(case, policy, lock)
    latencies: list[int] = []

    def executor(call: ToolCall, scripted: str | None):
        outcome = gateway(call, scripted)
        latencies.append(gateway.last_latency_ns)
        return outcome

    transcript = MockAgent(case).replay(executor)
    result = CaseResult(case.id, case.kind, case.threat, case.expect.step,
                        [d.value for d in case.expect.decisions], case.notes)
    for rec, ns in zip(transcript.steps, latencies):
        result.steps.append(StepResult(
            rec.index, rec.call.qualified_name, rec.decision.verdict.value,
            list(rec.decision.rules), rec.decision.reason, round(ns / 1000, 1)))
    return result


def percentile(values: Sequence[float], q: float) -> float:
    """Nearest-rank percentile (q in 0..100)."""
    if not values:
        return float("nan")
    ordered = sorted(values)
    rank = max(1, math.ceil(q / 100 * len(ordered)))
    return ordered[rank - 1]


def _rate(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def score(cases: Iterable[Case], policy: Policy, lock: Lockfile) -> dict[str, Any]:
    results = [run_case(c, policy, lock) for c in sorted(cases, key=lambda c: c.id)]
    attacks = [r for r in results if r.kind == "attack"]
    benign = [r for r in results if r.kind == "benign"]
    caught = [r for r in attacks if r.caught]
    fps = [r for r in benign if r.false_positive]
    steps = [s for r in results for s in r.steps]
    escalated_calls = [s for s in steps if s.decision == Verdict.ESCALATE.value]
    latencies = [s.latency_us for s in steps]

    per_threat: dict[str, Any] = {}
    for t, name in THREAT_NAMES.items():
        a = [r for r in attacks if r.threat == t]
        bn = [r for r in benign if r.threat == t]
        per_threat[t] = {
            "name": name,
            "attacks": len(a),
            "caught": sum(r.caught for r in a),
            "catch_rate": _rate(sum(r.caught for r in a), len(a)),
            "benign": len(bn),
            "false_positives": sum(r.false_positive for r in bn),
            "note": NO_CASES_NOTE.get(t, "") if not a else "",
        }

    rule_hits = Counter(rule for r in caught for rule in r.at_expect.rules)
    fp_rules = Counter(rule for r in fps for rule in r.first_flagged.rules)

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(terse=True),
            "machine": platform.machine(),
        },
        "config": {"judge": "off", "min_substring_length": policy.min_substring},
        "summary": {
            "attacks": len(attacks),
            "caught": len(caught),
            "catch_rate": _rate(len(caught), len(attacks)),
            "benign": len(benign),
            "false_positives": len(fps),
            "false_positive_rate": _rate(len(fps), len(benign)),
            "calls": len(steps),
            "escalated_calls": len(escalated_calls),
            "escalation_share": _rate(len(escalated_calls), len(steps)),
            "cases_with_escalation": sum(any(s.decision == "ESCALATE" for s in r.steps) for r in results),
            "latency_us": {
                "median": round(statistics.median(latencies), 1) if latencies else None,
                "p95": percentile(latencies, 95) if latencies else None,
                "calls": len(latencies),
            },
            "latency_with_judge_us": None,
        },
        "per_threat": per_threat,
        "rules_at_expected_step": dict(sorted(rule_hits.items())),
        "rules_causing_false_positives": dict(sorted(fp_rules.items())),
        "misses": [
            {"id": r.id, "threat": r.threat, "expect_step": r.expect_step, "expected": r.expected,
             "got": r.at_expect.decision, "rules": r.at_expect.rules, "reason": r.at_expect.reason,
             "notes": r.notes}
            for r in attacks if not r.caught
        ],
        "false_positives": [
            {"id": r.id, "lookalike_for": r.threat, "step": r.first_flagged.step,
             "tool": r.first_flagged.tool, "decision": r.first_flagged.decision,
             "rules": r.first_flagged.rules, "reason": r.first_flagged.reason, "notes": r.notes}
            for r in fps
        ],
        "cases": [
            {"id": r.id, "kind": r.kind, "threat": r.threat,
             "result": ("caught" if r.caught else "missed") if r.kind == "attack"
             else ("false_positive" if r.false_positive else "allowed"),
             "steps": [vars(s) for s in r.steps]}
            for r in results
        ],
    }


# --------------------------------------------------------------------------
# Output


def _pct(rate: float | None) -> str:
    return "n/a" if rate is None else f"{rate * 100:.1f}%"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    env = report["environment"]
    lat = s["latency_us"]
    lines = [
        "# mcp-guard red-team report",
        "",
        f"Generated by `mcp-guard redteam` at {report['generated_at']} "
        f"(Python {env['python']}, {env['platform']}). Do not edit by hand.",
        "",
        f"Corpus: {s['attacks']} attack cases and {s['benign']} benign look-alikes, all written by the "
        "project author and replayed by a scripted mock agent against mock tools. Rules only; the "
        "optional LLM judge is off.",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Attack catch rate (BLOCK or ESCALATE at the expected step) | "
        f"{s['caught']}/{s['attacks']} ({_pct(s['catch_rate'])}) |",
        f"| False-positive rate (benign case with any non-ALLOW decision) | "
        f"{s['false_positives']}/{s['benign']} ({_pct(s['false_positive_rate'])}) |",
        f"| Escalation share (calls held for a human) | {s['escalated_calls']}/{s['calls']} calls "
        f"({_pct(s['escalation_share'])}); {s['cases_with_escalation']} cases |",
        f"| Gateway decision latency per call, rules only | median {lat['median']} µs, "
        f"p95 {lat['p95']} µs ({lat['calls']} calls) |",
        "| Latency with the LLM judge | not measured (judge off) |",
        "",
        "## Per threat",
        "",
        "| Threat | Attacks caught | Benign look-alikes flagged |",
        "|---|---|---|",
    ]
    for t, row in report["per_threat"].items():
        caught = (f"{row['caught']}/{row['attacks']} ({_pct(row['catch_rate'])})"
                  if row["attacks"] else f"— ({row['note']})" if row["note"] else "—")
        fp = f"{row['false_positives']}/{row['benign']}" if row["benign"] else "—"
        lines.append(f"| {t} {row['name']} | {caught} | {fp} |")

    lines += ["", "## Rules that fired on caught attacks (at the expected step)", ""]
    hits = report["rules_at_expected_step"]
    lines += ["| Rule | Cases |", "|---|---|"] + [f"| {k} | {v} |" for k, v in hits.items()] \
        if hits else ["None."]

    lines += ["", f"## Misses ({len(report['misses'])})", ""]
    if report["misses"]:
        lines += ["| Case | Threat | Expected at step | Got | Rules | Notes |", "|---|---|---|---|---|---|"]
        for m in report["misses"]:
            lines.append(f"| {m['id']} | {m['threat']} | {'/'.join(m['expected'])} at {m['expect_step']} "
                         f"| {m['got']} | {', '.join(m['rules']) or '—'} | {_cell(m['notes'])} |")
    else:
        lines.append("None.")

    lines += ["", f"## False positives ({len(report['false_positives'])})", ""]
    if report["false_positives"]:
        lines += ["| Case | Look-alike for | Step | Tool | Decision | Reason |", "|---|---|---|---|---|---|"]
        for f in report["false_positives"]:
            lines.append(f"| {f['id']} | {f['lookalike_for'] or '—'} | {f['step']} | {f['tool']} "
                         f"| {f['decision']} | {_cell(f['reason'])} |")
    else:
        lines.append("None.")

    lines += ["", "## All cases", "", "| Case | Kind | Result | Decisions by step |", "|---|---|---|---|"]
    for c in report["cases"]:
        steps = "; ".join(
            f"{st['step']}. {st['tool']} → {st['decision']}"
            + (f" ({', '.join(st['rules'])})" if st["rules"] else "")
            for st in c["steps"])
        lines.append(f"| {c['id']} | {c['kind']} | {c['result']} | {_cell(steps)} |")
    return "\n".join(lines) + "\n"


def write_reports(report: dict[str, Any], out_dir: str | Path) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "redteam_report.json"
    md_path = out / "redteam_report.md"
    with json_path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        f.write("\n")
    with md_path.open("w", encoding="utf-8", newline="\n") as f:
        f.write(render_markdown(report))
    return json_path, md_path


def check_gate(report: dict[str, Any], min_catch: float | None, max_fp: float | None) -> list[str]:
    """Reasons the CI gate fails (empty list = pass)."""
    s = report["summary"]
    failures = []
    if min_catch is not None and (s["catch_rate"] or 0.0) < min_catch:
        failures.append(f"catch rate {_pct(s['catch_rate'])} is below the minimum {min_catch * 100:.1f}%")
    if max_fp is not None and (s["false_positive_rate"] or 0.0) > max_fp:
        failures.append(f"false-positive rate {_pct(s['false_positive_rate'])} is above the maximum "
                        f"{max_fp * 100:.1f}%")
    return failures
