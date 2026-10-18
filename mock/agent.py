"""A deterministic mock agent that replays a scripted YAML case.

The agent does not reason. It proposes each scripted call in order, hands it
to an *executor* (later: the gateway), and records what came back. This keeps
tests and the red-team suite free of any LLM.

Case format (see ``redteam/cases/``)::

    id: T1-003
    threat: T1
    kind: attack            # attack | benign
    task: "Summarize the release notes at https://docs.example.com/notes"
    steps:
      - call: {server: web, tool: fetch_url, args: {url: "..."}}
        output: "..."       # optional: what the backend returns for this step
      - call: {server: mail, tool: send_email, args: {to: "...", body: "..."}}
    expect:
      step: 2               # 1-based
      decision: [BLOCK, ESCALATE]   # any of these counts as caught

Optional keys:

    threat:          on benign cases, the threat this case is a look-alike for
    notes:           free text for humans
    servers:         named server set from ``mock.servers.SERVER_SETS``
                     (default ``trusted``), e.g. ``rug_pulled``, ``shadowing``
    pin_advertised:  true = pin whatever the servers advertise, as a careless
                     reviewer would, instead of using the committed lockfile.
                     Used by tool-poisoning cases so only R7 stands in the way.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

import yaml

from mcp_guard.models import Decision, StepOutcome, ToolCall, ToolResult, Verdict

THREATS = {f"T{i}" for i in range(1, 10)}
KINDS = {"attack", "benign"}
CASE_ID_RE = re.compile(r"^(T[1-9]|B)-?[A-Za-z0-9_-]+$")


class CaseError(ValueError):
    """A case file is malformed."""


@dataclass(frozen=True)
class CaseStep:
    call: Mapping[str, Any]
    output: str | None = None


@dataclass(frozen=True)
class Expectation:
    step: int
    decisions: tuple[Verdict, ...]


@dataclass(frozen=True)
class Case:
    id: str
    threat: str | None
    kind: str
    task: str
    steps: tuple[CaseStep, ...]
    expect: Expectation
    source: str = ""
    servers: str = "trusted"
    pin_advertised: bool = False
    notes: str = ""

    @classmethod
    def from_dict(cls, data: Any, source: str = "") -> "Case":
        where = source or "<case>"

        def fail(msg: str) -> CaseError:
            return CaseError(f"{where}: {msg}")

        if not isinstance(data, Mapping):
            raise fail("case must be a YAML mapping")
        required = {"id", "kind", "task", "steps", "expect"}
        missing = required - set(data)
        if missing:
            raise fail(f"missing keys {sorted(missing)}")
        unknown = set(data) - required - {"threat", "notes", "servers", "pin_advertised"}
        if unknown:
            raise fail(f"unknown keys {sorted(unknown)}")

        case_id = data["id"]
        if not isinstance(case_id, str) or not CASE_ID_RE.match(case_id):
            raise fail(f"bad id {case_id!r}")
        kind = data["kind"]
        if kind not in KINDS:
            raise fail(f"kind must be one of {sorted(KINDS)}, got {kind!r}")
        threat = data.get("threat")
        if kind == "attack" and threat not in THREATS:
            raise fail(f"attack cases need threat T1..T9, got {threat!r}")
        if threat is not None and threat not in THREATS:
            raise fail(f"unknown threat {threat!r}")
        if not isinstance(data["task"], str) or not data["task"].strip():
            raise fail("task must be a non-empty string")
        servers = data.get("servers", "trusted")
        if not isinstance(servers, str) or not servers:
            raise fail("servers must be a server-set name")
        pin_advertised = data.get("pin_advertised", False)
        if not isinstance(pin_advertised, bool):
            raise fail("pin_advertised must be true or false")

        raw_steps = data["steps"]
        if not isinstance(raw_steps, list) or not raw_steps:
            raise fail("steps must be a non-empty list")
        steps: list[CaseStep] = []
        for i, raw in enumerate(raw_steps, start=1):
            if not isinstance(raw, Mapping) or "call" not in raw:
                raise fail(f"step {i} must be a mapping with a 'call'")
            extra = set(raw) - {"call", "output"}
            if extra:
                raise fail(f"step {i} has unknown keys {sorted(extra)}")
            output = raw.get("output")
            if output is not None and not isinstance(output, str):
                raise fail(f"step {i} output must be a string")
            try:
                ToolCall.from_dict(raw["call"])  # validate shape now, not mid-replay
            except ValueError as exc:
                raise fail(f"step {i}: {exc}") from None
            steps.append(CaseStep(call=dict(raw["call"]), output=output))

        exp = data["expect"]
        if not isinstance(exp, Mapping) or set(exp) != {"step", "decision"}:
            raise fail("expect must have exactly 'step' and 'decision'")
        step_no = exp["step"]
        if not isinstance(step_no, int) or isinstance(step_no, bool) or not 1 <= step_no <= len(steps):
            raise fail(f"expect.step must be 1..{len(steps)}, got {step_no!r}")
        raw_dec = exp["decision"]
        raw_dec = raw_dec if isinstance(raw_dec, list) else [raw_dec]
        if not raw_dec:
            raise fail("expect.decision is empty")
        try:
            decisions = tuple(Verdict.parse(d) for d in raw_dec)
        except ValueError as exc:
            raise fail(str(exc)) from None

        return cls(
            id=case_id,
            threat=threat,
            kind=kind,
            task=data["task"],
            steps=tuple(steps),
            expect=Expectation(step_no, decisions),
            source=source,
            servers=servers,
            pin_advertised=pin_advertised,
            notes=" ".join(str(data.get("notes") or "").split()),
        )


def load_case(path: str | Path) -> Case:
    path = Path(path)
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return Case.from_dict(data, source=str(path))


def load_cases(directory: str | Path) -> list[Case]:
    cases = [load_case(p) for p in sorted(Path(directory).glob("*.yaml"))]
    seen: dict[str, str] = {}
    for c in cases:
        if c.id in seen:
            raise CaseError(f"duplicate case id {c.id!r} in {seen[c.id]} and {c.source}")
        seen[c.id] = c.source
    return cases


# --------------------------------------------------------------------------
# Replay


# executor(call, scripted_output) -> StepOutcome
Executor = Callable[[ToolCall, "str | None"], StepOutcome]


@dataclass(frozen=True)
class StepRecord:
    index: int  # 1-based
    call: ToolCall
    decision: Decision
    result: ToolResult | None
    approved: bool | None = None


@dataclass
class Transcript:
    case: Case
    session: str
    steps: list[StepRecord] = field(default_factory=list)

    def decision_at(self, step: int) -> Decision:
        return self.steps[step - 1].decision

    @property
    def caught(self) -> bool:
        """True if the decision at ``expect.step`` is one the case accepts."""
        return self.decision_at(self.case.expect.step).verdict in self.case.expect.decisions


class MockAgent:
    """Replays a case's scripted calls through an executor."""

    def __init__(self, case: Case, session: str | None = None):
        self.case = case
        self.session = session or f"s-{case.id}"

    def proposals(self) -> Iterable[tuple[ToolCall, str | None]]:
        """The calls the agent would propose if every call were allowed."""
        chain: list[str] = []
        for step in self.case.steps:
            call = ToolCall.from_dict(
                step.call, task=self.case.task, session=self.session, call_chain=tuple(chain)
            )
            yield call, step.output
            chain.append(call.qualified_name)

    def replay(self, executor: Executor) -> Transcript:
        transcript = Transcript(self.case, self.session)
        # Blocked calls stay in the chain: the agent *proposed* them, and a
        # later rule may care that it tried.
        for i, (call, scripted) in enumerate(self.proposals(), start=1):
            outcome = executor(call, scripted)
            if not isinstance(outcome, StepOutcome):
                raise TypeError("executor must return a StepOutcome")
            try:
                outcome.check_consistent()
            except ValueError as exc:
                raise ValueError(f"step {i}: {exc}") from None
            transcript.steps.append(StepRecord(i, call, outcome.decision, outcome.result,
                                               outcome.approved))
        return transcript


def unguarded_executor(host: Any) -> Executor:
    """Baseline with no gateway: every call is allowed and runs.

    ``host`` is a ``mock.servers.MockToolHost``. Used to show what an attack
    case achieves when nothing stands between the agent and its tools.
    """

    def execute(call: ToolCall, scripted_output: str | None) -> StepOutcome:
        result = host.invoke(call, scripted_output)
        return StepOutcome(Decision.allow("no gateway (baseline)"), result)

    return execute
