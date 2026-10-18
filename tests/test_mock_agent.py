from pathlib import Path

import pytest
import yaml

from mcp_guard.models import Decision, Verdict
from mock.agent import (
    Case,
    CaseError,
    MockAgent,
    StepOutcome,
    load_case,
    load_cases,
    unguarded_executor,
)
from mock.servers import MockToolHost, trusted_servers

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "redteam" / "cases"
T1_CASE = CASES / "T1_web_injection_email.yaml"


@pytest.fixture
def case():
    return load_case(T1_CASE)


def raw_case():
    return yaml.safe_load(T1_CASE.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- loading

def test_load_t1_case(case):
    assert case.id == "T1-003" and case.threat == "T1" and case.kind == "attack"
    assert len(case.steps) == 2
    assert case.steps[0].output.startswith("Release 2.1")
    assert case.steps[1].output is None
    assert case.expect.step == 2
    assert case.expect.decisions == (Verdict.BLOCK, Verdict.ESCALATE)


def test_load_cases_directory():
    ids = [c.id for c in load_cases(CASES)]
    assert "T1-003" in ids and len(ids) == len(set(ids))


def test_duplicate_ids_across_files_rejected(tmp_path):
    for name in ("a.yaml", "b.yaml"):
        (tmp_path / name).write_text(T1_CASE.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(CaseError, match="duplicate case id"):
        load_cases(tmp_path)


def test_single_decision_string_is_accepted():
    data = raw_case()
    data["expect"]["decision"] = "BLOCK"
    assert Case.from_dict(data).expect.decisions == (Verdict.BLOCK,)


def test_benign_case_without_threat_is_valid():
    data = raw_case()
    data.update(id="B-001", kind="benign", expect={"step": 2, "decision": ["ALLOW"]})
    del data["threat"]
    assert Case.from_dict(data).threat is None


def _mutate(fn):
    data = raw_case()
    fn(data)
    return data


@pytest.mark.parametrize("mutation,msg", [
    (lambda d: d.pop("task"), "missing keys"),
    (lambda d: d.update(surprise=1), "unknown keys"),
    (lambda d: d.update(kind="maybe"), "kind must be"),
    (lambda d: d.update(threat="T10"), "threat"),
    (lambda d: d.update(id="has space"), "bad id"),
    (lambda d: d.update(task="  "), "task"),
    (lambda d: d.update(steps=[]), "non-empty list"),
    (lambda d: d["steps"][0].update(extra=1), "unknown keys"),
    (lambda d: d["steps"][0].update(output=42), "output must be a string"),
    (lambda d: d["steps"][1]["call"].pop("tool"), "missing tool"),
    (lambda d: d["steps"][1]["call"].update(server="a.b"), "invalid server name"),
    (lambda d: d["expect"].update(step=3), "expect.step"),
    (lambda d: d["expect"].update(step=0), "expect.step"),
    (lambda d: d["expect"].update(decision=["MAYBE"]), "unknown decision"),
    (lambda d: d["expect"].update(decision=[]), "empty"),
    (lambda d: d["expect"].pop("decision"), "exactly"),
])
def test_malformed_cases_rejected(mutation, msg):
    with pytest.raises(CaseError, match=msg):
        Case.from_dict(_mutate(mutation), source="x.yaml")


def test_non_mapping_case_rejected():
    with pytest.raises(CaseError):
        Case.from_dict(["not", "a", "case"])


# ---------------------------------------------------------------- replay

def test_proposals_carry_task_session_and_chain(case):
    calls = [c for c, _ in MockAgent(case, session="s-1").proposals()]
    assert [c.qualified_name for c in calls] == ["web.fetch_url", "mail.send_email"]
    assert all(c.task == case.task and c.session == "s-1" for c in calls)
    assert calls[0].call_chain == ()
    assert calls[1].call_chain == ("web.fetch_url",)


def test_unguarded_replay_lets_the_attack_succeed(case):
    """Baseline: with no gateway, the injected instruction is carried out.
    This is the behaviour M3+ must stop."""
    host = MockToolHost(trusted_servers())
    transcript = MockAgent(case).replay(unguarded_executor(host))

    assert [s.decision.verdict for s in transcript.steps] == [Verdict.ALLOW, Verdict.ALLOW]
    assert "evil-mail.com" in transcript.steps[0].result.output   # scripted page
    assert host.backend.outbox[0]["to"] == "ops@evil-mail.com"    # exfiltration happened
    assert transcript.caught is False


def test_replay_with_a_blocking_executor(case):
    host = MockToolHost(trusted_servers())
    seen = []

    def executor(call, scripted):
        seen.append((call.qualified_name, scripted))
        if call.tool == "send_email":
            return StepOutcome(Decision.block(["R1"], "address came from untrusted content", ["to"]))
        return StepOutcome(Decision.allow(), host.invoke(call, scripted))

    transcript = MockAgent(case).replay(executor)
    assert host.backend.outbox == []
    assert transcript.decision_at(2).rules == ("R1",)
    assert transcript.steps[1].result is None
    assert transcript.caught is True
    assert seen[0][1] == case.steps[0].output and seen[1][1] is None


def test_replay_is_deterministic(case):
    def run():
        host = MockToolHost(trusted_servers())
        t = MockAgent(case).replay(unguarded_executor(host))
        return [(s.call.to_dict(), s.decision, s.result.output) for s in t.steps], host.backend.outbox
    assert run() == run()


def test_replay_rejects_inconsistent_executors(case):
    with pytest.raises(ValueError, match="no result"):
        MockAgent(case).replay(lambda c, s: StepOutcome(Decision.allow()))
    host = MockToolHost(trusted_servers())
    with pytest.raises(ValueError, match="blocked but ran"):
        MockAgent(case).replay(
            lambda c, s: StepOutcome(Decision.block(["R0"], "x"), host.invoke(c, s)))
    with pytest.raises(TypeError):
        MockAgent(case).replay(lambda c, s: "ALLOW")
