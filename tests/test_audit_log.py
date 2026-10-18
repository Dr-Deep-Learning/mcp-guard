"""Hash-chained audit log and verify-log (T9)."""

import hashlib
import json

import pytest

from mcp_guard import cli
from mcp_guard.audit_log import GENESIS, AuditLog, AuditLogError, record_hash, verify_lines, verify_log
from mcp_guard.models import AUDIT_FIELDS, Decision, ToolCall, canonical_json

CALLS = [
    (ToolCall("web", "fetch_url", {"url": "https://docs.example.com/n"}, session="s1"), Decision.allow("ok")),
    (ToolCall("mail", "send_email", {"to": "x@evil.example", "body": "b"}, session="s1"),
     Decision.block(["R1", "R4"], "tainted", ["to"])),
    (ToolCall("workspace", "deploy", {"environment": "prod", "ref": "v1"}, session="s1"),
     Decision.escalate(["R3"], "irreversible")),
    (ToolCall("workspace", "run_shell", {"command": "ls"}, session="s1"), Decision.allow("ok")),
]


def build(path=None):
    log = AuditLog(path)
    for call, decision in CALLS:
        if decision.verdict.value == "ESCALATE":
            log.log_decision(call, decision, "auto-deny", False)
        else:
            log.log_decision(call, decision)
    return log


def edit(lines, i, rehash=False, **changes):
    out = list(lines)
    rec = json.loads(out[i])
    rec.update(changes)
    if rehash:
        rec["hash"] = record_hash(rec)
    out[i] = json.dumps(rec, separators=(",", ":"))
    return out


# ---------------------------------------------------------------- writing

def test_chain_structure():
    log = build()
    recs = [json.loads(line) for line in log.lines]
    assert [r["seq"] for r in recs] == [0, 1, 2, 3]
    assert recs[0]["prev_hash"] == GENESIS
    for prev, cur in zip(recs, recs[1:]):
        assert cur["prev_hash"] == prev["hash"]
    assert log.head == recs[-1]["hash"] and log.seq == 4
    assert all(list(r) == list(AUDIT_FIELDS) for r in recs)


def test_hash_is_sha256_of_canonical_record_without_hash():
    rec = json.loads(build().lines[1])
    body = {k: v for k, v in rec.items() if k != "hash"}
    assert rec["hash"] == hashlib.sha256(canonical_json(body)).hexdigest()


def test_record_contents():
    recs = [json.loads(line) for line in build().lines]
    assert (recs[1]["decision"], recs[1]["rules"], recs[1]["tainted_args"]) == ("BLOCK", ["R1", "R4"], ["to"])
    assert (recs[2]["approver"], recs[2]["approved"]) == ("auto-deny", False)
    assert (recs[0]["approver"], recs[0]["approved"]) == (None, None)
    assert "args" not in recs[0]          # arguments (and any secrets in them) are not logged


def test_event_records():
    log = AuditLog()
    rec = log.log_event("web", "fetch_url", "RUG_PULL", "description changed")
    assert (rec.session, rec.decision.value, rec.rules) == ("gateway", "BLOCK", ("RUG_PULL",))
    assert log.verify().ok


def test_file_log_reopens_and_continues_the_chain(tmp_path):
    path = tmp_path / "logs" / "audit.jsonl"
    first = build(path)
    again = AuditLog(path)
    assert (again.seq, again.head) == (first.seq, first.head)
    again.log_decision(*CALLS[0])
    result = verify_log(path)
    assert result.ok and result.records == 5
    assert b"\r\n" not in path.read_bytes()


def test_refuses_to_append_to_a_broken_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    build(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(edit(lines, 1, decision="ALLOW")) + "\n", encoding="utf-8")
    with pytest.raises(AuditLogError, match="refusing to append"):
        AuditLog(path)


# ---------------------------------------------------------------- tampering (T9)

def test_intact_log_verifies():
    log = build()
    r = verify_lines(log.lines, expected_head=log.head)
    assert r.ok and r.records == 4 and r.head == log.head


@pytest.mark.parametrize("tamper,line,reason", [
    (lambda ls: edit(ls, 1, decision="ALLOW"), 2, "edited"),
    (lambda ls: edit(ls, 2, approved=True), 3, "edited"),
    (lambda ls: ls[:1] + ls[2:], 2, "seq"),                                # delete
    (lambda ls: ls[:2] + [ls[1]] + ls[2:], 3, "seq"),                      # duplicate/insert
    (lambda ls: [ls[0], ls[2], ls[1], ls[3]], 2, "seq"),                   # reorder
    (lambda ls: edit(ls, 1, rehash=True, decision="ALLOW"), 3, "prev_hash"),  # rehash middle
    (lambda ls: edit(ls, 0, rehash=True, prev_hash="f" * 64), 1, "prev_hash"),  # wrong genesis
    (lambda ls: ls[:1] + ["{not json"] + ls[1:], 2, "not valid JSON"),
    (lambda ls: edit(ls, 1, extra="x"), 2, "fields"),
])
def test_tampering_is_detected_at_the_first_bad_line(tamper, line, reason):
    r = verify_lines(tamper(build().lines))
    assert not r.ok and r.broken_line == line and reason in r.reason


def test_truncation_needs_the_head_anchor():
    log = build()
    truncated = log.lines[:-1]
    assert verify_lines(truncated).ok                      # documented limit of a bare chain
    r = verify_lines(truncated, expected_head=log.head)
    assert not r.ok and "head does not match" in r.reason


def test_rewriting_the_last_record_needs_the_head_anchor():
    log = build()
    forged = edit(log.lines, 3, rehash=True, decision="BLOCK")
    assert verify_lines(forged).ok
    assert not verify_lines(forged, expected_head=log.head).ok


def test_blank_lines_are_ignored():
    assert verify_lines(build().lines + ["", "  "]).ok


def test_empty_log():
    r = verify_lines([])
    assert r.ok and r.records == 0 and r.head == GENESIS


def test_missing_file(tmp_path):
    with pytest.raises(AuditLogError, match="not found"):
        verify_log(tmp_path / "none.jsonl")


# ---------------------------------------------------------------- CLI

def test_cli_verify_log(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    log = build(path)
    assert cli.main(["verify-log", str(path)]) == cli.EXIT_OK
    assert "OK: 4 records" in capsys.readouterr().out
    assert cli.main(["verify-log", str(path), "--head", log.head]) == cli.EXIT_OK

    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    assert cli.main(["verify-log", str(path), "--head", log.head]) == cli.EXIT_REFUSED
    path.write_text("\n".join(edit(lines, 1, decision="ALLOW")) + "\n", encoding="utf-8")
    assert cli.main(["verify-log", str(path)]) == cli.EXIT_REFUSED
    assert "BROKEN at line 2" in capsys.readouterr().out


def test_cli_verify_log_missing_file(tmp_path, capsys):
    assert cli.main(["verify-log", str(tmp_path / "x.jsonl")]) == cli.EXIT_ERROR
