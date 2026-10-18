import json

import pytest

from mcp_guard.models import (
    AUDIT_FIELDS,
    AuditRecord,
    Decision,
    ToolCall,
    ToolResult,
    ToolSpec,
    Verdict,
    canonical_json,
    qualify,
    split_qualified,
    utc_now_iso,
)


# ---------------------------------------------------------------- canonical_json

def test_canonical_json_sorted_compact_utf8():
    assert canonical_json({"b": 1, "a": [1, {"d": 2, "c": "é"}]}) == \
        '{"a":[1,{"c":"é","d":2}],"b":1}'.encode("utf-8")


def test_canonical_json_independent_of_insertion_order():
    assert canonical_json({"x": 1, "y": 2}) == canonical_json({"y": 2, "x": 1})


def test_canonical_json_rejects_nan():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


# ---------------------------------------------------------------- names

def test_qualify_and_split_roundtrip():
    assert qualify("mail", "send_email") == "mail.send_email"
    assert split_qualified("mail.send_email") == ("mail", "send_email")
    # tool names may contain dots; split happens on the first one
    assert split_qualified("svc.tool.v2") == ("svc", "tool.v2")


@pytest.mark.parametrize("bad", ["", "a.b", "has space", "x" * 65, None, 3])
def test_bad_server_names_rejected(bad):
    with pytest.raises(ValueError):
        ToolCall(server=bad, tool="t")


@pytest.mark.parametrize("bad", ["", "has space", "semi;colon", "x" * 129])
def test_bad_tool_names_rejected(bad):
    with pytest.raises(ValueError):
        ToolCall(server="s", tool=bad)


def test_split_qualified_needs_a_dot():
    with pytest.raises(ValueError):
        split_qualified("nodot")


# ---------------------------------------------------------------- ToolSpec

def test_toolspec_from_and_to_mcp():
    raw = {"name": "t", "description": "d", "inputSchema": {"type": "object"},
           "annotations": {"readOnlyHint": True}}
    spec = ToolSpec.from_mcp("srv", raw)
    assert spec.qualified_name == "srv.t"
    assert spec.to_mcp() == {"name": "t", "description": "d", "inputSchema": {"type": "object"}}


def test_toolspec_defaults_when_fields_absent():
    spec = ToolSpec.from_mcp("srv", {"name": "t"})
    assert spec.description == "" and spec.input_schema == {}


def test_toolspec_copies_schema():
    schema = {"type": "object", "properties": {}}
    spec = ToolSpec("s", "t", "d", schema)
    schema["properties"]["evil"] = {"type": "string"}
    assert spec.input_schema == {"type": "object", "properties": {}}


@pytest.mark.parametrize("raw", [{"name": "t", "description": 5},
                                 {"name": "t", "inputSchema": []},
                                 {"description": "no name"}])
def test_toolspec_rejects_bad_fields(raw):
    with pytest.raises(ValueError):
        ToolSpec.from_mcp("srv", raw)


# ---------------------------------------------------------------- ToolCall

def test_toolcall_from_dict_with_context():
    call = ToolCall.from_dict(
        {"server": "mail", "tool": "send_email", "args": {"to": "a@example.com"}},
        task="t", session="s1", call_chain=["web.fetch_url"],
    )
    assert call.qualified_name == "mail.send_email"
    assert call.call_chain == ("web.fetch_url",)
    assert call.to_dict()["args"] == {"to": "a@example.com"}


def test_toolcall_args_are_a_private_copy():
    args = {"to": "a@example.com", "nested": {"k": "v"}}
    call = ToolCall("mail", "send_email", args)
    args["to"] = "evil@example.net"
    args["nested"]["k"] = "changed"
    assert call.args == {"to": "a@example.com", "nested": {"k": "v"}}


def test_toolcall_missing_args_defaults_to_empty():
    assert ToolCall.from_dict({"server": "s", "tool": "t"}).args == {}
    assert ToolCall.from_dict({"server": "s", "tool": "t", "args": None}).args == {}


@pytest.mark.parametrize("data", [
    {"tool": "t"},
    {"server": "s"},
    {"server": "s", "tool": "t", "args": ["not", "a", "mapping"]},
    {"server": "s", "tool": "t", "extra": 1},
    "not a mapping",
])
def test_toolcall_from_dict_rejects_bad_input(data):
    with pytest.raises(ValueError):
        ToolCall.from_dict(data)


def test_toolresult_is_untrusted_by_default():
    r = ToolResult(ToolCall("web", "fetch_url"), "page")
    assert r.untrusted and not r.error


# ---------------------------------------------------------------- Verdict / Decision

def test_verdict_parse():
    assert Verdict.parse("block") is Verdict.BLOCK
    assert Verdict.parse(Verdict.ALLOW) is Verdict.ALLOW
    assert str(Verdict.ESCALATE) == "ESCALATE"
    with pytest.raises(ValueError):
        Verdict.parse("MAYBE")


def test_decision_constructors():
    d = Decision.block(["R1"], "arg 'to' came from untrusted content", ["to"])
    assert d.verdict is Verdict.BLOCK and d.rules == ("R1",) and d.tainted_args == ("to",)
    assert not d.allowed
    assert Decision.allow().allowed
    assert Decision.escalate(["R3"], "irreversible").verdict is Verdict.ESCALATE


def test_decision_accepts_string_verdict_and_rejects_empty_rule():
    assert Decision("allow").verdict is Verdict.ALLOW
    with pytest.raises(ValueError):
        Decision(Verdict.BLOCK, ("",), "x")


# ---------------------------------------------------------------- AuditRecord

def _record(**kw):
    base = dict(ts="2026-10-18T14:02:11Z", seq=42, session="s-7f3a", server="web",
                tool="fetch_url", decision="BLOCK", rules=["R1"],
                reason="arg 'to' came from untrusted content", tainted_args=["to"],
                prev_hash="9c1e", hash="e04b")
    base.update(kw)
    return AuditRecord(**base)


def test_audit_record_field_order_matches_plan():
    assert list(_record().to_dict()) == list(AUDIT_FIELDS)
    assert "hash" not in _record().to_dict(include_hash=False)


def test_audit_record_roundtrip_through_json():
    rec = _record()
    again = AuditRecord.from_dict(json.loads(json.dumps(rec.to_dict())))
    assert again == rec
    assert again.decision is Verdict.BLOCK


@pytest.mark.parametrize("seq", [-1, True, "3"])
def test_audit_record_rejects_bad_seq(seq):
    with pytest.raises(ValueError):
        _record(seq=seq)


def test_audit_record_from_dict_rejects_unknown_and_missing():
    d = _record().to_dict()
    with pytest.raises(ValueError):
        AuditRecord.from_dict({**d, "surprise": 1})
    del d["tool"]
    with pytest.raises(ValueError):
        AuditRecord.from_dict(d)


def test_audit_record_for_decision():
    call = ToolCall("mail", "send_email", {"to": "x"}, session="s1")
    rec = AuditRecord.for_decision(call, Decision.block(["R1"], "tainted", ["to"]),
                                   seq=0, prev_hash="0" * 64)
    assert (rec.server, rec.tool, rec.session, rec.decision) == \
        ("mail", "send_email", "s1", Verdict.BLOCK)
    assert rec.hash is None
    assert rec.ts.endswith("Z") and len(rec.ts) == len(utc_now_iso())
