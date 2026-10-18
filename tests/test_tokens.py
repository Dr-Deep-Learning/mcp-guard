"""Token broker, credential stripping, and scope enforcement by the mock backends (T4)."""

from pathlib import Path

import pytest

from mcp_guard.models import ToolCall
from mcp_guard.policy import load_policy
from mcp_guard.tokens import REDACTED, TokenBroker, strip_credentials
from mock.servers import MockToolHost, trusted_servers

ROOT = Path(__file__).resolve().parents[1]
POLICY = load_policy(ROOT / "policy" / "policy.yaml")


@pytest.fixture
def broker():
    return TokenBroker(POLICY)


# ---------------------------------------------------------------- broker

def test_token_carries_only_the_tools_policy_scopes(broker):
    tok = broker.token_for("mail.send_email")
    assert tok.tool == "mail.send_email" and tok.scopes == ("mail:send",)
    assert tok.allows("mail:send") and not tok.allows("repo:write")


def test_one_token_per_tool(broker):
    a = broker.token_for("workspace.read_file")
    assert broker.token_for("workspace.read_file") is a
    assert broker.token_for("workspace.write_file").secret != a.secret


def test_no_token_for_tools_without_scopes_or_unknown_tools(broker):
    assert broker.token_for("web.fetch_url") is None
    assert broker.token_for("workspace.run_shell") is None
    assert broker.token_for("nope.tool") is None


def test_secret_is_not_in_repr(broker):
    tok = broker.token_for("mail.send_email")
    assert tok.secret not in repr(tok) and "secret" not in repr(tok)


def test_brokers_issue_different_secrets():
    assert TokenBroker(POLICY).token_for("mail.send_email").secret != \
        TokenBroker(POLICY).token_for("mail.send_email").secret


# ---------------------------------------------------------------- stripping

def test_strip_removes_credential_fields_and_redacts_values():
    args = {
        "to": "a@example.com",
        "headers": {"Authorization": "Bearer abc", "X-Trace": "1"},
        "body": "key AKIAIOSFODNN7EXAMPLE and Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
        "notes": ["ok", "ghp_" + "a1B2" * 9],
    }
    clean, stripped = strip_credentials(args)
    assert clean["headers"] == {"X-Trace": "1"}
    assert "AKIA" not in clean["body"] and "eyJ" not in clean["body"]
    assert clean["body"].count(REDACTED) == 2
    assert clean["notes"] == ["ok", REDACTED]
    assert clean["to"] == "a@example.com"
    assert set(stripped) == {"headers.Authorization", "body", "notes[1]"}


def test_strip_redacts_authorization_header_lines():
    clean, stripped = strip_credentials({"raw": "GET / HTTP/1.1\nAuthorization: Basic dXNlcjpwYXNz\nAccept: */*"})
    assert clean["raw"] == f"GET / HTTP/1.1\nAuthorization: {REDACTED}\nAccept: */*"
    assert stripped == ["raw"]


def test_strip_leaves_clean_args_alone_and_does_not_mutate_input():
    args = {"to": "a@example.com", "body": "Use a bearer token from the vault.", "n": 3}
    original = {"to": "a@example.com", "body": "Use a bearer token from the vault.", "n": 3}
    clean, stripped = strip_credentials(args)
    assert clean == original and stripped == [] and args == original


# ---------------------------------------------------------------- scope enforcement (mock backends)

@pytest.fixture
def host():
    return MockToolHost(trusted_servers(), require_auth=True)


def test_backend_rejects_calls_without_a_token(host):
    r = host.invoke(ToolCall("mail", "send_email", {"to": "a@example.com", "body": "x"}))
    assert r.error and "401" in r.output and host.backend.outbox == []


def test_token_for_one_tool_cannot_be_used_for_another(host, broker):
    read_token = broker.token_for("workspace.read_file")
    r = host.invoke(ToolCall("mail", "send_email", {"to": "a@example.com", "body": "x"}),
                    credential=read_token)
    assert r.error and "needs scope mail:send" in r.output


def test_correct_token_works_and_only_its_id_is_recorded(host, broker):
    tok = broker.token_for("mail.send_email")
    r = host.invoke(ToolCall("mail", "send_email", {"to": "a@example.com", "body": "x"}), credential=tok)
    assert not r.error
    assert host.backend.auth_log == [{"tool": "mail.send_email", "token_id": tok.token_id,
                                      "token_tool": "mail.send_email"}]
    assert tok.secret not in str(host.backend.auth_log)


def test_deploy_scope_depends_on_environment(host, broker):
    tok = broker.token_for("workspace.deploy")
    assert not host.invoke(ToolCall("workspace", "deploy", {"environment": "staging", "ref": "v1"}),
                           credential=tok).error


def test_tools_without_a_required_scope_run_without_a_token(host):
    assert not host.invoke(ToolCall("workspace", "run_shell", {"command": "ls"})).error


def test_auth_is_off_by_default_for_the_unguarded_baseline():
    host = MockToolHost(trusted_servers())
    assert not host.invoke(ToolCall("mail", "send_email", {"to": "a@example.com", "body": "x"})).error
