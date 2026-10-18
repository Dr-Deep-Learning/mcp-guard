from pathlib import Path

import pytest
import yaml

from mcp_guard.policy import PolicyError, load_policy, parse_policy
from mcp_guard.registry import load_lockfile

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policy" / "policy.yaml"


@pytest.fixture
def policy():
    return load_policy(POLICY)


def raw():
    return yaml.safe_load(POLICY.read_text(encoding="utf-8"))


def test_committed_policy_loads(policy):
    assert policy.workspace_root == "/workspace"
    assert policy.min_substring == 20
    assert "docs.example.com" in policy.allow_hosts
    assert policy.allow_email_domains == ("example.com",)


def test_policy_covers_exactly_the_pinned_tools(policy):
    assert set(policy.tools) == set(load_lockfile(ROOT / "policy" / "registry.lock.yaml").tools)


def test_tool_flags(policy):
    assert policy.tool("mail.send_email").sink
    assert policy.tool("mail.send_email").destination_args == ("to",)
    assert not policy.tool("web.fetch_url").sink
    assert policy.tool("workspace.run_shell").shell_args == ("command",)
    assert policy.tool("nope.tool") is None


def test_conditional_irreversibility(policy):
    deploy = policy.tool("workspace.deploy")
    assert deploy.is_irreversible({"environment": "prod", "ref": "v1"})
    assert not deploy.is_irreversible({"environment": "staging", "ref": "v1"})
    push = policy.tool("workspace.git_push")
    assert push.is_irreversible({"branch": "main", "force": True})
    assert not push.is_irreversible({"branch": "main"})
    assert not push.is_irreversible({"branch": "main", "force": False})


def test_plain_irreversible_flag():
    data = raw()
    data["tools"]["workspace.deploy"] = {"irreversible": True}
    assert parse_policy(data).tool("workspace.deploy").is_irreversible({})


def test_tool_with_empty_body_gets_defaults():
    data = raw()
    data["tools"]["extra.tool"] = None
    t = parse_policy(data).tool("extra.tool")
    assert not t.sink and not t.irreversible and t.egress_args == ()


def test_hosts_are_normalised():
    data = raw()
    data["egress"]["allow_hosts"] = ["Docs.Example.COM."]
    assert parse_policy(data).allow_hosts == ("docs.example.com",)


@pytest.mark.parametrize("mutate,msg", [
    (lambda d: d.update(version=2), "version"),
    (lambda d: d.update(extra=1), "unknown top-level"),
    (lambda d: d.update(workspace_root="workspace"), "absolute"),
    (lambda d: d.update(workspace_root="/"), "must not be '/'"),
    (lambda d: d.update(tools={}), "non-empty"),
    (lambda d: d["tools"].update({"nodot": {}}), "server-qualified"),
    (lambda d: d["tools"]["mail.send_email"].update(sinks=True), "unknown keys"),
    (lambda d: d["tools"]["mail.send_email"].update(sink="yes"), "true or false"),
    (lambda d: d["tools"]["mail.send_email"].update(egress_args="to"), "list of non-empty strings"),
    (lambda d: d["tools"]["workspace.deploy"].update(irreversible_when=["prod"]), "mapping"),
    (lambda d: d["tools"]["workspace.deploy"].update(irreversible_when={"environment": []}), "scalar"),
    (lambda d: d["egress"].update(deny_hosts=[]), "egress may only"),
    (lambda d: d["taint"].update(min_substring_length=3), ">= 8"),
    (lambda d: d["taint"].update(other=1), "taint may only"),
])
def test_malformed_policies_rejected(mutate, msg):
    data = raw()
    mutate(data)
    with pytest.raises(PolicyError, match=msg):
        parse_policy(data)


def test_non_mapping_rejected():
    with pytest.raises(PolicyError):
        parse_policy(["tools"])


def test_missing_and_invalid_files(tmp_path):
    with pytest.raises(PolicyError, match="not found"):
        load_policy(tmp_path / "none.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("tools: [", encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid YAML"):
        load_policy(bad)
