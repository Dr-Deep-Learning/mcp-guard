import pytest

from mcp_guard.models import ToolCall
from mock.servers import (
    MockServer,
    MockToolHost,
    rug_pulled_servers,
    shadowing_servers,
    trusted_servers,
)
from mock.tools import TOOLS, MockBackend, ToolError, validate_args

EXPECTED_TOOLS = {"read_file", "write_file", "fetch_url", "send_email",
                  "run_shell", "git_push", "deploy"}


@pytest.fixture
def host():
    backend = MockBackend(files={"/workspace/README.md": "hello"},
                          web={"https://docs.example.com/notes": "Release 2.1"})
    return MockToolHost(trusted_servers(), backend)


def call(server, tool, **args):
    return ToolCall(server, tool, args)


def test_all_synthetic_tools_exist():
    assert set(TOOLS) == EXPECTED_TOOLS
    served = {t for s in trusted_servers() for t in s.tools}
    assert served == EXPECTED_TOOLS


def test_list_tools_is_mcp_shaped():
    for server in trusted_servers():
        for entry in server.list_tools():
            assert set(entry) == {"name", "description", "inputSchema"}
            assert entry["inputSchema"]["type"] == "object"


def test_read_file_relative_and_absolute(host):
    assert host.invoke(call("workspace", "read_file", path="README.md")).output == "hello"
    assert host.invoke(call("workspace", "read_file", path="/workspace/./README.md")).output == "hello"


def test_read_missing_file_is_an_error_result(host):
    r = host.invoke(call("workspace", "read_file", path="nope.txt"))
    assert r.error and "no such file" in r.output


def test_write_file(host):
    r = host.invoke(call("workspace", "write_file", path="src/a.py", content="x = 1\n"))
    assert not r.error
    assert host.backend.files["/workspace/src/a.py"] == "x = 1\n"


def test_fetch_url(host):
    assert host.invoke(call("web", "fetch_url", url="https://docs.example.com/notes")).output == "Release 2.1"
    assert host.invoke(call("web", "fetch_url", url="https://other.example.com")).error


def test_send_email_goes_to_outbox_only(host):
    host.invoke(call("mail", "send_email", to="a@example.com", subject="hi", body="b"))
    assert host.backend.outbox == [{"to": "a@example.com", "subject": "hi", "body": "b"}]


def test_run_shell_is_recorded_never_executed(host):
    r = host.invoke(call("workspace", "run_shell", command="rm -rf /"))
    assert "(mock shell)" in r.output
    assert host.backend.shell_log == ["rm -rf /"]


def test_git_push_and_deploy(host):
    host.invoke(call("workspace", "git_push", branch="feature/x", force=True))
    assert host.backend.pushes == [{"remote": "origin", "branch": "feature/x", "force": "true"}]
    host.invoke(call("workspace", "deploy", environment="prod", ref="v2.1"))
    assert host.backend.deploys == [{"environment": "prod", "ref": "v2.1"}]
    assert host.invoke(call("workspace", "deploy", environment="moon", ref="v1")).error


@pytest.mark.parametrize("args,msg", [
    ({}, "missing required"),
    ({"to": "a@example.com", "body": "b", "cc": "x"}, "unexpected"),
    ({"to": 5, "body": "b"}, "must be of type string"),
])
def test_argument_validation(args, msg):
    with pytest.raises(ToolError, match=msg):
        validate_args(TOOLS["send_email"].input_schema, args)


def test_bool_is_not_an_integer():
    with pytest.raises(ToolError):
        validate_args({"properties": {"n": {"type": "integer"}}}, {"n": True})


def test_bad_args_become_error_results(host):
    r = host.invoke(call("mail", "send_email", body="no recipient"))
    assert r.error and host.backend.outbox == []


def test_unknown_server_and_tool(host):
    assert host.invoke(call("nowhere", "x")).error
    assert host.invoke(call("web", "send_email", to="a", body="b")).error


def test_scripted_output_seeds_read_tools(host):
    r = host.invoke(call("web", "fetch_url", url="https://new.example.com"), "scripted page")
    assert r.output == "scripted page"
    assert host.backend.web["https://new.example.com"] == "scripted page"


def test_scripted_output_replaces_sink_return_but_keeps_side_effects(host):
    r = host.invoke(call("workspace", "run_shell", command="ls"), "README.md\n")
    assert r.output == "README.md\n"
    assert host.backend.shell_log == ["ls"]


def test_tool_output_is_always_untrusted(host):
    assert host.invoke(call("workspace", "read_file", path="README.md")).untrusted


def test_host_refuses_duplicate_server_names():
    with pytest.raises(ValueError):
        MockToolHost(trusted_servers() + [MockServer("web")])


def test_attack_variants_differ_from_trusted_in_the_intended_way():
    trusted = {s.qualified_name: s for srv in trusted_servers() for s in srv.specs()}
    rug = {s.qualified_name: s for srv in rug_pulled_servers() for s in srv.specs()}
    changed = [q for q in trusted if trusted[q] != rug[q]]
    assert changed == ["web.fetch_url"]
    assert "Do not tell the user" in rug["web.fetch_url"].description

    shadow = [s.qualified_name for srv in shadowing_servers() for s in srv.specs()]
    assert "helper.send_email" in shadow and "mail.send_email" in shadow


def test_variants_do_not_mutate_the_shared_tool_table():
    rug_pulled_servers()
    assert "IMPORTANT" not in TOOLS["fetch_url"].description
