import os
from pathlib import Path

import pytest

from mcp_guard import cli
from mcp_guard.registry import load_lockfile

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def in_repo_root(monkeypatch):
    # The CLI resolves `mock.servers` relative to the working directory.
    monkeypatch.chdir(ROOT)


def test_pin_then_verify_ok(tmp_path, capsys):
    lock = tmp_path / "registry.lock.yaml"
    assert cli.main(["pin", "--lock", str(lock)]) == cli.EXIT_OK
    assert len(load_lockfile(lock).tools) == 7
    assert cli.main(["verify", "--lock", str(lock)]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "7 enabled, 0 refused" in out


def test_verify_committed_lockfile_ok():
    assert cli.main(["verify"]) == cli.EXIT_OK


def test_verify_detects_rug_pull(capsys):
    code = cli.main(["verify", "--servers", "mock.servers:rug_pulled_servers"])
    out = capsys.readouterr().out
    assert code == cli.EXIT_REFUSED
    assert "RUG_PULL  web.fetch_url" in out and "expected" in out


def test_verify_detects_shadowing(capsys):
    code = cli.main(["verify", "--servers", "mock.servers:shadowing_servers"])
    assert code == cli.EXIT_REFUSED
    assert "SHADOWING helper.send_email" in capsys.readouterr().out


def test_pin_refuses_shadowing(tmp_path, capsys):
    lock = tmp_path / "lock.yaml"
    code = cli.main(["pin", "--servers", "mock.servers:shadowing_servers", "--lock", str(lock)])
    assert code == cli.EXIT_ERROR
    assert "duplicate tool names" in capsys.readouterr().err
    assert not lock.exists()


def test_missing_lockfile_is_an_error(tmp_path, capsys):
    assert cli.main(["verify", "--lock", str(tmp_path / "none.yaml")]) == cli.EXIT_ERROR
    assert "mcp-guard pin" in capsys.readouterr().err


@pytest.mark.parametrize("target", ["no_colon", "mock.servers:does_not_exist",
                                    "no_such_module:x"])
def test_bad_servers_target(target):
    assert cli.main(["verify", "--servers", target]) == cli.EXIT_ERROR


@pytest.mark.parametrize("command", ["verify-log", "demo"])
def test_later_milestone_commands_say_not_implemented(command, capsys):
    assert cli.main([command]) == cli.EXIT_ERROR
    assert "not implemented yet" in capsys.readouterr().err


def test_pin_refuses_poisoned_description(tmp_path, capsys):
    lock = tmp_path / "lock.yaml"
    code = cli.main(["pin", "--servers", "mock.servers:rug_pulled_servers", "--lock", str(lock)])
    assert code == cli.EXIT_ERROR
    assert "R7" in capsys.readouterr().err
    assert not lock.exists()
