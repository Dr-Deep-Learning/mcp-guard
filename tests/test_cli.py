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


def test_demo_t1_003_shows_block_r1(capsys):
    assert cli.main(["demo", "--case", "T1-003"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "BLOCK  [R1, R4, R2]" in out
    assert "came from untrusted content" in out


def test_demo_rug_pull(capsys):
    assert cli.main(["demo", "--case", "T1-003", "--servers", "rug_pulled"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "RUG_PULL web.fetch_url" in out and "BLOCK  [REGISTRY]" in out


def test_demo_t6_001_shows_r5(capsys):
    assert cli.main(["demo", "--case", "T6-001"]) == cli.EXIT_OK
    assert "BLOCK  [R5]" in capsys.readouterr().out


def test_demo_writes_a_verifiable_log(tmp_path, capsys):
    log = tmp_path / "audit.jsonl"
    assert cli.main(["demo", "--case", "T1-003", "--log", str(log)]) == cli.EXIT_OK
    assert cli.main(["demo", "--case", "T7-001", "--log", str(log)]) == cli.EXIT_OK
    assert "approval: denied by auto-deny" in capsys.readouterr().out
    assert cli.main(["verify-log", str(log)]) == cli.EXIT_OK
    assert "OK: 4 records" in capsys.readouterr().out


def test_demo_unknown_case_or_server_set(capsys):
    assert cli.main(["demo", "--case", "T0-000"]) == cli.EXIT_ERROR
    assert "no case" in capsys.readouterr().err
    assert cli.main(["demo", "--case", "T1-003", "--servers", "nope"]) == cli.EXIT_ERROR


def test_pin_refuses_poisoned_description(tmp_path, capsys):
    lock = tmp_path / "lock.yaml"
    code = cli.main(["pin", "--servers", "mock.servers:rug_pulled_servers", "--lock", str(lock)])
    assert code == cli.EXIT_ERROR
    assert "R7" in capsys.readouterr().err
    assert not lock.exists()
