"""Command-line interface: ``mcp-guard pin | verify | redteam | verify-log | demo``.

Implemented so far (M2): ``pin`` and ``verify``. The rest arrive in M4/M5.

Servers are loaded from ``--servers module:attr``, where ``attr`` is a callable
(or a list) giving objects with a ``specs()`` method, or ToolSpecs directly.
Like uvicorn's ``--app-dir``, the current directory is put on ``sys.path`` so
the dev-only ``mock`` package resolves when run from the repo root.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .models import ToolSpec
from .registry import (
    BLOCKING_EVENTS,
    RegistryError,
    load_lockfile,
    verify,
    write_lockfile,
)

DEFAULT_SERVERS = "mock.servers:trusted_servers"
DEFAULT_LOCK = "policy/registry.lock.yaml"

EXIT_OK = 0
EXIT_REFUSED = 1       # verification found a rug pull, shadowing, etc.
EXIT_ERROR = 2         # bad input, missing file, not implemented


def load_specs(target: str) -> list[ToolSpec]:
    module_name, sep, attr = target.partition(":")
    if not sep or not module_name or not attr:
        raise ValueError(f"--servers must look like module:attr, got {target!r}")
    cwd = str(Path.cwd())
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    obj: Any = getattr(importlib.import_module(module_name), attr)
    if callable(obj):
        obj = obj()
    specs: list[ToolSpec] = []
    for item in obj:
        if isinstance(item, ToolSpec):
            specs.append(item)
        elif hasattr(item, "specs"):
            specs.extend(item.specs())
        else:
            raise ValueError(f"{target}: cannot get tool specs from {item!r}")
    return specs


def cmd_pin(args: argparse.Namespace) -> int:
    specs = load_specs(args.servers)
    lock = write_lockfile(args.lock, specs)
    print(f"pinned {len(lock.tools)} tools -> {args.lock}")
    for qname in sorted(lock.tools):
        print(f"  {qname:28s} {lock.tools[qname].sha256[:16]}...")
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    lock = load_lockfile(args.lock)
    specs = load_specs(args.servers)
    registry = verify(specs, lock)
    for qname in sorted(registry.enabled):
        print(f"  OK        {qname}")
    for event in registry.events:
        print(f"  {event.kind.value:9s} {event.qualified_name}: {event.detail}")
        if event.expected:
            print(f"            expected {event.expected}")
            print(f"            actual   {event.actual}")
    refused = [e for e in registry.events if e.kind in BLOCKING_EVENTS]
    print(f"{len(registry.enabled)} enabled, {len(refused)} refused")
    return EXIT_OK if registry.ok else EXIT_REFUSED


def _not_yet(milestone: str):
    def run(args: argparse.Namespace) -> int:
        print(f"`{args.command}` is not implemented yet (planned for {milestone}).",
              file=sys.stderr)
        return EXIT_ERROR
    return run


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-guard",
        description="Security gateway between a coding agent and its MCP tools (prototype).",
    )
    p.add_argument("--version", action="version", version=f"mcp-guard {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_registry_args(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--servers", default=DEFAULT_SERVERS,
                        help=f"module:attr giving the servers (default {DEFAULT_SERVERS})")
        sp.add_argument("--lock", default=DEFAULT_LOCK,
                        help=f"lockfile path (default {DEFAULT_LOCK})")

    sp = sub.add_parser("pin", help="hash every advertised tool and write the lockfile")
    add_registry_args(sp)
    sp.set_defaults(func=cmd_pin)

    sp = sub.add_parser("verify", help="check advertised tools against the lockfile")
    add_registry_args(sp)
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("redteam", help="score the red-team corpus (M4)")
    sp.set_defaults(func=_not_yet("M4"))
    sp = sub.add_parser("verify-log", help="check the audit log's hash chain (M5)")
    sp.set_defaults(func=_not_yet("M5"))
    sp = sub.add_parser("demo", help="replay one case through the gateway (M5)")
    sp.set_defaults(func=_not_yet("M5"))
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RegistryError, ValueError, ImportError, AttributeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
