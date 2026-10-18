"""Synthetic tools for the mock MCP servers.

Nothing here touches the real filesystem, network, shell, git or cloud. Every
tool reads and writes an in-memory ``MockBackend`` so tests can assert exactly
what an (unguarded or guarded) agent managed to do.

Tools: read_file, write_file, fetch_url, send_email, run_shell, git_push, deploy.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping


class ToolError(Exception):
    """A tool rejected its arguments or failed. Returned to the agent as an
    error result, never raised past the tool host."""


@dataclass
class MockBackend:
    """In-memory stand-in for the repo, the web, the mail server, CI/CD."""

    workspace_root: str = "/workspace"
    files: dict[str, str] = field(default_factory=dict)
    web: dict[str, str] = field(default_factory=dict)
    outbox: list[dict[str, str]] = field(default_factory=list)
    shell_log: list[str] = field(default_factory=list)
    pushes: list[dict[str, str]] = field(default_factory=list)
    deploys: list[dict[str, str]] = field(default_factory=list)

    def resolve(self, path: str) -> str:
        """Normalise a path; relative paths are taken from the workspace root.

        The mock does not refuse paths outside the workspace: enforcing that is
        the gateway's job (rule R5), and tests need to see what happens
        without it.
        """
        if not posixpath.isabs(path):
            path = posixpath.join(self.workspace_root, path)
        return posixpath.normpath(path)


# --------------------------------------------------------------------------
# A deliberately small JSON-Schema subset: object with typed properties,
# "required", and no extra properties. Enough to reject malformed calls.

_JSON_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "boolean": (bool,),
    "integer": (int,),
    "object": (dict,),
    "array": (list,),
}


def validate_args(schema: Mapping[str, Any], args: Mapping[str, Any]) -> None:
    props: Mapping[str, Any] = schema.get("properties", {})
    for name in schema.get("required", []):
        if name not in args:
            raise ToolError(f"missing required argument {name!r}")
    if schema.get("additionalProperties") is False:
        extra = set(args) - set(props)
        if extra:
            raise ToolError(f"unexpected arguments: {sorted(extra)}")
    for name, value in args.items():
        expected = props.get(name, {}).get("type")
        if expected is None:
            continue
        py_types = _JSON_TYPES[expected]
        ok = isinstance(value, py_types)
        if expected == "integer" and isinstance(value, bool):
            ok = False
        if not ok:
            raise ToolError(f"argument {name!r} must be of type {expected}")


def _schema(properties: dict[str, dict[str, Any]], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


_STR = {"type": "string"}


# --------------------------------------------------------------------------
# Handlers. Each takes (backend, args) and returns the tool's text output.


def _read_file(b: MockBackend, args: Mapping[str, Any]) -> str:
    path = b.resolve(args["path"])
    if path not in b.files:
        raise ToolError(f"no such file: {path}")
    return b.files[path]


def _write_file(b: MockBackend, args: Mapping[str, Any]) -> str:
    path = b.resolve(args["path"])
    b.files[path] = args["content"]
    return f"wrote {len(args['content'])} bytes to {path}"


def _fetch_url(b: MockBackend, args: Mapping[str, Any]) -> str:
    url = args["url"]
    if url not in b.web:
        raise ToolError(f"404 Not Found: {url}")
    return b.web[url]


def _send_email(b: MockBackend, args: Mapping[str, Any]) -> str:
    msg = {"to": args["to"], "subject": args.get("subject", ""), "body": args["body"]}
    b.outbox.append(msg)
    return f"sent message #{len(b.outbox)} to {args['to']}"


def _run_shell(b: MockBackend, args: Mapping[str, Any]) -> str:
    # Never executed: the command is only recorded.
    b.shell_log.append(args["command"])
    return f"(mock shell) exit 0: {args['command']}"


def _git_push(b: MockBackend, args: Mapping[str, Any]) -> str:
    push = {
        "remote": args.get("remote", "origin"),
        "branch": args["branch"],
        "force": "true" if args.get("force") else "false",
    }
    b.pushes.append(push)
    return f"pushed {push['branch']} to {push['remote']}" + (" (forced)" if args.get("force") else "")


def _deploy(b: MockBackend, args: Mapping[str, Any]) -> str:
    env = args["environment"]
    if env not in ("staging", "prod"):
        raise ToolError(f"unknown environment {env!r}")
    rec = {"environment": env, "ref": args["ref"]}
    b.deploys.append(rec)
    return f"deployed {rec['ref']} to {env}"


Handler = Callable[[MockBackend, Mapping[str, Any]], str]


@dataclass(frozen=True)
class MockTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Handler

    def run(self, backend: MockBackend, args: Mapping[str, Any]) -> str:
        validate_args(self.input_schema, args)
        return self.handler(backend, args)


TOOLS: dict[str, MockTool] = {
    t.name: t
    for t in (
        MockTool(
            "read_file",
            "Read a UTF-8 text file from the workspace and return its contents.",
            _schema({"path": _STR}, ["path"]),
            _read_file,
        ),
        MockTool(
            "write_file",
            "Create or overwrite a UTF-8 text file in the workspace.",
            _schema({"path": _STR, "content": _STR}, ["path", "content"]),
            _write_file,
        ),
        MockTool(
            "fetch_url",
            "Fetch a web page over HTTPS and return its text.",
            _schema({"url": _STR}, ["url"]),
            _fetch_url,
        ),
        MockTool(
            "send_email",
            "Send a plain-text email.",
            _schema({"to": _STR, "subject": _STR, "body": _STR}, ["to", "body"]),
            _send_email,
        ),
        MockTool(
            "run_shell",
            "Run a shell command in the workspace and return its output.",
            _schema({"command": _STR}, ["command"]),
            _run_shell,
        ),
        MockTool(
            "git_push",
            "Push a local branch to a git remote.",
            _schema(
                {"branch": _STR, "remote": _STR, "force": {"type": "boolean"}},
                ["branch"],
            ),
            _git_push,
        ),
        MockTool(
            "deploy",
            "Deploy a git ref to an environment (staging or prod).",
            _schema({"environment": _STR, "ref": _STR}, ["environment", "ref"]),
            _deploy,
        ),
    )
}
