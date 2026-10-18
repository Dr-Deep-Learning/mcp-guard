"""Load and validate ``policy/policy.yaml``.

The policy is the part of the gateway a team reviews like code: which tools
are sinks, which are irreversible, where data may go, and where the
workspace is. Rules read it; they never hard-code tool names.

Per-tool fields (all optional except that the tool must be listed at all;
a tool missing from the policy is blocked):

    sink                  bool   sends, writes or executes (R1, R2)
    irreversible          bool   always held for a human (R3)
    irreversible_when     {arg: [values]}  irreversible only for these values (R3)
    destination_args      [arg]  where a sink sends things (R2)
    trusted_destinations  [str]  destinations that never need naming in the task (R2)
    egress_args           [arg]  args whose URLs / email addresses must be allowlisted (R4)
    shell_args            [arg]  args holding a shell command (R5)
    path_args             [arg]  args holding a path the call writes to (R5 sandbox check)
    scopes                [str]  token scopes the broker may attach (M5)
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from .models import split_qualified

POLICY_VERSION = 1
DEFAULT_MIN_SUBSTRING = 20

_TOOL_KEYS = {
    "sink", "irreversible", "irreversible_when", "destination_args",
    "trusted_destinations", "egress_args", "shell_args", "path_args", "scopes",
}
_TOP_KEYS = {"version", "workspace_root", "tools", "egress", "taint"}


class PolicyError(ValueError):
    """The policy file is missing or malformed."""


@dataclass(frozen=True)
class ToolPolicy:
    sink: bool = False
    irreversible: bool = False
    irreversible_when: Mapping[str, tuple[Any, ...]] = field(default_factory=dict)
    destination_args: tuple[str, ...] = ()
    trusted_destinations: tuple[str, ...] = ()
    egress_args: tuple[str, ...] = ()
    shell_args: tuple[str, ...] = ()
    path_args: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()

    def is_irreversible(self, args: Mapping[str, Any]) -> bool:
        if self.irreversible:
            return True
        return any(args.get(arg) in values for arg, values in self.irreversible_when.items())


@dataclass(frozen=True)
class Policy:
    workspace_root: str
    tools: Mapping[str, ToolPolicy]
    allow_hosts: tuple[str, ...] = ()
    allow_email_domains: tuple[str, ...] = ()
    min_substring: int = DEFAULT_MIN_SUBSTRING

    def tool(self, qualified_name: str) -> ToolPolicy | None:
        return self.tools.get(qualified_name)


def _str_list(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise PolicyError(f"{where} must be a list of non-empty strings")
    return tuple(value)


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{where} must be true or false")
    return value


def _tool_policy(name: str, raw: Any) -> ToolPolicy:
    where = f"tools.{name}"
    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        raise PolicyError(f"{where} must be a mapping")
    unknown = set(raw) - _TOOL_KEYS
    if unknown:
        raise PolicyError(f"{where} has unknown keys {sorted(unknown)}")

    when_raw = raw.get("irreversible_when") or {}
    if not isinstance(when_raw, Mapping):
        raise PolicyError(f"{where}.irreversible_when must be a mapping of arg -> values")
    when: dict[str, tuple[Any, ...]] = {}
    for arg, values in when_raw.items():
        values = values if isinstance(values, list) else [values]
        if not values or not all(isinstance(v, (str, bool, int)) for v in values):
            raise PolicyError(f"{where}.irreversible_when.{arg} must be scalar values")
        when[str(arg)] = tuple(values)

    return ToolPolicy(
        sink=_bool(raw.get("sink", False), f"{where}.sink"),
        irreversible=_bool(raw.get("irreversible", False), f"{where}.irreversible"),
        irreversible_when=when,
        destination_args=_str_list(raw.get("destination_args"), f"{where}.destination_args"),
        trusted_destinations=_str_list(raw.get("trusted_destinations"), f"{where}.trusted_destinations"),
        egress_args=_str_list(raw.get("egress_args"), f"{where}.egress_args"),
        shell_args=_str_list(raw.get("shell_args"), f"{where}.shell_args"),
        path_args=_str_list(raw.get("path_args"), f"{where}.path_args"),
        scopes=_str_list(raw.get("scopes"), f"{where}.scopes"),
    )


def parse_policy(data: Any, source: str = "<policy>") -> Policy:
    try:
        return _parse(data)
    except PolicyError as exc:
        raise PolicyError(f"{source}: {exc}") from None


def _parse(data: Any) -> Policy:
    if not isinstance(data, Mapping):
        raise PolicyError("must be a YAML mapping")
    unknown = set(data) - _TOP_KEYS
    if unknown:
        raise PolicyError(f"unknown top-level keys {sorted(unknown)}")
    if data.get("version") != POLICY_VERSION:
        raise PolicyError(f"unsupported version {data.get('version')!r}")

    root = data.get("workspace_root")
    if not isinstance(root, str) or not posixpath.isabs(root):
        raise PolicyError("workspace_root must be an absolute POSIX path")
    root = posixpath.normpath(root)
    if root == "/":
        raise PolicyError("workspace_root must not be '/'")

    raw_tools = data.get("tools")
    if not isinstance(raw_tools, Mapping) or not raw_tools:
        raise PolicyError("tools must be a non-empty mapping")
    tools: dict[str, ToolPolicy] = {}
    for qname, raw in raw_tools.items():
        try:
            split_qualified(str(qname))
        except ValueError as exc:
            raise PolicyError(f"tools: {exc}") from None
        tools[str(qname)] = _tool_policy(str(qname), raw)

    egress = data.get("egress") or {}
    if not isinstance(egress, Mapping) or set(egress) - {"allow_hosts", "allow_email_domains"}:
        raise PolicyError("egress may only have allow_hosts and allow_email_domains")
    hosts = tuple(h.lower().rstrip(".") for h in _str_list(egress.get("allow_hosts"), "egress.allow_hosts"))
    domains = tuple(d.lower().rstrip(".") for d in
                    _str_list(egress.get("allow_email_domains"), "egress.allow_email_domains"))

    taint = data.get("taint") or {}
    if not isinstance(taint, Mapping) or set(taint) - {"min_substring_length"}:
        raise PolicyError("taint may only have min_substring_length")
    min_sub = taint.get("min_substring_length", DEFAULT_MIN_SUBSTRING)
    if not isinstance(min_sub, int) or isinstance(min_sub, bool) or min_sub < 8:
        raise PolicyError("taint.min_substring_length must be an integer >= 8")

    return Policy(root, tools, hosts, domains, min_sub)


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise PolicyError(f"{path}: not found") from None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path}: invalid YAML: {exc}") from None
    return parse_policy(data, source=str(path))
