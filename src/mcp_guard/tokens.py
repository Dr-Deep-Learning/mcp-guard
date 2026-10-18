"""Mock token broker and credential stripping (threat T4: confused deputy / token passthrough).

- Each tool gets its own token, carrying only the scopes ``policy.yaml`` lists
  for that tool. A token issued for ``workspace.read_file`` cannot send email.
- The gateway attaches the token out of band (``credential=`` on the tool
  host), never in the call's arguments, and never shows it to the agent.
- Any credential the agent puts in arguments is stripped before the call
  runs. R6 blocks such calls anyway; stripping is the second layer for a
  deployment that turns R6 off or downgrades it, and it keeps secrets out of
  anything derived from the arguments.

Tokens here are random strings standing in for real short-lived credentials.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Mapping

from .policy import Policy
from .rules import CREDENTIAL_KEYS, CREDENTIAL_PATTERNS

REDACTED = "[REDACTED]"
_AUTH_HEADER_LINE = re.compile(r"(?im)^(\s*authorization\s*:).*$")


@dataclass(frozen=True)
class ScopedToken:
    token_id: str
    tool: str
    scopes: tuple[str, ...]
    secret: str = field(repr=False)

    def allows(self, scope: str) -> bool:
        return scope in self.scopes


class TokenBroker:
    """Issues one token per tool, scoped by policy. Tools with no scopes get none."""

    def __init__(self, policy: Policy):
        self.policy = policy
        self._issued: dict[str, ScopedToken] = {}

    def token_for(self, qualified_name: str) -> ScopedToken | None:
        tool = self.policy.tool(qualified_name)
        if tool is None or not tool.scopes:
            return None
        if qualified_name not in self._issued:
            self._issued[qualified_name] = ScopedToken(
                token_id=f"tok-{secrets.token_hex(4)}",
                tool=qualified_name,
                scopes=tool.scopes,
                secret=f"mock-{secrets.token_urlsafe(24)}",
            )
        return self._issued[qualified_name]


def _redact(text: str) -> str:
    for _, pattern in CREDENTIAL_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return _AUTH_HEADER_LINE.sub(lambda m: f"{m.group(1)} {REDACTED}", text)


def strip_credentials(args: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Return ``(clean_args, stripped_paths)``. The input is not modified.

    Credential-named fields (``Authorization``, ``api_key`` ...) are removed;
    credential-shaped substrings in strings are replaced with ``[REDACTED]``.
    """
    stripped: list[str] = []

    def walk(value: Any, path: str) -> Any:
        if isinstance(value, Mapping):
            out = {}
            for k, v in value.items():
                p = f"{path}.{k}" if path else str(k)
                if CREDENTIAL_KEYS.match(str(k)) and v not in (None, ""):
                    stripped.append(p)
                    continue
                out[k] = walk(v, p)
            return out
        if isinstance(value, (list, tuple)):
            return [walk(v, f"{path}[{i}]") for i, v in enumerate(value)]
        if isinstance(value, str):
            clean = _redact(value)
            if clean != value:
                stripped.append(path)
            return clean
        return value

    return walk(dict(args), ""), stripped
