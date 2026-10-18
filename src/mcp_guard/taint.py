"""Taint tracker: which argument values came from untrusted content.

Every tool output is untrusted (web pages, repo files, command output). The
tracker remembers, per session:

- *tokens* found in untrusted outputs: URLs, email addresses, file paths;
- every run of ``min_len`` characters (default 20) of untrusted text.

An argument of a later call is *tainted* if it contains one of those tokens or
runs **and** that token or run does not also appear in the task the engineer
gave (the only trusted text the gateway sees). Text is compared after
lower-casing and collapsing whitespace.

Known limits (by design, documented in the README): paraphrase, encoding
(base64, hex), splitting a value into short pieces, or changing whitespace
inside a token all evade substring matching. Rule R2 (sequence) and the
approval gate are the backstops.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping

from .models import ToolResult

URL_RE = re.compile(r"\bhttps?://[^\s\"'<>`()\[\]{}]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
# POSIX-style paths starting with ~/ ./ ../ or /, and Windows drive paths.
PATH_RE = re.compile(
    r"(?<![\w/:.~-])(?:~|\.{1,2})?/(?:[\w.-]+/?)+"
    r"|(?<![\w])[A-Za-z]:\\(?:[\w .-]+\\?)+"
)
_TRAILING = ".,;:!?'\""
_WS = re.compile(r"\s+")
MIN_PATH_LEN = 4


def normalize(text: str) -> str:
    return _WS.sub(" ", text.lower()).strip()


def extract_tokens(text: str) -> list[tuple[str, str]]:
    """Return ``(kind, token)`` pairs: kind is ``url``, ``email`` or ``path``.

    URLs are removed before looking for emails and paths, so the path part
    of a URL is not reported twice.
    """
    found: list[tuple[str, str]] = []
    for m in URL_RE.finditer(text):
        found.append(("url", m.group(0).rstrip(_TRAILING)))
    rest = URL_RE.sub(" ", text)
    for m in EMAIL_RE.finditer(rest):
        found.append(("email", m.group(0)))
    rest = EMAIL_RE.sub(" ", rest)
    for m in PATH_RE.finditer(rest):
        token = m.group(0).rstrip(_TRAILING).rstrip("\\")
        if len(token) >= MIN_PATH_LEN:
            found.append(("path", token))
    return found


def iter_strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(arg_path, string)`` for every string inside nested args.

    Paths look like ``to``, ``headers.Authorization``, ``items[0]``.
    """
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, Mapping):
        for k, v in value.items():
            yield from iter_strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from iter_strings(v, f"{path}[{i}]")


def top_level(arg_path: str) -> str:
    """``headers.Authorization`` -> ``headers``; ``items[0]`` -> ``items``."""
    return re.split(r"[.\[]", arg_path, maxsplit=1)[0]


@dataclass(frozen=True)
class TaintMatch:
    arg: str       # arg path, e.g. "to" or "headers.X-Reply"
    kind: str      # url | email | path | substring
    snippet: str   # the matched token or run (normalised)
    source: str    # where the untrusted text came from, e.g. "web.fetch_url#1"


@dataclass
class _Source:
    label: str
    shingles: set[str]


@dataclass
class TaintTracker:
    """Per-session record of untrusted text."""

    min_len: int = 20
    tokens: dict[str, tuple[str, str]] = field(default_factory=dict)  # norm token -> (kind, source)
    sources: list[_Source] = field(default_factory=list)

    @property
    def has_untrusted(self) -> bool:
        return bool(self.sources)

    def _shingles(self, norm: str) -> set[str]:
        n = self.min_len
        return {norm[i:i + n] for i in range(len(norm) - n + 1)}

    def add(self, text: str, source: str) -> None:
        """Record a piece of untrusted text (first occurrence wins the label)."""
        for kind, token in extract_tokens(text):
            self.tokens.setdefault(normalize(token), (kind, source))
        self.sources.append(_Source(source, self._shingles(normalize(text))))

    def record(self, result: ToolResult, step: int | None = None) -> None:
        label = result.call.qualified_name + (f"#{step}" if step is not None else "")
        self.add(result.output, label)

    def matches(self, args: Mapping[str, Any], trusted: str = "") -> list[TaintMatch]:
        """All taint matches in ``args``, ignoring anything named in ``trusted``."""
        if not self.sources:
            return []
        trusted_norm = normalize(trusted)
        trusted_shingles = self._shingles(trusted_norm)
        out: list[TaintMatch] = []
        for arg_path, value in iter_strings(args):
            norm = normalize(value)
            hit = False
            for token, (kind, source) in self.tokens.items():
                if token in norm and token not in trusted_norm:
                    out.append(TaintMatch(arg_path, kind, token, source))
                    hit = True
            if hit:
                continue
            for i in range(len(norm) - self.min_len + 1):
                run = norm[i:i + self.min_len]
                if run in trusted_shingles:
                    continue
                src = next((s.label for s in self.sources if run in s.shingles), None)
                if src is not None:
                    out.append(TaintMatch(arg_path, "substring", run, src))
                    break
        return out

    def tainted_args(self, args: Mapping[str, Any], trusted: str = "") -> list[str]:
        """Top-level arg names with at least one match, in argument order."""
        hit = {top_level(m.arg) for m in self.matches(args, trusted)}
        return [a for a in args if a in hit]
