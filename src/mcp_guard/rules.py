"""Deterministic audit rules R1-R7.

Each per-call rule takes a ``RuleContext`` and returns zero or more
``Finding``s. R7 is different: it runs on tool *descriptions* when tools are
pinned or verified, not on calls.

| ID | Rule                                                              | Default  |
|----|-------------------------------------------------------------------|----------|
| R1 | sink call with an argument copied from untrusted content          | BLOCK    |
| R2 | untrusted read earlier, then a sink to a destination the task did not name | ESCALATE |
| R3 | irreversible tool (or irreversible argument values)               | ESCALATE |
| R4 | destination host / email domain not in the egress allowlist       | BLOCK    |
| R5 | dangerous shell command, or a write outside the workspace         | BLOCK    |
| R6 | credential-shaped argument                                        | BLOCK    |
| R7 | instruction-like text aimed at the model in a tool description    | refuse to register |

Every pattern list here was written from public descriptions of these attack
classes; thresholds are tuned only against the red-team corpus.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping

from . import egress
from .models import ToolCall, ToolSpec, Verdict
from .policy import Policy, ToolPolicy
from .taint import TaintTracker, iter_strings, top_level


@dataclass(frozen=True)
class Finding:
    rule: str
    verdict: Verdict
    reason: str
    args: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuleContext:
    call: ToolCall
    policy: Policy
    tool: ToolPolicy
    taint: TaintTracker


Rule = Callable[[RuleContext], list[Finding]]


def _quote_args(args: Iterable[str]) -> str:
    return ", ".join(f"'{a}'" for a in args)


# --------------------------------------------------------------------------
# R1: tainted argument to a sink


def r1_tainted_sink(ctx: RuleContext) -> list[Finding]:
    if not ctx.tool.sink:
        return []
    matches = ctx.taint.matches(ctx.call.args, trusted=ctx.call.task)
    if not matches:
        return []
    hit = {top_level(m.arg) for m in matches}
    args = tuple(a for a in ctx.call.args if a in hit)
    kinds = sorted({m.kind for m in matches})
    sources = sorted({m.source for m in matches})
    plural = "s" if len(args) > 1 else ""
    return [Finding(
        "R1", Verdict.BLOCK,
        f"arg{plural} {_quote_args(args)} came from untrusted content "
        f"({', '.join(kinds)} from {', '.join(sources)})",
        args,
    )]


# --------------------------------------------------------------------------
# R2: untrusted read, then a sink to an unnamed destination


def _split_destinations(value: Any) -> list[str]:
    if isinstance(value, str):
        return [p.strip() for p in re.split(r"[,;]", value) if p.strip()]
    if isinstance(value, (list, tuple)):
        return [v.strip() for v in value if isinstance(v, str) and v.strip()]
    return []


def r2_unnamed_destination(ctx: RuleContext) -> list[Finding]:
    if not (ctx.tool.sink and ctx.tool.destination_args and ctx.taint.has_untrusted):
        return []
    task = ctx.call.task.lower()
    trusted = {d.lower() for d in ctx.tool.trusted_destinations}
    unnamed: list[tuple[str, str]] = []
    for arg in ctx.tool.destination_args:
        if arg not in ctx.call.args:
            continue  # tool default applies; defaults are listed in trusted_destinations
        for dest in _split_destinations(ctx.call.args[arg]):
            if dest.lower() not in trusted and dest.lower() not in task:
                unnamed.append((arg, dest))
    if not unnamed:
        return []
    args = tuple(dict.fromkeys(a for a, _ in unnamed))
    dests = ", ".join(d for _, d in unnamed)
    return [Finding(
        "R2", Verdict.ESCALATE,
        f"after reading untrusted content, sends to {dests}, which the task did not name",
        args,
    )]


# --------------------------------------------------------------------------
# R3: irreversible


def r3_irreversible(ctx: RuleContext) -> list[Finding]:
    if not ctx.tool.is_irreversible(ctx.call.args):
        return []
    which = [f"{a}={ctx.call.args.get(a)!r}" for a, vals in ctx.tool.irreversible_when.items()
             if ctx.call.args.get(a) in vals]
    detail = f" ({', '.join(which)})" if which else ""
    return [Finding("R3", Verdict.ESCALATE,
                    f"{ctx.call.qualified_name} is irreversible{detail} and needs approval")]


# --------------------------------------------------------------------------
# R4: egress


def r4_egress(ctx: RuleContext) -> list[Finding]:
    violations = egress.check(ctx.policy, ctx.tool, ctx.call.args)
    if not violations:
        return []
    args = tuple(dict.fromkeys(top_level(v.arg) for v in violations))
    reasons = "; ".join(dict.fromkeys(v.reason for v in violations))
    return [Finding("R4", Verdict.BLOCK, reasons, args)]


# --------------------------------------------------------------------------
# R5: dangerous shell commands and writes outside the workspace

_SHELLS = r"(?:ba|z|da|k|fi|tc|c)?sh"
PIPE_TO_SHELL = [
    re.compile(rf"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+)?(?:/usr)?(?:/local)?(?:/s?bin/)?{_SHELLS}\b"),
    re.compile(rf"\b{_SHELLS}\s+(?:-\S+\s+)*<\(\s*(?:curl|wget)\b"),
    re.compile(rf"\b(?:{_SHELLS}\s+-c|eval)\s+[\"']?\$\(\s*(?:curl|wget)\b"),
    re.compile(r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:python[0-9.]*|perl|ruby|node|php)\b"),
]
CREDENTIAL_PATHS = re.compile(
    r"(?:~|\$HOME|\$\{HOME\}|/root|/home/[^/\s]+)?/?\.ssh(?:/|\b)"
    r"|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\bauthorized_keys\b"
    r"|\.aws/credentials\b|\.netrc\b|\.git-credentials\b|\.docker/config\.json\b"
    r"|\.kube/config\b|\.npmrc\b|\.pypirc\b|\.gnupg\b",
    re.IGNORECASE,
)
CHMOD_777 = re.compile(r"\bchmod\s+(?:-\S+\s+)*(?:0?777|[augo]*a[augo]*\+rwx|ugo\+rwx)\b")
HISTORY_WIPE = [
    re.compile(r"\bhistory\s+-[a-z]*c"),
    re.compile(r"\bunset\s+HISTFILE\b"),
    re.compile(r"\bHISTFILE=(?:/dev/null|\s|$)"),
    re.compile(r"\bHISTSIZE=0\b"),
    re.compile(r"\bset\s+\+o\s+history\b"),
    re.compile(r"(?:\brm\b|\bshred\b|>)[^;&|]*\.(?:bash|zsh|sh)_history\b"),
]
_SEGMENT_SPLIT = {";", "&&", "||", "|", "&", "\n", "(", ")"}
_PREFIXES = {"sudo", "env", "command", "nohup", "time", "nice", "xargs", "exec"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _outside_workspace(path: str, root: str) -> bool:
    """True if ``path`` (as the shell would see it, cwd = workspace root)
    leaves the workspace or is the workspace root itself."""
    if not path or path.startswith("~") or "$" in path or "`" in path:
        return True
    p = path if posixpath.isabs(path) else posixpath.join(root, path)
    p = posixpath.normpath(p)
    return not p.startswith(root.rstrip("/") + "/")


def _rm_targets(command: str) -> list[tuple[bool, list[str]]] | None:
    """For each ``rm`` invocation: (recursive?, targets). None if unparseable."""
    try:
        # shlex treats newlines as plain whitespace; for the shell they end a command.
        lex = shlex.shlex(command.replace("\n", " ; "), posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        return None
    out: list[tuple[bool, list[str]]] = []
    segment: list[str] = []
    for tok in tokens + [";"]:
        if tok in _SEGMENT_SPLIT or set(tok) <= set(";&|()"):
            words = list(segment)
            while words and (_ASSIGNMENT.match(words[0]) or posixpath.basename(words[0]) in _PREFIXES):
                words = words[1:]
                while words and words[0].startswith("-"):
                    words = words[1:]
            if words and posixpath.basename(words[0]) == "rm":
                recursive, targets, end_opts = False, [], False
                for w in words[1:]:
                    if not end_opts and w == "--":
                        end_opts = True
                    elif not end_opts and w.startswith("--"):
                        recursive |= w == "--recursive"
                    elif not end_opts and w.startswith("-") and len(w) > 1:
                        recursive |= "r" in w[1:] or "R" in w[1:]
                    else:
                        targets.append(w)
                out.append((recursive, targets))
            segment = []
        else:
            segment.append(tok)
    return out


def shell_findings(command: str, root: str) -> list[str]:
    """Reasons the command is dangerous (empty list = no pattern matched)."""
    reasons: list[str] = []
    rms = _rm_targets(command)
    if rms is None:
        if re.search(r"\brm\s+(?:-\S*[rR]|--recursive)", command):
            reasons.append("unparseable command with recursive rm")
    else:
        for recursive, targets in rms:
            bad = [t for t in targets if _outside_workspace(t, root)]
            if recursive and bad:
                reasons.append(f"recursive rm outside the workspace: {' '.join(bad)}")
    if any(p.search(command) for p in PIPE_TO_SHELL):
        reasons.append("pipes downloaded or piped content into a shell/interpreter")
    if CREDENTIAL_PATHS.search(command):
        reasons.append("touches SSH keys or a credential file")
    if CHMOD_777.search(command):
        reasons.append("chmod 777 / world-writable permissions")
    if any(p.search(command) for p in HISTORY_WIPE):
        reasons.append("wipes shell history")
    return reasons


def r5_unsafe_mutation(ctx: RuleContext) -> list[Finding]:
    root = ctx.policy.workspace_root
    reasons: list[str] = []
    args: list[str] = []
    for arg in ctx.tool.shell_args:
        value = ctx.call.args.get(arg)
        if isinstance(value, str):
            r = shell_findings(value, root)
            if r:
                reasons += r
                args.append(arg)
    if ctx.tool.sink:
        for arg in ctx.tool.path_args:
            value = ctx.call.args.get(arg)
            if isinstance(value, str):
                if _outside_workspace(value, root):
                    reasons.append(f"writes outside the workspace: {value}")
                    args.append(arg)
                elif CREDENTIAL_PATHS.search(value):
                    reasons.append(f"writes a credential file: {value}")
                    args.append(arg)
    if not reasons:
        return []
    return [Finding("R5", Verdict.BLOCK, "; ".join(dict.fromkeys(reasons)),
                    tuple(dict.fromkeys(args)))]


# --------------------------------------------------------------------------
# R6: credential-shaped arguments

CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("bearer token", re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE)),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
]
CREDENTIAL_KEYS = re.compile(r"^(?:authorization|proxy-authorization|x-api-key|api[_-]?key|"
                             r"access[_-]?token|secret[_-]?key|password)$", re.IGNORECASE)


def find_credentials(args: Mapping[str, Any]) -> list[tuple[str, str]]:
    """``(arg_path, what)`` for every credential-shaped value or field."""
    found: list[tuple[str, str]] = []

    def walk_keys(value: Any, path: str) -> None:
        if isinstance(value, Mapping):
            for k, v in value.items():
                p = f"{path}.{k}" if path else str(k)
                if CREDENTIAL_KEYS.match(str(k)) and v not in (None, ""):
                    found.append((p, f"{k} field"))
                walk_keys(v, p)
        elif isinstance(value, (list, tuple)):
            for i, v in enumerate(value):
                walk_keys(v, f"{path}[{i}]")

    walk_keys(args, "")
    for arg_path, text in iter_strings(args):
        for what, pattern in CREDENTIAL_PATTERNS:
            if pattern.search(text):
                found.append((arg_path, what))
        if re.search(r"(?im)^\s*authorization\s*:", text):
            found.append((arg_path, "Authorization header"))
    return list(dict.fromkeys(found))


def r6_credentials(ctx: RuleContext) -> list[Finding]:
    found = find_credentials(ctx.call.args)
    if not found:
        return []
    args = tuple(dict.fromkeys(top_level(p) for p, _ in found))
    whats = ", ".join(sorted({w for _, w in found}))
    return [Finding("R6", Verdict.BLOCK,
                    f"credential-shaped value in {_quote_args(args)} ({whats}); "
                    "tools get scoped tokens from the broker, never from the agent", args)]


# --------------------------------------------------------------------------
# R7: tool descriptions (registration time)

DESCRIPTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore previous instructions", re.compile(
        r"\b(?:ignore|disregard|forget)\b.{0,30}\b(?:previous|prior|above|earlier|other|system)\b"
        r".{0,20}\b(?:instructions?|prompts?|rules?|messages?)", re.IGNORECASE | re.DOTALL)),
    ("hide from the user", re.compile(
        r"\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention|reveal|show|notify)\b.{0,20}\buser\b"
        r"|\bwithout\s+(?:telling|informing|notifying)\b.{0,15}\buser\b"
        r"|\b(?:secretly|covertly)\b", re.IGNORECASE | re.DOTALL)),
    ("pre-use instruction", re.compile(
        r"\bbefore\s+(?:using|calling|invoking|running)\s+(?:this|the)\s+tool\b"
        r"|\byou\s+must\s+(?:first\s+)?(?:read|call|send|include|pass|fetch|run|open)\b",
        re.IGNORECASE)),
    ("prompt markup", re.compile(r"<\s*/?\s*(?:important|system|instructions?|admin)\s*>", re.IGNORECASE)),
    ("sensitive path", re.compile(r"~/\.ssh|\bid_rsa\b|\.env\b|\.aws/credentials", re.IGNORECASE)),
    ("hidden characters", re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")),
]


def scan_description(spec: ToolSpec) -> list[str]:
    """Labels of every R7 pattern found in the tool's description."""
    return [label for label, p in DESCRIPTION_PATTERNS if p.search(spec.description)]


def r7_check(spec: ToolSpec) -> str | None:
    """Registry hook: a refusal reason, or None if the description looks clean."""
    labels = scan_description(spec)
    return f"R7: instruction-like description ({', '.join(labels)})" if labels else None


# --------------------------------------------------------------------------

#: Per-call rules in the order the auditor runs them.
CALL_RULES: tuple[Rule, ...] = (
    r1_tainted_sink,
    r2_unnamed_destination,
    r3_irreversible,
    r4_egress,
    r5_unsafe_mutation,
    r6_credentials,
)
