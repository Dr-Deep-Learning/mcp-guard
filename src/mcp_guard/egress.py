"""Egress allowlist: where a call may send data (rule R4).

For every argument the policy lists in ``egress_args``, the gateway extracts
URLs and email addresses and checks each destination:

- URL -> host (via ``urllib.parse``, so ``https://docs.example.com@evil.com/``
  is correctly read as host ``evil.com``) must match ``egress.allow_hosts``;
- email -> domain must match ``egress.allow_email_domains``.

An egress arg that holds a value which looks like a URL but has no host is
treated as a violation. A value with no URL or email (``remote: origin``)
has no destination to check.

The auditor runs this as rule R4, and the gateway runs it again as its own
pipeline step (step 4), so egress holds even if the rule set is changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from .policy import Policy, ToolPolicy
from .taint import EMAIL_RE, URL_RE, iter_strings


@dataclass(frozen=True)
class Destination:
    arg: str
    kind: str   # "host" or "email"
    value: str  # host or full address
    domain: str  # host for URLs, domain part for emails (lower-case)


@dataclass(frozen=True)
class EgressViolation:
    arg: str
    value: str
    reason: str


def host_allowed(host: str, allow_hosts: Iterable[str]) -> bool:
    host = host.lower().rstrip(".")
    for pattern in allow_hosts:
        if pattern.startswith("*."):
            if host.endswith(pattern[1:]) and host != pattern[2:]:
                return True
        elif host == pattern:
            return True
    return False


def email_domain_allowed(domain: str, allow_domains: Iterable[str]) -> bool:
    return domain.lower().rstrip(".") in set(allow_domains)


def destinations(args: Mapping[str, Any], egress_args: Iterable[str]) -> tuple[
        list[Destination], list[EgressViolation]]:
    """Extract destinations from the listed args. Returns (destinations, malformed)."""
    found: list[Destination] = []
    malformed: list[EgressViolation] = []
    wanted = set(egress_args)
    for arg_path, text in iter_strings({k: v for k, v in args.items() if k in wanted}):
        for m in URL_RE.finditer(text):
            url = m.group(0).rstrip(".,;:!?'\"")
            try:
                host = urlsplit(url).hostname
            except ValueError:
                host = None
            if not host:
                malformed.append(EgressViolation(arg_path, url, "URL without a valid host"))
                continue
            found.append(Destination(arg_path, "host", host, host.lower()))
        for m in EMAIL_RE.finditer(URL_RE.sub(" ", text)):
            addr = m.group(0)
            found.append(Destination(arg_path, "email", addr, addr.rsplit("@", 1)[1].lower()))
        stripped = text.strip()
        if stripped.lower().startswith(("http:", "https:")) and not URL_RE.search(text):
            malformed.append(EgressViolation(arg_path, stripped, "URL without a valid host"))
    return found, malformed


def check(policy: Policy, tool: ToolPolicy, args: Mapping[str, Any]) -> list[EgressViolation]:
    """All egress violations for one call (empty list = allowed)."""
    found, violations = destinations(args, tool.egress_args)
    for d in found:
        if d.kind == "host" and not host_allowed(d.domain, policy.allow_hosts):
            violations.append(EgressViolation(d.arg, d.value, f"host {d.value} not in egress allowlist"))
        elif d.kind == "email" and not email_domain_allowed(d.domain, policy.allow_email_domains):
            violations.append(EgressViolation(
                d.arg, d.value, f"email domain {d.domain} not in egress allowlist"))
    return violations
