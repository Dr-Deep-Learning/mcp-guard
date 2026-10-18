"""Hash-chained, append-only JSONL audit log and its verifier (threat T9).

Each line is one JSON record (see ``models.AuditRecord``). The chain:

- ``prev_hash`` of the first record is 64 zeros (``GENESIS``);
- ``hash`` = SHA-256 of the record *without* ``hash``, in canonical JSON
  (sorted keys, no whitespace, UTF-8), which includes ``prev_hash``;
- ``prev_hash`` of every later record is the ``hash`` of the one before;
- ``seq`` counts up from 0 with no gaps.

``verify`` walks the chain and reports the first broken link. Editing,
deleting, inserting or reordering records breaks it.

What a chain alone cannot show: someone who removes the *newest* records, or
rewrites the tail and recomputes every hash after it, leaves a valid but
shorter chain. To catch that, copy the current head hash somewhere the log's
writer cannot change (a ticket, a CI artifact, a separate store) and pass it
as ``expected_head``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .models import AUDIT_FIELDS, AuditRecord, Decision, ToolCall, canonical_json, utc_now_iso

GENESIS = "0" * 64


class AuditLogError(Exception):
    """The log is broken, or cannot be appended to."""


def record_hash(record: dict[str, Any]) -> str:
    """SHA-256 over the record without its ``hash`` field."""
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(canonical_json(body)).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    head: str                     # hash of the last good record (GENESIS if none)
    broken_line: int | None = None  # 1-based line number of the first bad record
    reason: str = ""

    def __str__(self) -> str:
        if self.ok:
            return f"OK: {self.records} records, head {self.head}"
        return f"BROKEN at line {self.broken_line}: {self.reason} ({self.records} good records before it)"


def verify_lines(lines: Iterable[str], expected_head: str | None = None) -> VerifyResult:
    prev, count = GENESIS, 0
    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        def broken(reason: str) -> VerifyResult:
            return VerifyResult(False, count, prev, lineno, reason)

        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            return broken(f"not valid JSON ({exc.msg})")
        if not isinstance(rec, dict) or list(rec) != list(AUDIT_FIELDS):
            return broken("fields missing, extra or out of order")
        if rec["seq"] != count:
            return broken(f"seq is {rec['seq']!r}, expected {count} (record missing, added or moved)")
        if rec["prev_hash"] != prev:
            return broken("prev_hash does not match the previous record's hash")
        if rec["hash"] != record_hash(rec):
            return broken("hash does not match the record's contents (record was edited)")
        prev, count = rec["hash"], count + 1

    if expected_head is not None and prev != expected_head:
        return VerifyResult(False, count, prev, None,
                            "chain is intact but its head does not match the expected head "
                            "(records were removed from, or rewritten at, the end)")
    return VerifyResult(True, count, prev)


def verify_log(path: str | Path, expected_head: str | None = None) -> VerifyResult:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise AuditLogError(f"{path}: not found") from None
    return verify_lines(text.splitlines(), expected_head)


class AuditLog:
    """Append-only writer. ``path=None`` keeps the log in memory (tests, red team).

    Opening an existing file verifies it first and continues its chain;
    a broken file is refused rather than extended.
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else None
        self.lines: list[str] = []
        self.head = GENESIS
        self.seq = 0
        if self.path is not None and self.path.exists():
            existing = self.path.read_text(encoding="utf-8").splitlines()
            result = verify_lines(existing)
            if not result.ok:
                raise AuditLogError(f"{self.path}: refusing to append to a broken log: {result}")
            self.lines = [ln for ln in existing if ln.strip()]
            self.head, self.seq = result.head, result.records

    def append(self, record: AuditRecord) -> AuditRecord:
        """Chain ``record`` (its seq/prev_hash/hash are replaced) and write it."""
        body = record.to_dict(include_hash=False)
        body["seq"], body["prev_hash"] = self.seq, self.head
        body["hash"] = record_hash(body)
        line = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as f:
                f.write(line + "\n")
                f.flush()
        self.lines.append(line)
        self.head, self.seq = body["hash"], self.seq + 1
        return AuditRecord.from_dict(body)

    def log_decision(self, call: ToolCall, decision: Decision, approver: str | None = None,
                     approved: bool | None = None) -> AuditRecord:
        return self.append(AuditRecord.for_decision(
            call, decision, seq=self.seq, prev_hash=self.head,
            approver=approver, approved=approved))

    def log_event(self, server: str, tool: str, kind: str, detail: str) -> AuditRecord:
        """A gateway event that is not a call, e.g. a tool disabled for RUG_PULL."""
        return self.append(AuditRecord(
            ts=utc_now_iso(), seq=self.seq, session="gateway", server=server, tool=tool,
            decision="BLOCK", rules=(kind,), reason=detail, prev_hash=self.head))

    def verify(self, expected_head: str | None = None) -> VerifyResult:
        return verify_lines(self.lines, expected_head)
