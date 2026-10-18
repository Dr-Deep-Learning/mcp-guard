"""Hash-chained, append-only JSONL audit log and its verifier.

hash = SHA-256 of the record without `hash`, including `prev_hash`.
`verify-log` walks the chain and reports the first broken link.

Status: not implemented yet (planned for M5).
"""
