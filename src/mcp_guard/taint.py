"""Taint tracker: which argument values came from untrusted content.

Every tool output is untrusted. The tracker remembers substrings of those
outputs (long runs, URLs, emails, paths) so rule R1 can tell when an argument
of a later sink call was copied from them.

Status: not implemented yet (planned for M3).
"""
