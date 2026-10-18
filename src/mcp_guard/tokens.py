"""Mock token broker and credential stripping.

Each tool gets only its own scoped token from policy; any credential the
agent tries to pass in arguments is stripped (no token passthrough).

Status: not implemented yet (planned for M5).
"""
