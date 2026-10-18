"""mcp-guard: a security gateway between a coding agent and its MCP tools.

Research prototype. The agent, tools and backends in this repository are mocks.
"""

from .models import (
    AuditRecord,
    Decision,
    StepOutcome,
    ToolCall,
    ToolResult,
    ToolSpec,
    Verdict,
)

__version__ = "0.1.0"

__all__ = [
    "AuditRecord",
    "Decision",
    "StepOutcome",
    "ToolCall",
    "ToolResult",
    "ToolSpec",
    "Verdict",
    "__version__",
]
