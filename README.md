# mcp-guard

A small, open-source security gateway that sits between a coding agent and its MCP tools. Every tool call the agent proposes goes through the gateway before it runs.

**The idea:** the model is never trusted. Once an agent has read untrusted content, any action it proposes is treated as possibly attacker-influenced. mcp-guard does not rely on detecting the injection; it constrains what the action can do.

> **Status: research prototype, work in progress.** The agent is a scripted mock, the tools are synthetic, and the backends are in-memory. Nothing here has been used in production. Results and numbers will be added only once they come from running the red-team suite.

## What works today (milestones M1–M2)

| Piece | What it does |
|---|---|
| `src/mcp_guard/models.py` | `ToolSpec`, `ToolCall`, `ToolResult`, `Decision` (ALLOW / BLOCK / ESCALATE), `AuditRecord` |
| `mock/tools.py`, `mock/servers.py` | Synthetic tools (`read_file`, `write_file`, `fetch_url`, `send_email`, `run_shell`, `git_push`, `deploy`) on an in-memory backend; mock MCP servers plus rug-pull and shadowing variants |
| `mock/agent.py` | Deterministic mock agent that replays a scripted YAML case through any executor |
| `src/mcp_guard/registry.py` | Hash-pinned tool registry: canonical hashing, lockfile, runtime verify, rug-pull and shadowing detection |
| `mcp-guard pin` / `verify` | Write `policy/registry.lock.yaml`; check advertised tools against it |

Coming next: taint tracking and rules R1–R7 (M3), the red-team corpus and report (M4), token broker, egress, approval and the hash-chained audit log (M5), CI gate and full README (M6).

## Quickstart

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
pytest

mcp-guard verify                                            # all tools match their pins
mcp-guard verify --servers mock.servers:rug_pulled_servers  # RUG_PULL: web.fetch_url disabled
mcp-guard verify --servers mock.servers:shadowing_servers   # SHADOWING: helper.send_email refused
```

Run the CLI from the repository root (it loads the mock servers from `mock/`).

## Hash pinning

- Canonical form of a tool: JSON of `{server, name, description, inputSchema}` with sorted keys, no whitespace, UTF-8. No Unicode normalisation, so an invisible character added to a description counts as a change.
- Pin: SHA-256 of the canonical form.
- `mcp-guard pin` writes `policy/registry.lock.yaml`. Changes to it are reviewed in a pull request, like a dependency lockfile.
- At runtime every advertised tool is re-hashed. A mismatch disables the tool (`RUG_PULL`). A tool that is not pinned is refused (`UNPINNED`). A tool name advertised by more than one server is refused for every server except the one that pinned it (`SHADOWING`); `pin` refuses to write a lockfile with duplicate names.

## Repository layout

```
policy/        policy.yaml (tool flags, egress, workspace root), registry.lock.yaml (generated)
src/mcp_guard/ the gateway library and CLI
mock/          mock agent, synthetic tools, mock MCP servers (dev and tests only)
redteam/       attack and benign cases; scorer (M4)
tests/         pytest suite
results/       generated reports (M4)
```

## Clean-room note

This project was written from scratch from public material only (the MCP specification and security best practices, published research and write-ups on agent and MCP security). It contains no code, data, prompts, designs or numbers from any employer or client.

## References

- MCP security best practices: https://modelcontextprotocol.io/specification/latest/basic/security_best_practices
- Unit 42, MCP attack vectors: https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/
- Design Patterns for Securing LLM Agents against Prompt Injections: https://arxiv.org/abs/2506.08837
- CaMeL, Defeating Prompt Injections by Design: https://arxiv.org/abs/2503.18813
- OWASP Top 10 for Agentic Applications (2026): https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- The lethal trifecta: https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/

## License

MIT
