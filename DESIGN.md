# Design note

## Idea

An agent that has read untrusted content can be steered by it. mcp-guard treats
every tool output as untrusted and every call the agent proposes as possibly
attacker-influenced, then limits what that call can do. It does not try to be a
better injection detector; it tries to make a missed detection cheap. In the
"lethal trifecta" framing (private data + untrusted content + a way to send data
out), the gateway breaks the trifecta per call: taint tracking marks what came
from untrusted content, the egress allowlist limits where it can go, and the
token broker limits what each tool can touch.

## Pipeline

1. **Registry.** Only tools pinned in `policy/registry.lock.yaml` with a matching
   SHA-256 of `{server, name, description, inputSchema}` run. A changed pin
   disables the tool (rug pull); a name advertised by two servers stays with the
   server that pinned it (shadowing); an instruction-like description is refused
   (R7) at pin time and at runtime.
2. **Taint.** Per session, tokens (URLs, emails, paths) and every 20-character
   run of untrusted output are remembered; text the task itself contains is
   exempt.
3. **Auditor.** A tool missing from the policy is blocked. Rules R1-R6 all run;
   any BLOCK wins, else any ESCALATE, else ALLOW. The decision lists every rule
   that fired.
4. **Egress.** R4 runs again as its own step, so the allowlist holds even if the
   rule set is changed.
5. **Approval.** ESCALATE goes to an approver: auto-deny by default, a terminal
   prompt on request. The optional LLM judge may never approve R3 (irreversible).
6. **Token broker.** Agent-supplied credentials are stripped; the tool's own
   scoped token is attached outside the arguments. Mock backends check scopes.
7. **Audit log.** One hash-chained JSONL record per decision, written before the
   tool runs; registry events are logged at startup.

## Relation to published work

CaMeL (Debenedetti et al., 2025) has a privileged model turn the trusted request
into a program, so untrusted data cannot change which tools run, and tracks how
data flows between tool calls. mcp-guard is far cruder: it cannot change the
agent, so it approximates that tracking from the outside, at the tool-call
boundary, by substring matching. The design-patterns paper (Beurer-Kellner et
al., 2025) states that "once an LLM agent has ingested untrusted input, it must
be constrained so that it is impossible for that input to trigger any
consequential actions"; the per-call policy here is one small, deployable step
in that direction.

## What the red-team run shows

Numbers are in the README and `results/redteam_report.md`. The misses are the
hard cases written to probe the design: data sent to an allowlisted host in a
URL query string (T1-005), deletion through an interpreter instead of `rm`
(T6-004), an irreversible action through the shell instead of the push tool
(T7-003), and removal of the newest log records with no stored head hash
(T9-005). The false positives come from R1 flagging benign verbatim copies:
editing a file that was just read, and running a command an issue gave.

## Decisions log

| Date | Decision | Why |
|---|---|---|
| 2026-10-16 | Python library + CLI, mock agent replaying scripted cases | Deterministic tests; finishable in days |
| 2026-10-16 | Rules first, LLM judge optional and off in CI | Cost cascade; CI must be deterministic |
| 2026-10-16 | Hash-chained JSONL audit log | Tamper evidence at almost no cost |
| 2026-10-17 | Three mock servers (`workspace`, `web`, `mail`) | The plan's own example case calls `web` and `mail` |
| 2026-10-17 | Shadowing: the server that pinned a name keeps it; others are refused; if nobody pinned it, every copy is refused; `pin` refuses duplicate names | Safety over availability, without letting an impostor disable the real tool |
| 2026-10-17 | Pin only `{server, name, description, inputSchema}`; `title` and `annotations` are not covered | Follows the plan; recorded as a known gap |
| 2026-10-17 | Scripted case outputs are seeded into the mock backend for reads, and replace the return value for other tools | The gateway sees the same output the agent would |
| 2026-10-17 | Added `src/mcp_guard/policy.py` (not in the original layout) | Policy loading did not belong in `rules.py` or `auditor.py` |
| 2026-10-17 | R3 can depend on argument values (`deploy` to prod, force-push) | Staging deploys and normal pushes stay ALLOW instead of becoming false positives |
| 2026-10-17 | `fetch_url` is not a sink | Following links on allowed hosts is normal; other hosts are stopped by R4 |
| 2026-10-17 | R5 also blocks reading credential files from the shell | An agent has no normal reason to read `~/.ssh` or `.aws/credentials` |
| 2026-10-17 | R4 runs inside the auditor and again as its own gateway step | One of R1-R7 in M3; independent of the rule set from M5 |
| 2026-10-17 | R1 implemented as specified (20-character runs), not tuned | Tune only against the corpus; its false positives are measured, not hidden |
| 2026-10-17 | Case format gains optional `servers` and `pin_advertised` | Lets registry threats (T2, T3, T8) run through the same replay |
| 2026-10-17 | Attack caught = BLOCK or ESCALATE at the expected step; benign false positive = any non-ALLOW step | Matches the plan's case format; strict and simple |
| 2026-10-17 | Corpus written before the first run; no rule tuned against it | Avoids grading the rules on cases shaped to fit them |
| 2026-10-17 | Audit record keeps the pre-approval verdict, plus `approver` and `approved`; call arguments are not logged | Shows what the gateway decided and what the human did; keeps secrets out of the log |
| 2026-10-17 | One token per tool, scoped by policy (not narrowed per call) | Simple and enough to stop cross-tool reuse; per-call narrowing is future work |
| 2026-10-17 | T9 scored with five generated tampering checks, including the known miss (no stored head hash) | Log tampering is not a tool call; the miss is a real limit of a bare hash chain |
| 2026-10-17 | CI thresholds: `--min-catch 0.85 --max-fp 0.15` | First full run: 26/30 caught (86.7%), 3/25 flagged (12.0%). One new miss (25/30 = 83.3%) or one new false positive (4/25 = 16%) fails the gate |
| 2026-10-17 | README results are generated from the committed report; CI fails if that report no longer matches a fresh run | No hand-typed or stale numbers |
