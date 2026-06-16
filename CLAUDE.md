# Portcullis — Project Context for Claude Code

> This file is read automatically by Claude Code on session start. It gives
> Claude (and any team member running Claude Code) the project's mission,
> architecture, conventions, and current state. Keep it accurate and up to date.

---

## What Portcullis is

A local security proxy for AI agents. It sits between an AI client (Claude
Desktop, Cursor, Windsurf, etc.) and the MCP servers the client talks to.
Every tool call passes through Portcullis, where it is logged, classified by
capability, evaluated against a YAML policy, and either allowed, blocked, or
gated behind user confirmation.

**Tagline:** The portcullis between your agent and your data.

**Primary threat we defend against:** the **lethal trifecta** (Simon Willison's
framework) — when a single agent session has all three of:

1. **Reads private data** — access to user files, emails, secrets, etc.
2. **Sees untrusted content** — exposure to text from outside the user's trust boundary (web pages, emails, GitHub issues, etc.)
3. **Can exfiltrate** — ability to communicate outward (send messages, fetch URLs, write to remote systems).

When all three are present, prompt injection can exfiltrate data without any
traditional code vulnerability. Detection-based defenses are unreliable; the
only structural defense is to break one leg of the trifecta. Portcullis is
the place to enforce that break.

---

## Project status

**Phase:** Pre-alpha. Building v0.1 (observability only).

**Current milestone targets:**

- **v0.1 — Observability** (4 weeks): STDIO + HTTP/SSE proxy passthrough, JSONL audit log, read-only dashboard timeline, manual capability tagging via YAML.
- **v0.2 — Enforcement** (+4 weeks): policy engine, lethal trifecta detection, tool description injection scanner, kill switch hotkey.
- **v0.3 — Intelligence:** LLM-powered analysis, anomaly detection, sandbox mode.
- **v1.0 — Trust scoring:** server reputation, cloud sync, browser extension companion.
- **v2.0:** multi-agent, team/family deployment, OAuth-style per-agent scopes.

See README.md for full roadmap detail.

---

## Architecture overview

\`\`\`
MCP Client  <-- JSON-RPC -->  Portcullis Proxy  <-- JSON-RPC -->  MCP Servers
                                  |
                                  +-- policy engine + trifecta tracker
                                  +-- capability tagger
                                  +-- injection scanner
                                  +-- audit logger (JSONL + SQLite)
                                  +-- dashboard (localhost:7778)
\`\`\`

Every component is local. No cloud calls in v0.1. Optional Anthropic API
calls land in v0.3 for LLM-powered analysis, behind a config flag.

---

## Tech stack

- **Language:** TypeScript (Node 20+).
- **MCP SDK:** \`@modelcontextprotocol/sdk\`.
- **Storage:** SQLite (\`better-sqlite3\`) for queryable history; JSONL for append-only audit log.
- **Dashboard:** React + Vite. Initial scaffolds may come from Lovable or v0.
- **LLM analysis (optional, v0.3+):** Anthropic API. Sonnet for routine, Opus for deep review.
- **Distribution:** npm global install (\`npm install -g portcullis\`).

---

## Core concepts (terminology that recurs in the code)

- **Tool** — a specific function an AI can call (e.g. \`gmail.send_message\`). Each is described in MCP's \`tools/list\` response.
- **Tool call** — one invocation of a tool, captured as a JSON-RPC \`tools/call\` message.
- **Capability** — a tag attached to a tool indicating what kind of action it performs (\`reads_private_data\`, \`can_exfiltrate\`, etc.). Tags compose to session level.
- **Session** — a contiguous conversation between one MCP client and Portcullis. Has its own ID, capability set, and taint state.
- **Taint** — a session-level flag indicating that untrusted content has entered the session. Once tainted, subsequent exfiltration actions are high-risk. Borrowed from taint analysis in PL security.
- **Lethal trifecta** — the conjunction of \`reads_private_data\`, \`sees_untrusted_content\`, and \`can_exfiltrate\` in one session. Primary structural risk.
- **Policy** — YAML file declaring rules. Rules are \`when\` conditions plus an \`action\` (\`allow\` / \`block\` / \`warn\` / \`confirm\`). First match wins.

---

## Coding conventions

- **TypeScript strict mode.** No \`any\` without justification.
- **Functional core, imperative shell.** Pure functions for policy evaluation, capability resolution, taint propagation. Side effects (logging, network, file I/O) at the edges.
- **No silent failures.** Every error path is either logged at \`warn\`+ or surfaced to the user. A security tool that fails quietly is worse than one that crashes loudly.
- **Fail closed.** When uncertain, block. The user can override; an attacker cannot.
- **Append-only audit log.** Never rewrite or truncate audit JSONL. SQLite is the queryable mirror, not the source of truth.
- **No telemetry, no phone-home in v0.1.** Anything that leaves the user's machine is opt-in and clearly documented.
- **Naming:** \`kebab-case\` for files, \`camelCase\` for variables and functions, \`PascalCase\` for types and classes.
- **Tests live alongside fixtures.** Every detection rule has at least one positive test (a known attack it catches) and one negative test (a benign case it lets through).

---

## Security posture for the codebase itself

Portcullis is a security tool, so the bar for our own code is high:

- All dependencies pinned in \`package-lock.json\`.
- \`npm audit\` clean on \`main\`. Renovate or Dependabot configured.
- No \`eval\`, no dynamic \`require\`, no \`child_process.exec\` with user input.
- Tool descriptions and policy YAML are parsed with strict schemas (Zod or similar).
- The proxy must handle malformed JSON-RPC gracefully; never crash the user's AI client.
- If Portcullis itself crashes, the configured \`fail_mode\` (default: \`closed\`) determines whether traffic passes through or is blocked.

---

### Policy engine invariants

The `PolicyEngine` is a pure functional core. `evaluate()` is synchronous,
performs no I/O, writes no logs, and has no side effects beyond returning
a `PolicyDecision`. The decision carries the matched rule by reference so
the caller has everything needed to log the outcome.

Logging the policy decision is the caller's responsibility. In practice
that caller is the proxy intercept loop (`src/proxy/proxy.ts`), which
writes the matched rule name and action into the audit log entry for the
tool call it is gating. The engine never imports the logger.

Why:
1. Testability — a pure evaluator is unit-testable without filesystem or
   logger mocks.
2. Single-source audit ordering — the JSONL-first invariant only works if
   exactly one component owns the write. Letting the engine also log
   would create two writers racing on the same event.
3. Synchronous contract — the intercept loop cannot await a slow policy
   check. Banning side effects keeps `evaluate()` trivially fast.

Schema strictness: the engine validates the full rule list at load time
and rejects any `when` condition key it cannot evaluate. Silently
ignoring an unknown condition is a security failure — a rule that looks
like it blocks something but does nothing is worse than no rule at all.
Adding a new condition type requires both an engine change and a
schema-validator change in the same commit.

---

### Audit log invariants

The JSONL file is the source of truth. SQLite is a queryable mirror, always
rebuildable from JSONL via `replay-from-jsonl`. This dictates write ordering:

1. JSONL write (with fsync) MUST complete before the SQLite write.
2. SQLite write failures MUST NOT propagate out of `Logger.append()` — catch,
   log a warning, continue. A failed mirror write is recoverable; a failed
   audit write is not.
3. Nothing may write to SQLite that did not first land in JSONL.

Do not "fix" this with a transaction wrapper across both stores. There is no
real transaction across a file append and a separate SQLite process; faking
one would silently break the invariant.

---

## Research foundations

These shape how we think about the problem. New contributors should at least skim these before substantial work:

- **Simon Willison — "The Lethal Trifecta"** (June 2025). Conceptual core.
- **OWASP Top 10 for Agentic Applications (2026).** Maps to our threat model; every feature should map back to one or more ASI items.
- **Model Context Protocol spec** at modelcontextprotocol.io. Required reading for any work in \`src/proxy/\`.
- **CaMeL** (Google DeepMind, 2025, arXiv 2503.18813). Capability-based defense inspiration.
- **ATTESTMCP** (Maloyan & Namiot, 2026). Long-term direction for protocol-level attestation.
- **Real-world incidents:** GitHub MCP issue exfiltration (May 2025), malicious Postmark MCP package (September 2025), MCP STDIO RCE CVEs (CVE-2026-22252 family), NeighborJack exposure scan (June 2025). Reproductions live in \`tests/fixtures/attack-scenarios.json\`.

---

## How to work with Claude Code in this repo

When Claude Code is invoked here, prefer:

- **Reading README.md and this file before substantial changes.**
- **Asking before adding dependencies.** Especially anything that opens a network connection at install time.
- **Keeping diffs scoped.** One PR, one concern. Refactors separate from features.
- **Writing tests for any detection logic.** Pair each new pattern with a fixture in \`tests/fixtures/\`.
- **Updating \`docs/journal/\` for substantial sessions.** Date-stamped markdown notes — what was worked on, what was decided, what's still open. This becomes the build-in-public log.
- **Calling out security trade-offs explicitly.** If a change makes the proxy more permissive, say so in the PR description.

When in doubt about scope or approach: ask before committing.

---

## Team

- **Jose Torres IV** — project lead. Junior at Purdue, cybersecurity major. Background in network security, agentic AI security, systems administration, CTFs.
- **Dallan Stepps** - sub-lead. Junior at Purdue, cybersecurity major. Background in security operations, networking, CTFs, systems administration, agentic AI security.

---

## License

All Rights Reserved. See LICENSE.
