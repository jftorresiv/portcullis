# 2026-06-16 — Policy engine (load + evaluate)

Issue #18. First piece of v0.2 enforcement: a pure rule evaluator that loads
`policies/default.yaml` and returns a decision per tool call. Not yet wired
into the proxy — that's #19.

## What was built

- `src/types/mcp.ts` — added `ToolCallEvent`, the engine's input contract:
  `{ tool, server, capabilities: string[], sessionTrifecta?: boolean }`. The
  issue assumed a `ToolCallEvent` type already existed "emitted by the v0.1
  tagger," but no such type was in the repo — the tagger (`tagTool`) returns a
  bare `string[]`. Confirmed with the project lead and created the type fresh
  rather than overloading the audit-log `AuditEvent` shape.
- `src/policy/engine.ts` — `PolicyEngine` class:
  - `load(path)`: synchronous read + YAML parse + **full schema validation at
    load time**. Throws message-rich errors on malformed YAML, unknown action,
    unknown `when` key (Zod `.strict()`), or malformed condition shape. No
    schema error is ever deferred to `evaluate()`.
  - `evaluate(event)`: pure, synchronous, first-match-wins. No I/O, no logging.
    Returns `{ action, matchedRule? }`, the matched rule by reference. No match
    → default `{ action: 'allow' }`. Throws if called before `load()`
    (fail loud, not silently open).
- `tests/policy/engine.test.ts` — 18 tests: allow/block/warn/confirm,
  no-match default-allow, first-match-wins (later match not evaluated),
  malformed-YAML-throws-at-load, unknown-action/key/shape rejection, AND
  combination, glob wildcards, empty-`when` match-all, and the real
  default.yaml trifecta path.

## Supported `when` conditions (this issue only)

`tool` (glob), `server` (glob), `capabilities: { all?, any? }`,
`session_trifecta` (bool). All AND-combined; absent/empty `when` = match-all.
Capability values are validated against `KNOWN_CAPABILITIES` so a typo'd tag
fails at load instead of silently never matching.

## default.yaml reconciliation

The shipped rules used several conditions the engine can't yet evaluate. Rather
than silently drop them:

- Trifecta rule → rewritten to `session_trifecta: true` (block).
- Code-execution rule → `capabilities: { any: [can_execute_code] }` (confirm).
- Tainted-exfil, credential-arg-regex, tool-description-injection, suspicious-
  fetch-args, new-server, and bulk-read rules → **commented out** with
  `TODO(#...)` markers naming the future condition each needs (taint tracker,
  arg scanner, injection scanner, server registry, session metrics).

## Open / next

- #19: wire the engine into `src/proxy/proxy.ts` and have the intercept loop
  log the matched rule + action into the audit entry (engine stays pure).
- Future conditions per the TODOs above will each need a matching change in
  both the matcher and the load-time schema (CLAUDE.md invariant).

## Security note

This change adds no permissiveness to the running proxy (engine isn't wired in
yet). The engine fails closed on misuse (`evaluate` before `load` throws) and
fails loud on bad policy (load-time validation). The only behavioral shift is
that the default policy's previously-active arg/taint/registration rules are
now disabled-but-visible until their supporting conditions land.
