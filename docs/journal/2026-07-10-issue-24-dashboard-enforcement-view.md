# 2026-07-10 — Dashboard enforcement view

Issue #24. Surfaces v0.2's detection/enforcement events (#20 trifecta, #21
taint, #22 injection scanner, #23 kill switch) — already flowing into SQLite
since #34 — in the dashboard UI, which previously only rendered a plain
timeline.

## What was built

- `src/audit/logger.ts` / `src/audit/store.ts` — added `matchedRule` to
  `AuditEvent` and a `matched_rule TEXT` column (with the same ALTER TABLE
  upgrade path used for `type`/`capabilities_json`). The matched policy rule
  name was previously written to stderr only (`src/proxy/index.ts`) and never
  persisted; the issue's scope explicitly wants it on the decision feed.
- `src/proxy/index.ts` — warn/confirm/block audit appends now carry
  `matchedRule: decision.matchedRule.name` when a rule matched.
- `src/proxy/pidfile.ts` (new) — `resolvePidPath`/`writePidFile`/
  `readPidFile`/`removePidFile`, defaulting to `~/.portcullis/proxy.pid`
  (override via `PORTCULLIS_PID_PATH`). The proxy writes this on startup and
  removes it on `SIGINT`/`SIGTERM`.
- `src/dashboard/api.ts`:
  - `/api/events` now accepts a `type` filter (was already supported by
    `Store.query`, just never wired to the route).
  - `/api/sessions` gained `trifecta`/`tainted` booleans, derived in the
    existing per-session reduce pass.
  - New `GET /api/kill-switch/status` and `POST /api/kill-switch/activate`.
    `registerRoutes` takes an optional `{ pidPath, killFn }` so tests can
    inject a fake signal function instead of sending real signals.
- `src/dashboard/ui/index.ts` — trifecta dot + taint badge on session cards,
  a new Injection Alerts panel, a new Kill Switch panel (status + confirm()
  + POST), and matched-rule name in the timeline's expanded detail. Session
  and alert polling bumped to 1000ms per the issue's own note and to satisfy
  the "trifecta indicator flips within 1 second" acceptance criterion.

## The cross-process kill switch problem

The issue's "calls `KillSwitch.activate()`" phrasing assumes the dashboard
and proxy share a process. They don't — the dashboard only ever holds a
read-only `Store`; `KillSwitch` is an in-memory singleton inside the proxy
process, reachable before this issue only via `SIGUSR1`/`SIGUSR2` sent
directly to that PID. Resolved with the project lead: PID file + `SIGUSR1`,
reusing the exact signal path already wired and tested
(`tests/proxy/kill-switch.test.ts`), rather than a DB-polled control flag
(would add per-message latency and a bigger proxy hot-path change for no
real benefit at this scale). Verified manually end-to-end: a dummy process
holding the PID file received `SIGUSR1` when `POST
/api/kill-switch/activate` was called against it, and a missing/stale PID
file returns 503 instead of hanging.

## Known gap, not fixed here

The "allow" path never writes a `decision: "allowed"` audit row — only
warn/confirm/block do. The dashboard's "Allowed" timeline filter has
therefore been dead code since before this issue. Fixing it means logging a
row for every passed-through call (including non-tool-call traffic), which
is a proxy hot-path/perf decision beyond "add a dashboard view" — left alone
and flagged here rather than silently expanding scope.

## Branching note

Started this work on `feat/issue-34-sqlite-audit-sink` before realizing #34
had already been merged into `main` upstream mid-session (PR #38). Moved the
uncommitted #24 diff onto the pre-existing empty
`feat/issue-24-dashboard-enforcement-view` branch, rebased on current `main`,
rather than bundling both issues into one PR.

## Verification

- `npm test` — 183/183 passing, including new coverage for `pidfile.ts`, the
  `matched_rule` round-trip + ALTER TABLE upgrade path, and the new
  `/api/kill-switch/*` + `/api/sessions` enrichment routes.
- Manual: seeded a SQLite DB with trifecta/taint/injection/blocked-with-rule
  events, ran the dashboard against it, confirmed `/api/sessions` reports
  `trifecta`/`tainted`, `/api/events?type=injection_scan_alert` returns only
  matching rows, and the kill-switch endpoint correctly signals a live
  process via its PID file (and 503s when there is none).
