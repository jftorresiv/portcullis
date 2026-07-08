import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { replayFromJsonl } from "../../src/cli.js";
import { Store } from "../../src/audit/store.js";
import type { AuditEvent } from "../../src/audit/logger.js";

function tmpJsonl(): string {
  return path.join(os.tmpdir(), `portcullis-replay-${randomUUID()}.jsonl`);
}

function makeEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    timestamp: new Date().toISOString(),
    session_id: randomUUID(),
    direction: "client_to_server",
    server: "test-server",
    method: "tools/list",
    message: { jsonrpc: "2.0", id: 1 },
    ...overrides,
  };
}

function writeJsonl(filePath: string, events: AuditEvent[]): void {
  fs.writeFileSync(
    filePath,
    events.map((e) => JSON.stringify(e)).join("\n") + "\n",
    "utf8"
  );
}

function eventsEqual(a: AuditEvent, b: AuditEvent): boolean {
  return (
    a.timestamp === b.timestamp &&
    a.session_id === b.session_id &&
    a.direction === b.direction &&
    a.server === b.server &&
    a.method === b.method &&
    JSON.stringify(a.message) === JSON.stringify(b.message) &&
    a.decision === b.decision
  );
}

describe("replayFromJsonl", () => {
  const files: string[] = [];

  after(() => {
    for (const f of files) fs.rmSync(f, { force: true });
  });

  it("empty SQLite + populated JSONL → SQLite matches JSONL", () => {
    const jsonlPath = tmpJsonl();
    files.push(jsonlPath);

    const events = [
      makeEvent({ method: "tools/call", decision: "allowed" }),
      makeEvent({ method: "tools/list" }),
      makeEvent({ method: "resources/read", decision: "blocked" }),
    ];
    writeJsonl(jsonlPath, events);

    const store = new Store(":memory:");
    const count = replayFromJsonl(jsonlPath, store);

    assert.equal(count, 3, "should report 3 replayed events");

    const rows = store.query();
    assert.equal(rows.length, 3);
    for (let i = 0; i < events.length; i++) {
      const expected = events[i];
      const actual = rows[i];
      assert.ok(expected !== undefined && actual !== undefined);
      assert.ok(
        eventsEqual(expected, actual),
        `row ${i} mismatch: ${JSON.stringify(actual)} ≠ ${JSON.stringify(expected)}`
      );
    }

    store.close();
  });

  it("out-of-sync SQLite (missing rows) → matches JSONL after replay", () => {
    const jsonlPath = tmpJsonl();
    files.push(jsonlPath);

    const events = Array.from({ length: 5 }, (_, i) =>
      makeEvent({ method: `method-${i}` })
    );
    writeJsonl(jsonlPath, events);

    const store = new Store(":memory:");
    // Pre-populate with only the first two rows.
    store.insert(events[0]!);
    store.insert(events[1]!);
    assert.equal(store.query().length, 2, "pre-condition: 2 rows before replay");

    replayFromJsonl(jsonlPath, store);

    const rows = store.query();
    assert.equal(rows.length, 5, "all 5 JSONL events should be in SQLite after replay");
    for (let i = 0; i < events.length; i++) {
      const expected = events[i];
      const actual = rows[i];
      assert.ok(expected !== undefined && actual !== undefined);
      assert.ok(eventsEqual(expected, actual));
    }

    store.close();
  });

  it("dirty SQLite (extra rows not in JSONL) → matches JSONL after replay (truncate)", () => {
    const jsonlPath = tmpJsonl();
    files.push(jsonlPath);

    const canonical = [
      makeEvent({ method: "canonical-1" }),
      makeEvent({ method: "canonical-2" }),
    ];
    writeJsonl(jsonlPath, canonical);

    const store = new Store(":memory:");
    // Insert the canonical events PLUS an extra row that is not in the JSONL.
    for (const e of canonical) store.insert(e);
    store.insert(makeEvent({ method: "extra-not-in-jsonl" }));
    assert.equal(store.query().length, 3, "pre-condition: 3 rows before replay");

    replayFromJsonl(jsonlPath, store);

    const rows = store.query();
    assert.equal(
      rows.length,
      2,
      "extra row must be gone after replay — truncate is required"
    );
    assert.ok(rows.every((r) => r.method !== "extra-not-in-jsonl"));

    store.close();
  });

  it("returns 0 for an empty JSONL file", () => {
    const jsonlPath = tmpJsonl();
    files.push(jsonlPath);
    fs.writeFileSync(jsonlPath, "", "utf8");

    const store = new Store(":memory:");
    const count = replayFromJsonl(jsonlPath, store);
    assert.equal(count, 0);
    assert.equal(store.query().length, 0);
    store.close();
  });

  it("is idempotent — running twice yields the same state", () => {
    const jsonlPath = tmpJsonl();
    files.push(jsonlPath);

    const events = [makeEvent(), makeEvent()];
    writeJsonl(jsonlPath, events);

    const store = new Store(":memory:");
    replayFromJsonl(jsonlPath, store);
    replayFromJsonl(jsonlPath, store);

    assert.equal(store.query().length, 2);
    store.close();
  });
});
