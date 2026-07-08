import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { Store } from "../../src/audit/store.js";
import type { AuditEvent } from "../../src/audit/logger.js";

function makeEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    timestamp: new Date().toISOString(),
    session_id: randomUUID(),
    direction: "client_to_server",
    server: "test-server",
    method: "tools/list",
    message: { jsonrpc: "2.0", id: 1, method: "tools/list" },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Insert + readback
// ---------------------------------------------------------------------------

describe("Store", () => {
  describe("insert + readback", () => {
    it("round-trips a minimal event", () => {
      const store = new Store(":memory:");
      const event = makeEvent();
      store.insert(event);
      const results = store.query();
      assert.equal(results.length, 1);
      const row = results[0];
      assert.ok(row !== undefined);
      assert.equal(row.timestamp, event.timestamp);
      assert.equal(row.session_id, event.session_id);
      assert.equal(row.direction, event.direction);
      assert.equal(row.server, event.server);
      assert.equal(row.method, event.method);
      assert.deepEqual(row.message, event.message);
      assert.equal(row.decision, undefined);
      store.close();
    });

    it("round-trips an event with a decision", () => {
      const store = new Store(":memory:");
      const event = makeEvent({ decision: "blocked" });
      store.insert(event);
      const [row] = store.query();
      assert.ok(row !== undefined);
      assert.equal(row.decision, "blocked");
      store.close();
    });

    it("preserves insertion order across multiple events", () => {
      const store = new Store(":memory:");
      const methods = ["tools/list", "tools/call", "resources/read"] as const;
      const base = new Date("2025-01-01T00:00:00.000Z");
      for (let i = 0; i < methods.length; i++) {
        const method = methods[i];
        if (method === undefined) continue;
        store.insert(
          makeEvent({
            method,
            timestamp: new Date(base.getTime() + i * 1000).toISOString(),
          })
        );
      }
      const rows = store.query();
      assert.equal(rows.length, 3);
      assert.deepEqual(
        rows.map((r) => r.method),
        methods
      );
      store.close();
    });
  });

  // ---------------------------------------------------------------------------
  // Query filter paths
  // ---------------------------------------------------------------------------

  describe("query filters", () => {
    let store: Store;
    const sessionA = randomUUID();
    const sessionB = randomUUID();
    const base = new Date("2025-06-01T12:00:00.000Z");

    before(() => {
      store = new Store(":memory:");
      store.runInTransaction(() => {
        for (let i = 0; i < 10; i++) {
          store.insert(
            makeEvent({
              session_id: i < 5 ? sessionA : sessionB,
              server: i % 2 === 0 ? "server-alpha" : "server-beta",
              method: i % 3 === 0 ? "tools/call" : "tools/list",
              timestamp: new Date(base.getTime() + i * 60_000).toISOString(),
              decision: i % 4 === 0 ? "allowed" : undefined,
            })
          );
        }
      });
    });

    after(() => {
      store.close();
    });

    it("filters by session_id", () => {
      const rows = store.query({ session_id: sessionA });
      assert.equal(rows.length, 5);
      assert.ok(rows.every((r) => r.session_id === sessionA));
    });

    it("filters by session_id — other session", () => {
      const rows = store.query({ session_id: sessionB });
      assert.equal(rows.length, 5);
      assert.ok(rows.every((r) => r.session_id === sessionB));
    });

    it("filters by time range (from only)", () => {
      const from = new Date(base.getTime() + 5 * 60_000).toISOString();
      const rows = store.query({ from });
      assert.ok(rows.length >= 5, `expected ≥5, got ${rows.length}`);
      assert.ok(rows.every((r) => r.timestamp >= from));
    });

    it("filters by time range (to only)", () => {
      const to = new Date(base.getTime() + 4 * 60_000).toISOString();
      const rows = store.query({ to });
      assert.ok(rows.length >= 5, `expected ≥5, got ${rows.length}`);
      assert.ok(rows.every((r) => r.timestamp <= to));
    });

    it("filters by time range (from + to)", () => {
      const from = new Date(base.getTime() + 2 * 60_000).toISOString();
      const to = new Date(base.getTime() + 6 * 60_000).toISOString();
      const rows = store.query({ from, to });
      assert.ok(
        rows.every((r) => r.timestamp >= from && r.timestamp <= to),
        "all rows should be within the time window"
      );
    });

    it("filters by server", () => {
      const rows = store.query({ server: "server-alpha" });
      assert.ok(rows.length > 0);
      assert.ok(rows.every((r) => r.server === "server-alpha"));
    });

    it("filters by method", () => {
      const rows = store.query({ method: "tools/call" });
      assert.ok(rows.length > 0);
      assert.ok(rows.every((r) => r.method === "tools/call"));
    });

    it("filters by server + method combined", () => {
      const rows = store.query({ server: "server-alpha", method: "tools/call" });
      assert.ok(rows.every((r) => r.server === "server-alpha" && r.method === "tools/call"));
    });

    it("filters by session_id + time range", () => {
      const from = new Date(base.getTime() + 1 * 60_000).toISOString();
      const to = new Date(base.getTime() + 4 * 60_000).toISOString();
      const rows = store.query({ session_id: sessionA, from, to });
      assert.ok(
        rows.every(
          (r) =>
            r.session_id === sessionA &&
            r.timestamp >= from &&
            r.timestamp <= to
        )
      );
    });

    it("returns empty array for a session that has no events", () => {
      const rows = store.query({ session_id: randomUUID() });
      assert.equal(rows.length, 0);
    });

    it("returns all rows when no filters are given", () => {
      const rows = store.query();
      assert.equal(rows.length, 10);
    });

    it("caches prepared statements (same SQL shape re-uses cached stmt)", () => {
      // Two calls with the same filter shape must not throw or corrupt state.
      const a = store.query({ server: "server-alpha" });
      const b = store.query({ server: "server-alpha" });
      assert.deepEqual(a, b);
    });
  });

  // ---------------------------------------------------------------------------
  // replay()
  // ---------------------------------------------------------------------------

  describe("replay", () => {
    it("replaces existing rows with new event set", () => {
      const store = new Store(":memory:");
      const old = makeEvent({ method: "old-method" });
      store.insert(old);

      const fresh = [
        makeEvent({ method: "new-method-1" }),
        makeEvent({ method: "new-method-2" }),
      ];
      store.replay(fresh);

      const rows = store.query();
      assert.equal(rows.length, 2);
      assert.deepEqual(
        rows.map((r) => r.method),
        ["new-method-1", "new-method-2"]
      );
      store.close();
    });

    it("replay of empty array truncates the table", () => {
      const store = new Store(":memory:");
      store.insert(makeEvent());
      store.replay([]);
      assert.equal(store.query().length, 0);
      store.close();
    });
  });

  // ---------------------------------------------------------------------------
  // Performance sanity check: 100k rows, index-backed queries < 50 ms
  // ---------------------------------------------------------------------------

  describe("performance", () => {
    let store: Store;
    const targetSession = randomUUID();
    const targetServer = "perf-server";
    const targetMethod = "tools/call";
    const baseTime = new Date("2025-01-01T00:00:00.000Z");

    before(() => {
      store = new Store(":memory:");

      store.runInTransaction(() => {
        for (let i = 0; i < 100_000; i++) {
          store.insert(
            makeEvent({
              session_id: i % 1000 === 0 ? targetSession : randomUUID(),
              server: i % 100 === 0 ? targetServer : "other-server",
              method: i % 50 === 0 ? targetMethod : "tools/list",
              timestamp: new Date(
                baseTime.getTime() + i * 100
              ).toISOString(),
            })
          );
        }
      });
    }, { timeout: 30_000 });

    after(() => {
      store.close();
    });

    it("session_id query on 100k rows completes in < 50 ms", () => {
      const t0 = performance.now();
      const rows = store.query({ session_id: targetSession });
      const elapsed = performance.now() - t0;
      assert.ok(rows.length > 0, "should find at least one matching row");
      assert.ok(elapsed < 50, `session query took ${elapsed.toFixed(1)} ms (limit 50 ms)`);
    });

    it("timestamp range query on 100k rows completes in < 50 ms", () => {
      const from = new Date(baseTime.getTime() + 50_000 * 100).toISOString();
      const to = new Date(baseTime.getTime() + 51_000 * 100).toISOString();
      const t0 = performance.now();
      store.query({ from, to });
      const elapsed = performance.now() - t0;
      assert.ok(elapsed < 50, `time-range query took ${elapsed.toFixed(1)} ms (limit 50 ms)`);
    });

    it("server + method query on 100k rows completes in < 50 ms", () => {
      const t0 = performance.now();
      const rows = store.query({ server: targetServer, method: targetMethod });
      const elapsed = performance.now() - t0;
      assert.ok(rows.length > 0, "should find at least one matching row");
      assert.ok(
        elapsed < 50,
        `server+method query took ${elapsed.toFixed(1)} ms (limit 50 ms)`
      );
    });
  });
});
