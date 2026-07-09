import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import type { FastifyInstance } from "fastify";
import { registerRoutes } from "../../src/dashboard/api.js";
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

describe("dashboard api", () => {
  describe("with no events", () => {
    let app: FastifyInstance;
    let store: Store;

    before(() => {
      store = new Store(":memory:");
      app = Fastify({ logger: false });
      registerRoutes(app, store);
    });

    after(async () => {
      await app.close();
      store.close();
    });

    it("GET /api/sessions returns an empty array", async () => {
      const res = await app.inject({ method: "GET", url: "/api/sessions" });
      assert.equal(res.statusCode, 200);
      assert.deepEqual(res.json(), []);
    });

    it("GET /api/events returns an empty array", async () => {
      const res = await app.inject({ method: "GET", url: "/api/events" });
      assert.equal(res.statusCode, 200);
      assert.deepEqual(res.json(), []);
    });

    it("GET /api/health reports ok", async () => {
      const res = await app.inject({ method: "GET", url: "/api/health" });
      assert.equal(res.statusCode, 200);
      assert.equal(res.json().status, "ok");
    });
  });

  describe("with seeded events", () => {
    let app: FastifyInstance;
    let store: Store;
    const sessionA = randomUUID();
    const sessionB = randomUUID();
    const base = new Date("2025-06-01T12:00:00.000Z");

    before(() => {
      store = new Store(":memory:");
      app = Fastify({ logger: false });
      registerRoutes(app, store);

      store.runInTransaction(() => {
        for (let i = 0; i < 6; i++) {
          store.insert(
            makeEvent({
              session_id: i < 4 ? sessionA : sessionB,
              server: i % 2 === 0 ? "server-alpha" : "server-beta",
              timestamp: new Date(base.getTime() + i * 60_000).toISOString(),
            })
          );
        }
      });
    });

    after(async () => {
      await app.close();
      store.close();
    });

    it("GET /api/sessions aggregates per session_id", async () => {
      const res = await app.inject({ method: "GET", url: "/api/sessions" });
      assert.equal(res.statusCode, 200);
      const sessions = res.json() as Array<{
        session_id: string;
        event_count: number;
        servers: string[];
      }>;
      assert.equal(sessions.length, 2);

      const a = sessions.find((s) => s.session_id === sessionA);
      assert.ok(a !== undefined);
      assert.equal(a.event_count, 4);
      assert.deepEqual([...a.servers].sort(), ["server-alpha", "server-beta"]);

      const b = sessions.find((s) => s.session_id === sessionB);
      assert.ok(b !== undefined);
      assert.equal(b.event_count, 2);
    });

    it("GET /api/events filters by session_id", async () => {
      const res = await app.inject({
        method: "GET",
        url: `/api/events?session_id=${sessionA}`,
      });
      assert.equal(res.statusCode, 200);
      const events = res.json() as AuditEvent[];
      assert.equal(events.length, 4);
      assert.ok(events.every((e) => e.session_id === sessionA));
    });

    it("GET /api/events respects limit", async () => {
      const res = await app.inject({ method: "GET", url: "/api/events?limit=2" });
      assert.equal(res.statusCode, 200);
      const events = res.json() as AuditEvent[];
      assert.equal(events.length, 2);
    });
  });
});
