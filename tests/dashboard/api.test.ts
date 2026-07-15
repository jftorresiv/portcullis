import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Fastify from "fastify";
import type { FastifyInstance } from "fastify";
import { registerRoutes } from "../../src/dashboard/api.js";
import { Store } from "../../src/audit/store.js";
import type { AuditEvent } from "../../src/audit/logger.js";

function tmpPidPath(): string {
  return path.join(os.tmpdir(), `portcullis-api-test-${randomUUID()}.pid`);
}

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

  describe("type filter and enforcement enrichment", () => {
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
        store.insert(
          makeEvent({
            session_id: sessionA,
            timestamp: new Date(base.getTime()).toISOString(),
          })
        );
        store.insert(
          makeEvent({
            session_id: sessionA,
            type: "trifecta_alert",
            timestamp: new Date(base.getTime() + 60_000).toISOString(),
          })
        );
        store.insert(
          makeEvent({
            session_id: sessionA,
            type: "injection_scan_alert",
            message: { toolName: "evil-tool", field: "description", pattern: "ignore previous instructions", severity: "critical" },
            timestamp: new Date(base.getTime() + 120_000).toISOString(),
          })
        );
        store.insert(
          makeEvent({
            session_id: sessionB,
            type: "session_tainted",
            timestamp: new Date(base.getTime() + 180_000).toISOString(),
          })
        );
      });
    });

    after(async () => {
      await app.close();
      store.close();
    });

    it("GET /api/events?type= filters to only that event type", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/api/events?type=injection_scan_alert",
      });
      assert.equal(res.statusCode, 200);
      const events = res.json() as AuditEvent[];
      assert.equal(events.length, 1);
      assert.equal(events[0]?.type, "injection_scan_alert");
    });

    it("GET /api/sessions marks a session with a trifecta_alert as trifecta:true", async () => {
      const res = await app.inject({ method: "GET", url: "/api/sessions" });
      const sessions = res.json() as Array<{
        session_id: string;
        trifecta: boolean;
        tainted: boolean;
      }>;
      const a = sessions.find((s) => s.session_id === sessionA);
      assert.ok(a !== undefined);
      assert.equal(a.trifecta, true);
      assert.equal(a.tainted, false);
    });

    it("GET /api/sessions marks a session with a session_tainted event as tainted:true", async () => {
      const res = await app.inject({ method: "GET", url: "/api/sessions" });
      const sessions = res.json() as Array<{
        session_id: string;
        trifecta: boolean;
        tainted: boolean;
      }>;
      const b = sessions.find((s) => s.session_id === sessionB);
      assert.ok(b !== undefined);
      assert.equal(b.trifecta, false);
      assert.equal(b.tainted, true);
    });
  });

  describe("kill switch routes", () => {
    let app: FastifyInstance;
    let store: Store;
    let pidPath: string;
    let killCalls: Array<{ pid: number; signal: NodeJS.Signals }>;

    before(() => {
      store = new Store(":memory:");
      pidPath = tmpPidPath();
      killCalls = [];
      app = Fastify({ logger: false });
      registerRoutes(app, store, {
        pidPath,
        killFn: (pid, signal) => {
          killCalls.push({ pid, signal });
        },
      });
    });

    after(async () => {
      await app.close();
      store.close();
      fs.rmSync(pidPath, { force: true });
    });

    it("GET /api/kill-switch/status reports not frozen when no events exist", async () => {
      const res = await app.inject({ method: "GET", url: "/api/kill-switch/status" });
      assert.equal(res.statusCode, 200);
      assert.deepEqual(res.json(), { frozen: false });
    });

    it("POST /api/kill-switch/activate returns 503 when no pid file exists", async () => {
      const res = await app.inject({ method: "POST", url: "/api/kill-switch/activate" });
      assert.equal(res.statusCode, 503);
      assert.equal(killCalls.length, 0);
    });

    it("POST /api/kill-switch/activate signals the proxy pid via killFn once a pid file exists", async () => {
      fs.mkdirSync(path.dirname(pidPath), { recursive: true });
      fs.writeFileSync(pidPath, "4242", "utf8");

      const res = await app.inject({ method: "POST", url: "/api/kill-switch/activate" });
      assert.equal(res.statusCode, 200);
      assert.equal(killCalls.length, 1);
      assert.equal(killCalls[0]?.pid, 4242);
      assert.equal(killCalls[0]?.signal, "SIGUSR1");
    });

    it("POST /api/kill-switch/activate returns 503 when killFn throws (stale pid)", async () => {
      const throwingApp = Fastify({ logger: false });
      registerRoutes(throwingApp, store, {
        pidPath,
        killFn: () => {
          throw new Error("ESRCH: no such process");
        },
      });

      const res = await throwingApp.inject({ method: "POST", url: "/api/kill-switch/activate" });
      assert.equal(res.statusCode, 503);
      await throwingApp.close();
    });

    it("GET /api/kill-switch/status reflects the most recent event", async () => {
      store.insert(
        makeEvent({
          type: "kill_switch_activated",
          timestamp: new Date("2025-06-01T13:00:00.000Z").toISOString(),
        })
      );
      let res = await app.inject({ method: "GET", url: "/api/kill-switch/status" });
      assert.deepEqual(res.json(), { frozen: true });

      store.insert(
        makeEvent({
          type: "kill_switch_reset",
          timestamp: new Date("2025-06-01T13:05:00.000Z").toISOString(),
        })
      );
      res = await app.inject({ method: "GET", url: "/api/kill-switch/status" });
      assert.deepEqual(res.json(), { frozen: false });
    });
  });
});
