import type { FastifyInstance } from "fastify";
import type { Store } from "../audit/store.js";
import { dashboardHtml } from "./ui/index.js";
import { resolvePidPath, readPidFile } from "../proxy/pidfile.js";

const START_TIME = Date.now();
const VERSION = "0.1.0";

interface EventsQuery {
  session_id?: string;
  limit?: string;
  type?: string;
}

export interface RouteOptions {
  pidPath?: string;
  killFn?: (pid: number, signal: NodeJS.Signals) => void;
}

export function registerRoutes(
  app: FastifyInstance,
  store: Store,
  opts: RouteOptions = {}
): void {
  const pidPath = opts.pidPath ?? resolvePidPath();
  const killFn = opts.killFn ?? ((pid, signal) => process.kill(pid, signal));

  app.get("/", async (_request, reply) => {
    reply.type("text/html");
    return dashboardHtml;
  });

  app.get("/api/health", async () => ({
    version: VERSION,
    uptime_seconds: Math.floor((Date.now() - START_TIME) / 1000),
    status: "ok",
  }));

  app.get("/api/sessions", async () => {
    const events = store.query();

    const map = new Map<
      string,
      {
        first_seen: string;
        last_seen: string;
        event_count: number;
        servers: Set<string>;
        trifecta: boolean;
        tainted: boolean;
      }
    >();

    for (const event of events) {
      const s = map.get(event.session_id);
      if (!s) {
        map.set(event.session_id, {
          first_seen: event.timestamp,
          last_seen: event.timestamp,
          event_count: 1,
          servers: new Set([event.server]),
          trifecta: event.type === "trifecta_alert",
          tainted: event.type === "session_tainted",
        });
      } else {
        if (event.timestamp < s.first_seen) s.first_seen = event.timestamp;
        if (event.timestamp > s.last_seen) s.last_seen = event.timestamp;
        s.event_count++;
        s.servers.add(event.server);
        if (event.type === "trifecta_alert") s.trifecta = true;
        if (event.type === "session_tainted") s.tainted = true;
      }
    }

    return Array.from(map.entries()).map(([session_id, s]) => ({
      session_id,
      first_seen: s.first_seen,
      last_seen: s.last_seen,
      event_count: s.event_count,
      servers: Array.from(s.servers),
      trifecta: s.trifecta,
      tainted: s.tainted,
    }));
  });

  app.get<{ Querystring: EventsQuery }>("/api/events", async (request) => {
    const { session_id, limit, type } = request.query;

    const filters: { session_id?: string; type?: string } = {};
    if (session_id !== undefined) filters.session_id = session_id;
    if (type !== undefined) filters.type = type;

    let events = store.query(filters);

    if (limit !== undefined) {
      const n = parseInt(limit, 10);
      if (!isNaN(n) && n > 0) events = events.slice(0, n);
    }

    return events;
  });

  app.get("/api/kill-switch/status", async () => {
    const activated = store.query({ type: "kill_switch_activated" });
    const reset = store.query({ type: "kill_switch_reset" });
    const lastActivated = activated.at(-1)?.timestamp;
    const lastReset = reset.at(-1)?.timestamp;
    const frozen =
      lastActivated !== undefined &&
      (lastReset === undefined || lastActivated > lastReset);
    return { frozen };
  });

  app.post("/api/kill-switch/activate", async (_request, reply) => {
    const pid = readPidFile(pidPath);
    if (pid === null) {
      await reply.code(503).send({ error: "proxy not running (no pid file found)" });
      return;
    }

    try {
      killFn(pid, "SIGUSR1");
    } catch (err) {
      await reply.code(503).send({ error: `failed to signal proxy process: ${err}` });
      return;
    }

    return { status: "activated" };
  });
}
