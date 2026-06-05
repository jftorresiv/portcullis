import type { FastifyInstance } from "fastify";
import { readAuditLog } from "../audit/reader.js";
import { dashboardHtml } from "./ui/index.js";

const START_TIME = Date.now();
const VERSION = "0.1.0";

interface EventsQuery {
  session_id?: string;
  limit?: string;
}

export function registerRoutes(app: FastifyInstance, logPath: string): void {
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
    const events = await readAuditLog(logPath);

    const map = new Map<
      string,
      { first_seen: string; last_seen: string; event_count: number; servers: Set<string> }
    >();

    for (const event of events) {
      const s = map.get(event.session_id);
      if (!s) {
        map.set(event.session_id, {
          first_seen: event.timestamp,
          last_seen: event.timestamp,
          event_count: 1,
          servers: new Set([event.server]),
        });
      } else {
        if (event.timestamp < s.first_seen) s.first_seen = event.timestamp;
        if (event.timestamp > s.last_seen) s.last_seen = event.timestamp;
        s.event_count++;
        s.servers.add(event.server);
      }
    }

    return Array.from(map.entries()).map(([session_id, s]) => ({
      session_id,
      first_seen: s.first_seen,
      last_seen: s.last_seen,
      event_count: s.event_count,
      servers: Array.from(s.servers),
    }));
  });

  app.get<{ Querystring: EventsQuery }>("/api/events", async (request) => {
    const { session_id, limit } = request.query;
    let events = await readAuditLog(logPath);

    if (session_id !== undefined) {
      events = events.filter((e) => e.session_id === session_id);
    }

    if (limit !== undefined) {
      const n = parseInt(limit, 10);
      if (!isNaN(n) && n > 0) events = events.slice(0, n);
    }

    return events;
  });
}
