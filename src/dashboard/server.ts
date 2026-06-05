import Fastify from "fastify";
import { registerRoutes } from "./api.js";

export interface DashboardOptions {
  port?: number;
  logPath: string;
  token?: string;
}

// Never bind to anything outside loopback — a dashboard exposing the audit log
// to the LAN would be a serious privacy bug (cf. NeighborJack).
const HOST = "127.0.0.1";
const DEFAULT_PORT = 7778;

export async function startDashboard(options: DashboardOptions): Promise<void> {
  const { port = DEFAULT_PORT, logPath, token } = options;

  const app = Fastify({ logger: false });

  if (token !== undefined) {
    app.addHook("onRequest", async (request, reply) => {
      // Let the root page through so the user can see the token requirement.
      if (request.url === "/") return;
      if (request.headers.authorization !== `Bearer ${token}`) {
        await reply.code(401).send({ error: "Unauthorized" });
      }
    });
    process.stderr.write(`[portcullis] dashboard token: ${token}\n`);
  }

  registerRoutes(app, logPath);

  await app.listen({ port, host: HOST });
  process.stdout.write(`Portcullis dashboard running at http://${HOST}:${port}\n`);
}
