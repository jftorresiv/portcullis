import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { LineFramer } from "./line-framer.js";
import type { InterceptedMessage, JsonRpcMessage } from "../types/mcp.js";

export interface ForwardDecision {
  forward: boolean;
  syntheticResponse?: string;
}

export interface ProxyOptions {
  serverCommand: string[];
  serverName: string;
  onMessage: (msg: InterceptedMessage) => Promise<ForwardDecision>;
  onSessionStart?: (sessionId: string) => void;
}

export function startProxy(options: ProxyOptions): void {
  const [cmd, ...args] = options.serverCommand;
  if (!cmd) throw new Error("serverCommand must not be empty");

  const sessionId = randomUUID();
  options.onSessionStart?.(sessionId);

  const server = spawn(cmd, args, {
    stdio: ["pipe", "pipe", "inherit"],
  });

  const clientFramer = new LineFramer();
  const serverFramer = new LineFramer();

  clientFramer.attach(process.stdin);

  if (!server.stdout) throw new Error("Failed to open server stdout");
  serverFramer.attach(server.stdout);

  clientFramer.on("line", (raw: string) => {
    void (async () => {
      const msg = parseMessage(raw);
      if (!msg) return;

      const intercepted: InterceptedMessage = {
        direction: "client->server",
        raw,
        parsed: msg,
        timestamp: new Date().toISOString(),
        sessionId,
        server: options.serverName,
      };

      let decision: ForwardDecision;
      try {
        decision = await options.onMessage(intercepted);
      } catch (err) {
        process.stderr.write(`[portcullis] enforcement error: ${err}\n`);
        decision = { forward: false };
      }

      if (decision.forward) {
        server.stdin?.write(raw + "\n");
      } else if (decision.syntheticResponse !== undefined) {
        process.stdout.write(decision.syntheticResponse + "\n");
      }
    })();
  });

  serverFramer.on("line", (raw: string) => {
    const msg = parseMessage(raw);
    if (!msg) return;

    const intercepted: InterceptedMessage = {
      direction: "server->client",
      raw,
      parsed: msg,
      timestamp: new Date().toISOString(),
      sessionId,
      server: options.serverName,
    };

    // Server→client messages are never blocked; call onMessage for logging only.
    void options.onMessage(intercepted);
    process.stdout.write(raw + "\n");
  });

  serverFramer.on("end", () => process.exit(0));
  process.on("SIGINT", () => { server.kill(); process.exit(0); });
  process.on("SIGTERM", () => { server.kill(); process.exit(0); });
}

function parseMessage(raw: string): JsonRpcMessage | null {
  try {
    return JSON.parse(raw) as JsonRpcMessage;
  } catch {
    process.stderr.write(`[portcullis] Failed to parse message: ${raw}\n`);
    return null;
  }
}
