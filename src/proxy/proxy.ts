import { spawn } from "node:child_process";
import { LineFramer } from "./line-framer.js";
import type { InterceptedMessage, JsonRpcMessage } from "../types/mcp.js";

export interface ProxyOptions {
  serverCommand: string[];
  onMessage: (msg: InterceptedMessage) => void;
}

export function startProxy(options: ProxyOptions): void {
  const [cmd, ...args] = options.serverCommand;
  if (!cmd) throw new Error("serverCommand must not be empty");

  const server = spawn(cmd, args, {
    stdio: ["pipe", "pipe", "inherit"],
  });

  const clientFramer = new LineFramer();
  const serverFramer = new LineFramer();

  clientFramer.attach(process.stdin);

  if (!server.stdout) throw new Error("Failed to open server stdout");
  serverFramer.attach(server.stdout);

  clientFramer.on("line", (raw: string) => {
    const msg = parseMessage(raw);
    if (!msg) return;

    const intercepted: InterceptedMessage = {
      direction: "client->server",
      raw,
      parsed: msg,
      timestamp: new Date().toISOString(),
    };

    options.onMessage(intercepted);
    server.stdin?.write(raw + "\n");
  });

  serverFramer.on("line", (raw: string) => {
    const msg = parseMessage(raw);
    if (!msg) return;

    const intercepted: InterceptedMessage = {
      direction: "server->client",
      raw,
      parsed: msg,
      timestamp: new Date().toISOString(),
    };

    options.onMessage(intercepted);
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
