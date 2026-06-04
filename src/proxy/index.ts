import { startProxy } from "./proxy.js";
import { Logger } from "../audit/logger.js";
import type { InterceptedMessage } from "../types/mcp.js";

const LOG_PATH = process.env["PORTCULLIS_AUDIT_LOG"] ?? "~/.portcullis/audit.jsonl";
const SERVER_NAME = "filesystem";

const logger = new Logger(LOG_PATH);

function extractMethod(msg: InterceptedMessage): string {
  return "method" in msg.parsed ? (msg.parsed.method as string) : "(response)";
}

function onMessage(msg: InterceptedMessage): void {
  process.stderr.write(
    `[portcullis] ${msg.timestamp} ${msg.direction} ${JSON.stringify(msg.parsed).slice(0, 120)}\n`
  );

  logger.append({
    timestamp: msg.timestamp,
    session_id: msg.sessionId,
    direction: msg.direction === "client->server" ? "client_to_server" : "server_to_client",
    server: msg.server,
    method: extractMethod(msg),
    message: msg.parsed as unknown as Record<string, unknown>,
  }).catch((err: unknown) => {
    process.stderr.write(`[portcullis] audit log write failed: ${err}\n`);
  });
}

startProxy({
  serverCommand: [
    "npx", "-y", "@modelcontextprotocol/server-filesystem",
    `${process.env["HOME"]}/projects/mcp-walkthrough/sandbox`
  ],
  serverName: SERVER_NAME,
  onMessage,
});

process.on("SIGTERM", () => { void logger.close(); });
process.on("SIGINT", () => { void logger.close(); });
