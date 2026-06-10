import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { startProxy } from "./proxy.js";
import { Logger } from "../audit/logger.js";
import { loadPolicy } from "../policy/parser.js";
import { CapabilityRegistry } from "../capabilities/registry.js";
import { init as initTagger, tagTool } from "../capabilities/tagger.js";
import type { InterceptedMessage } from "../types/mcp.js";

const LOG_PATH = process.env["PORTCULLIS_AUDIT_LOG"] ?? "~/.portcullis/audit.jsonl";
const SERVER_NAME = "filesystem";

const logger = new Logger(LOG_PATH);

const policyPath =
  process.env["PORTCULLIS_POLICY"] ??
  path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "../../policies/default.yaml"
  );

try {
  const policy = loadPolicy(policyPath);
  initTagger(new CapabilityRegistry(policy.tools));
} catch (err) {
  process.stderr.write(`[portcullis] Failed to load policy: ${err}\n`);
  process.stderr.write("[portcullis] Capability tagging disabled\n");
}

function extractMethod(msg: InterceptedMessage): string {
  return "method" in msg.parsed ? (msg.parsed.method as string) : "(response)";
}

function extractToolName(msg: InterceptedMessage): string | null {
  const parsed = msg.parsed as unknown as Record<string, unknown>;
  if (parsed["method"] !== "tools/call") return null;
  const params = parsed["params"];
  if (params === null || typeof params !== "object") return null;
  const name = (params as Record<string, unknown>)["name"];
  return typeof name === "string" ? name : null;
}

function onMessage(msg: InterceptedMessage): void {
  process.stderr.write(
    `[portcullis] ${msg.timestamp} ${msg.direction} ${JSON.stringify(msg.parsed).slice(0, 120)}\n`
  );

  const toolName = extractToolName(msg);
  const capabilities = toolName !== null ? tagTool(msg.server, toolName) : undefined;

  logger.append({
    timestamp: msg.timestamp,
    session_id: msg.sessionId,
    direction: msg.direction === "client->server" ? "client_to_server" : "server_to_client",
    server: msg.server,
    method: extractMethod(msg),
    message: msg.parsed as unknown as Record<string, unknown>,
    ...(capabilities !== undefined ? { capabilities } : {}),
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
