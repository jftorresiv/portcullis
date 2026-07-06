import * as fs from "node:fs";
import * as path from "node:path";
import * as readline from "node:readline";
import { fileURLToPath } from "node:url";
import { startProxy } from "./proxy.js";
import type { ForwardDecision } from "./proxy.js";
import { Logger } from "../audit/logger.js";
import { loadPolicy } from "../policy/parser.js";
import { PolicyEngine } from "../policy/engine.js";
import type { PolicyDecision } from "../policy/engine.js";
import { CapabilityRegistry } from "../capabilities/registry.js";
import { init as initTagger, tagTool } from "../capabilities/tagger.js";
import { TrifectaTracker } from "../detection/trifecta.js";
import { TaintTracker } from "../detection/taint.js";
import { ServerRegistry } from "../detection/server-registry.js";
import { InjectionScanner } from "../scanner/injection.js";
import type { ScanResult } from "../scanner/injection.js";
import type { InterceptedMessage, Tool, ToolCallEvent } from "../types/mcp.js";

const LOG_PATH = process.env["PORTCULLIS_AUDIT_LOG"] ?? "~/.portcullis/audit.jsonl";
const SERVER_NAME = "filesystem";

const logger = new Logger(LOG_PATH);

const policyPath =
  process.env["PORTCULLIS_POLICY"] ??
  path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "../../policies/default.yaml"
  );

let engine: PolicyEngine | null = null;

try {
  // loadPolicy still owns the `tools` block for the tagger; the engine owns
  // only the `rules` block and validates it itself via load().
  const policy = loadPolicy(policyPath);
  initTagger(new CapabilityRegistry(policy.tools));
  engine = new PolicyEngine();
  engine.load(policyPath);
} catch (err) {
  process.stderr.write(`[portcullis] Failed to load policy: ${err}\n`);
  process.stderr.write("[portcullis] Running in log-only mode (no enforcement)\n");
}

const tracker = new TrifectaTracker();
const taintTracker = new TaintTracker();

// Persistent registry of servers seen on previous runs (issue #28). A server is
// "new" only the first time it is ever encountered; the on-disk file carries
// that fact across processes. `sessionNewServers` remembers which servers were
// new at tools/list time this run so the tool-call event can reflect it even
// after the server has already been marked seen.
const serverRegistry = new ServerRegistry();
serverRegistry.load("~/.portcullis/known-servers.json");
const sessionNewServers = new Set<string>();

// Injection scanner + its result cache. The cache is keyed by tool name and is
// fully replaced on each tools/list response so a re-advertised tool can never
// retain stale findings. Looked up at tool-call time to enrich the policy event.
const scanner = new InjectionScanner();
const scanCache = new Map<string, ScanResult[]>();

// Extracts the tools array from a server→client tools/list response. Responses
// carry no `method`, so detection is structural: parsed.result.tools is an
// array. Returns null for anything else.
function extractToolsList(msg: InterceptedMessage): Tool[] | null {
  if (msg.direction !== "server->client") return null;
  const parsed = msg.parsed as unknown as Record<string, unknown>;
  const result = parsed["result"];
  if (result === null || typeof result !== "object") return null;
  const tools = (result as Record<string, unknown>)["tools"];
  if (!Array.isArray(tools)) return null;
  return tools.filter(
    (t): t is Tool =>
      t !== null && typeof t === "object" && typeof (t as Tool).name === "string"
  );
}

function extractMethod(msg: InterceptedMessage): string {
  return "method" in msg.parsed ? (msg.parsed.method as string) : "(response)";
}

function extractToolCall(
  msg: InterceptedMessage
): { toolName: string; args: unknown } | null {
  const parsed = msg.parsed as unknown as Record<string, unknown>;
  if (parsed["method"] !== "tools/call") return null;
  const params = parsed["params"];
  if (params === null || typeof params !== "object") return null;
  const p = params as Record<string, unknown>;
  const name = typeof p["name"] === "string" ? p["name"] : null;
  if (!name) return null;
  return { toolName: name, args: p["arguments"] ?? {} };
}

function buildSyntheticError(
  msg: InterceptedMessage,
  decision: PolicyDecision
): string {
  const id =
    "id" in msg.parsed
      ? (msg.parsed.id as string | number)
      : 0;
  const ruleLabel = decision.matchedRule?.name ?? "policy";
  const errorMsg = `Blocked by Portcullis policy: ${ruleLabel}`;
  return JSON.stringify({
    jsonrpc: "2.0",
    id,
    error: { code: -32000, message: errorMsg },
  });
}

async function promptConfirm(decision: PolicyDecision): Promise<boolean> {
  const rule = decision.matchedRule?.name ?? "unknown rule";
  const detail = decision.matchedRule?.message?.trim() ?? "";
  process.stderr.write(
    `\n[portcullis] CONFIRM REQUIRED\nRule: "${rule}"\n${detail ? detail + "\n" : ""}Allow? [y/N]: `
  );

  return new Promise<boolean>((resolve) => {
    let ttyFd: number;
    try {
      ttyFd = fs.openSync("/dev/tty", "r+");
    } catch {
      process.stderr.write("\n[portcullis] Cannot open /dev/tty — blocking by default\n");
      resolve(false);
      return;
    }

    const rl = readline.createInterface({
      input: fs.createReadStream("", { fd: ttyFd, autoClose: false }),
      output: process.stderr,
      terminal: false,
    });

    rl.once("line", (line) => {
      rl.close();
      try { fs.closeSync(ttyFd); } catch { /* ignore */ }
      resolve(line.trim().toLowerCase() === "y");
    });

    rl.once("close", () => {
      try { fs.closeSync(ttyFd); } catch { /* ignore */ }
      resolve(false);
    });
  });
}

async function onMessage(msg: InterceptedMessage): Promise<ForwardDecision> {
  process.stderr.write(
    `[portcullis] ${msg.timestamp} ${msg.direction} ${JSON.stringify(msg.parsed).slice(0, 120)}\n`
  );

  // Scan tools/list advertisements server→client. Repopulate the cache and emit
  // an alert (JSONL-first, then stderr) for every warn/critical finding.
  const toolsList = extractToolsList(msg);
  if (toolsList !== null) {
    // First sighting of this server? Record it (JSONL-first, then stderr) and
    // remember it as new for this session so tool-call events can carry the
    // flag even after markSeen has run.
    if (serverRegistry.isNew(msg.server)) {
      serverRegistry.markSeen(msg.server);
      serverRegistry.save();
      sessionNewServers.add(msg.server);
      logger.append({
        timestamp: new Date().toISOString(),
        session_id: msg.sessionId,
        direction: "server_to_client",
        server: msg.server,
        method: "tools/list",
        message: {
          alert: "new_server_seen",
          server: msg.server,
        },
        type: "new_server_seen",
      }).catch((err: unknown) => {
        process.stderr.write(`[portcullis] audit log write failed: ${err}\n`);
      });
      process.stderr.write(
        `[portcullis] [NEW SERVER] first time seeing server "${msg.server}"\n`
      );
    }

    const findings = scanner.scan(toolsList);
    scanCache.clear();
    for (const f of findings) {
      const existing = scanCache.get(f.toolName);
      if (existing) existing.push(f);
      else scanCache.set(f.toolName, [f]);
    }

    for (const f of findings) {
      if (f.severity !== "warn" && f.severity !== "critical") continue;
      logger.append({
        timestamp: new Date().toISOString(),
        session_id: msg.sessionId,
        direction: "server_to_client",
        server: msg.server,
        method: "tools/list",
        message: {
          alert: "injection_scan_alert",
          toolName: f.toolName,
          field: f.field,
          pattern: f.pattern,
          severity: f.severity,
        },
        type: "injection_scan_alert",
      }).catch((err: unknown) => {
        process.stderr.write(`[portcullis] audit log write failed: ${err}\n`);
      });
      process.stderr.write(
        `[portcullis] [INJECTION ${f.severity.toUpperCase()}] tool "${f.toolName}" ${f.field}: ${f.pattern}\n`
      );
    }
  }

  const call = msg.direction === "client->server" ? extractToolCall(msg) : null;
  const toolCapabilities =
    call !== null ? tagTool(msg.server, call.toolName) : undefined;

  // Observe capabilities and detect trifecta. Run for every client→server
  // tools/call so the tracker stays current even for non-enforced calls.
  if (call !== null) {
    const state = tracker.observe(toolCapabilities ?? []);

    if (state.justTriggered) {
      process.stderr.write(
        `[portcullis] [ALERT] Lethal trifecta detected in session ${msg.sessionId}\n`
      );
      logger.append({
        timestamp: new Date().toISOString(),
        session_id: msg.sessionId,
        direction: "client_to_server",
        server: msg.server,
        method: "tools/call",
        message: {
          alert: "lethal_trifecta",
          triggeredBy: call.toolName,
          sessionCapabilities: [...state.capabilities],
        },
        type: "trifecta_alert",
        capabilities: [...state.capabilities],
      }).catch((err: unknown) => {
        process.stderr.write(`[portcullis] audit log write failed: ${err}\n`);
      });
    }

    // Observe taint. Capture the pre-observe state so the session_tainted
    // audit event fires exactly once, on the false→true transition.
    const taintEvent: ToolCallEvent = {
      tool: call.toolName,
      server: msg.server,
      capabilities: toolCapabilities ?? [],
    };
    const wasTainted = taintTracker.isTainted();
    taintTracker.observe(taintEvent);
    if (!wasTainted && taintTracker.isTainted()) {
      process.stderr.write(
        `[portcullis] [ALERT] Session ${msg.sessionId} tainted by ${call.toolName}\n`
      );
      logger.append({
        timestamp: new Date().toISOString(),
        session_id: msg.sessionId,
        direction: "client_to_server",
        server: msg.server,
        method: "tools/call",
        message: {
          alert: "session_tainted",
          triggeredBy: call.toolName,
        },
        type: "session_tainted",
        ...(toolCapabilities !== undefined ? { capabilities: toolCapabilities } : {}),
      }).catch((err: unknown) => {
        process.stderr.write(`[portcullis] audit log write failed: ${err}\n`);
      });
    }
  }

  logger.append({
    timestamp: msg.timestamp,
    session_id: msg.sessionId,
    direction: msg.direction === "client->server" ? "client_to_server" : "server_to_client",
    server: msg.server,
    method: extractMethod(msg),
    message: msg.parsed as unknown as Record<string, unknown>,
    ...(toolCapabilities !== undefined ? { capabilities: toolCapabilities } : {}),
  }).catch((err: unknown) => {
    process.stderr.write(`[portcullis] audit log write failed: ${err}\n`);
  });

  // Only enforce on client→server tools/call messages.
  if (call === null || engine === null) {
    return { forward: true };
  }

  // Enrich with cached injection findings for this tool. Only warn+critical
  // pattern keys reach the policy engine; 'info' findings are excluded.
  const cached = scanCache.get(call.toolName) ?? [];
  const descriptionFindings = [
    ...new Set(
      cached
        .filter((f) => f.severity === "warn" || f.severity === "critical")
        .map((f) => f.pattern)
    ),
  ];

  const event: ToolCallEvent = {
    tool: call.toolName,
    server: msg.server,
    capabilities: toolCapabilities ?? [],
    sessionTrifecta: tracker.isTriggered(),
    sessionTainted: taintTracker.isTainted(),
    ...(descriptionFindings.length > 0 ? { descriptionFindings } : {}),
    // Pass the call arguments through so the engine's `arguments_match`
    // condition can scan them. extractToolCall already defaults this to {}.
    arguments: call.args,
    // True if this server was seen for the first time at tools/list time this
    // session (issue #28). By tool-call time it is already marked seen, so the
    // per-session set is the source of truth, not registry.isNew().
    serverIsNew: sessionNewServers.has(msg.server),
  };

  const decision = engine.evaluate(event);

  if (decision.action === "allow") {
    return { forward: true };
  }

  if (decision.action === "warn") {
    process.stderr.write(
      `[portcullis] WARN — rule "${decision.matchedRule?.name ?? "unknown"}": ${decision.matchedRule?.message?.trim() ?? ""}\n`
    );
    logger.append({
      timestamp: msg.timestamp,
      session_id: msg.sessionId,
      direction: "client_to_server",
      server: msg.server,
      method: "tools/call",
      message: msg.parsed as unknown as Record<string, unknown>,
      decision: "warned",
      ...(toolCapabilities !== undefined ? { capabilities: toolCapabilities } : {}),
    }).catch((err: unknown) => {
      process.stderr.write(`[portcullis] audit log write failed: ${err}\n`);
    });
    return { forward: true };
  }

  if (decision.action === "confirm") {
    const allowed = await promptConfirm(decision);
    const auditDecision = allowed ? "confirmed" : "blocked";
    logger.append({
      timestamp: new Date().toISOString(),
      session_id: msg.sessionId,
      direction: "client_to_server",
      server: msg.server,
      method: "tools/call",
      message: msg.parsed as unknown as Record<string, unknown>,
      decision: auditDecision,
      ...(toolCapabilities !== undefined ? { capabilities: toolCapabilities } : {}),
    }).catch((err: unknown) => {
      process.stderr.write(`[portcullis] audit log write failed: ${err}\n`);
    });
    if (allowed) return { forward: true };
    return { forward: false, syntheticResponse: buildSyntheticError(msg, decision) };
  }

  // action === "block"
  process.stderr.write(
    `[portcullis] BLOCKED — rule "${decision.matchedRule?.name ?? "unknown"}": ${decision.matchedRule?.message?.trim() ?? ""}\n`
  );
  logger.append({
    timestamp: msg.timestamp,
    session_id: msg.sessionId,
    direction: "client_to_server",
    server: msg.server,
    method: "tools/call",
    message: msg.parsed as unknown as Record<string, unknown>,
    decision: "blocked",
    ...(toolCapabilities !== undefined ? { capabilities: toolCapabilities } : {}),
  }).catch((err: unknown) => {
    process.stderr.write(`[portcullis] audit log write failed: ${err}\n`);
  });
  return { forward: false, syntheticResponse: buildSyntheticError(msg, decision) };
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
