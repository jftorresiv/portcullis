import * as http from "node:http";
import * as https from "node:https";
import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { URL } from "node:url";
import type { InterceptedMessage, JsonRpcMessage } from "../types/mcp.js";

export interface HttpSseProxyOptions {
  upstreamUrl: string;
  listenPort: number;
  serverName: string;
  onMessage: (msg: InterceptedMessage) => void;
}

// Parses the SSE wire format (RFC 8895) into typed events.
// Exported for unit testing.
export class SseParser extends EventEmitter {
  private buffer = "";
  private eventType = "message";
  private dataLines: string[] = [];

  feed(chunk: string): void {
    this.buffer += chunk;
    const parts = this.buffer.split("\n");
    this.buffer = parts.pop() ?? "";

    for (const line of parts) {
      // Strip optional trailing CR (CRLF line endings)
      const stripped = line.endsWith("\r") ? line.slice(0, -1) : line;
      if (stripped === "") {
        this.dispatch();
      } else if (stripped.startsWith("event:")) {
        this.eventType = stripped.slice(6).trim();
      } else if (stripped.startsWith("data:")) {
        this.dataLines.push(stripped.slice(5).trimStart());
      }
      // Ignore id:, retry:, and comment lines (:)
    }
  }

  private dispatch(): void {
    if (this.dataLines.length === 0) return;
    const data = this.dataLines.join("\n");
    this.emit(this.eventType, data);
    this.eventType = "message";
    this.dataLines = [];
  }
}

function upstream(
  url: URL,
  opts: http.RequestOptions,
  body?: string
): Promise<http.IncomingMessage> {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === "https:" ? https : http;
    const req = lib.request(url, opts, resolve);
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function parseJsonRpc(raw: string): JsonRpcMessage | null {
  try {
    return JSON.parse(raw) as JsonRpcMessage;
  } catch {
    process.stderr.write(`[portcullis] Failed to parse message: ${raw}\n`);
    return null;
  }
}

// Wraps a ServerResponse with a queue + drain loop so SSE writes never block
// or drop messages under backpressure.
function makeSseWriter(res: http.ServerResponse): (data: string) => void {
  let draining = false;
  const queue: string[] = [];

  function flush(): void {
    while (queue.length > 0 && !draining) {
      const chunk = queue.shift();
      if (chunk === undefined) break;
      const ok = res.write(chunk);
      if (!ok) {
        draining = true;
        res.once("drain", () => {
          draining = false;
          flush();
        });
      }
    }
  }

  return (data: string) => {
    queue.push(data);
    if (!draining) flush();
  };
}

// Resolves an endpoint value from the SSE `endpoint` event.
// The MCP spec says data is a full URL, but some servers emit a relative path.
function resolveEndpoint(endpoint: string, base: URL): URL {
  try {
    return new URL(endpoint);
  } catch {
    return new URL(endpoint, base);
  }
}

export function startHttpSseProxy(options: HttpSseProxyOptions): http.Server {
  const upstreamBase = new URL(options.upstreamUrl);
  // Maps session ID → upstream POST endpoint URL for that session.
  const sessions = new Map<string, string>();

  const server = http.createServer((req, res) => {
    const url = req.url ?? "/";
    if (req.method === "GET" && url === "/sse") {
      void handleSse(req, res, upstreamBase, options, sessions);
    } else if (req.method === "POST" && url.startsWith("/message")) {
      void handlePost(req, res, upstreamBase, options, sessions);
    } else {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not Found");
    }
  });

  server.listen(options.listenPort, "127.0.0.1", () => {
    process.stderr.write(
      `[portcullis] HTTP/SSE proxy listening on http://127.0.0.1:${options.listenPort}\n`
    );
  });

  return server;
}

async function handleSse(
  _req: http.IncomingMessage,
  clientRes: http.ServerResponse,
  upstreamBase: URL,
  options: HttpSseProxyOptions,
  sessions: Map<string, string>
): Promise<void> {
  const sessionId = randomUUID();
  const upstreamSseUrl = new URL("/sse", upstreamBase);

  let upstreamRes: http.IncomingMessage;
  try {
    upstreamRes = await upstream(upstreamSseUrl, {
      method: "GET",
      headers: { Accept: "text/event-stream", "Cache-Control": "no-cache" },
    });
  } catch (err) {
    process.stderr.write(`[portcullis] Failed to connect to upstream SSE: ${err}\n`);
    clientRes.writeHead(502);
    clientRes.end();
    return;
  }

  if ((upstreamRes.statusCode ?? 0) !== 200) {
    process.stderr.write(
      `[portcullis] Upstream SSE returned HTTP ${upstreamRes.statusCode}\n`
    );
    clientRes.writeHead(upstreamRes.statusCode ?? 502);
    clientRes.end();
    upstreamRes.destroy();
    return;
  }

  clientRes.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
    // Disable proxy buffering (nginx / caddy)
    "X-Accel-Buffering": "no",
  });

  const write = makeSseWriter(clientRes);
  const parser = new SseParser();

  // Intercept the endpoint event: store upstream URL, rewrite to our local URL.
  parser.on("endpoint", (data: string) => {
    sessions.set(sessionId, data.trim());
    const local = `http://127.0.0.1:${options.listenPort}/message/${sessionId}`;
    write(`event: endpoint\ndata: ${local}\n\n`);
  });

  // Forward all other message events after intercepting for logging.
  parser.on("message", (data: string) => {
    const msg = parseJsonRpc(data);
    if (msg) {
      options.onMessage({
        direction: "server->client",
        raw: data,
        parsed: msg,
        timestamp: new Date().toISOString(),
        sessionId,
        server: options.serverName,
      });
    }
    write(`data: ${data}\n\n`);
  });

  upstreamRes.on("data", (chunk: Buffer) => parser.feed(chunk.toString("utf8")));

  upstreamRes.on("end", () => {
    sessions.delete(sessionId);
    clientRes.end();
  });

  upstreamRes.on("error", (err) => {
    process.stderr.write(`[portcullis] Upstream SSE stream error: ${err}\n`);
    sessions.delete(sessionId);
    clientRes.end();
  });

  // Clean up when client disconnects.
  clientRes.on("close", () => {
    sessions.delete(sessionId);
    upstreamRes.destroy();
  });
}

async function handlePost(
  req: http.IncomingMessage,
  clientRes: http.ServerResponse,
  upstreamBase: URL,
  options: HttpSseProxyOptions,
  sessions: Map<string, string>
): Promise<void> {
  let body: string;
  try {
    body = await readBody(req);
  } catch (err) {
    process.stderr.write(`[portcullis] Failed to read POST body: ${err}\n`);
    clientRes.writeHead(400);
    clientRes.end();
    return;
  }

  // Path is /message/<sessionId>; look up upstream POST endpoint for this session.
  const sessionId = (req.url ?? "").split("/").at(-1) ?? "";

  const msg = parseJsonRpc(body);
  if (msg) {
    options.onMessage({
      direction: "client->server",
      raw: body,
      parsed: msg,
      timestamp: new Date().toISOString(),
      sessionId,
      server: options.serverName,
    });
  }
  const storedEndpoint = sessions.get(sessionId);
  const upstreamPostUrl = storedEndpoint
    ? resolveEndpoint(storedEndpoint, upstreamBase)
    : new URL("/message", upstreamBase);

  let upstreamRes: http.IncomingMessage;
  try {
    upstreamRes = await upstream(
      upstreamPostUrl,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body).toString(),
        },
      },
      body
    );
  } catch (err) {
    process.stderr.write(`[portcullis] Failed to forward POST to upstream: ${err}\n`);
    clientRes.writeHead(502);
    clientRes.end();
    return;
  }

  clientRes.writeHead(upstreamRes.statusCode ?? 200, {
    "Content-Type": upstreamRes.headers["content-type"] ?? "application/json",
  });

  // Stream the upstream response back without buffering.
  upstreamRes.pipe(clientRes);

  upstreamRes.on("error", (err) => {
    process.stderr.write(`[portcullis] Upstream POST response error: ${err}\n`);
    clientRes.end();
  });
}
