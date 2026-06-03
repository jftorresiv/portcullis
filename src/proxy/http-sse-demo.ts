/**
 * Quick-start demo for the HTTP/SSE proxy.
 *
 * Starts a minimal mock MCP HTTP/SSE server on port 3001, then starts the
 * Portcullis proxy on port 7777 pointing at it. Run from repo root:
 *
 *   npm run build && node dist/proxy/http-sse-demo.js
 *
 * Then in a second terminal:
 *
 *   # 1. Connect to the proxy SSE stream — note the rewritten endpoint URL
 *   curl -sN -H "Accept: text/event-stream" http://127.0.0.1:7777/sse
 *
 *   # 2. POST a JSON-RPC message to the endpoint URL printed above
 *   curl -s -X POST -H "Content-Type: application/json" \
 *     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
 *     http://127.0.0.1:7777/message/<session-id>
 */

import * as http from "node:http";
import { startHttpSseProxy } from "./http-sse-proxy.js";
import type { InterceptedMessage } from "../types/mcp.js";

const MOCK_PORT = 3001;
const PROXY_PORT = 7777;

// ---------------------------------------------------------------------------
// Minimal mock MCP HTTP/SSE upstream
// ---------------------------------------------------------------------------

const mockResponses: Record<string, unknown> = {
  "tools/list": {
    jsonrpc: "2.0",
    id: null,
    result: {
      tools: [
        { name: "echo", description: "Echoes its input back", inputSchema: {} },
      ],
    },
  },
  "tools/call": {
    jsonrpc: "2.0",
    id: null,
    result: { content: [{ type: "text", text: "pong from mock server" }] },
  },
};

// Track open SSE responses so we can push notifications back.
const sseClients = new Set<http.ServerResponse>();

const mockUpstream = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/sse") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
    sseClients.add(res);
    // Send the endpoint event so the client knows where to POST.
    const postEndpoint = `http://127.0.0.1:${MOCK_PORT}/message`;
    res.write(`event: endpoint\ndata: ${postEndpoint}\n\n`);
    res.on("close", () => sseClients.delete(res));

  } else if (req.method === "POST" && req.url === "/message") {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      let parsed: { id?: unknown; method?: string } = {};
      try { parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as typeof parsed; }
      catch { /* ignore */ }

      // Acknowledge the POST immediately (MCP servers typically return 202).
      res.writeHead(202, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "accepted" }));

      // Push the JSON-RPC response back over SSE.
      const method = parsed.method ?? "";
      const template = mockResponses[method] ?? {
        jsonrpc: "2.0",
        id: parsed.id,
        error: { code: -32601, message: `Method not found: ${method}` },
      };
      const response = JSON.stringify({ ...template as object, id: parsed.id });
      for (const client of sseClients) {
        client.write(`data: ${response}\n\n`);
      }
    });

  } else {
    res.writeHead(404);
    res.end();
  }
});

mockUpstream.listen(MOCK_PORT, "127.0.0.1", () => {
  process.stderr.write(`[mock-upstream] Listening on http://127.0.0.1:${MOCK_PORT}\n`);
  startProxy();
});

// ---------------------------------------------------------------------------
// Start the Portcullis HTTP/SSE proxy
// ---------------------------------------------------------------------------

function onMessage(msg: InterceptedMessage): void {
  const preview = JSON.stringify(msg.parsed).slice(0, 160);
  process.stderr.write(
    `[portcullis] ${msg.timestamp} ${msg.direction} ${preview}\n`
  );
}

function startProxy(): void {
  startHttpSseProxy({
    upstreamUrl: `http://127.0.0.1:${MOCK_PORT}`,
    listenPort: PROXY_PORT,
    serverName: "mock-upstream",
    onMessage,
  });
}
