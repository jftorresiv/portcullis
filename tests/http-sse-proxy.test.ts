import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import { SseParser, startHttpSseProxy } from "../src/proxy/http-sse-proxy.js";
import type { InterceptedMessage } from "../src/types/mcp.js";

// ---------------------------------------------------------------------------
// SseParser unit tests
// ---------------------------------------------------------------------------

describe("SseParser", () => {
  it("emits a message event for a simple data line", (_, done) => {
    const parser = new SseParser();
    parser.on("message", (data: string) => {
      assert.equal(data, '{"jsonrpc":"2.0","method":"ping"}');
      done();
    });
    parser.feed('data: {"jsonrpc":"2.0","method":"ping"}\n\n');
  });

  it("emits a named event when event: is set", (_, done) => {
    const parser = new SseParser();
    parser.on("endpoint", (data: string) => {
      assert.equal(data, "http://localhost:3001/message");
      done();
    });
    parser.feed("event: endpoint\ndata: http://localhost:3001/message\n\n");
  });

  it("handles CRLF line endings", (_, done) => {
    const parser = new SseParser();
    parser.on("message", (data: string) => {
      assert.equal(data, "hello");
      done();
    });
    parser.feed("data: hello\r\n\r\n");
  });

  it("reassembles events split across multiple feed() calls", (_, done) => {
    const parser = new SseParser();
    parser.on("message", (data: string) => {
      assert.equal(data, '{"id":1}');
      done();
    });
    parser.feed('data: {"id"');
    parser.feed(':1}\n\n');
  });

  it("joins multi-line data fields with newlines", (_, done) => {
    const parser = new SseParser();
    parser.on("message", (data: string) => {
      assert.equal(data, "line1\nline2");
      done();
    });
    parser.feed("data: line1\ndata: line2\n\n");
  });

  it("ignores comment lines", (_, done) => {
    const events: string[] = [];
    const parser = new SseParser();
    parser.on("message", (data: string) => events.push(data));
    parser.feed(": this is a comment\ndata: actual\n\n");
    setImmediate(() => {
      assert.deepEqual(events, ["actual"]);
      done();
    });
  });

  it("does not emit for empty data block", (_, done) => {
    const events: string[] = [];
    const parser = new SseParser();
    parser.on("message", (data: string) => events.push(data));
    parser.feed("\n\n");
    setImmediate(() => {
      assert.deepEqual(events, []);
      done();
    });
  });

  it("resets event type to message after dispatch", (_, done) => {
    const parser = new SseParser();
    const seen: Array<{ type: string; data: string }> = [];
    parser.on("endpoint", (data: string) => seen.push({ type: "endpoint", data }));
    parser.on("message", (data: string) => seen.push({ type: "message", data }));
    parser.feed("event: endpoint\ndata: http://x\n\nevent: endpoint\ndata: http://y\n\n");
    setImmediate(() => {
      assert.equal(seen.length, 2);
      assert.equal(seen[0]?.type, "endpoint");
      assert.equal(seen[1]?.type, "endpoint");
      done();
    });
  });
});

// ---------------------------------------------------------------------------
// Integration tests — spin up a mock upstream MCP server over HTTP/SSE
// ---------------------------------------------------------------------------

function buildMockUpstream(sessionEndpoint: string): http.Server {
  return http.createServer((req, res) => {
    if (req.method === "GET" && req.url === "/sse") {
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      });
      // Immediately send the endpoint event so the client knows where to POST.
      res.write(`event: endpoint\ndata: ${sessionEndpoint}\n\n`);
      // Keep the connection alive; close is driven by the client.
    } else if (req.method === "POST" && req.url === "/message") {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        // Echo back a minimal 202 Accepted — real MCP servers respond via SSE.
        res.writeHead(202, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ accepted: true }));
      });
    } else {
      res.writeHead(404);
      res.end();
    }
  });
}

function getJson(url: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
        catch (e) { reject(e); }
      });
      res.on("error", reject);
    }).on("error", reject);
  });
}

function getSseEvents(
  url: string,
  count: number
): Promise<Array<{ type: string; data: string }>> {
  return new Promise((resolve, reject) => {
    const events: Array<{ type: string; data: string }> = [];
    const req = http.get(url, { headers: { Accept: "text/event-stream" } }, (res) => {
      const parser = new SseParser();
      const types = ["endpoint", "message"];
      for (const t of types) {
        parser.on(t, (data: string) => {
          events.push({ type: t, data });
          if (events.length >= count) {
            req.destroy();
            resolve(events);
          }
        });
      }
      res.on("data", (chunk: Buffer) => parser.feed(chunk.toString("utf8")));
      res.on("error", reject);
    });
    req.on("error", (err) => {
      // Destroyed intentionally once we have enough events — ignore that error.
      if ((err as NodeJS.ErrnoException).code !== "ECONNRESET") reject(err);
    });
  });
}

function postJson(url: string, body: unknown): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const parsed = new URL(url);
    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload).toString(),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          try {
            resolve({
              status: res.statusCode ?? 0,
              body: JSON.parse(Buffer.concat(chunks).toString("utf8")),
            });
          } catch (e) { reject(e); }
        });
        res.on("error", reject);
      }
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

describe("startHttpSseProxy (integration)", () => {
  let mockUpstream: http.Server;
  let proxyServer: http.Server;
  const UPSTREAM_PORT = 47820;
  const PROXY_PORT = 47821;

  before(async () => {
    const upstreamPostUrl = `http://127.0.0.1:${UPSTREAM_PORT}/message`;
    mockUpstream = buildMockUpstream(upstreamPostUrl);
    await new Promise<void>((r) => mockUpstream.listen(UPSTREAM_PORT, "127.0.0.1", r));

    proxyServer = startHttpSseProxy({
      upstreamUrl: `http://127.0.0.1:${UPSTREAM_PORT}`,
      listenPort: PROXY_PORT,
      serverName: "mock-upstream",
      onMessage: () => { /* captured per test */ },
    });
    // Wait for proxy to be ready
    await new Promise<void>((r) => proxyServer.once("listening", r));
  });

  after(async () => {
    await new Promise<void>((r) => proxyServer.close(() => r()));
    await new Promise<void>((r) => mockUpstream.close(() => r()));
  });

  it("rewrites the endpoint event URL to the proxy's own address", async () => {
    const events = await getSseEvents(`http://127.0.0.1:${PROXY_PORT}/sse`, 1);
    const endpointEvent = events.find((e) => e.type === "endpoint");
    assert.ok(endpointEvent, "should receive an endpoint event");
    assert.match(
      endpointEvent.data,
      new RegExp(`http://127\\.0\\.0\\.1:${PROXY_PORT}/message/`)
    );
    // Must NOT expose the upstream port to the client.
    assert.doesNotMatch(endpointEvent.data, new RegExp(String(UPSTREAM_PORT)));
  });

  it("returns 404 for unknown paths", async () => {
    const result = await new Promise<number>((resolve, reject) => {
      http
        .get(`http://127.0.0.1:${PROXY_PORT}/unknown`, (res) => resolve(res.statusCode ?? 0))
        .on("error", reject);
    });
    assert.equal(result, 404);
  });

  it("intercepts client→server messages and calls onMessage", async () => {
    const captured: InterceptedMessage[] = [];

    // Restart proxy with a capturing onMessage for this test.
    const capturingProxy = startHttpSseProxy({
      upstreamUrl: `http://127.0.0.1:${UPSTREAM_PORT}`,
      listenPort: 47822,
      serverName: "mock-upstream",
      onMessage: (msg) => captured.push(msg),
    });
    await new Promise<void>((r) => capturingProxy.once("listening", r));

    // First grab the rewritten endpoint URL from the SSE stream.
    const events = await getSseEvents(`http://127.0.0.1:47822/sse`, 1);
    const endpointEvent = events.find((e) => e.type === "endpoint");
    assert.ok(endpointEvent);

    const rpc = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };
    await postJson(endpointEvent.data, rpc);

    assert.equal(captured.length, 1);
    assert.equal(captured[0]?.direction, "client->server");
    const parsed = captured[0]?.parsed as { method?: string };
    assert.equal(parsed.method, "tools/list");

    await new Promise<void>((r) => capturingProxy.close(() => r()));
  });

  it("forwards POST to upstream and streams response without buffering", async () => {
    // Capture the endpoint from the proxy SSE stream.
    const events = await getSseEvents(`http://127.0.0.1:${PROXY_PORT}/sse`, 1);
    const endpointEvent = events.find((e) => e.type === "endpoint");
    assert.ok(endpointEvent);

    const rpc = { jsonrpc: "2.0", id: 2, method: "tools/call" };
    const result = await postJson(endpointEvent.data, rpc);

    // Mock upstream returns 202 Accepted.
    assert.equal(result.status, 202);
    assert.deepEqual(result.body, { accepted: true });
  });

  it("returns 502 when upstream SSE is unavailable", async () => {
    const deadProxy = startHttpSseProxy({
      upstreamUrl: "http://127.0.0.1:47899",  // nothing listening here
      listenPort: 47823,
      serverName: "dead-upstream",
      onMessage: () => {},
    });
    await new Promise<void>((r) => deadProxy.once("listening", r));

    const status = await new Promise<number>((resolve, reject) => {
      http
        .get(
          `http://127.0.0.1:47823/sse`,
          { headers: { Accept: "text/event-stream" } },
          (res) => resolve(res.statusCode ?? 0)
        )
        .on("error", reject);
    });

    assert.equal(status, 502);
    await new Promise<void>((r) => deadProxy.close(() => r()));
  });
});
