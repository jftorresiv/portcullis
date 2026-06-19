import { describe, it, before, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { Logger, AuditEventSchema } from "../../src/audit/logger.js";
import type { AuditEvent } from "../../src/audit/logger.js";
import { Store } from "../../src/audit/store.js";

function tmpLog(): string {
  return path.join(os.tmpdir(), `portcullis-test-${randomUUID()}.jsonl`);
}

function makeEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    timestamp: new Date().toISOString(),
    session_id: randomUUID(),
    direction: "client_to_server",
    server: "test-server",
    method: "tools/list",
    message: { jsonrpc: "2.0", id: 1, method: "tools/list" },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

describe("AuditEventSchema", () => {
  it("accepts a valid event", () => {
    assert.doesNotThrow(() => AuditEventSchema.parse(makeEvent()));
  });

  it("accepts an event with a decision field", () => {
    assert.doesNotThrow(() =>
      AuditEventSchema.parse(makeEvent({ decision: "allowed" }))
    );
  });

  it("rejects a non-ISO8601 timestamp", () => {
    assert.throws(() =>
      AuditEventSchema.parse(makeEvent({ timestamp: "not-a-date" }))
    );
  });

  it("rejects an invalid UUID for session_id", () => {
    assert.throws(() =>
      AuditEventSchema.parse(makeEvent({ session_id: "bad-uuid" }))
    );
  });

  it("rejects an invalid direction value", () => {
    assert.throws(() =>
      AuditEventSchema.parse(
        makeEvent({ direction: "outbound" as AuditEvent["direction"] })
      )
    );
  });

  it("rejects an empty server name", () => {
    assert.throws(() => AuditEventSchema.parse(makeEvent({ server: "" })));
  });

  it("rejects an invalid decision value", () => {
    assert.throws(() =>
      AuditEventSchema.parse(
        makeEvent({ decision: "maybe" as AuditEvent["decision"] })
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Logger behaviour
// ---------------------------------------------------------------------------

describe("Logger", () => {
  let logPath: string;
  let logger: Logger;

  before(async () => {
    logPath = tmpLog();
    logger = new Logger(logPath);
  });

  after(async () => {
    await logger.close();
    fs.rmSync(logPath, { force: true });
  });

  it("creates the log file on first write", async () => {
    await logger.append(makeEvent());
    assert.ok(fs.existsSync(logPath));
  });

  it("writes one valid JSON object per line", async () => {
    const event = makeEvent({ method: "tools/call" });
    await logger.append(event);

    const lines = fs.readFileSync(logPath, "utf8").trim().split("\n");
    for (const line of lines) {
      assert.doesNotThrow(() => JSON.parse(line), `Line is not valid JSON: ${line}`);
    }
  });

  it("file grows with each append (no rotation or truncation)", async () => {
    const sizeBefore = fs.statSync(logPath).size;
    await logger.append(makeEvent({ method: "ping" }));
    const sizeAfter = fs.statSync(logPath).size;
    assert.ok(sizeAfter > sizeBefore, "file should grow after each append");
  });

  it("rejects a malformed event without writing anything", async () => {
    const sizeBefore = fs.statSync(logPath).size;
    await assert.rejects(() =>
      logger.append(makeEvent({ timestamp: "invalid" }))
    );
    const sizeAfter = fs.statSync(logPath).size;
    assert.equal(sizeAfter, sizeBefore, "file must not grow on rejected event");
  });

  it("concurrent appends produce one complete JSON object per line", async () => {
    const concurrentLog = tmpLog();
    const concurrent = new Logger(concurrentLog);

    const events = Array.from({ length: 20 }, (_, i) =>
      makeEvent({ method: `method-${i}` })
    );

    await Promise.all(events.map((e) => concurrent.append(e)));
    await concurrent.close();

    const lines = fs.readFileSync(concurrentLog, "utf8").trim().split("\n");
    assert.equal(lines.length, 20, "should have exactly 20 lines");
    for (const line of lines) {
      assert.doesNotThrow(
        () => JSON.parse(line),
        `Interleaved write produced invalid JSON: ${line}`
      );
    }
    fs.rmSync(concurrentLog, { force: true });
  });

  it("creates parent directories if they do not exist", async () => {
    const nestedPath = path.join(
      os.tmpdir(),
      `portcullis-nested-${randomUUID()}`,
      "sub",
      "audit.jsonl"
    );
    const nested = new Logger(nestedPath);
    assert.ok(fs.existsSync(path.dirname(nestedPath)));
    await nested.close();
    fs.rmSync(path.dirname(path.dirname(nestedPath)), {
      recursive: true,
      force: true,
    });
  });

  it("expands leading ~ in the log path", async () => {
    const tildeLog = path.join(
      "~",
      `.portcullis-test-${randomUUID()}`,
      "audit.jsonl"
    );
    const resolved = path.join(os.homedir(), tildeLog.slice(1));
    const tilde = new Logger(tildeLog);
    assert.ok(fs.existsSync(path.dirname(resolved)));
    await tilde.close();
    fs.rmSync(path.dirname(resolved), { recursive: true, force: true });
  });
});

// ---------------------------------------------------------------------------
// Logger + Store integration
// ---------------------------------------------------------------------------

describe("Logger + Store", () => {
  it("happy path: append writes to both JSONL and SQLite", async () => {
    const logPath = path.join(
      os.tmpdir(),
      `portcullis-store-test-${randomUUID()}.jsonl`
    );
    const store = new Store(":memory:");
    const logger = new Logger(logPath, store);

    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      session_id: randomUUID(),
      direction: "client_to_server",
      server: "test-server",
      method: "tools/call",
      message: { jsonrpc: "2.0", id: 1, method: "tools/call" },
      decision: "allowed",
    };

    await logger.append(event);
    await logger.close();

    // JSONL side
    const lines = fs.readFileSync(logPath, "utf8").trim().split("\n");
    assert.equal(lines.length, 1);
    const parsed = JSON.parse(lines[0] ?? "{}") as unknown;
    assert.doesNotThrow(() => AuditEventSchema.parse(parsed));

    // SQLite side
    const rows = store.query();
    assert.equal(rows.length, 1);
    const row = rows[0];
    assert.ok(row !== undefined);
    assert.equal(row.session_id, event.session_id);
    assert.equal(row.method, event.method);
    assert.equal(row.decision, "allowed");

    store.close();
    fs.rmSync(logPath, { force: true });
  });

  it("failure path: SQLite insert throws → JSONL still written, no exception escapes, warning logged", async () => {
    const logPath = path.join(
      os.tmpdir(),
      `portcullis-store-fail-${randomUUID()}.jsonl`
    );

    // Minimal mock Store whose insert always throws.
    const mockStore = {
      insert(_event: AuditEvent): void {
        throw new Error("simulated SQLite failure");
      },
    } as unknown as Store;

    const logger = new Logger(logPath, mockStore);

    const warns: string[] = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    (process.stderr as unknown as { write: (chunk: string) => boolean }).write =
      (chunk: string) => {
        warns.push(chunk);
        return true;
      };

    try {
      // Must not throw.
      await assert.doesNotReject(() =>
        logger.append({
          timestamp: new Date().toISOString(),
          session_id: randomUUID(),
          direction: "server_to_client",
          server: "test-server",
          method: "tools/list",
          message: {},
        })
      );
    } finally {
      process.stderr.write = origWrite;
    }

    await logger.close();

    // JSONL must contain the event despite the SQLite failure.
    assert.ok(
      fs.existsSync(logPath) && fs.statSync(logPath).size > 0,
      "JSONL file must be non-empty"
    );

    // A warning must have been emitted to stderr.
    assert.ok(
      warns.some((w) => w.includes("SQLite mirror write failed")),
      "expected SQLite failure warning on stderr"
    );

    fs.rmSync(logPath, { force: true });
  });
});
