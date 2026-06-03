import { describe, it, before, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { Logger, AuditEventSchema } from "../../src/audit/logger.js";
import type { AuditEvent } from "../../src/audit/logger.js";

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
