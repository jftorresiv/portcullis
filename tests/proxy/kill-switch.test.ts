import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { Logger } from "../../src/audit/logger.js";
import { KillSwitch } from "../../src/proxy/kill-switch.js";
import type { ForwardDecision } from "../../src/proxy/proxy.js";

function tmpLog(): string {
  return path.join(os.tmpdir(), `portcullis-killswitch-test-${randomUUID()}.jsonl`);
}

// Mirrors the guard in src/proxy/index.ts: while frozen, forwarding is
// refused with a synthetic block response; otherwise the call proceeds.
function attemptCall(killSwitch: KillSwitch): ForwardDecision {
  if (killSwitch.isFrozen()) {
    return {
      forward: false,
      syntheticResponse: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        error: { code: -32000, message: "Session frozen by kill switch" },
      }),
    };
  }
  return { forward: true };
}

describe("KillSwitch", () => {
  it("starts unfrozen", () => {
    const killSwitch = new KillSwitch();
    assert.equal(killSwitch.isFrozen(), false);
  });

  it("activate() freezes and reset() unfreezes", () => {
    const killSwitch = new KillSwitch();
    killSwitch.activate();
    assert.equal(killSwitch.isFrozen(), true);
    killSwitch.reset();
    assert.equal(killSwitch.isFrozen(), false);
  });

  it("flips frozen state even before configure() is called", () => {
    const killSwitch = new KillSwitch();
    assert.doesNotThrow(() => killSwitch.activate());
    assert.equal(killSwitch.isFrozen(), true);
  });

  it("freeze, attempt call, verify block response, reset, attempt call, verify forward", () => {
    const killSwitch = new KillSwitch();

    assert.deepEqual(attemptCall(killSwitch), { forward: true });

    killSwitch.activate();
    const blocked = attemptCall(killSwitch);
    assert.equal(blocked.forward, false);
    assert.ok(blocked.syntheticResponse);
    const parsed = JSON.parse(blocked.syntheticResponse ?? "{}") as {
      error?: { message?: string };
    };
    assert.equal(parsed.error?.message, "Session frozen by kill switch");

    killSwitch.reset();
    assert.deepEqual(attemptCall(killSwitch), { forward: true });
  });

  describe("audit logging", () => {
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

    it("logs a kill_switch_activated event on activate()", async () => {
      const killSwitch = new KillSwitch();
      const sessionId = randomUUID();
      killSwitch.configure(logger, { sessionId, server: "filesystem" });

      killSwitch.activate();
      await logger.close();

      const lines = fs.readFileSync(logPath, "utf8").trim().split("\n");
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const event = events.find((e) => e["type"] === "kill_switch_activated");
      assert.ok(event, "expected a kill_switch_activated event");
      assert.equal(event?.["session_id"], sessionId);
      assert.equal(event?.["server"], "filesystem");
    });

    it("logs a kill_switch_reset event on reset()", async () => {
      const resetLogPath = tmpLog();
      const resetLogger = new Logger(resetLogPath);
      const killSwitch = new KillSwitch();
      const sessionId = randomUUID();
      killSwitch.configure(resetLogger, { sessionId, server: "filesystem" });

      killSwitch.activate();
      killSwitch.reset();
      await resetLogger.close();

      const lines = fs.readFileSync(resetLogPath, "utf8").trim().split("\n");
      const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      const event = events.find((e) => e["type"] === "kill_switch_reset");
      assert.ok(event, "expected a kill_switch_reset event");
      assert.equal(event?.["session_id"], sessionId);

      fs.rmSync(resetLogPath, { force: true });
    });

    it("does not throw when activate()/reset() are called without configure()", () => {
      const killSwitch = new KillSwitch();
      assert.doesNotThrow(() => killSwitch.activate());
      assert.doesNotThrow(() => killSwitch.reset());
    });
  });
});
