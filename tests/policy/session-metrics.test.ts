import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { PolicyEngine } from "../../src/policy/engine.js";
import type { SessionCallRecord, ToolCallEvent } from "../../src/types/mcp.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_POLICY = path.resolve(__dirname, "../../../policies/default.yaml");

let counter = 0;
function writeTmp(content: string): string {
  const p = path.join(
    os.tmpdir(),
    `portcullis-session-metrics-test-${Date.now()}-${counter++}.yaml`
  );
  fs.writeFileSync(p, content);
  return p;
}

function engineFrom(yaml: string): PolicyEngine {
  const tmp = writeTmp(yaml);
  try {
    const engine = new PolicyEngine();
    engine.load(tmp);
    return engine;
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

function event(over: Partial<ToolCallEvent> = {}): ToolCallEvent {
  return {
    tool: "read_file",
    server: "filesystem",
    capabilities: [],
    sessionTrifecta: false,
    ...over,
  };
}

// Builds `n` history records at `agoSeconds` before now, each carrying `caps`.
function records(
  n: number,
  agoSeconds: number,
  caps: string[]
): SessionCallRecord[] {
  const ts = Date.now() - agoSeconds * 1000;
  return Array.from({ length: n }, () => ({ timestamp: ts, capabilities: [...caps] }));
}

// A rule that confirms when >= 3 reads_private_data calls land in a 60s window.
const bulkReadRule =
  `rules:\n` +
  `  - name: bulk-read\n` +
  `    when:\n` +
  `      session_metrics:\n` +
  `        tool_calls_with_capability:\n` +
  `          capability: reads_private_data\n` +
  `          count_in_window: 3\n` +
  `          window_seconds: 60\n` +
  `    action: confirm\n`;

describe("PolicyEngine session_metrics", () => {
  it("fires when the count meets the threshold within the window", () => {
    const engine = engineFrom(bulkReadRule);
    const decision = engine.evaluate(
      event({ sessionCallHistory: records(3, 10, ["reads_private_data"]) })
    );
    assert.equal(decision.action, "confirm");
    assert.equal(decision.matchedRule?.name, "bulk-read");
  });

  it("does not fire when the count is below the threshold", () => {
    const engine = engineFrom(bulkReadRule);
    const decision = engine.evaluate(
      event({ sessionCallHistory: records(2, 10, ["reads_private_data"]) })
    );
    assert.equal(decision.action, "allow");
    assert.equal(decision.matchedRule, undefined);
  });

  it("does not fire when the calls are older than the window", () => {
    const engine = engineFrom(bulkReadRule);
    // Enough calls, but all 90s ago — outside the 60s window.
    const decision = engine.evaluate(
      event({ sessionCallHistory: records(5, 90, ["reads_private_data"]) })
    );
    assert.equal(decision.action, "allow");
    assert.equal(decision.matchedRule, undefined);
  });

  it("does not fire when the capability does not match", () => {
    const engine = engineFrom(bulkReadRule);
    const decision = engine.evaluate(
      event({ sessionCallHistory: records(5, 10, ["can_exfiltrate"]) })
    );
    assert.equal(decision.action, "allow");
    assert.equal(decision.matchedRule, undefined);
  });

  it("does not fire when sessionCallHistory is absent", () => {
    const engine = engineFrom(bulkReadRule);
    // event() sets no sessionCallHistory; the engine treats it as empty.
    const decision = engine.evaluate(event());
    assert.equal(decision.action, "allow");
    assert.equal(decision.matchedRule, undefined);
  });

  it("does not fire when sessionCallHistory is empty", () => {
    const engine = engineFrom(bulkReadRule);
    const decision = engine.evaluate(event({ sessionCallHistory: [] }));
    assert.equal(decision.action, "allow");
    assert.equal(decision.matchedRule, undefined);
  });

  it("counts only in-window records in a mixed history", () => {
    const engine = engineFrom(bulkReadRule);
    // 2 recent (in-window) + 5 old (out-of-window) reads => only 2 count,
    // which is below the threshold of 3 => no fire.
    const mixed = [
      ...records(2, 10, ["reads_private_data"]),
      ...records(5, 120, ["reads_private_data"]),
    ];
    assert.equal(engine.evaluate(event({ sessionCallHistory: mixed })).action, "allow");

    // Bumping the in-window count to 3 crosses the threshold => fire.
    const enough = [
      ...records(3, 10, ["reads_private_data"]),
      ...records(5, 120, ["reads_private_data"]),
    ];
    assert.equal(
      engine.evaluate(event({ sessionCallHistory: enough })).action,
      "confirm"
    );
  });

  it("counts a record carrying the capability among several tags", () => {
    const engine = engineFrom(bulkReadRule);
    const decision = engine.evaluate(
      event({
        sessionCallHistory: records(3, 5, ["reads_private_data", "sees_untrusted_content"]),
      })
    );
    assert.equal(decision.action, "confirm");
  });
});

describe("default.yaml Bulk read detection", () => {
  it("loads the real default.yaml (with the enabled rule) without error", () => {
    const engine = new PolicyEngine();
    assert.doesNotThrow(() => engine.load(DEFAULT_POLICY));
  });

  it("confirms once 20 reads_private_data calls land within 60s", () => {
    const engine = new PolicyEngine();
    engine.load(DEFAULT_POLICY);
    const decision = engine.evaluate(
      event({ sessionCallHistory: records(20, 30, ["reads_private_data"]) })
    );
    assert.equal(decision.action, "confirm");
    assert.match(decision.matchedRule?.name ?? "", /Bulk read/);
  });

  it("does not fire below the 20-call threshold", () => {
    const engine = new PolicyEngine();
    engine.load(DEFAULT_POLICY);
    const decision = engine.evaluate(
      event({ sessionCallHistory: records(19, 30, ["reads_private_data"]) })
    );
    // No other default rule matches a plain filesystem read => default allow.
    assert.equal(decision.action, "allow");
  });
});
