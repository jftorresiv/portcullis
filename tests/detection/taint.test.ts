import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { TaintTracker, TAINT_CAPABILITY } from "../../src/detection/taint.js";
import { PolicyEngine } from "../../src/policy/engine.js";
import type { ToolCallEvent } from "../../src/types/mcp.js";

let counter = 0;
function writeTmp(content: string): string {
  const p = path.join(os.tmpdir(), `portcullis-taint-test-${Date.now()}-${counter++}.yaml`);
  fs.writeFileSync(p, content);
  return p;
}

// Loads an engine from inline YAML, cleaning up the tmp file afterward.
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
    ...over,
  };
}

// The warn-on-tainted-exfiltration rule mirrors the default.yaml policy.
const TAINT_EXFIL_POLICY =
  `rules:\n` +
  `  - name: "Taint + exfiltration risk"\n` +
  `    when:\n` +
  `      session_tainted: true\n` +
  `      capabilities:\n` +
  `        any: [can_exfiltrate]\n` +
  `    action: warn\n`;

describe("TaintTracker", () => {
  it("starts untainted", () => {
    const tracker = new TaintTracker();
    assert.equal(tracker.isTainted(), false);
  });

  it("taints on a call that sees untrusted content", () => {
    const tracker = new TaintTracker();
    tracker.observe(event({ capabilities: [TAINT_CAPABILITY] }));
    assert.equal(tracker.isTainted(), true);
  });

  it("does not taint on calls without untrusted content", () => {
    const tracker = new TaintTracker();
    tracker.observe(event({ capabilities: ["reads_private_data"] }));
    tracker.observe(event({ capabilities: ["can_exfiltrate"] }));
    assert.equal(tracker.isTainted(), false);
  });

  it("taint is sticky: never clears once set", () => {
    const tracker = new TaintTracker();
    tracker.observe(event({ capabilities: [TAINT_CAPABILITY] }));
    assert.equal(tracker.isTainted(), true);
    // Subsequent benign calls must not clear it.
    tracker.observe(event({ capabilities: [] }));
    tracker.observe(event({ capabilities: ["reads_private_data"] }));
    assert.equal(tracker.isTainted(), true);
  });
});

describe("TaintTracker + PolicyEngine integration", () => {
  it("taint then exfiltrate: warn fires", () => {
    const tracker = new TaintTracker();
    const engine = engineFrom(TAINT_EXFIL_POLICY);

    // Untrusted content enters the session.
    tracker.observe(event({ capabilities: [TAINT_CAPABILITY] }));

    // A later exfiltration-capable call is evaluated against the taint flag.
    const decision = engine.evaluate(
      event({
        tool: "send_message",
        server: "gmail",
        capabilities: ["can_exfiltrate"],
        sessionTainted: tracker.isTainted(),
      })
    );
    assert.equal(decision.action, "warn");
    assert.equal(decision.matchedRule?.name, "Taint + exfiltration risk");
  });

  it("exfiltrate before taint: no warn", () => {
    const tracker = new TaintTracker();
    const engine = engineFrom(TAINT_EXFIL_POLICY);

    // Exfiltration happens before any untrusted content is seen.
    const decision = engine.evaluate(
      event({
        tool: "send_message",
        server: "gmail",
        capabilities: ["can_exfiltrate"],
        sessionTainted: tracker.isTainted(),
      })
    );
    assert.equal(decision.action, "allow");
    assert.equal(decision.matchedRule, undefined);
  });

  it("taint-only, no exfiltration: allow", () => {
    const tracker = new TaintTracker();
    const engine = engineFrom(TAINT_EXFIL_POLICY);

    // Untrusted content enters, but the next call cannot exfiltrate.
    tracker.observe(event({ capabilities: [TAINT_CAPABILITY] }));

    const decision = engine.evaluate(
      event({
        tool: "read_file",
        server: "filesystem",
        capabilities: ["reads_private_data"],
        sessionTainted: tracker.isTainted(),
      })
    );
    assert.equal(decision.action, "allow");
    assert.equal(decision.matchedRule, undefined);
  });
});
