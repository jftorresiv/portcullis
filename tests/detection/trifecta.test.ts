import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { TrifectaTracker, TRIFECTA_LEGS } from "../../src/detection/trifecta.js";
import { PolicyEngine } from "../../src/policy/engine.js";
import type { ToolCallContext } from "../../src/policy/engine.js";
import type { Policy } from "../../src/policy/parser.js";

function makePolicy(rules: Policy["rules"]): Policy {
  return {
    version: 1,
    name: "test",
    capabilities: ["reads_private_data", "can_exfiltrate", "sees_untrusted_content", "can_execute_code", "can_modify_files", "can_send_messages", "touches_credentials"],
    tools: [],
    rules,
  };
}

const baseCtx: ToolCallContext = {
  toolName: "read_file",
  serverName: "filesystem",
  toolCapabilities: [],
  sessionCapabilities: [],
  sessionTainted: false,
  trifecta: false,
  arguments: {},
};

describe("TrifectaTracker", () => {
  it("starts with no capabilities and not triggered", () => {
    const tracker = new TrifectaTracker();
    assert.equal(tracker.isTriggered(), false);
    assert.equal(tracker.getCapabilities().size, 0);
  });

  it("accumulates capabilities across multiple observe() calls", () => {
    const tracker = new TrifectaTracker();
    tracker.observe(["reads_private_data"]);
    tracker.observe(["sees_untrusted_content"]);
    const state = tracker.observe(["can_execute_code"]);
    assert.ok(state.capabilities.has("reads_private_data"));
    assert.ok(state.capabilities.has("sees_untrusted_content"));
    assert.ok(state.capabilities.has("can_execute_code"));
    assert.equal(state.capabilities.size, 3);
  });

  it("does not trigger on two legs of the trifecta", () => {
    const tracker = new TrifectaTracker();
    tracker.observe(["reads_private_data"]);
    const state = tracker.observe(["sees_untrusted_content"]);
    assert.equal(state.triggered, false);
    assert.equal(state.justTriggered, false);
    assert.equal(tracker.isTriggered(), false);
  });

  it("triggers when all three legs are present", () => {
    const tracker = new TrifectaTracker();
    tracker.observe(["reads_private_data", "sees_untrusted_content"]);
    const state = tracker.observe(["can_exfiltrate"]);
    assert.equal(state.triggered, true);
    assert.equal(tracker.isTriggered(), true);
  });

  it("justTriggered is true only on the call that first completes the trifecta", () => {
    const tracker = new TrifectaTracker();
    tracker.observe(["reads_private_data", "sees_untrusted_content"]);
    const trigger = tracker.observe(["can_exfiltrate"]);
    assert.equal(trigger.justTriggered, true);

    // Subsequent calls must not re-fire the alert
    const after1 = tracker.observe(["can_execute_code"]);
    const after2 = tracker.observe(["reads_private_data"]);
    assert.equal(after1.justTriggered, false);
    assert.equal(after2.justTriggered, false);
    // But triggered stays true
    assert.equal(after1.triggered, true);
    assert.equal(after2.triggered, true);
  });

  it("triggers when all three legs arrive in a single observe() call", () => {
    const tracker = new TrifectaTracker();
    const state = tracker.observe([...TRIFECTA_LEGS]);
    assert.equal(state.triggered, true);
    assert.equal(state.justTriggered, true);
  });

  it("getCapabilities() reflects current accumulated state", () => {
    const tracker = new TrifectaTracker();
    tracker.observe(["reads_private_data"]);
    assert.ok(tracker.getCapabilities().has("reads_private_data"));
    assert.equal(tracker.getCapabilities().size, 1);
    tracker.observe(["can_exfiltrate"]);
    assert.equal(tracker.getCapabilities().size, 2);
  });

  it("observe() with empty array does not change state", () => {
    const tracker = new TrifectaTracker();
    tracker.observe(["reads_private_data"]);
    const before = tracker.getCapabilities().size;
    tracker.observe([]);
    assert.equal(tracker.getCapabilities().size, before);
    assert.equal(tracker.isTriggered(), false);
  });
});

describe("PolicyEngine — trifecta: true condition", () => {
  const engine = new PolicyEngine(makePolicy([
    {
      name: "block on trifecta",
      action: "block",
      when: { trifecta: true },
    },
  ]));

  it("does not block when trifecta is false", () => {
    const ctx: ToolCallContext = { ...baseCtx, trifecta: false };
    assert.equal(engine.evaluate(ctx).action, "allow");
  });

  it("blocks when trifecta is true", () => {
    const ctx: ToolCallContext = { ...baseCtx, trifecta: true };
    const result = engine.evaluate(ctx);
    assert.equal(result.action, "block");
    assert.equal(result.matchedRule, "block on trifecta");
  });

  it("trifecta: false rule matches when trifecta is not triggered", () => {
    const safeEngine = new PolicyEngine(makePolicy([
      {
        name: "warn when safe",
        action: "warn",
        when: { trifecta: false },
      },
    ]));
    const ctx: ToolCallContext = { ...baseCtx, trifecta: false };
    assert.equal(safeEngine.evaluate(ctx).action, "warn");
  });
});
