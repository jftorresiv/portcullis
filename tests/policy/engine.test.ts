import { describe, it } from "node:test";
import assert from "node:assert/strict";
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
  toolCapabilities: ["reads_private_data"],
  sessionCapabilities: ["reads_private_data"],
  sessionTainted: false,
  trifecta: false,
  arguments: { path: "/home/user/doc.txt" },
};

describe("PolicyEngine.evaluate", () => {
  it("returns allow when no rules are defined", () => {
    const engine = new PolicyEngine(makePolicy([]));
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "allow");
    assert.equal(result.matchedRule, undefined);
  });

  it("returns allow when no rules match", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "block exec",
        action: "block",
        when: { tool_call: { has_capability: "can_execute_code" } },
      },
    ]));
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "allow");
  });

  it("returns block with matched rule name", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "no reads",
        action: "block",
        when: { tool_call: { has_capability: "reads_private_data" } },
        message: "Reading private data is not allowed.",
      },
    ]));
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "block");
    assert.equal(result.matchedRule, "no reads");
    assert.equal(result.message, "Reading private data is not allowed.");
  });

  it("returns warn with matched rule name", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "warn reads",
        action: "warn",
        when: { tool_call: { has_capability: "reads_private_data" } },
      },
    ]));
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "warn");
    assert.equal(result.matchedRule, "warn reads");
  });

  it("returns confirm with matched rule name", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "confirm reads",
        action: "confirm",
        when: { tool_call: { has_capability: "reads_private_data" } },
      },
    ]));
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "confirm");
    assert.equal(result.matchedRule, "confirm reads");
  });

  it("first-match-wins: earlier block shadows later warn", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "first",
        action: "block",
        when: { tool_call: { has_capability: "reads_private_data" } },
      },
      {
        name: "second",
        action: "warn",
        when: { tool_call: { has_capability: "reads_private_data" } },
      },
    ]));
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "block");
    assert.equal(result.matchedRule, "first");
  });

  it("matches tool_call.tool_matches glob", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "block filesystem writes",
        action: "block",
        when: { tool_call: { tool_matches: ["filesystem.write*"] } },
      },
    ]));

    const writeCtx: ToolCallContext = { ...baseCtx, toolName: "write_file", toolCapabilities: ["can_modify_files"] };
    const readCtx: ToolCallContext = { ...baseCtx, toolName: "read_file" };

    assert.equal(engine.evaluate(writeCtx).action, "block");
    assert.equal(engine.evaluate(readCtx).action, "allow");
  });

  it("matches tool_call.arguments_match regex — credential pattern", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "credential exfil",
        action: "block",
        when: {
          tool_call: {
            arguments_match: ["sk-[a-zA-Z0-9]{32,}"],
          },
        },
      },
    ]));

    const cleanCtx: ToolCallContext = { ...baseCtx, arguments: { body: "hello world" } };
    const credCtx: ToolCallContext = {
      ...baseCtx,
      arguments: { body: "here is sk-abcdefghijklmnopqrstuvwxyz12345678" },
    };

    assert.equal(engine.evaluate(cleanCtx).action, "allow");
    assert.equal(engine.evaluate(credCtx).action, "block");
  });

  it("matches session_has_capabilities.all — lethal trifecta", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "Lethal trifecta",
        action: "block",
        when: {
          session_has_capabilities: {
            all: ["reads_private_data", "sees_untrusted_content", "can_exfiltrate"],
          },
        },
      },
    ]));

    const safeCtx: ToolCallContext = {
      ...baseCtx,
      sessionCapabilities: ["reads_private_data", "sees_untrusted_content"],
    };
    const dangerCtx: ToolCallContext = {
      ...baseCtx,
      sessionCapabilities: ["reads_private_data", "sees_untrusted_content", "can_exfiltrate"],
    };

    assert.equal(engine.evaluate(safeCtx).action, "allow");
    assert.equal(engine.evaluate(dangerCtx).action, "block");
  });

  it("skips rules with unimplemented conditions (tool_registration)", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "injection scanner",
        action: "block",
        when: { tool_registration: { description_matches: ["ignore previous"] } },
      },
      {
        name: "fallback allow",
        action: "warn",
        when: { tool_call: { has_capability: "reads_private_data" } },
      },
    ]));
    // tool_registration rule is skipped; falls through to the warn rule
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "warn");
    assert.equal(result.matchedRule, "fallback allow");
  });

  it("skips rules with unimplemented conditions (server, session_metrics)", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "new server",
        action: "confirm",
        when: { server: "new" },
      },
      {
        name: "bulk read",
        action: "confirm",
        when: {
          session_metrics: {
            tool_calls_with_capability: {
              capability: "reads_private_data",
              count_in_window: 20,
              window_seconds: 60,
            },
          },
        },
      },
    ]));
    const result = engine.evaluate(baseCtx);
    assert.equal(result.action, "allow");
  });

  it("AND semantics: session_tainted AND tool_call.has_capability both must match", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "tainted exfil",
        action: "confirm",
        when: {
          session_tainted: true,
          tool_call: { has_capability: "can_exfiltrate" },
        },
      },
    ]));

    const notTaintedExfil: ToolCallContext = {
      ...baseCtx,
      toolCapabilities: ["can_exfiltrate"],
      sessionTainted: false,
    };
    const taintedNoExfil: ToolCallContext = {
      ...baseCtx,
      toolCapabilities: ["reads_private_data"],
      sessionTainted: true,
    };
    const taintedExfil: ToolCallContext = {
      ...baseCtx,
      toolCapabilities: ["can_exfiltrate"],
      sessionTainted: true,
    };

    assert.equal(engine.evaluate(notTaintedExfil).action, "allow");
    assert.equal(engine.evaluate(taintedNoExfil).action, "allow");
    assert.equal(engine.evaluate(taintedExfil).action, "confirm");
  });

  it("rule with no when never matches", () => {
    const engine = new PolicyEngine(makePolicy([
      {
        name: "empty when",
        action: "block",
        when: undefined,
      },
    ]));
    assert.equal(engine.evaluate(baseCtx).action, "allow");
  });
});
